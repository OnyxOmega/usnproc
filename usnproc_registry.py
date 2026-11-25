"""
usnproc_registry.py -- offline registry hive access and source-machine
identity extraction (DESIGN_LOCK Q1, Q4, "Source identity extraction").

Hives are read from the MOUNTED IMAGE (<drive>\\Windows\\System32\\config),
never from the analysis VM's live registry.

Primary reader: python-registry (pure Python, never touches the live
registry). Fallback: RegLoadAppKey via ctypes (private, isolated namespace,
not loaded under HKLM), used only if python-registry cannot open the hive.
Only one method runs per hive; the manifest records which one succeeded and
every attempt made.
"""

import re
import struct
from datetime import datetime, timezone

METHOD_PYREG = "python-registry"
METHOD_APPKEY = "RegLoadAppKey"

CONFIG_DIR = r"Windows\System32\config"


class HiveError(Exception):
    """A hive could not be opened by either method."""

    def __init__(self, hive, attempts):
        super().__init__("%s hive unreadable: %s" % (
            hive, "; ".join("%s: %s" % (a["method"], a["error"]) for a in attempts)))
        self.hive = hive
        self.attempts = attempts


def hive_path(drive_root, name):
    return drive_root.rstrip("\\") + "\\" + CONFIG_DIR + "\\" + name


# --------------------------------------------------------------------------- #
# Backends -- same two calls for both: get_value(), subkeys()
# --------------------------------------------------------------------------- #
class PyRegistryHive:
    def __init__(self, path):
        from Registry import Registry      # python-registry
        self._reg = Registry.Registry(path)

    def get_value(self, key_path, name):
        """Return the value, or None if the key or value doesn't exist."""
        try:
            key = self._reg.open(key_path)
        except Exception:                  # noqa: BLE001 -- key not found
            return None
        for v in key.values():
            if v.name().lower() == name.lower():
                return v.value()
        return None

    def subkeys(self, key_path):
        try:
            return [k.name() for k in self._reg.open(key_path).subkeys()]
        except Exception:                  # noqa: BLE001
            return []

    def close(self):
        pass


class AppKeyHive:
    """RegLoadAppKey fallback (Windows). The hive is loaded into a private
    namespace and unloaded when the handle is closed."""

    KEY_READ = 0x20019

    def __init__(self, path):
        import ctypes
        import winreg
        self._winreg = winreg
        hkey = ctypes.c_void_p()
        rc = ctypes.windll.advapi32.RegLoadAppKeyW(
            ctypes.c_wchar_p(path), ctypes.byref(hkey), self.KEY_READ, 0, 0)
        if rc != 0:
            raise OSError(rc, "RegLoadAppKeyW failed (error %d)" % rc)
        self._root = hkey.value
        self._advapi = ctypes.windll.advapi32

    def get_value(self, key_path, name):
        try:
            with self._winreg.OpenKey(self._root, key_path) as k:
                return self._winreg.QueryValueEx(k, name)[0]
        except OSError:
            return None

    def subkeys(self, key_path):
        out = []
        try:
            with self._winreg.OpenKey(self._root, key_path) as k:
                i = 0
                while True:
                    try:
                        out.append(self._winreg.EnumKey(k, i))
                    except OSError:
                        break
                    i += 1
        except OSError:
            pass
        return out

    def close(self):
        if self._root:
            self._advapi.RegCloseKey(self._root)
            self._root = None


BACKENDS = [(METHOD_PYREG, PyRegistryHive), (METHOD_APPKEY, AppKeyHive)]


def open_hive(path, hive_name, backends=None):
    """Try python-registry, then RegLoadAppKey. Returns (hive, method,
    attempts). Raises HiveError if both fail."""
    attempts = []
    for method, cls in (backends or BACKENDS):
        try:
            hive = cls(path)
            attempts.append({"method": method, "result": "ok", "error": ""})
            return hive, method, attempts
        except Exception as exc:          # noqa: BLE001
            attempts.append({"method": method, "result": "failed", "error": repr(exc)})
    raise HiveError(hive_name, attempts)


# --------------------------------------------------------------------------- #
# Decoders
# --------------------------------------------------------------------------- #
def epoch_to_iso(secs):
    if not secs:
        return ""
    try:
        return datetime.fromtimestamp(int(secs), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return ""


def decode_sid(raw):
    """Decode a binary SID."""
    rev, count = raw[0], raw[1]
    auth = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack_from("<%dI" % count, raw, 8)
    return "S-%d-%d" % (rev, auth) + "".join("-%d" % s for s in subs)


def machine_sid_from_v(v):
    """The machine (account domain) SID is the last 24 bytes of
    SAM\\Domains\\Account value V: S-1-5-21-a-b-c."""
    if not v or len(v) < 24:
        return ""
    tail = bytes(v[-24:])
    if tail[0] != 1 or tail[1] != 4:
        return ""
    return decode_sid(tail)


def _s(v):
    return "" if v is None else str(v)


def drive_letter_of(path):
    """'C:\\Windows' -> 'C:'; '' if no drive letter."""
    m = re.match(r"\s*([A-Za-z]):", path or "")
    return m.group(1).upper() + ":" if m else ""


def filetime_from_reg(v):
    """ShutdownTime is REG_BINARY holding an 8-byte FILETIME."""
    if isinstance(v, (bytes, bytearray)) and len(v) >= 8:
        ft = struct.unpack_from("<Q", bytes(v), 0)[0]
        return ft or None
    if isinstance(v, int) and v > 0:
        return v
    return None


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
def current_control_set(system):
    cur = system.get_value("Select", "Current")
    try:
        return "ControlSet%03d" % int(cur)
    except (TypeError, ValueError):
        return "ControlSet001"


def read_software_identity(software):
    cv = r"Microsoft\Windows NT\CurrentVersion"
    build = software.get_value(cv, "CurrentBuild") or software.get_value(cv, "CurrentBuildNumber")
    return {
        "machine_guid": _s(software.get_value(r"Microsoft\Cryptography", "MachineGuid")),
        "os_product_name": _s(software.get_value(cv, "ProductName")),
        "os_current_build": _s(build),
        "os_install_date_utc": epoch_to_iso(software.get_value(cv, "InstallDate")),
        "registered_owner": _s(software.get_value(cv, "RegisteredOwner")),
        "registered_organization": _s(software.get_value(cv, "RegisteredOrganization")),
        "system_root": _s(software.get_value(cv, "SystemRoot")),
    }


def read_system_identity(system):
    cs = current_control_set(system)
    host = system.get_value(cs + r"\Control\ComputerName\ComputerName", "ComputerName")
    tcpip = cs + r"\Services\Tcpip\Parameters"
    domain = system.get_value(tcpip, "Domain") or system.get_value(tcpip, "NV Domain")
    shutdown = filetime_from_reg(system.get_value(cs + r"\Control\Windows", "ShutdownTime"))
    return {"hostname": _s(host), "domain": _s(domain), "control_set": cs,
            "shutdown_filetime": shutdown}


def read_machine_sid(sam):
    return machine_sid_from_v(sam.get_value(r"SAM\Domains\Account", "V"))


def fqdn(hostname, domain):
    if hostname and domain:
        return "%s.%s" % (hostname, domain)
    return hostname or ""
