"""usnproc_verify.py -- verify that a mounted NTFS image is compatible with usnproc.

Given a mounted drive letter (typically an image mounted read-only via FTK Imager,
Arsenal Image Mounter, OSFMount, imdisk, etc.), this script checks whether the
mount supports the operations usnproc needs:

    1. Drive letter is present and accessible
    2. Filesystem is NTFS
    3. FSCTL_QUERY_USN_JOURNAL succeeds (mount driver exposes journal metadata)
    4. FSCTL_READ_USN_JOURNAL succeeds or channel legitimately empty
    5. Registry hives exist at Windows\\System32\\config\\{SOFTWARE, SYSTEM}
    6. python-registry can open the SOFTWARE hive (primary read path)
    7. MachineGuid extractable from Cryptography key
    8. Running elevated (usnproc needs administrator rights)
    9. SYSTEM hive opens and the hostname is readable (usnproc exit 6 otherwise)
   10. SAM hive readable -> machine SID                   [warning only]
   11. SystemRoot readable -> source drive letter (Q12)   [warning only]
   12. ShutdownTime readable (status-record time, Q11)    [warning only]
   13. $Extend\\$UsnJrnl visible through the mount (D4)   [warning only]

Warning-only checks never fail verification: usnproc has a documented
fallback for each (empty MachineSID, VolumeSerial path prefix, 1601-01-01
status time, disabled/missing journals reported as missing).

Exit codes:
    0 = all checks passed (mount compatible with usnproc)
    1 = one or more checks failed (mount NOT compatible)
    2 = command-line error (bad drive-letter argument, etc.)

Usage:
    usnproc_verify.py <drive-letter>

Examples:
    usnproc_verify.py F
    usnproc_verify.py F:
    usnproc_verify.py F:\\

Design note: this script does NOT modify the mounted volume in any way. All IOCTLs
issued are read-only queries. If a check fails, subsequent checks that depend on
the failed one are skipped rather than attempted.

License: PolyForm Noncommercial 1.0.0 -- YASDC, Inc.
"""

import argparse
from datetime import datetime, timedelta, timezone
import os
import re
import struct
import sys

# --- Windows-only imports (guarded so the module parses on non-Windows) ---
try:
    import win32api
    import win32con
    import win32file
    _WINDOWS = True
except Exception:
    win32api = win32con = win32file = None
    _WINDOWS = False


# =========================================================================== #
# Constants
# =========================================================================== #
# USN journal IOCTL codes. These are the exact values Windows uses; we redefine
# them here so we don't depend on winioctlcon's completeness (it varies across
# pywin32 versions).
FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL  = 0x000900BB

# Layouts.
# USN_JOURNAL_DATA_V0 (returned by FSCTL_QUERY_USN_JOURNAL):
#     ULONGLONG UsnJournalID
#     USN       FirstUsn         (INT64)
#     USN       NextUsn          (INT64)
#     USN       LowestValidUsn   (INT64)
#     USN       MaxUsn           (INT64)
#     ULONGLONG MaximumSize
#     ULONGLONG AllocationDelta
# Total: 56 bytes.
_QUERY_USN_JOURNAL_FMT = "<Qqqqq QQ"
_QUERY_USN_JOURNAL_SIZE = struct.calcsize(_QUERY_USN_JOURNAL_FMT)   # 56

# READ_USN_JOURNAL_DATA_V0 (input to FSCTL_READ_USN_JOURNAL):
#     USN       StartUsn
#     DWORD     ReasonMask
#     DWORD     ReturnOnlyOnClose
#     ULONGLONG Timeout
#     ULONGLONG BytesToWaitFor
#     ULONGLONG UsnJournalID
_READ_USN_JOURNAL_FMT = "<q I I Q Q Q"
_READ_USN_JOURNAL_SIZE = struct.calcsize(_READ_USN_JOURNAL_FMT)     # 40


# =========================================================================== #
# Output formatting
# =========================================================================== #
_STATUS_WIDTH = 8
_INDENT = "        "


def _print_ok(msg):
    print("[OK]    %s" % msg)


def _print_info(msg):
    print("%s%s" % (_INDENT, msg))


def _print_fail(msg):
    print("[FAIL]  %s" % msg)


def _print_skip(msg):
    print("[SKIP]  %s" % msg)


def _print_warn(msg):
    print("[WARN]  %s" % msg)


# =========================================================================== #
# Drive-letter normalization
# =========================================================================== #
def normalize_drive_letter(raw):
    """Accept 'F', 'F:', or 'F:\\' -- return 'F:\\' or raise ValueError."""
    s = str(raw).strip().strip('"').strip("'")
    if not s:
        raise ValueError("empty drive letter")
    # Just a letter.
    if re.fullmatch(r"[A-Za-z]", s):
        return "%s:\\" % s.upper()
    # Letter with colon.
    if re.fullmatch(r"[A-Za-z]:", s):
        return "%s\\" % s.upper()
    # Letter with backslash.
    if re.fullmatch(r"[A-Za-z]:[\\/]", s):
        return "%s:\\" % s[0].upper()
    raise ValueError("invalid drive letter format: %r "
                     "(expected 'F', 'F:', or 'F:\\')" % raw)


def volume_path(drive_letter):
    """Return the device path for direct-volume IOCTLs: \\\\.\\F:"""
    return r"\\.\%s" % drive_letter.rstrip("\\")


# =========================================================================== #
# Check 1: Drive letter exists and is accessible
# =========================================================================== #
def check_drive_present(drive_letter):
    """Confirm the drive letter is currently mounted."""
    try:
        drive_type = win32file.GetDriveType(drive_letter)
    except Exception as exc:
        return False, "GetDriveType failed: %r" % exc
    # DRIVE_UNKNOWN = 0, DRIVE_NO_ROOT_DIR = 1 -> not mounted.
    if drive_type == 0:
        return False, "drive type UNKNOWN (not mounted)"
    if drive_type == 1:
        return False, "drive has no root directory (not mounted)"
    # Anything else means it's mounted; specific type reported for context.
    types = {2: "REMOVABLE", 3: "FIXED", 4: "REMOTE",
             5: "CDROM", 6: "RAMDISK"}
    return True, "drive type %s" % types.get(drive_type, "code %d" % drive_type)


# =========================================================================== #
# Check 2: Filesystem is NTFS
# =========================================================================== #
def check_ntfs(drive_letter):
    """Confirm the filesystem on the drive is NTFS."""
    try:
        info = win32api.GetVolumeInformation(drive_letter)
    except Exception as exc:
        return False, "GetVolumeInformation failed: %r" % exc
    # info = (label, serial, max_component, flags, fs_name)
    fs_name = info[4]
    if fs_name.upper() != "NTFS":
        return False, "filesystem is %r (not NTFS)" % fs_name
    return True, "NTFS confirmed"


# =========================================================================== #
# Check 3: FSCTL_QUERY_USN_JOURNAL
# =========================================================================== #
def check_query_journal(drive_letter):
    """Issue FSCTL_QUERY_USN_JOURNAL against the volume. Returns (ok, message,
    journal_info_dict-or-None). journal_info_dict has keys: JournalId, FirstUsn,
    NextUsn, LowestValidUsn, MaxUsn, MaxSize, AllocationDelta."""
    vol = volume_path(drive_letter)
    h = None
    try:
        # Open volume without granting write access. Read-only volumes (like a
        # mounted image) will REJECT FILE_GENERIC_WRITE.
        h = win32file.CreateFile(
            vol,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None)
    except Exception as exc:
        if (getattr(exc, "winerror", None) or 0) == 5:
            return False, ("CreateFile(%s) failed: access denied (winerror 5) -- "
                           "run from an elevated (Administrator) prompt" % vol), None
        return False, "CreateFile(%s) failed: %r" % (vol, exc), None

    try:
        buf = win32file.DeviceIoControl(
            h, FSCTL_QUERY_USN_JOURNAL, None, _QUERY_USN_JOURNAL_SIZE)
    except Exception as exc:
        # Common failure modes:
        #   winerror 1179 (ERROR_JOURNAL_NOT_ACTIVE) -- journal absent
        #   winerror 1180 (ERROR_JOURNAL_ENTRY_DELETED) -- ring-buffer purge
        #   winerror 1 (ERROR_INVALID_FUNCTION) -- mount doesn't support IOCTL
        errno = getattr(exc, "winerror", None) or 0
        if errno == 1179:
            return False, "FSCTL_QUERY_USN_JOURNAL failed (winerror 1179 -- " \
                          "ERROR_JOURNAL_NOT_ACTIVE: no USN journal on this " \
                          "volume)", None
        if errno == 1:
            return False, "FSCTL_QUERY_USN_JOURNAL failed (winerror 1 -- " \
                          "ERROR_INVALID_FUNCTION: mount driver does not " \
                          "expose USN journal IOCTLs)", None
        return False, "FSCTL_QUERY_USN_JOURNAL failed: %r" % exc, None
    finally:
        try:
            win32file.CloseHandle(h)
        except Exception:
            pass

    if len(buf) < _QUERY_USN_JOURNAL_SIZE:
        return False, ("FSCTL_QUERY_USN_JOURNAL returned only %d bytes "
                       "(expected %d)" % (len(buf), _QUERY_USN_JOURNAL_SIZE)), None

    (jid, first_usn, next_usn, lowest_valid, max_usn,
     max_size, alloc_delta) = struct.unpack_from(
        _QUERY_USN_JOURNAL_FMT, buf, 0)

    info = {
        "JournalId": jid,
        "FirstUsn": first_usn,
        "NextUsn": next_usn,
        "LowestValidUsn": lowest_valid,
        "MaxUsn": max_usn,
        "MaxSize": max_size,
        "AllocationDelta": alloc_delta,
    }
    return True, "journal metadata retrieved", info


# =========================================================================== #
# Check 4: FSCTL_READ_USN_JOURNAL
# =========================================================================== #
def check_read_journal(drive_letter, journal_info):
    """Issue FSCTL_READ_USN_JOURNAL from FirstUsn and read at least one record
    (or confirm the journal is legitimately empty). Empty journal is a valid
    outcome that still means 'IOCTL works'."""
    vol = volume_path(drive_letter)
    h = None
    try:
        h = win32file.CreateFile(
            vol,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None)
    except Exception as exc:
        return False, "CreateFile(%s) failed: %r" % (vol, exc), 0

    # Read from FirstUsn. Reason mask 0xFFFFFFFF = every reason flag.
    # ReturnOnlyOnClose = 0. Timeout = 0 (non-blocking).
    # BytesToWaitFor = 0 (return whatever is available, don't block).
    read_in = struct.pack(
        _READ_USN_JOURNAL_FMT,
        journal_info["FirstUsn"],   # StartUsn
        0xFFFFFFFF,                 # ReasonMask (all)
        0,                          # ReturnOnlyOnClose
        0,                          # Timeout
        0,                          # BytesToWaitFor
        journal_info["JournalId"],  # UsnJournalID
    )

    try:
        buf = win32file.DeviceIoControl(
            h, FSCTL_READ_USN_JOURNAL, read_in, 65536)
    except Exception as exc:
        errno = getattr(exc, "winerror", None) or 0
        if errno == 1180:
            # ERROR_JOURNAL_ENTRY_DELETED -- StartUsn precedes FirstUsn (which
            # shouldn't happen since we PASSED FirstUsn, but some mounts glitch
            # here). Reported as a failure; no retry is attempted.
            return False, ("FSCTL_READ_USN_JOURNAL failed at FirstUsn "
                           "(winerror 1180 -- journal entry deleted; ring "
                           "buffer boundary condition)"), 0
        return False, "FSCTL_READ_USN_JOURNAL failed: %r" % exc, 0
    finally:
        try:
            win32file.CloseHandle(h)
        except Exception:
            pass

    # First 8 bytes of the returned buffer are the "next USN" the caller should
    # use to continue reading. If the buffer is exactly 8 bytes, there are no
    # records -- journal is legitimately empty.
    if len(buf) < 8:
        return False, ("FSCTL_READ_USN_JOURNAL returned truncated buffer "
                       "(%d bytes)" % len(buf)), 0
    if len(buf) == 8:
        return True, "IOCTL succeeded (journal empty -- zero records)", 0

    # We have at least one record. We don't parse it here (verification only
    # cares that the IOCTL works); just count that we got past the 8-byte
    # header.
    record_bytes = len(buf) - 8
    return True, ("IOCTL succeeded (at least one record read; %d bytes of "
                  "record data in first batch)" % record_bytes), record_bytes


# =========================================================================== #
# Check 5: Registry hive files present
# =========================================================================== #
def check_hive_files_present(drive_letter):
    """Confirm the SOFTWARE and SYSTEM hive files exist in the standard path."""
    base = os.path.join(drive_letter, "Windows", "System32", "config")
    software = os.path.join(base, "SOFTWARE")
    system = os.path.join(base, "SYSTEM")
    results = {}
    missing = []
    for name, path in (("SOFTWARE", software), ("SYSTEM", system)):
        if os.path.exists(path):
            try:
                size = os.path.getsize(path)
                results[name] = (True, "%s bytes" % f"{size:,}")
            except Exception as exc:
                results[name] = (False, "stat failed: %r" % exc)
                missing.append(name)
        else:
            results[name] = (False, "file not found at %s" % path)
            missing.append(name)
    if missing:
        return False, "missing hive(s): %s" % ", ".join(missing), results
    return True, "both hives present", results


# =========================================================================== #
# Check 6: python-registry can open the SOFTWARE hive
# =========================================================================== #
def check_python_registry_available():
    """Confirm python-registry is importable. Returns (ok, message)."""
    try:
        import Registry.Registry   # noqa: F401
        return True, "python-registry importable"
    except ImportError:
        return False, ("python-registry NOT installed. Install with: "
                       "pip install python-registry")
    except Exception as exc:
        return False, "python-registry import failed: %r" % exc


def check_python_registry_open(drive_letter):
    """Open the SOFTWARE hive via python-registry. Returns (ok, message)."""
    software_path = os.path.join(drive_letter, "Windows", "System32", "config",
                                 "SOFTWARE")
    try:
        from Registry.Registry import Registry
        Registry(software_path)   # constructor validates the hive header
        return True, "SOFTWARE hive opened via python-registry"
    except Exception as exc:
        return False, "python-registry could not open SOFTWARE hive: %r" % exc


# =========================================================================== #
# Check 7: MachineGuid extractable
# =========================================================================== #
def check_machineguid(drive_letter):
    """Extract MachineGuid from the SOFTWARE hive. Returns (ok, message, guid)."""
    software_path = os.path.join(drive_letter, "Windows", "System32", "config",
                                 "SOFTWARE")
    try:
        from Registry.Registry import Registry
        reg = Registry(software_path)
        key = reg.open("Microsoft\\Cryptography")
        val = key.value("MachineGuid")
        guid = val.value()
        if not guid:
            return False, "MachineGuid value is empty", None
        return True, "MachineGuid extracted", guid
    except Exception as exc:
        return False, ("could not read Microsoft\\Cryptography\\MachineGuid: %r"
                       % exc), None


# =========================================================================== #
# Checks 8-13: what usnproc needs beyond the original seven
# =========================================================================== #
_CONFIG = ("Windows", "System32", "config")


def _hive_path(drive_letter, name):
    return os.path.join(drive_letter, *(_CONFIG + (name,)))


def _reg_value(reg, key_path, name):
    """Value from a python-registry hive, or None if key/value missing."""
    try:
        key = reg.open(key_path)
    except Exception:
        return None
    for v in key.values():
        if v.name().lower() == name.lower():
            return v.value()
    return None


def _control_set(reg):
    cur = _reg_value(reg, "Select", "Current")
    try:
        return "ControlSet%03d" % int(cur)
    except (TypeError, ValueError):
        return "ControlSet001"


def check_elevated():
    """Check 8: usnproc opens the raw volume, which needs administrator
    rights. Returns (ok, message)."""
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True, "running elevated (Administrator)"
        return False, ("NOT elevated -- run usnproc (and this check) from an "
                       "Administrator prompt")
    except Exception as exc:
        return False, "could not determine elevation: %r" % exc


def check_system_hive(drive_letter):
    """Check 9: SYSTEM hive opens via python-registry and ComputerName is
    readable. Returns (ok, message, hostname)."""
    try:
        from Registry.Registry import Registry
        reg = Registry(_hive_path(drive_letter, "SYSTEM"))
    except Exception as exc:
        return False, "python-registry could not open SYSTEM hive: %r" % exc, None
    cs = _control_set(reg)
    host = _reg_value(reg, cs + "\\Control\\ComputerName\\ComputerName", "ComputerName")
    if not host:
        return False, "ComputerName not found under %s" % cs, None
    return True, "SYSTEM hive opened (%s)" % cs, str(host)


def check_sam_sid(drive_letter):
    """Check 10 (warning only): machine SID from SAM\\Domains\\Account V.
    Returns (ok, message, sid)."""
    try:
        from Registry.Registry import Registry
        reg = Registry(_hive_path(drive_letter, "SAM"))
    except Exception as exc:
        return False, ("SAM hive not readable (%r); usnproc will leave MachineSID "
                       "empty" % exc), None
    v = _reg_value(reg, "SAM\\Domains\\Account", "V")
    if not v or len(v) < 24 or v[-24] != 1 or v[-23] != 4:
        return False, "machine SID not found in SAM; MachineSID will be empty", None
    tail = bytes(v[-24:])
    subs = struct.unpack_from("<4I", tail, 8)
    sid = "S-1-%d" % int.from_bytes(tail[2:8], "big") + "".join("-%d" % x for x in subs)
    return True, "machine SID read from SAM", sid


def check_system_root(drive_letter):
    """Check 11 (warning only): SystemRoot gives the drive letter the source
    system used (DESIGN_LOCK Q12). Returns (ok, message, letter)."""
    try:
        from Registry.Registry import Registry
        reg = Registry(_hive_path(drive_letter, "SOFTWARE"))
        root = _reg_value(reg, "Microsoft\\Windows NT\\CurrentVersion", "SystemRoot")
    except Exception as exc:
        root, err = None, exc
    else:
        err = None
    m = re.match(r"\s*([A-Za-z]):", root or "")
    if not m:
        why = ("SystemRoot not found" if err is None
               else "SOFTWARE hive not readable: %r" % err)
        return False, ("%s; usnproc will use the VolumeSerial in place of the "
                       "drive letter in paths" % why), None
    return True, "SystemRoot = %s" % root, m.group(1).upper() + ":\\"


def check_shutdown_time(drive_letter):
    """Check 12 (warning only): ShutdownTime is the timestamp usnproc gives a
    status record when the journal is unusable (DESIGN_LOCK Q11).
    Returns (ok, message, iso_time)."""
    try:
        from Registry.Registry import Registry
        reg = Registry(_hive_path(drive_letter, "SYSTEM"))
        raw = _reg_value(reg, _control_set(reg) + "\\Control\\Windows", "ShutdownTime")
    except Exception as exc:
        return False, "SYSTEM hive not readable: %r" % exc, None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8 or not any(raw[:8]):
        return False, ("ShutdownTime not found; a status record would be dated "
                       "1601-01-01"), None
    ft = struct.unpack_from("<Q", bytes(raw), 0)[0]
    when = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
    return True, "ShutdownTime read", when.strftime("%Y-%m-%d %H:%M:%SZ")


def check_usnjrnl_visible(drive_letter):
    """Check 13 (warning only): can $Extend\\$UsnJrnl be seen through the
    mount? usnproc uses this to tell a DISABLED journal from a MISSING one
    (plan D4). Access denied still proves the name exists. Returns
    (ok, message)."""
    path = os.path.join(drive_letter, "$Extend", "$UsnJrnl")
    try:
        os.stat(path)
        return True, "$Extend\\$UsnJrnl visible"
    except PermissionError:
        return True, "$Extend\\$UsnJrnl present (access denied, name resolves)"
    except OSError as exc:
        if getattr(exc, "winerror", None) in (5, 32):
            return True, "$Extend\\$UsnJrnl present (locked, name resolves)"
        return False, ("$Extend\\$UsnJrnl not visible through this mount (%r); a "
                       "disabled journal would be reported as missing" % exc)


# =========================================================================== #
# Main verification orchestrator
# =========================================================================== #
def run_verification(drive_letter):
    """Run all checks in order. Skip dependent checks if prerequisites fail.
    Returns (passed_count, failed_count, skipped_count)."""
    passed = 0
    failed = 0
    skipped = 0

    print("usnproc mount verification: %s" % drive_letter)
    print("=" * 60)

    # Check 1
    ok, msg = check_drive_present(drive_letter)
    if ok:
        _print_ok("Drive %s mounted and accessible" % drive_letter)
        _print_info(msg)
        passed += 1
    else:
        _print_fail("Drive %s not accessible" % drive_letter)
        _print_info(msg)
        failed += 1
        # Everything else depends on the drive being present.
        print()
        _print_skip("Remaining checks skipped (drive not accessible)")
        skipped = 6 + N_EXTRA_CHECKS
        return passed, failed, skipped

    # Check 2
    ok, msg = check_ntfs(drive_letter)
    if ok:
        _print_ok("Filesystem is NTFS")
        passed += 1
    else:
        _print_fail("Filesystem check failed")
        _print_info(msg)
        failed += 1
        print()
        _print_skip("Remaining checks skipped (not NTFS)")
        skipped = 5 + N_EXTRA_CHECKS
        return passed, failed, skipped

    # Check 3
    ok, msg, jinfo = check_query_journal(drive_letter)
    if ok:
        _print_ok("FSCTL_QUERY_USN_JOURNAL succeeded")
        _print_info("JournalId:       0x%016x" % jinfo["JournalId"])
        _print_info("FirstUsn:        %d" % jinfo["FirstUsn"])
        _print_info("NextUsn:         %d" % jinfo["NextUsn"])
        _print_info("LowestValidUsn:  %d" % jinfo["LowestValidUsn"])
        _print_info("MaxUsn:          %d" % jinfo["MaxUsn"])
        _print_info("MaxSize:         %s bytes (%.1f MB)"
                    % (f"{jinfo['MaxSize']:,}",
                       jinfo['MaxSize'] / (1024 * 1024)))
        _print_info("AllocationDelta: %s bytes" % f"{jinfo['AllocationDelta']:,}")
        passed += 1
    else:
        _print_fail("FSCTL_QUERY_USN_JOURNAL failed")
        _print_info(msg)
        failed += 1
        # Check 4 depends on check 3. Checks 5-7 are independent.
        _print_skip("Journal-read check skipped (query failed)")
        skipped += 1
        jinfo = None

    # Check 4
    if jinfo is not None:
        ok, msg, record_bytes = check_read_journal(drive_letter, jinfo)
        if ok:
            _print_ok("FSCTL_READ_USN_JOURNAL succeeded")
            _print_info(msg)
            passed += 1
        else:
            _print_fail("FSCTL_READ_USN_JOURNAL failed")
            _print_info(msg)
            failed += 1

    # Check 5
    ok, msg, hive_results = check_hive_files_present(drive_letter)
    if ok:
        _print_ok("Registry hive files present")
        for name, (present, detail) in hive_results.items():
            marker = " " if present else "!"
            _print_info("%s %s: %s" % (marker, name, detail))
        passed += 1
    else:
        _print_fail("Registry hive files missing")
        _print_info(msg)
        for name, (present, detail) in hive_results.items():
            marker = " " if present else "!"
            _print_info("%s %s: %s" % (marker, name, detail))
        failed += 1
        _print_skip("SOFTWARE hive open + MachineGuid extraction skipped "
                    "(hive file missing)")
        skipped += 2 + N_EXTRA_CHECKS
        return passed, failed, skipped

    # Check 6a: python-registry importable
    ok, msg = check_python_registry_available()
    if ok:
        _print_ok(msg)
        passed += 1
    else:
        _print_fail("python-registry not available")
        _print_info(msg)
        failed += 1
        _print_skip("MachineGuid extraction skipped (python-registry missing)")
        skipped += 1 + N_EXTRA_CHECKS
        return passed, failed, skipped

    # Check 6b: python-registry can open SOFTWARE hive
    ok, msg = check_python_registry_open(drive_letter)
    if ok:
        _print_ok(msg)
        passed += 1
    else:
        _print_fail("python-registry could not open SOFTWARE hive")
        _print_info(msg)
        failed += 1
        _print_skip("MachineGuid extraction skipped (hive open failed)")
        skipped += 1 + N_EXTRA_CHECKS
        return passed, failed, skipped

    # Check 7: MachineGuid
    ok, msg, guid = check_machineguid(drive_letter)
    if ok:
        _print_ok("MachineGuid extracted from SOFTWARE hive")
        _print_info("MachineGuid: %s" % guid)
        passed += 1
    else:
        _print_fail("MachineGuid extraction failed")
        _print_info(msg)
        failed += 1

    p, f = run_extra_checks(drive_letter)
    return passed + p, failed + f, skipped


N_EXTRA_CHECKS = 6


def run_extra_checks(drive_letter):
    """Checks 8-13. Required checks (8, 9) count as pass/fail. Warning-only
    checks (10-13) count as passed when OK; a [WARN] never fails
    verification. Returns (passed, failed)."""
    passed = failed = 0

    ok, msg = check_elevated()
    if ok:
        _print_ok(msg)
        passed += 1
    else:
        _print_fail("Not running elevated")
        _print_info(msg)
        failed += 1

    ok, msg, host = check_system_hive(drive_letter)
    if ok:
        _print_ok(msg)
        _print_info("Hostname: %s" % host)
        passed += 1
    else:
        _print_fail("SYSTEM hive check failed")
        _print_info(msg)
        failed += 1

    for label, fn in (("Machine SID", check_sam_sid),
                      ("Source drive letter", check_system_root),
                      ("ShutdownTime", check_shutdown_time)):
        ok, msg, value = fn(drive_letter)
        if ok:
            _print_ok(msg)
            _print_info("%s: %s" % (label, value))
            passed += 1
        else:
            _print_warn(msg)

    ok, msg = check_usnjrnl_visible(drive_letter)
    if ok:
        _print_ok(msg)
        passed += 1
    else:
        _print_warn(msg)
    return passed, failed


# =========================================================================== #
# Entry point
# =========================================================================== #
def main():
    parser = argparse.ArgumentParser(
        description="Verify a mounted NTFS forensic image is compatible with "
                    "usnproc. Confirms drive presence, NTFS filesystem, USN "
                    "journal IOCTL support, registry hive readability, and "
                    "MachineGuid extractability.",
        epilog="Exit codes: 0=all passed, 1=at least one check failed, "
               "2=command-line error.")
    parser.add_argument(
        "drive",
        help="drive letter of the mounted image "
             "(accepts 'F', 'F:', or 'F:\\'; normalizes to 'F:\\')")
    parser.add_argument(
        "--version", action="version", version="usnproc_verify 0.0.1")
    args = parser.parse_args()

    if not _WINDOWS:
        print("ERROR: this script requires Windows (pywin32 not importable).",
              file=sys.stderr)
        sys.exit(2)

    try:
        drive_letter = normalize_drive_letter(args.drive)
    except ValueError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        sys.exit(2)

    passed, failed, skipped = run_verification(drive_letter)

    print()
    print("=" * 60)
    print("Summary: %d passed, %d failed, %d skipped" % (passed, failed, skipped))
    if failed == 0 and skipped == 0:
        print()
        print("VERIFICATION PASSED -- mount is compatible with usnproc.")
        if passed < 8 + N_EXTRA_CHECKS:
            print("(See [WARN] lines above: usnproc will run, using the "
                  "documented fallbacks.)")
        sys.exit(0)
    else:
        print()
        print("VERIFICATION FAILED -- this mount is NOT compatible with usnproc.")
        print("Consider trying a different mount tool "
              "(FTK Imager, Arsenal Image Mounter, OSFMount, imdisk).")
        sys.exit(1)


if __name__ == "__main__":
    main()
