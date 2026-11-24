"""
usnproc_journal.py -- volume and USN journal access for usnproc.

Ported from usnmon (OnyxOmega/USNJournal2EventLog @ bd09f19, usnmon.py) and
usnproc_verify.py, adapted for offline single-pass processing:

  * query_journal() returns all 7 USN_JOURNAL_DATA_V0 fields (manifest Q9)
  * parse_record() keeps the record's own Timestamp (Q11) and attributes
  * iterate_records() is a finite loop ending at the NextUsn captured at start
    (Q6) -- no cursor, no sleep, no live-follow
  * PathResolver adds an offline fallback: rebuild paths from the journal's
    own (file_ref -> parent_ref, name) records when OpenFileById fails (D3)

Everything here that touches the volume is Windows-only; the pure functions
(parse, FILETIME conversion, path map) are platform-independent and tested
on any OS.
"""

import os
import struct
from collections import namedtuple
from datetime import datetime, timedelta, timezone

try:
    import win32api
    import win32file
    _WINDOWS = True
except ImportError:   # non-Windows: pure functions still importable for tests
    win32api = None
    win32file = None
    _WINDOWS = False

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
FILE_SHARE_ALL = 0x01 | 0x02 | 0x04
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
READ_BUFFER = 65536
VOLUME_NAME_NONE = 0x4

ERROR_ACCESS_DENIED = 5
ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178
ERROR_JOURNAL_NOT_ACTIVE = 1179

RENAME_DELETE_MASK = 0x200 | 0x1000 | 0x2000   # same as usnmon
NTFS_ROOT_MFT_INDEX = 5

JournalData = namedtuple("JournalData", [
    "journal_id", "first_usn", "next_usn", "lowest_valid_usn", "max_usn",
    "max_size", "allocation_delta"])

STATE_NORMAL, STATE_EMPTY, STATE_DISABLED, STATE_MISSING = (
    "normal", "empty", "disabled", "missing")

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


class JournalError(Exception):
    """Unrecoverable journal problem (exit 4)."""


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def drive_root_to_device(root):
    """'F:\\' -> '\\\\.\\F:'  (from usnmon)"""
    return "\\\\.\\" + root.rstrip("\\")


def filetime_to_datetime(ft):
    return _EPOCH_1601 + timedelta(microseconds=ft // 10)


def filetime_to_utc_str(ft):
    """FILETIME -> usnmon UtcTime format 'YYYY-MM-DD HH:MM:SS.mmmZ'."""
    if not ft or ft < 0:
        return ""
    return filetime_to_datetime(ft).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def winerror_of(exc):
    return getattr(exc, "winerror", None) or (exc.args[0] if getattr(exc, "args", None)
                                              and isinstance(exc.args[0], int) else 0)


def parse_journal_data(out):
    """USN_JOURNAL_DATA_V0: UsnJournalID(Q) FirstUsn(q) NextUsn(q)
    LowestValidUsn(q) MaxUsn(q) MaximumSize(Q) AllocationDelta(Q)."""
    if len(out) < 56:
        raise JournalError("FSCTL_QUERY_USN_JOURNAL returned %d bytes" % len(out))
    return JournalData(*struct.unpack_from("<QqqqqQQ", out, 0))


def build_read_input(journal_id, start_usn):
    """READ_USN_JOURNAL_DATA_V0 (from usnmon): StartUsn(q) ReasonMask(L)
    ReturnOnlyOnClose(L) Timeout(Q) BytesToWaitFor(Q) UsnJournalID(Q).
    Timeout=0 and BytesToWaitFor=0 -> every read returns immediately."""
    return struct.pack("<qLLQQQ", start_usn, 0xFFFFFFFF, 0, 0, 0, journal_id)


def parse_record(buf, offset):
    """Parse USN_RECORD_V2/V3. Unlike usnmon, keeps 'timestamp' (FILETIME)
    and 'attributes'. Returns None for unsupported versions (V4 range
    records are never requested). Raises on truncated/garbled data."""
    rec_len, maj, _minor = struct.unpack_from("<LHH", buf, offset)
    if rec_len < 60 or offset + rec_len > len(buf):
        raise ValueError("bad record length %d at offset %d" % (rec_len, offset))
    if maj == 2:
        (file_ref, parent_ref, usn, ts, reason, _si, _sid, attr,
         name_len, name_off) = struct.unpack_from("<QQqqLLLLHH", buf, offset + 8)
    elif maj == 3:
        file_ref = bytes(buf[offset + 8:offset + 24])
        parent_ref = bytes(buf[offset + 24:offset + 40])
        (usn, ts, reason, _si, _sid, attr, name_len, name_off) = \
            struct.unpack_from("<qqLLLLHH", buf, offset + 40)
    else:
        return None
    if name_off + name_len > rec_len:
        raise ValueError("file name outside record at offset %d" % offset)
    name = bytes(buf[offset + name_off: offset + name_off + name_len]).decode(
        "utf-16-le", errors="replace")
    return {"record_length": rec_len, "major": maj, "file_ref": file_ref,
            "parent_ref": parent_ref, "usn": usn, "timestamp": ts,
            "reason": reason, "attributes": attr, "name": name}


def iter_buffer(buf):
    """Yield (offset, rec_or_None, error_or_None) for each record in one
    FSCTL_READ_USN_JOURNAL output buffer (after the 8-byte NextUsn)."""
    offset = 8
    while offset + 4 <= len(buf):
        rec_len = struct.unpack_from("<L", buf, offset)[0]
        if rec_len == 0:
            break
        try:
            yield offset, parse_record(buf, offset), None
        except Exception as exc:          # noqa: BLE001 -- reported per record
            yield offset, None, exc
            if rec_len < 8 or offset + rec_len > len(buf):
                return                    # can't trust the length; abandon buffer
        offset += rec_len


def mft_index(ref):
    if isinstance(ref, (bytes, bytearray)):
        ref = int.from_bytes(ref[:8], "little")
    return ref & 0x0000FFFFFFFFFFFF


# --------------------------------------------------------------------------- #
# Volume / journal (Windows)
# --------------------------------------------------------------------------- #
def volume_info(root):
    """Return (volume_serial '%08X', filesystem name). Uses the mounted
    image's boot sector via GetVolumeInformation."""
    info = win32api.GetVolumeInformation(root)
    return "%08X" % (info[1] & 0xFFFFFFFF), info[4]


def open_volume(root):
    return win32file.CreateFile(drive_root_to_device(root), GENERIC_READ,
                                FILE_SHARE_ALL, None, OPEN_EXISTING, 0, None)


def query_journal(h_vol):
    out = win32file.DeviceIoControl(h_vol, FSCTL_QUERY_USN_JOURNAL, None, 80)
    return parse_journal_data(bytes(out))


def usnjrnl_present(root):
    """Does $Extend\\$UsnJrnl exist on the volume? Access-denied counts as
    present (the name resolved). Used to tell a disabled journal from a
    missing one (D4)."""
    path = root.rstrip("\\") + "\\$Extend\\$UsnJrnl"
    try:
        os.stat(path)
        return True
    except PermissionError:
        return True
    except OSError as exc:
        return getattr(exc, "winerror", None) in (ERROR_ACCESS_DENIED, 32)


def detect_journal_state(root, h_vol):
    """Return (state, JournalData_or_None, detail).
    Raises JournalError for an unusable/garbled journal or a mount that does
    not pass the USN IOCTLs through."""
    try:
        jd = query_journal(h_vol)
    except JournalError:
        raise
    except Exception as exc:       # noqa: BLE001
        err = winerror_of(exc)
        if err in (ERROR_JOURNAL_NOT_ACTIVE, ERROR_JOURNAL_DELETE_IN_PROGRESS):
            if usnjrnl_present(root):
                return STATE_DISABLED, None, (
                    "journal not active (winerror %d) but $Extend\\$UsnJrnl present; "
                    "records cannot be read through FSCTL_READ_USN_JOURNAL" % err)
            return STATE_MISSING, None, "no USN journal on volume (winerror %d)" % err
        raise JournalError("FSCTL_QUERY_USN_JOURNAL failed: %r -- run "
                           "usnproc_verify.py to check the mount tool" % (exc,))
    if jd.next_usn < jd.first_usn:
        raise JournalError("journal bounds invalid: FirstUsn=%d > NextUsn=%d"
                           % (jd.first_usn, jd.next_usn))
    if jd.first_usn == jd.next_usn:
        return STATE_EMPTY, jd, "journal present with no records"
    return STATE_NORMAL, jd, "journal present"


def read_buffers(h_vol, journal_id, start_usn, stop_usn):
    """Single-pass finite read (Q6). Yields raw output buffers until the
    journal's NextUsn reaches stop_usn (captured at start) or a read returns
    no records. Raises JournalError on an IOCTL failure."""
    usn = start_usn
    while usn < stop_usn:
        try:
            out = bytes(win32file.DeviceIoControl(
                h_vol, FSCTL_READ_USN_JOURNAL, build_read_input(journal_id, usn),
                READ_BUFFER))
        except Exception as exc:   # noqa: BLE001
            raise JournalError("FSCTL_READ_USN_JOURNAL at USN %d failed: %r" % (usn, exc))
        if len(out) < 8:
            raise JournalError("truncated read buffer (%d bytes) at USN %d" % (len(out), usn))
        next_usn = struct.unpack_from("<q", out, 0)[0]
        if len(out) == 8 or next_usn <= usn:
            return
        yield out
        usn = next_usn


def iterate_records(h_vol, journal_id, start_usn, stop_usn):
    """Yield (rec_or_None, error_or_None, offset_desc) for every record in
    [start_usn, stop_usn). Records with usn >= stop_usn are dropped."""
    for buf in read_buffers(h_vol, journal_id, start_usn, stop_usn):
        for offset, rec, err in iter_buffer(buf):
            if rec is not None and rec["usn"] >= stop_usn:
                return
            yield rec, err, offset


# --------------------------------------------------------------------------- #
# Path resolution
# --------------------------------------------------------------------------- #
class ParentMap:
    """file_ref -> (parent_ref, name) learned from the journal itself.
    Built in a first pass over the journal so a record can be resolved even
    when its parent directory no longer exists in the image (D3)."""

    def __init__(self):
        self.entries = {}

    def note(self, rec):
        if rec and rec.get("name"):
            self.entries[rec["file_ref"]] = (rec["parent_ref"], rec["name"])

    def rebuild(self, ref, limit=512):
        """Return drive-relative '\\a\\b' for ref, or None if any link in the
        chain is unknown. Stops at the NTFS root (MFT index 5)."""
        parts = []
        seen = set()
        while mft_index(ref) != NTFS_ROOT_MFT_INDEX:
            if ref in seen or len(parts) >= limit:
                return None
            seen.add(ref)
            entry = self.entries.get(ref)
            if entry is None:
                return None
            ref, name = entry
            parts.append(name)
        return "\\" + "\\".join(reversed(parts)) if parts else ""


class PathResolver:
    """usnmon's PathResolver (parent-directory resolution via OpenFileById,
    cached on parent_ref) with an offline fallback to ParentMap."""

    CACHE_LIMIT = 20000

    def __init__(self, h_vol, drive_root, parent_map=None, opener=None):
        self.h_vol = h_vol
        self.drive_root = drive_root.rstrip("\\")
        self.cache = {}
        self.parent_map = parent_map or ParentMap()
        self._opener = opener or self._open_and_resolve
        self.last_error = None
        self.stats = {"resolved_live": 0, "resolved_from_journal": 0, "unresolved": 0}

    def resolve(self, rec):
        pref = rec["parent_ref"]
        name = rec["name"]
        if rec["reason"] & RENAME_DELETE_MASK:
            self.cache.pop(rec["file_ref"], None)
        parent = self.cache.get(pref)
        if parent is None:
            if mft_index(pref) == NTFS_ROOT_MFT_INDEX:
                parent = self.drive_root
            else:
                raw = self._opener(pref)
                if raw is not None:
                    self.stats["resolved_live"] += 1
                    parent = raw if raw.startswith(self.drive_root) else self.drive_root + raw
                else:
                    rebuilt = self.parent_map.rebuild(pref)
                    if rebuilt is None:
                        self.stats["unresolved"] += 1
                        return self.drive_root + "\\?\\" + name
                    self.stats["resolved_from_journal"] += 1
                    parent = self.drive_root + rebuilt
            if len(self.cache) > self.CACHE_LIMIT:
                self.cache.clear()
            self.cache[pref] = parent
        return parent.rstrip("\\") + "\\" + name

    def _open_and_resolve(self, ref):
        """From usnmon: OpenFileById(parent) -> GetFinalPathNameByHandle
        (changed to VOLUME_NAME_NONE for offline mounts)."""
        try:
            share = (win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE
                     | win32file.FILE_SHARE_DELETE)
            h = win32file.OpenFileById(self.h_vol, ref, 0, share, 0, None)
            try:
                # VOLUME_NAME_NONE: path without any volume prefix ("\\dir\\sub").
                # Offline mounters may not give the volume a DOS letter mapping,
                # so usnmon's flag 0 could return "\\?\\Volume{GUID}\\..." here.
                name = win32file.GetFinalPathNameByHandle(h, VOLUME_NAME_NONE)
                return name if name.startswith("\\") else "\\" + name
            finally:
                win32file.CloseHandle(h)
        except Exception as exc:   # noqa: BLE001
            self.last_error = exc
            return None
