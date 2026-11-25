"""Test fakes: synthetic USN records, a fake volume serving the USN IOCTLs,
and fake registry hives. Lets the whole pipeline run on any OS."""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usnproc_journal as journal  # noqa: E402

ROOT_REF = (1 << 48) | 5          # NTFS root dir, seq 1


def ref(index, seq=1):
    return (seq << 48) | index


def v2_record(usn, file_ref, parent_ref, name, reason, timestamp, attr=0x20):
    nb = name.encode("utf-16-le")
    name_off = 60
    rec_len = (name_off + len(nb) + 7) & ~7
    b = bytearray(rec_len)
    struct.pack_into("<LHH", b, 0, rec_len, 2, 0)
    struct.pack_into("<QQqqLLLLHH", b, 8, file_ref, parent_ref, usn, timestamp,
                     reason, 0, 0, attr, len(nb), name_off)
    b[name_off:name_off + len(nb)] = nb
    return bytes(b)


def v3_record(usn, file_ref, parent_ref, name, reason, timestamp, attr=0x20):
    nb = name.encode("utf-16-le")
    name_off = 76
    rec_len = (name_off + len(nb) + 7) & ~7
    b = bytearray(rec_len)
    struct.pack_into("<LHH", b, 0, rec_len, 3, 0)
    b[8:24] = file_ref.to_bytes(16, "little")
    b[24:40] = parent_ref.to_bytes(16, "little")
    struct.pack_into("<qqLLLLHH", b, 40, usn, timestamp, reason, 0, 0, attr,
                     len(nb), name_off)
    b[name_off:name_off + len(nb)] = nb
    return bytes(b)


class FakeJournal:
    """Holds records keyed by USN; serves FSCTL query/read like NTFS."""

    def __init__(self, records, journal_id=0x01D5A1B2C3D40001, per_read=3,
                 query_error=None, read_error_at=None):
        self.records = records                     # list of raw record bytes
        self.journal_id = journal_id
        self.per_read = per_read
        self.query_error = query_error
        self.read_error_at = read_error_at
        self.usns = [struct.unpack_from("<q", r, 24 if r[4] == 2 else 40)[0]
                     for r in records]
        if records:
            self.first = self.usns[0]
            self.next = self.usns[-1] + len(records[-1])
        else:
            self.first = self.next = 4096

    def query(self):
        if self.query_error:
            raise self.query_error
        return struct.pack("<QqqqqQQ", self.journal_id, self.first, self.next,
                           0, 0x7FFFFFFFFFFFFFFF, 32 * 1024 * 1024, 512 * 1024)

    def read(self, inbuf):
        start_usn, _mask, _roc, _to, _bw, jid = struct.unpack("<qLLQQQ", inbuf)
        assert jid == self.journal_id
        if self.read_error_at is not None and start_usn >= self.read_error_at:
            e = OSError("read failed")
            e.winerror = 1181
            raise e
        idx = [i for i, u in enumerate(self.usns) if u >= start_usn][:self.per_read]
        if not idx:
            return struct.pack("<q", self.next)
        last = idx[-1]
        nxt = self.usns[last + 1] if last + 1 < len(self.usns) else self.next
        return struct.pack("<q", nxt) + b"".join(self.records[i] for i in idx)


class FakeWin32File:
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 1, 2, 4

    def __init__(self, fj, live_paths=None):
        self.fj = fj
        self.live_paths = live_paths or {}         # ref -> "\\dir"

    def DeviceIoControl(self, h, code, inbuf, size):
        if code == journal.FSCTL_QUERY_USN_JOURNAL:
            return self.fj.query()
        if code == journal.FSCTL_READ_USN_JOURNAL:
            return self.fj.read(inbuf)
        raise AssertionError(hex(code))

    def CreateFile(self, *a):
        return "HVOL"

    def OpenFileById(self, h, r, *a):
        if r in self.live_paths:
            return ("H", r)
        raise OSError("not found")

    def GetFinalPathNameByHandle(self, h, flags):
        return self.live_paths[h[1]]

    def CloseHandle(self, h):
        pass


class FakeHive:
    def __init__(self, values):
        self.values = {(k.lower(), n.lower()): v for (k, n), v in values.items()}
        self.closed = False

    def get_value(self, key, name):
        return self.values.get((key.lower(), name.lower()))

    def subkeys(self, key):
        return []

    def close(self):
        self.closed = True


def sam_v_blob(a=1111111111, b=2222222222, c=3333333333):
    return b"\x00" * 40 + bytes([1, 4, 0, 0, 0, 0, 0, 5]) + struct.pack("<IIII", 21, a, b, c)


SHUTDOWN_FT = 133_600_000_000_000_000   # 2024-05-12, from the image
GUID = "a1b2c3d4-e5f6-7890-abcd-ef0123456789"

SOFTWARE = {
    (r"Microsoft\Cryptography", "MachineGuid"): GUID,
    (r"Microsoft\Windows NT\CurrentVersion", "ProductName"): "Windows 10 Pro",
    (r"Microsoft\Windows NT\CurrentVersion", "CurrentBuild"): "19045",
    (r"Microsoft\Windows NT\CurrentVersion", "InstallDate"): 1700000000,
    (r"Microsoft\Windows NT\CurrentVersion", "RegisteredOwner"): "owner",
    (r"Microsoft\Windows NT\CurrentVersion", "RegisteredOrganization"): "org",
    (r"Microsoft\Windows NT\CurrentVersion", "SystemRoot"): "C:\\WINDOWS",
}
SYSTEM = {
    ("Select", "Current"): 1,
    (r"ControlSet001\Control\ComputerName\ComputerName", "ComputerName"): "SRCHOST",
    (r"ControlSet001\Services\Tcpip\Parameters", "Domain"): "corp.example",
    (r"ControlSet001\Control\Windows", "ShutdownTime"): struct.pack("<Q", SHUTDOWN_FT),
}
SAM = {(r"SAM\Domains\Account", "V"): sam_v_blob()}
