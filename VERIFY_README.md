# usnproc_verify

Verification script that checks whether a mounted NTFS forensic image is
compatible with usnproc. Runs thirteen checks against the mounted volume
and reports pass/fail per check, plus a summary. Checks 1–9 are required.
Checks 10–13 only warn, because usnproc has a fallback for each.

## Purpose

Different forensic mounters (FTK Imager, Arsenal Image Mounter, OSFMount,
imdisk, etc.) present mounted images with different capabilities. Some pass
through USN journal IOCTLs; some don't. Before running usnproc against an
image, this script confirms the mount will work.

## Usage

```
python usnproc_verify.py F
python usnproc_verify.py F:
python usnproc_verify.py F:\
```

All three forms are accepted and normalized to `F:\` internally.

## Requirements

- Windows 10 or later
- Python 3
- `pywin32` (`pip install pywin32`)
- `python-registry` (`pip install python-registry`)

## What it checks

1. **Drive letter is mounted and accessible** — `GetDriveType` succeeds and
   returns a valid drive type
2. **Filesystem is NTFS** — `GetVolumeInformation` returns "NTFS"
3. **FSCTL_QUERY_USN_JOURNAL succeeds** — mount driver exposes USN journal
   metadata (JournalId, FirstUsn, NextUsn, MaxSize, AllocationDelta)
4. **FSCTL_READ_USN_JOURNAL succeeds** — can actually pull records (or
   confirms journal is legitimately empty)
5. **Registry hive files present** — `Windows\System32\config\SOFTWARE`
   and `SYSTEM` both exist
6. **python-registry importable and can open SOFTWARE hive** — the primary
   read path for MachineGuid extraction works
7. **MachineGuid extractable** — the value at
   `Microsoft\Cryptography\MachineGuid` is readable
8. **Running elevated** — usnproc opens the raw volume, which needs an
   Administrator prompt (usnproc exit 9 otherwise)
9. **SYSTEM hive readable** — opens via python-registry, and the hostname
   (`ControlSet00X\Control\ComputerName\ComputerName`) is present
   (usnproc exit 6 otherwise)
10. **Machine SID** *(warning only)* — read from the SAM hive. If it
    can't be read, usnproc leaves `MachineSID` empty.
11. **Source drive letter** *(warning only)* — from SOFTWARE `SystemRoot`
    (e.g. `C:\Windows` → `C:\`). usnproc uses it in event paths. If it's
    missing, usnproc puts the VolumeSerial in its place
    (`D66FD839:\...`).
12. **ShutdownTime** *(warning only)* — from SYSTEM
    `Control\Windows\ShutdownTime`. usnproc uses it as the time of the
    status record it writes for an unusable journal. If it's missing, that
    record is dated 1601-01-01.
13. **`$Extend\$UsnJrnl` visible** *(warning only)* — lets usnproc tell
    a disabled journal from a missing one. If it isn't visible, a disabled
    journal is reported as missing.

## Exit codes

- `0` = all checks passed (mount is compatible with usnproc)
- `1` = one or more checks failed (mount is NOT compatible)
- `2` = command-line error (bad drive-letter argument, etc.)

## Sample output (all checks pass)

```
usnproc mount verification: F:\
============================================================
[OK]    Drive F:\ mounted and accessible
        drive type FIXED
[OK]    Filesystem is NTFS
[OK]    FSCTL_QUERY_USN_JOURNAL succeeded
        JournalId:       0x01d5a1b2c3d40001
        FirstUsn:        12345678
        NextUsn:         87654321
        LowestValidUsn:  0
        MaxUsn:          9223372036854775807
        MaxSize:         33,554,432 bytes (32.0 MB)
        AllocationDelta: 524,288 bytes
[OK]    FSCTL_READ_USN_JOURNAL succeeded
        IOCTL succeeded (at least one record read; 96 bytes of record data in first batch)
[OK]    Registry hive files present
          SOFTWARE: 52,428,800 bytes
          SYSTEM: 33,554,432 bytes
[OK]    python-registry importable
[OK]    SOFTWARE hive opened via python-registry
[OK]    MachineGuid extracted from SOFTWARE hive
        MachineGuid: a1b2c3d4-e5f6-7890-abcd-ef0123456789
[OK]    running elevated (Administrator)
[OK]    SYSTEM hive opened (ControlSet001)
        Hostname: SRCHOST
[OK]    machine SID read from SAM
        Machine SID: S-1-5-21-1111111111-2222222222-3333333333
[OK]    SystemRoot = C:\WINDOWS
        Source drive letter: C:\
[OK]    ShutdownTime read
        ShutdownTime: 2024-05-12 15:06:40Z
[OK]    $Extend\$UsnJrnl visible

============================================================
Summary: 14 passed, 0 failed, 0 skipped

VERIFICATION PASSED -- mount is compatible with usnproc.
```

## Sample output (mount driver doesn't support USN IOCTLs)

```
usnproc mount verification: F:\
============================================================
[OK]    Drive F:\ mounted and accessible
        drive type FIXED
[OK]    Filesystem is NTFS
[FAIL]  FSCTL_QUERY_USN_JOURNAL failed
        FSCTL_QUERY_USN_JOURNAL failed (winerror 1 -- ERROR_INVALID_FUNCTION: mount driver does not expose USN journal IOCTLs)
[SKIP]  Journal-read check skipped (query failed)
[OK]    Registry hive files present
          SOFTWARE: 52,428,800 bytes
          SYSTEM: 33,554,432 bytes
[OK]    python-registry importable
[OK]    SOFTWARE hive opened via python-registry
[OK]    MachineGuid extracted from SOFTWARE hive
        MachineGuid: a1b2c3d4-e5f6-7890-abcd-ef0123456789
[OK]    running elevated (Administrator)
[OK]    SYSTEM hive opened (ControlSet001)
        Hostname: SRCHOST
[OK]    machine SID read from SAM
        Machine SID: S-1-5-21-1111111111-2222222222-3333333333
[WARN]  SystemRoot not found; usnproc will use the VolumeSerial in place of the drive letter in paths
[OK]    ShutdownTime read
        ShutdownTime: 2024-05-12 15:06:40Z
[OK]    $Extend\$UsnJrnl visible

============================================================
Summary: 11 passed, 1 failed, 1 skipped

VERIFICATION FAILED -- this mount is NOT compatible with usnproc.
Consider trying a different mount tool (FTK Imager, Arsenal Image Mounter, OSFMount, imdisk).
```

## Common failure modes and interpretation

| Failure | Meaning | Recommended action |
|---|---|---|
| `winerror 1179 (JOURNAL_NOT_ACTIVE)` | Source volume has no active USN journal | The mount works, but there are no records. usnproc still runs and writes one 919 status record (exit 2 if disabled, 3 if missing) |
| `CreateFile ... access denied (winerror 5)` / `NOT elevated` | Not running as Administrator | Re-run from an elevated prompt |
| `ComputerName not found` / `could not open SYSTEM hive` | SYSTEM hive damaged or not a full system volume | usnproc will stop with exit 6; check the image |
| `winerror 1 (INVALID_FUNCTION)` | Mount driver doesn't pass through IOCTLs | Try a different mounter (Arsenal, OSFMount) |
| `Filesystem is FAT32/exFAT/etc.` | Not an NTFS volume | Wrong image or wrong mount mode |
| `Drive UNKNOWN` | Mount didn't complete | Re-mount the image |
| `SOFTWARE hive not found` | Not a Windows system volume | Wrong partition mounted |
| `python-registry not installed` | Missing dependency | `pip install python-registry` |
| `[WARN]` lines (checks 10–13) | Optional data missing from the image | usnproc runs and uses the fallback named in the warning |

## Testing which mounters work

Recommended workflow: mount a known-good NTFS image with each mounter,
run `usnproc_verify.py` against the mount, and record the result.
Then decide which mounter to standardize on for your workflow.

Known candidates:

- **FTK Imager** (File System / Read Only mode) — primary candidate
- **Arsenal Image Mounter** — widely used in DFIR
- **OSFMount** — free, PassMark
- **imdisk** — free, open source
- **Windows native attach VHD** — only for .vhd/.vhdx images

## Test suite

`test_usnproc_verify.py` contains 56 unit tests covering drive-letter
normalization, drive presence checks, NTFS detection, FSCTL query/read
success and failure paths, hive presence detection, checks 8–13, and
orchestrator control flow including a full 14-check pass. All tests use mocks and can run on any platform (including
non-Windows for CI purposes).

Run with:

```
python test_usnproc_verify.py
```

## License

PolyForm Noncommercial 1.0.0 — YASDC, Inc.
