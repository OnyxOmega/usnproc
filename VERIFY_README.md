# usnproc_verify

Verification script that checks whether a mounted NTFS forensic image is
compatible with usnproc. Runs seven checks against the mounted volume and
reports pass/fail per check, plus a summary.

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

============================================================
Summary: 8 passed, 0 failed, 0 skipped

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

============================================================
Summary: 6 passed, 1 failed, 1 skipped

VERIFICATION FAILED -- this mount is NOT compatible with usnproc.
Consider trying a different mount tool (FTK Imager, Arsenal Image Mounter, OSFMount, imdisk).
```

## Common failure modes and interpretation

| Failure | Meaning | Recommended action |
|---|---|---|
| `winerror 1179 (JOURNAL_NOT_ACTIVE)` | Source volume has no USN journal | Image is real but source system had no journal; usnproc cannot process it |
| `winerror 1 (INVALID_FUNCTION)` | Mount driver doesn't pass through IOCTLs | Try a different mounter (Arsenal, OSFMount) |
| `Filesystem is FAT32/exFAT/etc.` | Not an NTFS volume | Wrong image or wrong mount mode |
| `Drive UNKNOWN` | Mount didn't complete | Re-mount the image |
| `SOFTWARE hive not found` | Not a Windows system volume | Wrong partition mounted |
| `python-registry not installed` | Missing dependency | `pip install python-registry` |

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

`test_usnproc_verify.py` contains 41 unit tests covering drive-letter
normalization, drive presence checks, NTFS detection, FSCTL query/read
success and failure paths, hive presence detection, and orchestrator
control flow. All tests use mocks and can run on any platform (including
non-Windows for CI purposes).

Run with:

```
python test_usnproc_verify.py
```

## License

PolyForm Noncommercial 1.0.0 — YASDC, Inc.
