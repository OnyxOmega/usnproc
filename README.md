# usnproc — Offline USN Journal Processor

**Convert a mounted NTFS forensic image's USN journal into a standard Windows
Event Log (.evtx) file for analysis with the DFIR tools you already use.**

Maintained by YASDC, Inc. · License: [PolyForm Noncommercial 1.0.0](LICENSE)

> Companion to [usnmon](https://github.com/OnyxOmega/USNJournal2EventLog) (live
> recorder) and [logmon](https://github.com/OnyxOmega/logmon) (archive manager).
> usnproc is the **offline** tool in the suite — it processes already-acquired
> images, after the fact.

---

## Why

NTFS's USN change journal is a goldmine for forensic investigators — file
creates, modifies, deletes, renames, security changes, all timestamped. The
problem: on a typical Windows workstation the journal ring is ~32 MB, which
holds less than one day of history. By the time an investigator arrives with
an image, the on-disk journal data is still there, but getting to it is awkward
— custom parsers, scripts, or digging through `fsutil usn readjournal` output.

usnproc gives you a cleaner path. Point it at a mounted read-only image, it
walks the USN journal and produces a standard `.evtx` file using the same event
contract as usnmon. Open it in **EvtxECmd**, **Timeline Explorer**, **Event Log
Explorer**, **Velociraptor**, or any SIEM — the tools you already know, no
custom parser required.

## Scope

- **Input:** a mounted NTFS forensic image (read-only), on a Windows analysis VM
- **Output:** a standalone `.evtx` file + JSON chain-of-custody manifest
- **Not included:** image acquisition, analysis, reporting — those are your
  existing workflow

## Status

**v0.0.1 implemented, pending field testing on Windows.** The design is
locked (see [DESIGN_LOCK.md](DESIGN_LOCK.md) v1.2), and the build follows
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). The test suite runs on any
OS with simulated volumes and hives. It still has to be run against a real
image mounted with FTK Imager.

## Usage

Run from an **elevated** prompt on a Windows 10+ analysis VM:

```
pip install -r requirements.txt
python usnproc_verify.py F                                  # one-time mount check
python usnproc.py F --case 2026-0712-Ev003 --image-path E:\cases\img.dd --output E:\out
```

Outputs, never overwritten:

- `{MachineGuid}[_{CaseID}]_{YYYYMMDDTHHMMSSZ}.evtx` holds one event per USN
  record (IDs 100–105, provider `USNJournalMonitor`, usnmon's EventData
  layout). Use usnmon's EvtxECmd `maps/` to read it.
- `{MachineGuid}[_{CaseID}]_{YYYYMMDDTHHMMSSZ}.manifest.json` is the
  chain-of-custody manifest.

Events contain **only USN journal and source-image data**. `TimeCreated` and
`UtcTime` are the USN record's own timestamp, and `Computer` is the source
machine's hostname. Paths use the drive letter the source system used (from
SystemRoot, e.g. `C:\Users\...`), not the mount letter. The processing time
appears only in the file names and the manifest.

If the journal is empty, disabled, missing or unreadable, the `.evtx` holds
one status record (EventID 919 or 916) saying "USN Journal logging not
enabled, missing or corrupt", timed at the source system's last shutdown.

Options: `--case`, `--case-notes`, `--output`, `--image-path`,
`--image-hash`, `--skip-image-hash`, `--no-image-path`,
`--continue-on-error`, `--verbose` or `--quiet`, `--version`. The exit codes
(0–10) are listed in `usnproc.py` and DESIGN_LOCK Q5.

## Development

```
python -m unittest discover -s tests     # usnproc tests (any OS)
python test_usnproc_verify.py            # verify-script tests
```

`pip install python-evtx` turns on the tests that read the `.evtx` back.

## Related

- [usnmon](https://github.com/OnyxOmega/USNJournal2EventLog) — live USN journal
  recorder (Windows service)
- [logmon](https://github.com/OnyxOmega/logmon) — Windows Event Log archive
  manager

## License

PolyForm Noncommercial 1.0.0 — YASDC, Inc. Free for non-commercial use.
