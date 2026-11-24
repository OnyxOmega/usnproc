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

**Design phase.** The design is locked (see [DESIGN_LOCK.md](DESIGN_LOCK.md)).
Verification script delivered. Main implementation forthcoming.

## Related

- [usnmon](https://github.com/OnyxOmega/USNJournal2EventLog) — live USN journal
  recorder (Windows service)
- [logmon](https://github.com/OnyxOmega/logmon) — Windows Event Log archive
  manager

## License

PolyForm Noncommercial 1.0.0 — YASDC, Inc. Free for non-commercial use.
