# usnproc v0.0.1 — Design Lock

**Document version:** 1.3
**Date:** 2026-11-25 (v1.1 2026-11-24, v1.2–v1.3 2026-11-25; see Change log)
**Status:** Design locked — ready for implementation
**Target:** usnproc v0.0.1
**Maintainer:** YASDC, Inc.

---

## Purpose

Offline processing of a mounted NTFS forensic image → standalone `.evtx` file
compatible with the usnmon event schema + JSON sidecar manifest documenting
provenance.

**Not a live recorder. Not an analyzer chain-runner. Single job: produce a
portable, tool-compatible `.evtx` + manifest from an offline image.**

## Relationship to usnmon suite

- **usnmon** — live USN journal recorder (Windows service)
- **logmon** — Windows Event Log archive manager (rotation, retention)
- **usnproc** — *this project* — offline processor for already-acquired images

usnproc reuses usnmon's event contract (field order, EventData schema, event
IDs 100-106) so the same EvtxECmd maps and downstream analyzers work on
usnproc-produced archives without modification.

## Design decisions (locked)

### Q1 — Source machine identification

**MachineGuid from the mounted image's SOFTWARE hive** is the primary machine
identifier.

- Registry path: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
- Read from the offline hive file at
  `<drive>:\Windows\System32\config\SOFTWARE` on the mounted image
- Never from the analysis VM's live registry
- Used in output filename and in every emitted event's `MachineGuid` field
- VSN and image hash captured separately in the manifest for full provenance

**Filename pattern:**
- With `--case`: `{MachineGuid}_{CaseID}_{ProcessedUtc}.evtx`
- Without `--case`: `{MachineGuid}_{ProcessedUtc}.evtx`
- Manifest mirrors: `{MachineGuid}[_{CaseID}]_{ProcessedUtc}.manifest.json`
- `{ProcessedUtc}` = the run's processing time in compact UTC form,
  `YYYYMMDDTHHMMSSZ` (e.g. `20261124T192400Z`). It is the same value as the
  manifest's `processing_timestamp_utc`, and both files get the same one.
- **Never overwrite.** Each run makes new files. If a target file already
  exists (two runs in the same second), abort with exit 8.

### Q2 — Command-line surface

```
usnproc.py <drive-letter> [--case <case-id>]
                          [--case-notes <string>]
                          [--output <dir>]
                          [--image-path <path>]
                          [--image-hash <sha256>]
                          [--skip-image-hash]
                          [--no-image-path]
                          [--continue-on-error]
                          [--verbose | --quiet]
                          [--help] [--version]
```

**Behaviors:**
- Drive letter accepts `F`, `F:`, or `F:\` — normalized to `F:\` internally
  **and in all outputs** (for no ambiguity)
- `--case` is **optional**. Missing → no identifier, no note, ignored in
  filename/manifest. Supports both case-tracked and quick-triage workflows.
- `--case-notes` optional free-form string, embedded verbatim in manifest
- `--output` defaults to current working directory
- `--continue-on-error` silently records errors and moves on
- Default mode (no `--continue-on-error`): interactive prompt on first error
  (`y/N`), subsequent errors (`y`es / `i`gnore future / `n`o).
  "Ignore future" = continue-on-error behavior for the rest of the run.
- `--quiet` = reduced output volume; does NOT disable prompts
- `--verbose` and `--quiet` mutually exclusive
- `--help` and `--version` standard

**Explicitly NOT included:**
- No `--dry-run` (if validation succeeds, just do the work)
- No MachineGuid override (identity comes from the image, period)
- No `--no-manifest` (manifest is a first-class output)

### Q3 — Platform

**Windows 10+ only.** Same runtime environment as usnmon:
- Windows 10 or later
- Python 3
- pywin32
- python-registry

No cross-platform scope in v0.0.1.

### Q4 — Offline registry reading

**Primary: python-registry**
- Pure Python, parses raw hive files
- Zero analysis-VM contamination (never loads into live registry)
- One pip dependency, MIT licensed

**Fallback: RegLoadAppKey (pywin32)**
- Invoked only if python-registry fails to open the hive
- Loads hive in isolated namespace (not into HKLM)
- No cross-check between the two paths (only one runs per invocation)
- Manifest records which method succeeded

**On total failure:** hard error, abort processing, manifest documents both
attempts.

### Q5 — USN journal states

usnproc handles all four possible journal states with distinct exit codes:

| State | Behavior | Manifest flag |
|---|---|---|
| **1 — Normal** (journal + records) | Process normally | `complete` |
| **2 — Disabled** (file exists, disabled) | Read what records are present, no recovery attempts. If none: one status record (see below) | `partial` |
| **3 — Empty** (file exists, no records) | `.evtx` with one status record + manifest | `empty` |
| **4 — Missing** (no journal file) | `.evtx` with one status record + manifest | `aborted` |

**Status record (v1.2).** Whenever no USN records can be extracted (empty,
disabled, missing, or corrupt/unreadable, exit 4), the `.evtx` holds exactly
ONE record that says so, instead of being header-only or absent:

- EventID **919** (usnmon "no active USN journal") for empty, disabled and
  missing. EventID **916** (usnmon "drive/journal failure") for corrupt or
  unreadable. Level 3 (warning). This matches usnmon's operational events
  and its EvtxECmd maps (PayloadData1 = `Data[1]`).
- One `Data` string: `USN Journal logging not enabled, missing or corrupt.`
  followed by the state, the reason, the volume (source drive letter, Q12),
  VolumeSerial, Hostname and MachineGuid.
- TimeCreated: see Q11. Never the processing time.

**Truncation record (v1.3).** If reading stops partway (a journal read
fails, or the analyst stops at a parse-failure prompt) after some events
were written, those events are kept and ONE EventID **916** record is
appended at the end: `USN Journal read failed before the end of the
journal.` followed by the reason, the number of records written, the last
USN written, and the volume identity. TimeCreated = the last written
record's own USN Timestamp, so it sorts right after that event.

### Exit code scheme

| Code | Meaning |
|---|---|
| 0 | Success — normal processing complete (state 1) |
| 1 | Success with note — empty journal (state 3) |
| 2 | Success with note — disabled journal, partial records read (state 2) |
| 3 | Aborted — journal missing (state 4) |
| 4 | Aborted — journal corrupt/unparseable |
| 5 | Aborted — SOFTWARE hive unreadable (can't get MachineGuid) |
| 6 | Aborted — SYSTEM hive unreadable |
| 7 | Aborted — drive invalid or not NTFS |
| 8 | Aborted — output directory problem |
| 9 | Aborted — insufficient privileges |
| 10 | Aborted — command-line argument error |

`--continue-on-error` behavior: silently record error, continue processing;
final exit code reflects the worst non-fatal state reached.

Default mode error-prompt flow:
- First error: `Continue? [y/N]`
- Second and subsequent errors: `Continue? [y]es / [i]gnore future / [n]o`
- "Ignore future" = continue-on-error for the rest of the run
- `--quiet` does NOT disable prompts (quiet only reduces output verbosity)

### Q6 — Loop termination

**Single-pass finite loop terminating at NextUsn.** Not usnmon's live-follow
loop. Code-phase concern, no design decision needed beyond this note.

### Q7 — Forensic mount tool

**FTK Imager "File System / Read Only" mode** is the standardized mount tool.

- Primary candidate — widely used and simple
- Verification required before code phase: FTK Imager's mount driver must pass
  through `FSCTL_QUERY_USN_JOURNAL` and `FSCTL_READ_USN_JOURNAL` IOCTLs
- Verification script delivered: `usnproc_verify.py`
- Documented alternatives if FTK Imager doesn't work: Arsenal Image Mounter,
  OSFMount, imdisk

**The verification script works against any mounter** — code is mount-tool-
agnostic. The analyst picks a mounter, runs the verification once, knows if it
works.

### Q8 — Non-extractable identity fields

Fields that don't exist in the offline image (SourceIP, MAC, FQDN, etc.):

**Emit as empty string (`""`)**

- Same schema as usnmon output
- Downstream tools (EvtxECmd, Timeline Explorer, SIEM parsers) handle empty
  fields cleanly
- No literal placeholder strings that would break equality checks
- Minimal event size impact

### Q9 — Manifest schema

JSON sidecar — one file per usnproc run. Documents provenance of the derived
`.evtx`.

```json
{
  "manifest_schema_version": "1.0",
  "usnproc_version": "0.0.1",
  "processing_timestamp_utc": "2026-11-24T19:24:00Z",
  "processing_status": "complete | partial | empty | aborted",
  "status_detail": "...",

  "source_image": {
    "image_hash_sha256_computed": "...",
    "image_hash_sha256_examiner_supplied": "...",
    "image_hash_match": true,
    "image_path_at_processing": "E:\\cases\\...\\image.E01",
    "mount_tool": "unknown",
    "mount_drive_letter": "F:\\"
  },

  "source_machine_identity": {
    "machine_guid": "a1b2c3d4-...",
    "hostname": "...",
    "domain": "...",
    "os_product_name": "Windows 10 Pro",
    "os_current_build": "19045",
    "os_install_date_utc": "...",
    "registered_owner": "...",
    "registered_organization": "...",
    "machine_sid": "S-1-5-21-..."
  },

  "volume": {
    "drive_letter_at_processing": "F:\\",
    "volume_serial_number": "D66FD839",
    "filesystem": "NTFS"
  },

  "usn_journal": {
    "journal_id": "0x01d5a1b2c3d40001",
    "first_usn": 12345678,
    "next_usn": 87654321,
    "lowest_valid_usn": 0,
    "max_usn": 9223372036854775807,
    "max_size_bytes": 33554432,
    "allocation_delta_bytes": 524288,
    "records_extracted": 423891,
    "records_failed_parse": 0
  },

  "processing_environment": {
    "analysis_vm_hostname": "FORENSIC-VM-01",
    "analysis_vm_user": "analyst",
    "python_version": "3.12.1",
    "registry_read_method": "python-registry",
    "pywin32_version": "306",
    "python_registry_version": "1.4"
  },

  "case": {
    "case_id": "2026-0712-Ev003",
    "case_notes": "..."
  },

  "output": {
    "evtx_filename": "a1b2c3d4-..._2026-0712-Ev003_20261124T192400Z.evtx",
    "evtx_hash_sha256": "...",
    "evtx_size_bytes": 785432109
  },

  "errors_and_warnings": [
    {
      "timestamp_utc": "2026-11-24T19:24:03.142Z",
      "severity": "error | warning",
      "code": "USN_PARSE_FAIL",
      "detail": "Record at USN 12345 failed to parse: ..."
    }
  ]
}
```

**Image hash handling:**
- Always computed by default (hashing a large image takes minutes, but this is
  forensic work)
- `--image-hash <sha256>` input is a **verification check**, not a replacement
  for computation
- Mismatch between examiner-supplied and computed hashes is flagged loudly
  (interactive prompt in default mode, documented in manifest in all modes)
- Use case for mismatch flagging: **drive-labeling errors** — if the examiner's
  hash is for a drive labeled "Windows 10" but our extracted MachineGuid comes
  from a Windows 11 machine, something is mixed up in the chain of custody
- `--image-path` optional. If omitted, skip hashing with manifest note
  ("image hash skipped: image path not provided").
- `--skip-image-hash` opts out of computing hash even with `--image-path` supplied
- `--no-image-path` suppresses source image path from manifest (per-org policy)

### Q10 — Analysis VM identity placement

**Analysis VM identity in the manifest only.**

- `.evtx` contains only source-image-derived data
- Clean separation — analyst who receives the pair can trust the file's events
  represent the source system
- Manifest carries the "how it was processed" story
- Maximum portability of the `.evtx`

### Q11 — Event timestamps: journal data only

**Every event record is populated ONLY from the USN journal record and the
source image.** No processing, capture or "current" time appears anywhere in
any event.

- `TimeCreated` (event record header) = the USN record's own `Timestamp`
- `UtcTime` (EventData field) = the same USN record `Timestamp`, in usnmon's
  `YYYY-MM-DD HH:MM:SS.mmmZ` format
- `Qpc` / `HiResUtc` = `""` (see Implementation notes)
- The processing time appears ONLY in reporting outputs: the file names
  (Q1) and the manifest (`processing_timestamp_utc`, error/warning entries)
- Why: a processing time inside an event would put every event in a
  timeline at the same moment, on the wrong day
- No `ProcessedUtc` or similar field is added to the event schema
- Note for analysts: the USN `Timestamp` is when NTFS logged the change in
  the journal. It is not the file's `$STANDARD_INFORMATION` times.

**Status record time (v1.2).** When no USN record exists (Q5 status record),
TimeCreated = the source system's last shutdown time, read from the image's
SYSTEM hive (`ControlSet00X\Control\Windows\ShutdownTime`, a FILETIME).
If the image has no ShutdownTime, TimeCreated = 1601-01-01 (FILETIME zero).
Both choices are stated in the record text. The truncation record (Q5)
uses the last written USN record's Timestamp.

This is why usnproc uses a native EVTX writer instead of `ReportEvent`:
`ReportEvent` would stamp `TimeCreated` with the processing time and
`Computer` with the analysis VM's name.

### Q12 — Drive letter in event paths (v1.2)

**Paths use the drive letter the SOURCE system used for this volume**, not
the analysis VM's mount letter. Mount letters change from machine to machine;
the source letter matches what live usnmon would have recorded on that system
and what other artifacts from the image show.

- Source letter = the drive in `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot`
  (e.g. `C:\Windows` → `C:\`). usnproc needs the SOFTWARE hive on the
  volume, so the volume is always that system's Windows volume.
- If SystemRoot is missing (v1.3): the volume's own **VolumeSerial** takes
  the place of the letter, e.g. `D66FD839:\Users\...`, plus a manifest
  warning (`SOURCE_DRIVE_LETTER_UNKNOWN`). The VolumeSerial comes from the
  image's boot sector, so it is the same on every analysis machine. The
  mount letter is never used in events.
- The manifest records both: `volume.drive_letter_at_processing` (mount
  letter) and `volume.drive_letter_on_source_system`, with its basis.
- The volume is also identified in every event by `VolumeSerial`.

## Implementation notes

### QPC / HiResUtc fields

usnmon's event schema includes `Qpc` and `HiResUtc` fields from the recording
machine's QueryPerformanceCounter. These are meaningless for offline processing
of records that originated on a different machine at a different time.

**Decision:** emit as empty strings with manifest note explaining why.

### Source identity extraction

For fields usnproc must pull from the mounted image:

| Field | Source |
|---|---|
| MachineGuid | SOFTWARE hive → `Microsoft\Cryptography\MachineGuid` |
| Hostname | SYSTEM hive → `ControlSet00X\Control\ComputerName\ComputerName` |
| Domain | SYSTEM hive → `ControlSet00X\Services\Tcpip\Parameters\Domain` |
| MachineSID | SAM hive |
| OSBuild | SOFTWARE hive → `Microsoft\Windows NT\CurrentVersion\CurrentBuild` |
| OS Product Name | SOFTWARE hive → `Microsoft\Windows NT\CurrentVersion\ProductName` |
| Install date | SOFTWARE hive → `Microsoft\Windows NT\CurrentVersion\InstallDate` |
| VolumeSerial | Boot sector of mounted image (via `GetVolumeInformation`) |
| JournalId | From `FSCTL_QUERY_USN_JOURNAL` on mounted volume |
| FQDN | Partial reconstruction from hostname + domain |
| SourceIP | Not extractable (network state ephemeral) — empty string |
| MAC | Registry-cached, may be stale — empty string in v0.0.1 |

### Provider identification

Events emitted by usnproc may use the same provider name as usnmon
(`USNJournalMonitor`) to ensure EvtxECmd maps work without modification. This
is a code-phase decision — alternative is `USNJournalMonitor.Offline` for
downstream disambiguation. Trade-off between tool compatibility and
offline-vs-live attribution.

**Preliminary decision:** use same provider name (`USNJournalMonitor`) for
EvtxECmd map compatibility. Record offline origin in the manifest instead.

## Open items (noted for code phase, not design)

### Pre-code verification required

- **FTK Imager IOCTL pass-through:** run `usnproc_verify.py` against a test
  image mounted with FTK Imager File System / Read Only mode. Confirm the
  required checks (1–9) pass. Since v1.3 the script runs 13 checks, and
  checks 10–13 only warn.
- **python-registry library API:** confirm current API hasn't drifted since
  initial research.

### Related project open items (not in scope for v0.0.1)

**usnmon Pass 3:**
- Error 1181 tight-retry storm (cursor aged out of ring → engine spams 916
  warnings 1/sec forever instead of emitting 923 and resetting cursor)

**logmon Pass 3:**
- Boundary never advances after empty extraction
- WARNING severity on empty-channel messages (should be INFO)
- False-positive EXTERNAL CLEAR on cold boot after long shutdown

## Ready-to-use artifacts

- **usnproc_verify.py** — mount compatibility check (originally 7 checks;
  13 since v1.3: elevation, SYSTEM hive, SAM SID, SystemRoot, ShutdownTime
  and `$UsnJrnl` visibility added)
- **test_usnproc_verify.py** — mock suite covering all branch logic (41
  tests originally, 56 since v1.3)
- This document — complete design lock

## Workflow

Once implementation is complete, the analyst workflow will be:

1. Acquire forensic image using existing tools (FTK Imager, Guymager, etc.)
2. Mount image read-only in forensic analysis VM (FTK Imager File System mode)
3. One-time: run `usnproc_verify.py F` to confirm mount compatibility
4. Run `usnproc.py F --case 2026-0712-Ev003`
5. usnproc extracts source machine identity, walks the USN journal, produces:
   - `{MachineGuid}_{CaseID}_{ProcessedUtc}.evtx` — ready for EvtxECmd / Timeline Explorer
   - `{MachineGuid}_{CaseID}_{ProcessedUtc}.manifest.json` — chain of custody
6. Analyst runs their existing analyzer tools against the `.evtx`

## Design freeze

This document locks the design for v0.0.1. Future revisions will create a
new version of this document; the Q&A decisions above are not open for
re-litigation without a specific technical reason to revisit.

---

**End of DESIGN_LOCK v1.0**

## Change log

- **v1.3 (2026-11-25):** Q5: a read that stops partway appends one 916
  truncation record, timed at the last written USN record. Q12: when the
  source letter is unknown, paths use the VolumeSerial (`D66FD839:\`)
  instead of `?:\`. usnproc_verify.py gained checks 8–13 for the data
  usnproc now relies on.
- **v1.2 (2026-11-25):** Q5: empty, disabled, missing and corrupt journals
  each produce an `.evtx` holding one status record (EventID 919 / 916),
  instead of header-only or no `.evtx`. Q11: the status record's TimeCreated
  = the image's last ShutdownTime (1601-01-01 if absent). Added Q12: event
  paths use the source system's drive letter (from SystemRoot), `?:` if
  unknown, never the analysis mount letter.
- **v1.1 (2026-11-24):** Q1 file names now include the processing time
  (`_{ProcessedUtc}`, compact UTC `YYYYMMDDTHHMMSSZ`) so repeat runs never
  overwrite. Added Q11: event records contain only USN journal and
  source-image data; processing time appears only in file names and the
  manifest. The native EVTX writer is required to meet Q10/Q11.
- **v1.0 (2026-11-24):** Initial design lock.
