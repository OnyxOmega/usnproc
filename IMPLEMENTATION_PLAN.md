# usnproc v0.0.1 — Implementation Plan

> Status: draft for review · Date: 2026-11-24
> Inputs: `DESIGN_LOCK.md` v1.0 (this repo) and usnmon at
> `OnyxOmega/USNJournal2EventLog` commit `bd09f19` (`usnmon.py`, `usn_common.py`,
> `EVENT_ID.md`, `maps/`).
> This plan follows the design lock. It does not reopen Q1–Q10. Section 3
> lists the places where the lock is silent, or where the reused code behaves
> differently offline. Each one needs a decision before or during coding.

---

## 1. What we're building

`usnproc.py` is a single-pass command-line program for a Windows analysis VM:

1. Take the drive letter of a read-only, mounted NTFS image.
2. Read the source machine's identity from that image's offline registry
   hives (SOFTWARE, SYSTEM, SAM).
3. Query the volume's USN journal, then read every record from `FirstUsn` up
   to the `NextUsn` captured at start.
4. Turn each record into a usnmon-contract event (IDs 100–105, provider
   `USNJournalMonitor`, same EventData layout).
5. Write a standalone `{MachineGuid}[_{CaseID}]_{ProcessedUtc}.evtx`
   (see D6).
6. Write a `{MachineGuid}[_{CaseID}]_{ProcessedUtc}.manifest.json`
   chain-of-custody manifest
   (schema 1.0).
7. Exit with one of the 11 locked codes (0–10).

---

## 2. What we reuse from usnmon

| usnmon piece | Where | Reuse in usnproc |
|---|---|---|
| `EVENT_IDS`, `EVENT_FIELD_NAMES`, `PARAM_FIELDS`, `SCHEMA_VERSION` | `usn_common.py` | **As is.** This is the event contract, and the EvtxECmd maps depend on it. |
| `REASON_FLAGS`, `reason_text()`, `classify_event()` | `usn_common.py` | **As is.** Classification must match live usnmon exactly. |
| `build_event_strings()` | `usn_common.py` | **As is.** Produces the blob plus the 6 PARAM strings. |
| `FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL`, `FILE_SHARE_ALL` | `usnmon.py` L72–74 | **As is.** |
| `drive_root_to_device()`, `volume_serial()` | `usnmon.py` L280–288 | **As is.** |
| `query_journal()` | `usnmon.py` L318 | **Extend.** It currently returns 4 of the 7 `USN_JOURNAL_DATA_V0` fields. The manifest needs all 7, adding MaxUsn, MaximumSize and AllocationDelta. |
| `build_read_input()` | `usnmon.py` L328 | **As is.** BytesToWaitFor=0 and Timeout=0 already make every read return immediately. |
| `parse_record()` | `usnmon.py` L338 | **Change.** It throws away the record's `Timestamp`, which usnproc needs (see D2). Also keep `FileAttributes`. |
| `PathResolver` | `usnmon.py` L368 | **Reuse, plus an offline fallback** (see D3). |
| Read loop body | `usnmon.py` L611–631 | **Adapt** into a finite loop that stops at the captured NextUsn (Q6). Drop the cursor, sleep, stop-flag and self-write suppression. |
| `_handle_record()` | `usnmon.py` L721 | **Adapt.** Use the source-image identity, the record timestamp, and `Qpc`/`HiResUtc` = `""`. |
| `compute_machine_id()` | `usn_common.py` L304 | **As is**, with `instance_id=None`. An offline image has no cloud instance. |

**Not reused:** the service and SCM code, drive polling and classification,
device identity (500 series), operational events (9xx), the error trail, the
cursor and config files, `register_event_source()`, `emit_event()`
(ReportEvent; see D1), live MachineGuid/hostname lookups, QPC and HiResUtc,
and the stats and histogram helpers.

**How we take the code:** vendor a pinned copy of `usn_common.py` into this
repo, with a header naming the source repo and commit. Then copy the handful
of journal and record functions from `usnmon.py` into `usnproc_journal.py`.
usnmon is a separate repo and a live service, so a pinned copy keeps the
offline tool's output from changing silently when usnmon changes. A
contract-parity unit test (section 6) catches any drift.

---

## 3. Decisions needed (gaps the lock doesn't cover)

### Decision record (2026-11-24)

| # | Decision | Status |
|---|---|---|
| D1 | **Native EVTX writer**, option (a). No ReportEvent, no temporary channel. | Decided |
| D2 | Proposed: `TimeCreated` and `UtcTime` = the USN record timestamp. The conversion time goes only in the manifest and file name. | **Waiting for confirmation** |
| D3 | **Rebuild paths where possible** (OpenFileById, then the parent map built from journal records, then `?` for parts that can't be resolved). | Decided |
| D4 | As recommended: tell disabled and missing apart by whether `$UsnJrnl` exists. Raw `$J` read is a stretch goal, pending the verify results. | Decided |
| D5 | As recommended: hash the image file as given, label it a file hash, and add the E01 caveat to the mismatch message. | Decided |
| D6 | **Never overwrite.** Add the processing time to the file names so repeat runs make new files: `{MachineGuid}[_{CaseID}]_{YYYYMMDDTHHMMSSZ}.evtx` and the matching `.manifest.json`. The timestamp is `processing_timestamp_utc` in compact form, the same value in both names. If a file still exists (two runs in the same second) → exit 8. **This changes the Q1 file name in DESIGN_LOCK.md.** | Decided |

The original analysis of each option follows.

**D1 — How the `.evtx` is written. This is the biggest one.**
usnmon writes with `ReportEvent` into the live `FileSystem` channel. For
usnproc, that approach has three problems:
- every event's `<Computer>` would be the **analysis VM's** name, which
  breaks Q10 (the `.evtx` must hold only source-image data);
- `TimeCreated` would be the processing time, not when the change happened;
- registering a channel and source writes to the analysis VM's registry.

Options:
- **(a) Native EVTX writer (recommended).** A small pure-Python writer for
  the file header, 64 KB chunks, BinXML templates and CRC32 checksums. It
  writes exactly the `<System>` and `<EventData>` that usnmon's events
  render to, with `Computer` = the source hostname and `TimeCreated` = the
  USN record time. This needs the most work. We'd check it with
  `python-evtx` and EvtxECmd against a reference `.evtx` produced by usnmon
  (`diag/diag_evtx.py` already dumps that layout).
- (b) ReportEvent into a temporary channel, export with `wevtutil epl`, then
  remove the channel. Fast to build, but it breaks Q10 and touches the
  analysis VM.
- (c) Build with (b) first, then replace it with (a) before v0.0.1 ships.

**D2 — What `UtcTime` holds.** usnmon stamps `UtcTime` with the time it
captured the record (`now_utc_str()`). Offline, the only meaningful time is
the record's own `Timestamp` (a FILETIME). Recommendation: `UtcTime` = the
record timestamp, in the same `YYYY-MM-DD HH:MM:SS.mmmZ` format. Note this
in the manifest.

**D3 — Paths for deleted parent folders.** `OpenFileById` works on a
mounted image for directories that still exist. When the parent folder is
gone, usnmon writes `X:\?\name`. Offline we can do better: as we read, build
a `file_ref → (parent_ref, name)` map from the journal's own records, and
rebuild the path from that when `OpenFileById` fails. Recommendation:
include this in v0.0.1. It's small, and it really helps on older records.

**D4 — Disabled journal (state 2) vs missing journal (state 4).** When a
journal is disabled or being deleted, `FSCTL_QUERY_USN_JOURNAL` fails with
error 1179 or 1178. The IOCTL path then can't read any records, even if
`$Extend\$UsnJrnl:$J` still holds data. To "read what records are present"
we'd have to read `$J` raw (open `F:\$Extend\$UsnJrnl:$J`, skip the sparse
zeros, parse V2/V3 records). Recommendation: tell the states apart by
whether `$UsnJrnl` exists, and treat the raw `$J` read as a stretch goal.
Wait for the results of `usnproc_verify.py` on FTK Imager before deciding.

**D5 — Image hash vs E01 container.** With `--image-path` pointing at a
`.E01`, we hash the **container file**. An examiner's acquisition hash is
usually the hash of the **media** stored inside the E01, so the two will
never match and we'd raise a false alarm every time. Recommendation for
v0.0.1: hash the file as given, label the manifest field "file hash", and
say in the mismatch message that E01 media hashes aren't comparable. Media
hashing (pyewf) can come later.

**D6 — Existing output files.** Recommendation: never overwrite. If the
target `.evtx` or manifest already exists, stop with exit 8.

---

## 4. Program flow

```
main()
 ├─ parse_args()                         → exit 10 on bad arguments
 ├─ normalize_drive()                    F / F: / F:\ → "F:\"
 ├─ ErrorPolicy(continue_on_error, quiet/verbose)
 ├─ Manifest.start()                     timestamp, environment, case
 ├─ preflight
 │    ├─ check_admin()                   → 9
 │    ├─ check_ntfs(drive)               → 7   (GetVolumeInformation fs name)
 │    └─ check_output_dir(out, names)    → 8   (exists, writable, no clobber)
 ├─ identity = read_source_identity()    → 5 SOFTWARE / 6 SYSTEM; SAM is non-fatal
 │    └─ open_hive(): python-registry → fallback RegLoadAppKey; record method
 ├─ (names now known: {MachineGuid}[_{CaseID}].evtx / .manifest.json)
 ├─ image hash (background thread, if --image-path and not --skip-image-hash)
 ├─ journal = open_volume(); detect_journal_state()
 │    ├─ missing  → manifest only, status "aborted", exit 3
 │    ├─ disabled → partial (D4), exit 2
 │    ├─ empty    → header-only .evtx, exit 1
 │    └─ normal   → continue
 ├─ EvtxWriter.open(path, computer=hostname)
 ├─ for rec in iterate_records(h_vol, journal_id, first_usn, stop_usn):
 │      ├─ path = resolver.resolve(rec)
 │      ├─ eid, cat = classify_event(rec.reason)
 │      ├─ values = build_values(identity, volume, rec, path)
 │      └─ writer.write(eid, rec.timestamp, build_event_strings(values))
 │    (parse errors → ErrorPolicy; corrupt journal → exit 4)
 ├─ writer.close(); hash .evtx
 ├─ join image-hash thread; compare against --image-hash; mismatch → prompt / flag
 ├─ Manifest.finalize(); write_manifest()   (always, including on abort)
 └─ exit(worst_code)
```

**Fatal vs non-fatal.** Codes 3–10 abort. Even then, a manifest is written
whenever the output directory is usable, with status `aborted` and both
registry attempts recorded. Per-record parse failures, path failures, a
missing SAM, and a hash mismatch are non-fatal. They go through the
`ErrorPolicy` prompt flow, and each one adds an `errors_and_warnings` entry.

**Precedence when several codes apply:** the highest-numbered code wins
among fatal errors. Among non-fatal outcomes: 2 > 1 > 0.

---

## 5. Module layout

Keep it small. One entry script plus three helper modules:

| File | Contents |
|---|---|
| `usnproc.py` | CLI, `main()`, preflight, ErrorPolicy, orchestration, exit codes |
| `usn_common.py` | Vendored, pinned copy of usnmon's event contract (unchanged) |
| `usnproc_journal.py` | Volume open, journal query and state, read loop, record parse, path resolver |
| `usnproc_registry.py` | Offline hive access (python-registry + RegLoadAppKey fallback) and identity extraction |
| `usnproc_evtx.py` | Standalone EVTX writer (D1) |
| `usnproc_manifest.py` | Manifest builder, file hashing, JSON write |
| `tests/` | Unit tests with mocks, mirroring the `test_usnproc_verify.py` style |

`usnproc_verify.py` stays a standalone script, as the lock specifies.

---

## 6. Testing

- **Unit tests, runnable on Linux** (pywin32 and ctypes mocked):
  normalizing the drive argument; the argparse rules (mutually exclusive
  flags); exit-code precedence; the ErrorPolicy prompt state machine
  (`y/N`, then `y/i/n`); parsing V2 and V3 records from hand-built buffers;
  FILETIME conversion; parent-map path rebuilding; manifest schema
  (keys, types, `--no-image-path`, skipped-hash note); output file naming
  with and without `--case`.
- **Contract parity:** for a given set of values, `build_event_strings()`
  output must be byte-identical to usnmon's at `bd09f19`. The field list and
  order must match `EVENT_FIELD_NAMES`.
- **Registry:** use small test hive files (or a python-registry mock) to
  check MachineGuid, `Select\Current` → ControlSet, decoding the SID from
  SAM's `V` value, and InstallDate epoch → ISO-8601.
- **EVTX writer:** write N events, then read them back with `python-evtx`.
  Check the header and chunk CRCs, the record count, Provider, EventID,
  Computer, TimeCreated, and the `Data[]` order. Then compare field by field
  with a `.evtx` recorded by usnmon.
- **On Windows with a mounted image:** a known test image under FTK Imager.
  Run `usnproc_verify.py`, then usnproc. Load the output in EvtxECmd with
  usnmon's `maps/`, and confirm the PayloadData columns fill in.

---

## 7. Build order

1. Vendor `usn_common.py`. Scaffold the CLI, exit codes, ErrorPolicy and
   tests. *(no Windows needed)*
2. `usnproc_manifest.py` and file hashing. *(no Windows needed)*
3. `usnproc_registry.py`: python-registry path first, then the fallback.
4. `usnproc_journal.py`: port and extend the usnmon functions, add the
   finite loop, the state detection and the D3 parent map.
5. `usnproc_evtx.py`: build per the D1 decision. This is the riskiest step,
   so start it early, alongside steps 2–4.
6. Wire it together in `main()`, then test end to end on a mounted image.
7. Update the README and usage docs, and set the version string to 0.0.1.

**Before coding:** run `usnproc_verify.py` under FTK Imager (pending the
upload of the verify files). Confirm python-registry's current API. Get
answers on D1–D6.

---

## 8. Risks

- **The EVTX binary format** (D1) is the main technical risk. Mitigation:
  small fixed templates, and checking against two independent readers
  (python-evtx and EvtxECmd).
- **Mounter IOCTL support:** if FTK Imager doesn't pass the IOCTLs through,
  the lock's alternatives apply (Arsenal, OSFMount, imdisk).
- **RegLoadAppKey on read-only media** may need a writable copy of the hive.
  If so, copy it to a temp folder, hash the copy, and record that in the
  manifest.
- **Note on the EvtxECmd maps:** some `maps/*.map` files point at
  `Data[11]` through `Data[14]`, but `build_event_strings()` writes 7
  strings. The maps probably cover several layouts. Check this when
  comparing against the reference output.
- **Large journals** can reach millions of records. Write events as a
  stream, don't hold them in memory. The parent map uses about 100 bytes per
  directory, which is fine.

---

## Appendix A — Function outline

### `usnproc.py` (entry and orchestration)
- `VERSION = "0.0.1"`; constants for the `EXIT_*` codes (0–10)
- `parse_args(argv)` — argparse per Q2, with `--verbose`/`--quiet` mutually exclusive; raises `UsageError` → exit 10
- `normalize_drive(arg)` — `F`, `F:`, `F:\` → `"F:\"`; rejects anything else
- `output_names(machine_guid, case_id, processed_utc)` — returns `{guid}[_{case}]_{YYYYMMDDTHHMMSSZ}.evtx` and `.manifest.json` (D6)
- `check_admin()` — elevated token check → exit 9
- `check_ntfs(drive)` — `GetVolumeInformation`, file system must be `NTFS` → exit 7
- `check_output_dir(path, names)` — exists, writable, nothing to overwrite → exit 8
- `class ErrorPolicy`
  - `__init__(continue_on_error, quiet)`
  - `handle(code, detail, severity)` — records the entry, prompts `Continue? [y/N]` the first time, then `[y]es / [i]gnore future / [n]o`; returns continue or abort
  - `worst_code` — highest code reached
- `class Console` — `info()`, `verbose()`, `warn()`, `progress()`; respects `--quiet`/`--verbose`
- `build_values(identity, volume, rec, path)` — fills the usnmon field dict: `TargetFilename`, `UtcTime` (record time), `MachineGuid`, `VolumeSerial`, `Hostname`, `Category`, `Reason`, `Usn`, `JournalId`, `Domain`, `FQDN`, `MachineSID`, `OSBuild`, `MachineId`, `SchemaVersion`; sets `HwSerial`, `Vsn`, `PreviousVsn`, `SourceIP`, `MAC`, `Qpc`, `HiResUtc` to `""`
- `process(args)` — the flow in section 4; returns the exit code
- `main()` — wraps `process`, makes sure the manifest is written, `sys.exit(code)`

### `usn_common.py` (vendored from usnmon `bd09f19`, unchanged)
- `SCHEMA_VERSION`, `EVENT_IDS`, `EVENT_FIELD_NAMES`, `PARAM_FIELDS`, `REASON_FLAGS`
- `reason_text(reason)`, `classify_event(reason)`, `build_event_strings(values)`, `compute_machine_id(guid, instance_id)`

### `usnproc_journal.py` (volume and journal)
- `drive_root_to_device(root)` — `F:\` → `\\.\F:` *(from usnmon)*
- `volume_info(root)` — serial (`%08X`) and file system name *(extends usnmon `volume_serial`)*
- `open_volume(root)` — read-only handle with share-all; access denied → exit 9
- `query_journal(h_vol)` — all 7 `USN_JOURNAL_DATA_V0` fields as a dataclass *(extends usnmon)*
- `detect_journal_state(root, h_vol)` — returns normal / empty / disabled / missing plus journal data; uses error codes 1179/1178 and whether `$Extend\$UsnJrnl` exists (D4)
- `build_read_input(journal_id, start_usn)` *(from usnmon, unchanged)*
- `parse_record(buf, offset)` — V2/V3; adds `timestamp` (FILETIME) and `attributes` *(changed from usnmon)*
- `filetime_to_utc_str(ft)` — FILETIME → `YYYY-MM-DD HH:MM:SS.mmmZ`
- `iterate_records(h_vol, journal_id, first_usn, stop_usn, on_error)` — finite read loop that yields parsed records and stops when `NextUsn >= stop_usn` or a read returns nothing (Q6); journal corruption → exit 4
- `class PathResolver` *(from usnmon)* — `resolve(rec)`, `_open_and_resolve(ref)`
  - new: `note(rec)` — records `file_ref → (parent_ref, name)` in a parent map
  - new: `_rebuild_from_map(ref)` — fallback when `OpenFileById` fails (D3); `?` only for parts that can't be resolved
  - `stats` — counts of resolve hits, misses and rebuilds for the manifest

### `usnproc_registry.py` (offline identity)
- `hive_path(drive, name)` — `F:\Windows\System32\config\{SOFTWARE,SYSTEM,SAM}`
- `open_hive(path)` — tries python-registry, then `RegLoadAppKey` (ctypes/pywin32); returns `(HiveReader, method, attempts[])`
- `class HiveReader` — `get_value(key_path, name)` and `subkeys(key_path)`, the same calls for both backends
- `current_control_set(system)` — `Select\Current` → `ControlSet00N`
- `read_software_identity(software)` — MachineGuid, ProductName, CurrentBuild, InstallDate, RegisteredOwner, RegisteredOrganization; no MachineGuid → exit 5
- `read_system_identity(system)` — ComputerName, Tcpip Domain; unreadable → exit 6
- `read_machine_sid(sam)` — decodes `S-1-5-21-a-b-c` from `SAM\Domains\Account\V`; non-fatal
- `epoch_to_iso(secs)` — for InstallDate
- `read_source_identity(drive, policy)` — combines the above, builds `FQDN = host[.domain]`, returns the identity plus registry method details for the manifest

### `usnproc_evtx.py` (standalone EVTX writer, D1)
- `class EvtxWriter`
  - `__init__(path, provider="USNJournalMonitor", channel="FileSystem", computer)`
  - `write(event_id, timestamp_filetime, strings)` — adds one record, starting a new 64 KB chunk when needed
  - `close()` — writes the last chunk, fixes up the header (chunk count, next record ID), computes the CRC32s
  - `count` — records written
- `_file_header()`, `_chunk_header()`, `_record(...)` — binary layout helpers
- `_binxml_template(n_strings)` — fixed template matching usnmon's classic-event layout (System fields and N `<Data>` elements)
- `_crc32(data)`
- `write_empty(path, ...)` — header-only file for state 3

### `usnproc_manifest.py` (chain of custody)
- `class Manifest`
  - `__init__(version, args)` — fills `processing_environment` (VM hostname, user, Python, pywin32 and python-registry versions) and `case`
  - `set_source_image(...)`, `set_identity(...)`, `set_volume(...)`, `set_journal(...)`, `set_output(...)`
  - `add_error(severity, code, detail)` — adds a timestamped entry
  - `add_note(text)` — e.g. the Qpc/HiResUtc explanation, "image hash skipped: image path not provided", the UtcTime source
  - `finalize(status, detail)`
  - `to_dict()` — key order follows the Q9 schema
- `sha256_file(path, progress_cb)` — streaming hash, 8 MB blocks
- `class HashJob` — runs `sha256_file` on a background thread; `start()`, `result()`
- `compare_hash(computed, supplied)` — case-insensitive compare, returns match or mismatch
- `write_manifest(path, manifest)` — writes JSON atomically (temp file, then rename), UTF-8, indented
