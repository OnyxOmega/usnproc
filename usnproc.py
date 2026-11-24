"""
usnproc.py -- Offline USN Journal Processor (v0.0.1)

Converts the USN change journal of a mounted, read-only NTFS forensic image
into a standalone Windows Event Log (.evtx) file using usnmon's event
contract, plus a JSON chain-of-custody manifest.

    usnproc.py <drive-letter> [--case <case-id>] [--case-notes <string>]
                              [--output <dir>] [--image-path <path>]
                              [--image-hash <sha256>] [--skip-image-hash]
                              [--no-image-path] [--continue-on-error]
                              [--verbose | --quiet] [--help] [--version]

Design: DESIGN_LOCK.md v1.1. Key rules:
  * Every event is built ONLY from the USN journal record and the source
    image (Q11). TimeCreated and UtcTime = the USN record Timestamp. No
    processing/capture time appears in any event.
  * The processing time appears only in the output file names and manifest.
  * Output: {MachineGuid}[_{CaseID}]_{YYYYMMDDTHHMMSSZ}.evtx / .manifest.json.
    Never overwrites.

Exit codes (Q5):
  0 complete | 1 empty journal | 2 disabled journal (partial) |
  3 journal missing | 4 journal corrupt/unreadable | 5 SOFTWARE hive |
  6 SYSTEM hive | 7 drive invalid / not NTFS | 8 output directory |
  9 insufficient privileges | 10 command-line argument error

License: PolyForm Noncommercial 1.0.0 -- YASDC, Inc.
"""

import argparse
import os
import re
import sys

import usn_common as common
import usnproc_evtx as evtx
import usnproc_journal as journal
import usnproc_manifest as mf
import usnproc_registry as reg

VERSION = "0.0.1"

EXIT_OK = 0
EXIT_EMPTY = 1
EXIT_DISABLED = 2
EXIT_MISSING = 3
EXIT_CORRUPT = 4
EXIT_SOFTWARE = 5
EXIT_SYSTEM = 6
EXIT_DRIVE = 7
EXIT_OUTPUT = 8
EXIT_PRIVILEGE = 9
EXIT_ARGS = 10

UNKNOWN_GUID = "UNKNOWN"

NOTE_QPC = ("Qpc and HiResUtc are emitted as empty strings: they are "
            "recording-machine QueryPerformanceCounter values that do not exist "
            "for offline journal records.")
NOTE_TIME = ("Event times come only from the USN journal: each event's "
             "TimeCreated and UtcTime are the USN record's own Timestamp (when "
             "NTFS logged the change). The processing time appears only in the "
             "file names and this manifest.")
NOTE_PROVIDER = ("Events use provider 'USNJournalMonitor' / channel 'FileSystem' "
                 "for usnmon EvtxECmd map compatibility; this .evtx was produced "
                 "OFFLINE by usnproc from a forensic image (see this manifest).")
NOTE_EMPTY_FIELDS = ("SourceIP, MAC, HwSerial, Vsn and PreviousVsn are emitted as "
                     "empty strings (not extractable from an offline image / not "
                     "applicable to file events).")
NOTE_NO_IMAGE_PATH = "image hash skipped: image path not provided"
NOTE_HASH_SKIPPED = "image hash skipped: --skip-image-hash"
NOTE_E01 = ("image hash is of the image FILE as given. For container formats "
            "(E01/Ex01/AFF/etc.) this is not the acquisition (media) hash stored "
            "inside the container, so an examiner-supplied media hash will not "
            "match.")
CONTAINER_EXTS = (".e01", ".ex01", ".l01", ".lx01", ".aff", ".aff4", ".s01", ".ad1")


class Abort(Exception):
    def __init__(self, code, detail, status=mf.STATUS_ABORTED):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status


class UsageError(Exception):
    pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def build_parser():
    p = _Parser(prog="usnproc.py", description="Offline USN journal -> .evtx processor.")
    p.add_argument("drive", help="drive letter of the mounted image: F, F: or F:\\")
    p.add_argument("--case", dest="case_id", help="case identifier (optional)")
    p.add_argument("--case-notes", help="free-form notes, embedded verbatim in the manifest")
    p.add_argument("--output", default=os.getcwd(), help="output directory (default: cwd)")
    p.add_argument("--image-path", help="path to the image file (for hashing)")
    p.add_argument("--image-hash", help="examiner-supplied SHA-256 to verify against")
    p.add_argument("--skip-image-hash", action="store_true",
                   help="do not hash the image even if --image-path is given")
    p.add_argument("--no-image-path", action="store_true",
                   help="omit the image path from the manifest")
    p.add_argument("--continue-on-error", action="store_true",
                   help="record errors and continue without prompting")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--verbose", action="store_true")
    g.add_argument("--quiet", action="store_true")
    p.add_argument("--version", action="version", version="usnproc " + VERSION)
    return p


def parse_args(argv):
    args = build_parser().parse_args(argv)
    args.drive = normalize_drive(args.drive)
    if args.image_hash and not re.fullmatch(r"[0-9A-Fa-f]{64}", args.image_hash.strip()):
        raise UsageError("--image-hash must be a 64-character hex SHA-256")
    if args.case_id is not None:
        if not args.case_id.strip() or re.search(r'[<>:"/\\|?*\x00-\x1f]', args.case_id):
            raise UsageError("--case contains characters not allowed in a file name")
    return args


def normalize_drive(arg):
    """'F', 'F:', 'F:\\' (any case) -> 'F:\\'."""
    m = re.fullmatch(r"\s*([A-Za-z])(:\\?)?\s*", arg or "")
    if not m:
        raise UsageError("invalid drive letter %r (use F, F: or F:\\)" % arg)
    return m.group(1).upper() + ":\\"


def output_names(machine_guid, case_id, processed_at):
    stem = machine_guid or UNKNOWN_GUID
    if case_id:
        stem += "_" + case_id
    stem += "_" + mf.compact_utc(processed_at)
    return stem + ".evtx", stem + ".manifest.json"


# --------------------------------------------------------------------------- #
# Console + error policy
# --------------------------------------------------------------------------- #
class Console:
    def __init__(self, quiet=False, verbose=False, out=None):
        self.quiet = quiet
        self.verbose_on = verbose
        self.out = out or sys.stdout

    def info(self, msg):
        if not self.quiet:
            print(msg, file=self.out)

    def verbose(self, msg):
        if self.verbose_on:
            print(msg, file=self.out)

    def warn(self, msg):
        print("WARNING: " + msg, file=self.out)

    def error(self, msg):
        print("ERROR: " + msg, file=self.out)


class ErrorPolicy:
    """Q2/Q5 error flow. --continue-on-error: record and continue silently.
    Default: first error 'Continue? [y/N]', later errors
    'Continue? [y]es / [i]gnore future / [n]o'. 'i' = continue-on-error for
    the rest of the run. --quiet does NOT disable prompts. If stdin is not
    interactive the answer is No (never assume consent)."""

    def __init__(self, manifest, console, continue_on_error=False, ask=None):
        self.manifest = manifest
        self.console = console
        self.silent = continue_on_error
        self.ask = ask or self._ask_stdin
        self.prompts = 0

    @staticmethod
    def _ask_stdin(prompt):
        if not sys.stdin or not sys.stdin.isatty():
            return ""
        try:
            return input(prompt)
        except EOFError:
            return ""

    def handle(self, severity, code, detail):
        """Record the problem; return True to continue, False to abort."""
        self.manifest.add_error(severity, code, detail)
        if self.silent:
            self.console.verbose("%s %s: %s" % (severity.upper(), code, detail))
            return True
        self.console.error("%s: %s" % (code, detail))
        if self.prompts == 0:
            ans = self.ask("Continue? [y/N] ").strip().lower()
            self.prompts += 1
            return ans in ("y", "yes")
        ans = self.ask("Continue? [y]es / [i]gnore future / [n]o ").strip().lower()
        self.prompts += 1
        if ans in ("i", "ignore"):
            self.silent = True
            self.manifest.add_note("analyst chose 'ignore future' errors at prompt %d"
                                   % self.prompts)
            return True
        return ans in ("y", "yes")


# --------------------------------------------------------------------------- #
# Preflight (Windows)
# --------------------------------------------------------------------------- #
def check_output_dir(path):
    if not os.path.isdir(path):
        raise Abort(EXIT_OUTPUT, "output directory does not exist: %s" % path)
    probe = os.path.join(path, ".usnproc_write_test_%d" % os.getpid())
    try:
        with open(probe, "x"):
            pass
        os.remove(probe)
    except OSError as exc:
        raise Abort(EXIT_OUTPUT, "output directory not writable: %s (%r)" % (path, exc))


def check_targets_free(out_dir, names):
    for n in names:
        p = os.path.join(out_dir, n)
        if os.path.exists(p):
            raise Abort(EXIT_OUTPUT, "refusing to overwrite existing file: %s" % p)


def check_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                       # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# Event construction -- journal + source-image data ONLY (Q11)
# --------------------------------------------------------------------------- #
def base_values(identity, volume_serial, journal_id):
    """Fields constant for every event of this run, all from the image."""
    return {
        "SchemaVersion": common.SCHEMA_VERSION,
        "MachineGuid": identity["machine_guid"],
        "MachineId": common.compute_machine_id(identity["machine_guid"], None),
        "Hostname": identity["hostname"],
        "FQDN": reg.fqdn(identity["hostname"], identity["domain"]),
        "Domain": identity["domain"],
        "MachineSID": identity["machine_sid"],
        "OSBuild": identity["os_current_build"],
        "VolumeSerial": volume_serial,
        "JournalId": str(journal_id),      # decimal, as usnmon emits it
        "SourceIP": "", "MAC": "", "HwSerial": "", "Vsn": "", "PreviousVsn": "",
        "HiResUtc": "", "Qpc": "",
    }


def build_values(base, rec, target):
    event_id, category = common.classify_event(rec["reason"])
    values = dict(base)
    values.update({
        "TargetFilename": target,
        "UtcTime": journal.filetime_to_utc_str(rec["timestamp"]),
        "Category": category,
        "Reason": common.reason_text(rec["reason"]),
        "Usn": str(rec["usn"]),
    })
    return event_id, values


# --------------------------------------------------------------------------- #
# Main processing
# --------------------------------------------------------------------------- #
class Run:
    def __init__(self, args, console, ask=None):
        self.args = args
        self.console = console
        self.processed_at = mf.utc_now()
        self.manifest = mf.Manifest(VERSION, self.processed_at, args.case_id, args.case_notes)
        self.policy = ErrorPolicy(self.manifest, console, args.continue_on_error, ask)
        self.machine_guid = None
        self.evtx_path = None
        self.manifest_written = False
        for n in (NOTE_TIME, NOTE_QPC, NOTE_PROVIDER, NOTE_EMPTY_FIELDS):
            self.manifest.add_note(n)
        self.manifest.update("source_image", mount_drive_letter=args.drive)
        self.manifest.update("volume", drive_letter_at_processing=args.drive)

    # -- manifest -----------------------------------------------------------
    def names(self):
        return output_names(self.machine_guid, self.args.case_id, self.processed_at)

    def write_manifest(self):
        path = os.path.join(self.args.output, self.names()[1])
        mf.write_manifest(path, self.manifest)
        self.manifest_written = True
        self.console.info("Manifest: %s" % path)
        return path

    # -- steps --------------------------------------------------------------
    def preflight(self):
        check_output_dir(self.args.output)
        if not journal._WINDOWS:
            raise Abort(EXIT_DRIVE, "usnproc requires Windows 10+ with pywin32")
        if not check_admin():
            raise Abort(EXIT_PRIVILEGE, "administrator privileges required to open "
                                        "the volume (run from an elevated prompt)")
        try:
            serial, fs = journal.volume_info(self.args.drive)
        except Exception as exc:            # noqa: BLE001
            raise Abort(EXIT_DRIVE, "drive %s not accessible: %r" % (self.args.drive, exc))
        self.manifest.update("volume", volume_serial_number=serial, filesystem=fs)
        if (fs or "").upper() != "NTFS":
            raise Abort(EXIT_DRIVE, "drive %s is %s, not NTFS" % (self.args.drive, fs))
        self.volume_serial = serial

    def read_identity(self):
        d = self.args.drive
        env = self.manifest.section("processing_environment")
        hives = {}
        for name, code in (("SOFTWARE", EXIT_SOFTWARE), ("SYSTEM", EXIT_SYSTEM)):
            try:
                hive, method, attempts = reg.open_hive(reg.hive_path(d, name), name)
            except reg.HiveError as exc:
                env["registry_read_attempts"][name] = exc.attempts
                raise Abort(code, str(exc))
            env["registry_read_method"][name] = method
            env["registry_read_attempts"][name] = attempts
            hives[name] = hive
        identity = reg.read_software_identity(hives["SOFTWARE"])
        if not identity["machine_guid"]:
            raise Abort(EXIT_SOFTWARE, "MachineGuid not found in SOFTWARE hive "
                                       r"(Microsoft\Cryptography\MachineGuid)")
        self.machine_guid = identity["machine_guid"]
        sysid = reg.read_system_identity(hives["SYSTEM"])
        identity.update(hostname=sysid["hostname"], domain=sysid["domain"])
        if not sysid["hostname"]:
            self.manifest.add_error("warning", "HOSTNAME_NOT_FOUND",
                                    "ComputerName not found under %s" % sysid["control_set"])
        identity["machine_sid"] = ""
        try:
            sam, method, attempts = reg.open_hive(reg.hive_path(d, "SAM"), "SAM")
            env["registry_read_method"]["SAM"] = method
            env["registry_read_attempts"]["SAM"] = attempts
            identity["machine_sid"] = reg.read_machine_sid(sam)
            sam.close()
        except reg.HiveError as exc:
            env["registry_read_attempts"]["SAM"] = exc.attempts
            if not self.policy.handle("warning", "SAM_UNREADABLE",
                                      str(exc) + " (MachineSID left empty)"):
                raise Abort(EXIT_CORRUPT, "aborted by analyst after SAM_UNREADABLE")
        for h in hives.values():
            h.close()
        self.identity = identity
        self.manifest.update("source_machine_identity", **{
            k: identity.get(k, "") for k in self.manifest.section("source_machine_identity")})
        self.console.info("Source machine: %s  MachineGuid %s" % (
            identity["hostname"] or "?", identity["machine_guid"]))

    def start_image_hash(self):
        a = self.args
        si = self.manifest.section("source_image")
        si["image_hash_sha256_examiner_supplied"] = a.image_hash.lower() if a.image_hash else None
        if a.image_path and not a.no_image_path:
            si["image_path_at_processing"] = a.image_path
        if a.no_image_path:
            self.manifest.add_note("image path omitted from manifest (--no-image-path)")
        if not a.image_path:
            self.manifest.add_note(NOTE_NO_IMAGE_PATH)
            return None
        if a.image_path.lower().endswith(CONTAINER_EXTS):
            self.manifest.add_note(NOTE_E01)
        if a.skip_image_hash:
            self.manifest.add_note(NOTE_HASH_SKIPPED)
            return None
        if not os.path.isfile(a.image_path):
            if not self.policy.handle("error", "IMAGE_PATH_NOT_FOUND", a.image_path):
                raise Abort(EXIT_ARGS, "image path not found: %s" % a.image_path)
            return None
        self.console.info("Hashing image (SHA-256): %s" % a.image_path)
        job = mf.HashJob(a.image_path).start()
        if a.image_hash:
            # Verify BEFORE processing so a mismatch can stop the run (Q9).
            self.finish_image_hash(job)
            return None
        return job

    def finish_image_hash(self, job):
        if job is None:
            return
        digest, err = job.result()
        si = self.manifest.section("source_image")
        if err:
            self.policy.handle("error", "IMAGE_HASH_FAILED", repr(err))
            return
        si["image_hash_sha256_computed"] = digest
        match = mf.compare_hash(digest, self.args.image_hash)
        si["image_hash_match"] = match
        self.console.info("Image SHA-256: %s" % digest)
        if match is False:
            detail = ("examiner-supplied %s != computed %s -- check drive labels and "
                      "chain of custody" % (self.args.image_hash.lower(), digest))
            if self.args.image_path.lower().endswith(CONTAINER_EXTS):
                detail += " (note: container file hash, not media hash)"
            self.console.warn("IMAGE HASH MISMATCH")
            if not self.policy.handle("error", "IMAGE_HASH_MISMATCH", detail):
                raise Abort(EXIT_ARGS, "aborted by analyst after IMAGE_HASH_MISMATCH")

    def process_journal(self):
        """Return (exit_code, status, detail)."""
        d = self.args.drive
        try:
            h_vol = journal.open_volume(d)
        except Exception as exc:            # noqa: BLE001
            if journal.winerror_of(exc) == journal.ERROR_ACCESS_DENIED:
                raise Abort(EXIT_PRIVILEGE, "access denied opening volume %s" % d)
            raise Abort(EXIT_DRIVE, "cannot open volume %s: %r" % (d, exc))
        try:
            return self._process_volume(h_vol)
        finally:
            try:
                journal.win32file.CloseHandle(h_vol)
            except Exception:               # noqa: BLE001
                pass

    def _process_volume(self, h_vol):
        d = self.args.drive
        try:
            state, jd, detail = journal.detect_journal_state(d, h_vol)
        except journal.JournalError as exc:
            raise Abort(EXIT_CORRUPT, str(exc))
        uj = self.manifest.section("usn_journal")
        if jd is not None:
            uj.update(journal_id="0x%016x" % jd.journal_id, first_usn=jd.first_usn,
                      next_usn=jd.next_usn, lowest_valid_usn=jd.lowest_valid_usn,
                      max_usn=jd.max_usn, max_size_bytes=jd.max_size,
                      allocation_delta_bytes=jd.allocation_delta)
        self.console.info("Journal state: %s (%s)" % (state, detail))
        evtx_name = self.names()[0]
        self.evtx_path = os.path.join(self.args.output, evtx_name)

        if state == journal.STATE_MISSING:
            raise Abort(EXIT_MISSING, detail)
        if state in (journal.STATE_EMPTY, journal.STATE_DISABLED):
            evtx.write_empty(self.evtx_path)
            self._record_output()
            if state == journal.STATE_EMPTY:
                return EXIT_EMPTY, mf.STATUS_EMPTY, detail
            self.manifest.add_note("journal disabled: no records are readable through "
                                   "FSCTL_READ_USN_JOURNAL; raw $UsnJrnl:$J reading is "
                                   "not implemented in v0.0.1. Header-only .evtx written.")
            return EXIT_DISABLED, mf.STATUS_PARTIAL, detail

        stop_usn = jd.next_usn                 # captured once at start (Q6)
        # Pass 1: learn file_ref -> (parent, name) from the journal itself (D3).
        pmap = journal.ParentMap()
        self.console.info("Pass 1/2: building path map from journal records ...")
        try:
            for rec, _err, _off in journal.iterate_records(h_vol, jd.journal_id,
                                                           jd.first_usn, stop_usn):
                pmap.note(rec)
        except journal.JournalError as exc:
            if not self.policy.handle("error", "USN_READ_FAIL", "pass 1: %s" % exc):
                raise Abort(EXIT_CORRUPT, str(exc))
        self.console.verbose("  %d journal entries mapped" % len(pmap.entries))

        resolver = journal.PathResolver(h_vol, d, pmap)
        base = base_values(self.identity, self.volume_serial, jd.journal_id)
        n_ok = n_bad = 0
        code, status, final_detail = EXIT_OK, mf.STATUS_COMPLETE, "all records processed"
        self.console.info("Pass 2/2: writing events -> %s" % evtx_name)
        writer = evtx.EvtxWriter(self.evtx_path, computer=self.identity["hostname"])
        try:
            for rec, err, off in journal.iterate_records(h_vol, jd.journal_id,
                                                         jd.first_usn, stop_usn):
                if rec is None:
                    n_bad += 1
                    why = repr(err) if err else "unsupported record version"
                    if not self.policy.handle("warning", "USN_PARSE_FAIL",
                                              "record at buffer offset %d: %s" % (off, why)):
                        code, status = EXIT_CORRUPT, mf.STATUS_ABORTED
                        final_detail = "aborted by analyst after USN_PARSE_FAIL"
                        break
                    continue
                event_id, values = build_values(base, rec, resolver.resolve(rec))
                writer.write(event_id, rec["timestamp"], common.build_event_strings(values))
                n_ok += 1
                if n_ok % 50000 == 0:
                    self.console.info("  %d events written ..." % n_ok)
        except journal.JournalError as exc:
            self.policy.handle("error", "USN_READ_FAIL", str(exc))
            code, status = EXIT_CORRUPT, mf.STATUS_PARTIAL
            final_detail = "journal read failed after %d records: %s" % (n_ok, exc)
        finally:
            writer.close()
            uj.update(records_extracted=n_ok, records_failed_parse=n_bad,
                      paths_resolved_live=resolver.stats["resolved_live"],
                      paths_resolved_from_journal=resolver.stats["resolved_from_journal"],
                      paths_unresolved=resolver.stats["unresolved"])
            self._record_output()
        if n_ok == 0 and code == EXIT_OK:
            return EXIT_EMPTY, mf.STATUS_EMPTY, "journal returned no records"
        if code == EXIT_OK and n_bad:
            final_detail = "%d records processed, %d failed to parse" % (n_ok, n_bad)
        self.console.info("Events written: %d (parse failures: %d)" % (n_ok, n_bad))
        return code, status, final_detail

    def _record_output(self):
        p = self.evtx_path
        self.manifest.update("output", evtx_filename=os.path.basename(p),
                             evtx_hash_sha256=mf.sha256_file(p),
                             evtx_size_bytes=os.path.getsize(p))

    # -- orchestration ------------------------------------------------------
    def run(self):
        code, status, detail = EXIT_OK, mf.STATUS_COMPLETE, ""
        try:
            self.preflight()
            self.read_identity()
            check_targets_free(self.args.output, self.names())
            job = self.start_image_hash()
            code, status, detail = self.process_journal()
            self.finish_image_hash(job)
        except Abort as exc:
            code, status, detail = exc.code, exc.status, exc.detail
            self.console.error(detail)
        except KeyboardInterrupt:
            code, status, detail = EXIT_CORRUPT, mf.STATUS_ABORTED, "interrupted by analyst"
            self.console.error(detail)
        self.manifest.update("output", evtx_record_count=
                             self.manifest.section("usn_journal")["records_extracted"])
        self.manifest.finalize(status, detail)
        if code != EXIT_OUTPUT:
            try:
                self.write_manifest()
            except Exception as exc:        # noqa: BLE001
                self.console.error("could not write manifest: %r" % exc)
                return EXIT_OUTPUT
        self.console.info("Status: %s (exit %d)" % (status, code))
        return code


def main(argv=None, ask=None):
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
    except UsageError as exc:
        print("usnproc: error: %s" % exc, file=sys.stderr)
        print("usage: usnproc.py <drive-letter> [options]  (--help for details)",
              file=sys.stderr)
        return EXIT_ARGS
    console = Console(quiet=args.quiet, verbose=args.verbose)
    console.info("usnproc %s -- offline USN journal processor" % VERSION)
    return Run(args, console, ask).run()


if __name__ == "__main__":
    sys.exit(main())
