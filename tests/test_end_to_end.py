"""End-to-end: run usnproc.main() against a simulated mounted volume (fake
IOCTLs + fake hives) and check exit codes, file names, manifest and the
Q11 rule that events carry ONLY journal data (no processing time)."""

import glob
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakes  # noqa: E402
from fakes import ref, v2_record, ROOT_REF  # noqa: E402

import usnproc  # noqa: E402
import usnproc_journal as journal  # noqa: E402
import usnproc_registry as reg  # noqa: E402

try:
    from Evtx.Evtx import Evtx as PyEvtx
except Exception:                        # noqa: BLE001
    PyEvtx = None

FT0 = 133_500_000_000_000_000           # 2024-01-21 -- long before "now"


def sample_journal():
    """Users\\bob\\doc.txt created+modified, a file in a deleted dir, and a
    root-level file. Folder 'Old' (ref 60) was deleted before imaging."""
    specs = [
        (ref(30), ROOT_REF, "Users", 0x100),
        (ref(31), ref(30), "bob", 0x100),
        (ref(40), ref(31), "doc.txt", 0x100),
        (ref(40), ref(31), "doc.txt", 0x2),
        (ref(60), ROOT_REF, "Old", 0x100),
        (ref(61), ref(60), "gone.tmp", 0x200),
        (ref(60), ROOT_REF, "Old", 0x200),
        (ref(70), ROOT_REF, "root.log", 0x80000000 | 0x2),
    ]
    recs, usn = [], 8192
    for i, (fr, pr, name, reason) in enumerate(specs):
        r = v2_record(usn, fr, pr, name, reason, FT0 + i * 10_000_000)
        recs.append(r)
        usn += len(r)
    return recs


class E2E(unittest.TestCase):
    def run_usnproc(self, fj, extra=(), hives=None, answers=None, live=None):
        self.td = tempfile.mkdtemp()
        hives = hives if hives is not None else {
            "SOFTWARE": fakes.SOFTWARE, "SYSTEM": fakes.SYSTEM, "SAM": fakes.SAM}

        def open_hive(path, name, backends=None):
            if name not in hives:
                raise reg.HiveError(name, [{"method": "python-registry", "result": "failed",
                                            "error": "missing"}])
            return fakes.FakeHive(hives[name]), "python-registry", [
                {"method": "python-registry", "result": "ok", "error": ""}]

        fw = fakes.FakeWin32File(fj, live_paths=live or {ref(31): "\\Users\\bob"})
        ans = list(answers or [])
        with mock.patch.object(journal, "_WINDOWS", True), \
                mock.patch.object(journal, "win32file", fw), \
                mock.patch.object(journal, "volume_info", return_value=("D66FD839", "NTFS")), \
                mock.patch.object(journal, "usnjrnl_present", return_value=True), \
                mock.patch.object(usnproc, "check_admin", return_value=True), \
                mock.patch.object(reg, "open_hive", side_effect=open_hive), \
                mock.patch("sys.stdout", open(os.devnull, "w")):
            code = usnproc.main(["F", "--output", self.td] + list(extra),
                                ask=lambda p: ans.pop(0) if ans else "")
        mans = glob.glob(os.path.join(self.td, "*.manifest.json"))
        man = json.load(open(mans[0])) if mans else None
        evs = glob.glob(os.path.join(self.td, "*.evtx"))
        return code, man, (evs[0] if evs else None)

    def test_normal_run(self):
        code, man, ev = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                         ["--case", "2026-0712-Ev003"])
        self.assertEqual(code, 0)
        self.assertEqual(man["processing_status"], "complete")
        ts = re.sub(r"[-:]", "", man["processing_timestamp_utc"])
        stem = "%s_2026-0712-Ev003_%s" % (fakes.GUID, ts)
        self.assertEqual(os.path.basename(ev), stem + ".evtx")
        self.assertTrue(os.path.exists(os.path.join(self.td, stem + ".manifest.json")))
        uj = man["usn_journal"]
        self.assertEqual((uj["records_extracted"], uj["records_failed_parse"]), (8, 0))
        self.assertEqual(uj["journal_id"], "0x01d5a1b2c3d40001")
        self.assertEqual(man["source_machine_identity"]["machine_sid"],
                         "S-1-5-21-1111111111-2222222222-3333333333")
        self.assertEqual(man["output"]["evtx_filename"], stem + ".evtx")
        self.assertEqual(man["output"]["evtx_size_bytes"], os.path.getsize(ev))
        self.assertIn(usnproc.NOTE_NO_IMAGE_PATH, man["notes"])
        self.assertEqual(man["processing_environment"]["registry_read_method"]["SOFTWARE"],
                         "python-registry")

    @unittest.skipIf(PyEvtx is None, "python-evtx not installed")
    def test_events_contain_only_journal_data(self):
        code, man, ev = self.run_usnproc(fakes.FakeJournal(sample_journal()))
        self.assertEqual(code, 0)
        with PyEvtx(ev) as log:
            recs = [(r.timestamp(), r.xml()) for r in log.records()]
        self.assertEqual(len(recs), 8)
        processed_day = man["processing_timestamp_utc"][:10]
        for i, (ts, x) in enumerate(recs):
            want = journal.filetime_to_datetime(FT0 + i * 10_000_000)
            self.assertEqual(ts, want)                                      # TimeCreated
            self.assertIn("UtcTime: " + journal.filetime_to_utc_str(FT0 + i * 10_000_000), x)
            self.assertNotIn(processed_day, x)                              # no "now"
            self.assertIn("<Computer>SRCHOST</Computer>", x)
            self.assertIn("HiResUtc: \n", x)
            self.assertIn("Qpc: </Data>", x)
        texts = [x for _, x in recs]
        self.assertIn("<Data>F:\\Users\\bob\\doc.txt</Data>", texts[2])     # live path
        self.assertIn("<Data>F:\\Old\\gone.tmp</Data>", texts[5])          # rebuilt (D3)
        self.assertIn("<Data>F:\\root.log</Data>", texts[7])
        self.assertIn(">102</EventID>", texts[5])                           # Delete
        # "Users" (ref 30) is not live in the fake mount and "Old" is deleted:
        # both are rebuilt from the journal.
        self.assertEqual(man["usn_journal"]["paths_resolved_from_journal"], 2)

    def test_empty_journal_exit_1(self):
        code, man, ev = self.run_usnproc(fakes.FakeJournal([]))
        self.assertEqual((code, man["processing_status"]), (1, "empty"))
        self.assertEqual(os.path.getsize(ev), 4096)

    def test_disabled_exit_2(self):
        e = OSError("x")
        e.winerror = 1179
        code, man, ev = self.run_usnproc(fakes.FakeJournal([], query_error=e))
        self.assertEqual((code, man["processing_status"]), (2, "partial"))
        self.assertIsNotNone(ev)

    def test_missing_exit_3_manifest_only(self):
        e = OSError("x")
        e.winerror = 1179
        fj = fakes.FakeJournal([], query_error=e)
        with mock.patch.object(journal, "detect_journal_state",
                               return_value=(journal.STATE_MISSING, None, "none")):
            code, man, ev = self.run_usnproc(fj)
        self.assertEqual((code, man["processing_status"], ev), (3, "aborted", None))

    def test_unsupported_mount_exit_4(self):
        e = OSError("x")
        e.winerror = 1
        code, man, ev = self.run_usnproc(fakes.FakeJournal([], query_error=e))
        self.assertEqual((code, man["processing_status"]), (4, "aborted"))

    def test_read_failure_midway_exit_4_partial(self):
        recs = sample_journal()
        fj = fakes.FakeJournal(recs, per_read=3)
        fj.read_error_at = fj.usns[6]       # 3rd read (records 6-7) fails
        code, man, ev = self.run_usnproc(fj, ["--continue-on-error"])
        self.assertEqual((code, man["processing_status"]), (4, "partial"))
        self.assertEqual(man["usn_journal"]["records_extracted"], 6)

    def test_software_hive_exit_5_unknown_name(self):
        code, man, ev = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                         hives={"SYSTEM": fakes.SYSTEM})
        self.assertEqual(code, 5)
        self.assertIsNone(ev)
        self.assertTrue(glob.glob(os.path.join(self.td, "UNKNOWN_*.manifest.json")))

    def test_system_hive_exit_6(self):
        code, man, ev = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                         hives={"SOFTWARE": fakes.SOFTWARE})
        self.assertEqual(code, 6)

    def test_sam_missing_is_warning_with_coe(self):
        code, man, ev = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                         ["--continue-on-error"],
                                         hives={"SOFTWARE": fakes.SOFTWARE,
                                                "SYSTEM": fakes.SYSTEM})
        self.assertEqual(code, 0)
        self.assertEqual(man["errors_and_warnings"][0]["code"], "SAM_UNREADABLE")

    def test_not_ntfs_exit_7(self):
        td = tempfile.mkdtemp()
        with mock.patch.object(journal, "_WINDOWS", True), \
                mock.patch.object(journal, "volume_info", return_value=("1", "FAT32")), \
                mock.patch.object(usnproc, "check_admin", return_value=True), \
                mock.patch("sys.stdout", open(os.devnull, "w")):
            self.assertEqual(usnproc.main(["F", "--output", td]), 7)

    def test_output_dir_missing_exit_8(self):
        with mock.patch("sys.stdout", open(os.devnull, "w")):
            self.assertEqual(usnproc.main(["F", "--output", "/no/such/dir/x"]), 8)

    def test_not_admin_exit_9(self):
        td = tempfile.mkdtemp()
        with mock.patch.object(journal, "_WINDOWS", True), \
                mock.patch.object(usnproc, "check_admin", return_value=False), \
                mock.patch("sys.stdout", open(os.devnull, "w")):
            self.assertEqual(usnproc.main(["F", "--output", td]), 9)

    def test_image_hash_match_and_mismatch(self):
        img = os.path.join(tempfile.mkdtemp(), "disk.dd")
        open(img, "wb").write(b"abc")
        good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        code, man, _ = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                        ["--image-path", img, "--image-hash", good.upper()])
        self.assertEqual(code, 0)
        self.assertTrue(man["source_image"]["image_hash_match"])
        # mismatch, analyst declines -> no .evtx produced
        code, man, ev = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                         ["--image-path", img, "--image-hash", "0" * 64],
                                         answers=["n"])
        self.assertEqual(code, 10)
        self.assertIsNone(ev)
        self.assertFalse(man["source_image"]["image_hash_match"])
        self.assertEqual(man["errors_and_warnings"][0]["code"], "IMAGE_HASH_MISMATCH")

    def test_image_hash_background_and_no_image_path(self):
        img = os.path.join(tempfile.mkdtemp(), "disk.E01")
        open(img, "wb").write(b"abc")
        code, man, _ = self.run_usnproc(fakes.FakeJournal(sample_journal()),
                                        ["--image-path", img, "--no-image-path"])
        self.assertEqual(code, 0)
        si = man["source_image"]
        self.assertTrue(si["image_hash_sha256_computed"].startswith("ba7816bf"))
        self.assertIsNone(si["image_path_at_processing"])
        self.assertIn(usnproc.NOTE_E01, man["notes"])


if __name__ == "__main__":
    unittest.main()
