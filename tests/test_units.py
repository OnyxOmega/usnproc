"""Unit tests: CLI, error policy, journal parsing/paths, registry decoding,
manifest, EVTX writer and the usnmon contract. Runs on any OS:

    python -m unittest discover -s tests
"""

import json
import os
import struct
import sys
import tempfile
import unittest
import zlib
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakes  # noqa: E402
from fakes import ref, v2_record, v3_record, ROOT_REF  # noqa: E402

import usn_common as common  # noqa: E402
import usnproc  # noqa: E402
import usnproc_evtx as evtx  # noqa: E402
import usnproc_journal as journal  # noqa: E402
import usnproc_manifest as mf  # noqa: E402
import usnproc_registry as reg  # noqa: E402

FT_2026 = 134_000_000_000_000_000      # a FILETIME in 2025/2026

try:
    from Evtx.Evtx import Evtx as PyEvtx
except Exception:                        # noqa: BLE001
    PyEvtx = None


class TestCli(unittest.TestCase):
    def test_normalize_drive(self):
        for a in ("F", "f", "F:", "f:", "F:\\", " F: "):
            self.assertEqual(usnproc.normalize_drive(a), "F:\\")
        for a in ("", "FF", "1", "F:/", "F:\\x", "C:\\\\"):
            with self.assertRaises(usnproc.UsageError):
                usnproc.normalize_drive(a)

    def test_verbose_quiet_exclusive(self):
        with self.assertRaises(usnproc.UsageError):
            usnproc.parse_args(["F", "--verbose", "--quiet"])

    def test_bad_case_and_hash(self):
        with self.assertRaises(usnproc.UsageError):
            usnproc.parse_args(["F", "--case", "a/b"])
        with self.assertRaises(usnproc.UsageError):
            usnproc.parse_args(["F", "--image-hash", "abc"])
        a = usnproc.parse_args(["F:", "--case", "2026-0712-Ev003", "--image-hash", "A" * 64])
        self.assertEqual(a.drive, "F:\\")

    def test_main_arg_error_exit_10(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(usnproc.main(["--nope"]), usnproc.EXIT_ARGS)
            self.assertEqual(usnproc.main([]), usnproc.EXIT_ARGS)

    def test_output_names(self):
        t = datetime(2026, 11, 24, 19, 24, 0, tzinfo=timezone.utc)
        self.assertEqual(usnproc.output_names("g", "C1", t),
                         ("g_C1_20261124T192400Z.evtx", "g_C1_20261124T192400Z.manifest.json"))
        self.assertEqual(usnproc.output_names("g", None, t)[0], "g_20261124T192400Z.evtx")
        self.assertEqual(usnproc.output_names(None, None, t)[1],
                         "UNKNOWN_20261124T192400Z.manifest.json")


class TestErrorPolicy(unittest.TestCase):
    def make(self, answers, coe=False):
        m = mf.Manifest("0.0.1", mf.utc_now())
        asked = []

        def ask(p):
            asked.append(p)
            return answers.pop(0)
        con = usnproc.Console(quiet=True, out=open(os.devnull, "w"))
        return usnproc.ErrorPolicy(m, con, coe, ask), asked, m

    def test_first_prompt_default_no(self):
        p, asked, m = self.make([""])
        self.assertFalse(p.handle("error", "X", "d"))
        self.assertIn("[y/N]", asked[0])
        self.assertEqual(len(m.data["errors_and_warnings"]), 1)

    def test_second_prompt_three_way_and_ignore(self):
        p, asked, _ = self.make(["y", "i"])
        self.assertTrue(p.handle("error", "X", "1"))
        self.assertTrue(p.handle("error", "X", "2"))
        self.assertIn("[i]gnore future", asked[1])
        self.assertTrue(p.handle("error", "X", "3"))     # silent now
        self.assertEqual(len(asked), 2)

    def test_second_prompt_no(self):
        p, _, _ = self.make(["y", "n"])
        p.handle("e", "X", "1")
        self.assertFalse(p.handle("e", "X", "2"))

    def test_continue_on_error_never_prompts(self):
        p, asked, m = self.make([], coe=True)
        for _ in range(3):
            self.assertTrue(p.handle("warning", "X", "d"))
        self.assertEqual(asked, [])
        self.assertEqual(len(m.data["errors_and_warnings"]), 3)


class TestJournal(unittest.TestCase):
    def test_parse_v2_keeps_timestamp(self):
        b = b"\x00" * 8 + v2_record(1000, ref(40), ROOT_REF, "a.txt", 0x100, FT_2026)
        r = journal.parse_record(b, 8)
        self.assertEqual((r["usn"], r["timestamp"], r["name"], r["major"]),
                         (1000, FT_2026, "a.txt", 2))

    def test_parse_v3(self):
        b = v3_record(77, ref(40), ROOT_REF, "b.txt", 0x200, FT_2026)
        r = journal.parse_record(b, 0)
        self.assertEqual(r["file_ref"], ref(40).to_bytes(16, "little"))
        self.assertEqual(journal.mft_index(r["parent_ref"]), 5)
        self.assertEqual(r["timestamp"], FT_2026)

    def test_parse_rejects_garbage(self):
        b = bytearray(v2_record(1, ref(9), ROOT_REF, "x", 1, 1))
        struct.pack_into("<L", b, 0, 9999)
        with self.assertRaises(ValueError):
            journal.parse_record(bytes(b), 0)

    def test_iter_buffer_reports_bad_record(self):
        good = v2_record(10, ref(9), ROOT_REF, "x", 1, 1)
        bad = bytearray(v2_record(20, ref(9), ROOT_REF, "y", 1, 1))
        struct.pack_into("<HH", bad, 4, 9, 0)               # unsupported major
        out = list(journal.iter_buffer(b"\x00" * 8 + good + bytes(bad)))
        self.assertEqual(len(out), 2)
        self.assertIsNotNone(out[0][1])
        self.assertIsNone(out[1][1])

    def test_filetime_format(self):
        ft = 116444736000000000 + 1_234_5678          # 1970-01-01 00:00:01.2345678
        self.assertEqual(journal.filetime_to_utc_str(ft), "1970-01-01 00:00:01.234Z")
        self.assertEqual(journal.filetime_to_utc_str(0), "")

    def test_parent_map_rebuild(self):
        pm = journal.ParentMap()
        pm.note({"file_ref": ref(30), "parent_ref": ROOT_REF, "name": "Users"})
        pm.note({"file_ref": ref(31), "parent_ref": ref(30), "name": "bob"})
        self.assertEqual(pm.rebuild(ref(31)), "\\Users\\bob")
        self.assertIsNone(pm.rebuild(ref(99)))
        pm.note({"file_ref": ref(50), "parent_ref": ref(51), "name": "a"})
        pm.note({"file_ref": ref(51), "parent_ref": ref(50), "name": "b"})
        self.assertIsNone(pm.rebuild(ref(50)))              # cycle

    def test_resolver_live_then_journal_then_unknown(self):
        pm = journal.ParentMap()
        pm.note({"file_ref": ref(30), "parent_ref": ROOT_REF, "name": "Gone"})
        live = {ref(20): "\\Live\\Dir"}
        r = journal.PathResolver("H", "F:\\", pm, opener=lambda x: live.get(x))
        mk = lambda p, n: {"parent_ref": p, "file_ref": ref(999), "name": n, "reason": 2}
        self.assertEqual(r.resolve(mk(ref(20), "a")), "F:\\Live\\Dir\\a")
        self.assertEqual(r.resolve(mk(ref(30), "b")), "F:\\Gone\\b")
        self.assertEqual(r.resolve(mk(ROOT_REF, "c")), "F:\\c")
        self.assertEqual(r.resolve(mk(ref(77), "d")), "F:\\?\\d")
        self.assertEqual(r.stats, {"resolved_live": 1, "resolved_from_journal": 1,
                                   "unresolved": 1})

    def _patch(self, fj):
        return mock.patch.object(journal, "win32file", fakes.FakeWin32File(fj))

    def test_states(self):
        recs = [v2_record(4096, ref(9), ROOT_REF, "x", 1, FT_2026)]
        with self._patch(fakes.FakeJournal(recs)):
            self.assertEqual(journal.detect_journal_state("F:\\", "H")[0], journal.STATE_NORMAL)
        with self._patch(fakes.FakeJournal([])):
            self.assertEqual(journal.detect_journal_state("F:\\", "H")[0], journal.STATE_EMPTY)
        for present, want in ((True, journal.STATE_DISABLED), (False, journal.STATE_MISSING)):
            e = OSError("x")
            e.winerror = 1179
            with self._patch(fakes.FakeJournal([], query_error=e)), \
                    mock.patch.object(journal, "usnjrnl_present", return_value=present):
                self.assertEqual(journal.detect_journal_state("F:\\", "H")[0], want)
        e = OSError("x")
        e.winerror = 1
        with self._patch(fakes.FakeJournal([], query_error=e)):
            with self.assertRaises(journal.JournalError):
                journal.detect_journal_state("F:\\", "H")

    def test_iterate_stops_at_captured_next_usn(self):
        recs, usn = [], 4096
        for i in range(10):
            r = v2_record(usn, ref(100 + i), ROOT_REF, "f%d" % i, 0x100, FT_2026 + i)
            recs.append(r)
            usn += len(r)
        fj = fakes.FakeJournal(recs, per_read=4)
        with self._patch(fj):
            got = [r["usn"] for r, e, o in journal.iterate_records("H", fj.journal_id,
                                                                    fj.first, fj.usns[6])]
        self.assertEqual(got, fj.usns[:6])


class TestRegistry(unittest.TestCase):
    def test_sid(self):
        self.assertEqual(reg.machine_sid_from_v(fakes.sam_v_blob(1, 2, 3)), "S-1-5-21-1-2-3")
        self.assertEqual(reg.machine_sid_from_v(b"short"), "")

    def test_identity(self):
        sw = reg.read_software_identity(fakes.FakeHive(fakes.SOFTWARE))
        self.assertEqual(sw["machine_guid"], fakes.GUID)
        self.assertEqual(sw["os_install_date_utc"], "2023-11-14T22:13:20Z")
        sy = reg.read_system_identity(fakes.FakeHive(fakes.SYSTEM))
        self.assertEqual((sy["hostname"], sy["domain"]), ("SRCHOST", "corp.example"))
        self.assertEqual(reg.fqdn("H", "d.com"), "H.d.com")
        self.assertEqual(reg.fqdn("H", ""), "H")

    def test_control_set_from_select(self):
        h = fakes.FakeHive({("Select", "Current"): 2})
        self.assertEqual(reg.current_control_set(h), "ControlSet002")

    def test_fallback_and_total_failure(self):
        def boom(path):
            raise IOError("bad hive")
        ok = lambda path: fakes.FakeHive({})
        hive, method, attempts = reg.open_hive("p", "SOFTWARE", [("a", boom), ("b", ok)])
        self.assertEqual(method, "b")
        self.assertEqual([a["result"] for a in attempts], ["failed", "ok"])
        with self.assertRaises(reg.HiveError) as cm:
            reg.open_hive("p", "SYSTEM", [("a", boom), ("b", boom)])
        self.assertEqual(len(cm.exception.attempts), 2)


class TestManifest(unittest.TestCase):
    def test_schema_keys_and_no_overwrite(self):
        m = mf.Manifest("0.0.1", datetime(2026, 11, 24, 19, 24, tzinfo=timezone.utc), "C", "n")
        d = m.to_dict()
        for k in ("manifest_schema_version", "usnproc_version", "processing_timestamp_utc",
                  "processing_status", "status_detail", "source_image",
                  "source_machine_identity", "volume", "usn_journal",
                  "processing_environment", "case", "output", "errors_and_warnings"):
            self.assertIn(k, d)
        self.assertEqual(d["processing_timestamp_utc"], "2026-11-24T19:24:00Z")
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "m.json")
            mf.write_manifest(p, m)
            self.assertEqual(json.load(open(p))["case"]["case_id"], "C")
            with self.assertRaises(FileExistsError):
                mf.write_manifest(p, m)

    def test_hash(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "img")
            open(p, "wb").write(b"abc")
            d = mf.sha256_file(p)
            self.assertEqual(d[:8], "ba7816bf")
            self.assertEqual(mf.HashJob(p).start().result(), (d, None))
            self.assertTrue(mf.compare_hash(d, d.upper()))
            self.assertFalse(mf.compare_hash(d, "0" * 64))
            self.assertIsNone(mf.compare_hash(d, None))


class TestEvtxWriter(unittest.TestCase):
    def write(self, td, n):
        p = os.path.join(td, "t.evtx")
        with evtx.EvtxWriter(p, computer="SRCHOST") as w:
            for i in range(n):
                w.write(100 + i % 6, FT_2026 + i * 10_000_000,
                        ["\nblob %d" % i, "F:\\f%d" % i, "u", "g", "", "", "D66FD839"])
        return p

    def test_structure_and_crcs(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.write(td, 2500)
            data = open(p, "rb").read()
            self.assertEqual(data[:8], b"ElfFile\x00")
            self.assertEqual(struct.unpack_from("<I", data, 124)[0],
                             zlib.crc32(data[:120]) & 0xFFFFFFFF)
            n_chunks = struct.unpack_from("<H", data, 42)[0]
            self.assertGreater(n_chunks, 1)
            self.assertEqual(len(data), 4096 + n_chunks * 65536)
            self.assertEqual(struct.unpack_from("<Q", data, 24)[0], 2501)
            for c in range(n_chunks):
                ch = data[4096 + c * 65536: 4096 + (c + 1) * 65536]
                self.assertEqual(ch[:8], b"ElfChnk\x00")
                free = struct.unpack_from("<I", ch, 48)[0]
                self.assertEqual(struct.unpack_from("<I", ch, 52)[0],
                                 zlib.crc32(ch[512:free]) & 0xFFFFFFFF)
                self.assertEqual(struct.unpack_from("<I", ch, 124)[0],
                                 zlib.crc32(ch[:120] + ch[128:512]) & 0xFFFFFFFF)

    def test_never_overwrites(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.write(td, 1)
            with self.assertRaises(FileExistsError):
                evtx.EvtxWriter(p, computer="x")
            with self.assertRaises(FileExistsError):
                evtx.write_empty(p)

    @unittest.skipIf(PyEvtx is None, "python-evtx not installed")
    def test_roundtrip_python_evtx(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.write(td, 2500)
            with PyEvtx(p) as log:
                fh = log.get_file_header()
                self.assertTrue(fh.verify())
                self.assertTrue(all(c.verify() for c in fh.chunks()))
                recs = list(log.records())
                self.assertEqual(len(recs), 2500)
                x = recs[1234].xml()
                self.assertIn('<Provider Name="USNJournalMonitor">', x)
                self.assertIn("<EventID Qualifiers=\"0\">104</EventID>", x)
                self.assertIn("<Computer>SRCHOST</Computer>", x)
                self.assertIn("<Channel>FileSystem</Channel>", x)
                self.assertIn("<EventRecordID>1235</EventRecordID>", x)
                self.assertIn("<Data>F:\\f1234</Data>", x)
                self.assertEqual(x.count("<Data>"), 7)
                self.assertEqual(recs[1234].timestamp(),
                                 journal.filetime_to_datetime(FT_2026 + 1234 * 10_000_000))

    @unittest.skipIf(PyEvtx is None, "python-evtx not installed")
    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "e.evtx")
            evtx.write_empty(p)
            with PyEvtx(p) as log:
                self.assertTrue(log.get_file_header().verify())
                self.assertEqual(list(log.records()), [])


class TestContract(unittest.TestCase):
    USNMON = os.path.join(os.path.dirname(__file__), "..", "..", "onyxomega",
                          "usnjournal2eventlog", "usn_common.py")

    @unittest.skipUnless(os.path.exists(USNMON), "usnmon checkout not present")
    def test_vendored_copy_matches_usnmon(self):
        here = open(os.path.join(os.path.dirname(__file__), "..", "usn_common.py"),
                    encoding="utf-8").read()
        there = open(self.USNMON, encoding="utf-8").read()
        self.assertTrue(here.endswith(there))

    def test_values_cover_every_contract_field(self):
        ident = {"machine_guid": "g", "hostname": "h", "domain": "d",
                 "machine_sid": "S-1", "os_current_build": "19045"}
        base = usnproc.base_values(ident, "D66FD839", 123)
        rec = {"reason": 0x100, "timestamp": FT_2026, "usn": 42}
        eid, vals = usnproc.build_values(base, rec, "F:\\a")
        self.assertEqual(eid, 100)
        self.assertEqual(set(vals) - set(common.EVENT_FIELD_NAMES), set())
        self.assertEqual(set(common.EVENT_FIELD_NAMES) - set(vals), set())
        self.assertEqual(vals["UtcTime"], journal.filetime_to_utc_str(FT_2026))
        self.assertEqual((vals["Qpc"], vals["HiResUtc"]), ("", ""))
        self.assertEqual(len(common.build_event_strings(vals)), 7)


if __name__ == "__main__":
    unittest.main()
