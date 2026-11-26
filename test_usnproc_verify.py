"""test_usnproc_verify.py -- exercise branch logic in usnproc_verify without Windows.

Simulates various Windows API return values and error conditions to verify
that verification logic produces the right output for each scenario.
"""

import io
import struct
import sys
import unittest
from unittest.mock import patch, MagicMock

# Make usnproc_verify importable despite non-Windows environment
sys.path.insert(0, '.')

# Force _WINDOWS = True in the module even though we're on Linux, and inject
# fake win32 modules BEFORE import.
fake_win32api = MagicMock()
fake_win32con = MagicMock()
fake_win32file = MagicMock()
fake_win32con.GENERIC_READ = 0x80000000
fake_win32con.FILE_SHARE_READ = 0x00000001
fake_win32con.FILE_SHARE_WRITE = 0x00000002
fake_win32con.OPEN_EXISTING = 3

sys.modules['win32api'] = fake_win32api
sys.modules['win32con'] = fake_win32con
sys.modules['win32file'] = fake_win32file

import usnproc_verify as uv
# Force the flag on since our mocks satisfy the import
uv._WINDOWS = True
uv.win32api = fake_win32api
uv.win32con = fake_win32con
uv.win32file = fake_win32file


class DriveLetterNormalizationTests(unittest.TestCase):

    def test_basic_letter(self):
        self.assertEqual(uv.normalize_drive_letter('F'), 'F:\\')

    def test_lowercase(self):
        self.assertEqual(uv.normalize_drive_letter('f'), 'F:\\')

    def test_letter_colon(self):
        self.assertEqual(uv.normalize_drive_letter('F:'), 'F:\\')

    def test_letter_colon_backslash(self):
        self.assertEqual(uv.normalize_drive_letter('F:\\'), 'F:\\')

    def test_letter_colon_slash(self):
        self.assertEqual(uv.normalize_drive_letter('F:/'), 'F:\\')

    def test_whitespace_stripped(self):
        self.assertEqual(uv.normalize_drive_letter('  F  '), 'F:\\')

    def test_quotes_stripped(self):
        self.assertEqual(uv.normalize_drive_letter('"F:"'), 'F:\\')
        self.assertEqual(uv.normalize_drive_letter("'F:'"), 'F:\\')

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            uv.normalize_drive_letter('')

    def test_whitespace_only_raises(self):
        with self.assertRaises(ValueError):
            uv.normalize_drive_letter('   ')

    def test_double_letter_raises(self):
        with self.assertRaises(ValueError):
            uv.normalize_drive_letter('FG')

    def test_extra_path_raises(self):
        with self.assertRaises(ValueError):
            uv.normalize_drive_letter('F:extra')
        with self.assertRaises(ValueError):
            uv.normalize_drive_letter('F:\\extra')

    def test_dots_raise(self):
        with self.assertRaises(ValueError):
            uv.normalize_drive_letter('..')

    def test_volume_path(self):
        self.assertEqual(uv.volume_path('F:\\'), r'\\.\F:')
        self.assertEqual(uv.volume_path('C:\\'), r'\\.\C:')


class DrivePresenceTests(unittest.TestCase):

    def test_drive_fixed_ok(self):
        fake_win32file.GetDriveType.return_value = 3   # DRIVE_FIXED
        ok, msg = uv.check_drive_present('F:\\')
        self.assertTrue(ok)
        self.assertIn('FIXED', msg)

    def test_drive_removable_ok(self):
        fake_win32file.GetDriveType.return_value = 2   # DRIVE_REMOVABLE
        ok, msg = uv.check_drive_present('F:\\')
        self.assertTrue(ok)
        self.assertIn('REMOVABLE', msg)

    def test_drive_unknown_fails(self):
        fake_win32file.GetDriveType.return_value = 0   # DRIVE_UNKNOWN
        ok, msg = uv.check_drive_present('F:\\')
        self.assertFalse(ok)
        self.assertIn('UNKNOWN', msg)

    def test_drive_no_root_fails(self):
        fake_win32file.GetDriveType.return_value = 1   # DRIVE_NO_ROOT_DIR
        ok, msg = uv.check_drive_present('F:\\')
        self.assertFalse(ok)
        self.assertIn('no root', msg.lower())

    def test_drive_exception(self):
        fake_win32file.GetDriveType.side_effect = OSError('boom')
        ok, msg = uv.check_drive_present('F:\\')
        self.assertFalse(ok)
        self.assertIn('boom', msg)
        # restore
        fake_win32file.GetDriveType.side_effect = None


class NTFSCheckTests(unittest.TestCase):

    def test_ntfs_ok(self):
        fake_win32api.GetVolumeInformation.return_value = (
            'MyLabel', 0xA1B2C3D4, 255, 0, 'NTFS')
        ok, msg = uv.check_ntfs('F:\\')
        self.assertTrue(ok)
        self.assertIn('NTFS', msg)

    def test_ntfs_case_insensitive(self):
        fake_win32api.GetVolumeInformation.return_value = (
            '', 0, 255, 0, 'ntfs')
        ok, _msg = uv.check_ntfs('F:\\')
        self.assertTrue(ok)

    def test_fat32_fails(self):
        fake_win32api.GetVolumeInformation.return_value = (
            '', 0, 255, 0, 'FAT32')
        ok, msg = uv.check_ntfs('F:\\')
        self.assertFalse(ok)
        self.assertIn('FAT32', msg)

    def test_exfat_fails(self):
        fake_win32api.GetVolumeInformation.return_value = (
            '', 0, 255, 0, 'exFAT')
        ok, msg = uv.check_ntfs('F:\\')
        self.assertFalse(ok)
        self.assertIn('exFAT', msg)

    def test_exception(self):
        fake_win32api.GetVolumeInformation.side_effect = OSError('permission')
        ok, msg = uv.check_ntfs('F:\\')
        self.assertFalse(ok)
        self.assertIn('permission', msg)
        fake_win32api.GetVolumeInformation.side_effect = None


class QueryJournalTests(unittest.TestCase):

    def setUp(self):
        # Successful CreateFile default
        fake_win32file.CreateFile.reset_mock()
        fake_win32file.CreateFile.side_effect = None
        fake_win32file.CreateFile.return_value = 'handle'
        fake_win32file.CloseHandle.return_value = None
        fake_win32file.DeviceIoControl.reset_mock()
        fake_win32file.DeviceIoControl.side_effect = None

    def _make_journal_buf(self, jid=0x01d5000000000001,
                          first_usn=1000, next_usn=2000,
                          lowest_valid=500, max_usn=(1<<63)-1,
                          max_size=33554432, alloc_delta=524288):
        return struct.pack(uv._QUERY_USN_JOURNAL_FMT, jid,
                           first_usn, next_usn, lowest_valid, max_usn,
                           max_size, alloc_delta)

    def test_query_success(self):
        buf = self._make_journal_buf()
        fake_win32file.DeviceIoControl.return_value = buf
        ok, msg, info = uv.check_query_journal('F:\\')
        self.assertTrue(ok)
        self.assertIsNotNone(info)
        self.assertEqual(info['JournalId'], 0x01d5000000000001)
        self.assertEqual(info['FirstUsn'], 1000)
        self.assertEqual(info['NextUsn'], 2000)
        self.assertEqual(info['MaxSize'], 33554432)

    def test_query_error_1179_no_journal(self):
        exc = OSError('no journal')
        exc.winerror = 1179
        fake_win32file.DeviceIoControl.side_effect = exc
        ok, msg, info = uv.check_query_journal('F:\\')
        self.assertFalse(ok)
        self.assertIsNone(info)
        self.assertIn('1179', msg)
        self.assertIn('JOURNAL_NOT_ACTIVE', msg)

    def test_query_error_1_no_ioctl_support(self):
        exc = OSError('invalid function')
        exc.winerror = 1
        fake_win32file.DeviceIoControl.side_effect = exc
        ok, msg, info = uv.check_query_journal('F:\\')
        self.assertFalse(ok)
        self.assertIsNone(info)
        self.assertIn('INVALID_FUNCTION', msg)
        self.assertIn('does not', msg)

    def test_query_generic_error(self):
        exc = OSError('other')
        exc.winerror = 5   # ERROR_ACCESS_DENIED
        fake_win32file.DeviceIoControl.side_effect = exc
        ok, msg, info = uv.check_query_journal('F:\\')
        self.assertFalse(ok)
        self.assertIsNone(info)

    def test_createfile_error(self):
        fake_win32file.CreateFile.side_effect = OSError('cannot open')
        ok, msg, info = uv.check_query_journal('F:\\')
        self.assertFalse(ok)
        self.assertIsNone(info)
        self.assertIn('CreateFile', msg)

    def test_truncated_buffer(self):
        fake_win32file.DeviceIoControl.return_value = b'\x00' * 30
        ok, msg, info = uv.check_query_journal('F:\\')
        self.assertFalse(ok)
        self.assertIsNone(info)


class ReadJournalTests(unittest.TestCase):

    def setUp(self):
        fake_win32file.CreateFile.reset_mock()
        fake_win32file.CreateFile.side_effect = None
        fake_win32file.CreateFile.return_value = 'handle'
        fake_win32file.CloseHandle.return_value = None
        fake_win32file.DeviceIoControl.reset_mock()
        fake_win32file.DeviceIoControl.side_effect = None
        self.jinfo = {
            'JournalId': 0x01d5000000000001,
            'FirstUsn': 1000,
            'NextUsn': 2000,
            'LowestValidUsn': 500,
            'MaxUsn': (1 << 63) - 1,
            'MaxSize': 33554432,
            'AllocationDelta': 524288,
        }

    def test_read_success_with_records(self):
        # Response: 8-byte next-usn header + fake record data
        fake_record = b'\x00' * 96   # fake USN record
        buf = struct.pack('<q', 1500) + fake_record
        fake_win32file.DeviceIoControl.return_value = buf
        ok, msg, rec_bytes = uv.check_read_journal('F:\\', self.jinfo)
        self.assertTrue(ok)
        self.assertEqual(rec_bytes, 96)

    def test_read_success_empty_journal(self):
        # Response: just the 8-byte next-usn header, no records
        buf = struct.pack('<q', 1000)
        fake_win32file.DeviceIoControl.return_value = buf
        ok, msg, rec_bytes = uv.check_read_journal('F:\\', self.jinfo)
        self.assertTrue(ok)
        self.assertEqual(rec_bytes, 0)
        self.assertIn('empty', msg.lower())

    def test_read_1180_error(self):
        exc = OSError('entry deleted')
        exc.winerror = 1180
        fake_win32file.DeviceIoControl.side_effect = exc
        ok, msg, rec_bytes = uv.check_read_journal('F:\\', self.jinfo)
        self.assertFalse(ok)
        self.assertIn('1180', msg)

    def test_read_truncated_buffer(self):
        fake_win32file.DeviceIoControl.return_value = b'\x00' * 4
        ok, msg, rec_bytes = uv.check_read_journal('F:\\', self.jinfo)
        self.assertFalse(ok)


class HivePresenceTests(unittest.TestCase):

    def test_both_hives_present(self, ):
        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', return_value=1024*1024*50):
            ok, msg, results = uv.check_hive_files_present('F:\\')
            self.assertTrue(ok)
            self.assertTrue(results['SOFTWARE'][0])
            self.assertTrue(results['SYSTEM'][0])

    def test_software_missing(self):
        def fake_exists(path):
            return 'SYSTEM' in path
        with patch('os.path.exists', side_effect=fake_exists), \
             patch('os.path.getsize', return_value=1024):
            ok, msg, results = uv.check_hive_files_present('F:\\')
            self.assertFalse(ok)
            self.assertFalse(results['SOFTWARE'][0])
            self.assertTrue(results['SYSTEM'][0])
            self.assertIn('SOFTWARE', msg)

    def test_both_missing(self):
        with patch('os.path.exists', return_value=False):
            ok, msg, results = uv.check_hive_files_present('F:\\')
            self.assertFalse(ok)
            self.assertFalse(results['SOFTWARE'][0])
            self.assertFalse(results['SYSTEM'][0])

    def test_stat_failure(self):
        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', side_effect=OSError('EIO')):
            ok, msg, results = uv.check_hive_files_present('F:\\')
            self.assertFalse(ok)


class PythonRegistryAvailableTests(unittest.TestCase):

    def test_import_success(self):
        # Simulate the registry module being available
        fake_reg = MagicMock()
        fake_reg.Registry = MagicMock()
        with patch.dict(sys.modules, {
            'Registry': fake_reg, 'Registry.Registry': fake_reg.Registry}):
            ok, msg = uv.check_python_registry_available()
            self.assertTrue(ok)

    def test_import_failure(self):
        # Force ImportError by making sure Registry can't be imported
        original = sys.modules.get('Registry.Registry')
        original_pkg = sys.modules.get('Registry')
        try:
            sys.modules.pop('Registry', None)
            sys.modules.pop('Registry.Registry', None)
            # Also block re-import by inserting None
            sys.modules['Registry.Registry'] = None
            ok, msg = uv.check_python_registry_available()
            self.assertFalse(ok)
            self.assertIn('pip install python-registry', msg)
        finally:
            if original:
                sys.modules['Registry.Registry'] = original
            elif 'Registry.Registry' in sys.modules and \
                    sys.modules['Registry.Registry'] is None:
                del sys.modules['Registry.Registry']
            if original_pkg:
                sys.modules['Registry'] = original_pkg


class OrchestratorTests(unittest.TestCase):
    """Test the main run_verification orchestration - happy path and various
    failure paths."""

    def setUp(self):
        # Sensible defaults for all fake_win32 calls
        fake_win32file.CreateFile.reset_mock()
        fake_win32file.CreateFile.side_effect = None
        fake_win32file.CreateFile.return_value = 'handle'
        fake_win32file.CloseHandle.return_value = None
        fake_win32file.DeviceIoControl.reset_mock()
        fake_win32file.DeviceIoControl.side_effect = None
        fake_win32file.GetDriveType.reset_mock()
        fake_win32file.GetDriveType.side_effect = None
        fake_win32file.GetDriveType.return_value = 3   # FIXED
        fake_win32api.GetVolumeInformation.reset_mock()
        fake_win32api.GetVolumeInformation.side_effect = None
        fake_win32api.GetVolumeInformation.return_value = (
            'MyLabel', 0xA1B2C3D4, 255, 0, 'NTFS')

    def test_orchestrator_drive_not_present(self):
        fake_win32file.GetDriveType.return_value = 0
        # Suppress print output
        with patch('sys.stdout', new_callable=io.StringIO) as buf:
            passed, failed, skipped = uv.run_verification('F:\\')
        self.assertEqual(passed, 0)
        self.assertGreaterEqual(failed, 1)
        self.assertGreater(skipped, 0)
        output = buf.getvalue()
        self.assertIn('FAIL', output)
        self.assertIn('SKIP', output)

    def test_orchestrator_wrong_filesystem(self):
        fake_win32api.GetVolumeInformation.return_value = (
            '', 0, 255, 0, 'FAT32')
        with patch('sys.stdout', new_callable=io.StringIO) as buf:
            passed, failed, skipped = uv.run_verification('F:\\')
        # Drive-present passes, ntfs fails, rest skipped (5 original + 6 new)
        self.assertEqual(passed, 1)
        self.assertEqual(failed, 1)
        self.assertEqual(skipped, 5 + uv.N_EXTRA_CHECKS)


# --------------------------------------------------------------------------- #
# Checks 8-13 (added for usnproc v0.0.1 / DESIGN_LOCK v1.3)
# --------------------------------------------------------------------------- #
import os  # noqa: E402
import struct as _struct  # noqa: E402


class _Val:
    def __init__(self, name, value):
        self._n, self._v = name, value

    def name(self):
        return self._n

    def value(self):
        return self._v


class _Key:
    def __init__(self, values):
        self._values = values

    def values(self):
        return [_Val(n, v) for n, v in self._values.items()]

    def value(self, name):
        if name not in self._values:
            raise KeyError(name)
        return _Val(name, self._values[name])


def fake_registry_module(hives):
    """hives: {hive_file_name: {key_path: {value_name: value}}} -> a fake
    Registry.Registry module whose Registry(path) serves those keys."""
    class FakeRegistry:
        def __init__(self, path):
            name = os.path.basename(path.replace("\\", "/"))
            if name not in hives:
                raise IOError("cannot open %s" % path)
            self._keys = hives[name]

        def open(self, key_path):
            if key_path not in self._keys:
                raise KeyError(key_path)
            return _Key(self._keys[key_path])

    mod = MagicMock()
    mod.Registry = FakeRegistry
    pkg = MagicMock()
    pkg.Registry = mod
    return {"Registry": pkg, "Registry.Registry": mod}


SID_V = b"\x00" * 40 + bytes([1, 4, 0, 0, 0, 0, 0, 5]) + _struct.pack("<4I", 21, 1, 2, 3)
GOOD_HIVES = {
    "SOFTWARE": {"Microsoft\\Windows NT\\CurrentVersion": {"SystemRoot": "C:\\WINDOWS"},
                 "Microsoft\\Cryptography": {"MachineGuid": "g"}},
    "SYSTEM": {"Select": {"Current": 1},
               "ControlSet001\\Control\\ComputerName\\ComputerName":
                   {"ComputerName": "SRCHOST"},
               "ControlSet001\\Control\\Windows":
                   {"ShutdownTime": _struct.pack("<Q", 133600000000000000)}},
    "SAM": {"SAM\\Domains\\Account": {"V": SID_V}},
}


class ExtraCheckTests(unittest.TestCase):

    def reg(self, hives=GOOD_HIVES):
        return patch.dict(sys.modules, fake_registry_module(hives))

    def test_system_hive_ok(self):
        with self.reg():
            ok, msg, host = uv.check_system_hive('F:\\')
        self.assertTrue(ok)
        self.assertEqual(host, 'SRCHOST')

    def test_system_hive_missing_hostname(self):
        h = dict(GOOD_HIVES, SYSTEM={"Select": {"Current": 2}})
        with self.reg(h):
            ok, msg, host = uv.check_system_hive('F:\\')
        self.assertFalse(ok)
        self.assertIn('ControlSet002', msg)

    def test_system_hive_unopenable(self):
        h = {k: v for k, v in GOOD_HIVES.items() if k != "SYSTEM"}
        with self.reg(h):
            ok, msg, _ = uv.check_system_hive('F:\\')
        self.assertFalse(ok)

    def test_sam_sid(self):
        with self.reg():
            ok, msg, sid = uv.check_sam_sid('F:\\')
        self.assertTrue(ok)
        self.assertEqual(sid, 'S-1-5-21-1-2-3')

    def test_sam_missing_is_not_ok(self):
        h = {k: v for k, v in GOOD_HIVES.items() if k != "SAM"}
        with self.reg(h):
            ok, msg, sid = uv.check_sam_sid('F:\\')
        self.assertFalse(ok)
        self.assertIn('MachineSID', msg)

    def test_system_root(self):
        with self.reg():
            ok, msg, letter = uv.check_system_root('F:\\')
        self.assertTrue(ok)
        self.assertEqual(letter, 'C:\\')

    def test_system_root_missing_mentions_fallback(self):
        h = dict(GOOD_HIVES, SOFTWARE={"Microsoft\\Cryptography": {"MachineGuid": "g"}})
        with self.reg(h):
            ok, msg, letter = uv.check_system_root('F:\\')
        self.assertFalse(ok)
        self.assertIn('VolumeSerial', msg)

    def test_shutdown_time(self):
        with self.reg():
            ok, msg, when = uv.check_shutdown_time('F:\\')
        self.assertTrue(ok)
        self.assertTrue(when.startswith('2024-05-12'))

    def test_shutdown_time_missing(self):
        h = dict(GOOD_HIVES, SYSTEM={"Select": {"Current": 1}})
        with self.reg(h):
            ok, msg, when = uv.check_shutdown_time('F:\\')
        self.assertFalse(ok)
        self.assertIn('1601-01-01', msg)

    def test_usnjrnl_visible(self):
        with patch('os.stat', return_value=None):
            self.assertTrue(uv.check_usnjrnl_visible('F:\\')[0])
        with patch('os.stat', side_effect=PermissionError()):
            self.assertTrue(uv.check_usnjrnl_visible('F:\\')[0])
        with patch('os.stat', side_effect=FileNotFoundError()):
            ok, msg = uv.check_usnjrnl_visible('F:\\')
        self.assertFalse(ok)
        self.assertIn('missing', msg)

    def test_elevated(self):
        fake_ctypes = MagicMock()
        fake_ctypes.windll.shell32.IsUserAnAdmin.return_value = 0
        with patch.dict(sys.modules, {'ctypes': fake_ctypes}):
            ok, msg = uv.check_elevated()
        self.assertFalse(ok)
        self.assertIn('Administrator', msg)
        fake_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
        with patch.dict(sys.modules, {'ctypes': fake_ctypes}):
            self.assertTrue(uv.check_elevated()[0])

    def test_createfile_access_denied_hint(self):
        exc = Exception('denied')
        exc.winerror = 5
        fake_win32file.CreateFile.side_effect = exc
        try:
            ok, msg, _ = uv.check_query_journal('F:\\')
        finally:
            fake_win32file.CreateFile.side_effect = None
        self.assertFalse(ok)
        self.assertIn('elevated', msg)

    def test_extra_checks_warnings_do_not_fail(self):
        h = {"SOFTWARE": {}, "SYSTEM": GOOD_HIVES["SYSTEM"]}     # no SAM, no SystemRoot
        fake_ctypes = MagicMock()
        fake_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
        with self.reg(h), patch.dict(sys.modules, {'ctypes': fake_ctypes}), \
                patch('os.stat', return_value=None), \
                patch('sys.stdout', new_callable=io.StringIO) as buf:
            passed, failed = uv.run_extra_checks('F:\\')
        self.assertEqual(failed, 0)
        self.assertEqual(passed, 4)       # elevated, SYSTEM, ShutdownTime, $UsnJrnl
        self.assertEqual(buf.getvalue().count('[WARN]'), 2)

    def test_extra_checks_required_failures(self):
        fake_ctypes = MagicMock()
        fake_ctypes.windll.shell32.IsUserAnAdmin.return_value = 0
        with self.reg({}), patch.dict(sys.modules, {'ctypes': fake_ctypes}), \
                patch('os.stat', side_effect=FileNotFoundError()), \
                patch('sys.stdout', new_callable=io.StringIO):
            passed, failed = uv.run_extra_checks('F:\\')
        self.assertEqual((passed, failed), (0, 2))

    def test_full_run_all_fourteen_pass(self):
        q = _struct.pack("<QqqqqQQ", 1, 100, 200, 0, 2**63 - 1, 33554432, 524288)
        fake_win32file.GetDriveType.side_effect = None
        fake_win32file.GetDriveType.return_value = 3
        fake_win32file.CreateFile.side_effect = None
        fake_win32file.CreateFile.return_value = 'h'
        fake_win32file.DeviceIoControl.side_effect = [q, _struct.pack("<q", 1) + b"\x00" * 96]
        fake_win32api.GetVolumeInformation.side_effect = None
        fake_win32api.GetVolumeInformation.return_value = ('L', 1, 255, 0, 'NTFS')
        c = MagicMock()
        c.windll.shell32.IsUserAnAdmin.return_value = 1
        try:
            with self.reg(), patch.dict(sys.modules, {'ctypes': c}), \
                    patch('os.path.exists', return_value=True), \
                    patch('os.path.getsize', return_value=1), \
                    patch('os.stat', return_value=None), \
                    patch('sys.stdout', new_callable=io.StringIO):
                result = uv.run_verification('F:\\')
        finally:
            fake_win32file.DeviceIoControl.side_effect = None
        self.assertEqual(result, (8 + uv.N_EXTRA_CHECKS, 0, 0))


if __name__ == '__main__':
    unittest.main(verbosity=2)
