"""
usnproc_manifest.py -- chain-of-custody manifest (DESIGN_LOCK Q9) and file
hashing.

The manifest is the ONLY place the processing ("current") time and the
analysis-VM identity appear, alongside the output file names (Q10, Q11).
"""

import getpass
import hashlib
import json
import os
import platform
import socket
import sys
import threading
from datetime import datetime, timezone

MANIFEST_SCHEMA_VERSION = "1.0"
HASH_BLOCK = 8 * 1024 * 1024

STATUS_COMPLETE, STATUS_PARTIAL, STATUS_EMPTY, STATUS_ABORTED = (
    "complete", "partial", "empty", "aborted")


def utc_now():
    return datetime.now(timezone.utc)


def iso_z(dt, ms=False):
    if ms:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def compact_utc(dt):
    """File-name form of the processing time: YYYYMMDDTHHMMSSZ."""
    return dt.strftime("%Y%m%dT%H%M%SZ")


def _pkg_version(name):
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:                       # noqa: BLE001
        return ""


def sha256_file(path, progress=None, block=HASH_BLOCK):
    h = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(block)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    return h.hexdigest()


class HashJob:
    """Hash a (large) image file on a background thread while the journal
    is processed."""

    def __init__(self, path, progress=None):
        self.path = path
        self.progress = progress
        self.digest = None
        self.error = None
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            self.digest = sha256_file(self.path, self.progress)
        except Exception as exc:            # noqa: BLE001
            self.error = exc

    def start(self):
        self._t.start()
        return self

    def result(self):
        self._t.join()
        return self.digest, self.error


def compare_hash(computed, supplied):
    """None if either side is missing, else True/False (case-insensitive)."""
    if not computed or not supplied:
        return None
    return computed.strip().lower() == supplied.strip().lower()


class Manifest:
    def __init__(self, version, processed_at, case_id=None, case_notes=None):
        self.processed_at = processed_at
        self.data = {
            "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
            "usnproc_version": version,
            "processing_timestamp_utc": iso_z(processed_at),
            "processing_status": STATUS_ABORTED,
            "status_detail": "",
            "source_image": {
                "image_hash_sha256_computed": None,
                "image_hash_sha256_examiner_supplied": None,
                "image_hash_match": None,
                "image_hash_scope": "file",
                "image_path_at_processing": None,
                "mount_tool": "unknown",
                "mount_drive_letter": None,
            },
            "source_machine_identity": {
                "machine_guid": "", "hostname": "", "domain": "",
                "os_product_name": "", "os_current_build": "",
                "os_install_date_utc": "", "registered_owner": "",
                "registered_organization": "", "machine_sid": "",
                "system_root": "", "last_shutdown_utc": "",
            },
            "volume": {
                "drive_letter_at_processing": None,
                "drive_letter_on_source_system": None,
                "drive_letter_on_source_system_basis": "",
                "volume_serial_number": "",
                "filesystem": "",
            },
            "usn_journal": {
                "journal_id": "", "first_usn": None, "next_usn": None,
                "lowest_valid_usn": None, "max_usn": None,
                "max_size_bytes": None, "allocation_delta_bytes": None,
                "records_extracted": 0, "records_failed_parse": 0,
                "paths_resolved_live": 0, "paths_resolved_from_journal": 0,
                "paths_unresolved": 0,
            },
            "processing_environment": {
                "analysis_vm_hostname": socket.gethostname(),
                "analysis_vm_user": _safe_user(),
                "python_version": platform.python_version(),
                "registry_read_method": {},
                "registry_read_attempts": {},
                "pywin32_version": _pkg_version("pywin32"),
                "python_registry_version": _pkg_version("python-registry"),
                "command_line": list(sys.argv),
            },
            "case": {"case_id": case_id, "case_notes": case_notes},
            "output": {"evtx_filename": None, "evtx_hash_sha256": None,
                       "evtx_size_bytes": None, "evtx_record_count": 0},
            "notes": [],
            "errors_and_warnings": [],
        }

    # -- setters ------------------------------------------------------------
    def section(self, name):
        return self.data[name]

    def update(self, name, **fields):
        self.data[name].update(fields)

    def add_error(self, severity, code, detail):
        self.data["errors_and_warnings"].append({
            "timestamp_utc": iso_z(utc_now(), ms=True),
            "severity": severity, "code": code, "detail": detail})

    def add_note(self, text):
        if text not in self.data["notes"]:
            self.data["notes"].append(text)

    def finalize(self, status, detail):
        self.data["processing_status"] = status
        self.data["status_detail"] = detail

    def to_dict(self):
        return self.data


def _safe_user():
    try:
        return getpass.getuser()
    except Exception:                       # noqa: BLE001
        return ""


def write_manifest(path, manifest):
    """Write JSON to a temp file, then rename into place. Never overwrites:
    raises FileExistsError if the target already exists."""
    tmp = path + ".tmp"
    with open(tmp, "x", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    try:
        if os.path.exists(path):
            raise FileExistsError(path)
        os.rename(tmp, path)        # on Windows, rename fails if target exists
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
