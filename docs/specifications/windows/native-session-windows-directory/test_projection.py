"""Portable integrity checks; synthetic shapes are not native observations."""

import copy
import hashlib
import unittest
from pathlib import Path

from verify import verify


def counted(text):
    raw = text.encode("utf-16-le")
    return {
        "text": text,
        "units": [
            int.from_bytes(raw[i : i + 2], "little") for i in range(0, len(raw), 2)
        ],
    }


def fixture(crlf=False):
    raw = (Path(__file__).parent / "run-v2.py").read_bytes().replace(b"\r\n", b"\n")
    if crlf:
        raw = raw.replace(b"\n", b"\r\n")
    files = {
        name: {"path": name, "bytes": 100, "sha256": "1" * 64, "pe_machine": 0x8664}
        for name in ("observer", "python", "python_dll", "ntdll")
    }
    files["observer"].update(
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), pe_machine=None
    )
    paths = {
        "directory": ["\\Windows", "\\Sessions\\2\\Windows"],
        "section": [
            "\\Windows\\SharedSection",
            "\\Sessions\\2\\Windows\\SharedSection",
        ],
    }
    rows = []
    for kind, names in paths.items():
        for index, path in enumerate(names):
            for altered in (False, True):
                for flags in (0, 0x40, 0x1000, 0x1040):
                    rows.append(
                        {
                            "kind": kind,
                            "path_index": index,
                            "path": path.swapcase() if altered else path,
                            "altered_case": altered,
                            "flags": flags,
                            "requested_access": (
                                0x02000000 if kind == "directory" else 4
                            ),
                            "status": 0,
                            "information": {
                                "name": counted(names[1]),
                                "type": counted(
                                    "Directory" if kind == "directory" else "Section"
                                ),
                                "granted_access": 3 if kind == "directory" else 4,
                            },
                            "same_reference_status": 0,
                        }
                    )
    return {
        "schema": "native-session-windows-directory-v2",
        "version": [10, 0, 20348, 2, ""],
        "pointer_bytes": 8,
        "attributes_bytes": 48,
        "unicode_bytes": 16,
        "process_machine": 0,
        "native_machine": 0x8664,
        "session": 2,
        "paths": paths,
        "rows": rows,
        "distinct_type_status": 0xC00001AC,
        "handle_count_before": 20,
        "handle_count_after": 20,
        "files_before": files,
        "files_after": copy.deepcopy(files),
    }


class Integrity(unittest.TestCase):
    def test_exact_lf_and_crlf_source_inputs(self):
        verify(fixture())
        verify(fixture(True))

    def test_rejects_replaced_executed_source(self):
        value = fixture()
        for files in (value["files_before"], value["files_after"]):
            files["observer"]["sha256"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "source differs"):
            verify(value)

    def test_rejects_changed_runtime(self):
        value = fixture()
        value["files_after"]["ntdll"]["sha256"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "identity changed"):
            verify(value)

    def test_rejects_unqualified_native_abi(self):
        value = fixture()
        value["process_machine"] = 0x8664
        with self.assertRaisesRegex(ValueError, "native observer ABI"):
            verify(value)

    def test_rejects_duplicate_query(self):
        value = fixture()
        value["rows"][-1] = copy.deepcopy(value["rows"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(value)

    def test_rejects_foreign_session_path(self):
        value = fixture()
        value["rows"][-1]["path"] = "\\Sessions\\3\\Windows\\SharedSection"
        with self.assertRaisesRegex(ValueError, "path differs"):
            verify(value)

    def test_rejects_rendered_name_without_original_units(self):
        value = fixture()
        value["rows"][0]["information"]["name"]["text"] = "\\Changed"
        with self.assertRaisesRegex(ValueError, "rendered text disagree"):
            verify(value)

    def test_rejects_metadata_after_failed_open(self):
        value = fixture()
        value["rows"][-1]["status"] = 0xC0000034
        with self.assertRaisesRegex(ValueError, "failed open"):
            verify(value)
