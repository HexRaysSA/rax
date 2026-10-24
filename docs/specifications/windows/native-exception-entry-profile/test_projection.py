"""The public dispatcher observation cannot contain private code captures."""

import hashlib
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "exception_entry_profile", Path(__file__).with_name("run-v2.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class ProjectionTests(unittest.TestCase):
    def test_code_capture_becomes_bounded_identity_without_mutating_input(self):
        raw = bytes(range(192))
        capture = {
            "kind": "code",
            "export": "KiUserExceptionDispatcher",
            "rva": 4096,
            "hex": raw.hex(),
        }
        original = dict(capture)
        public = PROFILE.project_record(capture)
        self.assertEqual(capture, original)
        self.assertEqual(
            public,
            {
                "kind": "code",
                "export": "KiUserExceptionDispatcher",
                "rva": 4096,
                "instruction_bytes": 192,
                "code_sha256": hashlib.sha256(raw).hexdigest(),
            },
        )
        self.assertNotIn("hex", public)

    def test_absent_export_stays_explicit(self):
        row = {"kind": "code", "export": "RtlDispatchException", "available": False}
        self.assertEqual(PROFILE.project_record(row), row)

    def test_truncated_and_oversized_instruction_captures_are_rejected(self):
        for size in (0, 191, 193):
            with self.subTest(size=size), self.assertRaises(RuntimeError):
                PROFILE.project_record(
                    {
                        "kind": "code",
                        "export": "dispatcher",
                        "rva": 4096,
                        "hex": "90" * size,
                    }
                )

    def test_extra_code_fields_are_rejected(self):
        with self.assertRaises(RuntimeError):
            PROFILE.project_record(
                {
                    "kind": "code",
                    "export": "dispatcher",
                    "rva": 4096,
                    "hex": "90" * 192,
                    "address": 123,
                }
            )

    def test_private_code_under_another_record_kind_is_rejected(self):
        with self.assertRaises(RuntimeError):
            PROFILE.project_record({"kind": "host", "hex": "90" * 192})

    def test_available_export_without_bytes_is_rejected(self):
        with self.assertRaises(RuntimeError):
            PROFILE.project_record(
                {"kind": "code", "export": "dispatcher", "available": True}
            )


if __name__ == "__main__":
    unittest.main()
