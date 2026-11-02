"""Parser and provenance boundaries for native Darwin policy observations."""

import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import observe_trace_policy as probe


class ObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (probe.ROOT / "target").mkdir(exist_ok=True)

    def test_runtime_allowed_and_denied_transitions_remain_distinct(self):
        for after in ["22010001", "32010021"]:
            raw = ("parent_before=22010001 parent_after=22010001 "
                   "child_before=22010001 child_after=" + after + "\n"
                   "child_external=0 errno=0 flags=" + after + "\n")
            result = probe.parse_observation("ptrace_cs_trace", raw)
            self.assertEqual(result["child_after"], int(after, 16))
            self.assertEqual(result["child_external_flags"], int(after, 16))

    def test_restrict_errno_fields_are_not_collapsed(self):
        result = probe.parse_observation("ptrace_restrict",
            "mark=-1 errno=22 trace=-1 errno=1 before=22020801 after=22020801\n")
        self.assertEqual((result["mark_errno"], result["trace_errno"]), (22, 1))
        allowed = probe.parse_observation("ptrace_restrict",
            "mark=0 errno=0 trace=0 errno=0 before=00000800 after=00000820\n")
        self.assertEqual((allowed["trace"], allowed["after"]), (0, 0x820))

    def test_partial_or_extra_output_is_not_a_successful_observation(self):
        valid = "mark=0 errno=0 trace=0 errno=0 before=00000800 after=00000820\n"
        for raw in [valid[:-2], valid + "diagnostic\n", valid.replace("trace=0", "trace=unknown")]:
            with self.assertRaises(ValueError):
                probe.parse_observation("ptrace_restrict", raw)

    def test_image_architecture_and_truncation(self):
        with tempfile.TemporaryDirectory(dir=probe.ROOT / "target") as directory:
            path = Path(directory) / "image"
            path.write_bytes(struct.pack("<II", 0xFEEDFACF, 0x0100000C) + bytes(24))
            self.assertEqual(probe.macho_identity(path, "arm64")["bytes"], 32)
            with self.assertRaises(ValueError):
                probe.macho_identity(path, "x86_64")
            path.write_bytes(path.read_bytes()[:16])
            with self.assertRaises(ValueError):
                probe.macho_identity(path, "arm64")

    def test_output_refuses_existing_directory_and_escape(self):
        with tempfile.TemporaryDirectory(dir=probe.ROOT / "target") as directory:
            root = Path(directory)
            for invalid in [root, root.parent / "outside"]:
                with self.assertRaises(ValueError):
                    probe.contained_output(root, invalid)
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaises(ValueError):
                probe.contained_output(root, existing)
            if probe.sys.platform != "win32":
                (root / "escape").symlink_to(root.parent, target_is_directory=True)
                with self.assertRaises(ValueError):
                    probe.contained_output(root, root / "escape" / "new")

    def test_non_darwin_reports_unavailability_without_creating_output(self):
        with patch.object(probe.sys, "platform", "linux"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main(["--output", "unused"]), 2)
        self.assertIn('"state": "unavailable"', output.getvalue())


if __name__ == "__main__":
    (probe.ROOT / "target").mkdir(exist_ok=True)
    unittest.main()
