"""Validate bounded public metadata without deriving expectations from native code."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "dispatch_contract", Path(__file__).with_name("run-dispatch-v4.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def frame():
    return {
        "kind": "frame_contract",
        "context_ex_all_offset_bytes": -1232,
        "context_ex_all_bytes": 1632,
        "context_ex_legacy_offset_bytes": -1232,
        "context_ex_legacy_bytes": 1232,
        "context_ex_xstate_offset_bytes": 80,
        "context_ex_xstate_bytes": 320,
        "word0_is_record": False,
        "word1_is_context": False,
        "machine_frame_offsets_bytes": [1424],
    }


class ContractTests(unittest.TestCase):
    def test_scalar_frame_projection_preserves_input(self):
        row = frame()
        self.assertEqual(PROFILE.project_record(row), row)
        self.assertEqual(row["machine_frame_offsets_bytes"], [1424])

    def test_raw_stack_and_out_of_bounds_candidates_are_rejected(self):
        for change in (
            {"stack": "deadbeef"},
            {"machine_frame_offsets_bytes": [8192]},
            {"context_ex_all_offset_bytes": -8193},
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                PROFILE.project_record({**frame(), **change})

    def test_unwind_slots_have_exact_width_and_count(self):
        row = {
            "kind": "unwind_metadata",
            "available": True,
            "begin_rva": 4096,
            "end_rva": 8192,
            "unwind_rva": 12288,
            "version": 1,
            "flags": 0,
            "prolog_bytes": 1,
            "frame_register": 0,
            "frame_offset_units16": 0,
            "slots": [0xA01],
        }
        self.assertEqual(PROFILE.project_record(row), row)
        for slots in ([65536], [0] * 256, ["4096"]):
            with self.subTest(slots=slots), self.assertRaises(RuntimeError):
                PROFILE.project_record({**row, "slots": slots})

    def test_unavailability_remains_an_explicit_reason(self):
        row = {
            "kind": "unwind_metadata",
            "available": False,
            "reason": "x86 registration chain",
        }
        self.assertEqual(PROFILE.project_record(row), row)
        with self.assertRaises(RuntimeError):
            PROFILE.project_record({"kind": "unwind_metadata", "available": False})


if __name__ == "__main__":
    unittest.main()
