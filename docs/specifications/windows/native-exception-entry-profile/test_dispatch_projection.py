"""Dispatcher observations reject raw bytes and require native lifecycle proof."""

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "dispatch_profile", Path(__file__).with_name("run-dispatch-v3.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def capture():
    return [
        {
            "kind": "host",
            "build": 20348,
            "native_processor_architecture": 9,
            "process_machine": 0,
            "native_machine": 0x8664,
            "ntdll_machine": 0x8664,
            "context_bytes": 1232,
            "record_bytes": 152,
            "dispatcher_rva": 4096,
        },
        {
            "kind": "code",
            "export": "KiUserExceptionDispatcher",
            "rva": 4096,
            "instruction_bytes": 192,
            "code_sha256": "0" * 64,
        },
        {
            "kind": "fault_stop",
            "context_read": True,
            "selected_ntdll_identity": True,
            "breakpoint_installed": True,
            "fault_sp_mod16": 0,
        },
        {
            "kind": "dispatcher_entry",
            "frame_bytes": 1808,
            "entry_sp_mod16": 0,
            "context_candidates": 1,
            "record_candidates": 1,
            "context_offset_bytes": 0,
            "record_offset_bytes": 1264,
            "context_flags": "0010005F",
            "frame_captured": True,
        },
        {
            "kind": "child_handler",
            "seen": 1,
            "caught": "C0000005",
            "context_to_fault_sp_bytes": -1808,
            "record_to_fault_sp_bytes": -544,
            "handler_removed": True,
            "freed": True,
        },
        {
            "kind": "complete",
            "fault_seen": True,
            "entry_captured": True,
            "breakpoint_restored": True,
            "child_exit": 0,
            "child_wait": 0,
            "failed": False,
        },
    ]


class DispatchProjectionTests(unittest.TestCase):
    def test_bounded_code_is_projected_before_publication(self):
        raw = {
            "kind": "code",
            "export": "KiUserExceptionDispatcher",
            "rva": 4096,
            "hex": "90" * 192,
        }
        before = dict(raw)
        projected = PROFILE.project_record(raw)
        self.assertEqual(raw, before)
        self.assertNotIn("hex", projected)
        self.assertEqual(projected["instruction_bytes"], 192)

    def test_extra_fields_and_unknown_kinds_cannot_export_stack_bytes(self):
        for row in (
            {"kind": "unknown", "bytes": "deadbeef"},
            {**capture()[0], "hex": "deadbeef"},
            {**capture()[3], "stack": "deadbeef"},
        ):
            with self.subTest(row=row), self.assertRaises(RuntimeError):
                PROFILE.project_record(row)

    def test_valid_geometry_is_independent_of_volatile_frame_size(self):
        for shift in (0, 16, 1024):
            rows = copy.deepcopy(capture())
            rows[3]["frame_bytes"] += shift
            rows[4]["context_to_fault_sp_bytes"] -= shift
            rows[4]["record_to_fault_sp_bytes"] -= shift
            PROFILE.validate_capture(rows, "x64")

    def test_copied_veh_context_cannot_be_admitted_as_entry_identity(self):
        rows = capture()
        rows[4]["context_to_fault_sp_bytes"] += 16
        with self.assertRaises(RuntimeError):
            PROFILE.validate_capture(rows, "x64")

    def test_ambiguous_or_truncated_records_are_rejected(self):
        for field, value in (
            ("context_candidates", 2),
            ("record_candidates", 0),
            ("frame_bytes", 8193),
            ("record_offset_bytes", 1700),
        ):
            rows = capture()
            rows[3][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                PROFILE.validate_capture(rows, "x64")

    def test_child_failure_or_unrestored_breakpoint_cannot_pass(self):
        for field, value in (
            ("child_exit", 97),
            ("child_wait", 258),
            ("breakpoint_restored", False),
            ("failed", True),
        ):
            rows = capture()
            rows[5][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                PROFILE.validate_capture(rows, "x64")

    def test_selected_abi_and_event_order_are_required(self):
        rows = capture()
        with self.assertRaises(RuntimeError):
            PROFILE.validate_capture(rows, "arm64")
        rows[2], rows[3] = rows[3], rows[2]
        with self.assertRaises(RuntimeError):
            PROFILE.validate_capture(rows, "x64")


if __name__ == "__main__":
    unittest.main()
