"""A failed native control keeps its verdict and emits only allowed scalars."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "second_chance_v2", Path(__file__).with_name("run-second-chance-v2.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class DiagnosticTests(unittest.TestCase):
    def test_failed_exit_is_recorded_and_still_fails(self):
        stream = io.StringIO()
        rows = [{"kind": "ready", "mode": "invalid-context", "code": 0xE0425345}]
        with contextlib.redirect_stdout(stream), self.assertRaises(RuntimeError):
            PROFILE.validate("invalid-context", -1073741819, rows)
        receipt = json.loads(stream.getvalue())
        self.assertEqual(receipt["exit_code"], 0xC0000005)
        self.assertEqual(receipt["records"], [{"kind": "ready", "code": 0xE0425345}])

    def test_success_emits_no_extra_diagnostic(self):
        stream = io.StringIO()
        rows = [{"kind": "ready", "mode": "last", "code": 0xE0425345}]
        with contextlib.redirect_stdout(stream):
            PROFILE.validate("last", 0xE0425345, rows)
        self.assertEqual(stream.getvalue(), "")

    def test_diagnostics_remove_unknown_fields_objects_and_excess_rows(self):
        rows = [
            {"kind": "complete", "seen": 0, "address": 123, "status": {"raw": 1}},
            {"kind": "other", "raw": "private"},
            {"kind": "ready", "code": -1},
            {"kind": "handler", "ordinal": 0x100000000},
            {"kind": "handler", "ordinal": 2},
        ]
        self.assertEqual(
            PROFILE.projected_rows(rows),
            [
                {"kind": "complete", "seen": 0},
                {"kind": "unexpected"},
                {"kind": "ready"},
                {"kind": "handler"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
