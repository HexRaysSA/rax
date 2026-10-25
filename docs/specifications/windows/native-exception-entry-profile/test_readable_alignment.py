import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "control", Path(__file__).with_name("run-second-chance-v5.py")
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def ready(mode, arch="arm64"):
    return {
        "kind": "ready",
        "mode": mode,
        "code": CONTROL.EXCEPTION,
        "build": 29683,
        "process_machine": 0,
        "native_machine": 0xAA64,
        "pointer_bytes": 8,
    }


class ReadableAlignment(unittest.TestCase):
    def test_retains_actual_status_without_assuming_copy_or_alignment_order(self):
        for status in (0xC0000005, 0x80000002):
            rows = [
                ready("context-1"),
                {
                    "kind": "complete",
                    "seen": 0,
                    "caught": 0,
                    "call_returned": True,
                    "status": status,
                    "removed": True,
                },
            ]
            CONTROL.validate("context-1", 0, rows, "arm64")

    def test_accepts_x64_native_machine_reporting_for_arm_translation(self):
        CONTROL.validate(
            "record-15", CONTROL.EXCEPTION, [ready("record-15", "x64")], "x64"
        )

    def test_replays_all_native_cases_with_explicit_modes_and_architectures(self):
        rows = json.loads(
            Path(__file__).with_name("local-readable-alignment-v3.json").read_text()
        )
        cases = [r for r in rows if r["kind"] == "case"]
        self.assertEqual(len(cases), 3 * len(CONTROL.MODES))
        self.assertEqual(
            [(r["arch"], r["mode"]) for r in cases],
            [
                (arch, mode)
                for arch in ("arm64", "x64", "x86")
                for mode in CONTROL.MODES
            ],
        )
        for row in cases:
            CONTROL.validate(row["mode"], row["exit_code"], row["records"], row["arch"])

    def test_rejects_redispatch_extra_fields_and_nonerror_returns(self):
        row = {
            "kind": "complete",
            "seen": 0,
            "caught": 0,
            "call_returned": True,
            "status": 0x80000002,
            "removed": True,
        }
        for field, value in (("seen", 1), ("extra", 0), ("status", 0)):
            bad = copy.deepcopy(row)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                CONTROL.validate("context-1", 0, [ready("context-1"), bad], "arm64")


if __name__ == "__main__":
    unittest.main()
