"""First/second-chance input identity remains explicit in each observation."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "raise_arguments_v2", Path(__file__).with_name("run-v2.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def observation(first):
    return [
        {
            "kind": "host",
            "build": 29683,
            "process_machine": 0,
            "native_machine": 0xAA64,
            "pointer_bytes": 8,
        },
        {"kind": "chance", "first_chance": first},
    ] + [
        {
            "kind": "case",
            "mode": mode,
            "pointer": pointer,
            "status": 0xC0000005,
            "returned": True,
            "caught": 0,
        }
        for mode in range(3)
        for pointer in (0, 1, 2, 3, 4, 7, 8, 12, 15, 16, 32, 4096)
    ]


class ProjectionTests(unittest.TestCase):
    def test_both_chance_values_and_native_statuses_are_preserved(self):
        for first in (False, True):
            rows = observation(first)
            rows[15]["status"] = 0x80000002
            self.assertEqual(PROFILE.validate(rows, "arm64", first), rows)

    def test_absent_wrong_and_nonboolean_chance_markers_are_rejected(self):
        for marker in (
            {"kind": "chance", "first_chance": True},
            {"kind": "chance", "first_chance": 0},
            {"kind": "chance"},
        ):
            rows = observation(False)
            rows[1] = marker
            with self.assertRaises(ValueError):
                PROFILE.validate(rows, "arm64", False)
        with self.assertRaises(ValueError):
            PROFILE.validate(observation(False)[1:], "arm64", False)

    def test_raw_fields_and_missing_cases_are_rejected(self):
        rows = observation(True)
        rows[-1]["raw_context"] = "private"
        with self.assertRaises(ValueError):
            PROFILE.validate(rows, "arm64", True)
        with self.assertRaises(ValueError):
            PROFILE.validate(observation(True)[:-1], "arm64", True)


if __name__ == "__main__":
    unittest.main()
