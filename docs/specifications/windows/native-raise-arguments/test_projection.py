"""Validate identity and disclosure bounds independently of returned statuses."""

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "raise_arguments", Path(__file__).with_name("run.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def observation():
    return [
        {
            "kind": "host",
            "build": 29683,
            "process_machine": 0,
            "native_machine": 0xAA64,
            "pointer_bytes": 8,
        }
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
    def test_all_argument_pairs_are_retained_with_status_variation(self):
        rows = observation()
        rows[14]["status"] = 0x80000002
        self.assertEqual(PROFILE.validate(rows, "arm64"), rows)

    def test_missing_duplicate_reordered_and_foreign_fields_are_rejected(self):
        original = observation()
        variants = [
            original[:-1],
            [original[0], original[2], original[1], *original[3:]],
            [original[0], original[1], original[1], *original[3:]],
        ]
        bad = copy.deepcopy(original)
        bad[1]["context_bytes"] = "private"
        variants.append(bad)
        for rows in variants:
            with self.assertRaises(ValueError):
                PROFILE.validate(rows, "arm64")

    def test_scalar_types_widths_and_compiler_identity_are_checked(self):
        original = observation()
        for index, key, value in [
            (0, "pointer_bytes", 4),
            (1, "status", -1),
            (1, "caught", 1 << 32),
            (1, "returned", 1),
            (1, "mode", False),
            (1, "pointer", False),
        ]:
            rows = copy.deepcopy(original)
            rows[index][key] = value
            with self.assertRaises(ValueError):
                PROFILE.validate(rows, "arm64")


if __name__ == "__main__":
    unittest.main()
