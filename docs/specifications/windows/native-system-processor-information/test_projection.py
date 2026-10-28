"""Detect incomplete or corrupted native processor observations."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("processor_control", FOLDER / "run-v1.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((FOLDER / "local-29683-v1.json").read_text())

    def test_original_capture_and_canonical_source_are_bound(self):
        source = (FOLDER / "native-system-processor-information-v1.cpp").read_bytes()
        # A Windows checkout may contain CRLF. Executed-input checks use raw
        # hashes; this comparison identifies the canonical Git source only.
        expected = hashlib.sha256(source.replace(b"\r\n", b"\n")).hexdigest()
        CONTROL.validate_dataset(self.data, expected)
        self.assertEqual(sum(len(s["rows"]) for s in self.data["samples"]), 900)

    def test_missing_duplicate_or_retyped_query_is_rejected(self):
        for mutation in ("missing", "duplicate", "boolean_length"):
            data = copy.deepcopy(self.data)
            rows = data["samples"][0]["rows"]
            if mutation == "missing":
                rows.pop()
            elif mutation == "duplicate":
                rows.append(copy.deepcopy(rows[0]))
            else:
                rows[0][2] = False
            with self.assertRaises(ValueError, msg=mutation):
                CONTROL.validate_dataset(data)

    def test_native_and_compatibility_identity_cannot_be_collapsed(self):
        data = copy.deepcopy(self.data)
        data["samples"][-1]["identity"]["shared_native_architecture"] = 0
        with self.assertRaises(ValueError):
            CONTROL.validate_dataset(data)
        data = copy.deepcopy(self.data)
        rows = data["samples"][-1]["rows"]
        for row in rows:
            if row[:4] == [1, 1, 12, "valid"]:
                row[9] = "0000" + row[9][4:]
        with self.assertRaises(ValueError):
            CONTROL.validate_dataset(data)

    def test_a_wider_processor_copy_or_lost_input_binding_is_rejected(self):
        data = copy.deepcopy(self.data)
        data["samples"][0]["rows"][0][9] = "a5" * 12 + "00" + "a5" * 67
        with self.assertRaises(ValueError):
            CONTROL.validate_dataset(data)
        data = copy.deepcopy(self.data)
        data["inputs_unchanged"] = False
        with self.assertRaises(ValueError):
            CONTROL.validate_dataset(data)
        with self.assertRaises(ValueError):
            CONTROL.validate_dataset(self.data, "0" * 64)

    def test_roundtrip_retains_native_fault_and_guard_observations(self):
        for sample in self.data["samples"]:
            rows = CONTROL.expand(sample)
            roundtrip = CONTROL.compact(
                sample["arch"],
                rows,
                sample["compiler_sha256"],
                sample["binary_sha256"],
                sample["binary_bytes"],
            )
            self.assertEqual(sample, roundtrip)
        x86 = self.data["samples"][-1]
        row = next(row for row in x86["rows"] if row[:4] == [1, 1, 12, "both_guard"])
        self.assertEqual((row[4], row[7], row[8]), (0x80000001, False, True))


if __name__ == "__main__":
    unittest.main()
