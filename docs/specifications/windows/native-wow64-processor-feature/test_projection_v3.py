import copy
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("control", FOLDER / "run-v3.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class ByteProjection(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((FOLDER / "local-29683-v1.json").read_text())["rows"]
        for row in self.rows[1:]:
            row["nt_raw"] = row["nt"]

    def test_retains_upper_register_bits_with_matching_byte_result(self):
        self.rows[65]["nt_raw"] = 0x88170D00
        self.assertEqual(CONTROL.validate(self.rows), self.rows)

    def test_rejects_byte_mismatch_and_nonboolean_low_byte(self):
        for raw in (0x88170D01, 0xC000000D):
            rows = copy.deepcopy(self.rows)
            rows[65]["nt_raw"] = raw
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                CONTROL.validate(rows)


if __name__ == "__main__":
    unittest.main()
