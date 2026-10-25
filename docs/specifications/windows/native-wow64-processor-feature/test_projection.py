import copy
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("control", FOLDER / "run.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class Projection(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((FOLDER / "local-29683-v1.json").read_text())["rows"]

    def test_retains_native_api_disagreement_for_analysis(self):
        rows = copy.deepcopy(self.rows)
        rows[1]["nt"] = 1 - rows[1]["nt"]
        self.assertEqual(CONTROL.validate(rows), rows)

    def test_rejects_missing_reordered_and_noninteger_observations(self):
        for change in ("missing", "reordered", "boolean", "status"):
            rows = copy.deepcopy(self.rows)
            if change == "missing":
                rows.pop()
            elif change == "reordered":
                rows[1], rows[2] = rows[2], rows[1]
            elif change == "boolean":
                rows[1]["nt"] = False
            else:
                rows[1]["nt"] = 0xC0000005
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROL.validate(rows)


if __name__ == "__main__":
    unittest.main()
