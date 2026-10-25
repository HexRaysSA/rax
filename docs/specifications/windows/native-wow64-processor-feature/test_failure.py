import copy
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("diagnostics", FOLDER / "run-v2.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class FailureReceipt(unittest.TestCase):
    def test_preserves_noncanonical_integer_without_accepting_it(self):
        rows = json.loads((FOLDER / "local-29683-v1.json").read_text())["rows"]
        rows[1]["nt"] = 0xC000000D
        self.assertEqual(CONTROL.bounded_failure(rows), rows)
        with self.assertRaises(ValueError):
            CONTROL.validate(rows)

    def test_rejects_unknown_fields_and_unbounded_values(self):
        original = [{"kind": "feature", "index": 0, "nt": 0, "rtl": 0, "win32": 0}]
        for field, value in (("address", 1), ("nt", 1 << 32), ("rtl", "unexpected")):
            rows = copy.deepcopy(original)
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTROL.bounded_failure(rows)


if __name__ == "__main__":
    unittest.main()
