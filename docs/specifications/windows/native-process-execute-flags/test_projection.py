import copy
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("execute_flags", FOLDER / "run-v2.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
RECORDS = json.loads((FOLDER / "local-29683-v2.json").read_text())


class Projection(unittest.TestCase):
    def setUp(self):
        self.observations = [r for r in RECORDS if r["kind"] == "observation"]
        self.rows = copy.deepcopy(self.observations[0]["rows"])

    def test_complete_native_profiles_retain_all_query_rows(self):
        self.assertEqual(len(self.observations), 5)
        self.assertEqual(len(list(CONTROL.inputs())), 239)
        for record in self.observations:
            with self.subTest(arch=record["arch"], nx=record["requested_nx_compat"]):
                self.assertEqual(
                    CONTROL.validate(record["rows"], record["arch"]), record["rows"]
                )
                self.assertEqual(record["exit_code"], 0)
                self.assertEqual(
                    record["rows"][0]["nx_compat"], record["requested_nx_compat"]
                )

    def test_rejects_missing_duplicate_and_reordered_inputs(self):
        for change in ("missing", "duplicate", "reordered"):
            rows = copy.deepcopy(self.rows)
            if change == "missing":
                del rows[20]
            elif change == "duplicate":
                rows[20] = copy.deepcopy(rows[19])
            else:
                rows[20], rows[21] = rows[21], rows[20]
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_rejects_extra_fields_and_non_scalar_projection(self):
        for field, value in (
            ("address", "unknown"),
            ("status", True),
            ("status", -1),
            ("exception", 1 << 32),
            ("output", "a5" * 15),
            ("returned", "A5" * 16),
            ("opened", 1),
            ("alias", False),
        ):
            rows = copy.deepcopy(self.rows)
            rows[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_rejects_wrong_view_host_and_cleanup_receipt(self):
        for change in ("view", "machine", "boolean", "complete"):
            rows = copy.deepcopy(self.rows)
            if change == "view":
                rows[0]["pointer_bytes"] = 4
            elif change == "machine":
                rows[0]["native_machine"] = 0
            elif change == "boolean":
                rows[0]["dep_permanent"] = 1
            else:
                rows[-1]["cases"] = 238
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_loader_rejection_is_separate_from_query_coverage(self):
        records = [r for r in RECORDS if r["kind"] == "unavailable"]
        self.assertEqual(len(records), 1)
        CONTROL.validate_unavailable(records[0])
        for field, value in (
            ("available", True),
            ("windows_error", 5),
            ("requested_nx_compat", True),
            ("machine", 0x8664),
            ("dll_characteristics", 0x100),
            ("binary_sha256", "unknown"),
            ("rows", []),
        ):
            record = copy.deepcopy(records[0])
            record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTROL.validate_unavailable(record)


if __name__ == "__main__":
    unittest.main()
