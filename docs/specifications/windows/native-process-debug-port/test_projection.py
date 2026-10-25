import copy
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("debug_port", FOLDER / "run-v3.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
RECORDS = json.loads((FOLDER / "local-29683-v3.json").read_text())
OBSERVATIONS = {r["arch"]: r["rows"] for r in RECORDS if r["kind"] == "observation"}


class Projection(unittest.TestCase):
    def test_complete_native_views_retain_all_1799_queries(self):
        self.assertEqual(set(OBSERVATIONS), {"arm64", "x64", "x86"})
        self.assertEqual(sum(len(rows) - 2 for rows in OBSERVATIONS.values()), 1799)
        for arch, rows in OBSERVATIONS.items():
            with self.subTest(arch=arch):
                self.assertEqual(CONTROL.validate(rows, arch), rows)
                self.assertFalse(rows[0]["debugger_present"])
                self.assertTrue(rows[0]["remote_query_ok"])
                self.assertFalse(rows[0]["remote_debugger_present"])
        self.assertEqual(OBSERVATIONS["arm64"], OBSERVATIONS["x64"])

    def test_rejects_missing_duplicate_and_reordered_inputs(self):
        for change in ("missing", "duplicate", "reordered"):
            rows = copy.deepcopy(OBSERVATIONS["arm64"])
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
            ("query_class", 34),
        ):
            rows = copy.deepcopy(OBSERVATIONS["arm64"])
            rows[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_rejects_wrong_view_host_and_cleanup_receipt(self):
        for change in ("view", "machine", "boolean", "complete", "win32"):
            rows = copy.deepcopy(OBSERVATIONS["arm64"])
            if change == "view":
                rows[0]["pointer_bytes"] = 4
            elif change == "machine":
                rows[0]["native_machine"] = 0
            elif change == "boolean":
                rows[0]["debugger_present"] = 1
            elif change == "win32":
                rows[0]["remote_debugger_present"] = True
            else:
                rows[-1]["cases"] -= 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_null_output_length_and_return_length_conversion_are_distinct(self):
        for arch, rows in OBSERVATIONS.items():
            size = CONTROL.width(arch)
            cases = [
                r
                for r in rows[1:-1]
                if r["family"] == "null-length" and r["return_role"] == 0
            ]
            self.assertEqual(len(cases), 7)
            for row in cases:
                self.assertEqual(
                    row["status"], 0xC0000005 if row["length"] == size else 0xC0000004
                )
                self.assertEqual(
                    row["returned"][:8], "fcffffff" if arch == "x86" else "a5a5a5a5"
                )

    def test_upper_output_range_precedes_native_return_guard_only(self):
        for arch, rows in OBSERVATIONS.items():
            for row in rows[1:-1]:
                if (
                    row["family"] not in ("upper-debug", "upper-flags", "upper-cookie")
                    or row["length"] != 1
                    or row["return_role"] != 7
                ):
                    continue
                with self.subTest(
                    arch=arch, family=row["family"], handle=row["handle_kind"]
                ):
                    if arch != "x86":
                        self.assertEqual(row["status"], 0xC0000005)
                        self.assertEqual(row["guard_protection"], 0x102)
                    elif row["query_class"] == 7:
                        self.assertEqual(row["status"], 0xC0000005)
                        self.assertEqual(row["guard_protection"], 0x102)
                    else:
                        self.assertEqual(row["status"], 0x80000001)
                        self.assertEqual(row["guard_protection"], 2)


if __name__ == "__main__":
    unittest.main()
