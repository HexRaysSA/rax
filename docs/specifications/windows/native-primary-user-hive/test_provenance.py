from pathlib import Path
import ast
import hashlib
import json
import unittest

ROOT = Path(__file__).parent


class NativeHiveEvidence(unittest.TestCase):
    def test_producers_and_physical_input_hashes(self):
        for version in [1, 2, 3, 4]:
            with self.subTest(version=version):
                source = (ROOT / f"probe-v{version}.py").read_bytes()
                ast.parse(source)
                data = json.loads((ROOT / f"arm64-29695-v{version}.json").read_text())
                self.assertEqual(hashlib.sha256(source).hexdigest(), data["source_sha256"])
                self.assertEqual(data["state"], "finished")
                self.assertEqual(data["exit_code"], 0)
                self.assertEqual(data["native_machine"], 0xAA64)
                self.assertEqual(data["process_machine"], 0)
                self.assertEqual(len(data["rows"]), 56 if version == 4 else 24)

    def test_diagnostic_failures_remain_visible(self):
        for version in [1, 2]:
            data = json.loads((ROOT / f"arm64-29695-v{version}.json").read_text())
            rows = [row for row in data["rows"] if row["status"] == 0]
            self.assertEqual(len(rows), 18)
            self.assertTrue(all(row["object_basic"]["status"] == 0xC0000004 for row in rows))
            self.assertTrue(all(row["object_basic"]["result_length"] == 0xCCCCCCCC for row in rows))

    def test_read_grants_aliases_and_known_native_gap(self):
        data = json.loads((ROOT / "arm64-29695-v3.json").read_text())
        rows = [row for row in data["rows"] if row["path"].endswith("S-1-5-18")]
        self.assertEqual(len(rows), 8)
        for row in rows:
            if row["access"] == 0:
                self.assertEqual(row["status"], 0xC0000022)
                self.assertIsNone(row["output_handle"])
            else:
                self.assertEqual(row["status"], 0)
                self.assertEqual(row["canonical_name"], "\\REGISTRY\\USER\\.DEFAULT")
                self.assertEqual(row["object_basic"]["result_length"], 56)
                expected = 0xF003F if row["access"] == 0x2000000 else row["access"]
                self.assertEqual(row["granted_access"], expected)

    def test_independent_absence_controls(self):
        data = json.loads((ROOT / "arm64-29695-v4.json").read_text())
        self.assertEqual(data["rtl_version"]["build"], 29695)
        self.assertEqual(len(data["win32_absence"]), 4)
        absent = {row["path"] for row in data["win32_absence"]}
        self.assertTrue(all(row["status"] == 2 for row in data["win32_absence"]))
        rows = [row for row in data["rows"] if row["path"] in absent]
        self.assertEqual(len(rows), 32)
        self.assertTrue(all(row["status"] == 0xC0000034 for row in rows))
        self.assertTrue(all(row["output_handle"] is None for row in rows))


if __name__ == "__main__":
    unittest.main()
