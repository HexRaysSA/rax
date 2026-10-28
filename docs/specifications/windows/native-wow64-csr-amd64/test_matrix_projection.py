"""Native evidence projections: independent values and damaged-report rejection."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "csr_projection", ROOT / "project-matrix-v1.py"
)
PROJECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROJECTION)


class MatrixProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports = json.loads((ROOT / "matrix-profiles-v1.json").read_bytes())[
            "reports"
        ]

    def altered(self, transform):
        report = copy.deepcopy(self.reports[0])
        sample = report["samples"][0]
        raw = base64.b64decode(sample["stdout_b64"])
        changed = transform(raw)
        self.assertNotEqual(changed, raw)
        sample["stdout_b64"] = base64.b64encode(changed).decode()
        sample["stdout_sha256"] = hashlib.sha256(changed).hexdigest()
        return report

    def test_native_positive_and_failure_values_on_both_kernels(self):
        for report in self.reports:
            result = PROJECTION.project(report)
            self.assertEqual((result["case_count"], result["return_count"]), (31, 38))
            samples = {sample["mode"]: sample for sample in result["samples"]}
            valid = samples["valid"]["steps"][0]
            self.assertEqual(valid["status"], "00000000")
            self.assertEqual(valid["handles_after"] - valid["handles_before"], 1)
            self.assertEqual(valid["data"]["inside"]["hex"], "00")
            self.assertEqual(
                [
                    (row["bytes"], row["state"], row["protect"])
                    for row in valid["new_mappings"]
                ],
                [(65536, 0x1000, 4), (20480, 0x1000, 2), (1028096, 0x2000, 0)],
            )
            self.assertEqual(samples["zero"]["steps"][0]["status"], "C000000D")
            self.assertEqual(
                samples["noaccess-buffer"]["steps"][0]["status"], "C0000005"
            )
            self.assertEqual(samples["guard-buffer"]["steps"][0]["status"], "80000001")
            readonly_guard = samples["readonly-guard-inside"]["steps"][0]
            self.assertEqual(readonly_guard["status"], "C0000005")
            self.assertEqual(readonly_guard["data"]["inside"]["protect"], 0x102)

    def test_unmodeled_native_heap_count_change_remains_in_evidence(self):
        projected = PROJECTION.project(self.reports[0])
        valid = next(
            sample for sample in projected["samples"] if sample["mode"] == "valid"
        )
        changes = valid["steps"][0]["peb_changes"]
        self.assertIn({"width": 64, "offset": 0xE8, "before": 1, "after": 2}, changes)

    def test_corrupted_stdout_identity_is_rejected(self):
        report = copy.deepcopy(self.reports[0])
        report["samples"][0]["stdout_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "stdout identity"):
            PROJECTION.project(report)

    def test_missing_return_and_invalid_data_extent_are_rejected(self):
        import re

        for transform in [
            lambda raw: re.sub(rb"RETURN ordinal=0[^\r\n]*\r?\n", b"", raw, count=1),
            lambda raw: raw.replace(b"bytes=8 ok=1 got=8", b"bytes=7 ok=1 got=8", 1),
        ]:
            with self.assertRaises(ValueError):
                PROJECTION.project(self.altered(transform))

    def test_peb_and_mapping_extents_are_bounded(self):
        import re

        for transform in [
            lambda raw: raw.replace(b"width=64 offset=138", b"width=64 offset=2048", 1),
            lambda raw: re.sub(
                rb"(MAPPED_NEW [^\r\n]* bytes=)65536", rb"\g<1>65537", raw, count=1
            ),
        ]:
            with self.assertRaises(ValueError):
                PROJECTION.project(self.altered(transform))

    def test_foreign_kernel_machine_and_incomplete_lifecycle_are_rejected(self):
        for mutate in [
            lambda report: report["kernel"].__setitem__(2, 20349),
            lambda report: report.__setitem__("machine", "ARM64"),
            lambda report: report["binaries"]["initial-v8.cpp"].__setitem__(
                "machine", 0xAA64
            ),
            lambda report: report.__setitem__("inputs_unchanged", False),
            lambda report: report.__setitem__("build_outputs_removed", False),
            lambda report: report["samples"].pop(),
        ]:
            report = copy.deepcopy(self.reports[0])
            mutate(report)
            with self.assertRaises(ValueError):
                PROJECTION.project(report)


if __name__ == "__main__":
    unittest.main()
