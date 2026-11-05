"""Provenance and stage-boundary guards over independent native CFG controls."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("windows_cfg_private_code", HERE / "windows_cfg_private_code.py")
CFG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CFG)
SOURCE = HERE.parents[1] / "docs/specifications/windows/native-cfg-private-code"


class NativeCfgEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = CFG.verify_retained(SOURCE)

    def report(self, kind, architecture="x64"):
        return copy.deepcopy(next(report for report in self.corpus["reports"]
                                  if (report["kind"], report["architecture"]) == (kind, architecture)))

    def assert_bad_report(self, report, message):
        report["stdout_sha256"] = CFG.sha(report["stdout"].encode())
        with self.assertRaisesRegex(ValueError, message):
            CFG.validate_report(report)

    def test_native_process_views_and_complete_controls(self):
        self.assertEqual(CFG.validate_report(self.report("api")), CFG.COUNTS)
        arm64 = CFG.validate_report(self.report("calls", "arm64"))
        x64 = CFG.validate_report(self.report("calls"))
        self.assertEqual(arm64, x64)
        self.assertEqual(x64["default"], 0)
        self.assertEqual(x64["invalid"], 0xC0000409)
        self.assertEqual(x64["invalid-mark-valid"], 0)
        self.assertEqual(x64["invalid-release-reuse"], 0)

    def test_failure_before_private_call_cannot_be_admission_evidence(self):
        report = self.report("calls", "arm64")
        report["stdout"] = "\n".join(line for line in report["stdout"].split("\n")
                                         if not line.startswith("CALL case=invalid "))
        self.assert_bad_report(report, "before its private CALL")

    def test_disabled_cfg_cannot_qualify_calls_or_api_results(self):
        for kind in ("calls", "api"):
            report = self.report(kind)
            report["stdout"] = report["stdout"].replace("cfg_policy=00000001", "cfg_policy=00000000")
            self.assert_bad_report(report, "CFG policy is not enabled")

    def test_duplicate_api_cell_cannot_replace_missing_native_case(self):
        report = self.report("api")
        lines = report["stdout"].splitlines(keepends=True)
        indexes = [i for i, line in enumerate(lines) if line.startswith("ALLOC ")]
        lines[indexes[-1]] = lines[indexes[0]]
        report["stdout"] = "".join(lines)
        self.assert_bad_report(report, "incomplete or duplicate API")

    def test_parent_success_cannot_hide_missing_child_terminal_result(self):
        report = self.report("calls")
        report["stdout"] = report["stdout"].replace("END_CASE case=invalid exit=c0000409\n", "")
        self.assert_bad_report(report, "missing child terminal")

    def test_other_child_exception_cannot_be_labelled_cfg_admission(self):
        report = self.report("calls")
        report["stdout"] = report["stdout"].replace("END_CASE case=invalid exit=c0000409",
                                                    "END_CASE case=invalid exit=c0000005")
        self.assert_bad_report(report, "unqualified child termination")

    def test_returned_leaf_must_have_its_exact_value_and_release_marker(self):
        for old, new, error in [("RETURN case=default result=1234", "RETURN case=default result=1235", "leaf result"),
                                ("COMPLETE case=default all_owned_allocations_released=true", "", "release marker")]:
            report = self.report("calls")
            report["stdout"] = report["stdout"].replace(old, new)
            self.assert_bad_report(report, error)

    def test_raw_output_hash_and_exit_code_are_independent_gates(self):
        report = self.report("api")
        report["stdout"] += "changed\n"
        with self.assertRaisesRegex(ValueError, "stdout identity"):
            CFG.validate_report(report)
        report = self.report("api")
        report["exit_code"] = 1
        with self.assertRaisesRegex(ValueError, "observer process failed"):
            CFG.validate_report(report)

    def test_image_metadata_and_dll_bindings_cannot_be_omitted(self):
        report = self.report("calls")
        report["pe"]["guard_flags"] = 0
        with self.assertRaisesRegex(ValueError, "PE CFG metadata"):
            CFG.validate_report(report)
        report = self.report("api", "arm64")
        del report["dll_sha256"]["ntdll.dll"]
        with self.assertRaisesRegex(ValueError, "native DLL identities"):
            CFG.validate_report(report)

    def test_native_capture_is_unavailable_without_windows_and_writes_nothing(self):
        absent = SOURCE / "never-created-by-unavailable-capture"
        with patch.object(CFG.sys, "platform", "linux"):
            with self.assertRaisesRegex(ValueError, "requires Windows"):
                CFG.capture(SOURCE, SOURCE, absent, {})
        self.assertFalse(absent.exists())

    def test_source_drift_and_duplicate_reports_fail_on_all_newline_conventions(self):
        # Scratch remains below this exact checkout and is removed on exit.
        scratch = SOURCE.parents[3] / "target"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cfg-evidence-test-", dir=scratch) as name:
            source = Path(name)
            for filename in CFG.SOURCES.values():
                (source / filename).write_bytes((SOURCE / filename).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
            path = source / "controls-arm64-29698-v1.json"
            path.write_text(json.dumps(self.corpus), encoding="utf-8")
            CFG.verify_retained(source)
            corpus = copy.deepcopy(self.corpus)
            corpus["reports"].append(corpus["reports"][0])
            path.write_text(json.dumps(corpus), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate retained"):
                CFG.verify_retained(source)
            corpus = copy.deepcopy(self.corpus)
            corpus["reports"][0]["dll_sha256"]["ntdll.dll"] = "0" * 64
            path.write_text(json.dumps(corpus), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "report DLL binding"):
                CFG.verify_retained(source)
            path.write_text(json.dumps(self.corpus), encoding="utf-8")
            with (source / "native-api-v1.rs").open("ab") as file:
                file.write(b"\n// changed producer\n")
            with self.assertRaisesRegex(ValueError, "observer source changed"):
                CFG.verify_retained(source)


if __name__ == "__main__":
    unittest.main()
