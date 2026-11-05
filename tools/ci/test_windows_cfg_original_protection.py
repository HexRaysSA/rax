"""Reject incomplete and misbound original-protection CFG observations."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("windows_cfg_original_protection", HERE / "windows_cfg_original_protection.py")
CFG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CFG)
SOURCE = HERE.parents[1] / "docs/specifications/windows/native-cfg-private-code"


class OriginalProtectionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = CFG.verify_retained(SOURCE)

    def report(self, architecture="x64"):
        return copy.deepcopy(next(r for r in self.corpus["reports"] if r["architecture"] == architecture))

    def reject(self, report, message):
        report["stdout_sha256"] = CFG.sha(report["stdout"].encode())
        with self.assertRaisesRegex(ValueError, message):
            CFG.validate_report(report)

    def test_all_original_protections_agree_in_both_process_views(self):
        first = CFG.validate_report(self.report("arm64"))
        self.assertEqual(first, CFG.validate_report(self.report()))
        self.assertEqual(len(first), 30)
        self.assertEqual(sum(v == 0 for v in first.values()), 18)
        self.assertEqual(sum(v == 0xC0000409 for v in first.values()), 12)

    def test_no_call_or_disabled_cfg_cannot_qualify_a_terminal_child(self):
        report = self.report()
        report["stdout"] = "\n".join(s for s in report["stdout"].split("\n")
                                         if not s.startswith("CALL case=initial-ro-repeat-default-invalid "))
        self.reject(report, "before its original-protection CALL")
        report = self.report()
        report["stdout"] = report["stdout"].replace("cfg_policy=00000001", "cfg_policy=00000000")
        self.reject(report, "CFG policy is not enabled")

    def test_original_protection_must_be_observed_not_inferred_from_the_case_name(self):
        report = self.report()
        report["stdout"] = report["stdout"].replace("initial=00000002 reserved=false", "initial=00000004 reserved=false")
        self.reject(report, "original allocation protection was not observed")

    def test_translated_view_cannot_be_labelled_native_and_offset_must_match(self):
        report = self.report()
        report["translated"] = False
        with self.assertRaisesRegex(ValueError, "process-view binding"):
            CFG.validate_report(report)
        report = self.report()
        report["stdout"] = report["stdout"].replace("offset=1 expected_leaf=1234", "offset=0 expected_leaf=1234")
        self.reject(report, "target offset differs")

    def test_crlf_is_tolerated_without_losing_raw_stdout_identity(self):
        report = self.report()
        report["stdout"] = report["stdout"].replace("\n", "\r\n")
        report["stdout_sha256"] = CFG.sha(report["stdout"].encode())
        self.assertEqual(len(CFG.validate_report(report)), 30)

    def test_every_child_remains_terminal_even_when_outside_the_qualified_subset(self):
        report = self.report()
        report["stdout"] = report["stdout"].replace("END_CASE case=invalid exit=c0000409\n", "")
        self.reject(report, "unique terminal records")
        report = self.report()
        report["stdout"] = report["stdout"].replace("COMPLETE controls=74 all_children_terminal=true", "")
        self.reject(report, "parent completion marker")

    def test_duplicate_or_reordered_original_controls_are_rejected(self):
        report = self.report()
        report["stdout"] = report["stdout"].replace("case=initial-ro-repeat-default-invalid ", "case=initial-rw-repeat-default-invalid ")
        self.reject(report, "unique terminal records")

    def test_different_kernel_outcomes_falsify_the_original_protection_rule(self):
        for case, old, new in [("initial-ro-repeat-default-invalid", "00000000", "c0000409"),
                               ("initial-x-repeat-default-invalid", "c0000409", "c0000005")]:
            report = self.report()
            report["stdout"] = report["stdout"].replace(f"END_CASE case={case} exit={old}", f"END_CASE case={case} exit={new}")
            self.reject(report, "outcome differs")

    def test_leaf_value_and_explicit_release_are_independent_gates(self):
        for old, new, message in [("RETURN case=initial-ro-repeat-default-invalid result=1234", "RETURN case=initial-ro-repeat-default-invalid result=1235", "leaf result"),
                                  ("COMPLETE case=initial-ro-repeat-default-invalid all_owned_allocations_released=true", "", "release marker")]:
            report = self.report()
            report["stdout"] = report["stdout"].replace(old, new)
            self.reject(report, message)

    def test_observer_exit_stdout_pe_and_dll_identity_are_independent_gates(self):
        for change, message in [(lambda r: r.update(exit_code=1), "observer process failed"),
                                (lambda r: r.update(stdout=r["stdout"] + "changed\n"), "stdout identity"),
                                (lambda r: r["pe"].update(guard_flags=0), "PE CFG metadata"),
                                (lambda r: r["dll_sha256"].pop("ntdll.dll"), "DLL identities")]:
            report = self.report()
            change(report)
            with self.assertRaisesRegex(ValueError, message):
                CFG.validate_report(report)

    def test_retained_source_and_report_bindings_cannot_drift(self):
        scratch = SOURCE.parents[3] / "target"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cfg-original-test-", dir=scratch) as temporary:
            root = Path(temporary)
            (root / CFG.SOURCE).write_bytes((SOURCE / CFG.SOURCE).read_bytes())
            corpus = copy.deepcopy(self.corpus)
            corpus["reports"][0]["source_sha256"] = "0" * 64
            (root / CFG.RETAINED).write_text(json.dumps(corpus), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source/DLL binding"):
                CFG.verify_retained(root)
            (root / CFG.RETAINED).write_text(json.dumps(self.corpus), encoding="utf-8")
            with (root / CFG.SOURCE).open("ab") as file:
                file.write(b"\n// different producer\n")
            with self.assertRaisesRegex(ValueError, "producer identity"):
                CFG.verify_retained(root)

    def test_native_capture_on_another_os_writes_nothing(self):
        absent = SOURCE / "unavailable-original-protection-capture"
        with patch.object(CFG.sys, "platform", "linux"):
            with self.assertRaisesRegex(ValueError, "requires Windows"):
                CFG.capture(SOURCE, SOURCE, absent)
        self.assertFalse(absent.exists())


if __name__ == "__main__":
    unittest.main()
