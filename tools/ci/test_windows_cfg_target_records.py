"""Evidence-parser rejection tests. Generated rows are synthetic format fixtures."""
import copy
from pathlib import Path
import unittest

import windows_cfg_target_records as records


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "docs/specifications/windows/native-cfg-target-records" / records.SOURCE).read_bytes()
CASES = records.cases_from_source(SOURCE.decode("utf-8"))


def block(case, width, list_bytes):
    lines = [f"BEGIN_CASE case={case}",
             f"ENTER case={case} range_count=1 information_bytes={list_bytes} "
             f"list_bytes={list_bytes} pointer_bytes={width} target=40000 "
             "range_pointer=10080 information_pointer=20080",
             f"RESULT case={case} status=00000000 last_error=abababab processed=00000001"]
    for name in records.BUFFERS:
        lines.append(f"BUFFER case={case} name={name} address=10080 "
                     f"before={'a5' * 64} after={'a5' * 64}")
    lines.extend([f"COMPLETE case={case} all_owned_allocations_released=true",
                  f"END_CASE case={case} exit=00000000 stderr_hex="])
    return "\n".join(lines) + "\n"


def stdout(architecture="arm64"):
    arch, _, width, length = records.ARCHES[architecture]
    header = f"PROFILE arch={arch} pointer_bytes={width} list_bytes={length} cfg_policy=00000001 cases={len(CASES)}\n"
    return header + "".join(block(case, width, length) for case in CASES) + \
        f"COMPLETE controls={len(CASES)} all_children_terminal=true\n"


def report(arch):
    text = stdout(arch)
    return {"architecture": arch, "exit_code": 0, "stderr": "", "stdout": text,
            "execution_view": "wow64" if arch == "x86" else "native",
            "stdout_sha256": records.sha(text.encode()), "image_sha256": "1" * 64,
            "pe": {"machine": records.ARCHES[arch][1], "guard_flags": 0x500,
                   "dll_characteristics": 0x4000, "optional_magic": 0x10B if arch == "x86" else 0x20B},
            "dll_sha256": {name: "2" * 64 for name in ("ntdll.dll", "KernelBase.dll", "kernel32.dll")}}


def corpus():
    return {"schema": records.SCHEMA, "state": "complete", "source_sha256": records.source_sha(SOURCE),
            "source_raw_sha256": records.sha(SOURCE), "native_machine": 0xAA64,
            "kernel": [10, 0, 29698], "reports": [report("arm64"), report("x86")]}


class EvidenceRejections(unittest.TestCase):
    def reject(self, text, message):
        with self.assertRaisesRegex(ValueError, message):
            records.validate_stdout(text, "arm64", CASES)

    def test_each_guest_abi_keeps_its_own_pointer_and_list_width(self):
        for arch in records.ARCHES:
            with self.subTest(arch=arch):
                rows = records.validate_stdout(stdout(arch), arch, CASES)
                self.assertEqual(len(rows), len(CASES))
                self.assertTrue(all(row["kind"] == "nt-result" for row in rows))

    def test_missing_case_is_not_a_complete_capture(self):
        self.reject(stdout().replace(block("offset-1", 8, 40), ""), "reordered cases")

    def test_duplicate_case_is_not_a_complete_capture(self):
        self.reject(stdout().replace("BEGIN_CASE case=offset-1\n", block("valid", 8, 40)), "reordered cases")

    def test_nt_success_needs_the_valid_positive_control(self):
        self.reject(stdout().replace("RESULT case=valid status=00000000", "RESULT case=valid status=c0000005"),
                    "valid record control failed")

    def test_a_child_exit_without_nt_result_cannot_report_a_successful_row(self):
        self.reject(stdout().replace("RESULT case=offset-1 status=00000000 last_error=abababab processed=00000001\n", ""),
                    "missing NT return row")

    def test_all_four_caller_snapshots_are_required(self):
        text = stdout().replace("BUFFER case=valid name=targets", "IGNORED case=valid name=targets")
        self.reject(text, "caller buffer set")

    def test_partial_output_and_nonhex_status_are_rejected(self):
        self.reject(stdout().replace("status=00000000", "status=garbage!", 1), "NT result status")
        self.reject(stdout().replace("after=" + "a5" * 64, "after=a5", 1), "caller buffer after")

    def test_normal_return_requires_owned_allocation_release(self):
        self.reject(stdout().replace("COMPLETE case=offset-1 all_owned_allocations_released=true\n", ""),
                    "release all owned allocations")

    def test_thunk_exception_is_retained_without_inventing_an_nt_return(self):
        case = "range-bad"
        exception = (f"BEGIN_CASE case={case}\nENTER case={case} range_count=1 information_bytes=40 "
                     "list_bytes=40 pointer_bytes=8 target=40000 range_pointer=1 information_pointer=20080\n"
                     f"END_CASE case={case} exit=c0000005 stderr_hex=\n")
        text = stdout().replace(block(case, 8, 40), exception)
        row = records.validate_stdout(text, "arm64", CASES)[CASES.index(case)]
        self.assertEqual(row["kind"], "thunk-exception")
        self.assertNotIn("result", row)

    def test_inconsistent_exception_and_nt_result_are_rejected(self):
        self.reject(stdout().replace("END_CASE case=offset-1 exit=00000000", "END_CASE case=offset-1 exit=c0000005"),
                    "inconsistent child exception")

    def test_wow64_is_mandatory_in_a_complete_corpus(self):
        value = corpus()
        value["reports"] = value["reports"][:1]
        with self.assertRaisesRegex(ValueError, "omitted.*WoW64"):
            records.validate_corpus(value, SOURCE)

    def test_source_and_stdout_identity_are_verified(self):
        value = corpus()
        self.assertEqual(records.validate_corpus(value, SOURCE), 2 * len(CASES))
        value["source_sha256"] = "3" * 64
        with self.assertRaisesRegex(ValueError, "source identity"):
            records.validate_corpus(value, SOURCE)
        value = corpus()
        value["reports"][0]["stdout_sha256"] = "3" * 64
        with self.assertRaisesRegex(ValueError, "stdout identity"):
            records.validate_corpus(value, SOURCE)

    def test_crlf_source_preserves_canonical_source_identity(self):
        lf_source = SOURCE.replace(b"\r\n", b"\n")
        for source in (lf_source, lf_source.replace(b"\n", b"\r\n")):
            with self.subTest(crlf=b"\r\n" in source):
                self.assertEqual(records.validate_corpus(corpus(), source), 2 * len(CASES))

    def test_doubled_carriage_returns_do_not_match_the_canonical_source(self):
        lf_source = SOURCE.replace(b"\r\n", b"\n")
        malformed = lf_source.replace(b"\n", b"\r\r\n")
        with self.assertRaisesRegex(ValueError, "source identity"):
            records.validate_corpus(corpus(), malformed)

    def test_wrong_pe_abi_cannot_qualify_a_wow64_capture(self):
        value = copy.deepcopy(corpus())
        value["reports"][1]["pe"]["optional_magic"] = 0x20B
        with self.assertRaisesRegex(ValueError, "optional-header ABI"):
            records.validate_corpus(value, SOURCE)

    def test_translated_x64_is_explicit_and_does_not_replace_native_or_wow64(self):
        value = corpus()
        extra = report("x64")
        value["reports"].append(extra)
        with self.assertRaisesRegex(ValueError, "execution view"):
            records.validate_corpus(value, SOURCE)
        extra["execution_view"] = "translated-x64"
        self.assertEqual(records.validate_corpus(value, SOURCE), 3 * len(CASES))
        value["reports"] = [value["reports"][0], extra]
        with self.assertRaisesRegex(ValueError, "omitted.*WoW64"):
            records.validate_corpus(value, SOURCE)


if __name__ == "__main__":
    unittest.main()
