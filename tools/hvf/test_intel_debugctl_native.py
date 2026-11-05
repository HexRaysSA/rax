"""Admission controls for SDK-only DEBUGCTL observations, including negative results."""
import copy
import json
from pathlib import Path
import unittest

from intel_debugctl_native import CASES, OPTIONAL_FIELDS, describe_exit, validate_observation
from intel_ram_entry_native import STATE_FIELDS


def observation(case="tf"):
    state = {"core": dict.fromkeys(STATE_FIELDS, 0), "dr6": 0xffff0ff0, "rdx": 0}
    state.update({key: {"status": 0, "value": 0} for key in (*OPTIONAL_FIELDS, "msr_debugctl")})
    bank = "native" if case.startswith("native-") else "managed" if case.startswith("managed-") else "field"
    action = case.removeprefix(bank + "-") if bank != "field" else case
    return [
        {"native_intel_process": True, "vm_created": True},
        {"probe": "debugctl", "version": 2, "case": case, "bank": bank,
         "initial_exception_bitmap": 0x40000, "exception_bitmap": 0x42002,
         "requested_debugctl": 2 if action == "btf" or action.startswith("btf-") else 0,
         "configuration_status": 0, "configuration_failure_stage": None,
         "before": copy.deepcopy(state), "after": state,
         "guest_entry_attempted": True, "entries": 1, "run_status": 0, "exit_reason": 12,
         "vcpu_destroy_status": 0, "guest_unmap_status": 0,
         "vm_destroy_status": 0, "host_unmap_status": 0},
    ]


class DebugctlObservationTests(unittest.TestCase):
    def test_each_named_control_is_admitted(self):
        for case in CASES:
            validate_observation(observation(case), case)

    def test_rejected_configuration_does_not_fabricate_guest_execution(self):
        rows = observation()
        rows[1].update(configuration_status=0xfae9400f, guest_entry_attempted=False,
                       configuration_failure_stage="field-write", entries=0,
                       run_status=None, exit_reason=None)
        entry = validate_observation(rows, "tf")
        self.assertEqual(describe_exit(entry), "SDK configuration rejected")
        for key, value in (("entries", 1), ("guest_entry_attempted", True),
                           ("run_status", 0), ("exit_reason", 0)):
            changed = copy.deepcopy(rows)
            changed[1][key] = value
            with self.assertRaises(ValueError):
                validate_observation(changed, "tf")

    def test_api_failure_has_no_exit_reason(self):
        rows = observation()
        rows[1].update(run_status=0xfae9400f, exit_reason=None)
        self.assertEqual(describe_exit(validate_observation(rows, "tf")), "SDK run rejected")
        rows[1]["exit_reason"] = 12
        with self.assertRaises(ValueError):
            validate_observation(rows, "tf")

    def test_exception_status_and_valid_bit_control_description(self):
        rows = observation()
        entry = rows[1]
        entry["exit_reason"] = 0
        info = entry["after"]["exit_interrupt_info"]
        info["value"] = 0x80000301
        self.assertEqual(describe_exit(validate_observation(rows, "tf")), "intercepted exception vector 1")
        info["value"] = 0x301
        self.assertEqual(describe_exit(validate_observation(rows, "tf")), "VM-exit 0x0")
        info.update(status=1, value=None)
        self.assertEqual(describe_exit(validate_observation(rows, "tf")), "VM-exit 0x0")

    def test_sdk_field_reads_cannot_invent_values_after_failure(self):
        for phase in ("before", "after"):
            for field in (*OPTIONAL_FIELDS, "msr_debugctl"):
                for status, value in ((0, None), (0, True), (False, 0), (1, 0), (-1, None)):
                    rows = observation()
                    rows[1][phase][field].update(status=status, value=value)
                    with self.assertRaises(ValueError):
                        validate_observation(rows, "tf")
                rows = observation()
                rows[1][phase][field].update(status=1, value=None)
                validate_observation(rows, "tf")

    def test_preserves_sdk_intercepts_and_adds_both_exception_controls(self):
        for bitmap in (0x2002, 0x40002, 0x42000, True, 1 << 32):
            rows = observation()
            rows[1]["exception_bitmap"] = bitmap
            with self.assertRaises(ValueError):
                validate_observation(rows, "tf")

    def test_rejects_partial_records_and_false_native_claims(self):
        for rows in (None, [], observation()[:1], [{}, []]):
            with self.assertRaises(ValueError):
                validate_observation(rows, "tf")
        for key in ("native_intel_process", "vm_created"):
            rows = observation()
            rows[0][key] = 1
            with self.assertRaises(ValueError):
                validate_observation(rows, "tf")
        for phase in ("before", "after"):
            for key in STATE_FIELDS:
                rows = observation()
                del rows[1][phase]["core"][key]
                with self.assertRaises(ValueError):
                    validate_observation(rows, "tf")

    def test_case_identity_scalars_bounds_and_cleanup(self):
        for key, value in (("version", True), ("case", "unknown"), ("probe", "ram-entry"),
                           ("requested_debugctl", 2), ("configuration_status", False),
                           ("guest_entry_attempted", 1), ("entries", 0), ("entries", 11),
                           ("run_status", False), ("exit_reason", None),
                           ("vcpu_destroy_status", False), ("guest_unmap_status", 1),
                           ("vm_destroy_status", 1), ("host_unmap_status", -1)):
            rows = observation()
            rows[1][key] = value
            with self.assertRaises(ValueError):
                validate_observation(rows, "tf")

    def test_binding_and_permission_failures_have_exact_frontiers(self):
        for case, stages in (("tf", ("field-write",)),
                             ("btf-load-entry", ("field-write", "entry-control")),
                             ("native-btf", ("field-write", "native-bind", "msr-write")),
                             ("managed-btf", ("field-write", "managed-bind", "managed-access", "msr-write"))):
            for stage in stages:
                rows = observation(case)
                rows[1].update(configuration_status=1, configuration_failure_stage=stage,
                               guest_entry_attempted=False, entries=0, run_status=None, exit_reason=None)
                validate_observation(rows, case)
            for stage in (None, "unknown", "other-bind", False):
                rows[1]["configuration_failure_stage"] = stage
                with self.assertRaises(ValueError):
                    validate_observation(rows, case)
        rows = observation("native-tf")
        rows[1]["bank"] = "managed"
        with self.assertRaises(ValueError):
            validate_observation(rows, "native-tf")

    def test_version_one_replays_retained_native_observations(self):
        path = Path(__file__).resolve().parents[2] / "docs/development/hvf-debugctl-sdk/native-debugctl-42108801244.json"
        report = json.loads(path.read_text())
        self.assertEqual(len(report["observations"]), 6)
        for rows in report["observations"]:
            validate_observation(rows, rows[1]["case"])
        rows = observation("native-btf")
        rows[1]["version"] = 1
        with self.assertRaises(ValueError):
            validate_observation(rows, "native-btf")


if __name__ == "__main__":
    unittest.main()
