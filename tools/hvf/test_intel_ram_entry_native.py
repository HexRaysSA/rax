"""Admission tests for the SDK-only native RAM-entry observation matrix."""
import copy
import unittest

from intel_ram_entry_native import MARKER, STATE_FIELDS, validate_observation


def observation():
    state = dict.fromkeys(STATE_FIELDS, 0)
    state.update(rip=0x10000, cr0=0x80010033, cr3=0x1000, cr4=0x220, efer=0x500,
                 rax=0x1122334455667788, rdi=0x40000080, rflags=2)
    return [
        {"native_intel_process": True, "vm_created": True},
        {"probe": "ram-entry", "variant": "baseline", "before": dict(state), "after": dict(state),
         "guest_entry_attempted": True, "run_status": 0, "exit_reason": 0x80000021,
         "entries": 1, "guest_reached_hlt": False, "vcpu_destroy_status": 0,
         "guest_unmap_status": 0, "vm_destroy_status": 0, "host_unmap_status": 0},
    ]


class ObservationTests(unittest.TestCase):
    def test_invalid_guest_state_is_observed_without_claiming_guest_pass(self):
        self.assertFalse(validate_observation(observation(), "baseline")["guest_reached_hlt"])

    def test_actual_hlt_requires_matching_exit_rip_and_marker(self):
        rows = observation()
        rows[1].update(exit_reason=12, guest_reached_hlt=True)
        rows[1]["after"].update(rip=0x1000A, r10=MARKER)
        self.assertTrue(validate_observation(rows, "baseline")["guest_reached_hlt"])
        for key, value in (("rip", 0x1000B), ("r10", 0), ("rax", 0), ("rdi", 0), ("rflags", 0)):
            changed = copy.deepcopy(rows)
            changed[1]["after"][key] = value
            with self.assertRaises(ValueError):
                validate_observation(changed, "baseline")

    def test_api_failure_has_no_fabricated_exit_reason(self):
        rows = observation()
        rows[1].update(run_status=0xFAE9400F, exit_reason=None)
        validate_observation(rows, "baseline")
        rows[1]["exit_reason"] = 0
        with self.assertRaises(ValueError):
            validate_observation(rows, "baseline")

    def test_rejects_missing_state_fields_and_boolean_scalars(self):
        for phase in ("before", "after"):
            for key in STATE_FIELDS:
                rows = observation()
                del rows[1][phase][key]
                with self.assertRaises(ValueError):
                    validate_observation(rows, "baseline")
                rows = observation()
                rows[1][phase][key] = True
                with self.assertRaises(ValueError):
                    validate_observation(rows, "baseline")

    def test_rejects_wrong_variant_non_native_process_or_missing_attempt(self):
        mutations = ((0, "native_intel_process", False), (0, "vm_created", False),
                     (1, "variant", "full-shadows"), (1, "guest_entry_attempted", False),
                     (1, "probe", "other"), (1, "guest_reached_hlt", 1))
        for index, key, value in mutations:
            rows = observation()
            rows[index][key] = value
            with self.assertRaises(ValueError):
                validate_observation(rows, "baseline")

    def test_rejects_invalid_status_entry_counts_and_failed_cleanup(self):
        for key, value in (("entries", 0), ("entries", 11), ("entries", True),
                           ("run_status", -1), ("run_status", False),
                           ("exit_reason", None), ("vcpu_destroy_status", 1),
                           ("guest_unmap_status", False), ("vm_destroy_status", 1),
                           ("host_unmap_status", -1)):
            rows = observation()
            rows[1][key] = value
            with self.assertRaises(ValueError):
                validate_observation(rows, "baseline")

    def test_rejects_partial_or_nonobject_records(self):
        for rows in (None, [], observation()[:1], [False, {}], [observation()[0], []]):
            with self.assertRaises(ValueError):
                validate_observation(rows, "baseline")


if __name__ == "__main__":
    unittest.main()
