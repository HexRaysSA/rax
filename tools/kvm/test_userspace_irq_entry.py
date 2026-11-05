import copy
import unittest

from userspace_irq_entry import DEADLINE, validate


def record(count, x2apic):
    return {"kernel_irqchip_created": False, "mwait_exit_disabled": True, "x2apic": x2apic,
            "cpu_count": count, "timer_expiry_qualified": False, "checkpoint_restore_qualified": False,
            "cpus": [{"id": i, "deadline": DEADLINE + i, "deadline_write_exits": 1,
                      "deadline_read_exits": 1, "apic_write_exits": 0 if x2apic else 1,
                      "x2apic_write_exits": int(x2apic), "x2apic_read_exits": int(x2apic),
                      "native_entries": 5 if x2apic else 4, "lapic_query_errno": 22,
                      "rip": 0x10000 + (54 if x2apic else 49), "r10": (DEADLINE + i) & 0xFFFFFFFF,
                      "r11": DEADLINE >> 32, "r13": 0x40041 if x2apic else 0,
                      "x2apic_write_reason": 1 if x2apic else None,
                      "x2apic_read_reason": 2 if x2apic else None, "passed": True} for i in range(count)]}


class RoutingAdmissionTests(unittest.TestCase):
    def test_all_profiles_and_topologies(self):
        for x2apic in (False, True):
            for count in (1, 2, 4):
                validate(record(count, x2apic), count, x2apic)

    def test_missing_or_duplicate_last_cpu_cannot_pass(self):
        for mutation in (lambda r: r["cpus"].pop(), lambda r: r["cpus"][-1].update(id=0)):
            r = record(4, False)
            mutation(r)
            with self.assertRaises(ValueError):
                validate(r, 4, False)

    def test_typed_guest_and_exit_values_cannot_be_fabricated(self):
        original = record(2, True)
        for key, value in (("deadline_write_exits", 0), ("native_entries", True),
                           ("deadline", DEADLINE), ("r10", 0), ("r11", 0), ("r13", 0),
                           ("rip", 0x10000), ("lapic_query_errno", 0), ("passed", 1),
                           ("x2apic_write_reason", 4), ("x2apic_read_reason", None)):
            r = copy.deepcopy(original)
            r["cpus"][-1][key] = value
            with self.assertRaises(ValueError):
                validate(r, 2, True)

    def test_no_restore_or_expiry_claim_and_complete_optional_schema(self):
        for key in ("timer_expiry_qualified", "checkpoint_restore_qualified", "kernel_irqchip_created"):
            r = record(1, False)
            r[key] = True
            with self.assertRaises(ValueError):
                validate(r, 1, False)
        r = record(1, False)
        del r["cpus"][0]["x2apic_read_reason"]
        with self.assertRaises(ValueError):
            validate(r, 1, False)
        r["cpus"][0]["x2apic_read_reason"] = 0
        with self.assertRaises(ValueError):
            validate(r, 1, False)


if __name__ == "__main__":
    unittest.main()
