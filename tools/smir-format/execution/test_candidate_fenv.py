"""INT-D009 accepted source fenv ABI and VM policy isolation witnesses."""
from copy import deepcopy
import struct
import unittest

from candidate.fenv import FLAG_CODES, ROUND_CODES, SourceFenv, mask, names, pack, unpack
from candidate.fenv import word, from_word, set_snapshot, get_rounding, rounding_snapshot
from common import Reject
from candidate.machine import Machine
from candidate.memory import GuestFault
from candidate.raw import Raw
from candidate.verify import verify
from test_candidate import fixture


class CandidateFenvTests(unittest.TestCase):
    def test_llvm_environment_words_and_mode_only_current_flags(self):
        for rounding in ROUND_CODES:
            for flags in range(64):
                snapshot = {'rounding': rounding, 'flags': names(flags), 'traps': []}
                self.assertEqual(from_word(word(snapshot)), snapshot)
                self.assertEqual(from_word(word(snapshot, True), True)['rounding'], rounding)
                self.assertEqual(rounding_snapshot(get_rounding(snapshot))['rounding'], rounding)
                machine = self.machine()
                machine.environment['flags'] = ['invalid']
                set_snapshot(machine, snapshot, True)
                self.assertEqual(machine.environment, {'rounding': rounding, 'flags': ['invalid'], 'traps': []})
                self.assertEqual(machine.diagnostic_fp_traps, ['invalid'])
        for invalid in [1 << 63, 0x1000, 0x40, -1, True]:
            with self.assertRaisesRegex(Reject, 'invalid_fenv'):
                from_word(invalid)
        with self.assertRaisesRegex(Reject, 'invalid_fenv'):
            from_word(1, True)
        with self.assertRaisesRegex(Reject, 'invalid_fenv'):
            rounding_snapshot(4)

    def machine(self):
        return Machine(verify(*fixture()), diagnostic_fp_traps=['invalid'])

    def test_snapshot_golden_layout_and_all_masks(self):
        for rounding, code in ROUND_CODES.items():
            for flags in range(64):
                environment = {'rounding': rounding, 'flags': names(flags), 'traps': []}
                raw = pack(environment)
                self.assertEqual(raw, struct.pack('<IIIIQQ', 1, code, flags, 0, 0, 0))
                self.assertEqual(unpack(raw), environment)
        self.assertEqual(mask(sorted(FLAG_CODES)), 63)

    def test_flag_selected_restore_preserves_other_flags_without_trap(self):
        machine = self.machine()
        api = SourceFenv(machine)
        for original in range(64):
            for selected in range(64):
                machine.environment['flags'] = names(original)
                self.assertEqual(api.flag_operation('setflag', selected, 63), 0)
                self.assertEqual(mask(machine.environment['flags']), original | selected)
                self.assertEqual(api.flag_operation('setflag', selected, 0), 0)
                self.assertEqual(mask(machine.environment['flags']), original & ~selected)
        self.assertEqual(machine.diagnostic_fp_traps, ['invalid'])

    def test_denorm_sticky_only_and_ieee_raise_traps_after_flags(self):
        machine = self.machine()
        api = SourceFenv(machine)
        self.assertEqual(api.flag_operation('raise', 32), 0)
        self.assertEqual(machine.environment['flags'], ['denormal'])
        with self.assertRaises(GuestFault) as error:
            api.flag_operation('raise', 4)
        self.assertEqual(error.exception.code, 'fp_invalid')
        self.assertEqual(machine.environment['flags'], ['denormal', 'invalid'])
        api.flag_operation('clear', 63)
        self.assertEqual(api.flag_operation('set', 4), 0)  # C23 fesetexcept is no-trap.
        self.assertEqual(machine.environment['flags'], ['invalid'])

    def test_hold_update_copy_and_policy_isolation(self):
        machine = self.machine()
        api = SourceFenv(machine)
        pointer = machine.memory.allocate(32, 8)
        machine.environment.update(rounding='downward', flags=['denormal', 'overflow'])
        self.assertEqual(api.getenv(pointer, hold=True), 0)
        self.assertEqual(machine.environment, {'rounding': 'downward', 'flags': [], 'traps': []})
        self.assertEqual(machine.diagnostic_fp_traps, ['invalid'])
        machine.environment.update(rounding='upward', flags=['invalid'])
        with self.assertRaises(GuestFault):
            api.setenv(pointer, update=True)
        self.assertEqual(machine.environment, {'rounding': 'downward', 'flags': ['denormal', 'invalid', 'overflow'], 'traps': []})
        other = Machine(verify(*fixture()))
        other_api = SourceFenv(other)
        copy_pointer = other.memory.allocate(32, 8)
        copy = machine.memory.raw_load(pointer, 32, 8)
        other.memory.raw_store(copy_pointer, copy, 8)
        self.assertEqual(other_api.setenv(copy_pointer), 0)
        self.assertEqual(other.environment['flags'], ['denormal', 'overflow'])
        self.assertEqual(other.diagnostic_fp_traps, [])

    def test_invalid_fields_round_and_memory_fail_before_mutation(self):
        machine = self.machine()
        api = SourceFenv(machine)
        pointer = machine.memory.allocate(32, 8)
        original = deepcopy(machine.environment)
        for offset, replacement in [(0, 2), (4, 1), (8, 64), (12, 4), (16, 1), (24, 1)]:
            raw = bytearray(pack(original)); raw[offset:offset + 4] = replacement.to_bytes(4, 'little')
            machine.memory.raw_store(pointer, Raw.integer(256, int.from_bytes(raw, 'little')), 8)
            self.assertEqual(api.setenv(pointer), 1)
            self.assertEqual(machine.environment, original)
        self.assertEqual(api.setround(0x1000), 1)
        self.assertEqual(machine.environment, original)
        small = machine.memory.allocate(16, 8)
        with self.assertRaises(GuestFault):
            api.getenv(small, hold=True)
        self.assertEqual(machine.environment, original)
        self.assertEqual(machine.diagnostic_fp_traps, ['invalid'])

    def test_mode_preserves_sticky_and_default_object_bytes(self):
        machine = self.machine()
        api = SourceFenv(machine)
        mode = machine.memory.allocate(16, 8)
        machine.environment['flags'] = ['denormal']
        machine.environment['rounding'] = 'upward'
        self.assertEqual(api.getmode(mode), 0)
        self.assertEqual(machine.memory.raw_load(mode, 16, 8).bits.to_bytes(16, 'little'), struct.pack('<IIQ', 0x800, 0, 0))
        machine.environment['rounding'] = 'downward'
        self.assertEqual(api.setmode(mode), 0)
        self.assertEqual(machine.environment, {'rounding': 'upward', 'flags': ['denormal'], 'traps': []})
        default = pack({'rounding': 'nearest_even', 'flags': [], 'traps': []})
        self.assertEqual(default, b'\x01' + b'\0' * 31)
