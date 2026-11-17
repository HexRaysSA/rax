"""S075 original-index obligations that a zero byte displacement cannot encode."""
from dataclasses import replace
import unittest

from common import Reject
from candidate.machine import Machine
from candidate.memory import GuestFault
from candidate.type_system import ref
from candidate.values import Pointer
from test_candidate import constant, decl, fixture, operation
from test_candidate_initializers import initializer_context, evaluate


class CandidateGepBaseTests(unittest.TestCase):
    def test_strict_zero_base_closed_extent_and_deallocated_tombstone(self):
        from candidate.verify import verify
        memory = Machine(verify(*fixture())).memory
        for size in [0, 8]:
            base = memory.allocate(size, 8)
            for offset in [0, size]:
                pointer = replace(base, address=base.address + offset)
                self.assertEqual(memory.offset(pointer, 0, True, False, True, check_base=True), pointer)
            memory.end_lifetime(base)
            self.assertEqual(memory.offset(base, 0, True, False, True, check_base=True), base)
            with self.assertRaises(GuestFault) as caught:
                memory.guard(base, 0)
            self.assertEqual(caught.exception.code, 'memory_lifetime')
            for pointer in [replace(base, generation=999), replace(base, address=base.address-1),
                            replace(base, address=base.address+size+1), Pointer(base.address), Pointer(0)]:
                self.assertIsNone(memory.offset(pointer, 0, True, False, True, check_base=True))
                self.assertEqual(memory.offset(pointer, 0, True, False, True), pointer)

    def test_zero_original_indices_select_masks_strict_poison_and_retains_range(self):
        # Original nonzero index through zero-size stride yields offset0. It
        # must poison an unprovenanced base, while original index0 preserves it.
        for index in [0, 1]:
            ops = [constant(0, 5, (index).to_bytes(8, 'little').hex()),
                constant(1, 5, '0000000000000000'), constant(2, 5, '1000000000000000'),
                operation('inttoptr', [decl(3, 4)], [2]),
                operation('i_mul', [decl(4, 5)], [0, 1], flags=['nsw']),
                operation('ptr_offset', [decl(5, 4)], [3, 4], inbounds=True, check_base=True,
                    nuw=False, nusw=True, inrange={'some': {'lower': 0, 'upper': 8}}),
                operation('ptr_offset', [decl(6, 4)], [3, 1], inbounds=False, check_base=False,
                    nuw=False, nusw=False, inrange={'some': {'lower': 0, 'upper': 8}}),
                operation('icmp', [decl(7, 300)], [0, 1], predicate='eq'),
                operation('select', [decl(8, 4)], [7, 6, 5])]
            context, machine, layout = initializer_context(ops, 4, 7)
            result = evaluate(context, machine, layout)
            self.assertEqual(result.value.state, 'concrete' if index == 0 else 'poison')
            if index == 0:
                self.assertEqual((result.value.data.address, result.value.data.access_range), (16, (16, 24)))
            else:
                self.assertTrue(all(byte.poison == 255 for byte in result.bytes))

    def test_check_base_requires_inbounds_before_execution(self):
        ops = [constant(0, 5, '0000000000000000'), operation('inttoptr', [decl(1, 4)], [0]),
            operation('ptr_offset', [decl(2, 4)], [1, 0], inbounds=False, check_base=True,
                      nuw=False, nusw=False, inrange=None)]
        with self.assertRaisesRegex(Reject, 'pointer_check_base'):
            initializer_context(ops, 4, 7)


if __name__ == '__main__':
    unittest.main()
