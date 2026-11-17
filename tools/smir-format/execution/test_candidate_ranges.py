"""Inrange restrictions survive raw copies and provenance loss without exposure."""
import unittest

from candidate import pure
from candidate.live import Registry, absolute_range, validate
from candidate.machine import Machine
from candidate.memory import GuestFault
from candidate.ranges import EMPTY, intersect, normalize, record
from candidate.raw import Raw, concat
from candidate.type_system import ref
from candidate.values import Pointer, Value, from_raw, raw_bits
from candidate.verify import verify
from test_candidate import decl, fixture, operation


class CandidateRangeTests(unittest.TestCase):
    def test_range_base_is_wrapped_result_then_mathematical_clipped_bounds(self):
        machine = Machine(verify(*fixture()))
        interval = {'lower': -1, 'upper': 1}
        high = machine.memory.offset(Pointer(16), -32, False, False, False, interval)
        self.assertEqual((high.address, high.access_range), (2**64 - 16, (2**64 - 17, 2**64 - 15)))
        low = machine.memory.offset(Pointer(2**64 - 16), 32, False, False, False, interval)
        self.assertEqual((low.address, low.access_range), (16, (15, 17)))
        edge = machine.memory.offset(Pointer(0), -1, False, False, False, interval)
        self.assertEqual(edge.access_range, (2**64 - 2, 2**64))
        restricted = machine.memory.offset(Pointer(16, access_range=(0, 32)), -32,
                                           False, False, False, interval)
        self.assertEqual(restricted.access_range, EMPTY)
        self.assertIsNone(machine.memory.offset(Pointer(16), -32, True, False, True, interval))
        self.assertIsNone(machine.memory.offset(Pointer(2**64 - 16), 32, False, True, False, interval))

    def test_raw_numeric_conversion_and_provenance_loss_keep_restriction(self):
        machine = Machine(verify(*fixture()))
        pointer = machine.memory.allocate(16, 8)
        restricted = machine.memory.offset(pointer, 0, True, False, True, {'lower': 0, 'upper': 8})
        raw = Raw.pointer(restricted)
        self.assertEqual(from_raw(machine.types, ref(7), raw).data, restricted)
        with self.assertRaisesRegex(GuestFault, 'ub_inrange_address_conversion'):
            from_raw(machine.types, ref(3), raw)
        partial = concat([raw.slice(0, 32), Raw.integer(32, 0)])
        lost = from_raw(machine.types, ref(7), partial)
        self.assertIsNone(lost.data.origin)
        self.assertEqual(lost.data.access_range, restricted.access_range)
        copied = raw_bits(machine.types, lost)
        self.assertIsNone(copied.origins[0].pointer.origin)
        with self.assertRaisesRegex(GuestFault, 'ub_inrange_address_conversion'):
            from_raw(machine.types, ref(3), copied)
        # Pinned ByteTy explicitly strips unrestricted provenance WITHOUT exposure.
        unrestricted = from_raw(machine.types, ref(3), Raw.pointer(pointer))
        self.assertEqual(unrestricted.data, pointer.address)
        self.assertEqual(machine.memory.exposed, set())
        self.assertIsNone(machine.memory.integer_pointer(unrestricted.data).origin)

    def test_clipping_empty_intersection_and_closed_point_comparison(self):
        self.assertEqual(normalize((-4, 4)), (0, 4))
        self.assertEqual(normalize((2**64 - 1, 2**64 + 10)), (2**64 - 1, 2**64))
        self.assertEqual(normalize((-4, -1)), EMPTY)
        self.assertEqual(intersect((1, 4), (8, 9)), EMPTY)
        self.assertNotEqual(record(EMPTY), record((0, 0)))
        self.assertEqual(absolute_range(record(EMPTY)), EMPTY)
        self.assertEqual(absolute_range(record((0, 0))), (0, 0))
        machine = Machine(verify(*fixture()))
        compare = operation('icmp', [decl(0, 0)], [], predicate='eq')
        null = Value(ref(7), 'concrete', Pointer(0))
        point = Value(ref(7), 'concrete', Pointer(0, access_range=(0, 0)))
        self.assertEqual(pure.execute(machine, compare, [point, null])[0].data, 1)
        empty = Value(ref(7), 'concrete', Pointer(0, access_range=EMPTY))
        with self.assertRaisesRegex(GuestFault, 'ub_inrange_compare'):
            pure.execute(machine, compare, [empty, null])

    def test_range_only_raw_span_live_record_grants_no_registry_object(self):
        machine = Machine(verify(*fixture()))
        live = {'type': ref(4), 'payload': {'kind': 'raw', 'bits': '1000000000000000',
            'poison': '0000000000000000', 'undef': '0000000000000000', 'origins': [
                {'offset': 0, 'length': 64, 'object': None, 'generation': 0, 'pointer_bits': 16,
                 'source_bit': 0, 'domain': 'data', 'range': record((16, 24)), 'binding_permit': None}]}}
        registry = Registry()
        validate(live, machine.types, registry, 1)
        self.assertEqual(registry.pointers, {})
        self.assertEqual(registry.handles, {})


if __name__ == '__main__':
    unittest.main()
