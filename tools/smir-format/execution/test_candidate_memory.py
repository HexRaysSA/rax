"""Physical layout, independent lane progress and representation boundaries."""
import unittest

from candidate.machine import Machine
from candidate.memory import GuestFault
from candidate.operations import Dependencies
from candidate.raw import Raw, concat
from candidate.type_system import ref
from candidate.values import Pointer, Value
from candidate.verify import verify
import test_candidate
from test_candidate import block, decl, fixture, operation

MODE = {'alignment': 1, 'volatile': False, 'order': 'none', 'failure_order': 'none',
        'scope': 'process', 'elementwise': False}


def scalar(identifier, typ, size, access=None, alignment=1):
    return {'id': identifier, 'type': ref(typ), 'size': size, 'access_bytes': size if access is None else access,
            'alignment': alignment, 'fields': [], 'element': None, 'stride': 0}


def storage(typ, layout, size):
    return {'type': ref(typ), 'layout': ref(layout), 'nominal': None, 'abi_binding': None, 'bytes': size}


class CandidateMemoryTests(unittest.TestCase):
    def test_readonly_atomic_write_intent_fails_before_observable_read(self):
        for name in ['atomic_rmw', 'cmpxchg']:
            roots = fixture()
            roots[0]['memory_layouts'] = [scalar(0, 2, 4, alignment=4)]
            roots[0]['types'][15].update(params=[ref(7)], param_noundef=[True])
            fn = roots[1]['functions'][0]
            fn['params'] = [decl(0, 7)]
            mode = {**MODE, 'alignment': 4, 'volatile': True, 'order': 'relaxed',
                    'failure_order': 'relaxed' if name == 'cmpxchg' else 'none'}
            node = (operation(name, [decl(3, 2), decl(4, 0)], [0, 1, 2],
                              storage=storage(2, 0, 4), mode=mode, weak=False) if name == 'cmpxchg' else
                    operation(name, [decl(3, 2)], [0, 2], storage=storage(2, 0, 4), mode=mode, action='add'))
            fn['blocks'] = [block(0, [test_candidate.constant(1, 2, '03000000'),
                test_candidate.constant(2, 2, '09000000'), node], {'op': 'return', 'values': [3]})]
            machine = Machine(verify(*roots))
            pointer = machine.memory.allocate(4, 4)
            machine.memory.raw_store(pointer, Raw.integer(32, 7))
            machine.memory.objects[pointer.origin]['mutable'] = False
            reads, load = [], machine.memory.load
            def observed(*args):
                reads.append(1)
                return load(*args)
            machine.memory.load = observed
            machine.start(0, [Value(ref(7), 'concrete', pointer)])
            self.assertEqual(machine.run()['reason'], 'memory_permission')
            self.assertEqual(reads, [])
            self.assertEqual(machine.memory.effects, [])
            self.assertEqual(machine.memory.raw_load(pointer, 4).bits, 7)

    def bulk_machine(self, name):
        types, functions, eh = fixture()
        signature = types['types'][15]
        arg_types = [7, 1 if name == 'memset' else 7, 3]
        signature.update(params=[ref(t) for t in arg_types], param_noundef=[False] * 3)
        function = functions['functions'][0]
        function['params'] = [decl(i, t) for i, t in enumerate(arg_types)]
        function['blocks'] = [block(0, [operation(name, [], [0, 1, 2], alignment=8, volatile=True),
            test_candidate.constant(3, 2, '2a000000')], {'op': 'return', 'values': [3]})]
        return Machine(verify(types, functions, eh))

    def test_zero_bulk_does_not_observe_pointers_or_byte_but_count_is_noundef(self):
        for name in ['memcpy', 'memmove', 'memset']:
            for state in ['poison', 'undef']:
                machine = self.bulk_machine(name)
                second = 1 if name == 'memset' else 7
                machine.start(0, [Value(ref(7), state), Value(ref(second), state), Value(ref(3), 'concrete', 0)])
                self.assertEqual(machine.run()['values'][0].data, 42)
                self.assertEqual(machine.memory.effects, [])
                machine = self.bulk_machine(name)
                machine.start(0, [Value(ref(7), 'poison'), Value(ref(second), 'poison'), Value(ref(3), state)])
                outcome = machine.run()
                self.assertEqual((outcome['kind'], outcome['reason'], outcome['operation']),
                                 ('language_ub', 'ub_memory_count', 0))
                self.assertEqual(machine.memory.effects, [])
            machine = self.bulk_machine(name)
            stale = machine.memory.allocate(8, 8)
            machine.memory.end_lifetime(stale)
            machine.start(0, [Value(ref(7), 'concrete', stale),
                Value(ref(1), 'poison') if name == 'memset' else Value(ref(7), 'concrete', Pointer(0)),
                Value(ref(3), 'concrete', 0)])
            self.assertEqual(machine.run()['values'][0].data, 42)

    def test_bulk_nonzero_pointer_undef_and_memset_byte_shadow(self):
        for name in ['memcpy', 'memmove', 'memset']:
            machine = self.bulk_machine(name)
            second = 1 if name == 'memset' else 7
            machine.start(0, [Value(ref(7), 'undef'), Value(ref(second), 'poison'), Value(ref(3), 'concrete', 1)])
            self.assertEqual(machine.run()['reason'], 'ub_memory_address')
        for state, poison, undef in [('poison', 255, 0), ('undef', 0, 255)]:
            machine = self.bulk_machine('memset')
            pointer = machine.memory.allocate(8, 8)
            machine.start(0, [Value(ref(7), 'concrete', pointer), Value(ref(1), state), Value(ref(3), 'concrete', 2)])
            self.assertEqual(machine.run()['values'][0].data, 42)
            self.assertEqual(machine.memory.objects[pointer.origin]['bytes'][:2], [Raw.integer(8, 0, poison, undef)] * 2)
            self.assertEqual(machine.memory.effects, [('memset', 2, True)])

    def test_memcpy_equal_allowed_partial_overlap_rejects_before_write(self):
        machine = self.bulk_machine('memcpy')
        pointer = machine.memory.allocate(16, 8)
        raw = Raw.integer(128, 0x1234, poison=1 << 16, undef=1 << 20)
        machine.memory.raw_store(pointer, raw)
        machine.memory.effects.clear()
        machine.start(0, [Value(ref(7), 'concrete', pointer)] * 2 + [Value(ref(3), 'concrete', 16)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        self.assertEqual(machine.memory.raw_load(pointer, 16), raw)
        other = self.bulk_machine('memcpy')
        pointer = other.memory.allocate(24, 8)
        before = list(other.memory.objects[pointer.origin]['bytes'])
        source = Pointer(pointer.address + 8, pointer.origin, pointer.generation)
        other.start(0, [Value(ref(7), 'concrete', pointer), Value(ref(7), 'concrete', source), Value(ref(3), 'concrete', 16)])
        self.assertEqual(other.run()['reason'], 'ub_memcpy_overlap')
        self.assertEqual(other.memory.objects[pointer.origin]['bytes'], before)
        self.assertEqual(other.memory.effects, [])

    def test_overlapping_memmove_snapshots_pointer_shadow_with_bytes(self):
        machine = self.bulk_machine('memmove')
        pointer = machine.memory.allocate(24, 8)
        pointee = machine.memory.allocate(8, 8)
        prefix = Raw.integer(64, 0x0706050403020100)
        pointer_bits = Raw.pointer(pointee)
        machine.memory.raw_store(pointer, concat([prefix, pointer_bits, Raw.integer(64, 0xa5)]))
        destination = Pointer(pointer.address + 8, pointer.origin, pointer.generation)
        machine.start(0, [Value(ref(7), 'concrete', destination), Value(ref(7), 'concrete', pointer),
                          Value(ref(3), 'concrete', 16)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        self.assertEqual(machine.memory.raw_load(pointer, 24), concat([prefix, prefix, pointer_bits]))
        self.assertEqual(machine.memory.raw_load(destination, 16).slice(64, 64).as_pointer()['identity'], pointee.origin)
        self.assertEqual(machine.memory.effects, [('memmove', 16, True)])

    def test_raw_top_byte_and_representable_source_one_past(self):
        machine = Machine(verify(*fixture()))
        machine.memory.next_address = 2**64 - 1
        with self.assertRaisesRegex(GuestFault, 'source_object_extent'):
            machine.memory.allocate(1, 1)
        self.assertEqual(machine.memory.objects, {})
        raw = machine.memory.allocate(1, 1, source_object=False)
        machine.memory.raw_store(raw, Raw.integer(8, 0xa5))
        self.assertEqual(machine.memory.raw_load(raw, 1).bits, 0xa5)
        self.assertIsNone(machine.memory.offset(raw, 1, True, False, True))
        self.assertEqual(machine.memory.offset(raw, 1, False, False, False).address, 0)
        other = Machine(verify(*fixture()))
        other.memory.next_address = 2**64 - 2
        pointer = other.memory.allocate(1, 1)
        self.assertEqual(other.memory.offset(pointer, 1, True, False, True).address, 2**64 - 1)

    def test_bitint65_access9_allocation16_tail_preserved(self):
        types, functions, eh = fixture()
        types['types'].append({'id': 17, 'kind': 'int', 'bits': 65})
        types['memory_layouts'] = [scalar(0, 17, 16, 9, 8)]
        machine = Machine(verify(types, functions, eh))
        pointer = machine.memory.allocate(16, 8)
        machine.memory.raw_store(pointer, Raw.integer(128, int.from_bytes(b'\xaa' * 16, 'little')))
        spec = storage(17, 0, 9)
        value = Value(ref(17), 'concrete', (1 << 64) | 17)
        machine.memory.store(pointer, value, spec, {**MODE, 'alignment': 8})
        data = machine.memory.raw_load(pointer, 16)
        self.assertEqual(data.bits.to_bytes(16, 'little'), b'\x11' + b'\0' * 7 + b'\x01' + b'\xaa' * 7)
        self.assertEqual(machine.memory.load(pointer, spec, MODE), value)
        # Pinned LLVM load is byte load + trunc nuw: nonzero discarded bits poison.
        bad = Pointer(pointer.address + 8, pointer.origin, pointer.generation)
        machine.memory.raw_store(bad, Raw.integer(8, 3))
        self.assertEqual(machine.memory.load(pointer, spec, MODE).state, 'poison')

    def test_packed_struct_and_vector_i1_distinct_from_array_i1(self):
        types, functions, eh = fixture()
        types['types'] += [{'id': 17, 'kind': 'vector', 'element': ref(0), 'count': 8},
                           {'id': 18, 'kind': 'array', 'element': ref(0), 'count': 8}]
        types['memory_layouts'] = [scalar(0, 0, 1), scalar(1, 1, 1), scalar(2, 2, 4),
            {'id': 3, 'type': ref(9), 'size': 5, 'access_bytes': 5, 'alignment': 1, 'element': None, 'stride': 0,
             'fields': [{'value_index': 0, 'bit_offset': 0, 'bit_width': 8, 'layout': ref(1)},
                        {'value_index': 1, 'bit_offset': 8, 'bit_width': 32, 'layout': ref(2)}]},
            {'id': 4, 'type': ref(17), 'size': 1, 'access_bytes': 1, 'alignment': 1, 'fields': [], 'element': {'some': ref(0)}, 'stride': 1},
            {'id': 5, 'type': ref(18), 'size': 8, 'access_bytes': 8, 'alignment': 1, 'fields': [], 'element': {'some': ref(0)}, 'stride': 8}]
        machine = Machine(verify(types, functions, eh))
        pointer = machine.memory.allocate(5, 1)
        value = Value(ref(9), 'concrete', (Value(ref(1), 'concrete', 0xab), Value(ref(2), 'concrete', 0x12345678)))
        machine.memory.store(pointer, value, storage(9, 3, 5), MODE)
        self.assertEqual(machine.memory.raw_load(pointer, 5).bits.to_bytes(5, 'little'), bytes.fromhex('ab78563412'))
        self.assertEqual(machine.memory.load(pointer, storage(9, 3, 5), MODE), value)
        lanes = tuple(Value(ref(0), 'concrete', i % 2) for i in range(8))
        for typ, layout, count, expected in [(17, 4, 1, b'\xaa'), (18, 5, 8, bytes([0, 1] * 4))]:
            pointer = machine.memory.allocate(count, 1)
            value = Value(ref(typ), 'concrete', lanes)
            machine.memory.store(pointer, value, storage(typ, layout, count), MODE)
            self.assertEqual(machine.memory.raw_load(pointer, count).bits.to_bytes(count, 'little'), expected)
            self.assertEqual(machine.memory.load(pointer, storage(typ, layout, count), MODE), value)

    def test_elementwise_fault_retains_exact_observed_prefix(self):
        layouts = [scalar(0, 1, 1), {'id': 1, 'type': ref(8), 'size': 4, 'access_bytes': 4,
                    'alignment': 1, 'fields': [], 'element': {'some': ref(0)}, 'stride': 8}]
        node = operation('atomic_load', [decl(1, 8)], [0], storage=storage(8, 1, 4),
                         mode={**MODE, 'order': 'acquire', 'elementwise': True})
        machine = test_candidate.CandidateTests().machine([node], result_type=8, params=[(0, 7)], layouts=layouts)
        pointer = machine.memory.allocate(2, 1)
        machine.memory.raw_store(pointer, Raw.integer(16, 0x3412))
        machine.start(0, [Value(ref(7), 'concrete', pointer)])
        result = machine.run()
        self.assertEqual((result['kind'], result['reason']), ('trap', 'memory_bounds'))
        progress = machine.stack[0].progress
        self.assertEqual(progress['next_lane'], 2)
        self.assertEqual([value.data for value in progress['observed']], [0x12, 0x34])
        self.assertNotIn(1, machine.stack[0].values)
        self.assertEqual(len(machine.memory.effects), 2)

    def test_wide_atomic_value_shadow_transaction(self):
        types, functions, eh = fixture()
        types['types'].append({'id': 17, 'kind': 'raw', 'bits': 256})
        types['memory_layouts'] = [scalar(0, 17, 32, alignment=8)]
        machine = Machine(verify(types, functions, eh))
        pointer = machine.memory.allocate(32, 8)
        value = Value(ref(17), 'concrete', Raw.integer(256, 123, poison=1 << 200, undef=1 << 80))
        mode = {**MODE, 'alignment': 8, 'order': 'seq_cst'}
        store = operation('atomic_store', [], [], storage=storage(17, 0, 32), mode=mode)
        load = operation('atomic_load', [decl(0, 17)], [], storage=storage(17, 0, 32), mode=mode)
        machine.memory_operation(store, [Value(ref(7), 'concrete', pointer), value])
        self.assertEqual(machine.memory_operation(load, [Value(ref(7), 'concrete', pointer)]), [value])


if __name__ == '__main__':
    unittest.main()
