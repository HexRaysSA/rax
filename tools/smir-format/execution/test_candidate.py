"""Coherent candidate records, full typed SSA and edge-result negative witnesses."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from common import Reject, SPEC
from candidate.schema_build import schema
from candidate.type_system import ref
from candidate.type_system import Types
from candidate.verify import verify
from candidate.wire import decode, encode
from candidate.machine import Machine, Pending, Raised
from candidate.operations import Dependencies
from candidate.values import Value, Pointer, raw_bits
from candidate.raw import Raw, Span, concat
from candidate.memory import GuestFault


def decl(identifier, type_id):
    return {'id': identifier, 'type': ref(type_id)}


def operation(name, result=(), operands=(), **fields):
    if name == 'call':
        fields = {'source_plan': None, **fields}  # Explicit generic fixture producer.
    return {'op': name, 'results': list(result), 'operands': list(operands), **fields}


def constant(identifier, type_id, raw):
    return operation('constant', [decl(identifier, type_id)], literal={'kind': 'bits', 'value': raw})


def block(identifier, operations, term, phis=()):
    if term['op'] in {'invoke', 'tailcall'}:
        term = {'source_plan': None, **term}  # Generic source fixture, never decoded bytes.
    return {'id': identifier, 'phis': list(phis), 'ops': operations, 'term': term}


def fixture():
    types = [{'id': 0, 'kind': 'int', 'bits': 1}, {'id': 1, 'kind': 'int', 'bits': 8},
             {'id': 2, 'kind': 'int', 'bits': 32}, {'id': 3, 'kind': 'int', 'bits': 64},
             {'id': 4, 'kind': 'raw', 'bits': 64}, {'id': 5, 'kind': 'float', 'format': 'binary32'},
             {'id': 6, 'kind': 'float', 'format': 'binary64'}, {'id': 7, 'kind': 'data_ptr', 'space': 'guest_data'},
             {'id': 8, 'kind': 'vector', 'element': ref(1), 'count': 4},
             {'id': 9, 'kind': 'struct', 'fields': [ref(1), ref(2)]},
             {'id': 10, 'kind': 'exception'}, {'id': 11, 'kind': 'fenv'},
             {'id': 12, 'kind': 'stack_mark'}, {'id': 13, 'kind': 'va_list'}, {'id': 14, 'kind': 'journal'},
             {'id': 15, 'kind': 'function', 'params': [], 'results': [ref(2)], 'variadic': False,
              'param_noundef': [], 'result_noundef': [True], 'cc': 'portable'},
             {'id': 16, 'kind': 'code_ptr', 'signature': ref(15)}]
    function = {'id': 0, 'signature': ref(15), 'abi_signature': None, 'params': [], 'entry': 0,
                'escape': 'propagate', 'no_return': False,
                'blocks': [block(0, [constant(0, 2, '2a000000')], {'op': 'return', 'values': [0]})]}
    return ({'payload_revision': 2, 'types': types, 'memory_layouts': []}, {'payload_revision': 2, 'functions': [function]},
            {'payload_revision': 1, 'functions': []})


class CandidateTests(unittest.TestCase):
    def machine(self, operations, result_type=2, params=(), blocks=None, dependencies=None, layouts=()):
        roots = fixture()
        roots[0]['memory_layouts'] = list(layouts)
        roots[0]['types'][15]['params'] = [ref(typ) for _, typ in params]
        roots[0]['types'][15]['param_noundef'] = [False] * len(params)
        roots[0]['types'][15]['results'] = [ref(result_type)]
        roots[1]['functions'][0]['params'] = [decl(identifier, typ) for identifier, typ in params]
        roots[1]['functions'][0]['blocks'] = blocks or [block(0, operations,
            {'op': 'return', 'values': [operations[-1]['results'][0]['id']]})]
        return Machine(verify(*roots, dependencies=dependencies))

    def test_generated_integer_poison_freezes_and_divisor_observes_precise_ub(self):
        cases = [('i_add', '7f', '01', ['nsw']), ('i_add', 'ff', '01', ['nuw']),
                 ('i_lshr', '03', '01', ['exact']), ('i_shl', '01', '08', [])]
        for name, a, b, flags in cases:
            with self.subTest(name=name, flags=flags):
                prefix = [constant(0, 1, a), constant(1, 1, b),
                          operation(name, [decl(2, 1)], [0, 1], flags=flags)]
                machine = self.machine(prefix + [operation('freeze', [decl(3, 1)], [2])], 1)
                machine.start(0, [])
                self.assertEqual(machine.run()['values'][0], Value(ref(1), 'concrete', 0))
                self.assertEqual(machine.stack, [])
                machine = self.machine(prefix + [operation('i_udiv', [decl(3, 1)], [0, 2], flags=[])], 1)
                machine.start(0, [])
                outcome = machine.run()
                self.assertEqual((outcome['kind'], outcome['reason'], outcome['operation']),
                                 ('language_ub', 'ub_poison_divisor', 3))
                self.assertEqual(machine.stack[0].values[2], Value(ref(1), 'poison'))
                self.assertNotIn(3, machine.stack[0].values)

    def test_integer_width_beyond_legacy_profile_preserves_candidate_semantics(self):
        roots = fixture()
        width = 65537
        roots[0]['types'][1]['bits'] = width
        roots[0]['types'][15]['results'] = [ref(1)]
        # 2^(w-1)-1 + 1 wraps to MIN, while nsw produces poison then freeze0.
        a = ((1 << (width - 1)) - 1).to_bytes((width + 7) // 8, 'little').hex()
        b = (1).to_bytes((width + 7) // 8, 'little').hex()
        for flags, expected in [([], 1 << (width - 1)), (['nsw'], 0)]:
            roots[1]['functions'][0]['blocks'] = [block(0, [constant(0, 1, a), constant(1, 1, b),
                operation('i_add', [decl(2, 1)], [0, 1], flags=flags),
                operation('freeze', [decl(3, 1)], [2])], {'op': 'return', 'values': [3]})]
            machine = Machine(verify(*roots))
            machine.start(0, [])
            self.assertEqual(machine.run()['values'][0].data, expected)

    def test_component_poison_extract_insert_and_vector_selection(self):
        aggregate = operation('constant', [decl(0, 9)], literal={'kind': 'aggregate', 'elements': [
            {'kind': 'poison'}, {'kind': 'bits', 'value': '2a000000'}]})
        machine = self.machine([aggregate, operation('extract', [decl(1, 2)], [0], indices=[1])])
        machine.start(0, [])
        self.assertEqual(machine.run()['values'][0].data, 42)
        vector = operation('constant', [decl(0, 8)], literal={'kind': 'aggregate', 'elements': [
            {'kind': 'bits', 'value': '01'}, {'kind': 'poison'},
            {'kind': 'bits', 'value': '03'}, {'kind': 'bits', 'value': '04'}]})
        machine = self.machine([vector, constant(1, 2, '01000000'), constant(2, 1, '07'),
                                operation('insert_element', [decl(3, 8)], [0, 2, 1]),
                                operation('extract_element', [decl(4, 1)], [3, 1])], 1)
        machine.start(0, [])
        self.assertEqual(machine.run()['values'][0].data, 7)

    def test_memory_atomic_cas_and_precise_fault(self):
        layout = {'id': 0, 'type': ref(2), 'size': 4, 'access_bytes': 4, 'alignment': 4,
                  'fields': [], 'element': None, 'stride': 0}
        dependencies = Dependencies()
        storage = {'type': ref(2), 'layout': ref(0), 'nominal': None, 'abi_binding': None, 'bytes': 4}
        mode = {'alignment': 4, 'volatile': True, 'order': 'none', 'failure_order': 'none', 'scope': 'process', 'elementwise': False}
        cas_mode = {**mode, 'order': 'relaxed', 'failure_order': 'seq_cst'}
        operations = [constant(1, 2, '2a000000'), operation('store', [], [0, 1], storage=storage, mode=mode),
                      constant(2, 2, '2d000000'),
                      operation('cmpxchg', [decl(3, 2), decl(4, 0)], [0, 1, 2], storage=storage, mode=cas_mode, weak=False),
                      operation('load', [decl(5, 2)], [0], storage=storage, mode=mode)]
        machine = self.machine(operations, params=[(0, 7)], dependencies=dependencies, layouts=[layout])
        pointer = machine.memory.allocate(4, 4)
        machine.start(0, [Value(ref(7), 'concrete', pointer)])
        self.assertEqual(machine.run()['values'][0].data, 45)
        self.assertEqual([event[0] for event in machine.memory.effects], ['store', 'cmpxchg', 'load'])
        failed = self.machine(operations, params=[(0, 7)], dependencies=dependencies, layouts=[layout])
        pointer = failed.memory.allocate(2, 4)
        failed.start(0, [Value(ref(7), 'concrete', pointer)])
        outcome = failed.run()
        self.assertEqual((outcome['kind'], outcome['operation'], outcome['reason']), ('trap', 1, 'memory_bounds'))
        self.assertEqual(failed.memory.objects[pointer.origin]['bytes'], [Raw.integer(8, 0, undef=255)] * 2)

    def test_fp_sqrt_conversion_and_enabled_trap_frontier(self):
        mode = {'environment': 'constrained', 'rounding': 'nearest_even', 'exceptions': 'strict'}
        machine = self.machine([constant(0, 5, '00008040'), operation('fp_sqrt', [decl(1, 5)], [0], mode=mode)], 5)
        machine.start(0, [])
        self.assertEqual(machine.run()['values'][0].data, 0x40000000)
        machine = self.machine([constant(0, 5, '000080bf'), operation('fp_sqrt', [decl(1, 5)], [0], mode=mode)], 5)
        machine.diagnostic_fp_traps = ['invalid']
        machine.start(0, [])
        result = machine.run()
        self.assertEqual((result['kind'], result['operation'], result['reason']), ('trap', 1, 'fp_invalid'))
        self.assertEqual(machine.environment['flags'], ['invalid'])
        self.assertNotIn(1, machine.stack[0].values)

    def test_undef_poison_and_pointer_spans_maximum_raw(self):
        width = 2**23
        raw = Raw.integer(width, (1 << (width - 1)) | 17, poison=1 << 7, undef=1 << 6)
        self.assertEqual(raw.freeze().bits, raw.bits)
        pointer = Pointer(0x1234567890abcdef, 'ab' * 32, 1)
        original = Raw.pointer(pointer)
        rebuilt = concat([original.slice(0, 17), original.slice(17, 47)])
        self.assertEqual(rebuilt.as_pointer()['identity'], pointer.origin)
        wide = concat([Raw.integer(65520, 0), original, Raw.integer(32, 0)])
        across = concat([wide.slice(0, 65535), wide.slice(65535, wide.width - 65535)])
        self.assertEqual(across.slice(65520, 64).as_pointer()['identity'], pointer.origin)

    def test_inbounds_tombstone_zero_null_and_inrange_guard(self):
        machine = Machine(verify(*fixture()))
        pointer = machine.memory.allocate(16, 8)
        machine.memory.end_lifetime(pointer)
        derived = machine.memory.offset(pointer, 8, True, False, True)
        self.assertEqual(derived.address, pointer.address + 8)
        with self.assertRaises(GuestFault):
            machine.memory.guard(derived, 1)
        self.assertEqual(machine.memory.offset(Pointer(0), 0, True, False, True).address, 0)
        fresh = machine.memory.allocate(16, 8)
        bounded = machine.memory.offset(fresh, 4, True, False, True, {'lower': 0, 'upper': 4})
        machine.memory.guard(bounded, 4)
        with self.assertRaises(GuestFault) as error:
            machine.memory.guard(bounded, 5)
        self.assertEqual(error.exception.code, 'ub_inrange_access')

    def test_schema_reproducible(self):
        self.assertEqual(json.loads((SPEC / 'schema/execution/candidate.json').read_text()), schema())

    def test_recursive_shape_digest_renaming_and_duplicate_sharing(self):
        original = fixture()[0]
        original['types'].append({'id': 17, 'kind': 'struct', 'fields': [ref(2), ref(2)]})
        a = Types(original)
        renamed = deepcopy(original)
        mapping = {item['id']: item['id'] + 100 for item in renamed['types']}
        for item in renamed['types']:
            item['id'] = mapping[item['id']]
            for name in ['element', 'signature']:
                if name in item:
                    item[name] = ref(mapping[item[name]['id']])
            for name in ['fields', 'params', 'results']:
                if name in item:
                    item[name] = [ref(mapping[child['id']]) for child in item[name]]
        renamed['types'].append({'id': 200, 'kind': 'int', 'bits': 32})
        renamed['types'][-2]['fields'][1] = ref(200)
        b = Types(renamed)
        self.assertEqual(a.digest(ref(17)), b.digest(ref(117)))
        self.assertNotEqual(a.digest(ref(1)), a.digest(ref(2)))
        # Two equivalent unfoldings of recursive code signatures.
        one = {'payload_revision': 2, 'types': [
            {'id': 0, 'kind': 'code_ptr', 'signature': ref(1)},
            {'id': 1, 'kind': 'function', 'params': [ref(0)], 'results': [], 'variadic': False,
             'param_noundef': [False], 'result_noundef': [], 'cc': 'portable'}]}
        two = deepcopy(one)
        two['types'] += [{'id': 2, 'kind': 'code_ptr', 'signature': ref(3)},
                         {'id': 3, 'kind': 'function', 'params': [ref(0)], 'results': [], 'variadic': False,
                          'param_noundef': [False], 'result_noundef': [], 'cc': 'portable'}]
        two['types'][1]['params'] = [ref(2)]
        self.assertEqual(Types(one).digest(ref(0)), Types(two).digest(ref(0)))
        two['types'][3]['param_noundef'] = [True]
        self.assertNotEqual(Types(one).digest(ref(0)), Types(two).digest(ref(0)))

    def test_exact_common_primitives(self):
        for kind, value, raw in [('u8', 255, 'ff'), ('i16', -32768, '0080'), ('bool', True, '01'),
                                 ('digest32', 'ab' * 32, 'ab' * 32), ('utf8', '\u03bb', '02000000cebb'),
                                 ('opt:opt:u32', {'some': None}, '0100'),
                                 ('opt:u32', {'some': 7}, '0107000000'), ('hex', 'abcd', '02000000abcd')]:
            self.assertEqual(encode(kind, value).hex(), raw)
            self.assertEqual(decode(kind, bytes.fromhex(raw)), value)
        self.assertEqual(decode('bytes', encode('bytes', b'\xff')), b'\xff')
        for kind, value in [('bool', 1), ('u32', True), ('opt:u32', 7), ('opt:u32', {'some': 7, 'extra': 1}),
                            ('digest32', 'AB' * 32), ('utf8', '\ud800'), ('bytes', 'aa')]:
            with self.assertRaises(Reject):
                encode(kind, value)
        for kind, raw in [('bool', b'\x02'), ('opt:u32', b'\x02'), ('utf8', bytes.fromhex('02000000c080'))]:
            with self.assertRaises(Reject):
                decode(kind, raw)

    def test_three_roots_roundtrip_and_admission(self):
        roots = fixture()
        for kind, root in zip(['execution_types', 'execution_functions', 'execution_exceptions'], roots):
            payload = encode(kind, root)
            self.assertEqual(decode(kind, payload), root)
            for end in range(len(payload)):
                with self.assertRaises(Reject):
                    decode(kind, payload[:end])
        admitted = verify(*roots)
        self.assertEqual(admitted.functions_root, roots[1])

    def test_wrong_edge_invoke_results_and_regions(self):
        types, functions, exceptions = fixture()
        function = functions['functions'][0]
        function['blocks'] = [
            block(0, [], {'op': 'invoke', 'target': {'kind': 'direct', 'function': ref(1), 'signature': ref(15)},
                          'operands': [], 'normal': {'target': 1, 'results': [decl(0, 2)]},
                          'unwind': {'target': 2, 'exception': decl(1, 10)}, 'region': 0}),
            block(1, [], {'op': 'return', 'values': [0]}),
            block(2, [constant(2, 2, '00000000')], {'op': 'return', 'values': [2]})]
        callee = deepcopy(fixture()[1]['functions'][0]); callee['id'] = 1
        functions['functions'].append(callee)
        exceptions['functions'] = [{'function': 0, 'actions': [], 'regions': [
            {'id': 0, 'parent': None, 'blocks': [0], 'exit_actions': [], 'handlers': [], 'escape': 'continue'}]}]
        verify(types, functions, exceptions)
        function['blocks'][2]['term']['values'] = [0]
        with self.assertRaises(Reject) as error:
            verify(types, functions, exceptions)
        self.assertEqual(error.exception.code, 'ssa_dominance')
        function['blocks'][2]['term']['values'] = [2]
        exceptions['functions'][0]['regions'][0]['parent'] = {'some': 0}
        with self.assertRaises(Reject) as error:
            verify(types, functions, exceptions)
        self.assertEqual(error.exception.code, 'region_cycle')


if __name__ == '__main__':
    unittest.main()
