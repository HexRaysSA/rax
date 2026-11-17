"""Actual data/TLS/relocation/ABI physical-vs-logical join, no fake Dependencies."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.raw import Raw
from candidate.type_system import ref
from candidate.values import Value
from test_candidate import block, constant, decl, operation
from test_candidate_context import roots
from candidate_fixtures import declared_abi_source, seal_declared_abi


def storage_wrapper():
    candidate = roots()
    actual_abi, _ = declared_abi_source()
    # Real source int* nominal/layout, whose pointee int is already present.
    candidate[10]['types'].append(deepcopy(next(item for item in actual_abi['types'] if item['id'] == 4)))
    pointer_type = candidate[10]['types'][-1]
    pointer_type['elements'] = [ref(1)]  # int*, rather than the source fixture's Value*.
    candidate[10]['types'].sort(key=lambda item: item['id'])
    candidate[10]['layouts'].append(deepcopy(next(item for item in actual_abi['layouts'] if item['id'] == 4)))
    candidate[10]['layouts'].sort(key=lambda item: item['id'])
    # Hash the explicit declaration graph; admission occurs in the real tests.
    candidate[10] = seal_declared_abi(candidate[10])
    helper = runtime_package_module('helpers')
    candidate[1]['types'] += [
        {'id': 201, 'kind': 'function', 'params': [ref(5)], 'results': [ref(4)],
         'variadic': False, 'param_noundef': [False], 'result_noundef': [False], 'cc': 'portable'},
        {'id': 300, 'kind': 'int', 'bits': 1},
        {'id': 304, 'kind': 'array', 'element': ref(9), 'count': 4},
        {'id': 305, 'kind': 'array', 'element': ref(9), 'count': 8}]
    candidate[1]['memory_layouts'] += [
        {'id': 5, 'type': ref(9), 'size': 1, 'access_bytes': 1, 'alignment': 1, 'fields': [], 'element': None, 'stride': 0},
        {'id': 6, 'type': ref(304), 'size': 4, 'access_bytes': 4, 'alignment': 1, 'fields': [], 'element': {'some': ref(5)}, 'stride': 8},
        {'id': 7, 'type': ref(4), 'size': 8, 'access_bytes': 8, 'alignment': 8, 'fields': [], 'element': None, 'stride': 0},
        {'id': 8, 'type': ref(305), 'size': 8, 'access_bytes': 8, 'alignment': 1, 'fields': [], 'element': {'some': ref(5)}, 'stride': 8}]
    def binding(identifier, nominal, layout, size, align, allocation=False):
        return {'id': identifier, 'nominal': ref(nominal), 'execution_layout': ref(layout),
                'kind': 'allocation' if allocation else 'object_bytes', 'view_offset_bits': 0,
                'view_width_bits': 8 * size, 'required_alignment': align, 'access_bytes': size,
                'fragments': [{'source_path': [], 'source_offset_bits': 0, 'execution_offset_bits': 0,
                               'width_bits': 8 * size, 'role': 'object_representation' if allocation else 'value'}]}
    candidate[10]['storage_bindings'] = [binding(0, 1, 6, 4, 4, True), binding(1, 1, 0, 4, 4),
                                        binding(2, 4, 8, 8, 8, True), binding(3, 4, 7, 8, 8)]
    def segment(identifier, layout, nominal, association, initial, alignment):
        return {'id': identifier, 'layout': {'some': ref(layout)}, 'nominal': {'some': ref(nominal)},
                'abi_binding': {'some': ref(association)}, 'alignment': alignment, 'mutable': True,
                'initial': initial, 'poison': '00' * (len(initial) // 2), 'undef': '00' * (len(initial) // 2),
                'zero_fill': 0, 'zero_shadow': 'defined'}
    candidate[4]['segments'] = [segment(0, 6, 1, 0, '07000000', 4), segment(1, 8, 4, 2, '00' * 8, 8)]
    candidate[7] = {'payload_revision': 1, 'segments': [{'storage': segment(0, 6, 1, 0, '08000000', 4),
                    'initializers': [], 'destructors': [], 'initialization': 'static'}]}
    def symbol(identifier, name, kind, execution, nominal, source, size, alignment):
        return {'id': identifier, 'namespace': 'example', 'name': name, 'kind': kind, 'source_linkage': 'c',
                'binding': 'strong', 'visibility': 'default', 'execution': ref(execution), 'nominal': {'some': ref(nominal)},
                'abi_signature': None,
                'definition': {'some': {'kind': source[0], 'segment': source[1]}}, 'size': {'some': size},
                'alignment': alignment, 'comdat': None, 'fallback': None}
    candidate[2]['symbols'] += [symbol(1, 'global_value', 'data', 304, 1, ('data', 0), 4, 4),
        symbol(2, 'global_pointer', 'data', 305, 4, ('data', 1), 8, 8),
        symbol(3, 'tls_value', 'tls', 304, 1, ('tls', 0), 4, 4)]
    candidate[5] = {'payload_revision': 2, 'relocations': [{'source_kind': 'data', 'source': 1,
        'offset': 0, 'width': 8, 'integer_bits': 0, 'kind': 'data_address', 'target': ref(1), 'addend': 0,
        'derivation': [], 'check_base': False, 'flags': [], 'inrange': None}], 'constant_initializers': []}
    candidate[6]['imports'] = [{'id': 0, 'kind': 'internal', 'namespace': 'smir.internal.v1', 'name': 'tls_address_raw',
        'version': 1, 'catalog': helper.digest(), 'signature': ref(201), 'abi': None, 'types': [], 'contract': 'default',
        'options': {**deepcopy(helper.DEFAULT_OPTIONS), 'target': {'some': ref(0)}}}]
    candidate[9] = {'payload_revision': 1, 'capabilities': ['memory'], 'requirements': [], 'limits': []}
    mode = {'alignment': 4, 'volatile': False, 'order': 'none', 'failure_order': 'none', 'scope': 'process', 'elementwise': False}
    def view(typ, layout, nominal, association, size):
        return {'type': ref(typ), 'layout': ref(layout), 'nominal': {'some': ref(nominal)},
                'abi_binding': {'some': ref(association)}, 'bytes': size}
    function = candidate[3]['functions'][0]
    function['blocks'] = [block(0, [
        operation('address_of', [decl(1, 4)], symbol=ref(2)),
        operation('load', [decl(2, 4)], [1], storage=view(4, 7, 4, 3, 8), mode={**mode, 'alignment': 8}),
        operation('load', [decl(3, 17)], [2], storage=view(17, 0, 1, 1, 4), mode=mode),
        constant(4, 5, '0000000000000000'),
        operation('call', [decl(5, 4)], [4], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind'),
        operation('load', [decl(6, 17)], [5], storage=view(17, 0, 1, 1, 4), mode=mode),
        operation('i_add', [decl(7, 17)], [0, 3], flags=[]), operation('i_add', [decl(8, 17)], [7, 6], flags=[])],
        {'op': 'return', 'values': [8]})]
    return candidate


def reference_image(context):
    """Sequential fixture loader, not production container/parallel runtime.

    Uses actual admitted segment/relocation records; data-address patches retain
    pointer bits AND shadow. Logical TLS slot is reserved before any guest call.
    """
    tls_pointers, data_pointers = {}, {}
    def lookup(machine, arguments):
        pointer = machine.memory.offset(tls_pointers[0], arguments[0].data, False, False, False)
        return [Value(ref(4), 'concrete', pointer)]
    machine = Machine(context.execution_checked, imports={('self', 0): lookup})
    def reserve(segment):
        initial = bytes.fromhex(segment['initial']) + bytes(segment['zero_fill'])
        pointer = machine.memory.allocate(len(initial), segment['alignment'])
        if initial:
            machine.memory.raw_store(pointer, Raw.integer(8 * len(initial), int.from_bytes(initial, 'little')))
        return pointer
    for segment in context.sections[4]['segments']:
        data_pointers[segment['id']] = reserve(segment)
    for wrapper in context.sections[7]['segments']:
        tls_pointers[wrapper['storage']['id']] = reserve(wrapper['storage'])
    for identifier, symbol in context.symbols.items():
        definition = symbol['definition']['some']
        if definition['kind'] in {'data', 'tls'}:
            machine.symbols[identifier] = (data_pointers if definition['kind'] == 'data' else tls_pointers)[definition['segment']]
    for relocation in context.sections[5]['relocations']:
        if (relocation['kind'] != 'data_address' or relocation['source_kind'] != 'data' or relocation['addend'] != 0 or relocation['integer_bits'] != 0 or relocation['derivation']
                or relocation['check_base'] or relocation['flags'] or relocation['inrange'] is not None):
            raise ValueError('This focused loader covers only its declared data_address fixture')
        source = data_pointers[relocation['source']]
        destination = machine.memory.offset(source, relocation['offset'], False, False, False)
        target = machine.symbols[('self', relocation['target']['id'])]
        machine.memory.raw_store(destination, Raw.pointer(target))
    for segment in context.sections[4]['segments']:
        machine.memory.objects[data_pointers[segment['id']].origin]['mutable'] = segment['mutable']
    for wrapper in context.sections[7]['segments']:
        segment = wrapper['storage']
        machine.memory.objects[tls_pointers[segment['id']].origin]['mutable'] = segment['mutable']
    return machine


class CandidateStorageJoinTests(unittest.TestCase):
    def test_readonly_segment_sealed_after_relocation_rejects_store_before_mutation(self):
        candidate = storage_wrapper()
        candidate[4]['segments'][0]['mutable'] = False
        ops = candidate[3]['functions'][0]['blocks'][0]['ops']
        ops[2:2] = [constant(9, 17, '2a000000'), operation('store', [], [2, 9],
            storage=deepcopy(ops[2]['storage']), mode=deepcopy(ops[2]['mode']))]
        context = RootContext(candidate)
        context.verify_abi()
        context.verify_execution()
        machine = reference_image(context)
        machine.start(0, [Value(ref(17), 'concrete', 27)])
        outcome = machine.run()
        self.assertEqual((outcome['kind'], outcome['reason'], outcome['operation']), ('trap', 'memory_permission', 3))
        pointer = machine.symbols[('self', 1)]
        self.assertEqual(machine.memory.raw_load(pointer, 4).bits, 7)
        self.assertFalse(any(event[0] == 'store' for event in machine.memory.effects))

    def test_actual_roots_storage_tls_relocation_and_logical_loads(self):
        context = RootContext(storage_wrapper())
        context.verify_abi()
        context.verify_execution()
        machine = reference_image(context)
        machine.start(0, [Value(ref(17), 'concrete', 27)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        self.assertEqual(context.target_entity('tls', ref(0))['storage']['initial'], '08000000')
        self.assertNotIn(('self', 0), context.abi_masks)  # Allocation is not value-mask authority.

    def test_wrong_source_physical_binding_rejects(self):
        candidate = storage_wrapper()
        candidate[10]['storage_bindings'][3]['execution_layout'] = ref(6)  # B4 cannot hold source pointer8B.
        with self.assertRaisesRegex(Exception, 'ABI_CC_STORAGE'):
            RootContext(candidate).verify_abi()
        candidate = storage_wrapper()
        candidate[3]['functions'][0]['blocks'][0]['ops'][1]['storage']['abi_binding'] = {'some': ref(1)}
        context = RootContext(candidate)
        context.verify_abi()
        with self.assertRaisesRegex(Reject, 'storage_binding_match'):
            context.verify_execution()

    def test_allocation_is_not_source_value_access_or_comparison_mask(self):
        candidate = storage_wrapper()
        binding = deepcopy(candidate[10]['storage_bindings'][0])
        binding.update(id=4, execution_layout=ref(0))  # Same i32 physical shape, still allocation-only.
        candidate[10]['storage_bindings'].append(binding)
        candidate[3]['functions'][0]['blocks'][0]['ops'][2]['storage']['abi_binding'] = {'some': ref(4)}
        context = RootContext(candidate)
        context.verify_abi()
        self.assertNotIn(('self', 4), context.abi_masks)
        with self.assertRaisesRegex(Reject, 'storage_allocation_not_value'):
            context.verify_execution()


if __name__ == '__main__':
    unittest.main()
