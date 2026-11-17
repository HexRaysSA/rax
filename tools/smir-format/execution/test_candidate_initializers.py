"""Restricted initializer evaluator against actual ABI/runtime/execution roots."""
from copy import deepcopy
from dataclasses import replace
import unittest
from unittest.mock import patch

from common import Reject
from candidate.context import RootContext
from candidate import pure
from candidate.initializers import evaluate_initializer
from candidate.memory import GuestFault
from candidate.raw import concat
from candidate.type_system import ref
from candidate.values import Pointer, Value
from test_candidate import block, constant, decl, operation
from test_candidate_memory import scalar
from test_candidate_storage_join import reference_image, storage_wrapper


def initializer_roots(operations=None, result_type=5, layout=9, extra_types=(), extra_layouts=()):
    roots = storage_wrapper()
    roots[1]['types'] += list(extra_types) + [{'id': 601, 'kind': 'function', 'cc': 'portable', 'variadic': False,
        'params': [], 'results': [ref(result_type)], 'param_noundef': [], 'result_noundef': [False]}]
    roots[1]['types'].sort(key=lambda item: item['id'])
    roots[1]['memory_layouts'] += [scalar(9, 5, 8, alignment=8)] + list(extra_layouts)
    roots[1]['memory_layouts'].sort(key=lambda item: item['id'])
    if operations is None:
        operations = [operation('address_of', [decl(0, 4)], symbol=ref(1)),
            operation('ptrtoint', [decl(1, 5)], [0]),
            operation('address_of', [decl(2, 4)], symbol=ref(2)),
            operation('ptrtoint', [decl(3, 5)], [2]),
            operation('i_sub', [decl(4, 5)], [3, 1], flags=[])]
    roots[3]['functions'].append({'id': 7, 'signature': ref(601), 'abi_signature': None, 'params': [],
        'entry': 0, 'escape': 'propagate', 'no_return': False,
        'blocks': [block(0, operations, {'op': 'return', 'values': [operations[-1]['results'][0]['id']]})]})
    return roots


def initializer_context(operations=None, result_type=5, layout=9, extra_types=(), extra_layouts=()):
    roots = initializer_roots(operations, result_type, layout, extra_types, extra_layouts)
    context = RootContext(roots)
    context.verify_abi()
    context.verify_execution()
    return context, reference_image(context), ref(layout)


def evaluate(context, machine, layout, **changes):
    options = {'memory': machine.memory, 'symbols': machine.symbols,
               'code_pointers': machine.code_pointers, 'exposed_code': machine.exposed_code}
    options.update(changes)
    return evaluate_initializer(context, ref(7), layout, **options)


class CandidateInitializerTests(unittest.TestCase):
    def test_multibase_difference_and_private_exposure_do_not_mutate_input(self):
        context, machine, layout = initializer_context()
        before = deepcopy(machine.memory.objects)
        result = evaluate(context, machine, layout)
        expected = machine.symbols[('self', 2)].address - machine.symbols[('self', 1)].address
        self.assertEqual((result.value.data, concat(list(result.bytes)).bits), (expected, expected))
        self.assertEqual(result.data_exposed, frozenset(machine.symbols[('self', i)].origin for i in [1, 2]))
        self.assertEqual(result.code_exposed, frozenset())
        self.assertEqual(machine.memory.exposed, set())
        self.assertEqual(machine.memory.objects, before)

    def test_ptrtoaddr_no_exposure_and_numeric_roundtrip_no_authority(self):
        for conversion in ['ptrtoaddr', 'ptrtoint']:
            with self.subTest(conversion=conversion):
                operations = [operation('address_of', [decl(0, 4)], symbol=ref(1)),
                    operation(conversion, [decl(1, 5)], [0]), operation('inttoptr', [decl(2, 4)], [1])]
                context, machine, layout = initializer_context(operations, 4, 7)
                result = evaluate(context, machine, layout)
                pointer = machine.symbols[('self', 1)]
                self.assertEqual(result.value.data.address, pointer.address)
                self.assertEqual(result.value.data.origin, pointer.origin if conversion == 'ptrtoint' else None)
                self.assertEqual(bool(result.data_exposed), conversion == 'ptrtoint')
                self.assertEqual(machine.memory.exposed, set())

    def test_registered_code_token_exposure_separate_from_data(self):
        for conversion in ['ptrtoaddr', 'ptrtoint']:
            operations = [operation('address_of', [decl(0, 600)], symbol=ref(0)),
                          operation(conversion, [decl(1, 5)], [0])]
            context, machine, layout = initializer_context(operations, extra_types=[
                {'id': 600, 'kind': 'code_ptr', 'signature': ref(12)}])
            pointer = machine.register_function(ref(0), ref(0), ref(12))
            result = evaluate(context, machine, layout)
            self.assertEqual(result.value.data, pointer.address)
            self.assertEqual(result.data_exposed, frozenset())
            self.assertEqual(result.code_exposed, frozenset({pointer.address}) if conversion == 'ptrtoint' else frozenset())
            self.assertEqual(machine.exposed_code, set())
            with self.assertRaisesRegex(Reject, 'initializer_code_reservation'):
                evaluate(context, machine, layout, code_pointers={})

    def test_numeric_or_stale_code_token_cannot_expose_registered_authority(self):
        context, machine, layout = initializer_context(extra_types=[
            {'id': 600, 'kind': 'code_ptr', 'signature': ref(12)}])
        registered = machine.register_function(ref(0), ref(0), ref(12))
        for pointer in [Pointer(registered.address, domain='code'),
                        replace(registered, generation=999), Pointer(0, domain='code')]:
            numeric = pure.execute(machine, operation('ptrtoint', [decl(0, 5)], [0]),
                                   [Value(ref(600), 'concrete', pointer)])[0]
            roundtrip = pure.execute(machine, operation('inttoptr', [decl(1, 600)], [0]), [numeric])[0]
            self.assertIsNone(roundtrip.data.origin)
            self.assertEqual(machine.exposed_code, set())
        numeric = pure.execute(machine, operation('ptrtoint', [decl(0, 5)], [0]),
                               [Value(ref(600), 'concrete', registered)])[0]
        self.assertEqual(machine.exposed_code, {registered.address})
        self.assertEqual(pure.execute(machine, operation('inttoptr', [decl(1, 600)], [0]), [numeric])[0].data,
                         registered)

    def test_vector_shuffle_and_pointer_origin_serialization(self):
        types = [{'id': 600, 'kind': 'vector', 'element': ref(4), 'count': 2}]
        layouts = [{'id': 10, 'type': ref(600), 'size': 16, 'access_bytes': 16, 'alignment': 8,
                    'fields': [], 'element': {'some': ref(7)}, 'stride': 64}]
        operations = [operation('constant', [decl(0, 600)], literal={'kind': 'poison'}),
            operation('address_of', [decl(1, 4)], symbol=ref(1)), constant(2, 5, '0000000000000000'),
            operation('insert_element', [decl(3, 600)], [0, 1, 2]),
            operation('shuffle', [decl(4, 600)], [3, 3], mask=[{'some': 0}, {'some': 0}])]
        context, machine, layout = initializer_context(operations, 600, 10, types, layouts)
        result = evaluate(context, machine, layout)
        self.assertEqual(len(result.bytes), 16)
        for offset in [0, 8]:
            self.assertEqual(concat(list(result.bytes[offset:offset+8])).as_pointer()['identity'],
                             machine.symbols[('self', 1)].origin)

    def test_poison_shadow_nonbyte_integer_and_alignment_tail(self):
        context, machine, layout = initializer_context(
            [operation('constant', [decl(0, 10)], literal={'kind': 'poison'})], 10, 2)
        result = evaluate(context, machine, layout)
        self.assertEqual((len(result.bytes), concat(list(result.bytes)).poison), (9, (1 << 65) - 1))
        self.assertEqual(context.layouts.items[('self', 2)]['size'], 16)  # Seven tail bytes untouched by caller patch.

    def test_rejections_no_calls_loads_wrong_signature_or_layout(self):
        context, machine, layout = initializer_context()
        with self.assertRaisesRegex(Reject, 'initializer_resource_operations'):
            evaluate(context, machine, layout, max_operations=4)
        with self.assertRaisesRegex(Reject, 'initializer_layout_extent'):
            evaluate(context, machine, ref(0))
        stale = dict(machine.symbols)
        stale[('self', 1)] = replace(stale[('self', 1)], generation=999)
        with self.assertRaisesRegex(Reject, 'initializer_object_reservation'):
            evaluate(context, machine, layout, symbols=stale)
        restricted = dict(machine.symbols)
        restricted[('self', 1)] = replace(restricted[('self', 1)], access_range=(0, 2**64))
        with self.assertRaises(GuestFault) as caught:
            evaluate(context, machine, layout, symbols=restricted)
        self.assertEqual(caught.exception.code, 'ub_inrange_address_conversion')
        fn = context.sections[3]['functions'][-1]
        fn['escape'] = 'terminate'
        changed = RootContext(context.sections)
        changed.verify_abi(); changed.verify_execution()
        with self.assertRaisesRegex(Reject, 'initializer_signature'):
            evaluate(changed, machine, layout)
        # Actual verifier admits this load; the restricted phase rejects it.
        operations = [operation('address_of', [decl(0, 4)], symbol=ref(1)),
            operation('load', [decl(1, 17)], [0], storage={'type': ref(17), 'layout': ref(0),
                'nominal': {'some': ref(1)}, 'abi_binding': {'some': ref(1)}, 'bytes': 4},
                mode={'alignment': 4, 'volatile': False, 'order': 'none', 'failure_order': 'none',
                      'scope': 'process', 'elementwise': False})]
        context, machine, layout = initializer_context(operations, 17, 0)
        with self.assertRaisesRegex(Reject, 'initializer_operation'):
            evaluate(context, machine, layout)

    def test_cumulative_working_budget_rejects_before_any_literal_expansion(self):
        context, machine, layout = initializer_context()
        with patch('candidate.initializers.pure.execute') as execute:
            with self.assertRaisesRegex(Reject, 'initializer_resource_values'):
                evaluate(context, machine, layout, max_bytes=50)
            execute.assert_not_called()
        for count, element in [(1000000000, 9), (100001, 600)]:
            # The second case has zero total bits but over 100000 present nodes.
            types = ([{'id': 600, 'kind': 'struct', 'fields': []}] if element == 600 else [])
            types += [{'id': 602, 'kind': 'array', 'element': ref(element), 'count': count}]
            ops = [operation('constant', [decl(0, 602)], literal={'kind': 'zero'}),
                   constant(1, 5, '0100000000000000')]
            context, machine, layout = initializer_context(ops, extra_types=types)
            with patch('candidate.initializers.pure.execute') as execute:
                with self.assertRaisesRegex(Reject, 'initializer_resource_(values|nodes)'):
                    evaluate(context, machine, layout)
                execute.assert_not_called()

    def test_well_typed_call_and_unused_opaque_value_reject_restricted_profile(self):
        ops = [constant(0, 5, '0000000000000000'), operation('call', [decl(1, 4)], [0],
            target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind')]
        context, machine, layout = initializer_context(ops, 4, 7)
        with self.assertRaisesRegex(Reject, 'initializer_operation'):
            evaluate(context, machine, layout)
        ops = [operation('constant', [decl(0, 7)], literal={'kind': 'undef'}),
               constant(1, 5, '0100000000000000')]
        context, machine, layout = initializer_context(ops)
        with self.assertRaisesRegex(Reject, 'initializer_opaque'):
            evaluate(context, machine, layout)
        roots = initializer_roots([constant(0, 5, '0100000000000000')])
        fn = roots[3]['functions'][-1]
        fn['blocks'][0]['term'] = {'op': 'jump', 'target': 1}
        fn['blocks'].append(block(1, [], {'op': 'return', 'values': [0]}))
        context = RootContext(roots)
        context.verify_abi(); context.verify_execution()
        with self.assertRaisesRegex(Reject, 'initializer_block'):
            evaluate(context, reference_image(context), ref(9))


if __name__ == '__main__':
    unittest.main()
