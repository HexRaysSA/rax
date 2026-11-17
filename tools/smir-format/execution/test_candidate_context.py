"""Joint actual execution/runtime/ABI roots; no injected nominal/shape callbacks."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from common import Reject, SPEC
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.type_system import ref
from candidate.values import Value
from test_candidate import block, decl

FIXTURE = SPEC / 'conformance/execution/candidate/portable-identity.json'


def roots():
    return {int(number): value for number, value in json.loads(FIXTURE.read_text())['sections'].items()}


def consumer_expectation_roots(*, scalar_alias=True):
    """Original current-tree DEP Fn12 counter plus a separate scalar alias."""
    document = roots()
    declarations = []
    targets = [(1, 12), (2, 1)] if scalar_alias else [(1, 12)]
    for identifier, target in targets:
        declarations.append({'id': identifier, 'kind': 'nominal', 'symbol_kind': 'none',
            'source_linkage': 'none', 'namespace': 'example',
            'name': 'expected_function' if identifier == 1 else 'expected_int',
            'execution': None, 'nominal': {'some': ref(target)}, 'abi_signature': None, 'weak': False})
    document[2]['manifest']['dependencies'] = [{'slot': 0,
        'key': {'namespace': 'example', 'name': 'provider', 'abi_major': 1, 'abi_minor': 0},
        'minimum_minor': 0, 'maximum_minor': None, 'site': document[10]['identity'],
        'declarations': declarations}]
    document[10]['signatures'][0]['function_type'] = ref(1, 0)
    return document


class CandidateContextTests(unittest.TestCase):
    def test_consumer_nominal_original_dep_plan_verifies_without_record_rewrite(self):
        document = consumer_expectation_roots(scalar_alias=False)
        original = deepcopy(document)
        context = RootContext(document)
        self.assertEqual(context.verify_abi()['signatures'], 1)
        self.assertEqual(context.sections, original)
        owner = context.abi_graph.module_id
        self.assertEqual(dict(context.abi_graph.nominal_expectations[owner]), {(0, 1): 12})
        self.assertEqual(context.abi_graph.resolve(ref(1, 0))[0], owner)
        self.assertEqual(context.abi_graph.resolve(ref(1, 0))[1]['id'], 12)
        self.assertEqual(context.sections[10]['signatures'][0]['function_type'], ref(1, 0))

    def test_consumer_nominal_postverify_callbacks_and_execution_deepcopy_agree(self):
        context = RootContext(consumer_expectation_roots())
        context.verify_abi()
        self.assertTrue(context.source_compatible(ref(1, 0), ref(12)))
        self.assertEqual(context.source_layout(ref(2, 0)), context.source_layout(ref(1)))
        copied = deepcopy(context.abi_graph)
        self.assertEqual(copied.resolve(ref(1, 0))[1]['id'], 12)
        self.assertEqual(copied.layout(ref(2, 0)), context.source_layout(ref(1)))
        machine = Machine(context.verify_execution())
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        self.assertEqual(machine.run()['values'][0].data, 42)

    def test_consumer_nominal_provider_collisions_cannot_override_local_expectations(self):
        document = consumer_expectation_roots()
        provider = deepcopy(document[10])
        next(t for t in provider['types'] if t['id'] == 12)['identity']['entity'] = 'provider.other_function'
        context = RootContext(document)
        owner = 'example:identity:1'
        bindings = {owner: {0: {'module': 'provider', 'types': {1: 1, 2: 12}}}}
        context.verify_abi(modules={'provider': provider}, bindings=bindings)
        self.assertEqual(context.abi_graph.resolve(ref(1, 0))[0], owner)
        self.assertEqual(context.abi_graph.resolve(ref(1, 0))[1]['id'], 12)
        self.assertEqual(context.abi_graph.resolve(ref(2, 0))[1]['id'], 1)
        self.assertEqual(context.source_layout(ref(2, 0)), context.source_layout(ref(1)))

    def test_consumer_nominal_missing_wrong_kind_or_slot_never_provider_fallback(self):
        for mutation in ['missing_expectation', 'wrong_kind', 'wrong_slot', 'wrong_id']:
            document = consumer_expectation_roots()
            if mutation == 'missing_expectation':
                document[2]['manifest']['dependencies'][0]['declarations'][0]['nominal'] = None
            elif mutation == 'wrong_kind':
                document[2]['manifest']['dependencies'][0]['declarations'][0]['kind'] = 'type'
            elif mutation == 'wrong_slot':
                document[10]['signatures'][0]['function_type'] = ref(1, 1)
            else:
                document[10]['signatures'][0]['function_type'] = ref(99, 0)
            context = RootContext(document)
            owner = 'example:identity:1'
            binding = {'module': 'provider', 'types': {1: 12, 99: 12}}
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'ABI_CC_UNBOUND_DECLARATION'):
                context.verify_abi(modules={'provider': roots()[10]}, bindings={owner: {0: binding, 1: binding}})
            self.assertFalse(context.abi_checked)
        document = consumer_expectation_roots()
        document[2]['manifest']['dependencies'][0]['declarations'][0]['nominal'] = {'some': ref(999)}
        with self.assertRaisesRegex(Reject, 'declaration_nominal'):
            RootContext(document)

    def test_consumer_nominal_empty_owner_is_strict_even_with_provider_binding(self):
        document = roots()
        document[10]['signatures'][0]['function_type'] = ref(1, 0)
        context = RootContext(document)
        with self.assertRaisesRegex(ValueError, 'ABI_CC_UNBOUND_DECLARATION'):
            context.verify_abi(modules={'provider': roots()[10]}, bindings={
                'example:identity:1': {0: {'module': 'provider', 'types': {1: 12}}}})
        self.assertFalse(context.abi_checked)

    def test_consumer_nominal_source_call_capture_preserves_original_dep_and_old_ledger(self):
        from candidate.source_data_projection import source_api
        context = RootContext(consumer_expectation_roots())
        context.verify_abi()
        def budget():
            return source_api().SourceQueryBudget(max_work=10**9, max_edges=10**9,
                max_copied_bytes=10**9, max_depth=128)
        old, current = budget(), budget()
        stamp = context.prepare_source_data(budget=old)
        counters = old._used_work, old._used_edges, old._used_copied_bytes
        view = context.source_call_context(budget=current)
        original = view.record('signature', ref(0), budget=current).record['function_type']
        self.assertEqual(original['module']['kind'], 'dependency')
        self.assertEqual((original['module']['slot'], original['id']), (0, 1))
        selected = view.record('nominal', original, budget=current)
        self.assertEqual(selected.local_reference['module']['kind'], 'self')
        self.assertEqual((selected.local_reference['id'], selected.record['id']), (12, 12))
        self.assertIs(context.source_stamp, stamp)
        self.assertEqual((old._used_work, old._used_edges, old._used_copied_bytes), counters)

    def test_capture_source_paths_use_canonical_names_and_actual_owner_graph(self):
        from candidate_fixtures import declared_abi_source, seal_declared_abi
        actual, _ = declared_abi_source()
        candidate = roots()
        candidate[10]['types'] += [deepcopy(t) for t in actual['types'] if t['id'] in (2, 3)]
        candidate[10]['types'].sort(key=lambda t: t['id'])
        candidate[10]['layouts'] += [deepcopy(t) for t in actual['layouts'] if t['id'] in (2, 3)]
        candidate[10]['layouts'].sort(key=lambda t: t['id'])
        record = next(t for t in candidate[10]['types'] if t['id'] == 3)
        layout = next(t for t in candidate[10]['layouts'] if t['id'] == 3)
        for index, (source, selected) in enumerate(zip(record['record_input']['some']['fields'], layout['fields'])):
            source['name'] = {'some': '$capture' + str(index)}
            selected['name'] = '$capture' + str(index)
        binding = deepcopy(next(b for b in actual['storage_bindings'] if b['id'] == 3))
        binding['fragments'][0]['source_path'] = ['$capture0']
        binding['fragments'][2]['source_path'] = ['$capture1']
        candidate[10]['storage_bindings'] = [binding]
        candidate[10] = seal_declared_abi(candidate[10])
        context = RootContext(candidate)
        context.verify_abi()
        context.verify_execution()
        definition = next(t for t in candidate[10]['types'] if t['id'] == 3)['identity']['definition']
        renamed = deepcopy(candidate)
        typ = next(t for t in renamed[10]['types'] if t['id'] == 3)
        typ['id'] = 500
        typ['layout'] = {'some': 500}
        geometry = next(t for t in renamed[10]['layouts'] if t['id'] == 3)
        geometry.update(id=500, type=ref(500))
        renamed[10]['storage_bindings'][0]['nominal'] = ref(500)
        renamed[10]['types'].sort(key=lambda t: t['id'])
        renamed[10]['layouts'].sort(key=lambda t: t['id'])
        renamed[10] = seal_declared_abi(renamed[10])
        self.assertEqual(next(t for t in renamed[10]['types'] if t['id'] == 500)['identity']['definition'], definition)
        RootContext(renamed).verify_abi()
        for name in ['$capture01', '$capture1', '$capture']:
            wrong = deepcopy(candidate)
            field = next(t for t in wrong[10]['types'] if t['id'] == 3)['record_input']['some']['fields'][0]
            field['name'] = {'some': name}
            wrong[10] = seal_declared_abi(wrong[10])
            with self.subTest(name=name), self.assertRaisesRegex(Exception, 'ABI_CC_CAPTURE_FIELD_NAME'):
                RootContext(wrong).verify_abi()
        for change in [{'anonymous': True}, {'bit_width': {'some': 8}}]:
            wrong = deepcopy(candidate)
            field = next(t for t in wrong[10]['types'] if t['id'] == 3)['record_input']['some']['fields'][0]
            field.update(change)
            wrong[10] = seal_declared_abi(wrong[10])
            with self.subTest(change=change), self.assertRaisesRegex(Exception, 'ABI_CC_CAPTURE_FIELD_NAME'):
                RootContext(wrong).verify_abi()
        changed = deepcopy(candidate)
        next(t for t in changed[10]['types'] if t['id'] == 3)['record_input']['some']['fields'][0]['name'] = {'some': 'renamed'}
        next(t for t in changed[10]['layouts'] if t['id'] == 3)['fields'][0]['name'] = 'renamed'
        changed[10] = seal_declared_abi(changed[10])
        self.assertNotEqual(next(t for t in changed[10]['types'] if t['id'] == 3)['identity']['definition'], definition)
        wrong = deepcopy(candidate)
        wrong[10]['storage_bindings'][0]['fragments'][0]['source_path'] = ['$capture0.part']
        with self.assertRaisesRegex(Exception, 'ABI_CC_STORAGE_SOURCE_PATH'):
            RootContext(wrong).verify_abi()
        # Generic name validity does not certify actual lambda AST origin.

    def test_nominal_domain_uses_actual_record_and_returns_isolated_copy(self):
        for identifier in [0, 1, 19, 65537, 0xfffffffe]:
            with self.subTest(domain=identifier):
                candidate = roots()
                candidate[10]['domains'][0]['id'] = identifier
                for nominal in candidate[10]['types']:
                    nominal['domain'] = identifier
                context = RootContext(candidate)
                context.verify_abi()
                expected = candidate[10]['domains'][0]
                for nominal in candidate[10]['types']:
                    result = context.abi_entity('nominal_domain', ref(nominal['id']))
                    self.assertEqual(result, expected)
                    result['isa'] = 'changed-copy'
                    self.assertEqual(context.abi_entity('nominal_domain', ref(nominal['id'])), expected)
                self.assertEqual(context.sections[10]['domains'][0], expected)

    def test_nominal_domain_preserves_expectation_namespace(self):
        # Resolver-only namespace probe: these roots do not certify a foreign ABI.
        candidate = roots()
        candidate[10]['domains'][0]['id'] = 19
        foreign = deepcopy(candidate[10]['domains'][0])
        foreign.update(id=0, isa='x86_64', abi='itanium', personality='linux')
        candidate[10]['domains'].insert(0, foreign)
        candidate[10]['types'][0]['domain'] = 0
        candidate[10]['types'][1]['domain'] = 19
        candidate[2]['manifest']['dependencies'] = [{'slot': 0,
            'key': {'namespace': 'example', 'name': 'provider', 'abi_major': 1, 'abi_minor': 0},
            'minimum_minor': 0, 'maximum_minor': None, 'site': candidate[10]['identity'],
            'declarations': [{'id': 1, 'kind': 'nominal', 'symbol_kind': 'none',
                'source_linkage': 'none', 'namespace': 'example', 'name': 'expected_function',
                'execution': None, 'nominal': {'some': ref(12)}, 'abi_signature': None, 'weak': False}]}]
        context = RootContext(candidate)
        self.assertEqual(context.abi_entity('nominal_domain', ref(1))['id'], 0)
        self.assertEqual(context.abi_entity('nominal_domain', ref(1, 0))['id'], 19)
        self.assertEqual(context.abi_entity('nominal_domain', ref(1, 0))['isa'], 'portable')
        for reference in [ref(999), ref(12, 0), ref(1, 1)]:
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(Reject, 'abi_namespace_reference'):
                    context.abi_entity('nominal_domain', reference)
        with self.assertRaisesRegex(Reject, 'abi_namespace_reference'):
            context.abi_entity('domain', ref(19))
        context.abi_entity('nominal_domain', ref(1, 0))['id'] = 999
        self.assertEqual(context.abi_entity('nominal_domain', ref(1, 0))['id'], 19)

    def test_nominal_domain_index_preserves_abi_domain_rejections(self):
        for change in ['duplicate', 'reserved']:
            with self.subTest(change=change):
                candidate = roots()
                if change == 'duplicate':
                    candidate[10]['domains'].append(deepcopy(candidate[10]['domains'][0]))
                else:
                    candidate[10]['domains'][0]['id'] = 0xffffffff
                    for nominal in candidate[10]['types']:
                        nominal['domain'] = 0xffffffff
                context = RootContext(candidate)
                with self.assertRaisesRegex(Exception, 'ABI_CC_DUPLICATE_DOMAINS'):
                    context.verify_abi()
        candidate = roots()
        candidate[10]['types'][0]['domain'] = 19
        with self.assertRaisesRegex(Reject, 'abi_namespace_reference'):
            RootContext(candidate).abi_entity('nominal_domain', ref(1))

    def test_actual_source_call_comparator_survives_temporary_import_path(self):
        context = RootContext(roots())
        before = list(__import__('sys').path)
        context.verify_abi()
        self.assertEqual(__import__('sys').path, before)
        self.assertTrue(context.abi_graph.signature_compatible(ref(0), ref(0)))
        self.assertFalse(context.abi_graph.signature_compatible(ref(0), ref(999)))

    def test_actual_roots_and_abi_lowered_signature(self):
        context = RootContext(roots())
        self.assertEqual(context.verify_abi()['signatures'], 1)
        machine = Machine(context.verify_execution())
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        result = context.component_result()
        self.assertTrue(result['requires_runtime_link_admission'])
        self.assertEqual(result['kind'], 'verified_execution_declarations')

    def test_producer_cannot_supply_binding_evidence(self):
        candidate = roots()
        candidate[10]['signatures'][0]['lowered_params'][0]['noundef'] = False
        with self.assertRaises(Exception) as caught:
            RootContext(candidate).verify_abi()
        self.assertIn('ABI_CC_CALL_PARAMETER', str(caught.exception))
        candidate = roots()
        candidate[3]['functions'][0]['abi_signature'] = {'some': ref(12)}
        context = RootContext(candidate)
        context.verify_abi()
        with self.assertRaises(Reject) as caught:
            context.verify_execution()
        self.assertIn('function_abi_signature', str(caught.exception))
        candidate = roots()
        candidate[3]['functions'][0]['abi_signature'] = {'some': ref(0, 0)}
        context = RootContext(candidate)
        context.verify_abi()
        with self.assertRaisesRegex(Reject, 'function_abi_signature_self'):
            context.verify_execution()

    def test_strict_shape_and_real_metadata(self):
        context = RootContext(roots())
        with self.assertRaises(Reject):
            context.verify_execution()
        with self.assertRaises(Reject):
            context.metadata(ref(0))  # Function symbol cannot certify data bytes.
        candidate = roots()
        candidate[10]['types'][0]['execution'] = {'some': ref(2)}  # i8, not source int.
        with self.assertRaises(Exception) as caught:
            RootContext(candidate).verify_abi()
        self.assertIn('TYPE_BINDING', str(caught.exception))

    def test_post_admission_root_mutation_invalidates_context(self):
        context = RootContext(roots())
        context.verify_abi()
        context.sections[10]['types'][0]['bits'] = 8
        with self.assertRaisesRegex(Reject, 'context_snapshot_changed'):
            context.verify_execution()

    def test_source_view_memory_effect_cannot_overrun_nominal_object(self):
        document = json.loads((SPEC / 'conformance/execution/candidate/reject-storage-effect.json').read_text())
        with self.assertRaisesRegex(Exception, 'ABI_CC_STORAGE_EFFECT_RANGE'):
            RootContext({int(number): value for number, value in document['sections'].items()}).verify_abi()

    def test_readonly_metadata_includes_defined_zero_tail(self):
        candidate = roots()
        symbol = deepcopy(candidate[2]['symbols'][0])
        candidate[1]['types'].append({'id': 304, 'kind': 'array', 'element': ref(9), 'count': 8})
        candidate[1]['memory_layouts'] += [
            {'id': 5, 'type': ref(9), 'size': 1, 'alignment': 1, 'access_bytes': 1, 'fields': [], 'element': None, 'stride': 0},
            {'id': 6, 'type': ref(304), 'size': 8, 'alignment': 1, 'access_bytes': 8,
             'fields': [], 'element': {'some': ref(5)}, 'stride': 8}]
        symbol.update(id=1, kind='data', execution=ref(304), nominal=None, abi_signature=None,
                      definition={'some': {'kind': 'data', 'segment': 0}}, size={'some': 8})
        if 'source_linkage' in symbol:
            symbol['source_linkage'] = 'none'
        candidate[2]['symbols'].append(symbol)
        segment = {'id': 0, 'layout': {'some': ref(6)}, 'nominal': None, 'alignment': 1, 'mutable': False,
                   'initial': 'aabbccdd', 'poison': '00000000', 'undef': '00000000',
                   'zero_fill': 4, 'zero_shadow': 'defined'}
        from candidate.context import records
        if any(name == 'abi_binding' for name, _ in records()['runtime_segment']['fields']):
            segment['abi_binding'] = None
        candidate[4]['segments'] = [segment]
        self.assertEqual(RootContext(candidate).metadata(ref(1)), bytes.fromhex('aabbccdd00000000'))
        segment['zero_shadow'] = 'undef'
        with self.assertRaisesRegex(Reject, 'metadata_initialized_readonly_bytes'):
            RootContext(candidate).metadata(ref(1))


if __name__ == '__main__':
    unittest.main()
