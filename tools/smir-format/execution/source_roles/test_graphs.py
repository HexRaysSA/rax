"""Actual ABI/execution graph checks of independent source-role declarations."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from sem_fixtures import (base, builtin_state, atomic_flag, reference_cell,
                          seal_declared_abi, nominal, geometry, append_nominals, STATE, WRAPPER)
from candidate.context import RootContext
from candidate.type_system import ref
from candidate_fixtures import canonical_helper_source

ROOT = Path(__file__).resolve().parents[4]


def decoded_case(name):
    sys.path.insert(0, str(ROOT / 'tools/smir-format'))
    from codec import CandidateCodec
    spec = ROOT / 'docs/specifications/smir/portable'
    codec = CandidateCodec({owner: json.loads((spec / f'schema/{owner}/candidate.json').read_text())
                            for owner in ['execution', 'runtime', 'abi']})
    manifest = json.loads((spec / 'conformance/execution/candidate/source-roles/cases.json').read_text())
    case = next(c for c in manifest['cases'] if c['name'] == name)
    context = RootContext(codec.decode(bytes.fromhex(case['encoded_hex'])).roots)
    context.verify_abi()
    return context


def admit(roots):
    context = RootContext(roots)
    context.verify_abi()
    context.verify_execution()
    return context


class SourceGraphTests(unittest.TestCase):
    def test_known_wrong_kind_precedes_absent_source_geometry(self):
        context = decoded_case('atomic_flag_test-int32')
        with patch.object(context, 'source_layout', None):
            with self.assertRaisesRegex(Exception, 'RT_HELPER_SOURCE_ROLE'):
                context.verify_execution()

    def test_missing_actual_callbacks_never_supply_source_evidence(self):
        context = decoded_case('atomic_flag_test-flag')
        with patch.object(context, 'source_layout', None):
            with self.assertRaisesRegex(Exception, 'RT_HELPER_SOURCE_EVIDENCE_UNAVAILABLE'):
                context.verify_execution()
        context = decoded_case('tls_address-whole-object')
        with patch.object(context, 'source_compatible', None):
            with self.assertRaisesRegex(Exception, 'RT_HELPER_SOURCE_EVIDENCE_UNAVAILABLE'):
                context.verify_execution()

    def test_independent_graphs_match_released_abi_builder_after_real_seal(self):
        for family in ['va', 'jmp']:
            with self.subTest(family=family):
                independent = base()
                selected = builtin_state(independent, family)
                producer = base()
                # Explicit actual portable domain selection; no implicit domain0.
                for sections in [independent, producer]:
                    sections[10]['domains'][0]['id'] = 19
                    for typ in sections[10]['types']:
                        typ['domain'] = 19
                    sections[10] = seal_declared_abi(sections[10])
                produced = canonical_helper_source(producer, family)
                a, b = admit(independent), admit(producer)
                self.assertNotEqual(selected, produced)
                self.assertEqual(a.abi_graph.fingerprint(selected), b.abi_graph.fingerprint(produced))
                self.assertEqual((a.source_layout(selected)['size'], a.source_layout(selected)['align']), (32, 8))
                self.assertEqual((b.source_layout(produced)['size'], b.source_layout(produced)['align']), (32, 8))

    def test_source_callbacks_resolve_dependency_expectations_before_private_ids(self):
        roots = base()
        cell = reference_cell(roots, incomplete=True)
        roots[2]['manifest']['dependencies'] = [{'slot': 0,
            'key': {'namespace': 'example', 'name': 'source-provider', 'abi_major': 1, 'abi_minor': 0},
            'minimum_minor': 0, 'maximum_minor': None, 'site': roots[10]['identity'],
            'declarations': [{'id': 1, 'kind': 'nominal', 'symbol_kind': 'none',
                'source_linkage': 'none', 'namespace': 'example', 'name': 'reference',
                'execution': None, 'nominal': {'some': cell}, 'abi_signature': None, 'weak': False}]}]
        context = admit(roots)
        self.assertEqual(context.source_layout(ref(1))['size'], 4)
        self.assertEqual(context.source_layout(ref(1, 0))['size'], 8)
        self.assertTrue(context.source_compatible(ref(1, 0), cell))
        self.assertFalse(context.source_compatible(ref(1, 0), ref(1)))
        result = context.source_layout(ref(1, 0))
        result['size'] = 1
        self.assertEqual(context.source_layout(ref(1, 0))['size'], 8)
        self.assertTrue(context.component_result()['requires_runtime_link_admission'])
        with self.assertRaisesRegex(Exception, 'abi_namespace_reference'):
            context.source_layout(ref(999, 0))

    def test_source_callbacks_ignore_only_root_cv(self):
        roots = base()
        const = deepcopy(roots[10]['types'][0])
        const.update(id=3020, qualifiers=['const'], layout={'some': 3020})
        const_layout = deepcopy(roots[10]['layouts'][0])
        const_layout.update(id=3020, type=ref(3020))
        plain_pointer = nominal(3021, 'pointer', 'pointer', 4, bits=64, elements=[ref(1)])
        const_pointer = nominal(3022, 'pointer', 'pointer', 4, bits=64, elements=[ref(3020)])
        references = [nominal(identifier, 'reference', 'reference', 4, bits=64,
            elements=[ref(1)], flags=sorted(['complete', 'trivial_copy', 'trivial_destroy', category]))
            for identifier, category in [(3023, 'lvalue_ref'), (3024, 'rvalue_ref')]]
        append_nominals(roots, [const, plain_pointer, const_pointer, *references],
                        [const_layout, *[geometry(i, 8, 8) for i in range(3021, 3025)]])
        context = admit(roots)
        self.assertTrue(context.source_compatible(ref(1), ref(3020)))
        self.assertFalse(context.abi_graph.compatible(ref(1), ref(3020)))
        self.assertFalse(context.source_compatible(ref(3021), ref(3022)))
        self.assertFalse(context.source_compatible(ref(3023), ref(3024)))

    def test_source_callbacks_recheck_actual_abi_stage_and_snapshot(self):
        roots = base()
        context = RootContext(roots)
        with self.assertRaisesRegex(Exception, 'abi_before_execution_binding'):
            context.source_layout(ref(1))
        context.verify_abi()
        self.assertEqual(context.source_layout(ref(1))['size'], 4)
        context.sections[10]['types'][0]['qualifiers'] = ['const']
        with self.assertRaisesRegex(Exception, 'context_snapshot_changed'):
            context.source_layout(ref(1))
        with self.assertRaisesRegex(Exception, 'context_snapshot_changed'):
            context.source_compatible(ref(1), ref(1))

    def test_exact_graphs_reach_real_abi_and_execution_references(self):
        for name, build in [
            ('va', lambda r: builtin_state(r, 'va')),
            ('jmp', lambda r: builtin_state(r, 'jmp')),
            ('flag', atomic_flag), ('reference', reference_cell),
            ('reference-incomplete', lambda r: reference_cell(r, incomplete=True))]:
            with self.subTest(name=name):
                roots = base()
                build(roots)
                context = admit(roots)
                self.assertTrue(context.abi_checked)
                self.assertIsNotNone(context.execution_checked)
                self.assertEqual(context.component_result()['kind'], 'verified_execution_declarations')

    def test_unsealed_source_fragments_are_not_admitted(self):
        roots = base()
        builtin_state(roots, 'va')
        next(t for t in roots[10]['types'] if t['id'] == STATE)['identity']['definition'] = '0' * 64
        with self.assertRaisesRegex(Exception, 'ABI_CC_DEFINITION_HASH'):
            RootContext(roots).verify_abi()

    def test_nominal_layout_and_execution_ids_are_independent_namespaces(self):
        roots = base()
        builtin_state(roots, 'jmp')
        admit(roots)
        old = {t['id']: t['identity']['definition'] for t in roots[10]['types']}
        renamed = deepcopy(roots)
        source_ids = {i: i + 10000 for i in range(3000, 3004)}
        layout_ids = {i: i + 20000 for i in range(3000, 3004)}
        execution_ids = {4000: 14000, 4001: 14001}
        def rename(reference, mapping):
            self.assertEqual(reference['module']['kind'], 'self')
            reference['id'] = mapping.get(reference['id'], reference['id'])
        for typ in renamed[10]['types']:
            typ['id'] = source_ids.get(typ['id'], typ['id'])
            if typ['layout'] is not None:
                typ['layout']['some'] = layout_ids.get(typ['layout']['some'], typ['layout']['some'])
            if typ['execution'] is not None:
                rename(typ['execution']['some'], execution_ids)
            for child in typ['elements']:
                rename(child, source_ids)
            if typ['record_input'] is not None:
                for field in typ['record_input']['some']['fields']:
                    rename(field['type'], source_ids)
        for layout in renamed[10]['layouts']:
            layout['id'] = layout_ids.get(layout['id'], layout['id'])
            rename(layout['type'], source_ids)
            for field in layout['fields']:
                rename(field['type'], source_ids)
        for typ in renamed[1]['types']:
            typ['id'] = execution_ids.get(typ['id'], typ['id'])
            if typ['kind'] == 'array':
                rename(typ['element'], execution_ids)
        renamed[1]['types'].sort(key=lambda t: t['id'])
        renamed[10]['types'].sort(key=lambda t: t['id'])
        renamed[10]['layouts'].sort(key=lambda t: t['id'])
        renamed[10] = seal_declared_abi(renamed[10])
        admit(renamed)
        for original, actual in source_ids.items():
            self.assertEqual(old[original], next(t for t in renamed[10]['types'] if t['id'] == actual)['identity']['definition'])
        self.assertNotEqual(renamed[10]['types'], roots[10]['types'])

    def test_reference_cell_allocation_is_not_referent_or_guard_identity(self):
        roots = base()
        selected = reference_cell(roots)
        context = admit(roots)
        cell = context.abi_graph.layout(selected)
        referred = context.abi_graph.layout({'module': {'kind': 'self'}, 'id': 1})
        self.assertEqual((cell['size'], cell['align']), (8, 8))
        self.assertEqual((referred['size'], referred['align']), (4, 4))
        self.assertFalse(context.abi_graph.compatible(selected, {'module': {'kind': 'self'}, 'id': 1}))
        # Equal guard8B geometry has no static address-to-variable authority.


if __name__ == '__main__':
    unittest.main()
