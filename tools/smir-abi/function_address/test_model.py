"""Actual ABI3 sections and genuine canonical views, never proof dictionaries."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from .fixtures import cases, dependency_plan, ordinary, seal, variadic
from .model import ordinary_address_call_compatible
from . import model

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
from candidate.context import RootContext, source_call_api
from candidate.source_data_projection import source_api
from nominal import NominalGraph, ref, some


def ledger(**changes):
    policy = dict(max_work=10**10, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    policy.update(changes)
    return source_api().SourceQueryBudget(**policy)


def checked(document):
    context = RootContext(document)
    context.verify_abi()
    return context


def pair(a, b, budget=None):
    budget = ledger() if budget is None else budget
    a, b = checked(a), checked(b)
    return a, b, a.source_call_context(budget=budget), b.source_call_context(budget=budget), budget


class OrdinaryAddressCallTests(unittest.TestCase):
    def compare(self, a, b, ar=None, br=None):
        _, _, av, bv, budget = pair(a, b)
        return ordinary_address_call_compatible(av, ar or ref(201), bv, br or ref(201), budget=budget)

    def test_authored_positive_and_mismatch_corpus(self):
        for group in ('ordinary', 'rejections'):
            for case in cases()[group]:
                with self.subTest(case=case['name']):
                    self.assertIs(self.compare(case['actual'], case['expected'], case['actual_plan'],
                                               case['expected_plan']), case['compatible'])

    def test_source_only_incomplete_byvalue_prototype_and_address_are_valid(self):
        context = checked(ordinary())
        function = next(t for t in context.sections[10]['types'] if t['id'] == 106)
        pointer = next(t for t in context.sections[10]['types'] if t['id'] == 107)
        self.assertIsNone(function['execution'])
        self.assertEqual(function['representation'], 'none')
        self.assertEqual(pointer['representation'], 'code_address')
        self.assertEqual(context.types.get(pointer['execution']['some'])['kind'], 'code_address')
        self.assertEqual(context.types.width(pointer['execution']['some']), 64)
        self.assertFalse(any(p['function_type'] == ref(106) for p in context.sections[10]['signatures']))

    def test_source_completion_preserves_expressions_but_changes_definitions(self):
        a, b = ordinary(), ordinary(complete_record=True)
        ag, bg = NominalGraph(a[10], 'a'), NominalGraph(b[10], 'b')
        for identifier in (102, 103, 104, 105, 106, 107):
            self.assertEqual(ag.fingerprint(ref(identifier)), bg.fingerprint(ref(identifier)))
        for identifier in (100, 101):
            self.assertNotEqual(ag.fingerprint(ref(identifier)), bg.fingerprint(ref(identifier)))

    def test_default_none_is_independent_of_mandatory_plan_execution(self):
        document = ordinary()
        next(t for t in document[10]['types'] if t['id'] == 105).update(execution=None, representation='none')
        self.assertTrue(self.compare(seal(document), ordinary()))

    def test_default_equivalent_execution_does_not_require_same_numeric_id(self):
        document = ordinary()
        extra = deepcopy(next(t for t in document[1]['types'] if t['id'] == 1001))
        extra['id'] = 1003
        document[1]['types'].append(extra)
        next(t for t in document[10]['types'] if t['id'] == 105)['execution'] = some(ref(1003))
        self.assertTrue(self.compare(seal(document), ordinary()))

    def test_default_requires_exact_source_key_not_equivalent_prototype(self):
        document = ordinary()
        clone = deepcopy(next(t for t in document[10]['types'] if t['id'] == 105))
        clone.update(id=108, execution=None, representation='none')
        document[10]['types'].append(clone)
        next(p for p in document[10]['signatures'] if p['id'] == 201)['function_type'] = ref(108)
        with self.assertRaisesRegex(ValueError, 'ABI_CC_FUNCTION_DEFAULT'):
            checked(seal(document))

    def test_absent_and_wrong_default_are_errors_without_fake_void_fn(self):
        for execution in (ref(1000), ref(1001)):
            document = ordinary()
            function = next(t for t in document[10]['types'] if t['id'] == 103)
            function.update(execution=some(execution), representation='signature')
            with self.subTest(execution=execution), self.assertRaisesRegex(
                    ValueError, 'ABI_CC_TYPE_BINDING|ABI_CC_FUNCTION_DEFAULT'):
                checked(seal(document))

    def test_none_does_not_hide_malformed_function_arity_or_flags(self):
        for change in (dict(extent=some(2)), dict(flags=['complete', 'union']), dict(bits=64)):
            document = ordinary()
            next(t for t in document[10]['types'] if t['id'] == 106).update(change)
            with self.subTest(change=change), self.assertRaisesRegex(
                    ValueError, 'ABI_CC_SOURCE_SIGNATURE|ABI_CC_TYPE_KIND'):
                checked(seal(document))

    def test_incomplete_record_byvalue_plan_is_rejected(self):
        document = ordinary()
        signature = next(p for p in document[10]['signatures'] if p['id'] == 201)
        signature.update(function_type=ref(106), params=[ref(100)], result=some(ref(100)),
                         lowered_params=[], lowered_results=[])
        with self.assertRaisesRegex(ValueError, 'ABI_CC_INCOMPLETE_VALUE'):
            checked(seal(document))

    def test_missing_wrong_and_mismatched_plan_execution_reject(self):
        for variant in ('missing', 'scalar', 'wrong_fn'):
            document = ordinary()
            signature = next(p for p in document[10]['signatures'] if p['id'] == 201)
            if variant == 'missing':
                del signature['execution']
            else:
                signature['execution'] = ref(1000 if variant == 'scalar' else 12)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                checked(document)

    def test_original_dependency_call_plan_uses_own_expectation(self):
        document, reference = dependency_plan(ordinary())
        self.assertTrue(self.compare(document, ordinary(), reference, ref(201)))
        bad = deepcopy(document)
        bad[2]['manifest']['dependencies'][0]['declarations'][0]['abi_signature'] = None
        with self.assertRaisesRegex(Exception, 'ABI_CC_ENTITY_REFERENCE'):
            self.compare(bad, ordinary(), reference, ref(201))

    def test_full_execution_result_noundef_is_significant(self):
        document = ordinary()
        next(p for p in document[10]['signatures'] if p['id'] == 201)['return_noundef'] = False
        next(t for t in document[1]['types'] if t['id'] == 1001)['result_noundef'] = [False]
        self.assertFalse(self.compare(document, ordinary()))

    def test_variadic_state_and_original_dependency_table_scope(self):
        a, b = variadic(), variadic()
        b, _ = dependency_plan(b)
        next(p for p in b[10]['signatures'] if p['id'] == 201)['varargs']['some'][
            'table_module'] = dict(kind='dependency', slot=7)
        self.assertTrue(self.compare(a, b))
        self.assertFalse(self.compare(a, ordinary()))
        bad = deepcopy(b)
        next(p for p in bad[10]['signatures'] if p['id'] == 201)['varargs']['some'][
            'table_module']['slot'] = 8
        with self.assertRaisesRegex(Exception, 'ABI_CC_ENTITY_REFERENCE'):
            self.compare(a, bad)

    def test_c_linkage_projection_requires_both_sides(self):
        a, b = ordinary(), ordinary()
        for document in (a, b):
            next(t for t in document[10]['types'] if t['id'] == 105)['flags'].append('c_linkage')
        for typ in b[10]['types']:
            typ['identity']['language'] = 'c23'
        self.assertTrue(self.compare(seal(a), seal(b)))
        self.assertFalse(self.compare(a, ordinary()))

    def test_independent_source_layout_plan_domain_and_execution_id_renaming(self):
        a, b = ordinary(complete_record=True), ordinary(complete_record=True)
        source_ids = {t['id']: t['id'] + 1000 for t in b[10]['types'] if t['id'] >= 100}
        execution_ids = {t['id']: t['id'] + 2000 for t in b[1]['types'] if t['id'] >= 1000}
        layout_ids = {t['id']: t['id'] + 3000 for t in b[10]['layouts'] if t['id'] >= 100}

        def qref(value, identifiers):
            if value is None:
                return
            if type(value) is dict:
                if set(value) == {'module', 'id'}:
                    if value['module']['kind'] == 'self':
                        value['id'] = identifiers.get(value['id'], value['id'])
                else:
                    for child in value.values():
                        qref(child, identifiers)
            elif type(value) is list:
                for child in value:
                    qref(child, identifiers)

        for typ in b[1]['types']:
            typ['id'] = execution_ids.get(typ['id'], typ['id'])
            qref(typ, execution_ids)
        for typ in b[10]['types']:
            typ['id'] = source_ids.get(typ['id'], typ['id'])
            typ['domain'] = 70
            qref(typ['execution'], execution_ids)
            if typ['layout'] is not None:
                typ['layout']['some'] = layout_ids.get(typ['layout']['some'], typ['layout']['some'])
            for key in ('elements', 'methods', 'record_input'):
                qref(typ[key], source_ids)
        for layout in b[10]['layouts']:
            layout['id'] = layout_ids.get(layout['id'], layout['id'])
            qref(layout, source_ids)
        for signature in b[10]['signatures']:
            qref(signature['execution'], execution_ids)
            execution = signature.pop('execution')
            qref(signature, source_ids)
            signature['execution'] = execution
            if signature['id'] == 201:
                signature['id'] = 1201
        b[10]['domains'][0]['id'] = 70
        self.assertTrue(self.compare(a, seal(b), ref(201), ref(1201)))

    def test_recipe_interfaces_use_source_types_and_not_recipe_numbers(self):
        # Genuine views over verified unused identity recipes exercise the recipe
        # component; this does not invent a lifecycle recipe for a pointer plan.
        a, b = ordinary(), ordinary()
        for document, identifier in ((a, 300), (b, 400)):
            document[10]['recipes'].append(dict(id=identifier, domain=0,
                params=[dict(id=0, type=ref(1))], results=[ref(1)], entry=0,
                steps=[dict(id=0, action='return', inputs=[0], outputs=[], source_type=None,
                    target_type=None, callee=None, adjustment=None, extent=0, align=1,
                    journal_slot=None, ticket=0, normal=None, unwind=None, exception=None)]))
        _, _, av, bv, budget = pair(a, b)
        comparison = model._Comparison(av, bv, budget)
        self.assertTrue(comparison.recipe(some(300), some(400)))
        self.assertFalse(comparison.recipe(None, some(400)))
        recipe = b[10]['recipes'][-1]
        recipe['params'][0]['type'] = ref(104)
        recipe['results'] = [ref(104)]
        _, _, av, bv, budget = pair(a, b)
        self.assertFalse(model._Comparison(av, bv, budget).recipe(some(300), some(400)))

    def test_wrong_ledger_and_unissued_context_are_not_false(self):
        a, b, av, bv, budget = pair(ordinary(), ordinary())
        error = sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError
        with self.assertRaisesRegex(error, 'ABI_CC_CONTEXT'):
            ordinary_address_call_compatible(av, ref(201), bv, ref(201), budget=ledger())
        fake = object.__new__(source_call_api().SourceCallContext)
        with self.assertRaisesRegex(error, 'ABI_CC_CONTEXT'):
            ordinary_address_call_compatible(fake, ref(201), bv, ref(201), budget=budget)

    def test_private_identity_needs_actual_family_and_unit_but_not_minor(self):
        a, b = ordinary(), ordinary()
        for document, namespace in ((a, 'first'), (b, 'second')):
            document[2]['manifest']['key']['namespace'] = namespace
            record = next(t for t in document[10]['types'] if t['id'] == 100)
            record['identity'].update(linkage='internal', unit=some('a' * 64))
            seal(document)
        _, _, av, bv, budget = pair(a, b)
        self.assertFalse(ordinary_address_call_compatible(av, ref(201), bv, ref(201), budget=budget))
        b[2]['manifest']['key'].update(a[2]['manifest']['key'])
        b[2]['manifest']['key']['abi_minor'] += 1
        self.assertTrue(self.compare(a, b))
        record = next(t for t in b[10]['types'] if t['id'] == 100)
        record['identity']['unit'] = some('b' * 64)
        self.assertFalse(self.compare(a, seal(b)))

    def test_mutation_after_cached_row_is_rechecked_before_either_boolean(self):
        for compatible in (True, False):
            a, b, av, bv, budget = pair(ordinary(), ordinary(count=3 if compatible else 4))
            original = model._Comparison.compare

            def mutate(comparison, ar, br):
                result = original(comparison, ar, br)
                next(t for t in b.sections[10]['types'] if t['id'] == 103)['qualifiers'] = ['const']
                return result

            with patch.object(model._Comparison, 'compare', new=mutate):
                with self.subTest(compatible=compatible), self.assertRaisesRegex(
                        source_api().SourceDataError, 'context_snapshot_changed'):
                    ordinary_address_call_compatible(av, ref(201), bv, ref(201), budget=budget)

    def test_programming_exception_propagates_and_has_no_false_fallback(self):
        _, _, av, bv, budget = pair(ordinary(), ordinary())
        marker = KeyError('ordinary-comparison-programming-counter')
        with patch.object(model._Comparison, 'compare', side_effect=marker):
            with self.assertRaises(KeyError) as caught:
                ordinary_address_call_compatible(av, ref(201), bv, ref(201), budget=budget)
        self.assertIs(caught.exception, marker)


if __name__ == '__main__':
    unittest.main()
