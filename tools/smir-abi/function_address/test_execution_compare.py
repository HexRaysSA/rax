"""Genuine-context execution comparison and source-authored conformance vectors.

Run in a fresh interpreter from tools/smir-abi:
    python3 -B -m unittest function_address.test_execution_compare -v
    python3 -B -O -m unittest function_address.test_execution_compare -v

The old ABI tool and execution package historically share the name `candidate`.
This isolated group never evicts an existing module to hide that collision.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from function_address import execution_compare as comparison


ROOT = Path(__file__).resolve().parents[3]
EXECUTION = ROOT / 'tools/smir-format/execution'
VECTORS = ROOT / ('docs/specifications/smir/portable/conformance/abi/'
                  'function-address/execution-compare-vectors.json')
if 'candidate' in sys.modules:
    path = getattr(sys.modules['candidate'], '__file__', None)
    if path is None or Path(path).resolve() != EXECUTION / 'candidate/__init__.py':
        raise ImportError('execution comparison tests require an isolated execution package')
sys.path.insert(0, str(EXECUTION))

from candidate.context import RootContext, source_call_api
from candidate.source_data_projection import source_api
from candidate.type_system import ref
from common import Reject


def ledger(**changes):
    policy = dict(max_work=10**10, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    policy.update(changes)
    return source_api().SourceQueryBudget(**policy)


def counters(budget):
    return budget._used_work, budget._used_edges, budget._used_copied_bytes


def vectors():
    return json.loads(VECTORS.read_text())


def roots(*, added=True, offset=0):
    fixture = vectors()
    document = {int(n): v for n, v in json.loads((ROOT / fixture['base_fixture']).read_text())['sections'].items()}
    if added:
        rows = deepcopy(fixture['added_types'])
        identifiers = {row['id'] for row in rows}

        def rename(value):
            if type(value) is dict:
                if set(value) == {'module', 'id'}:
                    if value['module']['kind'] == 'self' and value['id'] in identifiers:
                        value['id'] += offset
                    return
                for child in value.values():
                    rename(child)
            elif type(value) is list:
                for child in value:
                    rename(child)

        for row in rows:
            rename(row)
            row['id'] += offset
        document[1]['types'] += rows
        document[1]['types'].sort(key=lambda row: row['id'])
    return document


def actual(document=None):
    context = RootContext(roots() if document is None else document)
    context.verify_abi()
    return context


def views(left=None, right=None, *, budget=None):
    budget = ledger() if budget is None else budget
    a, b = actual(left), actual(right)
    return a, b, a.source_call_context(budget=budget), b.source_call_context(budget=budget), budget


def dependency(document, declarations):
    document[2]['manifest']['dependencies'] = [dict(slot=7,
        key=dict(namespace='example', name='other', abi_major=1, abi_minor=0),
        minimum_minor=0, maximum_minor=None, site=document[10]['identity'],
        declarations=[dict(id=identifier, kind='type', symbol_kind='none', source_linkage='none',
                           namespace='example', name='t' + str(identifier), weak=False,
                           execution=None if target is None else {'some': ref(target)},
                           nominal=None, abi_signature=None)
                      for identifier, target in declarations])]


class ExecutionComparisonTests(unittest.TestCase):
    def setUp(self):
        self.api = source_call_api()
        self.error = sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError

    def test_authored_vectors_cover_every_current_constructor(self):
        fixture = vectors()
        self.assertEqual(hashlib.sha256((ROOT / fixture['base_fixture']).read_bytes()).hexdigest(),
                         fixture['base_fixture_sha256'])
        schema = json.loads((ROOT / 'docs/specifications/smir/portable/schema/execution/candidate.json').read_text())
        kinds = set(schema['records']['type']['variants'])
        self.assertEqual({row['kind'] for row in fixture['added_types']}, kinds)
        for kind, fields in schema['records']['type']['variants'].items():
            self.assertEqual(set(comparison._FIELDS[kind]),
                             {name for name, _ in fields} - {'id'})
        self.assertIn('code_address', kinds)
        self.assertEqual(fixture['active_shape']['children'], [])
        self.assertEqual(len(fixture['pairs']), 94)

    def test_all_authored_pairs_genuine_context_and_existing_structural_oracle(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        before = deepcopy(context.sections)
        for case in vectors()['pairs']:
            with self.subTest(case=case['name']):
                a, b = ref(case['actual']), ref(case['expected'])
                observed = comparison.same_execution_shape(view, a, view, b, budget=budget)
                self.assertIs(observed, case['equal'])
                self.assertIs(observed, context.types.equal(a, b))
        self.assertEqual(context.sections, before)

    def test_alpha_renamed_ids_cross_distinct_actual_contexts(self):
        _, _, left, right, budget = views(right=roots(offset=1000))
        self.assertIsNot(left, right)
        self.assertIsNot(left._stamp, right._stamp)
        for row in vectors()['added_types']:
            with self.subTest(kind=row['kind'], identifier=row['id']):
                self.assertTrue(comparison.same_execution_shape(left, ref(row['id']),
                    right, ref(row['id'] + 1000), budget=budget))

    def test_same_id_other_context_width_and_constructor_are_not_equal(self):
        for replacement in [dict(id=102, kind='int', bits=64), dict(id=102, kind='raw', bits=32)]:
            document = roots()
            document[1]['types'] = [replacement if row['id'] == 102 else row for row in document[1]['types']]
            _, _, left, right, budget = views(right=document)
            self.assertFalse(comparison.same_execution_shape(left, ref(102), right, ref(102), budget=budget))

    def test_recursive_sharing_and_delayed_difference_use_pairs(self):
        document = roots()
        row = next(row for row in document[1]['types'] if row['id'] == 135)
        row['param_noundef'] = [True]
        _, _, left, right, budget = views(right=document)
        self.assertFalse(comparison.same_execution_shape(left, ref(131), right, ref(133), budget=budget))
        self.assertTrue(comparison.same_execution_shape(left, ref(136), right, ref(138), budget=budget))

    def test_noundef_and_parameter_result_boundaries_are_semantic(self):
        _, _, left, right, budget = views()
        for a, b in [(125, 126), (125, 127), (128, 129), (118, 119), (147, 148)]:
            with self.subTest(a=a, b=b):
                self.assertFalse(comparison.same_execution_shape(left, ref(a), right, ref(b), budget=budget))

    def test_dependency_expectation_resolves_own_local_graph_without_rewriting(self):
        left_doc, right_doc = roots(), roots(offset=1000)
        dependency(left_doc, [(102, 103), (201, 131)])
        dependency(right_doc, [(102, 1103), (201, 1133)])
        a, b, left, right, budget = views(left_doc, right_doc)
        before = deepcopy((a.sections, b.sections))
        self.assertTrue(comparison.same_execution_shape(left, ref(102, 7), right, ref(1103), budget=budget))
        self.assertFalse(comparison.same_execution_shape(left, ref(102), right, ref(102, 7), budget=budget))
        self.assertTrue(comparison.same_execution_shape(left, ref(201, 7), right, ref(201, 7), budget=budget))
        self.assertEqual((a.sections, b.sections), before)

    def test_original_dependency_children_are_followed_in_same_context(self):
        document = roots()
        dependency(document, [(201, 102)])
        next(row for row in document[1]['types'] if row['id'] == 125)['params'] = [ref(201, 7)]
        _, _, left, right, budget = views(document)
        self.assertTrue(comparison.same_execution_shape(left, ref(125), right, ref(125), budget=budget))

    def test_missing_dependency_expectation_and_wrong_reference_keep_specific_errors(self):
        document = roots()
        dependency(document, [(201, None)])
        _, _, left, right, budget = views(document)
        for reference, code in [(ref(201, 7), 'ABI_CC_ENTITY_REFERENCE'),
                                (ref(999), 'ABI_CC_TYPE_REFERENCE'),
                                (ref(201, 8), 'ABI_CC_ENTITY_REFERENCE'),
                                (ref(True), 'ABI_CC_ENTITY_REFERENCE'),
                                (ref(0xffffffff), 'ABI_CC_ENTITY_REFERENCE')]:
            with self.subTest(reference=reference), self.assertRaisesRegex(self.error, code):
                comparison.same_execution_shape(left, reference, right, ref(102), budget=budget)

    def test_duck_unissued_and_subclass_views_reject_before_record_callback(self):
        class Duck:
            def record(self, *args, **kwargs):
                raise AssertionError('duck callback invoked')

        class Child(self.api.SourceCallContext):
            pass

        _, _, left, right, budget = views()
        for bad in [Duck(), object.__new__(self.api.SourceCallContext), object.__new__(Child), None]:
            for a, b in [(bad, right), (left, bad)]:
                with self.subTest(bad=type(bad)), self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
                    comparison.same_execution_shape(a, ref(102), b, ref(102), budget=budget)

    def test_different_ledgers_and_wrong_budget_are_not_false(self):
        a, b = actual(), actual()
        first, second = ledger(), ledger()
        left = a.source_call_context(budget=first)
        right = b.source_call_context(budget=second)
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            comparison.same_execution_shape(left, ref(102), right, ref(102), budget=first)
        for bad in [None, types.SimpleNamespace(work=lambda n: None)]:
            with self.subTest(bad=bad), self.assertRaises(source_api().SourceDataError) as error:
                comparison.same_execution_shape(left, ref(102), left, ref(102), budget=bad)
            self.assertEqual(error.exception.code, 'SOURCE_DATA_BUDGET')
        with self.assertRaises(TypeError):
            comparison.same_execution_shape(left, ref(102), left, ref(102))

    def test_mutated_original_source_rejects_before_either_boolean(self):
        for same in [True, False]:
            _, b, left, right, budget = views()
            next(row for row in b.sections[1]['types'] if row['id'] == 102)['bits'] = 65
            with self.subTest(same=same), self.assertRaisesRegex(source_api().SourceDataError,
                                                                 'context_snapshot_changed'):
                comparison.same_execution_shape(left, ref(102), right, ref(102 if same else 103), budget=budget)

    def test_mutation_during_traversal_rechecked_before_true_and_false(self):
        for side in [0, 1]:
            for same in [True, False]:
                a, b, left, right, budget = views()
                describe, count = comparison._describe, 0

                def mutate(record, quota):
                    nonlocal count
                    result = describe(record, quota)
                    count += 1
                    if count == 2:
                        context = (a, b)[side]
                        next(row for row in context.sections[1]['types'] if row['id'] == 102)['bits'] = 65
                    return result

                with patch.object(comparison, '_describe', side_effect=mutate):
                    with self.subTest(side=side, same=same), self.assertRaisesRegex(
                            source_api().SourceDataError, 'context_snapshot_changed'):
                        comparison.same_execution_shape(left, ref(102), right,
                                                        ref(102 if same else 103), budget=budget)

    def test_old_source_data_stamps_and_ledgers_unchanged(self):
        contexts = [actual(), actual()]
        old = [ledger(), ledger()]
        saved = []
        for context, quota in zip(contexts, old):
            context.prepare_source_data(budget=quota)
            saved.append((context.source_stamp, counters(quota)))
        budget = ledger()
        left, right = [context.source_call_context(budget=budget) for context in contexts]
        self.assertTrue(comparison.same_execution_shape(left, ref(131), right, ref(133), budget=budget))
        for context, quota, before in zip(contexts, old, saved):
            self.assertIs(context.source_stamp, before[0])
            self.assertEqual(counters(quota), before[1])

    def test_each_exhausted_dimension_refuses_without_reset(self):
        context = actual()
        measuring = ledger()
        context.source_call_context(budget=measuring)
        used = counters(measuring)
        for index, dimension in enumerate(['max_work', 'max_edges', 'max_copied_bytes']):
            budget = ledger(**{dimension: used[index]})
            view = context.source_call_context(budget=budget)
            before = counters(budget)
            self.assertEqual(before[index], used[index])
            with self.subTest(dimension=dimension), self.assertRaises(source_api().SourceDataError) as error:
                comparison.same_execution_shape(view, ref(102), view, ref(102), budget=budget)
            self.assertEqual((error.exception.kind, error.exception.code), ('resource', 'SOURCE_DATA_RESOURCE'))
            self.assertEqual(counters(budget)[index], before[index])
            self.assertTrue(all(a >= b for a, b in zip(counters(budget), before)))

    def test_zero_and_small_budgets_cannot_issue_a_genuine_input_view(self):
        context = actual()
        for limits in [dict(max_work=0), dict(max_edges=0), dict(max_copied_bytes=0),
                       dict(max_work=1), dict(max_edges=1), dict(max_copied_bytes=1),
                       dict(max_depth=1)]:
            quota = ledger(**limits)
            with self.subTest(limits=limits), self.assertRaises(source_api().SourceDataError) as error:
                context.source_call_context(budget=quota)
            self.assertEqual(error.exception.kind, 'resource')

    def test_resource_during_final_check_never_publishes_false(self):
        context = actual()
        measuring = ledger()
        view = context.source_call_context(budget=measuring)
        validate, count, before_final = self.api.validate_source_call_context, 0, []

        def watch(value, *, budget):
            nonlocal count
            count += 1
            if count == 7:
                before_final.append(counters(budget)[0])
            return validate(value, budget=budget)

        with patch.object(self.api, 'validate_source_call_context', side_effect=watch):
            self.assertFalse(comparison.same_execution_shape(view, ref(102), view, ref(103), budget=measuring))
        self.assertEqual(count, 8)
        self.assertEqual(len(before_final), 1)
        budget = ledger(max_work=before_final[0])
        view = context.source_call_context(budget=budget)
        with self.assertRaises(source_api().SourceDataError) as error:
            comparison.same_execution_shape(view, ref(102), view, ref(103), budget=budget)
        self.assertEqual(error.exception.kind, 'resource')

    def test_deep_recursive_graph_has_bounded_first_visit_depth(self):
        document = roots()
        for index in range(40):
            fn, pointer = 2000 + 2 * index, 2001 + 2 * index
            document[1]['types'] += [dict(id=fn, kind='function', params=[ref(pointer)], results=[],
                variadic=False, cc='portable', param_noundef=[False], result_noundef=[]),
                dict(id=pointer, kind='code_ptr', signature=ref(2000 + 2 * ((index + 1) % 40)))]
        context = actual(document)
        budget = ledger(max_depth=64)
        view = context.source_call_context(budget=budget)
        with self.assertRaisesRegex(source_api().SourceDataError, 'execution comparison depth'):
            comparison.same_execution_shape(view, ref(2000), view, ref(2000), budget=budget)
        budget = ledger(max_depth=128)
        view = context.source_call_context(budget=budget)
        self.assertTrue(comparison.same_execution_shape(view, ref(2000), view, ref(2000), budget=budget))

    def test_no_digest_or_numeric_id_shortcut(self):
        a, _, left, right, budget = views()
        with patch.object(type(a.types), 'digest', side_effect=AssertionError('digest shortcut')):
            self.assertFalse(comparison.same_execution_shape(left, ref(102), right, ref(103), budget=budget))
            self.assertTrue(comparison.same_execution_shape(left, ref(131), right, ref(133), budget=budget))

    def test_programming_exceptions_are_not_compatibility_false(self):
        _, _, left, right, budget = views()
        marker = KeyError('execution-programming-counter')
        with patch.object(self.api.SourceCallContext, 'record', side_effect=marker):
            with self.assertRaises(KeyError) as caught:
                comparison.same_execution_shape(left, ref(102), right, ref(102), budget=budget)
        self.assertIs(caught.exception, marker)

    def test_canonical_module_collision_and_exact_error_identity(self):
        _, _, left, right, budget = views()
        with patch.dict(sys.modules, {'_rax_smir_source_call_v1': types.SimpleNamespace(__file__='/tmp/alias.py')}):
            with self.assertRaises(self.error) as caught:
                comparison.same_execution_shape(left, ref(102), right, ref(102), budget=budget)
        self.assertIs(type(caught.exception), self.error)
        self.assertEqual((caught.exception.kind, caught.exception.code), ('semantic', 'ABI_CC_CONTEXT'))
        with patch.dict(sys.modules, {'_rax_smir_call_comparison_errors_v1': types.SimpleNamespace(__file__='/tmp/alias.py')}):
            with self.assertRaisesRegex(RuntimeError, 'CALL_COMPARISON_MODULE_IDENTITY'):
                comparison.same_execution_shape(left, ref(102), right, ref(102), budget=budget)

    def test_future_descriptor_negative_is_explicit_unavailable_not_a_forged_view(self):
        # Pure descriptor rejection branch only. No new-kind success/view claimed.
        for record in [dict(id=1, kind='future'), dict(id=1, kind='int', bits=8, future=True)]:
            with self.subTest(record=record), self.assertRaises(self.error) as caught:
                comparison._describe(record, ledger())
            self.assertEqual((caught.exception.kind, caught.exception.code),
                             ('unavailable', 'ABI_CC_TYPE_UNAVAILABLE'))

    def test_code_address_is_genuine_current_scalar_without_callable_signature(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        self.assertEqual(context.types.width(ref(154)), 64)
        record = view.record('execution', ref(154), budget=budget).record
        self.assertEqual(set(record), {'id', 'kind'})
        self.assertTrue(comparison.same_execution_shape(view, ref(154), view, ref(154), budget=budget))
        for other in (103, 105, 111, 130):
            self.assertFalse(comparison.same_execution_shape(view, ref(154), view, ref(other), budget=budget))

    def test_invalid_cc_and_open_variadic_reject_before_genuine_view(self):
        for replacement in [dict(id=2000, kind='function', cc='native', variadic=False,
                                 params=[], results=[], param_noundef=[], result_noundef=[]),
                            dict(id=2000, kind='function', cc='portable', variadic=True,
                                 params=[], results=[], param_noundef=[], result_noundef=[])]:
            document = roots()
            document[1]['types'].append(replacement)
            with self.subTest(replacement=replacement), self.assertRaises(Reject):
                actual(document)


if __name__ == '__main__':
    unittest.main()
