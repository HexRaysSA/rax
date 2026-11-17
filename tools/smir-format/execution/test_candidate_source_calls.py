"""Genuine current-grammar ABI-checked views, not new-format admission proofs."""
from collections.abc import Mapping
from copy import deepcopy
import gc
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import weakref

from candidate.context import RootContext, source_call_api
from candidate.source_data_projection import ROOT, source_api
from candidate.type_system import ref
from test_candidate_context import roots


def ledger(**changes):
    policy = dict(max_work=10**9, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    policy.update(changes)
    return source_api().SourceQueryBudget(**policy)


def actual(document=None, cls=RootContext):
    context = cls(roots() if document is None else document)
    context.verify_abi()
    return context


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(child) for key, child in value.items()}
    if type(value) is tuple:
        return [thaw(child) for child in value]
    return value


def declarations(document):
    fn = next(t['id'] for t in document[1]['types'] if t['kind'] == 'function')
    integer = next(t['id'] for t in document[1]['types'] if t['kind'] == 'int')
    rows = []
    for identifier, kind, execution, nominal, signature in [
            (1, 'nominal', None, {'some': ref(12)}, None),
            (2, 'function', {'some': ref(fn)}, None, {'some': ref(0)}),
            (3, 'type', {'some': ref(integer)}, None, None),
            (4, 'function', {'some': ref(fn)}, None, None)]:
        rows.append(dict(id=identifier, kind=kind, symbol_kind='none', source_linkage='none',
                         namespace='consumer', name='expected_' + str(identifier), execution=execution,
                         nominal=nominal, abi_signature=signature, weak=False))
    document[2]['manifest']['dependencies'] = [dict(slot=0,
        key=dict(namespace='example', name='provider', abi_major=1, abi_minor=0), minimum_minor=0,
        maximum_minor=None, site=document[10]['identity'], declarations=rows)]
    return fn, integer


class CandidateSourceCallTests(unittest.TestCase):
    def setUp(self):
        self.api = source_call_api()
        self.error = sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError

    def test_original_module_family_minor_excluded_and_budget_snapshot(self):
        document = roots()
        document[2]['manifest']['key']['abi_minor'] = 7
        context, budget = actual(document), ledger()
        view = context.source_call_context(budget=budget)
        self.assertEqual(view.module_family(budget=budget), ('example', 'identity', 1))
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            view.module_family(budget=ledger())
        context.sections[2]['manifest']['key']['name'] = 'other'
        with self.assertRaises(ValueError):
            view.module_family(budget=budget)

    def test_raw_records_and_execution_children_not_digests(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        for namespace, section, table in [('signature', 10, 'signatures'), ('nominal', 10, 'types'),
                                          ('layout', 10, 'layouts'), ('domain', 10, 'domains'),
                                          ('execution', 1, 'types')]:
            for row in context.sections[section][table]:
                result = view.record(namespace, ref(row['id']), budget=budget)
                self.assertEqual(thaw(result.record), row)
                self.assertEqual(thaw(result.original_reference), ref(row['id']))
                self.assertEqual(thaw(result.local_reference), ref(row['id']))
        fn = next(t for t in context.sections[1]['types'] if t['kind'] == 'function')
        description = view.record('execution', ref(fn['id']), budget=budget).record
        self.assertIsInstance(description['params'][0], Mapping)
        child = view.record('execution', description['params'][0], budget=budget)
        self.assertEqual(child.record['id'], fn['params'][0]['id'])
        self.assertIs(self.api.validate_source_call_context(view, budget=budget), view)

    def test_complete_site_and_deep_immutability(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        site = view.site(budget=budget)
        self.assertEqual(thaw(site), context.sections[10]['site'])
        with self.assertRaises(TypeError):
            site['namespace'] = 'fake'
        with self.assertRaises(AttributeError):
            site.__init__(None, None, None)
        with self.assertRaises(AttributeError):
            del site._record
        if site['options']:
            with self.assertRaises(TypeError):
                site['options'][0]['name'] = 'fake'
        record = view.record('signature', ref(0), budget=budget)
        with self.assertRaises(AttributeError):
            record.__init__(None, None, None)
        with self.assertRaises(AttributeError):
            view._stamp.__init__(None, None, None)
        with self.assertRaises(AttributeError):
            del view._context

    def test_distinct_old_source_data_ledgers_untouched(self):
        contexts = [actual(), actual()]
        old = [ledger(), ledger()]
        before = []
        for context, budget in zip(contexts, old):
            context.prepare_source_data(budget=budget)
            before.append((context.source_stamp, context._source_roots, context._source_grammar,
                           budget._used_work, budget._used_edges, budget._used_copied_bytes))
        shared = ledger()
        views = [c.source_call_context(budget=shared) for c in contexts]
        self.assertIsNot(views[0]._stamp, views[1]._stamp)
        for i, (context, budget) in enumerate(zip(contexts, old)):
            self.assertEqual((context.source_stamp, context._source_roots, context._source_grammar,
                              budget._used_work, budget._used_edges, budget._used_copied_bytes), before[i])
            self.assertIs(self.api.validate_source_call_context(views[i], budget=shared), views[i])
        fresh = contexts[0].source_call_context(budget=ledger())
        self.assertIsNot(fresh._stamp, views[0]._stamp)
        self.assertIsNone(actual().source_stamp)

    def test_dependency_expectations_original_namespace_no_provider(self):
        document = roots()
        fn, integer = declarations(document)
        context, budget = actual(document), ledger()
        view = context.source_call_context(budget=budget)
        for namespace, identifier, expected in [('nominal', 1, 12), ('signature', 2, 0),
                                                 ('execution', 2, fn), ('execution', 3, integer)]:
            result = view.record(namespace, ref(identifier, 0), budget=budget)
            self.assertEqual(thaw(result.original_reference), ref(identifier, 0))
            self.assertEqual(thaw(result.local_reference), ref(expected))
            self.assertEqual(result.record['id'], expected)
        self.assertEqual(view.record('signature', ref(2, 0), budget=budget).record['function_type']['id'], 12)
        for namespace, reference, code in [
                ('nominal', ref(2, 0), 'ABI_CC_ENTITY_NAMESPACE'),
                ('signature', ref(4, 0), 'ABI_CC_ENTITY_REFERENCE'),
                ('nominal', ref(1, 1), 'ABI_CC_ENTITY_REFERENCE'),
                ('execution', ref(999, 0), 'ABI_CC_ENTITY_REFERENCE'),
                ('domain', ref(1, 0), 'ABI_CC_ENTITY_NAMESPACE')]:
            with self.subTest(namespace=namespace, reference=reference):
                with self.assertRaisesRegex(self.error, code):
                    view.record(namespace, reference, budget=budget)

    def test_unverified_failed_and_duck_context_rejected(self):
        context = RootContext(roots())
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            context.source_call_context(budget=ledger())
        bad = roots()
        bad[10]['types'][0]['kind'] = 'not_a_kind'
        context = RootContext(bad)
        with self.assertRaises(Exception):
            context.verify_abi()
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            context.source_call_context(budget=ledger())
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            self.api._issue(types.SimpleNamespace(abi_checked=True), budget=ledger())

    def test_no_public_constructor_subclass_duck_or_unissued_object(self):
        class Duck:
            def record(self, *args, **kwargs):
                self.fail = True
                raise RuntimeError('duck method invoked')
        class Child(self.api.SourceCallContext):
            pass
        for value in [Duck(), object.__new__(self.api.SourceCallContext), object.__new__(Child)]:
            with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
                self.api.validate_source_call_context(value, budget=ledger())
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            self.api.SourceCallContext()

    def test_genuine_context_alias_uses_same_canonical_view_class(self):
        name = '_sem_source_call_actual_context_alias'
        path = ROOT / 'tools/smir-format/execution/candidate/context.py'
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            context, budget = actual(cls=module.RootContext), ledger()
            view = context.source_call_context(budget=budget)
            self.assertIs(type(view), self.api.SourceCallContext)
            self.assertIs(module.source_call_api(), self.api)
            self.assertIs(self.api.validate_source_call_context(view, budget=budget), view)
        finally:
            del sys.modules[name]

    def test_module_path_collision_and_alias_import_fail_closed(self):
        name = '_rax_smir_source_call_v1'
        with patch.dict(sys.modules, {name: types.SimpleNamespace(__file__='/tmp/wrong.py')}):
            with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
                source_call_api()
        errors_name = '_rax_smir_call_comparison_errors_v1'
        with patch.dict(sys.modules, {errors_name: types.SimpleNamespace(__file__='/tmp/wrong.py')}):
            with self.assertRaisesRegex(RuntimeError, 'SOURCE_CALL_MODULE_IDENTITY'):
                source_call_api()
        path = ROOT / 'tools/smir-format/execution/candidate/source_call_projection.py'
        spec = importlib.util.spec_from_file_location('_wrong_view_alias', path)
        module = importlib.util.module_from_spec(spec)
        with self.assertRaisesRegex(ImportError, 'SOURCE_CALL_MODULE_IDENTITY'):
            spec.loader.exec_module(module)
        self.assertIs(source_call_api(), self.api)

    def test_zero_depth_byte_and_wrong_ledger_refusal_no_reset(self):
        context = actual()
        for budget in [None, ledger(max_work=0), ledger(max_edges=0),
                       ledger(max_copied_bytes=0), ledger(max_depth=1)]:
            with self.subTest(budget=budget), self.assertRaises(source_api().SourceDataError):
                context.source_call_context(budget=budget)
        budget = ledger()
        view = context.source_call_context(budget=budget)
        used = budget._used_work
        with self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
            view.site(budget=ledger())
        self.assertEqual(budget._used_work, used)
        with self.assertRaises(source_api().SourceDataError):
            view.site(budget=None)
        self.assertIsNone(context.source_stamp)

    def test_failed_canonical_initialization_removes_only_own_entry(self):
        name = '_rax_smir_source_call_v1'
        path = ROOT / 'tools/smir-format/execution/candidate/source_call_projection.py'
        spec = importlib.util.spec_from_file_location(name, path)
        previous = sys.modules.pop(name)
        marker = types.ModuleType('_source_call_unrelated_marker')
        try:
            with patch.dict(sys.modules, {marker.__name__: marker}):
                with patch.object(spec.loader, 'exec_module', side_effect=KeyError('initialization-counter')):
                    with patch('candidate.context.importlib.util.spec_from_file_location', return_value=spec):
                        with self.assertRaisesRegex(KeyError, 'initialization-counter'):
                            source_call_api()
                self.assertNotIn(name, sys.modules)
                self.assertIs(sys.modules[marker.__name__], marker)
        finally:
            sys.modules[name] = previous

    def test_varargs_namespace_data_check_is_not_live_table_authority(self):
        # Isolated frozen-data branch witness, not a full variadic ABI admission.
        document = roots()
        declarations(document)
        context, budget = actual(document), ledger()
        view = context.source_call_context(budget=budget)
        F = source_api().FrozenRecord
        for slot in [None, 0, 99]:
            module = F((('kind', 'self'),)) if slot is None else F((('kind', 'dependency'), ('slot', slot)))
            signature = F((('varargs', F((('some', F((('table_module', module),))),))),))
            candidate = {2: view._roots[2], 10: F((('signatures', (signature,)),))}
            if slot == 99:
                with self.assertRaisesRegex(self.error, 'ABI_CC_ENTITY_REFERENCE'):
                    self.api._varargs(candidate, budget)
            else:
                self.api._varargs(candidate, budget)

    def test_original_verified_roots_not_restamped_after_mutation(self):
        for section in [1, 2, 10]:
            context = actual()
            if section == 1:
                context.sections[1]['types'][0]['bits'] += 1
            elif section == 2:
                context.sections[2]['manifest']['key']['name'] += '_changed'
            else:
                context.sections[10]['types'][0]['identity']['entity'] += '_changed'
            with self.subTest(section=section), self.assertRaisesRegex(Exception, 'context_snapshot_changed'):
                context.source_call_context(budget=ledger())

    def test_every_lookup_and_final_validation_detect_root_mutation(self):
        for section in [1, 2, 10]:
            context, budget = actual(), ledger()
            view = context.source_call_context(budget=budget)
            if section == 1:
                context.sections[1]['types'][0]['bits'] += 1
            elif section == 2:
                context.sections[2]['manifest']['key']['name'] += '_changed'
            else:
                context.sections[10]['types'][0]['identity']['entity'] += '_changed'
            for query in [lambda: view.site(budget=budget),
                          lambda: view.record('signature', ref(0), budget=budget),
                          lambda: self.api.validate_source_call_context(view, budget=budget)]:
                with self.subTest(section=section), self.assertRaisesRegex(Exception, 'context_snapshot_changed'):
                    query()

    def test_active_schema_change_and_programming_exception_propagation(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        projection = view._projection
        original = projection._schema
        def changed(query_budget):
            grammar, digest = original(query_budget)
            return grammar, b'changed'
        with patch.object(projection, '_schema', side_effect=changed):
            with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_SCHEMA'):
                view.site(budget=budget)
        with patch.object(projection, '_schema', side_effect=KeyError('programming-counter')):
            with self.assertRaisesRegex(KeyError, 'programming-counter'):
                view.site(budget=budget)

    def test_precise_namespace_and_malformed_reference_errors(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        for namespace in ['wrong', None, 'manifest', 'x' * 10000]:
            with self.assertRaisesRegex(self.error, 'ABI_CC_ENTITY_NAMESPACE') as caught:
                view.record(namespace, ref(0), budget=budget)
            self.assertLess(len(caught.exception.detail), 64)
        bad = [None, {}, {'id': 0}, {'module': None, 'id': 0}, ref(True), ref(-1),
               ref(0xffffffff), {'module': {'kind': 'dependency', 'slot': True}, 'id': 0}]
        for reference in bad:
            with self.subTest(reference=reference), self.assertRaisesRegex(self.error, 'ABI_CC_ENTITY_REFERENCE'):
                view.record('signature', reference, budget=budget)
        for namespace, code in [('recipe', 'ABI_CC_ENTITY_REFERENCE'), ('execution', 'ABI_CC_TYPE_REFERENCE')]:
            with self.assertRaisesRegex(self.error, code):
                view.record(namespace, ref(999), budget=budget)

    def test_weak_identity_registry_releases_view_and_capture(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        identifier, observed = id(view), weakref.ref(view)
        self.assertIs(self.api._ISSUED[identifier][0](), view)
        del view
        gc.collect()
        self.assertIsNone(observed())
        self.assertNotIn(identifier, self.api._ISSUED)

    def test_original_stamp_context_and_capture_identity_not_equal_bytes(self):
        first, second, budget = actual(), actual(), ledger()
        view = first.source_call_context(budget=budget)
        other = second.source_call_context(budget=budget)
        for name, replacement in [('_stamp', other._stamp), ('_context', second),
                                  ('_roots', other._roots), ('_budget', ledger())]:
            original = getattr(view, name)
            try:
                object.__setattr__(view, name, replacement)
                with self.subTest(name=name), self.assertRaisesRegex(self.error, 'ABI_CC_CONTEXT'):
                    self.api.validate_source_call_context(view, budget=budget)
            finally:
                object.__setattr__(view, name, original)
        self.assertIs(self.api.validate_source_call_context(view, budget=budget), view)

    def test_shared_error_identity_and_mandatory_execution_data_without_execution_proof(self):
        context, budget = actual(), ledger()
        view = context.source_call_context(budget=budget)
        with self.assertRaises(self.error) as caught:
            view.record('signature', ref(999), budget=budget)
        self.assertIs(type(caught.exception), sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError)
        self.assertEqual(caught.exception.kind, 'semantic')
        self.assertEqual(thaw(view.record('signature', ref(0), budget=budget).record['execution']), ref(12))
        self.assertIsNone(context.execution_checked)
        self.assertIsNone(context.source_stamp)


if __name__ == '__main__':
    unittest.main()
