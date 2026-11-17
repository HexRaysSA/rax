"""Draft registry data factory: genuine verification, no runtime fact stand-ins."""
from copy import deepcopy
import gc
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import weakref

from candidate.context import RootContext, source_registry_api
from candidate.source_data_projection import ROOT, source_api
from candidate.type_system import ref
from test_candidate_context import roots
from test_candidate_source_calls import declarations, ledger, thaw


def all_roots():
    document = roots()
    # Authored source sections: the factory must never insert these itself.
    document[5] = dict(payload_revision=2, relocations=[], constant_initializers=[])
    document[7] = dict(payload_revision=1, segments=[])
    document[9] = dict(payload_revision=1, capabilities=[], requirements=[], limits=[])
    return document


def actual(document=None, cls=RootContext):
    context = cls(all_roots() if document is None else document)
    context.verify_abi()
    context.verify_execution()
    return context


class CandidateSourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.api = source_registry_api()
        self.error = sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError

    def test_genuine_verification_all_roots_and_canonical_cache(self):
        context, budget = actual(), ledger()
        view = context.source_registry_context(budget=budget)
        self.assertIs(self.api.validate_source_registry_context(view, budget=budget), view)
        self.assertIs(context.source_registry_context(budget=budget), view)
        call = view.call_context(budget=budget)
        self.assertIs(view.call_context(budget=budget), call)
        self.assertIsNot(context.source_call_context(budget=budget), call)
        self.assertIsNot(context.source_registry_context(budget=ledger()), view)
        for section in (2, 3, 4, 5, 6, 7, 9):
            self.assertEqual(thaw(view.root(section, budget=budget)), context.sections[section])

    def test_actual_record_tables_and_original_children(self):
        document = all_roots()
        declarations(document)
        document[2]['manifest']['exports'] = [dict(id=7, kind='function', source_linkage='cpp',
            namespace='example', name='identity', target=ref(0), execution={'some': ref(12)},
            nominal={'some': ref(12)}, abi_signature={'some': ref(0)})]
        # This fixture's ordinary function and export are real source records;
        # no runtime owner/definition-selection admission is claimed here.
        context, budget = actual(document), ledger()
        view = context.source_registry_context(budget=budget)
        for namespace, reference, expected in [
            ('function', ref(0), document[3]['functions'][0]),
            ('symbol', ref(0), document[2]['symbols'][0]),
            ('export', ref(7), document[2]['manifest']['exports'][0]),
            ('declaration', ref(2, 0), document[2]['manifest']['dependencies'][0]['declarations'][1])]:
            result = view.record(namespace, reference, budget=budget)
            self.assertEqual(result.namespace, namespace)
            self.assertEqual(thaw(result.original_reference), reference)
            self.assertEqual(thaw(result.record), expected)
            self.assertFalse(hasattr(result, 'local_reference'))
        call = view.call_context(budget=budget)
        self.assertEqual(call.record('signature', ref(2, 0), budget=budget).record['id'], 0)

    def test_missing_any_actual_root_rejects_without_fabrication(self):
        for missing in (5, 7, 9):
            document = all_roots()
            del document[missing]
            context, budget = actual(document), ledger()
            before = deepcopy(context.sections)
            with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_ROOT'):
                context.source_registry_context(budget=budget)
            self.assertEqual(context.sections, before)
            self.assertIsNone(context.source_stamp)

    def test_flags_neither_one_nor_both_certify_success(self):
        for phase in ('none', 'abi', 'execution_flag', 'both_flags'):
            context = RootContext(all_roots())
            if phase == 'abi':
                context.verify_abi()
            elif phase in ('execution_flag', 'both_flags'):
                other = actual()
                context.execution_checked = other.execution_checked
                context.abi_graph = other.abi_graph
                context.abi_checked = phase == 'both_flags'
            with self.subTest(phase=phase), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE') as caught:
                context.source_registry_context(budget=ledger())
            self.assertEqual(caught.exception.kind, 'unavailable')

    def test_execution_and_graph_original_identity_not_equal_bytes(self):
        for name in ('execution_checked', 'abi_graph'):
            context, other = actual(), actual()
            setattr(context, name, getattr(other, name))
            with self.subTest(name=name), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE'):
                context.source_registry_context(budget=ledger())

    def test_copied_context_and_constructor_bypass_cannot_reuse_receipt(self):
        context = actual()
        forged = object.__new__(RootContext)
        forged.__dict__.update(context.__dict__)
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            forged.source_registry_context(budget=ledger())
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            self.api._issue(types.SimpleNamespace(abi_checked=True), budget=ledger())

    def test_noncanonical_context_rejects_before_sections_attribute_access(self):
        accesses = []
        class SectionsTrap:
            @property
            def sections(self):
                accesses.append(True)
                raise AssertionError('sections accessed before canonical guard')
        for value in (types.SimpleNamespace(abi_checked=True), object(), SectionsTrap(),
                      object.__new__(RootContext)):
            with self.subTest(value_type=type(value)), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
                self.api._issue(value, budget=ledger())
        self.assertEqual(accesses, [])

    def test_malformed_original_function_and_abi_roots_reject_typed(self):
        for replacement in (None, {}, {'payload_revision': None}, {'payload_revision': True}):
            context = actual()
            context.sections[3] = replacement
            with self.subTest(root=replacement), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
                context.source_registry_context(budget=ledger())
        for missing in (3, 10):
            context = actual()
            del context.sections[missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
                context.source_registry_context(budget=ledger())

    def test_actual_v3_priority_requires_genuine_construction(self):
        path = ROOT / 'docs/specifications/smir/portable/conformance/execution/root3-context/published-sret.smo'
        budget = source_api().SourceQueryBudget(max_work=10**24, max_edges=10**24,
            max_copied_bytes=10**24, max_depth=128)
        context = RootContext.from_module(path.read_bytes(), budget=budget)
        # No ABI/execution proof exists: genuine v3 unavailable has priority.
        with self.assertRaisesRegex(self.error, 'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE') as caught:
            context.source_registry_context(budget=budget)
        self.assertEqual(caught.exception.kind, 'unavailable')
        copied = object.__new__(RootContext)
        copied.__dict__.update(context.__dict__)
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            copied.source_registry_context(budget=budget)

    def test_no_public_constructor_subclass_or_unissued_view(self):
        class Child(self.api.SourceRegistryContext):
            pass
        for value in (object.__new__(self.api.SourceRegistryContext), object.__new__(Child), object()):
            with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
                self.api.validate_source_registry_context(value, budget=ledger())
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            self.api.SourceRegistryContext()
        class ContextChild(RootContext):
            pass
        context = actual(cls=ContextChild)  # Existing generic verification still works.
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            context.source_registry_context(budget=ledger())

    def test_actual_verified_import_record(self):
        from test_candidate_bindings import add_import
        document, binding = add_import('va_arg', types=[16], abi={'some': ref(1)})
        for section in (5, 7, 9):
            document[section] = all_roots()[section]
        context, budget = actual(document), ledger()
        view = context.source_registry_context(budget=budget)
        record = view.record('import', ref(binding['id']), budget=budget)
        self.assertEqual(thaw(record.record), binding)
        self.assertEqual(thaw(record.original_reference), ref(binding['id']))

    def test_deep_immutable_records_stamp_and_reinitialization(self):
        context, budget = actual(), ledger()
        view = context.source_registry_context(budget=budget)
        record = view.record('function', ref(0), budget=budget)
        with self.assertRaises(TypeError):
            record.record['blocks'][0]['term']['op'] = 'trap'
        with self.assertRaises(AttributeError):
            record.__init__('bad', None, None)
        with self.assertRaises(AttributeError):
            record.record.__init__(None, None, None)
        with self.assertRaises(AttributeError):
            view._stamp.__init__(None, None, None)
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            view.__init__(None, None, None, None, None, None, None, None)
        with self.assertRaises(AttributeError):
            del view._roots

    def test_original_associations_not_structurally_equal_substitutes(self):
        for name in ('_context', '_stamp', '_roots', '_budget', '_call_view', '_receipt', '_generation'):
            context, budget = actual(), ledger()
            view = context.source_registry_context(budget=budget)
            old = getattr(view, name)
            object.__setattr__(view, name, object())
            with self.subTest(name=name), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
                self.api.validate_source_registry_context(view, budget=budget)
            object.__setattr__(view, name, old)

    def test_wrong_budget_zero_quotas_and_depth_are_typed(self):
        context = actual()
        for budget in (None, ledger(max_work=0), ledger(max_edges=0),
                       ledger(max_copied_bytes=0), ledger(max_depth=1)):
            with self.subTest(budget=budget), self.assertRaises(source_api().SourceDataError):
                context.source_registry_context(budget=budget)
        budget = ledger()
        view = context.source_registry_context(budget=budget)
        consumed = budget._used_work
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            view.root(3, budget=ledger())
        self.assertEqual(budget._used_work, consumed)
        with self.assertRaises(source_api().SourceDataError):
            view.root(3, budget=None)

    def test_source_data_stamp_and_ledger_untouched(self):
        context = actual()
        old, current = ledger(), ledger()
        context.prepare_source_data(budget=old)
        before = (context.source_stamp, context._source_roots, context._source_grammar,
                  old._used_work, old._used_edges, old._used_copied_bytes)
        view = context.source_registry_context(budget=current)
        view.call_context(budget=current)
        self.assertEqual(before, (context.source_stamp, context._source_roots, context._source_grammar,
                         old._used_work, old._used_edges, old._used_copied_bytes))
        self.assertIs(context._source_budget, old)

    def test_current_root_and_verified_copy_mutation_rejects_no_restamp(self):
        for target in ('source', 'verified', 'digest'):
            context, budget = actual(), ledger()
            view = context.source_registry_context(budget=budget)
            if target == 'source':
                context.sections[3]['functions'][0]['name'] = 'extra_field'
            elif target == 'verified':
                context.execution_checked.functions_root['functions'][0]['no_return'] = True
            else:
                context._root_hashes[3] = b'forged'
            with self.subTest(target=target), self.assertRaises((self.error, source_api().SourceDataError, ValueError)):
                context.source_registry_context(budget=budget)
            self.assertIsNone(context.source_stamp)
            self.assertIs(view._context, context)

    def test_reverification_invalidates_existing_epoch_not_relabels_it(self):
        context, budget = actual(), ledger()
        view = context.source_registry_context(budget=budget)
        context.verify_execution()
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            view.call_context(budget=budget)
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
            context.source_registry_context(budget=budget)
        del view
        gc.collect()
        fresh = context.source_registry_context(budget=budget)
        self.assertIs(self.api.validate_source_registry_context(fresh, budget=budget), fresh)

    def test_namespace_reference_and_root_rejections(self):
        context, budget = actual(), ledger()
        view = context.source_registry_context(budget=budget)
        for section in (1, 8, 10, 0, True, '3'):
            with self.subTest(section=section), self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_ROOT'):
                view.root(section, budget=budget)
        for namespace in ('execution', '', None, 'x' * 10000):
            with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_NAMESPACE') as caught:
                view.record(namespace, ref(0), budget=budget)
            self.assertLess(len(caught.exception.detail), 64)
        for namespace, reference in (('function', ref(0, 0)), ('declaration', ref(0))):
            with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_NAMESPACE'):
                view.record(namespace, reference, budget=budget)
        for reference in (None, {}, ref(True), ref(-1), ref(0xffffffff), ref(999)):
            with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_REFERENCE'):
                view.record('function', reference, budget=budget)
        with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_REFERENCE'):
            view.record('import', ref(0), budget=budget)

    def test_genuine_context_alias_same_canonical_view(self):
        name = '_sem_registry_context_alias'
        path = ROOT / 'tools/smir-format/execution/candidate/context.py'
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            context, budget = actual(cls=module.RootContext), ledger()
            view = context.source_registry_context(budget=budget)
            self.assertIs(type(view), self.api.SourceRegistryContext)
            self.assertIs(module.source_registry_api(), self.api)
        finally:
            del sys.modules[name]

    def test_canonical_module_path_ready_and_alias_fail_closed(self):
        name = '_rax_smir_source_registry_v1'
        for replacement in (types.SimpleNamespace(__file__='/tmp/wrong.py'),
                            types.SimpleNamespace(__file__=self.api.__file__, _SOURCE_REGISTRY_READY=False)):
            with patch.dict(sys.modules, {name: replacement}):
                with self.assertRaisesRegex(self.error, 'SOURCE_REGISTRY_CONTEXT'):
                    source_registry_api()
        path = Path(self.api.__file__)
        spec = importlib.util.spec_from_file_location('_wrong_registry_alias', path)
        with self.assertRaisesRegex(ImportError, 'SOURCE_REGISTRY_MODULE_IDENTITY'):
            spec.loader.exec_module(importlib.util.module_from_spec(spec))

    def test_schema_change_and_programming_errors_propagate(self):
        context, budget = actual(), ledger()
        view = context.source_registry_context(budget=budget)
        projection = view._projection
        original = projection._schema
        def changed(query):
            schema, digest = original(query)
            return schema, b'changed'
        with patch.object(projection, '_schema', side_effect=changed):
            with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_SCHEMA'):
                view.root(3, budget=budget)
        with patch.object(projection, '_schema', side_effect=KeyError('programming-counter')):
            with self.assertRaisesRegex(KeyError, 'programming-counter'):
                view.root(3, budget=budget)

    def test_weak_cache_does_not_retain_view_context_or_call_view(self):
        context, budget = actual(), ledger()
        view = context.source_registry_context(budget=budget)
        identity, context_id = id(view), id(context)
        seen_view, seen_context = weakref.ref(view), weakref.ref(context)
        seen_call = weakref.ref(view.call_context(budget=budget))
        cache_key = (id(context), id(budget))
        del view, context
        gc.collect()
        self.assertIsNone(seen_view())
        self.assertIsNone(seen_context())
        self.assertIsNone(seen_call())
        self.assertNotIn(identity, self.api._ISSUED)
        self.assertNotIn(context_id, self.api._CONTEXTS)
        self.assertNotIn(cache_key, self.api._CACHE)


if __name__ == '__main__':
    unittest.main()
