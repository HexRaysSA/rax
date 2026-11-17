"""Actual RootContext source-data capture; independent Rust INT023 fixture parity."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from candidate.bindings import runtime_package_module

CandidateCodec = runtime_package_module('wire').PRIMITIVES.CandidateCodec
from common import Reject
from candidate.context import RootContext, records
from candidate.source_data_projection import ROOT, source_api
from candidate.type_system import ref
from candidate.wire import SCHEMA, encode

FIXTURES = ROOT / 'crates/smir-portable/tests/metadata/fixtures'


def roots(name='base'):
    schemas = {owner: json.loads((ROOT / f'docs/specifications/smir/portable/schema/{owner}/candidate.json').read_text())
               for owner in ('execution', 'runtime', 'abi')}
    return CandidateCodec(schemas).decode((FIXTURES / (name + '.smo')).read_bytes()).roots


def budget(**changes):
    policy = dict(max_work=10**9, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    policy.update(changes)
    return source_api().SourceQueryBudget(**policy)


def prepared(document=None, name='base', ledger=None):
    context = RootContext(roots(name) if document is None else document)
    ledger = budget() if ledger is None else ledger
    context.prepare_source_data(budget=ledger)
    return context, ledger


def thaw(value):
    if type(value) is source_api().FrozenRecord:
        return {name: thaw(child) for name, child in value.fields}
    if type(value) is tuple:
        return [thaw(child) for child in value]
    return value


class CandidateSourceDataTests(unittest.TestCase):
    def test_active_schema_document_and_grammar_shape_errors_are_exact(self):
        # Actual RootContext construction occurs before injecting an active-schema
        # read, matching the coordinator's five literal composition counters.
        for document in (None, [], {}, {'records': []}, {'records': None}, {'records': {}},
                         {'records': {'extra': None}},
                         {'records': {'extra': {'fields': None}}},
                         {'records': {'extra': {'fields': [['x']]}}},
                         {'records': {'extra': {'fields': [['x', 'absent_record']]}}},
                         {'records': {'extra': {'discriminator': 'kind', 'variants': []}}}):
            context = RootContext(roots())
            with self.subTest(document=document), patch('candidate.source_data_projection._read_schema',
                                                        return_value=document):
                with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_SCHEMA') as error:
                    context.prepare_source_data(budget=budget())
                self.assertEqual(error.exception.kind, 'semantic')
                self.assertIsNone(context.source_stamp)
        context = RootContext(roots())
        with patch('candidate.source_data_projection._read_schema') as reader:
            with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_RESOURCE'):
                context.prepare_source_data(budget=budget(max_work=0))
            reader.assert_not_called()

    def test_schema_json_precharge_and_depth_before_parse(self):
        import io
        import types
        from unittest.mock import Mock
        from candidate.source_data_projection import _read_schema
        path = Mock()
        raw = b'{"records":{}}'
        path.stat.return_value = types.SimpleNamespace(st_size=len(raw))
        path.open.return_value = io.BytesIO(raw)
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_RESOURCE'):
            _read_schema(path, budget(max_copied_bytes=0))
        path.open.assert_not_called()
        for raw in (b'{"records":[[[0]]]}', b'not JSON'):
            path = Mock()
            path.stat.return_value = types.SimpleNamespace(st_size=len(raw))
            path.open.return_value = io.BytesIO(raw)
            code = 'SOURCE_DATA_RESOURCE' if raw.startswith(b'{') else 'SOURCE_DATA_SCHEMA'
            with self.subTest(raw=raw), self.assertRaisesRegex(source_api().SourceDataError, code):
                _read_schema(path, budget(max_depth=1))

    def test_private_shared_module_identity_is_not_duck_typed(self):
        import types
        name = '_rax_smir_source_data_v1'
        actual = source_api()
        try:
            sys.modules[name] = types.SimpleNamespace(__file__='/tmp/foreign-source-data.py')
            with self.assertRaisesRegex(Reject, 'SOURCE_DATA_CONTEXT'):
                source_api()
        finally:
            sys.modules[name] = actual
        self.assertIs(source_api(), actual)

    def test_no_eager_preparation_or_implicit_budget(self):
        with patch('candidate.source_data_projection.prepare', side_effect=AssertionError('eager')):
            context = RootContext(roots())
        self.assertIsNone(context.source_stamp)
        self.assertFalse(context.abi_checked)
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_EVIDENCE_UNAVAILABLE'):
            context.source_data(ref(1), 0, 1, budget=budget())
        self.assertIsNone(context.source_stamp)

    def test_charged_same_walk_capture_matches_independent_canonical_hashes(self):
        document = roots()
        context, ledger = prepared(document)
        stamp = context.source_stamp
        expected = hashlib.sha256(json.dumps(records(), sort_keys=True, ensure_ascii=True,
                                           allow_nan=False, separators=(',', ':')).encode('ascii')).digest()
        self.assertEqual(stamp.schema_digest, expected)
        for section, digest in stamp.root_digests:
            self.assertEqual(digest, context._root_hashes[section])
        # Actual immutable fields came from the SAME values whose canonical bytes
        # were hashed; no metadata callback or ABI phase supplied them.
        frozen = context._source_roots[2]
        self.assertEqual(thaw(frozen), document[2])
        self.assertFalse(context.abi_checked)
        self.assertIs(context.prepare_source_data(budget=ledger), stamp)

    def test_canonical_schema_json_escaping_and_root_utf8_are_exact(self):
        from candidate.source_data_projection import _freeze_json
        value = {'records': ['quote"', 'backslash\\', '\x7f', '\u00e9', '\U0001f600', '\n']}
        ledger = budget()
        hasher = hashlib.sha256()
        frozen = _freeze_json(value, hasher, ledger)
        expected = json.dumps(value, ensure_ascii=True, sort_keys=True,
                              separators=(',', ':')).encode('ascii')
        self.assertEqual(hasher.digest(), hashlib.sha256(expected).digest())
        self.assertIs(type(frozen['records']), tuple)
        document = roots()
        document[2]['symbols'][1]['name'] = 'sym\u00e9\U0001f600'
        context, ledger = prepared(document)
        view = context.source_data(ref(1), 0, 1, budget=ledger)
        self.assertEqual(view.symbol_record.field('name'), document[2]['symbols'][1]['name'])

    def test_base_fixture_matches_actual_int023_rust_oracle(self):
        context, ledger = prepared()
        view = context.source_data(ref(1), 1, 3, budget=ledger)
        self.assertEqual((view.symbol, view.storage, view.offset, view.length),
                         (('self', 1), ('self', 12), 1, 3))
        self.assertEqual((view.symbol_extent, view.backing_extent,
                          view.symbol_alignment, view.backing_alignment), (4, 4, 1, 1))
        self.assertTrue(view.prefix.readonly)
        self.assertIs(type(view.prefix.obj), bytes)
        self.assertEqual((view.prefix.tobytes(), view.zero_tail_bytes), (b'\x02\x03', 1))
        self.assertEqual(view.read(0, 3, budget=ledger), b'\x02\x03\x00')
        self.assertEqual(hashlib.sha256(view.read(0, 3, budget=ledger)).hexdigest(),
                         '01ac26723cbcba804b62c46419db1c078912c2905c421b5be95ed5b3523cb78b')
        self.assertEqual([(p.tag, p.start, p.end, p.ordinal) for p in view.patches], [('leaf', 1, 2, 0)])
        self.assertEqual(thaw(view.patches[0].record), roots()[5]['relocations'][0])
        self.assertIs(view.stamp, context.source_stamp)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            view.symbol_extent = 99
        with self.assertRaises(TypeError):
            view.prefix[0] = 255

    def test_leaf_constant_full_original_records_and_no_execution(self):
        document = roots('constant-header')
        context, ledger = prepared(document)
        view = context.source_data(ref(1), 1, 2, budget=ledger)
        self.assertEqual(view.read(0, 2, budget=ledger), b'\x02\x03')
        self.assertEqual([(p.tag, p.start, p.end) for p in view.patches],
                         [('leaf', 1, 2), ('constant', 2, 3)])
        self.assertEqual(thaw(view.patches[0].record), document[5]['relocations'][0])
        self.assertEqual(thaw(view.patches[1].record), document[5]['constant_initializers'][0])
        self.assertIsNone(context.execution_checked)
        self.assertFalse(context.abi_checked)

    def test_huge_tail_and_bounded_reads_have_no_extent_allocation(self):
        context, ledger = prepared(name='huge-tail')
        extent = (1 << 61) - 1
        view = context.source_data(ref(1), extent - 8, 8, budget=ledger)
        self.assertEqual((view.prefix.tobytes(), view.zero_tail_bytes, view.patches), (b'', 8, ()))
        before = ledger._used_copied_bytes
        self.assertEqual(view.read(0, 8, budget=ledger), bytes(8))
        # Snapshot processing is charged as well as the8B output; extent2^61 is
        # symbolic and cannot contribute an extent-sized copy or traversal.
        self.assertLess(ledger._used_copied_bytes - before, 2**20)
        self.assertEqual(view.read(8, 0, budget=ledger), b'')

    def test_actual_storage_rejections_and_whole_backing_definedness(self):
        for name, code in [('mutable', 'RT_METADATA_INITIALIZED_READONLY'),
                           ('poison', 'RT_METADATA_INITIALIZED_READONLY'),
                           ('undef', 'RT_METADATA_INITIALIZED_READONLY'),
                           ('wrong-size', 'RT_METADATA_SYMBOL_EXTENT')]:
            with self.subTest(name=name):
                context, ledger = prepared(name=name)
                with self.assertRaisesRegex(Reject, code):
                    context.source_data(ref(1), 0, 1, budget=ledger)
        document = roots()
        # Poison outside queried slice still makes the WHOLE backing ineligible.
        document[4]['segments'][0]['poison'] = '000001'
        context, ledger = prepared(document)
        with self.assertRaisesRegex(Reject, 'RT_METADATA_INITIALIZED_READONLY'):
            context.source_data(ref(1), 0, 1, budget=ledger)

    def test_alias_tls_code_undefined_and_weak_missing_are_not_local_data(self):
        context, ledger = prepared()
        for identifier in (0, 2, 3, 4):
            with self.subTest(identifier=identifier), self.assertRaisesRegex(Reject, 'RT_METADATA_DEFINITION'):
                context.source_data(ref(identifier), 0, 1, budget=ledger)
        for definition in ({'kind': 'common', 'size': 4, 'alignment': 1},
                           {'kind': 'native', 'image': '00' * 32, 'domain': 0, 'offset': 0, 'size': 4}):
            document = roots()
            document[2]['symbols'][1]['definition'] = {'some': definition}
            candidate, candidate_budget = prepared(document)
            with self.subTest(definition=definition['kind']), self.assertRaisesRegex(Reject, 'RT_METADATA_DEFINITION'):
                candidate.source_data(ref(1), 0, 1, budget=candidate_budget)
        # Direct defined weak and COMDAT are declared inputs, never winner proof.
        document = roots()
        symbol = next(s for s in document[2]['symbols'] if s['id'] == 1)
        symbol['binding'], symbol['comdat'] = 'weak', {'some': 17}
        context, ledger = prepared(document)
        view = context.source_data(ref(1), 0, 1, budget=ledger)
        self.assertEqual(view.symbol_record.field('binding'), 'weak')
        self.assertEqual(view.symbol_record.field('comdat').field('some'), 17)

    def test_dependency_actual_owner_original_namespace_no_provider_bytes(self):
        document = roots()
        context, ledger = prepared(document)
        result = context.source_data(ref(99, 3), 123, 7, budget=ledger)
        self.assertEqual((result.tag, result.symbol, result.slot, result.declaration,
                          result.offset, result.length), ('dependency', ('dependency', 3, 99), 3, 99, 123, 7))
        self.assertEqual(thaw(result.expected), document[2]['manifest']['dependencies'][0]['declarations'][0])
        self.assertEqual(thaw(result.owner.key), document[2]['manifest']['dependencies'][0]['key'])
        self.assertEqual(result.owner.site, bytes.fromhex(document[2]['manifest']['dependencies'][0]['site']))
        for field in ('prefix', 'storage', 'patches', 'backing_extent', 'symbol_alignment', 'read'):
            self.assertFalse(hasattr(result, field))
        for reference in (ref(12, 3), ref(99, 4), ref(99)):
            with self.subTest(reference=reference), self.assertRaises(Reject):
                context.source_data(reference, 0, 1, budget=ledger)
        # The exact data declaration is required, not merely a colliding ID/type.
        document[2]['manifest']['dependencies'][0]['declarations'][0]['symbol_kind'] = 'tls'
        context, ledger = prepared(document)
        with self.assertRaisesRegex(Reject, 'RT_METADATA_DEFINITION'):
            context.source_data(ref(99, 3), 0, 1, budget=ledger)

    def test_missing_root5_is_unavailable_only_for_local_claim(self):
        document = roots()
        del document[5]
        context, ledger = prepared(document)
        self.assertEqual(context.source_data(ref(99, 3), 1, 1, budget=ledger).tag, 'dependency')
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_EVIDENCE_UNAVAILABLE'):
            context.source_data(ref(1), 0, 1, budget=ledger)

    def test_context_budget_identity_and_mutation_are_rechecked_on_reads(self):
        context, ledger = prepared()
        view = context.source_data(ref(1), 0, 1, budget=ledger)
        for action in (lambda: context.prepare_source_data(budget=budget()),
                       lambda: context.source_data(ref(1), 0, 1, budget=budget()),
                       lambda: view.read(0, 1, budget=budget())):
            with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_CONTEXT'):
                action()
        other, other_budget = prepared()
        self.assertEqual(context.source_stamp.root_digests, other.source_stamp.root_digests)
        self.assertIsNot(context.source_stamp, other.source_stamp)
        with self.assertRaises(AttributeError):
            context.source_stamp = None
        from candidate.source_data_projection import check_snapshot
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_CONTEXT'):
            check_snapshot(other, stamp=context.source_stamp, budget=other_budget)
        context.sections[4]['segments'][0]['initial'] = 'ffffff'
        for action in (lambda: view.read(0, 0, budget=ledger),
                       lambda: context.source_data(ref(1), 0, 1, budget=ledger)):
            with self.assertRaisesRegex(source_api().SourceDataError, 'context_snapshot_changed'):
                action()
        self.assertEqual(view.prefix.tobytes(), b'\x01')  # retained immutable A, never retagged B

    def test_active_schema_mutation_is_not_free_or_accepted(self):
        context, ledger = prepared()
        view = context.source_data(ref(1), 0, 1, budget=ledger)
        original = SCHEMA['records']['entity_ref']['fields']
        try:
            SCHEMA['records']['entity_ref']['fields'] = list(reversed(original))
            with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_SCHEMA'):
                view.read(0, 1, budget=ledger)
        finally:
            SCHEMA['records']['entity_ref']['fields'] = original

    def test_prepare_quota_depth_and_repeated_queries_cannot_reset_cost(self):
        for changes in (dict(max_work=0), dict(max_edges=0), dict(max_copied_bytes=0), dict(max_depth=1)):
            with self.subTest(changes=changes):
                context = RootContext(roots())
                with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_RESOURCE'):
                    context.prepare_source_data(budget=budget(**changes))
                self.assertIsNone(context.source_stamp)
                self.assertFalse(hasattr(context, '_source_roots'))
        context = RootContext(roots())
        ledger = budget(max_work=700000)
        context.prepare_source_data(budget=ledger)
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_RESOURCE'):
            for _ in range(100):
                context.source_data(ref(1), 0, 1, budget=ledger)
        self.assertIs(context._source_budget, ledger)
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_CONTEXT'):
            context.prepare_source_data(budget=budget())

    def test_ranges_are_exact_u64_and_partial_patches_are_preserved(self):
        context, ledger = prepared()
        for offset, length in ((0, 0), (-1, 1), (True, 1), (0, True), (2**64 - 1, 1)):
            with self.subTest(offset=offset, length=length), self.assertRaisesRegex(Reject, 'ABI_CC_METADATA_EXTENT'):
                context.source_data(ref(1), offset, length, budget=ledger)
        with self.assertRaisesRegex(Reject, 'RT_METADATA_EXTENT'):
            context.source_data(ref(1), 4, 1, budget=ledger)
        view = context.source_data(ref(1), 0, 2, budget=ledger)
        for offset, length in ((-1, 0), (True, 0), (0, -1), (2, 1), (2**64 - 1, 1)):
            with self.subTest(read=(offset, length)), self.assertRaisesRegex(source_api().SourceDataError, 'RT_METADATA_EXTENT'):
                view.read(offset, length, budget=ledger)
        document = roots()
        document[5]['relocations'][0]['width'] = 3
        context, ledger = prepared(document)
        partial = context.source_data(ref(1), 2, 1, budget=ledger)
        self.assertEqual([(p.start, p.end) for p in partial.patches], [(1, 4)])
        self.assertEqual(partial.read(0, 1, budget=ledger), b'\x03')

    def test_malformed_patch_bounds_zero_width_and_initializer_dependency(self):
        for field, value, code in [('width', 0, 'RT_PATCH_EXTENT'), ('width', 4, 'RT_RELOCATION_BOUNDS')]:
            document = roots()
            document[5]['relocations'][0][field] = value
            context, ledger = prepared(document)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(Reject, code):
                context.source_data(ref(1), 0, 1, budget=ledger)
        document = roots('constant-header')
        document[5]['constant_initializers'][0]['layout'] = ref(0, 3)
        context, ledger = prepared(document)
        with self.assertRaisesRegex(Reject, 'RT_INITIALIZER_SELF'):
            context.source_data(ref(1), 2, 1, budget=ledger)


if __name__ == '__main__':
    unittest.main()
