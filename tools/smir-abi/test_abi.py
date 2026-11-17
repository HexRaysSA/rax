"""ABI draft conformance: mathematical model, schemas, protocols and Clang oracle."""

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import threading
import unittest

from contract_json import check_named, decode, encode, loads, verify
from descriptors import canonical_hash, validate
from layout import ABIError, LayoutModel, MAX_OBJECT, SCALARS
from protocols import (ExceptionState, HEADER, Transitions, VA_LIST, VarArgs,
                       VarType, classify_signature, encode_varargs)
from witness import FIXTURES, TARGETS, compile_witness, compiler, run


def fixture(name):
    return loads((FIXTURES / name).read_text())


def one_type(record, language='c23'):
    return {'revision': 'abi-layout-draft-v1', 'language': language,
            'types': [record], 'roots': [record['id']]}


class LayoutTests(unittest.TestCase):
    def test_hand_derived_layouts(self):
        result = LayoutModel(fixture('layouts.json')).all()
        for name, expected in fixture('layout-expected.json').items():
            with self.subTest(name=name):
                actual = result[name]
                self.assertEqual((actual['size'], actual['align']),
                                 (expected['size'], expected['align']))
                self.assertEqual([field['offset_bits'] for field in actual['fields']],
                                 expected['offsets'])

    def test_every_scalar_has_fixed_host_independent_layout(self):
        for name, (size, align) in SCALARS.items():
            record = {'id': 'T', 'kind': 'scalar', 'name': name}
            with self.subTest(name=name):
                self.assertEqual(LayoutModel(one_type(record)).all()['T'],
                                 {'size': size, 'align': align})

    def test_bitint_all_storage_boundaries(self):
        widths = [1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                  127, 128, 129, 255, 256, 257, 65534, 65535]
        for bits in widths:
            for signed in (False, True):
                record = {'id': 'T', 'kind': 'bitint', 'bits': bits, 'signed': signed}
                if bits == 1 and signed:
                    with self.assertRaisesRegex(ABIError, 'ABI_RANGE'):
                        LayoutModel(one_type(record)).all()
                    continue
                actual = LayoutModel(one_type(record)).all()['T']
                # Independent piecewise table, rather than model's bit_ceil.
                align = 1 if bits <= 8 else 2 if bits <= 16 else 4 if bits <= 32 else 8
                self.assertEqual(actual, {'size': ((bits + align * 8 - 1) //
                                                  (align * 8)) * align, 'align': align})

    def test_enum_boundary_selection_and_fixed_range(self):
        expected = {'Esmall': 'int', 'Eunsigned': 'unsigned int',
                    'Esigned64': 'long', 'Efixed': 'u8'}
        result = LayoutModel(fixture('layouts.json')).all()
        for name, underlying in expected.items():
            self.assertEqual(result[name]['underlying'], underlying)
        for values, base in [(['-2147483648', '2147483647'], 'int'),
                             (['0', '4294967295'], 'unsigned int'),
                             (['-1', '4294967295'], 'long'),
                             (['18446744073709551615'], 'unsigned long')]:
            record = {'id': 'T', 'kind': 'enum', 'underlying': None, 'values': values}
            self.assertEqual(LayoutModel(one_type(record)).all()['T']['underlying'], base)
        document = fixture('layouts.json')
        document['types'][-1]['values'] = ['256']
        with self.assertRaisesRegex(ABIError, 'ABI_ENUM_RANGE'):
            LayoutModel(document).all()
        large = {'revision': 'abi-layout-draft-v1', 'language': 'c23', 'types': [
            {'id': 'B', 'kind': 'bitint', 'bits': 20000, 'signed': False},
            {'id': 'E', 'kind': 'enum', 'underlying': 'B', 'values': ['1' + '0' * 5000]}],
                 'roots': ['E']}
        self.assertEqual(LayoutModel(large).all()['E']['size'], 2504)

    def test_size_overflow_and_recursive_objects_reject(self):
        document = fixture('layouts.json')
        document['types'].append({'id': 'huge', 'kind': 'array',
                                  'element': 'double', 'count': MAX_OBJECT})
        with self.assertRaisesRegex(ABIError, 'ABI_SIZE_OVERFLOW'):
            LayoutModel(document).all()
        document['types'][-1] = {'id': 'huge', 'kind': 'array', 'element': 'huge', 'count': 1}
        with self.assertRaisesRegex(ABIError, 'ABI_RECURSIVE_OBJECT'):
            LayoutModel(document).all()

    def test_empty_cpp_and_wide_bitfield(self):
        empty = {'id': 'T', 'kind': 'struct', 'fields': [], 'align': 1}
        self.assertEqual(LayoutModel(one_type(empty, 'c++23')).all()['T'], {'size': 1, 'align': 1})
        with self.assertRaisesRegex(ABIError, 'ABI_EMPTY_C_RECORD'):
            LayoutModel(one_type(empty)).all()
        document = {'revision': 'abi-layout-draft-v1', 'language': 'c++23',
                    'types': [{'id': 'u8', 'kind': 'scalar', 'name': 'unsigned char'},
                              {'id': 'T', 'kind': 'struct', 'align': 1, 'fields': [
                                  {'name': 'a', 'type': 'u8', 'bits': 20},
                                  {'name': 'b', 'type': 'u8', 'bits': None}]}], 'roots': ['T']}
        result = LayoutModel(document).all()['T']
        self.assertEqual((result['size'], result['align']), (4, 2))
        self.assertEqual([field['offset_bits'] for field in result['fields']], [0, 24])

    def test_flexible_members_misuse_rejects(self):
        document = fixture('layouts.json')
        flexible = next(record for record in document['types'] if record['id'] == 'Flexible')
        flexible['fields'].reverse()
        with self.assertRaisesRegex(ABIError, 'ABI_FLEXIBLE_POSITION'):
            LayoutModel(document).all()

    def test_logical_call_classification_and_hidden_order(self):
        model = LayoutModel(fixture('layouts.json'))
        signature = classify_signature(model, ['int', 'Plain', 'vector3'], 'Plain',
                                       this=True, vtt=True, variadic=True)
        self.assertEqual([item['role'] for item in signature['arguments']],
                         ['result', 'this', 'vtt', 'parameter', 'parameter', 'parameter', 'varargs'])
        self.assertEqual([item['mode'] for item in signature['arguments']],
                         ['sret', 'direct', 'direct', 'direct', 'indirect-copy', 'direct', 'direct'])
        self.assertEqual(signature['results'], [])
        self.assertEqual(classify_signature(model, [], 'int')['results'], ['int'])
        with self.assertRaisesRegex(ABIError, 'ABI_UNADJUSTED_PARAMETER'):
            classify_signature(model, ['tail'])


class JSONTests(unittest.TestCase):
    def test_archived_primary_source_checksums(self):
        spec = FIXTURES.parents[1]
        rows = loads((spec / 'schema/abi/sources.json').read_text())
        self.assertEqual(len(rows), 10)
        for row in rows:
            with self.subTest(source=row['source_path']):
                self.assertEqual(hashlib.sha256((spec / row['archive_path']).read_bytes()).hexdigest(),
                                 row['sha256'])
                self.assertEqual(row['source_revision'], '36763294ef639d8a6a4379d81da653dda1c20686')
                self.assertEqual(row['license'], 'Apache-2.0 WITH LLVM-exception')

    def test_cli_positive_and_duplicate_key_rejection(self):
        root = Path(__file__).resolve().parents[2]
        tool = Path(__file__).resolve().parent
        commands = [
            [sys.executable, str(tool / 'layout.py'), str(FIXTURES / 'layouts.json')],
            [sys.executable, str(tool / 'descriptors.py'), str(FIXTURES / 'descriptor.json'),
             '--evidence', str(FIXTURES / 'descriptor-evidence.json')],
        ]
        for argv in commands:
            result = subprocess.run(argv, cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsInstance(loads(result.stdout), dict)
        with tempfile.TemporaryDirectory(prefix='abi-cli-', dir=os.environ.get('SMIR_ABI_TMP')) as directory:
            source = Path(directory) / 'duplicate.json'
            source.write_text('{"revision":"a","revision":"b"}')
            result = subprocess.run([sys.executable, str(tool / 'layout.py'), str(source)],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr.strip(), 'ABI_JSON_DUPLICATE')

    def test_schemas_accept_positive_and_reject_unknown_fields(self):
        for name, schema in [('layouts.json', 'layout.schema.json'),
                             ('descriptor.json', 'descriptor.schema.json')]:
            value = fixture(name)
            check_named(value, schema)
            for key in list(value):
                bad = copy.deepcopy(value)
                del bad[key]
                with self.assertRaises(ValueError):
                    check_named(bad, schema)
            value['unknown'] = 0
            with self.assertRaisesRegex(ValueError, 'unknown-key'):
                check_named(value, schema)

    def test_canonical_json_duplicate_float_and_truncation(self):
        payload = encode(fixture('descriptor.json'))
        self.assertEqual(decode(payload), fixture('descriptor.json'))
        for truncated in [payload[:index] for index in range(len(payload))]:
            with self.assertRaises((ValueError, UnicodeError)):
                decode(truncated)
        for bad in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}',
                    b'{ "a":1}', b'{"a":-0}', b'{"a":1}\n'):
            with self.assertRaises(ValueError):
                decode(bad)

    def test_schema_checker_fails_closed_on_unsupported_keywords(self):
        with self.assertRaisesRegex(ValueError, 'unsupported-schema'):
            verify(1, {'not': {'const': 1}})
        with self.assertRaisesRegex(ValueError, 'type'):
            verify(True, {'type': 'integer'})
        with self.assertRaisesRegex(ValueError, 'reference'):
            verify(1, {'$ref': 'https://example.invalid/schema'})
        with self.assertRaisesRegex(ValueError, 'unsupported-schema'):
            verify(1, {'anyOf': [{'const': 1}, {'not': {'const': 2}}]})


class DescriptorTests(unittest.TestCase):
    def test_positive_descriptor(self):
        self.assertEqual(validate(fixture('descriptor.json'), fixture('descriptor-evidence.json')),
                         {'domains': 2, 'types': 2, 'mappings': 1, 'calls': 1,
                          'admitted_for_execution': False})

    def test_negative_descriptor_fixture_corpus(self):
        cases = fixture('descriptor-negative.json')
        self.assertEqual(len(cases), 18)
        for case in cases:
            with self.subTest(name=case['name']):
                inputs = {'document': fixture('descriptor.json'),
                          'evidence': fixture('descriptor-evidence.json')}
                for change in case['changes']:
                    parent = inputs[change['side']]
                    for step in change['path'][:-1]:
                        parent = parent[step]
                    parent[change['path'][-1]] = change['value']
                with self.assertRaisesRegex(ABIError, case['error']):
                    validate(inputs['document'], inputs['evidence'])

    def test_polymorphic_layout_cannot_be_shared(self):
        document = fixture('descriptor.json')
        evidence = fixture('descriptor-evidence.json')
        for record in document['types']:
            record['layout']['rtti'] = 'a' * 64
            evidence['types'][record['id']] = copy.deepcopy(record)
        with self.assertRaisesRegex(ABIError, 'ABI_POLYMORPHIC_SHARING'):
            validate(document, evidence)

    def test_shared_ownership_requires_owner_retain_release(self):
        document = fixture('descriptor.json')
        evidence = fixture('descriptor-evidence.json')
        for index, record in enumerate(document['types']):
            record['ownership'] = 'shared'
            for operation, (field, role) in enumerate([
                    ('allocator', 'allocate'), ('deallocator', 'deallocate'),
                    ('retain', 'retain'), ('release', 'release')]):
                name = record['domain'] + '.' + field
                record[field] = name
                evidence['symbols'][name] = {'domain': record['domain'], 'role': role,
                                             'token': 4 + index * 8 + operation * 2}
            evidence['types'][record['id']] = copy.deepcopy(record)
        self.assertEqual(validate(document, evidence)['calls'], 1)
        evidence['symbols']['f.release']['token'] = evidence['symbols']['f.retain']['token']
        with self.assertRaisesRegex(ABIError, 'ABI_TOKEN_IDENTITY'):
            validate(document, evidence)
        evidence['symbols']['f.release']['token'] = 18
        document['types'][1]['release'] = None
        evidence['types']['fv']['release'] = None
        with self.assertRaisesRegex(ABIError, 'ABI_MISSING_METADATA'):
            validate(document, evidence)

    def test_mapped_exception_requires_registered_adapter(self):
        document = fixture('descriptor.json')
        evidence = fixture('descriptor-evidence.json')
        for record in document['types']:
            record['layout']['rtti'] = 'a' * 64
            evidence['types'][record['id']] = copy.deepcopy(record)
        mapping = document['mappings'][0]
        mapping.update(mode='adapt', alias='exclusive', identity='proxy',
                       adapter='foreign.adapt', typed_catch=True)
        evidence['symbols']['foreign.adapt'] = {'domain': 'f', 'role': 'adapter', 'token': 4}
        call = document['calls'][0]
        call['exceptions'] = 'mapped'
        evidence['symbols']['foreign.bridge']['signature'] = canonical_hash(
            {key: call[key] for key in ('params', 'result', 'variadic', 'exceptions')})
        self.assertEqual(validate(document, evidence)['calls'], 1)

    def test_every_cross_domain_type_requires_mapping(self):
        document = fixture('descriptor.json')
        document['calls'][0]['mappings'] = []
        with self.assertRaisesRegex(ABIError, 'ABI_MISSING_TYPE_MAPPING'):
            validate(document, fixture('descriptor-evidence.json'))


class ProtocolTests(unittest.TestCase):
    def test_varargs_borrowed_host_thread_keeps_original_owner(self):
        arena, original, leases = self.start([(1, (42).to_bytes(4, 'little'))])
        copied, revoked = original.copy(), original.copy()
        owner_host = threading.get_ident()
        def visit(cursor):
            payload = cursor.arg(1, arena, self.registry, thread=leases[7][0], leases=leases)
            return threading.get_ident(), payload
        with ThreadPoolExecutor(max_workers=1) as executor:
            host, payload = executor.submit(visit, copied).result(timeout=5)
            self.assertNotEqual(host, owner_host)
            self.assertEqual(payload, (42).to_bytes(4, 'little'))
            self.assertEqual((original.cursor, copied.cursor), (0, 40))
            leases.clear()
            with self.assertRaisesRegex(ABIError, 'ABI_VARARG_LIFETIME'):
                executor.submit(lambda: revoked.arg(1, arena, self.registry,
                    thread=3, leases=leases)).result(timeout=5)
        self.assertEqual(revoked.cursor, 0)

    def setUp(self):
        self.registry = {1: VarType(1, 4, 4, 'signed', 32),
                         2: VarType(2, 4, 4, 'unsigned', 32),
                         3: VarType(3, 8, 8, 'float'),
                         4: VarType(4, 32, 32),
                         5: VarType(5, 8, 8, 'pointer', pointer_kind='void'),
                         6: VarType(6, 8, 8, 'pointer', pointer_kind='char')}

    def start(self, entries):
        arena = encode_varargs(entries, self.registry)
        return arena, VarArgs(0x1000, 0, len(arena), 7), {7: (3, 0x1000, len(arena))}

    def test_varargs_layout_copy_and_end(self):
        self.assertEqual((HEADER.size, VA_LIST.size), (32, 32))
        arena, cursor, leases = self.start([(1, (42).to_bytes(4, 'little')),
                                            (4, bytes(range(32)))])
        clone = cursor.copy()
        self.assertEqual(len(cursor.encode()), 32)
        self.assertEqual(cursor.arg(1, arena, self.registry, thread=3, leases=leases), b'*\0\0\0')
        self.assertEqual(clone.cursor, 0)
        self.assertEqual(cursor.arg(4, arena, self.registry, thread=3, leases=leases), bytes(range(32)))
        cursor.end()
        self.assertEqual(cursor.encode(), bytes(32))
        with self.assertRaisesRegex(ABIError, 'ABI_VARARG_LIFETIME'):
            cursor.arg(1, arena, self.registry, thread=3, leases=leases)

    def test_varargs_compatible_signed_pair_and_void_char_pointer(self):
        arena, cursor, leases = self.start([(2, (42).to_bytes(4, 'little')),
                                            (5, bytes(8))])
        self.assertEqual(cursor.arg(1, arena, self.registry, thread=3, leases=leases), b'*\0\0\0')
        self.assertEqual(cursor.arg(6, arena, self.registry, thread=3, leases=leases), bytes(8))
        arena, cursor, leases = self.start([(2, (1 << 31).to_bytes(4, 'little'))])
        with self.assertRaisesRegex(ABIError, 'ABI_VARARG_TYPE_MISMATCH'):
            cursor.arg(1, arena, self.registry, thread=3, leases=leases)
        self.assertEqual(cursor.cursor, 0)

    def test_varargs_corruption_is_failure_atomic(self):
        arena, original, leases = self.start([(1, bytes(4))])
        cases = [(4, b'\x01', 'ABI_VARARG_RESERVED'),
                 (8, (8).to_bytes(8, 'little'), 'ABI_VARARG_SIZE'),
                 (16, (3).to_bytes(8, 'little'), 'ABI_VARARG_SIZE'),
                 (24, (1 << 63).to_bytes(8, 'little'), 'ABI_VARARG_BOUNDS'),
                 (36, b'\x01', 'ABI_VARARG_PADDING')]
        for offset, replacement, error in cases:
            with self.subTest(offset=offset):
                bad = bytearray(arena)
                bad[offset:offset + len(replacement)] = replacement
                cursor = original.copy()
                with self.assertRaisesRegex(ABIError, error):
                    cursor.arg(1, bytes(bad), self.registry, thread=3, leases=leases)
                self.assertEqual(cursor.cursor, 0)
        for thread, active_leases in [(4, leases), (3, {})]:
            with self.assertRaisesRegex(ABIError, 'ABI_VARARG_LIFETIME'):
                original.arg(1, arena, self.registry, thread=thread, leases=active_leases)

    def test_varargs_absolute_alignment_wrap_and_bitint_padding(self):
        arena, cursor, leases = self.start([(4, bytes(32))])
        cursor.area += 8
        leases[7] = (3, cursor.area, cursor.limit)
        with self.assertRaisesRegex(ABIError, 'ABI_VARARG_ALIGNMENT'):
            cursor.arg(4, arena, self.registry, thread=3, leases=leases)
        self.assertEqual(cursor.cursor, 0)
        cursor.area = (1 << 64) - 8
        leases[7] = (3, cursor.area, cursor.limit)
        with self.assertRaisesRegex(ABIError, 'ABI_VARARG_BOUNDS'):
            cursor.arg(4, arena, self.registry, thread=3, leases=leases)
        self.registry[7] = VarType(7, 16, 8, 'signed', 65)
        with self.assertRaisesRegex(ABIError, 'ABI_VARARG_VALUE'):
            encode_varargs([(7, bytes([255] * 16))], self.registry)
        arena, cursor, leases = self.start([(7, ((1 << 65) - 1).to_bytes(16, 'little'))])
        self.assertEqual(cursor.arg(7, arena, self.registry, thread=3, leases=leases),
                         ((1 << 65) - 1).to_bytes(16, 'little'))

    def test_callbacks_nested_threads_and_stale_generations(self):
        transitions = Transitions()
        first = transitions.enter(1, 'p', 'f', ['p', 'f'])
        callback = transitions.enter(1, 'f', 'p', ['p', 'f'])
        other = transitions.enter(2, 'p', 'f', ['f'])
        with self.assertRaisesRegex(ABIError, 'ABI_STALE_CONTINUATION'):
            transitions.leave(1, first)
        with self.assertRaisesRegex(ABIError, 'ABI_STALE_CONTINUATION'):
            transitions.leave(2, callback)
        transitions.leave(1, callback)
        transitions.abandon(1, 0)
        with self.assertRaisesRegex(ABIError, 'ABI_STALE_CONTINUATION'):
            transitions.leave(1, first)
        self.assertEqual(transitions.leases, {'p': 0, 'f': 1})
        transitions.leave(2, other)
        self.assertEqual(transitions.leases['f'], 0)

    def test_unwind_search_cleanup_rethrow_and_owner_destruction(self):
        frames = [{'metadata': True, 'cleanups': ['f2'], 'catch': None},
                  {'metadata': True, 'cleanups': ['p1-exit'], 'handler_cleanups': ['p1'], 'catch': '*'},
                  {'metadata': True, 'cleanups': ['f0-exit'], 'handler_cleanups': ['f0'], 'catch': '*'}]
        state = ExceptionState('foreign', None, frames)
        self.assertEqual(state.search(), 1)
        self.assertEqual(state.events, [('search',)])
        state.cleanup()
        self.assertEqual(state.events[1:3], [('cleanup', 0, 'f2'), ('cleanup', 1, 'p1')])
        state.retain()
        state.rethrow([{'metadata': True, 'cleanups': ['p1-catch'], 'catch': None}, frames[2]])
        self.assertEqual(state.search(), 1)
        state.cleanup()
        state.release()
        self.assertFalse(state.destroyed)
        state.release()
        self.assertEqual(state.events[-1], ('destroy', 'foreign'))

    def test_unwind_missing_metadata_cleanup_throw_and_forced_exit(self):
        with self.assertRaisesRegex(ABIError, 'ABI_UNWIND_METADATA'):
            ExceptionState('f', 'T', [{'metadata': False}]).search()
        frames = [{'metadata': True, 'cleanups': ['d'], 'handler_cleanups': ['d-pre'], 'catch': '*'}]
        state = ExceptionState('f', 'T', frames)
        state.search()
        state.cleanup(throwing_cleanup='d-pre')
        self.assertEqual(state.phase, 'terminated')
        state = ExceptionState('f', 'T', frames)
        self.assertIsNone(state.search(forced=True))
        state.cleanup()
        self.assertEqual(state.phase, 'forced-exit')
        self.assertNotIn(('catch', 0), state.events)
        state = ExceptionState('f', 'T', [{'metadata': True, 'catch': None,
                                         'cleanups': ['must-not-run'], 'escape': 'terminate'}])
        state.search()
        state.cleanup()
        self.assertEqual(state.events, [('search',), ('terminate', 'noexcept')])

    def test_exception_active_reference_and_destroyed_rethrow_reject(self):
        state = ExceptionState('f', 'T', [{'metadata': True, 'catch': '*', 'cleanups': []}])
        with self.assertRaisesRegex(ABIError, 'ABI_EXCEPTION_ACTIVE'):
            state.release()
        self.assertEqual(state.references, 1)
        state.search()
        state.cleanup()
        state.release()
        self.assertTrue(state.destroyed)
        with self.assertRaisesRegex(ABIError, 'ABI_UNWIND_PHASE'):
            state.rethrow([])


class CompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-abi-',
                                                      dir=os.environ.get('SMIR_ABI_TMP'))
        cls.addClassCleanup(cls.directory.cleanup)
        cls.path = Path(cls.directory.name)
        cls.receipt = run(cls.path / 'profiles')
        cls.clang, cls.version = compiler()

    def test_all_six_compiler_profiles_are_observed(self):
        expected = fixture('compiler-profiles.json')
        self.assertEqual(set(self.receipt['targets']), set(TARGETS))
        for target, rows in self.receipt['targets'].items():
            for language, result in rows.items():
                with self.subTest(target=target, language=language):
                    self.assertEqual(result['properties'], expected['targets'][target][language]['properties'])
                    layouts = {name: value for name, value in result['layouts'].items()
                               if not name.startswith('__')}
                    self.assertEqual(layouts, expected['targets'][target][language]['layouts'])
                    self.assertGreaterEqual(len(layouts), 10)

    def test_independent_c_layout_model_matches_comparison_target(self):
        layouts = self.receipt['targets'][TARGETS[0]]['c']['layouts']
        for name, expected in fixture('layout-expected.json').items():
            with self.subTest(name=name):
                self.assertEqual(layouts[name]['Size'], expected['size'] * 8)
                self.assertEqual(layouts[name]['Alignment'], expected['align'] * 8)
                self.assertEqual(layouts[name]['FieldOffsets'], expected['offsets'])

    def test_cpp_hand_derived_layouts_and_member_representations(self):
        result = self.receipt['targets'][TARGETS[0]]['cxx']
        self.assertEqual(result['properties'], [8, 8, 16, 8, 32, 8])
        layouts = result['layouts']
        for name, size, align, offsets in [('Empty', 1, 1, []), ('Ebo', 4, 4, [0]),
                                            ('Poly', 16, 8, [64]), ('Multi', 32, 8, [200]),
                                            ('Virtual', 32, 8, [64]), ('Nua', 4, 4, [0, 0]),
                                            ('Wide', 4, 2, [0, 24]), ('Repeated', 2, 1, [8]),
                                            ('BridgeFrame', 80, 16, [0,32,64,128,192,256,320,384,448,512,544,576])]:
            self.assertEqual((layouts[name]['Size'], layouts[name]['Alignment'],
                              layouts[name]['FieldOffsets']), (size * 8, align * 8, offsets))
        self.assertEqual(layouts['Multi']['BaseOffsets'], [0, 16])  # base offsets in bytes
        self.assertEqual(layouts['Virtual']['VBaseOffsets'], [16])
        ir = (self.path / 'profiles/0-cxx.ll').read_text()
        self.assertRegex(ir, r'@null_data = .*global i64 -1')
        self.assertRegex(ir, r'@null_method = .*global \{ i64, i64 \} zeroinitializer')
        self.assertRegex(ir, r'@virtual_method = .*global \{ i64, i64 \} \{ i64 1, i64 0 \}')
        self.assertRegex(ir, r'define .*void @portable_va_parameter\(ptr')
        for profile in self.receipt['targets'].values():
            self.assertEqual(profile['cxx']['properties'][4:], [32, 8])

    def test_seeded_bitfield_differential(self):
        rng = random.Random(0x41424901)
        records = [{'id': 'u8', 'kind': 'scalar', 'name': 'unsigned char'},
                   {'id': 'u16', 'kind': 'scalar', 'name': 'unsigned short'},
                   {'id': 'u32', 'kind': 'scalar', 'name': 'unsigned int'},
                   {'id': 'u64', 'kind': 'scalar', 'name': 'unsigned long'}]
        source = []
        roots = []
        for case in range(64):
            name = f'Random{case}'
            fields, declarations = [], []
            for index in range(8):
                bits, ident, c_type = rng.choice([(8,'u8','unsigned char'), (16,'u16','unsigned short'),
                                                  (32,'u32','unsigned'), (64,'u64','unsigned long')])
                width = rng.randrange(bits + 1)
                field_name = f'f{index}' if width else None
                fields.append({'name': field_name, 'type': ident, 'bits': width})
                declarations.append(f'{c_type} {field_name or ""}:{width};')
            fields.append({'name': 'tail', 'type': 'u8', 'bits': None})
            declarations.append('unsigned char tail;')
            records.append({'id': name, 'kind': 'struct', 'fields': fields, 'align': 1})
            roots.append(name)
            source.append('struct ' + name + ' { ' + ' '.join(declarations) + ' };')
        source.append('const unsigned long long abi_properties[] = {1};')
        path = self.path / 'random.c'
        path.write_text('\n'.join(source) + '\n')
        result = compile_witness(self.clang, TARGETS[0], path, self.path / 'random.ll')['layouts']
        model = LayoutModel({'revision':'abi-layout-draft-v1', 'language':'c23',
                             'types':records, 'roots':roots}).all()
        self.assertEqual(len(model), 64)
        for name, layout in model.items():
            with self.subTest(seed='0x41424901', name=name):
                self.assertEqual((layout['size'] * 8, layout['align'] * 8,
                                  [field['offset_bits'] for field in layout['fields']]),
                                 (result[name]['Size'], result[name]['Alignment'], result[name]['FieldOffsets']))

    def test_microsoft_wide_bitfield_diagnostic_is_explicit(self):
        source = self.path / 'wide.cpp'
        source.write_text('struct Wide { unsigned char value:20; };\n')
        result = subprocess.run([self.clang, '-target', 'x86_64-pc-windows-msvc',
                                 '-std=c++23', '-ffreestanding', '-nostdinc',
                                 '-fsyntax-only', str(source)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("width of bit-field 'value' (20 bits) exceeds the size of its type (8 bits)",
                      result.stderr)


if __name__ == '__main__':
    unittest.main()
