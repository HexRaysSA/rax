"""Actual native reference/category and rejection controls; never ABI evidence."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('smir_byte_reference', HERE / 'source_byte_categories.py')
M = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = M
spec.loader.exec_module(M)
FIXTURES = M.PACKAGE / 'docs/specifications/smir/portable/conformance/llvm/source-bytes'
CASES = {row['id']: row for row in json.loads((FIXTURES / 'cases.json').read_bytes())}


def budget(**limits):
    policy = dict(max_work=10**13, max_edges=10**9, max_copied_bytes=10**13, max_depth=128)
    policy.update(limits)
    return M.source_api().SourceQueryBudget(**policy)


def usage(b):
    return b._used_work, b._used_edges, b._used_copied_bytes


def build_digest(oracle):
    receipt = json.loads(oracle.receipt.read_bytes())
    manifest = {'format': 'rax-source-build', 'revision': 1,
                'source_inputs': [{'name': name, 'sha256': value} for name, value in sorted(receipt['input_hashes'].items())],
                'compiler': M.COMPILER, 'options': receipt['command'],
                'outputs': [{'name': 'source-byte-category-oracle', 'sha256': receipt['binary']['sha256']}]}
    return M.sha(M.canonical(manifest))


def seal(bundle):
    vectors = [{'name': row['name'], 'kind': row['kind'], 'bytes': len(bytes.fromhex(row['data'])),
                'sha256': M.sha(bytes.fromhex(row['data']))} for row in bundle['files']]
    backend = bundle['recipe']['common']['backend']
    backend['sysroot'] = M.sha(M.canonical([row for row in vectors if row['kind'] != 'source']))
    bundle['frontend'] = M.sha(b'RAX-SMIR-SOURCE-BACKEND-V1\x00' + M.canonical(backend))
    bundle['inputs'] = M.sha(M.canonical(vectors))
    bundle['options'] = M.sha(M.canonical(bundle['recipe']))
    return M.canonical(bundle)


def make_bundle(name, oracle):
    case = CASES[name]
    rows = [{'name': case['entry'], 'kind': 'source', 'data': (FIXTURES / case['source']).read_bytes().hex()}]
    if case['headers']:
        for row in json.loads((FIXTURES / 'headers-manifest.json').read_bytes()):
            data = (FIXTURES / row['file']).read_bytes()
            if M.sha(data) != row['sha256']:
                raise RuntimeError('Actual library fixture changed')
            rows.append({'name': row['name'], 'kind': row['kind'], 'data': data.hex()})
    rows.sort(key=lambda row: row['name'].encode('utf8'))
    flags = {'exceptions': case['language'] == 'cpp23', 'rtti': case['language'] == 'cpp23',
             'plain_char': 'signed', 'wchar_bits': 32, 'wchar_signed': True,
             'short_enums': False, 'ms_compatibility': False, 'fp_contract': 'off',
             'fast_math': False, 'signed_overflow': 'language_undefined',
             'threadsafe_statics': True, 'diagnostics': 'default_at_pin',
             'input_encoding': 'utf8', 'execution_encoding': 'utf8'}
    actual = build_digest(oracle)
    backend = {'llvm_commit': M.PIN, 'frontend_build': actual, 'projector_build': M.projector_identity(actual),
               'projection_protocol': 'rax-source-projection-v1', 'target_contract': M.digest(M.TARGET),
               'sysroot': '0' * 64}
    common = {'language': case['language'], 'entry': case['entry'], 'dialect': 'strict', 'optimization': 0,
              'macros': [], 'includes': [{'kind': 'system', 'path': ['libcxx']}, {'kind': 'system', 'path': ['generated']}] if case['headers'] else [],
              'forced_includes': [], 'modules': [], 'flags': flags, 'backend': backend}
    recipe = {'kind': 'lp64-ast-surrogate-v1', 'common': common,
              'triple': 'x86_64-unknown-linux-gnu', 'observational_only': True}
    bundle = {'format': 'rax-smir-source-evidence-bundle', 'revision': 1, 'language': case['language'],
              'frontend': '0' * 64, 'options': '0' * 64, 'inputs': '0' * 64, 'recipe': recipe, 'files': rows}
    return seal(bundle), copy.deepcopy(case['selectors'])


class Pure(unittest.TestCase):
    def test_error_type_closed_and_read_only(self):
        error = M.ByteObservationError('semantic', 'BYTE_OBSERVATION_INPUT', 'bad')
        self.assertEqual((error.kind, error.code, error.detail), ('semantic', 'BYTE_OBSERVATION_INPUT', 'bad'))
        with self.assertRaises(AttributeError):
            error._kind = 'resource'
        with self.assertRaises(ValueError):
            M.ByteObservationError('semantic', 'UNKNOWN')

    def test_error_constructor_never_calls_nonplain_equality(self):
        class Evil:
            def __eq__(self, other):
                raise AssertionError('nonplain equality executed')
        with self.assertRaises(ValueError):
            M.ByteObservationError(Evil(), 'BYTE_OBSERVATION_INPUT')

    def test_exact_keys_never_rehash_nonplain_key(self):
        class Key:
            calls = 0
            def __hash__(self):
                self.calls += 1
                return 1
            def __eq__(self, other):
                raise AssertionError('key equality executed')
        key = Key()
        value = {key: 0}
        count = key.calls
        with self.assertRaises(M.ByteObservationError):
            M.exact(value, ('file',))
        self.assertEqual(key.calls, count)

    def test_zero_budget_before_selector_callback(self):
        class Evil:
            def __eq__(self, other):
                raise AssertionError('nonplain equality executed')
        with self.assertRaises(M.source_api().SourceDataError) as caught:
            M.observe_byte_categories(b'{}', [{'file': 'x', 'offset': 0, 'kind': Evil()}], oracle=None, budget=budget(max_work=0))
        self.assertEqual(caught.exception.kind, 'resource')

    def test_nonplain_kind_rejected_without_equality(self):
        class Evil:
            def __eq__(self, other):
                raise AssertionError('nonplain equality executed')
        with self.assertRaises(M.ByteObservationError):
            M.bounded_plain([{'file': 'x', 'offset': 0, 'kind': Evil()}], budget())

    def test_oversized_selector_before_serialization(self):
        with mock.patch.object(M, 'canonical', wraps=M.canonical) as encode:
            with self.assertRaises(M.ByteObservationError) as caught:
                M.bounded_plain([{'file': 'x' * (M.MAX_REQUEST + 1), 'offset': 0, 'kind': 'var'}], budget())
            self.assertEqual(caught.exception.kind, 'resource')
            self.assertEqual(encode.call_count, 0)

    def test_bool_offset_rejected(self):
        with self.assertRaises(M.ByteObservationError):
            M.bounded_plain([{'file': 'x', 'offset': True, 'kind': 'var'}], budget())

    def test_wrong_budget_reference(self):
        with self.assertRaises(M.ByteObservationError) as caught:
            M.observe_byte_categories(b'{}', [], oracle=None, budget=None)
        self.assertEqual(caught.exception.code, 'BYTE_OBSERVATION_BUDGET_REFERENCE')

    def test_strict_json_duplicate_float_and_noncanonical(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{ "x":1}'):
            with self.subTest(raw=raw), self.assertRaises(M.ByteObservationError):
                M.strict_json(raw, budget())

    def test_schema_u64_exact_and_bool_rejection(self):
        schema = json.loads(M.SCHEMA.read_bytes())
        rule = schema['$defs']['row']['properties']['storage_bits']
        M.validate_schema(rule, 1 << 55, schema['$defs'], budget())
        self.assertEqual(json.loads(M.canonical(1 << 55)), 1 << 55)
        for value in (True, 1 << 64, float(1 << 55)):
            with self.subTest(value=value), self.assertRaises(M.ByteObservationError):
                M.validate_schema(rule, value, schema['$defs'], budget())


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary, receipt = os.environ.get('SMIR_BYTE_ORACLE'), os.environ.get('SMIR_BYTE_BUILD_RECEIPT')
        if not binary or not receipt:
            raise unittest.SkipTest('native category tests require explicit pinned oracle/build receipt')
        cls.oracle = M.NativeOracle(Path(binary), Path(receipt))
        root = Path(os.environ['SMIR_BYTE_ARTIFACT_ROOT'])
        root.mkdir(exist_ok=False)
        cls.artifacts = root
        cls.serial = 0

    @contextmanager
    def private_schema(self, label):
        path = self.artifacts / (label + '.schema.json')
        path.write_bytes(M.SCHEMA.read_bytes())
        with mock.patch.object(M, 'SCHEMA', path):
            yield path

    @contextmanager
    def trace_schema_guards(self, path, *, before_first=None):
        scan = M.bounded_guard_digest
        original_open = Path.open
        rows = []
        class Reader:
            def __init__(self, stream, row):
                self.stream, self.row = stream, row
            def __enter__(self):
                self.stream.__enter__()
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def read(self, size):
                data = self.stream.read(size)
                self.row['reads'].append({'requested': size, 'returned': len(data), 'underlying_position': self.stream.tell()})
                return data
        def traced(candidate, captured_size):
            if Path(candidate).resolve() != path.resolve():
                return scan(candidate, captured_size)
            if not rows and before_first is not None:
                before_first()
            row = {'captured_size': captured_size, 'reads': []}
            rows.append(row)
            def opened(candidate, *args, **kw):
                stream = original_open(candidate, *args, **kw)
                if Path(candidate).resolve() == path.resolve():
                    row['raw_unbuffered'] = isinstance(stream, io.FileIO)
                    return Reader(stream, row)
                return stream
            with mock.patch.object(Path, 'open', opened):
                result = scan(candidate, captured_size)
            row['total_requested'] = sum(item['requested'] for item in row['reads'])
            row['total_returned'] = sum(item['returned'] for item in row['reads'])
            row['size_matches'] = result is not None
            return result
        with mock.patch.object(M, 'bounded_guard_digest', traced):
            yield rows
        for row in rows:
            self.assertTrue(row['raw_unbuffered'])
            self.assertTrue(all(item['underlying_position'] <= row['captured_size'] + 1 for item in row['reads']))
            self.assertLessEqual(row['total_requested'], row['captured_size'] + 1)
            self.assertLessEqual(row['total_returned'], row['captured_size'] + 1)
        (self.artifacts / (path.stem + '.guard-reads.json')).write_bytes(M.canonical(rows))

    def test_initial_guard_growth_is_bounded_before_native(self):
        with self.private_schema('initial-growth') as path:
            original_size = path.stat().st_size
            def grow():
                with path.open('ab') as stream:
                    stream.write(b' ' * (1 << 20))
            with self.trace_schema_guards(path, before_first=grow) as rows, mock.patch.object(M, 'native_run', wraps=M.native_run) as native:
                self.error('clock', 'BYTE_OBSERVATION_CHANGED')
            self.assertEqual(native.call_count, 0)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['captured_size'], original_size)
            self.assertEqual(rows[0]['total_returned'], original_size + 1)
            self.assertFalse(rows[0]['size_matches'])

    def test_after_guard_growth_is_bounded_on_success_and_native_error(self):
        run = M.native_run
        for case in ('clock', 'fake-library'):
            with self.subTest(case=case), self.private_schema('after-growth-' + case) as path:
                original_size = path.stat().st_size
                native_results = []
                def grow(*args, **kw):
                    result = run(*args, **kw)
                    native_results.append(result[0])
                    with path.open('ab') as stream:
                        stream.write(b' ' * (1 << 20))
                    return result
                with self.trace_schema_guards(path) as rows, mock.patch.object(M, 'native_run', grow):
                    self.error(case, 'BYTE_OBSERVATION_CHANGED')
                self.assertEqual(len(native_results), 1)
                self.assertEqual(native_results[0], 0 if case == 'clock' else 3)
                self.assertEqual(len(rows), 2)
                self.assertTrue(rows[0]['size_matches'])
                self.assertEqual(rows[1]['captured_size'], original_size)
                self.assertEqual(rows[1]['total_returned'], original_size + 1)
                self.assertFalse(rows[1]['size_matches'])

    def test_after_guard_growth_with_resource_keeps_original_cause(self):
        with self.private_schema('resource-growth') as path:
            original_size = path.stat().st_size
            baseline = budget()
            self.observe('clock', ledger=baseline)
            limits = dict(zip(('max_work', 'max_edges', 'max_copied_bytes'), usage(baseline)))
            limits['max_copied_bytes'] -= 1
            run = M.native_run
            charge = M.source_api().SourceQueryBudget.charge
            resources = []
            native_results = []
            def grow(*args, **kw):
                result = run(*args, **kw)
                native_results.append(result[0])
                with path.open('ab') as stream:
                    stream.write(b' ' * (1 << 20))
                return result
            def observe_charge(ledger, **counts):
                try:
                    return charge(ledger, **counts)
                except M.source_api().SourceDataError as error:
                    resources.append((error, error.kind, error.code, error.detail))
                    raise
            with self.trace_schema_guards(path) as rows, mock.patch.object(M, 'native_run', grow), mock.patch.object(M.source_api().SourceQueryBudget, 'charge', observe_charge):
                error = self.error('clock', 'BYTE_OBSERVATION_CHANGED', ledger=budget(**limits))
            self.assertEqual(native_results, [0])
            self.assertTrue(resources)
            original, kind, code, detail = resources[-1]
            self.assertIs(error.__cause__, original)
            self.assertEqual((original.kind, original.code, original.detail), (kind, code, detail))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1]['captured_size'], original_size)
            self.assertEqual(rows[1]['total_returned'], original_size + 1)
            self.assertFalse(rows[1]['size_matches'])

    def observe(self, case, *, raw=None, selected=None, ledger=None):
        normal, selectors = make_bundle(case, self.oracle)
        raw = normal if raw is None else raw
        selected = selectors if selected is None else selected
        self.__class__.serial += 1
        tag = str(self.serial) + '-' + case
        (self.artifacts / (tag + '.bundle.json')).write_bytes(raw)
        (self.artifacts / (tag + '.selectors.json')).write_bytes(M.canonical(selected))
        try:
            out = M.observe_byte_categories(raw, selected, oracle=self.oracle, budget=ledger or budget())
        except BaseException as error:
            (self.artifacts / (tag + '.error.json')).write_bytes(M.canonical({'class': type(error).__name__, 'kind': getattr(error, 'kind', None), 'code': getattr(error, 'code', None), 'detail': getattr(error, 'detail', str(error)), 'cause': getattr(getattr(error, '__cause__', None), 'code', None)}))
            raise
        (self.artifacts / (tag + '.output.json')).write_bytes(out.json_bytes)
        d = json.loads(out.json_bytes)
        self.assertEqual(d['binding'], 'unbound')
        for flag in ('semantic_admission', 'source_fact_authority', 'runtime_authority'):
            self.assertIs(d[flag], False)
        return d

    def error(self, case, code, **kw):
        with self.assertRaises(M.ByteObservationError) as caught:
            self.observe(case, **kw)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_real_pinned_library_and_alias(self):
        d = self.observe('library')
        self.assertEqual([row['category'] for row in d['rows']], ['std_byte', 'std_byte'])
        for row in d['rows']:
            self.assertEqual(row['declaration']['file'], 'libcxx/__fwd/byte.h')
            self.assertEqual(row['declaration']['offset'], 612)
            self.assertEqual(row['library_definition']['file'], 'libcxx/__cstddef/byte.h')
            self.assertEqual(row['library_definition']['offset'], 720)
        self.assertEqual(d['rows'][1]['cv'], 'const')

    def test_cpp_scalar_metrics_and_huge_objects(self):
        d = self.observe('scalar-cpp')
        rows = d['rows']
        self.assertEqual([r['category'] for r in rows[:6]], ['char', 'signed_char', 'unsigned_char', 'char8_t', 'unsigned_char', 'numeric'])
        self.assertEqual(rows[4]['cv'], 'const_volatile')
        self.assertEqual((rows[5]['value_bits'], rows[5]['storage_bits']), (1, 8))
        for index in (10, 11, 12):
            self.assertIsNone(rows[index]['value_bits'])
            self.assertIsNone(rows[index]['signed'])
        self.assertEqual(rows[12]['storage_bits'], 128)
        self.assertEqual((rows[13]['value_bits'], rows[13]['storage_bits']), (None, 64))
        for index in (14, 15, 16, 17):
            self.assertEqual((rows[index]['value_bits'], rows[index]['storage_bits'], rows[index]['alignment_bits']), (None, None, None))
        self.assertEqual((rows[18]['category'], rows[18]['value_bits'], rows[18]['storage_bits']), ('unsupported', None, 32))
        self.assertEqual(rows[19]['storage_bits'], 1 << 43)
        self.assertEqual(rows[20]['storage_bits'], 1 << 55)
        self.assertEqual([rows[i]['category'] for i in (21, 22)], ['unsigned_char', 'unsigned_char'])

    def test_c23_alias_bitint_atomic_vla(self):
        rows = self.observe('scalar-c')['rows']
        self.assertEqual([r['category'] for r in rows[3:6]], ['unsigned_char', 'unsigned_char', 'signed_char'])
        self.assertEqual(rows[6]['value_bits'], 1)
        self.assertEqual([r['value_bits'] for r in rows[7:12]], [1, 8, 9, 17, 65])
        self.assertEqual((rows[12]['category'], rows[12]['value_bits'], rows[12]['storage_bits']), ('unsupported', None, 8))
        self.assertEqual((rows[13]['storage_bits'], rows[13]['alignment_bits']), (None, None))

    def test_fake_library_rejected(self):
        self.error('fake-library', 'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE')

    def test_user_forward_rejected(self):
        self.error('user-forward', 'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE')

    def test_real_forward_without_definition_rejected(self):
        self.error('missing-definition', 'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE')

    def test_changed_library_bytes_even_resigned_rejected(self):
        raw, _ = make_bundle('library', self.oracle)
        d = json.loads(raw)
        row = next(row for row in d['files'] if row['name'] == 'libcxx/__cstddef/byte.h')
        row['data'] += '0a'
        self.error('library', 'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE', raw=seal(d))

    def test_clock_and_physical_line_coordinates(self):
        with mock.patch.dict(os.environ, {'SOURCE_DATE_EPOCH': 'invalid', 'TZ': 'Pacific/Honolulu'}):
            self.assertEqual(self.observe('clock')['rows'][0]['category'], 'char')
        row = self.observe('line')['rows'][0]
        self.assertEqual(row['selector'], CASES['line']['selectors'][0])
        self.assertNotIn('pretend', row['selector']['file'])

    def test_protected_source_macro_rejected(self):
        self.error('protected', 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE')

    def test_missing_header_unavailable(self):
        self.error('missing-header', 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE')

    def test_macro_location_rejected(self):
        self.error('macro', 'BYTE_OBSERVATION_LOCATION')

    def test_unsupported_module_recipe_before_native(self):
        raw, _ = make_bundle('scalar-c', self.oracle)
        d = json.loads(raw)
        d['recipe']['common']['modules'] = [{'name': 'X', 'kind': 'cxx_module', 'producer_unit': '0' * 64, 'import_name': 'X'}]
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('scalar-c', 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', raw=seal(d))
            self.assertEqual(run.call_count, 0)

    def test_portable_recipe_never_uses_surrogate(self):
        raw, _ = make_bundle('scalar-c', self.oracle)
        d = json.loads(raw)
        d['recipe']['kind'] = 'smir-source-v1'
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('scalar-c', 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', raw=seal(d))
            self.assertEqual(run.call_count, 0)

    def test_duplicate_selector_and_bool_revision_before_native(self):
        raw, selected = make_bundle('scalar-c', self.oracle)
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('scalar-c', 'BYTE_OBSERVATION_INPUT', selected=selected + selected)
            d = json.loads(raw)
            d['revision'] = True
            self.error('scalar-c', 'BYTE_OBSERVATION_INPUT', raw=seal(d))
            self.assertEqual(run.call_count, 0)

    def test_recipe_macro_protected_before_native(self):
        raw, _ = make_bundle('scalar-c', self.oracle)
        d = json.loads(raw)
        d['recipe']['common']['macros'] = [{'kind': 'undef', 'name': '__TIME__'}]
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('scalar-c', 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', raw=seal(d))
            self.assertEqual(run.call_count, 0)

    def test_budget_exact_one_less_and_original_resource(self):
        b = budget()
        expected = self.observe('clock', ledger=b)
        limits = dict(zip(('max_work', 'max_edges', 'max_copied_bytes'), usage(b)))
        self.assertEqual(self.observe('clock', ledger=budget(**limits)), expected)
        for dimension in limits:
            smaller = dict(limits)
            smaller[dimension] -= 1
            with self.subTest(dimension=dimension), self.assertRaises(M.source_api().SourceDataError) as caught:
                self.observe('clock', ledger=budget(**smaller))
            self.assertEqual((caught.exception.kind, caught.exception.code), ('resource', 'SOURCE_DATA_RESOURCE'))

    def test_dual_resource_and_changed_input(self):
        b = budget()
        self.observe('clock', ledger=b)
        limits = dict(zip(('max_work', 'max_edges', 'max_copied_bytes'), usage(b)))
        limits['max_copied_bytes'] -= 1
        original_schema = M.SCHEMA.read_bytes()
        run = M.native_run
        charge = M.source_api().SourceQueryBudget.charge
        resources = []
        def observe_charge(ledger, **counts):
            try:
                return charge(ledger, **counts)
            except M.source_api().SourceDataError as error:
                resources.append((error, error.kind, error.code, error.detail))
                raise
        def changed(*args, **kw):
            result = run(*args, **kw)
            M.SCHEMA.write_bytes(original_schema + b'\n')
            return result
        try:
            with mock.patch.object(M, 'native_run', changed), mock.patch.object(M.source_api().SourceQueryBudget, 'charge', observe_charge):
                error = self.error('clock', 'BYTE_OBSERVATION_CHANGED', ledger=budget(**limits))
            self.assertTrue(resources)
            original, kind, code, detail = resources[-1]
            self.assertIs(error.__cause__, original)
            self.assertEqual((original.kind, original.code, original.detail), (kind, code, detail))
        finally:
            M.SCHEMA.write_bytes(original_schema)

    def test_afterguard_on_success_and_native_error(self):
        run = M.native_run
        original = M.SCHEMA.read_bytes()
        def changed(*args, **kw):
            result = run(*args, **kw)
            M.SCHEMA.write_bytes(original + b'\n')
            return result
        try:
            for case in ('clock', 'fake-library'):
                with self.subTest(case=case), mock.patch.object(M, 'native_run', changed):
                    self.error(case, 'BYTE_OBSERVATION_CHANGED')
                M.SCHEMA.write_bytes(original)
        finally:
            M.SCHEMA.write_bytes(original)

    def test_native_unknown_status_and_invalid_output(self):
        run = M.native_run
        def malformed(*args, **kw):
            status, stdout, stderr = run(*args, **kw)
            return status, b'{"format":"unknown"}', stderr
        with mock.patch.object(M, 'native_run', malformed):
            self.error('clock', 'BYTE_OBSERVATION_ORACLE_PROTOCOL')

    def test_native_row_corruption_not_permission(self):
        run = M.native_run
        def corrupt(*args, **kw):
            status, stdout, stderr = run(*args, **kw)
            d = json.loads(stdout)
            d['rows'][0]['storage_bits'] = True
            return status, M.canonical(d), stderr
        with mock.patch.object(M, 'native_run', corrupt):
            self.error('clock', 'BYTE_OBSERVATION_ORACLE_PROTOCOL')

    def test_ordinary_resource_preserves_same_object(self):
        initial = budget()
        self.observe('clock', ledger=initial)
        limits = dict(zip(('max_work', 'max_edges', 'max_copied_bytes'), usage(initial)))
        limits['max_copied_bytes'] -= 1
        charge = M.source_api().SourceQueryBudget.charge
        saved = []
        def observe_charge(ledger, **counts):
            try:
                return charge(ledger, **counts)
            except M.source_api().SourceDataError as error:
                saved.append(error)
                raise
        with mock.patch.object(M.source_api().SourceQueryBudget, 'charge', observe_charge):
            with self.assertRaises(M.source_api().SourceDataError) as caught:
                self.observe('clock', ledger=budget(**limits))
        self.assertIs(caught.exception, saved[-1])
        self.assertIsNone(caught.exception.__cause__)

    def test_bounded_actual_native_timeout(self):
        with mock.patch.object(M, 'NATIVE_TIMEOUT_SECONDS', 0):
            self.error('clock', 'BYTE_OBSERVATION_RESOURCE')

    def test_forced_header_and_ordered_recipe_macros(self):
        raw, _ = make_bundle('clock', self.oracle)
        d = json.loads(raw)
        text = '#if PICK\nunsigned char picked;\n#else\nsigned char picked;\n#endif\n'
        main = next(row for row in d['files'] if row['kind'] == 'source')
        main['data'] = text.encode().hex()
        d['files'].append({'name': 'forced.h', 'kind': 'header', 'data': b'// actual forced header\n'.hex()})
        d['files'].sort(key=lambda row: row['name'])
        common = d['recipe']['common']
        common['forced_includes'] = ['forced.h']
        common['macros'] = [{'kind': 'define', 'name': 'PICK', 'parameters': None, 'variadic': False, 'replacement': '0'},
                            {'kind': 'undef', 'name': 'PICK'},
                            {'kind': 'define', 'name': 'PICK', 'parameters': None, 'variadic': False, 'replacement': '1'}]
        selected = [{'file': main['name'], 'offset': text.index('picked'), 'kind': 'var'}]
        rows = self.observe('clock', raw=seal(d), selected=selected)['rows']
        self.assertEqual(rows[0]['category'], 'unsigned_char')

    def test_nonplain_macro_params_closed_error(self):
        raw, _ = make_bundle('clock', self.oracle)
        d = json.loads(raw)
        d['recipe']['common']['macros'] = [{'kind': 'define', 'name': 'BAD', 'parameters': [{}], 'variadic': False, 'replacement': '0'}]
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('clock', 'BYTE_OBSERVATION_INPUT', raw=seal(d))
            self.assertEqual(run.call_count, 0)

    def test_unicode_virtual_filename(self):
        raw, _ = make_bundle('clock', self.oracle)
        d = json.loads(raw)
        main = d['files'][0]
        main['name'] = 'micro-\u00b5.cpp'
        text = 'unsigned char unicode_value;\n'
        main['data'] = text.encode().hex()
        d['recipe']['common']['entry'] = main['name']
        selected = [{'file': main['name'], 'offset': text.index('unicode_value'), 'kind': 'var'}]
        row = self.observe('clock', raw=seal(d), selected=selected)['rows'][0]
        self.assertEqual(row['selector']['file'], main['name'])
        self.assertEqual(row['category'], 'unsigned_char')

    def test_changed_native_config_resigned_before_native(self):
        raw, _ = make_bundle('library', self.oracle)
        d = json.loads(raw)
        config = next(row for row in d['files'] if row['name'] == 'generated/__config_site')
        config['data'] += '0a'
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('library', 'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE', raw=seal(d))
            self.assertEqual(run.call_count, 0)

    def test_missing_native_config_resigned_before_native(self):
        raw, _ = make_bundle('library', self.oracle)
        d = json.loads(raw)
        d['files'] = [row for row in d['files'] if row['name'] != 'generated/__config_site']
        with mock.patch.object(M, 'native_run', wraps=M.native_run) as run:
            self.error('library', 'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE', raw=seal(d))
            self.assertEqual(run.call_count, 0)


if __name__ == '__main__':
    unittest.main()
