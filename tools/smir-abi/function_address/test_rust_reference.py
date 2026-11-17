"""Offline independent Rust/Python source-graph differential, no admission proof."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from function_address.hash_v3 import Budget, HashError, SourceGraph
from function_address.test_hash_v3 import SOURCE, VECTORS, budget, geometry, ref, some, source_pair, source_type

ROOT = Path(__file__).resolve().parents[3]
LLVM = ROOT.parent / 'llvm-project'
PACKAGE = Path(__file__).resolve().parent / 'rust_reference'
LIMITS = dict(max_work=1_000_000_000, max_edges=1_000_000, max_bytes=512_000_000,
              max_depth=128, max_nodes=4096, max_input_bytes=1_048_576,
              max_output_bytes=1_048_576)


def outside(path):
    path = Path(path).expanduser().resolve()
    if any(path == root or root in path.parents for root in (ROOT, LLVM)):
        raise ValueError('V3 reference output/binary must be outside RAX and LLVM checkouts')
    return path


class RustReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        cls.cases = []
        parent = os.environ.get('SMIR_ABI_V3_REFERENCE_TMP') or os.environ.get('SMIR_ABI_TMP')
        if parent:
            cls.output = outside(parent)
            cls.output.mkdir(parents=True, exist_ok=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='smir-abi-v3-')
            cls.output = outside(cls.temporary.name)
        sources = [PACKAGE / 'Cargo.toml', PACKAGE / 'Cargo.lock',
                   *sorted((PACKAGE / 'src').glob('*.rs'))]
        cls.before = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        explicit = os.environ.get('SMIR_ABI_V3_REFERENCE_BIN')
        if explicit:
            cls.binary = outside(explicit)
            cls.build = {'override': str(cls.binary)}
        else:
            target = outside(os.environ.get('CARGO_TARGET_DIR') or cls.output / 'cargo-target')
            argv = ['cargo', 'build', '--offline', '--locked', '--manifest-path',
                    str(PACKAGE / 'Cargo.toml'), '--target-dir', str(target)]
            env = {**os.environ, 'CARGO_NET_OFFLINE': 'true', 'CARGO_TARGET_DIR': str(target)}
            result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True)
            (cls.output / 'rust-build.log').write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError('offline reference build failed: ' + result.stderr[-4000:])
            cls.binary = outside(target / 'debug' / ('smir-abi-v3-reference.exe' if os.name == 'nt' else 'smir-abi-v3-reference'))
            cls.build = {'argv': argv, 'exit_code': result.returncode, 'target': str(target)}
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise RuntimeError('independent reference binary is missing/not executable: ' + str(cls.binary))
        cls.binary_sha = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

    @classmethod
    def tearDownClass(cls):
        after = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in cls.before}
        receipt = {'binary': str(cls.binary), 'binary_sha256': cls.binary_sha, 'build': cls.build,
                   'sources_before': cls.before, 'sources_after': after,
                   'source_drift': [p for p in after if after[p] != cls.before[p]],
                   'cases': cls.cases, 'scope': 'Independent unconsumed mathematical source hash; no private ABI/execution/native proof.'}
        (cls.output / 'rust-differential-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        if after != cls.before:
            raise RuntimeError('Rust source changed during differential suite')
        if hashlib.sha256(cls.binary.read_bytes()).hexdigest() != cls.binary_sha:
            raise RuntimeError('Rust binary changed during differential suite')
        if cls.temporary:
            cls.temporary.cleanup()

    def request(self, document, identifier, *, view='DEF', ignore_top_cv=False, expectations=None):
        return {'documents': {'main': document}, 'expectations': expectations or [],
                'owner': 'main', 'root': ref(identifier), 'view': view, 'ignore_top_cv': ignore_top_cv}

    def run_rust(self, request, *, limits=None, raw=None):
        policy = {**LIMITS, **(limits or {})}
        header = json.dumps(policy, separators=(',', ':')).encode() + b'\n'
        body = raw if raw is not None else json.dumps(request, ensure_ascii=True, separators=(',', ':')).encode()
        result = subprocess.run([str(self.binary)], input=header + body, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        parsed = json.loads(result.stdout)
        self.cases.append({'test': self.id(), 'request_sha256': hashlib.sha256(body).hexdigest(),
                           'input_bytes': len(body), 'limits': policy,
                           'ok': parsed['ok'], 'code': parsed.get('code'),
                           'sha256': parsed.get('sha256'), 'output_bytes': len(result.stdout)})
        return parsed

    def equal(self, request):
        b = budget(max_work=1_000_000_000, max_bytes=512_000_000)
        expected_map = {(row['owner'], row['slot'], row['declaration']): row['target'] for row in request['expectations']}
        graph = SourceGraph(request['documents'], expectations=expected_map, budget=b)
        expected = graph.hash(request['owner'], request['root'], budget=b,
                              view=request['view'], ignore_top_cv=request['ignore_top_cv'])
        actual = self.run_rust(request)
        self.assertTrue(actual['ok'], actual)
        self.assertEqual(actual['sha256'], expected.digest)
        self.assertEqual(actual['preimage_ascii'].encode('ascii'), expected.preimage)
        self.assertEqual((actual['states'], actual['edges']), (expected.states, expected.edges))
        return actual

    def test_all_seven_committed_raw_source_vectors(self):
        document = json.loads(VECTORS.read_text())
        for vector in document['vectors']:
            with self.subTest(vector=vector['name']):
                request = self.request(vector['fragment'], vector['root']['id'], view=vector['view'])
                actual = self.equal(request)
                self.assertEqual(actual['sha256'], vector['sha256'])
                self.assertEqual(actual['preimage_ascii'], vector['preimage_ascii'])

    def test_full_source_inventory_and_alpha_renaming(self):
        current = json.loads(SOURCE.read_text())
        fragment = {k: current[k] for k in ('types', 'layouts', 'domains')}
        for typ in current['types']:
            with self.subTest(typ=typ['id']):self.equal(self.request(fragment, typ['id']))
        before, _ = source_pair()
        original = self.equal(self.request(before, 102))
        changed = deepcopy(before)
        ids = {t['id']: t['id'] + 1000 for t in changed['types']}
        for typ in changed['types']:
            typ['id'] = ids[typ['id']]
            if typ['layout'] is not None:typ['layout']['some'] += 2000
            for child in typ['elements']:child['id'] = ids[child['id']]
        for layout in changed['layouts']:
            layout['id'] += 2000; layout['type']['id'] = ids[layout['type']['id']]
        self.assertEqual(original['sha256'], self.equal(self.request(changed, ids[102]))['sha256'])

    def test_sharing_and_legal_pointer_cycle(self):
        before, after = source_pair()
        fn = next(t for t in before['types'] if t['id'] == 103)
        fn.update(elements=[ref(1), ref(1), ref(1)], extent=some(2))
        first = self.equal(self.request(before, 103))
        scalar = deepcopy(before['types'][0]); scalar.update(id=400, layout=some(401))
        layout = deepcopy(before['layouts'][0]); layout.update(id=401, type=ref(400))
        before['types'].append(scalar); before['layouts'].append(layout)
        fn['elements'][1] = ref(400)
        self.assertEqual(first['sha256'], self.equal(self.request(before, 103))['sha256'])
        next(t for t in after['types'] if t['id'] == 102)['elements'] = [ref(100)]
        record = next(t for t in after['types'] if t['id'] == 100)
        record['record_input']['some']['fields'][0]['type'] = ref(102)
        after['layouts'][-2] = geometry(100, 8, 8, [dict(declaration_index=0, name='value',
            type=ref(102), offset_bits=0, width_bits=64, flags=[])])
        after['layouts'][-1] = geometry(101, 24, 8)
        self.equal(self.request(after, 100))

    def test_dependency_expectation_and_root_cv(self):
        before, _ = source_pair()
        first = self.equal(self.request(before, 102))
        before['types'][3]['elements'] = [ref(7, 3)]
        request = self.request(before, 102, expectations=[dict(owner='main', slot=3, declaration=7, target=101)])
        self.assertEqual(first['sha256'], self.equal(request)['sha256'])
        before['types'][3]['qualifiers'] = ['const', 'restrict', 'volatile']
        projected = self.equal(self.request(before, 102, ignore_top_cv=True, expectations=request['expectations']))
        before['types'][3]['qualifiers'] = ['restrict']
        self.assertEqual(projected['sha256'], self.equal(self.request(before, 102, expectations=request['expectations']))['sha256'])
        before['types'][1]['qualifiers'] = ['const']
        self.assertNotEqual(projected['sha256'], self.equal(self.request(before, 102, expectations=request['expectations']))['sha256'])

    def test_unicode_common_prefix_and_def_expression(self):
        before, after = source_pair()
        for document in (before, after):
            document['types'][1]['identity']['entity'] = 'shared-prefix-' * 200 + 'é🔮\n"\\'
        for identifier in (100, 102, 103):
            for view in ('DEF', 'EXPR'):
                with self.subTest(identifier=identifier, view=view):
                    self.equal(self.request(before, identifier, view=view))
                    self.equal(self.request(after, identifier, view=view))

    def test_enum_methods_bases_and_virtual_adjustment_projection(self):
        before, after = source_pair()
        enum = source_type(before['types'][0], 200, 'enum', bits=32, signed=True,
            elements=[ref(1)], flags=['complete', 'scoped', 'fixed_base'],
            enumerators=[{'name': 'red', 'value': '01000000'}],
            layout=some(200), execution=some(ref(1)), representation='value')
        enum['identity'].update(language='cpp23', linkage='external', entity='Color')
        before['types'].append(enum); before['layouts'].append(geometry(200, 4, 4))
        self.equal(self.request(before, 200)); self.equal(self.request(before, 200, view='EXPR'))
        base = next(t for t in after['types'] if t['id'] == 100)
        base['identity']['entity'] = 'Base'
        derived = deepcopy(base)
        derived.update(id=200, layout=some(200), flags=['complete', 'polymorphic', 'trivial_destroy'],
            methods=[dict(name='f', signature=ref(103), virtual=True, slot=some(0), noexcept=False)])
        derived['identity']['entity'] = 'Derived'
        derived['record_input']['some'].update(fields=[],
            bases=[dict(type=ref(100), virtual=False, access='public')], pod03=False,
            trivial=False, standard_layout=False, polymorphic=True, dynamic=True)
        layout = geometry(200, 16, 8)
        layout.update(data_size=12, nonvirtual_size=12, bases=[dict(type=ref(100), offset=8,
            virtual=False, declaration_index=some(0), origin_path=[0],
            adjustment=dict(kind='fixed', offset=8))], vptrs=[dict(offset=0, offset_top=0,
            rtti=some(ref(800)), slots=[ref(900)], vcall_offsets=[], vbase_offsets=[], component_order=[])])
        after['types'].append(derived); after['layouts'].append(layout)
        fixed = self.equal(self.request(after, 200))
        layout['vptrs'][0].update(rtti=some(ref(801)), slots=[ref(901)])
        self.assertEqual(fixed['sha256'], self.equal(self.request(after, 200))['sha256'])
        derived['record_input']['some']['bases'][0]['virtual'] = True
        layout['nonvirtual_size'] = 8
        layout['bases'][0].update(virtual=True, adjustment=dict(kind='virtual', vptr_offset=0,
            slot_bytes=-24, addend=0))
        layout['vptrs'][0].update(vbase_offsets=[8], component_order=['vbase'])
        self.assertNotEqual(fixed['sha256'], self.equal(self.request(after, 200))['sha256'])

    def test_rejected_source_predicates_on_both_implementations(self):
        before, _ = source_pair()
        cases = [
            ('HASH3_ARITY', lambda d: d['types'][-1].update(elements=[ref(1)])),
            ('HASH3_KIND_FLAGS', lambda d: d['types'][-1].update(flags=['complete', 'polymorphic'])),
            ('HASH3_QUALIFIERS', lambda d: d['types'][-1].update(qualifiers=['volatile', 'const'])),
            ('HASH3_REFERENCE', lambda d: d['types'][3]['elements'][0].update(id=999)),
            ('HASH3_ID', lambda d: d['types'][3]['elements'][0].update(id=0xffffffff)),
            ('HASH3_EXTENT', lambda d: d['types'][2].update(extent=some(0))),
            ('HASH3_ARRAY_COMPLETENESS', lambda d: d['types'][2].update(flags=['complete'])),
            ('HASH3_SHAPE', lambda d: d['types'][1].update(cpp_class={})),
            ('HASH3_NONOBJECT_LAYOUT', lambda d: d['types'][-1].update(layout=some(102))),
            ('HASH3_INCOMPLETE', lambda d: d['types'][1].update(execution=some(ref(1)))),
            ('HASH3_UNBOUND_DECLARATION', lambda d: d['types'][3]['elements'][0].update(module={'kind': 'dependency', 'slot': 9})),
        ]
        for code, change in cases:
            changed = deepcopy(before); change(changed)
            with self.subTest(code=code):
                with self.assertRaises(HashError) as python_error:
                    b = budget(); SourceGraph({'main': changed}, expectations={}, budget=b)
                self.assertEqual(python_error.exception.code, code)
                rust = self.run_rust(self.request(changed, 102))
                self.assertFalse(rust['ok']); self.assertEqual(rust['kind'], 'semantic')
                self.assertEqual(rust['code'], code)

    def test_explicit_resource_limits(self):
        before, _ = source_pair(); request = self.request(before, 102)
        for limits in (dict(max_work=0), dict(max_bytes=0), dict(max_edges=0),
                       dict(max_nodes=1), dict(max_depth=1), dict(max_output_bytes=0),
                       dict(max_input_bytes=4)):
            with self.subTest(limits=limits):
                result = self.run_rust(request, limits=limits)
                self.assertFalse(result['ok']); self.assertEqual(result['kind'], 'resource')

    def test_strict_raw_parser_and_producer_preimage_not_accepted(self):
        before, _ = source_pair(); request = self.request(before, 102)
        for raw, code in [(b'{"x":1,"x":2}', 'HASH3_DUPLICATE_KEY'),
                          (b'{"x":1.5}', 'HASH3_JSON'),
                          (b'{"x":"\\ud800"}', 'HASH3_UTF8'),
                          (b'{"x":18446744073709551616}', 'HASH3_INTEGER')]:
            with self.subTest(code=code):
                result = self.run_rust(request, raw=raw)
                self.assertFalse(result['ok']); self.assertEqual(result['code'], code)
        request['preimage_ascii'] = 'not a source graph'
        result = self.run_rust(request)
        self.assertFalse(result['ok']); self.assertEqual(result['code'], 'HASH3_SHAPE')

    def test_value_cycle_and_in_checkout_output_rejections(self):
        _, after = source_pair()
        after['types'][1]['record_input']['some']['fields'][0]['type'] = ref(100)
        after['layouts'][-2]['fields'][0]['type'] = ref(100)
        result = self.run_rust(self.request(after, 100))
        self.assertFalse(result['ok']); self.assertEqual(result['code'], 'HASH3_VALUE_CYCLE')
        with self.assertRaises(ValueError):outside(ROOT / 'target')
        with self.assertRaises(ValueError):outside(LLVM / 'target')

    def test_missing_explicit_binary_is_a_failure_not_a_skip(self):
        with tempfile.TemporaryDirectory(prefix='missing-binary-', dir=self.output) as directory:
            path = Path(directory)
            env = {**os.environ, 'SMIR_ABI_V3_REFERENCE_BIN': str(path / 'absent'),
                   'SMIR_ABI_V3_REFERENCE_TMP': str(path / 'output'), 'PYTHONDONTWRITEBYTECODE': '1'}
            argv = [sys.executable, *(['-O'] if sys.flags.optimize else []), '-m', 'unittest',
                    'function_address.test_rust_reference.RustReferenceTests.test_all_seven_committed_raw_source_vectors']
            result = subprocess.run(argv, cwd=ROOT / 'tools/smir-abi', env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('missing/not executable', result.stderr)
            self.assertNotIn('skipped', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
