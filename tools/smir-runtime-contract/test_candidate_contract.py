"""Current candidate contract tests; legacy fixture suite remains independent."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import os
import random
import subprocess
import tempfile
import sys
import unittest

HERE = Path(__file__).resolve().parent
NAME = 'runtime_candidate'
if NAME not in sys.modules:
    specification = importlib.util.spec_from_file_location(NAME, HERE / 'candidate/__init__.py',
                                                          submodule_search_locations=[str(HERE / 'candidate')])
    module = importlib.util.module_from_spec(specification)
    sys.modules[NAME] = module
    specification.loader.exec_module(module)

from runtime_candidate.atomic import Atomics, Transfer
from runtime_candidate.errors import Reject, some
from runtime_candidate.fenv import DEFAULT_ENV, DEFAULT_MODE, Diagnostic, Environment, Fenv
from runtime_candidate.helpers import DEFAULT_OPTIONS, catalog, digest, instantiate
from runtime_candidate.linking import Context, bind_deployment, components, content_identity, validate
from runtime_candidate.schema_build import document
from runtime_candidate.wire import SCHEMA, decode, encode


def ref(identifier, slot=None):
    return {'module': {'kind': 'self'} if slot is None else {'kind': 'dependency', 'slot': slot},
            'id': identifier}


def roots(name='main'):
    return {
        2: {'payload_revision': 2, 'manifest': {
            'identity': '0' * 64, 'key': {'namespace': 'test', 'name': name, 'abi_major': 1, 'abi_minor': 1},
            'kind': 'object', 'entry': None, 'site': 'a' * 64, 'personality': 'linux',
            'foreign_isa': 'none', 'dependencies': [], 'exports': []},
            'symbols': [], 'comdats': [], 'initializers': [], 'finalizers': []},
        4: {'payload_revision': 1, 'segments': []},
        5: {'payload_revision': 2, 'relocations': [], 'constant_initializers': []},
        6: {'payload_revision': 1, 'imports': []},
        7: {'payload_revision': 1, 'segments': []},
        9: {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []},
    }


def declaration(identifier, name):
    return {'id': identifier, 'kind': 'function', 'symbol_kind':'none', 'source_linkage': 'c', 'namespace': 'test', 'name': name,
            'execution': some(ref(0)), 'nominal': some(ref(0)), 'abi_signature': some(ref(0)), 'weak': False}


def export(identifier, name, private):
    return {'id': identifier, 'kind': 'function', 'source_linkage': 'c', 'namespace': 'test', 'name': name,
            'target': ref(private), 'execution': some(ref(0)), 'nominal': some(ref(0)), 'abi_signature': some(ref(0))}


class CandidateContractTests(unittest.TestCase):
    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(Reject) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_abi2_joint_sources_reproduce_without_mutation(self):
        command = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
        result = subprocess.run(command + [str(HERE / 'candidate/fixture_build.py'),
            '--abi2-joint', '--check'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_function_definition_requires_function_symbol_kind(self):
        repository = HERE.parents[1]
        fixture = repository / 'docs/specifications/smir/portable/conformance/runtime/candidate/joint/function-symbol-kind-mismatch.json'
        cases = json.loads(fixture.read_text())['cases']
        self.assertEqual([case['symbol_kind'] for case in cases], ['function', 'data', 'tls', 'import'])
        with tempfile.TemporaryDirectory(prefix='smir-function-definition-') as directory:
            for case in cases:
                with self.subTest(symbol_kind=case['symbol_kind']):
                    encoded = bytes.fromhex(case['encoded_hex'])
                    self.assertEqual(hashlib.sha256(encoded).hexdigest(), case['sha256'])
                    path = Path(directory) / (case['symbol_kind'] + '.smo')
                    path.write_bytes(encoded)
                    command = [sys.executable, '-B']
                    if sys.flags.optimize:
                        command.append('-O')
                    command += [str(repository / 'tools/smir-format/codec.py'), 'verify-candidate-reference', str(path)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if case['accept'] else 2, result.stdout + result.stderr)
                    if not case['accept']:
                        self.assertEqual(result.stderr.strip().split(':', 1)[0], 'RT_DEFINITION_DOMAIN')

    def test_common_symbol_requires_object_type(self):
        repository = HERE.parents[1]
        fixture = repository / 'docs/specifications/smir/portable/conformance/runtime/candidate/joint/common-symbol-type-domain.json'
        document = json.loads(fixture.read_text())
        self.assertEqual(sum(case['accept'] for case in document['cases']), 2)
        with tempfile.TemporaryDirectory(prefix='smir-object-symbol-') as directory:
            for case in document['cases']:
                with self.subTest(case=case['name']):
                    encoded = bytes.fromhex(case['encoded_hex'])
                    self.assertEqual(hashlib.sha256(encoded).hexdigest(), case['sha256'])
                    path = Path(directory) / (case['name'] + '.smo')
                    path.write_bytes(encoded)
                    command = [sys.executable, '-B']
                    if sys.flags.optimize:
                        command.append('-O')
                    command += [str(repository / 'tools/smir-format/codec.py'), 'verify-candidate-reference', str(path)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if case['accept'] else 2, result.stdout + result.stderr)
                    if not case['accept']:
                        self.assertEqual(result.stderr.strip().split(':', 1)[0], case['expected_error'])
        # These additional cases exercise the LOCAL declaration/source-category
        # predicate against an actual checked nominal graph. They do not claim
        # absent-provider resolution or full-module external admission.
        script = r'''import json,sys
from pathlib import Path
root=Path(sys.argv[1]);document=json.loads(Path(sys.argv[2]).read_text())
sys.path.insert(0,str(root/'tools/smir-format'))
from codec import CandidateCodec
spec=root/'docs/specifications/smir/portable'
codec=CandidateCodec({name:json.loads((spec/'schema'/name/'candidate.json').read_text()) for name in ('execution','runtime','abi')})
case=next(case for case in document['cases'] if case['name']==document['local_graph_case'])
sections=codec.decode(bytes.fromhex(case['encoded_hex'])).roots
sys.path.insert(0,str(root/'tools/smir-format/execution'))
from candidate.context import RootContext
actual=RootContext(sections);actual.verify_abi()
sys.path.insert(0,str(root/'tools/smir-runtime-contract'))
from test_candidate_contract import Context
from runtime_candidate.linking import source_plan
from runtime_candidate.errors import Reject
from runtime_candidate.wire import encode
context=Context(site=sections[10]['identity'],execution=actual.execution,
 nominal=lambda ref:actual.abi_entity('nominal',ref),function=actual.function,
 symbol=actual.runtime_symbol,execution_equal=None,nominal_compatible=None,
 storage_layout=actual.memory_layout,symbol_body=None,symbol_identity=None,
 abi_entity=actual.abi_entity)
for case in document['local_source_categories']:
 encode('external_declaration',case['record'])
 try:source_plan(case['record'],context)
 except Reject as error:
  if case['accept'] or error.code!=case['expected_error']:raise RuntimeError((case['name'],error.code))
 else:
  if not case['accept']:raise RuntimeError((case['name'],'unexpected acceptance'))
print('actual_local_source_categories',len(document['local_source_categories']))
'''
        command = [sys.executable, '-B']
        if sys.flags.optimize:
            command.append('-O')
        command += ['-c', script, str(repository), str(fixture)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('actual_local_source_categories 6', result.stdout)

    def test_portable_domain_ids_do_not_control_source_plans(self):
        from runtime_candidate.linking import source_plan
        repository = HERE.parents[1]
        fixture = repository / 'docs/specifications/smir/portable/conformance/runtime/candidate/joint/portable-domain-identity.json'
        document = json.loads(fixture.read_text())
        self.assertEqual(len(document['cases']), 12)
        self.assertEqual(sum(case['accept'] for case in document['cases']), 6)
        with tempfile.TemporaryDirectory(prefix='smir-portable-domain-') as directory:
            for case in document['cases']:
                with self.subTest(case=case['name']):
                    encoded = bytes.fromhex(case['encoded_hex'])
                    self.assertEqual(hashlib.sha256(encoded).hexdigest(), case['sha256'])
                    path = Path(directory) / (case['name'] + '.smo')
                    path.write_bytes(encoded)
                    command = [sys.executable, '-B']
                    if sys.flags.optimize:
                        command.append('-O')
                    command += [str(repository / 'tools/smir-format/codec.py'), 'verify-candidate-reference', str(path)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if case['accept'] else 2, result.stdout + result.stderr)
                    if not case['accept']:
                        self.assertEqual(result.stderr.strip().split(':', 1)[0], case['expected_error'])
        # Bounded resolver-interface tests: no checked foreign issuer or native
        # certificate is claimed. Exact shapes are supplied for this query only.
        for case in document['bounded_resolver_cases']:
            def absent(*args):
                raise Reject('TEST_UNEXPECTED_REFERENCE')
            def abi_entity(namespace, reference):
                self.assertEqual(namespace, 'nominal_domain')
                self.assertEqual(reference, case['record']['nominal']['some'])
                return copy.deepcopy(case['domain'])
            context = Context('a' * 64, absent, lambda ref: copy.deepcopy(case['nominal']),
                              absent, absent, absent, absent, absent, absent, absent,
                              abi_entity=abi_entity)
            if case['accept']:
                self.assertIsNone(source_plan(case['record'], context))
            else:
                self.error(case['expected_error'], source_plan, case['record'], context)
            context.abi_entity = None
            self.error('RT_SOURCE_PLAN_NAMESPACE', source_plan, case['record'], context)
            self.assertIsNone(source_plan(case['record'], context, required=False))

    def test_all_runtime_roots_and_shared_option_roundtrip(self):
        self.assertEqual(json.loads(SCHEMA.read_text()), document())
        names = {2: 'runtime_symbols', 4: 'runtime_data', 5: 'runtime_relocations',
                 6: 'runtime_imports', 7: 'runtime_tls', 9: 'runtime_capabilities'}
        for index, value in roots().items():
            encoded = encode(names[index], value)
            self.assertEqual(decode(names[index], encoded), value)
            for end in range(len(encoded)):
                self.error('RT_WIRE', decode, names[index], encoded[:end])
        for value in [None, some(None), some(some(3))]:
            encoded = encode('opt:opt:u32', value)
            self.assertEqual(decode('opt:opt:u32', encoded), value)
        self.error('RT_WIRE', encode, 'opt:u32', 4)
        self.error('RT_WIRE', encode, 'bool', 1)
        self.error('RT_WIRE', encode, 'u64', True)

    def test_runtime_semantics_rejects_unknown_roots_and_capabilities(self):
        def absent(reference):
            raise Reject('TEST_UNEXPECTED_REFERENCE')
        context = Context('a' * 64, absent, absent, absent, absent, absent, absent, absent, absent, absent)
        validate(roots(), context)
        bad = roots()
        bad[9]['capabilities'] = ['host_pointer_execution']
        self.error('RT_CAPABILITIES', validate, bad, context)
        bad = roots()
        bad[2]['manifest']['kind'] = 'image'
        bad[2]['manifest']['entry'] = some(ref(4))
        self.error('TEST_UNEXPECTED_REFERENCE', validate, bad, context)
        bad = roots()
        bad[2]['manifest']['kind'] = 'object'
        bad[2]['manifest']['entry'] = some(ref(0))
        self.error('RT_IMAGE_ENTRY', validate, bad, context)

    def test_arbitrary_size_atomics_shadow_and_orders(self):
        for size in [1, 3, 8, 16, 17, 33, 65, 257]:
            model = Atomics()
            zero = Transfer.concrete(bytes(size))
            allones = Transfer.concrete(bytes([255]) * size)
            key = model.register('same-backing', 0, zero)
            for success in range(6):
                for failure in [0, 1, 2, 5]:
                    model.store(key, zero, 5)
                    observed, won = model.compare_exchange(key, zero, allones, success, failure)
                    self.assertTrue(won)
                    self.assertEqual(observed, zero)
                    observed, won = model.compare_exchange(key, zero, zero, success, failure)
                    self.assertFalse(won)
                    self.assertEqual(observed, allones)
            self.assertFalse(model.is_lock_free(size, 0))
        model = Atomics()
        poisoned = Transfer(b'\xff', b'\x80', b'\x40')
        key = model.register('b', 0, poisoned)
        observed, won = model.compare_exchange(key, Transfer.concrete(b'\x3f'),
                                               Transfer.concrete(b'\x01'), 3, 2)
        self.assertTrue(won)  # Compared poison/undef bits refine to0; no eager UB.
        self.assertEqual(observed, poisoned)
        self.assertEqual(model.load(key, 5).bits, b'\x01')
        self.error('RT_ATOMIC_FAILURE_ORDER', model.compare_exchange, key,
                   Transfer.concrete(b'\1'), Transfer.concrete(b'\0'), 5, 3)

    def test_atomic_integer_extra_rmw_precision_boundaries(self):
        expected = [('uinc_wrap', 5, 5, 0), ('uinc_wrap', 4, 5, 5),
                    ('udec_wrap', 0, 5, 5), ('udec_wrap', 7, 5, 5),
                    ('udec_wrap', 5, 5, 4), ('usub_cond', 3, 4, 3),
                    ('usub_sat', 3, 4, 0), ('usub_cond', 9, 4, 5)]
        for operation, a, b, value in expected:
            model = Atomics()
            key = model.register('b', 0, Transfer.concrete(a.to_bytes(33, 'little')))
            observed = model.rmw(key, operation, Transfer.concrete(b.to_bytes(33, 'little')), 5)
            self.assertEqual(int.from_bytes(observed.bits, 'little'), a)
            self.assertEqual(int.from_bytes(model.load(key, 5).bits, 'little'), value)
        model = Atomics()
        key = model.register('b', 0, Transfer.concrete(b'\x1f'))
        model.rmw(key, 'add', Transfer.concrete(b'\x01'), 5, precision=5)
        self.assertEqual(model.load(key, 5).bits, b'\0')

    def test_helper_exact_signature_and_context(self):
        types = {
            0: {'kind': 'int', 'id': 0, 'bits': 32},
            1: {'kind': 'int', 'id': 1, 'bits': 64},
            2: {'kind': 'data_ptr', 'id': 2, 'space': 'guest_data'},
            3: {'kind': 'float', 'id': 3, 'format': 'binary128'},
            4: {'kind': 'int', 'id': 4, 'bits': 1},
            5: {'kind': 'function', 'id': 5, 'params': [ref(3), ref(3)],
                'results': [ref(4)], 'param_noundef': [False, False],
                'result_noundef': [False], 'variadic': False, 'cc': 'portable'},
        }
        get = lambda reference: types[reference['id']]
        options = {**DEFAULT_OPTIONS, 'rounding': 'nearest_even',
                   'exceptions': 'ignore', 'predicate': 'oeq'}
        record = {'kind': 'internal', 'id': 0, 'namespace': 'smir.internal.v1',
                  'name': 'fp_compare', 'version': 1, 'catalog': digest(),
                  'signature': ref(5), 'abi': None, 'types': [ref(3)],
                  'contract': 'llvm_default', 'options': options}
        instantiate(record, get)
        bad = copy.deepcopy(record)
        bad['options']['predicate'] = 'none'
        self.error('RT_HELPER_PREDICATE', instantiate, bad, get)
        bad = copy.deepcopy(record)
        bad['catalog'] = '0' * 64
        self.error('RT_HELPER_VERSION', instantiate, bad, get)
        types[5]['params'][1] = ref(1)
        self.error('RT_HELPER_TYPE', instantiate, record, get)
        names = [row['name'] for row in catalog()['records']]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({'atomic_flag_test_and_set', 'atomic_fetch_uinc_wrap',
                         'fp_sincospi', 'fp_powi', 'va_start', 'journal_advance'} <= set(names))

    def test_fenv_exact_bytes_masks_and_diagnostic_isolation(self):
        self.assertEqual(DEFAULT_ENV, struct.pack('<IIIIQQ', 1, 0, 0, 0, 0, 0))
        self.assertEqual(DEFAULT_MODE, bytes(16))
        state = Fenv(diagnostic_mask=31)
        state.errno = 73
        for flag in [1, 2, 4, 8, 16, 32]:
            state.setexcept(flag)
            self.assertEqual(state.test(flag), flag)
            state.clear(flag)
            self.assertEqual(state.test(flag), 0)
        state.raise_flags(32)
        self.assertEqual(state.environment.flags, 32)
        for code in [0, 0x400, 0x800, 0xc00]:
            saved = Environment(code, 63).encode()
            state.setenv(saved)  # Restore never raises existing flags.
            self.assertEqual(state.getenv(), saved)
            self.assertEqual(state.diagnostic_mask, 31)
        self.assertEqual(state.wrapper('setenv', b'\0' * 32), 1)
        self.assertEqual(state.errno, 73)
        before = state.getenv()
        self.error('RT_FENV_MASK', state.setexcept, 64)
        self.assertEqual(state.getenv(), before)
        with self.assertRaises(Diagnostic) as trapped:
            state.arithmetic(42, 7)
        self.assertEqual(trapped.exception.cause, 'invalid')
        self.assertEqual(state.environment.flags, 63)
        writer = lambda value: (_ for _ in ()).throw(Reject('RT_MEMORY_FAULT'))
        self.error('RT_MEMORY_FAULT', state.hold, writer)
        self.assertEqual(state.getenv(), before)
        copied = []
        state.hold(copied.append)
        self.assertEqual(copied, [before])
        self.assertEqual(state.environment.flags, 0)
        self.assertEqual(state.diagnostic_mask, 31)

    def test_cyclic_explicit_declaration_private_id_binding(self):
        a, b = roots('a')[2], roots('b')[2]
        a['manifest']['identity'], b['manifest']['identity'] = 'a' * 64, 'b' * 64
        a['manifest']['exports'] = [export(50, 'a_fn', 700)]
        b['manifest']['exports'] = [export(60, 'b_fn', 900)]
        b['manifest']['key']['abi_minor'] = 2
        for source, target, name in [(a, b, 'b_fn'), (b, a, 'a_fn')]:
            key = copy.deepcopy(target['manifest']['key'])
            key['abi_minor'] = 1
            source['manifest']['dependencies'] = [{'slot': 0, 'key': key,
                'minimum_minor': 1, 'maximum_minor': some(3), 'site': 'a' * 64,
                'declarations': [declaration(4, name)]}]
        modules = {'a' * 64: a, 'b' * 64: b}
        deployment = {'payload_revision': 1,
            'modules': [{'key': a['manifest']['key'], 'artifact': 'a' * 64},
                        {'key': b['manifest']['key'], 'artifact': 'b' * 64}],
            'edges': [{'source': 'a' * 64, 'slot': 0, 'target': 'b' * 64,
                       'entities': [{'kind': 'export', 'entity_kind': 'function',
                                     'declaration': 4, 'export': 60}]},
                      {'source': 'b' * 64, 'slot': 0, 'target': 'a' * 64,
                       'entities': [{'kind': 'export', 'entity_kind': 'function',
                                     'declaration': 4, 'export': 50}]}]}
        equal = lambda source, expected, target, actual: expected == actual
        result = bind_deployment(modules, deployment, equal, equal, signature_compatible=equal)
        self.assertEqual(result['components'], [['a' * 64, 'b' * 64]])
        self.assertEqual(result['bindings']['a' * 64, 0, 4], ('b' * 64, 900))
        self.assertEqual(result['bindings']['b' * 64, 0, 4], ('a' * 64, 700))
        bad = copy.deepcopy(deployment)
        bad['edges'][0]['entities'][0]['export'] = 900  # Provider private ID is not export ID.
        self.error('RT_DEPLOY_EXPORT', bind_deployment, modules, bad, equal, equal)
        self.error('RT_DEPLOY_NOMINAL', bind_deployment, modules, deployment, equal,
                   lambda *args: False)
        b['manifest']['key']['abi_minor'] = 4
        bad = copy.deepcopy(deployment)
        bad['modules'][1]['key']['abi_minor'] = 4
        self.error('RT_DEPLOY_VERSION', bind_deployment, modules, bad, equal, equal)

    def test_identity_masks_exact_self_field_only(self):
        sections = {index: bytes([index]) for index in range(1, 11)}
        sections[2] = struct.pack('<I', 1) + bytes(32) + b'keep-this-data'
        original = content_identity(sections)
        changed = dict(sections)
        changed[2] = struct.pack('<I', 1) + bytes([255]) * 32 + b'keep-this-data'
        self.assertEqual(content_identity(changed), original)
        changed[2] += b'x'
        self.assertNotEqual(content_identity(changed), original)
        self.error('RT_HASH_SECTIONS', content_identity, {1: b''})


class IndependentCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-cc-r-',
                                                    dir=os.environ.get('SMIR_RUNTIME_TMPDIR'))
        cls.addClassCleanup(cls.directory.cleanup)
        cls.probe = Path(cls.directory.name) / 'atomic_probe'
        subprocess.run([os.environ.get('CXX', '/usr/bin/clang++'), '-std=c++20', '-pthread',
                        '-Wall', '-Wextra', '-Werror', str(HERE / 'candidate/atomic_probe.cpp'),
                        '-o', str(cls.probe)], check=True, capture_output=True, text=True, timeout=60)

    def test_independent_arbitrary_byte_rmw(self):
        from runtime_candidate.atomic import RMW
        rng = random.Random(0x43435241544f4d)
        count = 0
        for size in [1, 3, 8, 16, 17, 33, 65, 257]:
            for operation in sorted(RMW):
                for trial in range(3):
                    precision = size * 8 - trial
                    a = rng.randrange(1 << precision)
                    b = rng.randrange(1 << precision)
                    av, bv = a.to_bytes(size, 'little'), b.to_bytes(size, 'little')
                    model = Atomics()
                    key = model.register('object', 0, Transfer.concrete(av))
                    model.rmw(key, operation, Transfer.concrete(bv), 5, precision=precision)
                    expected = model.load(key, 5).bits.hex()
                    result = subprocess.run([str(self.probe), 'rmw', operation, str(precision),
                                             av.hex(), bv.hex()], capture_output=True,
                                            text=True, check=True, timeout=10)
                    self.assertEqual(result.stdout.strip(), expected, (size, operation, trial))
                    count += 1
        print(f'Independent candidate RMW: {count} cases; seed=0x43435241544f4d')

    def test_lock_free_flag_progress_and_mixed_large_sc(self):
        result = subprocess.run([str(self.probe), 'flag'], check=True, capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.stdout.strip(),
                         'flag_hot_operations=300000 paused_generic_owner_progress=passed mixed_sc_trials=1000 forbidden=0')
        print(result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
