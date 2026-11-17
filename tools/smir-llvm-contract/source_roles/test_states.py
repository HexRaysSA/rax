"""Actual Clang source layout versus accepted, unsealed ABI source fragments."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
COORD = Path('/tmp/rax-portable-smir-01/LLVM')
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/record-layout'


def private_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


class SourceStateWitnesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import subprocess
        cls.subprocess = subprocess
        cls.output = Path(tempfile.mkdtemp(prefix='source-state-', dir=COORD))
        ast = private_module('rax_llvm_ast_state_builder',
                             ROOT / 'tools/smir-llvm-contract/record_layout/builder.py')
        cls.binary = ast.build(Path('/Users/int/dev/llvm-project'), cls.output / 'build')
        folder = str(ROOT / 'tools/smir-abi')
        sys.path.insert(0, folder)
        try:
            cls.source_builder = private_module('rax_llvm_canonical_state_builder',
                                                ROOT / 'tools/smir-abi/source_roles/builder.py')
        finally:
            sys.path.remove(folder)
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        (cls.output / 'observations.json').write_text(json.dumps(cls.observations, indent=2) + '\n')
        print('Independent LLVM source-state witnesses retained:', cls.output)

    def fragment(self, base=1000, execution_base=4000):
        source = {key: base + index for index, key in enumerate(
            ('uint32', 'uint64', 'va_state', 'jmp_state', 'va_list', 'jmp_buf'), 1)}
        execution = {key: execution_base + index for index, key in enumerate(
            ('uint32', 'uint64', 'raw8', 'state_bytes', 'list_wrapper'), 1)}
        return self.source_builder.build_builtin_states(source_ids=source,
                                                        execution_ids=execution, domain_id=19)

    def ast(self, language):
        suffix = 'c' if language == 'c23' else 'cpp'
        source = FIXTURES / f'source-helper-states.{suffix}'
        result = self.subprocess.run([str(self.binary), str(source), 'source_states', language],
                                     capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.observations.append(dict(language=language, source=str(source), exit=result.returncode,
                                      stderr=result.stderr, report=report))
        return report

    def test_declared_canonical_geometry_matches_actual_c23_ast_without_source_id_inference(self):
        report = self.ast('c23')
        actual = {node['record_name']: node for node in report['types'] if node['kind'] == 'record'}
        actual_types = {node['id']: node for node in report['types']}
        fragment = self.fragment()
        nominal = {node['id']: node for node in fragment['types']}
        layouts = {node['id']: node for node in fragment['layouts']}
        for key, name in (('va_state', 'VaState'), ('jmp_state', 'JumpState')):
            source = nominal[fragment[key]['id']]
            selected = layouts[source['layout']['some']]
            observed = actual[name]
            self.assertEqual(source['identity']['definition'], '0' * 64)
            self.assertEqual((selected['size'], selected['align']),
                             (observed['native_layout']['size'], observed['native_layout']['align']))
            self.assertEqual(len(selected['fields']), len(observed['native_layout']['fields']))
            self.assertEqual(len(source['record_input']['some']['fields']), len(selected['fields']))
            for expected, source_field, actual_field in zip(selected['fields'],
                    source['record_input']['some']['fields'], observed['native_layout']['fields']):
                self.assertEqual((expected['name'], expected['offset_bits'], expected['width_bits']),
                                 (actual_field['name'], actual_field['offset_bits'], actual_field['width_bits']))
                scalar = nominal[source_field['type']['id']]
                actual_scalar = actual_types[actual_field['type']['id']]
                self.assertEqual((scalar['bits'], scalar['signed']),
                                 (actual_scalar['value_bits'], actual_scalar['signed']))
                self.assertEqual(scalar['identity']['entity'], actual_scalar['spelling'])

    def test_cpp_actual_traits_are_not_claimed_to_equal_reserved_c23_normalization(self):
        report = self.ast('cpp23')
        actual = next(node for node in report['types'] if node.get('record_name') == 'VaState')
        fragment = self.fragment()
        canonical = next(node for node in fragment['types'] if node['id'] == fragment['va_state']['id'])
        self.assertTrue(actual['record_input']['some']['pod03'])
        self.assertFalse(canonical['record_input']['some']['pod03'])
        self.assertEqual(canonical['identity']['language'], 'c23')
        # This is the explicitly selected reserved-builtin normalization, not
        # proof that this ordinary source declaration was compiler-created.

    def test_fragments_require_real_domain_sealing_and_validate_with_actual_reference_context(self):
        spec = ROOT / 'docs/specifications/smir/portable'
        codec = private_module('rax_llvm_state_wire_codec', ROOT / 'tools/smir-format/codec.py')
        tables = {owner: json.loads((spec / 'schema' / owner / 'candidate.json').read_text())
                  for owner in ('execution', 'runtime', 'abi')}
        fingerprints = []
        folder = str(ROOT / 'tools/smir-abi')
        sys.path.insert(0, folder)
        try:
            from nominal import NominalGraph, ref
            for source_base, execution_base in ((1000, 4000), (2000, 5000)):
                original = json.loads((spec / 'conformance/execution/candidate/portable-identity.json').read_text())
                roots = {int(key): value for key, value in original['sections'].items()}
                for number, value in {
                    5: dict(payload_revision=2, relocations=[], constant_initializers=[]),
                    7: dict(payload_revision=1, segments=[]),
                    9: dict(payload_revision=1, capabilities=[], requirements=[], limits=[]),
                }.items():
                    roots.setdefault(number, value)
                roots[2]['manifest'].update(kind='object', entry=None)
                document = roots[10]
                self.assertEqual(len(document['domains']), 1)
                old_domain = document['domains'][0]['id']
                document['domains'][0]['id'] = 19
                for node in document['types']:
                    self.assertEqual(node['domain'], old_domain)
                    node['domain'] = 19
                fragment = self.fragment(source_base, execution_base)
                for table, additions in ((document['types'], fragment['types']),
                                         (document['layouts'], fragment['layouts']),
                                         (roots[1]['types'], fragment['execution_graph'])):
                    self.assertTrue({node['id'] for node in table}.isdisjoint(node['id'] for node in additions))
                    table.extend(copy.deepcopy(additions))
                    table.sort(key=lambda node: node['id'])
                graph = NominalGraph(document, 'actual_source_state_owner')
                if source_base == 1000:
                    unsealed = codec.CandidateCodec(tables).encode(roots)
                    with self.assertRaisesRegex(ValueError, 'ABI_CC_DEFINITION_HASH'):
                        codec.reference_report(unsealed, capabilities=('memory',))
                for node in document['types']:
                    if 'complete' in node['flags']:
                        node['identity']['definition'] = graph.fingerprint(ref(node['id']))
                fingerprints.append([node['identity']['definition'] for node in document['types']
                                     if node['id'] in {node['id'] for node in fragment['types']}])
                raw = codec.CandidateCodec(tables).encode(roots)
                result = codec.reference_report(raw, capabilities=('memory',))
                self.assertIs(result['reference_verified'], True)
                self.assertIs(result['production_admitted'], False)
                self.observations.append(dict(source_base=source_base, execution_base=execution_base,
                    domain=19, reference=result, scope='Unused canonical source metadata, actual full reference; no production facts/execution'))
        finally:
            sys.path.remove(folder)
        self.assertEqual(fingerprints[0], fingerprints[1])


if __name__ == '__main__':
    unittest.main()
