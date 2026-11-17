"""INT031 complete static objects and separately bounded resolver failures."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_candidate_contract import HERE

FIXTURE = 'docs/specifications/smir/portable/conformance/runtime/candidate/joint/journal-helper-captures.json'


class JournalCaptureTests(unittest.TestCase):
    def test_actual_whole_root_journal_capture_programs(self):
        root = HERE.parents[1]
        document = json.loads((root / FIXTURE).read_text())
        self.assertEqual(len(document['cases']), 16)
        self.assertEqual(sum(case['accept'] for case in document['cases']), 10)
        with tempfile.TemporaryDirectory(prefix='smir-journal-captures-') as folder:
            for case in document['cases'] + document['legacy_cases']:
                with self.subTest(case=case['name']):
                    data = bytes.fromhex(case['encoded_hex'])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), case['sha256'])
                    path = Path(folder) / (case['name'] + '.smo')
                    path.write_bytes(data)
                    command = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
                    command += [str(root / 'tools/smir-format/codec.py'), 'verify-candidate-reference', str(path), '--capability', 'memory']
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if case['accept'] else 2, result.stdout + result.stderr)
                    if case['accept']:
                        report = json.loads(result.stdout)
                        self.assertTrue(report['reference_verified'])
                        self.assertFalse(report['production_admitted'])
                        self.assertEqual(report['content_digest'], case['content_identity'])
                    else:
                        self.assertTrue(result.stderr.strip().startswith(case['expected_error']), result.stderr)

    def test_generator_identity_original_bytes_and_exact_reproduction(self):
        root = HERE.parents[1]
        document = json.loads((root / FIXTURE).read_text())
        provenance = document['provenance']
        generator = 'tools/smir-runtime-contract/generate_journal_capture_fixtures.py'
        self.assertEqual(provenance['generator'], generator)
        self.assertEqual(hashlib.sha256((root / generator).read_bytes()).hexdigest(), provenance['generator_sha256'])
        for relative, digest in provenance['input_sha256'].items():
            self.assertFalse(Path(relative).is_absolute())
            self.assertNotIn('..', Path(relative).parts)
            self.assertEqual(hashlib.sha256((root / relative).read_bytes()).hexdigest(), digest)
        self.assertEqual(provenance['encoded_object_bytes'],
                         sum(len(bytes.fromhex(case['encoded_hex'])) for case in document['cases']))
        self.assertTrue(provenance['size_justification'])
        cases = {case['name']: case for case in document['legacy_cases']}
        for contract, digest in provenance['original_counter_sha256'].items():
            self.assertEqual(cases['legacy-abi1-' + contract + '-zero']['sha256'], digest)
        command = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
        result = subprocess.run(command + [str(root / generator), '--check'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_context_bounded_missing_source_resolver_metadata(self):
        # These negative protocol probes alter only a resolver COPY after actual
        # source ABI/execution validation. They are NOT full-object certificates.
        script = r'''from pathlib import Path
import json,sys
root=Path(sys.argv[1]);fixture=json.loads((root/sys.argv[2]).read_text())
sys.path.insert(0,str(root/'tools/smir-format'))
from codec import CandidateCodec
spec=root/'docs/specifications/smir/portable'
codec=CandidateCodec({name:json.loads((spec/'schema'/name/'candidate.json').read_text()) for name in ('execution','runtime','abi')})
sys.path.insert(0,str(root/'tools/smir-format/execution'))
from candidate.context import RootContext
from candidate.bindings import runtime_package_module
runtime=runtime_package_module('linking')
helpers=runtime_package_module('helpers')
sections=codec.decode(bytes.fromhex(next(case for case in fixture['cases'] if case['name']=='construction-one')['encoded_hex'])).roots
actual=RootContext(sections);actual.verify_abi();actual.verify_execution()
def absent(*args):raise RuntimeError('unsupported comparison in this bounded context')
def context(resolver):
 return runtime.Context(site=sections[10]['identity'],execution=actual.execution,
  nominal=lambda q:actual.abi_entity('nominal',q),function=actual.function,
  symbol=actual.runtime_symbol,execution_equal=actual.types.equal,
  nominal_compatible=actual.abi_graph.boundary_compatible,storage_layout=actual.memory_layout,
  symbol_body=absent,symbol_identity=absent,abi_entity=resolver,target_entity=actual.target_entity,
  native_symbol=actual.native_symbol,nominal_layout=actual.abi_graph.layout,grants=frozenset({'memory'}),
  signature_compatible=actual.abi_graph.signature_compatible)
for mode in ['missing-program','missing-params','missing-execution']:
 def resolver(namespace,reference):
  value=actual.abi_entity(namespace,reference)
  if namespace=='journal' and mode=='missing-program':return None
  if namespace=='journal' and mode=='missing-params':value.pop('params')
  if namespace=='nominal' and reference['id']==1 and mode=='missing-execution':value['execution']=None
  return value
 try:runtime.validate({number:sections[number] for number in runtime.ROOTS},context(resolver))
 except Exception as error:
  if getattr(error,'code',None)!='RT_HELPER_JOURNAL_CAPTURES':raise
 else:raise RuntimeError('missing metadata was accepted: '+mode)
actual.assert_snapshot()
control=codec.decode(bytes.fromhex(next(case for case in fixture['cases'] if case['name']=='noncapture-control')['encoded_hex'])).roots
plain=RootContext(control);plain.verify_abi();plain.verify_execution()
try:helpers.instantiate(control[6]['imports'][0],plain.execution,plain.abi_entity,plain.target_entity,journal_captures=[])
except Exception as error:
 if getattr(error,'code',None)!='RT_HELPER_UNUSED_CAPTURES':raise
else:raise RuntimeError('noncapture helper accepted unused capture vector')
print('bounded source metadata rejections: 4; no provider/native/runtime execution')
'''
        command = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
        result = subprocess.run(command + ['-c', script, str(HERE.parents[1]), FIXTURE], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('rejections: 4', result.stdout)


if __name__ == '__main__':
    unittest.main()
