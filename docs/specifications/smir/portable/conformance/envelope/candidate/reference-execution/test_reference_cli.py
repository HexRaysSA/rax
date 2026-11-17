"""Byte-to-result CLI conformance. No imported test adapter supplies execution."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[7]
CODEC = ROOT / 'tools/smir-format/codec.py'
spec = importlib.util.spec_from_file_location('_reference_cli_test_codec', CODEC)
codec = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = codec
spec.loader.exec_module(codec)


class ReferenceExecutionCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = ROOT / 'docs/specifications/smir/portable/schema'
        cls.codec = codec.CandidateCodec({name: json.loads((schema / name / 'candidate.json').read_text())
                                         for name in ('execution', 'abi', 'runtime')})
        cls.roots = {int(key): value for key, value in json.loads((HERE / 'source.json').read_text())['sections'].items()}
        cls.policy = json.loads((HERE / 'policy.json').read_text())

    def invoke(self, *, roots=None, raw=None, policy=None, policy_bytes=None, entry=1, arguments=('2a000000',)):
        with tempfile.TemporaryDirectory(prefix='smir-reference-cli-') as directory:
            path = Path(directory)
            (path / 'object.smo').write_bytes(raw if raw is not None else
                self.codec.encode(self.roots if roots is None else roots))
            (path / 'policy.json').write_bytes(policy_bytes if policy_bytes is not None else
                json.dumps(self.policy if policy is None else policy).encode())
            command = [sys.executable, '-B', str(CODEC), 'run-candidate-reference', str(path / 'object.smo'),
                       '--entry-function', str(entry), '--reference-policy', str(path / 'policy.json')]
            for bits in arguments:
                command += ['--argument-bits', bits]
            run = subprocess.run(command, capture_output=True, text=True, timeout=240)
            self.assertEqual(run.stderr, '', run.stderr)
            report = json.loads(run.stdout)
            self.assertIs(report['production_admitted'], False)
            return run.returncode, report

    def test_canonical_bytes_bind_call_and_release_with_two_roots(self):
        self.assertEqual(self.codec.encode(self.roots), (HERE / 'call42.smo').read_bytes())
        policy = deepcopy(self.policy)
        policy['registry']['max_roots'] = 2
        code, report = self.invoke(raw=(HERE / 'call42.smo').read_bytes(), policy=policy)
        self.assertEqual(code, 0, report)
        self.assertEqual(report['status'], 'reference-return')
        self.assertEqual(report['values'], [{'bits_le': '2a000000'}])
        self.assertEqual(report['steps'], 7)

    def test_result_depends_on_argument_and_generic_entry_works(self):
        code, report = self.invoke(entry=0, arguments=('2b000000',))
        self.assertEqual(code, 0, report)
        self.assertEqual(report['values'], [{'bits_le': '2b000000'}])

    def test_argument_entry_and_policy_rejections(self):
        for changes, expected in [({'entry': 999}, 'REFERENCE-ENTRY-FUNCTION'),
                                  ({'arguments': ()}, 'REFERENCE-ARGUMENT-ARITY'),
                                  ({'arguments': ('2a',)}, 'REFERENCE-ARGUMENT-BITS')]:
            with self.subTest(changes=changes):
                code, report = self.invoke(**changes)
                self.assertEqual(code, 2)
                self.assertEqual(report['code'], expected)
        for field, value in [('fuel', True), ('max_frames', -1), ('extra', 1)]:
            policy = deepcopy(self.policy)
            policy[field] = value
            code, report = self.invoke(policy=policy)
            self.assertEqual(code, 2)
            self.assertEqual(report['code'], 'REFERENCE-POLICY')
        code, report = self.invoke(policy_bytes=b'{"fuel":1,"fuel":2}')
        self.assertEqual((code, report['code']), (2, 'REFERENCE-POLICY-DUPLICATE'))

    def test_unsupported_body_rejected_before_effects(self):
        roots = deepcopy(self.roots)
        roots[3]['functions'][0]['blocks'][0]['ops'].insert(0,
            {'op': 'effect_barrier', 'results': [], 'operands': []})
        code, report = self.invoke(roots=roots)
        self.assertEqual((code, report['code']), (2, 'REFERENCE-EXECUTION-OPERATION-SCOPE'))
        self.assertNotIn('steps', report)

    def test_generic_indirect_cannot_bypass_source_call_plan(self):
        roots = deepcopy(self.roots)
        roots[3]['functions'][1]['blocks'][0]['ops'][-1]['source_plan'] = None
        code, report = self.invoke(roots=roots)
        self.assertEqual((code, report['code']), (2, 'REFERENCE-GENERIC-INDIRECT-CALL-SCOPE'))
        self.assertNotIn('steps', report)

    def test_content_identity_and_old_revision_reject(self):
        decoded = codec.decode_candidate((HERE / 'call42.smo').read_bytes())
        for revision in (False, True):
            changed = deepcopy(decoded)
            section = next(item for item in changed['sections'] if item['kind'] == (1 if revision else 2))
            data = bytearray.fromhex(section['hex'])
            if revision:
                data[:4] = (1).to_bytes(4, 'little')
            else:
                data[8] ^= 1  # Manifest identity field; representation remains valid.
            section['hex'] = data.hex()
            raw = codec.encode_candidate(changed)
            code, report = self.invoke(raw=raw)
            self.assertEqual((code, report['code']), (2, 'WIRE-REVISION' if revision else 'WIRE-IDENTITY'))

    def test_zero_source_budget_is_resource_before_guest_steps(self):
        policy = deepcopy(self.policy)
        policy['source_budget']['max_work'] = 0
        code, report = self.invoke(policy=policy)
        self.assertEqual(code, 2)
        self.assertEqual(report['status'], 'reference-resource')
        self.assertEqual(report['code'], 'SOURCE_DATA_RESOURCE')
        self.assertEqual(report['steps'], 0)


if __name__ == '__main__':
    unittest.main()
