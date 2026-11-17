"""Independent static source-scalar conformance; no production execution claim."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

import ordinary_scalar_cases as cases
import test_generic_functions as generic
import test_metadata_manifest as metadata

# Exact independently reviewed semantic pairs. ABI rejects precede metadata
# and ProgramFacts; a coverage/resource/schema refusal never counts as semantic.
NEGATIVES = {
    'reject-builtin-signedness': ('ABI_CC_SCALAR_SIGNEDNESS', 'ABI_CC_SCALAR_SIGNEDNESS'),
    'reject-builtin-precision': ('ABI_CC_TYPE_BINDING', 'ABI_CC_TYPE_BINDING'),
    'reject-layout-size': ('ABI_CC_LAYOUT_EXTENT', 'ABI_CC_LAYOUT_EXTENT'),
    'reject-source-index': ('ABI_CC_CALL_PARAMETER', 'ABI_CC_CALL_PARAMETER'),
    'reject-lowered-width': ('ABI_CC_DIRECT_TYPE', 'ABI_CC_DIRECT_TYPE'),
    'reject-plan-execution': ('ABI_CC_LOWERED_SIGNATURE', 'ABI_CC_LOWERED_SIGNATURE'),
    'reject-default-execution': ('ABI_CC_TYPE_BINDING', 'ABI_CC_TYPE_BINDING'),
    'reject-source-linkage': ('RT_SYMBOL_SOURCE_LINKAGE', 'RT_SYMBOL_SOURCE_LINKAGE'),
    'reject-param-noundef': ('ABI_CC_LOWERED_SIGNATURE', 'ABI_CC_LOWERED_SIGNATURE'),
    'reject-result-noundef': ('ABI_CC_LOWERED_SIGNATURE', 'ABI_CC_LOWERED_SIGNATURE'),
    'reject-return-arity': ('return_signature', 'return_signature'),
    'reject-same-width-source-identity': ('RT_SOURCE_PLAN_NOMINAL', 'RT_SOURCE_PLAN_NOMINAL'),
}
UNKNOWN = {'some-void-control': 'P2_ABI_VERIFIER_INCOMPLETE',
           'plain-char-control': 'P2_ABI_VERIFIER_INCOMPLETE',
           'hidden-control': 'P2_METADATA_PROFILE_UNAUDITED'}


def inputs(rust):
    paths = generic.inputs(rust) | {Path(__file__), Path(cases.__file__)}
    paths.update(p for p in cases.FIXTURES.rglob('*') if p.is_file())
    return paths


class OrdinaryScalarCalls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads((cases.FIXTURES / 'observed-python.json').read_text())
        cls.roots = cases.cases()
        cls.rust = Path(os.environ.get('SMIR_SCALAR_RUST_CLI', '/tmp/rax-portable-smir-01/RUNTIME/ORDINARY-SCALAR-qualified-snapshot-cli'))
        cls.before = {p: metadata.digest(p) for p in inputs(cls.rust)}

    @classmethod
    def tearDownClass(cls):
        drift = [str(p) for p, h in cls.before.items() if not p.is_file() or metadata.digest(p) != h]
        drift += [str(p) for p in inputs(cls.rust) - cls.before.keys()]
        if drift:
            raise AssertionError('Source/fixture/binary drift: ' + repr(drift))

    def test_wire_regeneration_and_old_76_unchanged(self):
        self.assertEqual(len(self.records), 43)
        self.assertEqual({r['name'] for r in self.records}, set(self.roots))
        self.assertEqual(set(NEGATIVES), {n for n in self.roots if n.startswith('reject-')})
        codec = cases.original.load_codec()
        for row in self.records:
            with self.subTest(case=row['name']):
                data = (cases.FIXTURES / (row['name'] + '.smo')).read_bytes()
                self.assertEqual(codec.encode(self.roots[row['name']]), data)
                self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        for directory in (cases.original.FIXTURES, generic.cases.FIXTURES):
            for row in json.loads((directory / 'observed-python.json').read_text()):
                with self.subTest(protected=row['name'], directory=str(directory)):
                    self.assertEqual(metadata.digest(directory / (row['name'] + '.smo')), row['sha256'])

    def test_actual_python_normal_and_optimized(self):
        for optimized in (False, True):
            for row in self.records:
                name = row['name']
                with self.subTest(case=name, optimized=optimized):
                    actual = cases.observe((cases.FIXTURES / (name + '.smo')).read_bytes(), optimized=optimized)
                    self.assertEqual(actual['interpreter_optimization'], int(optimized))
                    if name in NEGATIVES:
                        self.assertEqual(actual['status'], 'rejected')
                        self.assertEqual(actual['code'], NEGATIVES[name][0])
                        self.assertEqual(actual['exception'],
                                         'ABIError' if NEGATIVES[name][0].startswith('ABI_CC_') else 'Reject')
                    else:
                        self.assertEqual(actual['status'], 'verified-static-metadata')
                        self.assertIs(actual['production_admitted'], False)
                        self.assertIs(actual['provider_selection_performed'], False)

    def test_actual_full_rust_factories(self):
        self.assertTrue(self.rust.is_file(), 'Actual source-scalar Rust CLI required: SMIR_SCALAR_RUST_CLI')
        for row in self.records:
            name = row['name']
            with self.subTest(case=name):
                process = subprocess.run([str(self.rust), 'verify', str(cases.FIXTURES / (name + '.smo'))],
                    capture_output=True, text=True, check=False)
                actual = json.loads(process.stdout)
                if name in NEGATIVES or name in UNKNOWN:
                    self.assertEqual(process.returncode, 1)
                    self.assertEqual(actual['status'], 'rejected')
                    self.assertEqual(actual['class'], 'semantic' if name in NEGATIVES else 'unavailable-evidence')
                    self.assertEqual(actual['code'], NEGATIVES[name][1] if name in NEGATIVES else UNKNOWN[name])
                    self.assertTrue(process.stderr.startswith(actual['code'] + ':'))
                else:
                    self.assertEqual(process.returncode, 0, process.stderr)
                    self.assertEqual(process.stderr, '')
                    self.assertEqual(actual['status'], 'verified-object')
                    self.assertIs(actual['executable_admitted'], False)


if __name__ == '__main__':
    unittest.main()
