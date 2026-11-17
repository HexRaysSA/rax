"""Whole-factory metadata conformance, independent of R's fixture generator."""
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import metadata_manifest_cases as cases

# Exact independent diagnostic pairs, proposed to R/ROOT before gate intake.
# Different phase ordering is explicit; no framing/schema/resource failure can
# satisfy a semantic rejection. These are contracts, never copied at test time.
NEGATIVES = {
    'reject-export-function-target-namespace': ('function_definition_reference', 'P2_LOCAL_REFERENCE'),
    'reject-export-recipe-namespace': ('abi_namespace_reference', 'P2_LOCAL_REFERENCE'),
    'reject-export-function-execution': ('RT_EXPORT_EXECUTION', 'RT_EXPORT_EXECUTION'),
    'reject-export-function-nominal': ('RT_EXPORT_NOMINAL', 'RT_EXPORT_NOMINAL'),
    'reject-export-function-plan-missing': ('RT_EXPORT_SOURCE_PLAN_PRESENCE', 'RT_EXPORT_SOURCE_PLAN'),
    'reject-export-function-linkage': ('RT_EXPORT_SOURCE_LINKAGE', 'RT_EXPORT_SOURCE_LINKAGE'),
    'reject-export-type-nominal-binding': ('RT_EXPORT_NOMINAL_BINDING', 'RT_EXPORT_NOMINAL_BINDING'),
    'reject-export-type-execution-missing': ('RT_EXPORT_TYPE_PRESENCE', 'RT_EXPORT_TYPE_PRESENCE'),
    'reject-export-dependency-target': ('RT_EXPORT_SELF', 'RT_EXPORT_SELF'),
    'reject-declaration-type-symbol-kind': ('declaration_symbol_kind', 'RT_DECLARATION_SYMBOL_KIND'),
    'reject-declaration-type-weak': ('RT_WEAK_DECLARATION_KIND', 'RT_WEAK_DECLARATION_KIND'),
    'reject-declaration-type-linkage': ('RT_SOURCE_LINKAGE', 'RT_SOURCE_LINKAGE'),
    'reject-declaration-function-plan-missing': ('RT_SOURCE_PLAN_PRESENCE', 'RT_SOURCE_PLAN_PRESENCE'),
    'reject-declaration-symbol-execution': ('declaration_function_signature', 'RT_DECLARATION_SYMBOL_TYPE'),
    'reject-declaration-address-execution': ('declaration_function_address', 'RT_DECLARATION_SYMBOL_TYPE'),
    'reject-declaration-address-plan': ('declaration_function_address', 'RT_FUNCTION_ADDRESS_SHAPE'),
    'reject-symbol-linkage': ('RT_SYMBOL_SOURCE_LINKAGE', 'RT_SYMBOL_SOURCE_LINKAGE'),
    'reject-symbol-body-namespace': ('function_definition_reference', 'P2_LOCAL_REFERENCE'),
    'reject-manifest-site': ('RT_SITE_IDENTITY', 'RT_SITE_IDENTITY'),
    'reject-declaration-function-scalar': ('declaration_function_signature', 'RT_DECLARATION_FUNCTION_TYPE'),
    'reject-declaration-function-plan-execution': ('RT_DECLARATION_SOURCE_PLAN_EXECUTION', 'RT_DECLARATION_SOURCE_PLAN_EXECUTION'),
    'reject-declaration-symbol-plan-execution': ('RT_DECLARATION_SOURCE_PLAN_EXECUTION', 'RT_DECLARATION_SOURCE_PLAN_EXECUTION'),
    'reject-declaration-import-plan-execution': ('RT_DECLARATION_SOURCE_PLAN_EXECUTION', 'RT_DECLARATION_SOURCE_PLAN_EXECUTION'),
}
# Accepted ordinary-scalar mapping 711d3de3: original c-function bytes now
# receive a complete static proof. Hidden coverage remains an exact refusal.
UNKNOWN_CONTROLS = {'hidden-control': 'P2_METADATA_PROFILE_UNAUDITED'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def input_paths(rust):
    inputs = set(cases.FIXTURES.rglob('*'))
    for directory in ('tools/smir-format', 'tools/smir-abi', 'tools/smir-runtime-contract',
                      'docs/specifications/smir/portable/schema'):
        inputs.update((cases.ROOT / directory).rglob('*.py'))
        inputs.update((cases.ROOT / directory).rglob('*.json'))
    inputs.update((Path(cases.__file__), Path(__file__)))
    if rust.is_file():
        inputs.add(rust)
    return {p for p in inputs if p.is_file()}


class MetadataManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads((cases.FIXTURES / 'observed-python.json').read_text())
        cls.roots = cases.cases()
        cls.rust = Path(os.environ.get('SMIR_METADATA_RUST_CLI', str(cases.DEFAULT_RUST)))
        # Preserve exact semantic inputs and tools across this focused run.
        cls.inputs = {p: digest(p) for p in input_paths(cls.rust)}

    @classmethod
    def tearDownClass(cls):
        drift = [str(p) for p, before in cls.inputs.items() if not p.is_file() or digest(p) != before]
        drift += [str(p) for p in input_paths(cls.rust) - cls.inputs.keys()]
        if drift:
            raise AssertionError('Source/binary changed during verification: ' + repr(drift))

    def test_fixture_regeneration(self):
        codec = cases.load_codec()
        self.assertEqual(len(self.records), 41)
        self.assertEqual({r['name'] for r in self.records}, set(self.roots))
        self.assertEqual(set(NEGATIVES), {n for n in self.roots if n.startswith('reject-')})
        for record in self.records:
            with self.subTest(case=record['name']):
                payload = (cases.FIXTURES / (record['name'] + '.smo')).read_bytes()
                self.assertEqual(codec.encode(self.roots[record['name']]), payload)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), record['sha256'])

    def test_independent_python_contracts(self):
        for record in self.records:
            name = record['name']
            with self.subTest(case=name):
                actual = cases.observe((cases.FIXTURES / (name + '.smo')).read_bytes())
                self.assertEqual(actual, record['python'])
                if name in NEGATIVES:
                    self.assertEqual(actual['status'], 'rejected')
                    self.assertEqual(actual['code'], NEGATIVES[name][0])
                    self.assertEqual(actual['exception'], 'Reject')
                else:
                    self.assertEqual(actual, {'status': 'verified-static-metadata',
                        'production_admitted': False, 'provider_selection_performed': False})

    def test_actual_rust_whole_factory(self):
        self.assertTrue(self.rust.is_file(), 'Actual smir-inspect required; set SMIR_METADATA_RUST_CLI')
        for record in self.records:
            name = record['name']
            with self.subTest(case=name):
                command = [str(self.rust), 'verify', str(cases.FIXTURES / (name + '.smo'))]
                process = subprocess.run(command, capture_output=True, text=True, check=False)
                report = json.loads(process.stdout)
                if name in NEGATIVES:
                    self.assertEqual(process.returncode, 1)
                    self.assertEqual(report['status'], 'rejected')
                    self.assertEqual(report['class'], 'semantic')
                    self.assertEqual(report['code'], NEGATIVES[name][1])
                    self.assertTrue(process.stderr.startswith(report['code'] + ':'))
                elif name in UNKNOWN_CONTROLS:
                    self.assertEqual(process.returncode, 1)
                    self.assertEqual(report['class'], 'unavailable-evidence')
                    self.assertEqual(report['code'], UNKNOWN_CONTROLS[name])
                    self.assertTrue(process.stderr.startswith(report['code'] + ':'))
                else:
                    self.assertEqual(process.stderr, '')
                    self.assertEqual(process.returncode, 0, report)
                    self.assertEqual(report['status'], 'verified-object')
                    self.assertIs(report['executable_admitted'], False)


if __name__ == '__main__':
    unittest.main()
