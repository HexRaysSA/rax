"""Independent whole-object generic shapes and real reference execution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import generic_function_cases as cases
import test_metadata_manifest as protected

# Accepted ordinary-scalar mapping 711d3de3. Keep the original expected.json
# historical table and original object bytes; change only this current result.
CURRENT_RUST_OVERRIDES = {'cpp64-control': {'status': 'verified-object'}}


def inputs(rust):
    paths = protected.input_paths(rust) | {Path(__file__), Path(cases.__file__)}
    paths.update(p for p in cases.FIXTURES.rglob('*') if p.is_file())
    paths.add(cases.ROOT / 'docs/specifications/smir/portable/conformance/llvm/ordinary-scalar/plain-char-control.smo')
    return paths


class GenericFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((cases.FIXTURES / 'expected.json').read_text())['cases']
        cls.observed = json.loads((cases.FIXTURES / 'observed-python.json').read_text())
        cls.roots = cases.cases()
        cls.rust = Path(os.environ.get('SMIR_GENERIC_RUST_CLI', os.environ.get(
            'SMIR_METADATA_RUST_CLI', '/tmp/rax-portable-smir-01/RUNTIME/GENERIC-SHAPES-qualified-snapshot-cli')))
        cls.before = {p: protected.digest(p) for p in inputs(cls.rust)}
        cls.execution = []

    @classmethod
    def tearDownClass(cls):
        drift = [str(p) for p, h in cls.before.items() if not p.is_file() or protected.digest(p) != h]
        drift += [str(p) for p in inputs(cls.rust) - cls.before.keys()]
        if drift:
            raise AssertionError('Source/fixture/binary drift: ' + repr(drift))

    def test_wire_regeneration_and_protected_41(self):
        self.assertEqual(len(self.expected), 35)
        self.assertEqual({r['name'] for r in self.expected}, set(self.roots))
        codec = cases.original.load_codec()
        for row in self.observed:
            with self.subTest(case=row['name']):
                data = (cases.FIXTURES / (row['name'] + '.smo')).read_bytes()
                self.assertEqual(codec.encode(self.roots[row['name']]), data)
                self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        for row in json.loads((cases.original.FIXTURES / 'observed-python.json').read_text()):
            with self.subTest(protected=row['name']):
                self.assertEqual(protected.digest(cases.original.FIXTURES / (row['name'] + '.smo')), row['sha256'])

    def test_actual_python_contracts_normal_and_optimized(self):
        for optimized in (False, True):
            for row in self.expected:
                with self.subTest(case=row['name'], optimized=optimized):
                    actual = cases.observe((cases.FIXTURES / (row['name'] + '.smo')).read_bytes(), optimized=optimized)
                    self.assertEqual(actual['interpreter_optimization'], int(optimized))
                    self.assertEqual(actual['status'], row['python']['status'])
                    if 'code' in row['python']:
                        self.assertEqual(actual['code'], row['python']['code'])
                        self.assertEqual(actual['exception'], 'Reject')
                    else:
                        self.assertIs(actual['production_admitted'], False)
                        self.assertIs(actual['provider_selection_performed'], False)

    def test_actual_rust_whole_factories_and_protected_41(self):
        self.assertTrue(self.rust.is_file(), 'Actual generic-shape verifier required: SMIR_GENERIC_RUST_CLI')
        rows = [(cases.FIXTURES, dict(row, rust=CURRENT_RUST_OVERRIDES.get(row['name'], row['rust'])))
                for row in self.expected]
        old = json.loads((cases.original.FIXTURES / 'observed-python.json').read_text())
        for row in old:
            name = row['name']
            if name in protected.NEGATIVES:
                expected = dict(status='rejected', code=protected.NEGATIVES[name][1], **{'class': 'semantic'})
            elif name in protected.UNKNOWN_CONTROLS:
                expected = dict(status='rejected', code=protected.UNKNOWN_CONTROLS[name], **{'class': 'unavailable-evidence'})
            else:
                expected = dict(status='verified-object')
            rows.append((cases.original.FIXTURES, dict(name=name, rust=expected)))
        for directory, row in rows:
            with self.subTest(case=row['name'], directory=str(directory)):
                process = subprocess.run([str(self.rust), 'verify', str(directory / (row['name'] + '.smo'))],
                                         capture_output=True, text=True, check=False)
                actual = json.loads(process.stdout)
                for name, value in row['rust'].items():
                    self.assertEqual(actual[name], value)
                if actual['status'] == 'verified-object':
                    self.assertEqual(process.returncode, 0)
                    self.assertEqual(process.stderr, '')
                    self.assertIs(actual['executable_admitted'], False)
                else:
                    self.assertEqual(process.returncode, 1)
                    self.assertTrue(process.stderr.startswith(actual['code'] + ':'))

    def invoke(self, name, arguments, *, optimized):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='1' if optimized else '0')
        command = [sys.executable, '-B'] + (['-O'] if optimized else []) + [
            str(cases.ROOT / 'tools/smir-format/smir.py'), 'run', str(cases.FIXTURES / (name + '.smo')),
            '--entry-function', '0', '--reference-policy', str(cases.FIXTURES / 'policy.json')]
        for argument in arguments:
            command += ['--argument-bits', argument]
        result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
        self.execution.append(dict(command=command, optimized=optimized, exit=result.returncode,
                                   stdout=result.stdout, stderr=result.stderr))
        return result

    def test_real_wide_internal_call_and_wrapping_normal_and_optimized(self):
        mask = (1 << 64) - 1
        vectors = [(mask - 2, 17), (mask, 0), ((1 << 63) + 1, (1 << 63) + 1)]
        for optimized in (False, True):
            for x, y in vectors:
                with self.subTest(x=x, y=y, optimized=optimized):
                    result = self.invoke('wide-internal-call', [v.to_bytes(8, 'little').hex() for v in (x, y)], optimized=optimized)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    total = (x + y) & mask
                    expected = [total, (total * total) & mask]
                    self.assertEqual(report['status'], 'reference-return')
                    self.assertEqual(report['values'], [{'bits_le': v.to_bytes(8, 'little').hex()} for v in expected])
                    self.assertEqual(report['steps'], 7)
                    self.assertIs(report['production_admitted'], False)

    def test_real_small_width_and_void_entries(self):
        for optimized in (False, True):
            for name, arguments, values in [('int1', ['01'], [{'bits_le': '01'}]),
                    ('int9', ['ff01'], [{'bits_le': 'ff01'}]), ('void', [], []),
                    ('cpp64-control', ['00' * 8], [{'bits_le': '00' * 8}])]:
                with self.subTest(case=name, optimized=optimized):
                    result = self.invoke(name, arguments, optimized=optimized)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['values'], values)
                    self.assertIs(report['production_admitted'], False)

    def test_refusals_before_original_machine_methods_in_both_modes(self):
        failures = [('wide-internal-call', ['00' * 7, '00' * 8], 'REFERENCE-ARGUMENT-BITS'),
                    ('wide-internal-call', ['FD' + 'ff' * 7, '00' * 8], 'REFERENCE-ARGUMENT-BITS'),
                    ('int1', ['02'], 'REFERENCE-ARGUMENT-BITS'),
                    ('int9', ['ff03'], 'REFERENCE-ARGUMENT-BITS'),
                    ('int65', ['00' * 9], 'REFERENCE-ARGUMENT-BITS'),
                    ('int65', ['00' * 8], 'REFERENCE-EXECUTION-TYPE-SCOPE'),
                    ('code-address', ['00' * 8], 'REFERENCE-EXECUTION-SIGNATURE-SCOPE'),
                    ('data-pointer', ['00' * 8], 'REFERENCE-EXECUTION-TYPE-SCOPE'),
                    ('../ordinary-scalar/plain-char-control', ['ff'], 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')]
        for optimized in (False, True):
            for name, arguments, code in failures:
                with self.subTest(case=name, arguments=arguments, optimized=optimized):
                    command = [sys.executable, '-B'] + (['-O'] if optimized else []) + [str(Path(cases.__file__)), 'refusal-probe']
                    result = subprocess.run(command, input=json.dumps(dict(case=name, arguments=arguments)),
                                            text=True, capture_output=True, check=True)
                    actual = json.loads(result.stdout)
                    self.assertEqual(actual['interpreter_optimization'], int(optimized))
                    self.assertEqual(actual['status'], 'rejected')
                    self.assertEqual(actual['code'], code)
                    self.assertEqual(actual['calls'], {'__init__': 0, 'start': 0, 'run': 0})
                    self.assertIs(actual['restored'], True)


if __name__ == '__main__':
    unittest.main()
