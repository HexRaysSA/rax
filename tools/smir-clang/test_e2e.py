#!/usr/bin/env python3
"""End to end: C compiled to portable SMIR against the same C compiled natively.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v

For every exported function of every file in `tests/c`, at each optimization
level in LEVELS, the function is run on generated argument vectors in the Rust
interpreter (`smir-run --batch`) and its result compared with a native build of
the same source. The native build uses the host C compiler with the undefined
behaviour sanitizer set to abort, so a corpus program that is not fully defined
for some vector fails the test instead of weakening the comparison.

Requires the pinned LLVM checkout (see build.py), cargo, and a host C compiler
(`cc`, or $CC). A missing requirement is a failure, not a skip.
"""
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import smircc  # noqa: E402

CORPUS = sorted((HERE / 'tests/c').glob('*.c'))
LEVELS = ('-O0', '-O1', '-O2', '-Os')
CRATE = ROOT / 'crates/smir-portable'
# The corpus terminates; this only bounds a miscompiled loop.
FUEL = 20_000_000


def mask(bits):
    return (1 << bits) - 1


def edges(bits):
    """Boundary values of a width and a few small numbers."""
    sign = 1 << (bits - 1)
    values = {0, 1, 2, 3, mask(bits), mask(bits) - 1, sign, sign - 1, sign + 1, bits, bits - 1,
              5, 7, 10, 12, 27, 100, 255, 1000}
    return sorted(value & mask(bits) for value in values)


def vectors(params, generator):
    """Argument tuples: boundary combinations, then pseudo-random tuples."""
    if not params:
        return [()]
    if len(params) == 1:
        tuples = [(value,) for value in edges(params[0])]
    elif len(params) == 2:
        tuples = [(a, b) for a in edges(params[0]) for b in edges(params[1])]
    else:
        tuples = []
    for round_ in range(40):
        tuples.append(tuple(generator.getrandbits(bits) & (mask(bits) if round_ % 2 == 0 else 0xff)
                            for bits in params))
    return tuples


def little_endian(value, bits):
    return value.to_bytes((bits + 7) // 8, 'little').hex()


def run(arguments, **options):
    return subprocess.run([str(item) for item in arguments], capture_output=True, text=True, **options)


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-e2e-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.scratch = Path(cls.directory.name)
        build.build()
        cargo = run(['cargo', 'build', '--offline', '--locked', '--manifest-path', CRATE / 'Cargo.toml',
                     '--bin', 'smir-run'])
        if cargo.returncode != 0:
            raise RuntimeError('cannot build smir-run:\n' + cargo.stderr[-4000:])
        cls.runner = CRATE / 'target/debug/smir-run'
        cls.host = os.environ.get('CC', 'cc')

    def native(self, source, cases):
        """Results of `cases` from a native build of `source`, in order."""
        lines = ['#include <stdio.h>', f'#include "{source}"', 'int main(void) {']
        for case in cases:
            call = f'{case["name"]}({", ".join(f"{value:#x}ull" for value in case["values"])})'
            if case['results']:
                lines.append(f'  printf("%llx\\n", (unsigned long long)({call}) & {mask(case["results"][0]):#x}ull);')
            else:
                lines.append(f'  {call}; puts("void");')
        lines += ['  return 0;', '}', '']
        harness = self.scratch / (source.stem + '-native.c')
        harness.write_text('\n'.join(lines))
        binary = self.scratch / (source.stem + '-native')
        compiled = run([self.host, '-std=c2x', '-O1', '-fsigned-char', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', '-w', '-o', binary, harness])
        self.assertEqual(compiled.returncode, 0, compiled.stderr[-4000:])
        executed = run([binary], timeout=120)
        self.assertEqual(executed.returncode, 0,
                         f'{source.name} is not fully defined on the test vectors:\n{executed.stderr[-2000:]}')
        results = executed.stdout.split()
        self.assertEqual(len(results), len(cases))
        return results

    def test_corpus_matches_native_results_at_every_level(self):
        self.assertGreaterEqual(len(CORPUS), 7)
        total = 0
        for source in CORPUS:
            generator = random.Random(source.name)
            expected = cases = None
            for level in LEVELS:
                with self.subTest(source=source.name, level=level):
                    object_path = self.scratch / f'{source.stem}{level}.smo'
                    index = [entry for entry in smircc.compile_file(source, object_path, [level])
                             if not entry['local'] and 'ptr' not in entry['params'] + entry['results']]
                    signatures = [(entry['name'], entry['params'], entry['results']) for entry in index]
                    if cases is None:
                        # Vectors and native results are fixed by the first level.
                        reference = signatures
                        cases = [dict(name=name, params=params, results=results, values=values)
                                 for name, params, results in signatures
                                 for values in vectors(params, generator)]
                        expected = self.native(source, cases)
                    self.assertEqual(signatures, reference, 'exported signatures differ between levels')
                    identifiers = {entry['name']: entry['function'] for entry in index}
                    request = [{'function': identifiers[case['name']],
                                'arguments': [little_endian(value, bits)
                                              for value, bits in zip(case['values'], case['params'])]}
                               for case in cases]
                    executed = run([self.runner, object_path, '--batch', '--fuel', FUEL],
                                   input=json.dumps(request), timeout=600)
                    self.assertEqual(executed.returncode, 0, executed.stdout[-2000:] + executed.stderr[-2000:])
                    reports = json.loads(executed.stdout)
                    self.assertEqual(len(reports), len(cases))
                    wrong = []
                    for case, report, native in zip(cases, reports, expected):
                        if report.get('status') != 'return':
                            actual = json.dumps(report)
                        elif case['results']:
                            actual = format(int.from_bytes(bytes.fromhex(report['values'][0]['bits_le']), 'little'), 'x')
                        else:
                            actual = 'void' if report['values'] == [] else json.dumps(report)
                        if actual != native:
                            arguments = ', '.join(hex(value) for value in case['values'])
                            wrong.append(f'{case["name"]}({arguments}): smir {actual}, native {native}')
                    self.assertFalse(wrong, f'{len(wrong)} of {len(cases)} differ:\n' + '\n'.join(wrong[:10]))
                    total += len(cases)
        print(f'{total} results agree with native execution', file=sys.stderr)
        self.assertGreaterEqual(total, 60_000)

    def test_reference_machine_agrees_on_a_sample_of_compiled_programs(self):
        """A third opinion on the emitter's output, independent of smir-run.

        The Python reference machine executes about five thousand steps a
        second, so only short runs are sampled: per file, up to 40 cases that
        take at most 400 steps.
        """
        oracle = CRATE / 'tests/interp/oracle.py'
        sampled = 0
        for source in CORPUS:
            with self.subTest(source=source.name):
                generator = random.Random(source.name)
                object_path = self.scratch / f'{source.stem}-sample.smo'
                index = [entry for entry in smircc.compile_file(source, object_path, ['-O2'])
                         if not entry['local'] and 'ptr' not in entry['params'] + entry['results']]
                request = [{'function': entry['function'], 'fuel': 5000, 'max_frames': 256,
                            'max_memory_bytes': 1 << 20,
                            'arguments': [little_endian(value, bits) for value, bits in zip(values, entry['params'])]}
                           for entry in index for values in vectors(entry['params'], generator)]
                executed = run([self.runner, object_path, '--batch', '--fuel', 5000, '--max-frames', 256],
                               input=json.dumps(request), timeout=600)
                self.assertEqual(executed.returncode, 0, executed.stderr[-2000:])
                reports = json.loads(executed.stdout)
                short = [position for position, report in enumerate(reports)
                         if report.get('status') == 'return' and report['steps'] <= 400]
                chosen = short[::max(1, len(short) // 40)][:40]
                self.assertGreaterEqual(len(chosen), 20, 'too few short cases to sample')
                reference = run([sys.executable, '-B', oracle, 'machine', object_path],
                                input=json.dumps([request[position] for position in chosen]), timeout=600)
                self.assertEqual(reference.returncode, 0, reference.stderr[-3000:])
                for position, expected in zip(chosen, json.loads(reference.stdout), strict=True):
                    actual = {key: reports[position][key] for key in ('status', 'steps', 'values')}
                    self.assertEqual(actual, expected, f'{source.name} case {request[position]}')
                sampled += len(chosen)
        print(f'{sampled} sampled runs agree with the Python reference machine', file=sys.stderr)

    def test_unsupported_constructs_are_refused_with_nothing_written(self):
        programs = {
            'global': ('int counter; int next(void) { return ++counter; }', 'E-UNSUPPORTED-GLOBAL'),
            'volatile': ('int read(volatile int *p) { return *p; }', 'E-UNSUPPORTED-INSTRUCTION'),
            'variable array': ('int last(int n) { int a[n]; a[n - 1] = n; return a[n - 1]; }',
                               'E-UNSUPPORTED-INSTRUCTION'),
            'function pointer': ('typedef int (*f)(int); f same(f x) { return x; }', 'E-UNSUPPORTED-TYPE'),
            'floating': ('double half(double x) { return x / 2; }', 'E-UNSUPPORTED-TYPE'),
            'indirect': ('int apply(int (*f)(int), int x) { return f(x); }', 'E-UNSUPPORTED-CALL'),
            'external': ('int other(int); int call(int x) { return other(x) + 1; }', 'E-UNSUPPORTED-CALL'),
            'variadic': ('int first(int count, ...) { return count; }', 'E-UNSUPPORTED-FUNCTION'),
            'wide': ('_BitInt(200) widen(long x) { return x; }', 'E-UNSUPPORTED-TYPE'),
        }
        # A variable-length array only survives to the emitter unoptimized.
        levels = {'variable array': '-O0'}
        for name, (text, code) in programs.items():
            with self.subTest(program=name):
                source = self.scratch / f'refused-{name}.c'
                source.write_text(text + '\n')
                output = self.scratch / f'refused-{name}.smo'
                with self.assertRaises(smircc.CompileError) as raised:
                    smircc.compile_file(source, output, [levels.get(name, '-O2')])
                self.assertIn(code, str(raised.exception))
                self.assertIn('nothing written', str(raised.exception))
                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + '.index.json').exists())

    def test_source_errors_are_reported_by_the_compiler(self):
        source = self.scratch / 'broken.c'
        source.write_text('int broken(void) { return undeclared; }\n')
        with self.assertRaises(smircc.CompileError) as raised:
            smircc.compile_file(source, self.scratch / 'broken.smo', ['-O2'])
        self.assertIn("undeclared identifier 'undeclared'", str(raised.exception))


if __name__ == '__main__':
    unittest.main()
