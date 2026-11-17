#!/usr/bin/env python3
"""End to end: C compiled to portable SMIR against the same C compiled natively.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v

For every exported function of every file in `tests/c` and `tests/cxx`, at each optimization
level in LEVELS, the function is run on generated argument vectors in the Rust
interpreter (`smir-run --batch`) and its result compared with a native build of
the same source. The native build uses the host C compiler with the undefined
behaviour sanitizer set to abort, so a corpus program that is not fully defined
for some vector fails the test instead of weakening the comparison.

Each directory in `tests/linked` is one program of several translation units,
compiled and linked into one object and compared the same way. Its header,
named after the directory, declares the exported functions.

Each directory in `tests/programs` is a whole program with a `main`. It is run
with `smir-run --program` on every entry of its `runs.json` (arguments and
standard input), and its standard output, standard error and exit status are
compared with those of the native build, which gets the runtime services from
`tests/native/services.c`.

Requires the pinned LLVM checkout (see build.py), cargo, and a host C compiler
(`cc`, or $CC). A missing requirement is a failure, not a skip.
"""
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import smircc  # noqa: E402

CORPUS = sorted((HERE / 'tests/c').glob('*.c')) + sorted((HERE / 'tests/cxx').glob('*.cpp'))
LINKED = sorted(path for path in (HERE / 'tests/linked').iterdir() if path.is_dir())
PROGRAMS = sorted(path for path in (HERE / 'tests/programs').iterdir() if path.is_dir())
NATIVE_SERVICES = HERE / 'tests/native/services.c'
LEVELS = ('-O0', '-O1', '-O2', '-Os')
CRATE = ROOT / 'crates/smir-portable'
# The corpus terminates; this only bounds a miscompiled loop.
FUEL = 20_000_000


def mask(bits):
    return (1 << bits) - 1


def width(kind):
    """Bits of a parameter or result: an integer width, or 'f32' or 'f64'."""
    return {'f32': 32, 'f64': 64}.get(kind, kind)


def is_nan(kind, bits):
    """Whether `bits` encodes a NaN of the float `kind`; an integer never does."""
    if kind not in ('f32', 'f64'):
        return False
    exponent, fraction = (0xff, 23) if kind == 'f32' else (0x7ff, 52)
    return bits >> fraction & exponent == exponent and bits & mask(fraction) != 0


def float_edges(kind):
    """Encodings that exercise a float format."""
    code = '<f' if kind == 'f32' else '<d'
    numbers = [0.0, -0.0, 1.0, -1.0, 2.0, 0.5, 1.5, -2.5, 0.1, 3.0, 100.0, -1000.0, 1.0e10, -3.0e-10,
               255.5, -128.5, 2147483648.0, -2147483649.0, 4294967296.0, 9.0e18, -9.3e18, 1.0e30,
               float('inf'), float('-inf'), float('nan')]
    edges = {int.from_bytes(struct.pack(code, number), 'little') for number in numbers}
    # The largest finite value, the smallest normal and subnormal, a negative
    # NaN with a payload and a signaling NaN.
    edges |= ({0x7f7fffff, 0x00800000, 0x00000001, 0x807fffff, 0xffc12345, 0x7f800001} if kind == 'f32' else
              {0x7fefffffffffffff, 0x0010000000000000, 0x0000000000000001, 0x800fffffffffffff,
               0xfff8001234567890, 0x7ff0000000000001})
    return sorted(edges)


def edges(kind):
    """Boundary values of a width and a few small numbers, or of a float format."""
    if kind in ('f32', 'f64'):
        return float_edges(kind)
    bits = kind
    sign = 1 << (bits - 1)
    values = {0, 1, 2, 3, mask(bits), mask(bits) - 1, sign, sign - 1, sign + 1, bits, bits - 1,
              5, 7, 10, 12, 17, 27, 100, 255, 900, 1000, 40000, -70000}
    return sorted(value & mask(bits) for value in values)


def arbitrary(kind, generator, small):
    """A pseudo-random argument: any bit pattern, or when `small` a modest value."""
    bits = width(kind)
    if not small:
        return generator.getrandbits(bits)
    if kind in ('f32', 'f64'):
        number = (generator.getrandbits(20) - (1 << 19)) / 256.0
        return int.from_bytes(struct.pack('<f' if kind == 'f32' else '<d', number), 'little')
    return generator.getrandbits(bits) & 0xff


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
        tuples.append(tuple(arbitrary(kind, generator, round_ % 2 == 1) for kind in params))
    return tuples


def little_endian(value, kind):
    return value.to_bytes((width(kind) + 7) // 8, 'little').hex()


def entry_points(index):
    """The functions of an object that the tests call: exported, over integers and floats.

    A name that begins with two underscores is reserved for the language's
    runtime support, which a source may have to supply; it is not called.
    """
    return [entry for entry in index
            if not entry['local'] and not entry['name'].startswith('__')
            and not {'ptr', 'f128'} & set(entry['params'] + entry['results'])]


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

    def native(self, name, include, units, cases):
        """Results of `cases` from a native build, in order.

        The harness includes `include` for the functions it calls and is
        compiled together with `units`.
        """
        # A float argument is built from its encoding, and a float result is
        # printed as its encoding, or as "nan": which NaN a computation yields
        # is the one thing the two builds may differ in.
        lines = ['#include <stdio.h>', '#include <string.h>', f'#include "{include}"',
                 'static float harness_f32(unsigned bits) { float value; memcpy(&value, &bits, 4); return value; }',
                 'static double harness_f64(unsigned long long bits) {',
                 '  double value; memcpy(&value, &bits, 8); return value; }',
                 'static void harness_show32(float value) { unsigned bits; memcpy(&bits, &value, 4);',
                 '  if (value != value) puts("nan"); else printf("%x\\n", bits); }',
                 'static void harness_show64(double value) { unsigned long long bits; memcpy(&bits, &value, 8);',
                 '  if (value != value) puts("nan"); else printf("%llx\\n", bits); }',
                 'int main(void) {']
        literal = {'f32': 'harness_f32({:#x}u)', 'f64': 'harness_f64({:#x}ull)'}
        for case in cases:
            arguments = ', '.join(literal.get(kind, '{:#x}ull').format(value)
                                  for kind, value in zip(case['params'], case['values']))
            call = f'{case["name"]}({arguments})'
            if not case['results']:
                lines.append(f'  {call}; puts("void");')
            elif case['results'][0] in literal:
                lines.append(f'  harness_show{width(case["results"][0])}({call});')
            else:
                lines.append(f'  printf("%llx\\n", (unsigned long long)({call}) & {mask(case["results"][0]):#x}ull);')
        lines += ['  return 0;', '}', '']
        # A C++ source is included in a C++ harness and built as the compiler
        # under test builds it: no exceptions, no run-time type information.
        cxx = str(include).endswith('.cpp')
        harness = self.scratch / (name + ('-native.cpp' if cxx else '-native.c'))
        harness.write_text('\n'.join(lines))
        binary = self.scratch / (name + '-native')
        language = ([os.environ.get('CXX', 'c++'), '-std=c++2b', '-fno-exceptions', '-fno-rtti'] if cxx
                    else [self.host, '-std=c2x'])
        # Contraction is off, as it is in the compiler under test: a product
        # and a sum are rounded separately unless the source asks for a fused
        # operation.
        compiled = run([*language, '-O1', '-fsigned-char', '-ffp-contract=off',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all', '-w', '-o', binary, harness, *units])
        self.assertEqual(compiled.returncode, 0, compiled.stderr[-4000:])
        executed = run([binary], timeout=120)
        self.assertEqual(executed.returncode, 0,
                         f'{name} is not fully defined on the test vectors:\n{executed.stderr[-2000:]}')
        results = executed.stdout.split()
        self.assertEqual(len(results), len(cases))
        return results

    def agree(self, name, sources, include, units):
        """Compare one program with its native build at every level; return the case count.

        `sources` are compiled and linked to the object. The native harness
        includes `include` and is compiled together with `units`.
        """
        generator = random.Random(name)
        expected = cases = None
        for level in LEVELS:
            with self.subTest(program=name, level=level):
                object_path = self.scratch / f'{Path(name).stem}{level}.smo'
                index = entry_points(smircc.compile_files(sources, object_path, [level]))
                signatures = [(entry['name'], entry['params'], entry['results']) for entry in index]
                if cases is None:
                    # Vectors and native results are fixed by the first level.
                    reference = signatures
                    cases = [dict(name=function, params=params, results=results, values=values)
                             for function, params, results in signatures
                             for values in vectors(params, generator)]
                    expected = self.native(Path(name).stem, include, units, cases)
                self.assertEqual(signatures, reference, 'exported signatures differ between levels')
                identifiers = {entry['name']: entry['function'] for entry in index}
                request = [{'function': identifiers[case['name']],
                            'arguments': [little_endian(value, kind)
                                          for value, kind in zip(case['values'], case['params'])]}
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
                        bits = int.from_bytes(bytes.fromhex(report['values'][0]['bits_le']), 'little')
                        actual = 'nan' if is_nan(case['results'][0], bits) else format(bits, 'x')
                    else:
                        actual = 'void' if report['values'] == [] else json.dumps(report)
                    if actual != native:
                        arguments = ', '.join(hex(value) for value in case['values'])
                        wrong.append(f'{case["name"]}({arguments}): smir {actual}, native {native}')
                self.assertFalse(wrong, f'{len(wrong)} of {len(cases)} differ:\n' + '\n'.join(wrong[:10]))
        return len(LEVELS) * len(cases)

    def test_corpus_matches_native_results_at_every_level(self):
        self.assertGreaterEqual(len(CORPUS), 13)
        total = sum(self.agree(source.name, [source], source, []) for source in CORPUS)
        print(f'{total} results agree with native execution', file=sys.stderr)
        self.assertGreaterEqual(total, 195_000)

    def test_linked_translation_units_match_native_results(self):
        self.assertGreaterEqual(len(LINKED), 1)
        total = 0
        for directory in LINKED:
            units = sorted(directory.glob('*.c'))
            self.assertGreaterEqual(len(units), 2, f'{directory.name} is one translation unit')
            total += self.agree(directory.name, units, directory / f'{directory.name}.h', units)
            # The order the units are given in does not matter.
            with self.subTest(program=directory.name, order='reversed'):
                first, second = (self.scratch / f'{directory.name}-{order}.smo' for order in ('forward', 'reversed'))
                names = [{entry['name'] for entry in smircc.compile_files(given, output, ['-O2'])
                          if not entry['local']}
                         for given, output in ((units, first), (units[::-1], second))]
                self.assertEqual(names[0], names[1])
        print(f'{total} results of linked programs agree with native execution', file=sys.stderr)
        self.assertGreaterEqual(total, 7_000)

    def program(self, object_path, arguments=(), stdin=b'', limits=()):
        """Run a compiled program; returns the completed process, with bytes."""
        return subprocess.run([str(self.runner), str(object_path), '--program', *limits, '--', *arguments],
                              input=stdin, capture_output=True, timeout=120)

    def test_programs_match_native_output_and_exit_status(self):
        self.assertGreaterEqual(len(PROGRAMS), 4)
        total = 0
        for directory in PROGRAMS:
            units = sorted(directory.glob('*.c'))
            runs = json.loads((directory / 'runs.json').read_text())
            native = self.scratch / f'{directory.name}-program'
            compiled = run([self.host, '-std=c2x', '-O1', '-fsigned-char', '-fsanitize=undefined',
                            '-fno-sanitize-recover=all', '-w', '-I', smircc.INCLUDE, '-o', native,
                            *units, NATIVE_SERVICES])
            self.assertEqual(compiled.returncode, 0, compiled.stderr[-4000:])
            expected = [subprocess.run([str(native), *entry['arguments']], input=entry['stdin'].encode(),
                                       capture_output=True, timeout=60) for entry in runs]
            for level in LEVELS:
                object_path = self.scratch / f'{directory.name}-program{level}.smo'
                smircc.compile_files(units, object_path, [level])
                for entry, reference in zip(runs, expected):
                    with self.subTest(program=directory.name, level=level, arguments=entry['arguments']):
                        executed = self.program(object_path, entry['arguments'], entry['stdin'].encode())
                        self.assertEqual(executed.stdout, reference.stdout)
                        if reference.returncode >= 0:
                            self.assertEqual(executed.stderr, reference.stderr)
                            self.assertEqual(executed.returncode, reference.returncode)
                        else:
                            # The native program was ended by a signal, which
                            # only an abort does. The runner reports that after
                            # whatever the program wrote.
                            self.assertEqual(-reference.returncode, 6, 'the native program crashed')
                            self.assertTrue(executed.stderr.startswith(reference.stderr), executed.stderr)
                            report = json.loads(executed.stderr[len(reference.stderr):])
                            self.assertEqual(report['status'], 'abort')
                            self.assertEqual(executed.returncode, 134)
                        total += 1
        print(f'{total} program runs agree with native execution', file=sys.stderr)
        self.assertGreaterEqual(total, 84)

    def test_a_program_that_cannot_complete_is_reported(self):
        services = '#include <smir/services.h>\n'
        programs = {
            # A service guards its buffer like any other access to it.
            'short buffer': (services + 'int main(void) { char b[4] = "abc"; uint64_t n;\n'
                             '  return (int)smir_file_write(SMIR_STANDARD_OUTPUT, b, 5, &n); }',
                             [], ('trap', 'memory_bounds')),
            'null buffer': (services + 'int main(void) { uint64_t n;\n'
                            '  return (int)smir_file_read(SMIR_STANDARD_INPUT, 0, 1, &n); }',
                            [], ('language_ub', 'pointer_provenance')),
            'exit mode': (services + 'int main(void) { smir_process_exit(0, 7); }', [], ('trap', 'service_argument')),
            'endless': ('int main(void) { for (;;) {} }', ['--fuel', '10000'], ('resource', 'fuel')),
            'no main': ('int other(void) { return 1; }', [], ('rejected', 'EXEC_ENTRY')),
            'main shape': ('long main(long x) { return x; }', [], ('rejected', 'EXEC_ENTRY')),
        }
        for name, (text, limits, expected) in programs.items():
            with self.subTest(program=name):
                source = self.scratch / f'incomplete-{name}.c'
                source.write_text(text + '\n')
                object_path = self.scratch / f'incomplete-{name}.smo'
                smircc.compile_files([source], object_path, ['-O0'])
                executed = self.program(object_path, limits=limits)
                self.assertEqual(executed.returncode, 125, executed.stderr)
                self.assertEqual(executed.stdout, b'')
                report = json.loads(executed.stderr)
                self.assertEqual((report['status'], report['code']), expected)

    def test_a_library_supplies_only_what_the_program_uses(self):
        texts = {
            'scale.c': 'static int offset(int x) { return x + 7; }\n'
                       'int scale(int x) { return offset(x) * 3; }\n'
                       # A second name for the same function.
                       'int triple(int) __attribute__((alias("scale")));\n'
                       'int unused(int x) { return x; }\n',
            # Refers to a function nothing defines; harmless until it is used.
            'broken.c': 'int missing(int); int broken(int x) { return missing(x) + 1; }\n',
            'counter.cpp': 'namespace { struct Counter { int value; Counter() : value(40) {} } counter; }\n'
                           'extern "C" int next_count() { return ++counter.value; }\n',
            'program.c': 'int scale(int); int triple(int); int next_count(void);\n'
                         'int entry(int x) { return scale(x) + triple(x) * 100 + next_count() * 10000; }\n',
            'uses_broken.c': 'int broken(int); int entry(int x) { return broken(x); }\n',
        }
        paths = {}
        for name, text in texts.items():
            paths[name] = self.scratch / f'library-{name}'
            paths[name].write_text(text)
        library = self.scratch / 'library.bc'
        smircc.compile_library([paths['scale.c'], paths['broken.c'], paths['counter.cpp']], library, ['-O2'])
        for level in LEVELS:
            with self.subTest(level=level):
                object_path = self.scratch / f'library-program{level}.smo'
                index = {entry['name']: entry for entry in
                         smircc.compile_files([paths['program.c']], object_path, [level], libraries=[library])}
                # What the program does not reach was left in the library.
                self.assertIn('scale', index)
                self.assertFalse({'unused', 'broken', 'missing'} & set(index))
                executed = run([self.runner, object_path, '--entry-function', index['entry']['function'],
                                '--argument-bits', little_endian(5, 32)], timeout=120)
                report = json.loads(executed.stdout)
                # (5 + 7) * 3 = 36 through both names, and the library's
                # constructor ran before the entry: 41.
                self.assertEqual(report.get('values'), [{'bits_le': little_endian(36 + 3600 + 410000, 32)}], report)
        # The same library cannot complete a program that needs the missing function.
        with self.assertRaises(smircc.CompileError) as raised:
            smircc.compile_files([paths['uses_broken.c']], self.scratch / 'library-broken.smo', ['-O2'],
                                 libraries=[library])
        self.assertIn('E-UNSUPPORTED-CALL', str(raised.exception))
        self.assertIn('missing', str(raised.exception))
        # A library is linked as bitcode for this target, and nothing else.
        (self.scratch / 'library-foreign.ll').write_text('target triple = "x86_64-unknown-linux-gnu"\n')
        with self.assertRaises(smircc.CompileError) as raised:
            smircc.compile_files([paths['program.c']], self.scratch / 'library-foreign.smo', ['-O2'],
                                 libraries=[self.scratch / 'library-foreign.ll'])
        self.assertIn('x86_64-unknown-linux-gnu', str(raised.exception))

    def test_translation_units_that_do_not_link_are_refused(self):
        programs = {
            'duplicate function': (['int twice(int x) { return 2 * x; }', 'int twice(int x) { return x + x; }'],
                                   'E-LINK'),
            'duplicate global': (['int shared = 1; int get(void) { return shared; }', 'int shared = 2;'], 'E-LINK'),
            # A reference no unit defines survives linking and is refused by the emitter.
            'unresolved': (['int other(int); int call(int x) { return other(x); }', 'int unrelated(void) { return 1; }'],
                           'E-UNSUPPORTED-CALL'),
        }
        for name, (texts, code) in programs.items():
            with self.subTest(program=name):
                sources = []
                for position, text in enumerate(texts):
                    sources.append(self.scratch / f'unlinked-{name}-{position}.c')
                    sources[-1].write_text(text + '\n')
                output = self.scratch / f'unlinked-{name}.smo'
                with self.assertRaises(smircc.CompileError) as raised:
                    smircc.compile_files(sources, output, ['-O2'])
                self.assertIn(code, str(raised.exception))
                self.assertIn('nothing written', str(raised.exception))
                self.assertFalse(output.exists())

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
                index = entry_points(smircc.compile_file(source, object_path, ['-O2']))
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

    def test_runtime_faults_are_reported_with_their_codes(self):
        """C that goes wrong at run time stops with the registered fault.

        Native execution cannot be the reference here: these programs have
        undefined behaviour or exhaust a limit. Each expectation is the fault
        the execution chapter assigns to what the compiled code does.
        """
        int_min, int_max = 0x80000000, 0x7fffffff
        programs = [
            # An index one past the end is a valid address that cannot be read.
            ('int read(int i) { int a[4]; a[0] = 1; a[1] = 2; a[2] = 3; a[3] = 4; return a[i]; }',
             'read', [4], 'trap', 'memory_bounds', []),
            # Further out, the in-bounds address computation itself is poison.
            ('int read(int i) { int a[4]; a[0] = 1; a[1] = 2; a[2] = 3; a[3] = 4; return a[i]; }',
             'read', [9], 'language_ub', 'ub_pointer', []),
            ('static int *saved; static void keep(void) { int local = 7; saved = &local; }\n'
             'int stale(void) { keep(); return *saved; }',
             'stale', [], 'trap', 'memory_lifetime', []),
            ('static const int fixed = 5; int poke(int v) { int *p = (int *)&fixed; *p = v; return fixed; }',
             'poke', [6], 'trap', 'memory_permission', []),
            ('static int through(const int *p) { return *p; } int null_read(void) { return through(0); }',
             'null_read', [], 'language_ub', 'pointer_provenance', []),
            ('int forged(unsigned long address) { return *(const int *)address; }',
             'forged', [0x10000], 'language_ub', 'pointer_provenance', []),
            ('int divide(int a, int b) { return a / b; }', 'divide', [1, 0], 'language_ub', 'ub_div_zero', []),
            ('int divide(int a, int b) { return a / b; }',
             'divide', [int_min, 0xffffffff], 'language_ub', 'ub_signed_div_overflow', []),
            # Signed overflow and an oversized shift are poison. Emitted
            # signatures carry no noundef, so the poison is returned and
            # reported as such instead of faulting at the return.
            ('int add(int a, int b) { return a + b; }', 'add', [int_max, 1], 'return', 'poison', []),
            ('unsigned shift(unsigned x, unsigned n) { return x << n; }',
             'shift', [1, 40], 'return', 'poison', []),
            # Using that poison to decide a branch is undefined.
            ('int add(int a, int b) { return a + b; }\n'
             'int sign(int a, int b) { if (add(a, b) < 0) return -1; return 1; }',
             'sign', [int_max, 1], 'language_ub', 'ub_control_value', []),
            ('int choose(int x) { if (x == 3) __builtin_unreachable(); return x; }',
             'choose', [3], 'language_ub', 'ub_unreachable', []),
            ('int stop(int x) { if (x < 0) __builtin_trap(); return x; }',
             'stop', [0xffffffff], 'trap', 'llvm_trap', []),
            ('unsigned long down(unsigned long n) { return n ? down(n - 1) + 1 : 0; }',
             'down', [100000], 'resource', 'frames', []),
            ('unsigned long big(unsigned long n) { char buffer[600000]; buffer[n & 1] = 1;\n'
             '  return n ? big(n - 1) + buffer[n & 1] : 0; }',
             'big', [3], 'resource', 'resource_memory', []),
            ('unsigned spin(unsigned x) { for (;;) x++; }', 'spin', [1], 'resource', 'fuel', ['--fuel', 5000]),
            # A null function pointer designates no function.
            ('static int (*hook)(int); int call(int x) { return hook(x); }',
             'call', [1], 'trap', 'code_token_invalid', []),
            # Nor does a function pointer made of bytes that were never one.
            ('static unsigned long bits = 2; int call(int x) { return (*(int (**)(int))&bits)(x); }',
             'call', [1], 'trap', 'code_token_stale', []),
            # A call through a pointer converted to another function type.
            ('static int one(int x) { return x + 1; }\n'
             'int call(int x) { long (*f)(long, long) = (long (*)(long, long))one; return (int)f(x, x); }',
             'call', [1], 'trap', 'code_token_signature', []),
            # The same function type reached through a conversion and back is fine.
            ('static int one(int x) { return x + 1; }\n'
             'int call(int x) { void (*f)(void) = (void (*)(void))one; return ((int (*)(int))f)(x) - 2; }',
             'call', [1], 'return', 'zero', []),
        ]
        for position, (text, name, values, status, code, limits) in enumerate(programs):
            with self.subTest(function=name, values=values):
                source = self.scratch / f'fault-{position}.c'
                source.write_text(text + '\n')
                object_path = self.scratch / f'fault-{position}.smo'
                index = {entry['name']: entry for entry in smircc.compile_file(source, object_path, ['-O0'])}
                arguments = []
                for value, bits in zip(values, index[name]['params'], strict=True):
                    arguments += ['--argument-bits', little_endian(value, bits)]
                executed = run([self.runner, object_path, '--entry-function', index[name]['function'],
                                *limits, *arguments], timeout=120)
                self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
                report = json.loads(executed.stdout)
                if status == 'return':
                    expected = {'bits_le': '00000000'} if code == 'zero' else {'state': code}
                    self.assertEqual((report['status'], report.get('values')), ('return', [expected]), report)
                    continue
                self.assertEqual((report['status'], report.get('code')), (status, code), report)
                if status != 'resource':
                    # A located fault names a function of this object.
                    self.assertIn(report['function'], [entry['function'] for entry in index.values()])

    def test_long_double_is_carried_but_its_arithmetic_is_refused_by_the_engine(self):
        """binary128 has no native counterpart on every host, so its tests state their results."""
        source = self.scratch / 'long-double.c'
        source.write_text(
            '#include <stdarg.h>\n'
            'static unsigned long long fold(long double value) {\n'
            '  unsigned long long parts[2]; __builtin_memcpy(parts, &value, 16); return parts[0] ^ parts[1]; }\n'
            'static unsigned long long pick(int which, ...) {\n'
            '  va_list list; va_start(list, which); long double value = 0;\n'
            '  for (int i = 0; i <= which; i++) { (void)va_arg(list, int); value = va_arg(list, long double); }\n'
            '  va_end(list); return fold(value); }\n'
            'static long double stored[2] = {2.0L, -0.5L};\n'
            # 1.0L is 0x3fff followed by zeros; negation flips the sign bit.
            'unsigned long long passed(int which) { return pick(which, 7, 1.0L, 8, -stored[which & 1]); }\n'
            'long double doubled(long double value) { return value + value; }\n')
        object_path = self.scratch / 'long-double.smo'
        index = {entry['name']: entry for entry in smircc.compile_file(source, object_path, ['-O1'])}
        self.assertEqual(index['doubled']['params'], ['f128'])
        # The object holds an addition of long doubles, which the engine does not perform.
        executed = run([self.runner, object_path, '--entry-function', index['passed']['function'],
                        '--argument-bits', little_endian(0, 32)])
        report = json.loads(executed.stdout)
        self.assertEqual((executed.returncode, report['class'], report['code']), (1, 'unimplemented', 'EXEC_UNIMPLEMENTED'))
        self.assertIn('binary128', report['detail'])
        # Without it, long doubles are stored, negated and passed through a
        # variadic call.
        source.write_text(source.read_text().replace('long double doubled(long double value) { return value + value; }\n', ''))
        index = {entry['name']: entry for entry in smircc.compile_file(source, object_path, ['-O1'])}
        for which, expected in ((0, 0x3fff000000000000), (1, 0x3ffe000000000000)):
            executed = run([self.runner, object_path, '--entry-function', index['passed']['function'],
                            '--argument-bits', little_endian(which, 32)])
            report = json.loads(executed.stdout)
            self.assertEqual(report.get('values'), [{'bits_le': little_endian(expected, 64)}], report)

    def test_unsupported_constructs_are_refused_with_nothing_written(self):
        programs = {
            'external global': ('extern int counter; int next(void) { return ++counter; }',
                                'E-UNSUPPORTED-GLOBAL'),
            'thread local': ('_Thread_local int slot; int get(void) { return slot; }', 'E-UNSUPPORTED-GLOBAL'),
            'external function table': ('int other(int); int (*const table[1])(int) = {other};',
                                        'E-UNSUPPORTED-INITIALIZER'),
            'external function address': ('int other(int); int (*get(void))(int) { return other; }',
                                          'E-UNSUPPORTED-OPERAND'),
            'aggregate variadic': ('struct s { long a[4]; }; long f(int n, ...);\n'
                                   'long f(int n, ...) { return n; }\n'
                                   'long g(struct s v) { return f(1, v); }', 'E-UNSUPPORTED-CALL'),
            'wide variadic': ('#include <stdarg.h>\n'
                              'typedef _BitInt(200) wide;\n'
                              'int f(int n, ...) { va_list a; va_start(a, n); wide v = va_arg(a, wide);\n'
                              '  va_end(a); return (int)v; }', 'E-UNSUPPORTED'),
            'volatile': ('int read(volatile int *p) { return *p; }', 'E-UNSUPPORTED-INSTRUCTION'),
            'variable array': ('int last(int n) { int a[n]; a[n - 1] = n; return a[n - 1]; }',
                               'E-UNSUPPORTED-INSTRUCTION'),
            'function pointer bits': ('unsigned long bits(int (*f)(int)) { return (unsigned long)f; }',
                                      'E-UNSUPPORTED-INSTRUCTION'),
            'function pointer order': ('int before(int (*f)(int), int (*g)(int)) { return f < g; }',
                                       'E-UNSUPPORTED-INSTRUCTION'),
            'function as data': ('const void *data(int (*f)(int)) { return (const void *)f; }',
                                 'E-UNSUPPORTED-INSTRUCTION'),
            'rounding function': ('double down(double x) { return __builtin_floor(x); }',
                                  'E-UNSUPPORTED-INTRINSIC'),
            'external': ('int other(int); int call(int x) { return other(x) + 1; }', 'E-UNSUPPORTED-CALL'),
            'wide': ('_BitInt(200) widen(long x) { return x; }', 'E-UNSUPPORTED-TYPE'),
            'unknown service': ('int f(void) __asm__("smir.portable.v1:no.such"); int g(void) { return f(); }',
                                'E-SERVICE-BINDING'),
            # file.write also returns a count, which needs a fourth parameter.
            'service shape': ('unsigned f(unsigned long, const void *, unsigned long)\n'
                              '  __asm__("smir.portable.v1:file.write");\n'
                              'unsigned g(const void *p) { return f(1, p, 1); }', 'E-SERVICE-BINDING'),
            # thread.spawn takes a function pointer.
            'service types': ('unsigned f(void) __asm__("smir.portable.v1:thread.spawn");\n'
                              'unsigned g(void) { return f(); }', 'E-SERVICE-BINDING'),
            'service address': ('#include <smir/services.h>\n'
                                'void (*get(void))(void) { return smir_process_abort; }', 'E-UNSUPPORTED-OPERAND'),
        }
        # These only survive to the emitter unoptimized.
        levels = {'variable array': '-O0', 'aggregate variadic': '-O0'}
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
