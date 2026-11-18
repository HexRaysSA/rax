#!/usr/bin/env python3
"""Hosted C and C++ programs: the morok corpus against its recorded Linux results.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v

`tests/fixtures/user/linux/programs` holds C and C++ programs with the
standard output and exit status each produced on Linux. Every program of that
corpus is compiled here against the C library (LLVM libc; see
sysroot/build_libc.py) and, for C++, libc++'s headers, run with
`smir-run --program`, and compared with its recording, after the corpus's own
noise filters.

A program is compared with the x86-64 recording unless RECORDING names
another: this target has no SIMD and does not contract floating-point
operations, so where the recordings differ between architectures it follows
the one whose build took the same path. A program in EXCLUDED is not expected
to match, for the reason given; the test fails if one of them starts to, so
the list cannot go stale.

Requires what test_e2e.py requires, and a Python with PyYAML for the C
library's header generator.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import runner  # noqa: E402
import smircc  # noqa: E402

CORPUS = ROOT / 'tests/fixtures/user/linux/programs'
# C++ programs of this directory's own, compared with native builds.
LIBRARY_PROGRAMS = sorted((HERE / 'tests/cxxlib').glob('*.cpp'))
CRATE = ROOT / 'crates/smir-portable'
# The corpus's own flags (its build.sh), without those that name a host.
FLAGS = ['-O2', '-D_GNU_SOURCE', '-w']
STANDARD = {'.c': '-std=c11', '.cpp': '-std=c++23'}

# Programs whose recording is not the x86-64 one, and why.
RECORDING = {
    'asm_context_switch': 'riscv64',  # no register-saving assembly: the portable fallback
    'simd_dot_product': 'riscv64',    # the scalar kernel, which sums in a different order
    'simd_image_filter': 'riscv64',   # the scalar kernel
}

# Programs that rely on signed integer overflow wrapping. That is undefined,
# and the engine reports the first branch on the result; with -fwrapv the
# program says what it means.
WRAPPING = {'min_add_chain', 'min_mul_chain'}

# Programs that print pointers with %p. How a pointer is written is up to the
# C library (LLVM libc writes a null pointer as "(nullptr)", musl as "0"), and
# the addresses themselves are this engine's, so those are masked.
POINTERS = {'03_linked_list', '06_allocator'}

# Programs that are not expected to match, by cause.
EXCLUDED = {
    **dict.fromkeys(['asm_syscall_raw', 'cf_rorog', 'syscall_file_ops', 'syscall_fork_exec', 'syscall_mmap',
                     'syscall_signals', 'syscall_socket'],
                    'needs operating system services beyond the standard streams'),
    '02_fibonacci': 'needs the POSIX clock_gettime',
    'int_woma_keygen': 'needs time and localtime, which the freestanding C library lacks',
    **dict.fromkeys(['cf_longjmp_threaded_vm', 'cf_setjmp'], 'needs setjmp and longjmp'),
    'mem_sequential': 'converts a float out of range to an integer, which is undefined; the engine reports it',
    **dict.fromkeys(['04_bst', '08_json_parser', '10_template_madness', 'cpp_constexpr_variant_graph',
                     'cpp_coroutine_lifetime', 'cpp_type_erased_callmaze'],
                    'needs the stream classes of the C++ library, which need its localization'),
    **dict.fromkeys(['cf_exception', 'cpp_allocator_polymorph_zoo', 'cpp_exception_variant_unwind'],
                    'needs C++ exceptions'),
    'cpp_rtti': 'needs run-time type information',
    '05_thread_pool': 'needs C++ exceptions and the stream classes',
}


def source_of(name):
    """The source file of a program of the corpus, which is C or C++; None if there is none."""
    return next((path for path in (CORPUS / 'src' / f'{name}{suffix}' for suffix in STANDARD) if path.exists()),
                None)


def table(name):
    """The rows of one of the corpus's tables: whitespace-separated, # comments."""
    rows = []
    for line in (CORPUS / name).read_text().splitlines():
        line = line.split('#')[0].strip()
        if line:
            rows.append(line.split())
    return rows


def noise(arch):
    """The corpus's noise filters for one architecture, by program."""
    filters = {}
    for row_arch, program, name, *_ in table('noise.txt'):
        if row_arch in ('*', arch):
            filters.setdefault(program, []).append(name)
    return filters


def denoise(output, filters):
    """Standard output with the corpus's filters applied, as its own test applies them."""
    if 'ignore-stdout' in filters:
        return ''
    lines = []
    for line in output.decode('utf-8', 'replace').splitlines(keepends=True):
        for name in filters:
            kind, _, word = name.partition(':')
            if kind == 'addresses':
                line = re.sub(r'0x[0-9a-fA-F]{6,}', '0x?', line)
            elif kind == 'number-before':
                line = re.sub(r'\d[\d.]*(?= ' + re.escape(word) + ')', '?', line)
            elif kind == 'line' and word in line:
                line = '<masked>\n' if line.endswith('\n') else '<masked>'
            elif kind == 'drop' and word in line:
                line = ''
        lines.append(line)
    return ''.join(lines)


def without_pointers(text):
    """Text with every pointer masked and the padding around it collapsed.

    A null pointer is "(nullptr)" from LLVM libc and a bare "0" from musl. The
    bare zero is recognized where these programs print one: as the last
    column of a table row whose second column is a pointer, and before the
    words "(should be NULL)".
    """
    text = re.sub(r'0x[0-9a-fA-F?]+|\(nullptr\)', '<pointer>', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'(?m)^(\d+ <pointer> \d+ )0 $', r'\1<pointer> ', text)
    return re.sub(r'(?<=: )0(?= \(should be NULL\))', '<pointer>', text)


class Hosted(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-hosted-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.scratch = Path(cls.directory.name)
        build.build()
        cls.runner = runner.build()
        # Build the C library once, before the programs are compiled in parallel.
        sys.path.insert(0, str(HERE / 'sysroot'))
        import build_libc
        sys.path.pop(0)
        build_libc.build()

    def attempt(self, name, arguments):
        """Compile and run one program; returns None if it matches, else what differs."""
        arch = RECORDING.get(name, 'x86_64')
        object_path = self.scratch / f'{name}.smo'
        source = source_of(name)
        flags = FLAGS + [STANDARD[source.suffix]] + (['-fwrapv'] if name in WRAPPING else [])
        try:
            smircc.compile_files([source], object_path, flags, hosted=True)
        except smircc.CompileError as error:
            lines = [line for line in str(error).splitlines() if 'error' in line]
            return 'does not compile: ' + (lines[0] if lines else str(error))[:300]
        try:
            executed = subprocess.run([str(self.runner), str(object_path), '--program', '--', *arguments],
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            return 'does not finish'
        expected_status = int((CORPUS / 'expected' / arch / f'{name}.status').read_text())
        if executed.returncode != expected_status:
            return (f'exits with {executed.returncode}, not {expected_status}: '
                    f'{executed.stderr[-300:].decode("utf-8", "replace")}')
        filters = noise(arch).get(name, [])
        actual = denoise(executed.stdout, filters)
        expected = denoise((CORPUS / 'expected' / arch / f'{name}.stdout').read_bytes(), filters)
        if name in POINTERS:
            actual, expected = without_pointers(actual), without_pointers(expected)
        if actual != expected:
            ours, theirs = actual.splitlines(), expected.splitlines()
            first = next((index for index, pair in enumerate(zip(ours, theirs)) if pair[0] != pair[1]),
                         min(len(ours), len(theirs)))
            return (f'output differs at line {first + 1}: '
                    f'{ours[first:first + 1]} instead of {theirs[first:first + 1]}')
        # As native code the program must write and return the same.
        compiled = subprocess.run([str(self.runner), str(object_path), '--program', '--native', '--', *arguments],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
        if (compiled.returncode, compiled.stdout) != (executed.returncode, executed.stdout):
            return 'native code differs from the interpreter'
        return None

    def test_programs_that_use_the_cxx_library_match_their_native_builds(self):
        """Containers, strings, algorithms, the library's threads, and objects
        with static storage, against the host's compiler and library."""
        self.assertGreaterEqual(len(LIBRARY_PROGRAMS), 3)
        host = os.environ.get('CXX', 'c++')
        for source in LIBRARY_PROGRAMS:
            with self.subTest(program=source.stem):
                native = self.scratch / f'{source.stem}-native'
                compiled = subprocess.run([host, '-std=c++2b', '-O1', '-pthread', '-w', '-o', str(native),
                                           str(source)], capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr[-3000:])
                reference = subprocess.run([str(native)], capture_output=True, timeout=120)
                for level in ('-O1', '-O2'):
                    object_path = self.scratch / f'{source.stem}{level}.smo'
                    smircc.compile_files([source], object_path, [level, '-std=c++23', '-w'], hosted=True)
                    for engine in ([], ['--native']):
                        executed = subprocess.run([str(self.runner), str(object_path), '--program', *engine],
                                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
                        self.assertEqual((executed.returncode, executed.stdout, executed.stderr),
                                         (reference.returncode, reference.stdout, b''), f'{level} {engine}')

    def test_the_programs_of_the_corpus_match_their_recordings(self):
        cases = [(row[0], row[1:]) for row in table('cases.txt') if source_of(row[0])]
        self.assertGreaterEqual(len(cases), 97)
        self.assertFalse(set(EXCLUDED) - {name for name, _ in cases}, 'EXCLUDED names programs that do not exist')
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
            outcomes = dict(zip((name for name, _ in cases), pool.map(lambda case: self.attempt(*case), cases)))
        wrong = {name: outcome for name, outcome in outcomes.items() if outcome and name not in EXCLUDED}
        stale = [name for name in EXCLUDED if outcomes[name] is None]
        matching = [name for name, outcome in outcomes.items() if outcome is None]
        print(f'{len(matching)} of {len(cases)} programs match their recordings; '
              f'{len(EXCLUDED)} are excluded', file=sys.stderr)
        self.assertFalse(wrong, '\n' + '\n'.join(f'{name}: {outcome}' for name, outcome in sorted(wrong.items())))
        self.assertFalse(stale, f'these excluded programs now match; remove them from EXCLUDED: {stale}')
        self.assertGreaterEqual(len(matching), 74)


if __name__ == '__main__':
    unittest.main()
