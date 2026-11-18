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
# Programs that use files: each runs in a directory of its own, with the
# input beside it if there is one, and once more with an argument.
FILE_PROGRAMS = sorted(path for path in (HERE / 'tests/files').iterdir() if path.suffix in STANDARD)

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
    **dict.fromkeys(['cf_longjmp_threaded_vm', 'cf_setjmp'], 'needs setjmp and longjmp'),
    'mem_sequential': 'converts a float out of range to an integer, which is undefined; the engine reports it',
    '05_thread_pool': 'divides by the number of processors, which the runtime does not tell: the library '
                      'says zero, as the standard allows',
    'cpp_allocator_polymorph_zoo': 'its result depends on the order in which a vector destroys its elements, '
                                   'which the standard leaves open and libc++ has changed since the recording',
    'cpp_rtti': 'adds the hash of a type, which is an address: the recordings differ between architectures too',
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
        # Apart from what differs between any two runs, such as times.
        if (compiled.returncode, denoise(compiled.stdout, filters)) != (executed.returncode,
                                                                         denoise(executed.stdout, filters)):
            return 'native code differs from the interpreter'
        return None

    def test_programs_that_use_the_cxx_library_match_their_native_builds(self):
        """Containers, strings, algorithms, the library's threads, and objects
        with static storage, against the host's compiler and library."""
        self.assertGreaterEqual(len(LIBRARY_PROGRAMS), 8)
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
                                         (reference.returncode, reference.stdout, reference.stderr),
                                         f'{level} {engine}')

    def test_programs_with_files_match_their_native_builds(self):
        """What a program writes, how it ends and the files it leaves, against
        the host's compilers and libraries."""
        self.assertGreaterEqual(len(FILE_PROGRAMS), 3)
        hosts = {'.c': [os.environ.get('CC', 'cc'), '-std=c11'],
                 '.cpp': [os.environ.get('CXX', 'c++'), '-std=c++2b']}

        def files_under(root):
            return {str(path.relative_to(root)): path.read_bytes() for path in sorted(Path(root).rglob('*'))
                    if path.is_file()}

        def launch(command, given, arguments, stdin, native):
            with tempfile.TemporaryDirectory(prefix='smir-files-', dir=self.scratch) as root:
                placed = [*command, *(given(root)), *arguments]
                executed = subprocess.run(placed, input=stdin, capture_output=True, timeout=120,
                                          cwd=root if native else None)
                return executed.returncode, executed.stdout, executed.stderr, files_under(root)

        for source in FILE_PROGRAMS:
            native = self.scratch / f'{source.stem}-native'
            compiled = subprocess.run([*hosts[source.suffix], '-O1', '-w', '-o', str(native), str(source)],
                                      capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr[-3000:])
            given = source.with_suffix('.in')
            stdin = given.read_bytes() if given.exists() else b''
            for level in ('-O0', '-O2'):
                object_path = self.scratch / f'{source.stem}-files{level}.smo'
                smircc.compile_files([source], object_path, [level, STANDARD[source.suffix], '-w'], hosted=True)
                for arguments in ([], ['again']):
                    reference = launch([str(native)], lambda root: [], arguments, stdin, True)
                    for engine in ([], ['--native']):
                        with self.subTest(program=source.stem, level=level, arguments=arguments, engine=engine):
                            executed = launch([str(self.runner), str(object_path), '--program', *engine],
                                              lambda root: ['--directory', root, '--'], arguments, stdin, False)
                            self.assertEqual(executed, reference)

    def test_an_exception_nothing_catches_ends_the_program(self):
        programs = {
            'uncaught': '#include <cstdio>\n#include <stdexcept>\n'
                        'int main() { std::puts("before"); throw std::runtime_error("nobody listens"); }\n',
            # Out of a thread's function, which returns to the C library.
            'uncaught-thread': '#include <cstdio>\n#include <stdexcept>\n#include <thread>\n'
                               'int main() {\n  std::puts("before");\n'
                               '  std::thread thread([] { throw std::runtime_error("nobody listens"); });\n'
                               '  thread.join();\n  std::puts("after");\n}\n',
        }
        for name, text in programs.items():
            with self.subTest(program=name):
                source = self.scratch / f'{name}.cpp'
                source.write_text(text)
                object_path = self.scratch / f'{name}.smo'
                smircc.compile_files([source], object_path, ['-O2', '-std=c++23', '-w'], hosted=True)
                for engine in ([], ['--native']):
                    executed = subprocess.run([str(self.runner), str(object_path), '--program', *engine],
                                              stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
                    # What was written before is not lost; the program is aborted.
                    self.assertEqual((executed.returncode, executed.stdout), (134, b'before\n'))
                    self.assertIn(b'uncaught exception', executed.stderr)

    def test_the_time_functions_read_the_runtime_clocks(self):
        source = self.scratch / 'clocks.c'
        source.write_text(r"""
#include <errno.h>
#include <stdio.h>
#include <time.h>

int main(void) {
  struct timespec utc, real, first, second, cpu;
  timespec_get(&utc, TIME_UTC);
  time_t now = time(NULL), again;
  time(&again);
  printf("%d\n", clock_gettime(CLOCK_REALTIME, &real));
  // Three readings of one clock, a few seconds apart at most, in this century.
  printf("%d %d %d %d\n", now > 1600000000, now >= utc.tv_sec && now - utc.tv_sec < 5,
         again >= now && again - now < 5, real.tv_sec >= now && real.tv_sec - now < 5);
  clock_gettime(CLOCK_MONOTONIC, &first);
  for (volatile int spin = 0; spin < 1000; spin = spin + 1) {
  }
  clock_gettime(CLOCK_MONOTONIC, &second);
  printf("%d\n", second.tv_sec > first.tv_sec || (second.tv_sec == first.tv_sec && second.tv_nsec >= first.tv_nsec));
  printf("%d %d\n", clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu), clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu));
  errno = 0;
  printf("%d %d\n", clock_gettime(77, &cpu), errno == EINVAL);
  // Local time is UTC: 1971-01-01 05:01:01.
  time_t fixed = 86400 * 365 + 3600 * 5 + 61;
  struct tm local = *localtime(&fixed), split;
  localtime_r(&fixed, &split);
  printf("%d-%02d-%02d %02d:%02d:%02d %d %d\n", local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
         local.tm_hour, local.tm_min, local.tm_sec, split.tm_yday, mktime(&split) == fixed);
  return 0;
}
""")
        object_path = self.scratch / 'clocks.smo'
        smircc.compile_files([source], object_path, ['-O2', '-std=c11'], hosted=True)
        for engine in ([], ['--native']):
            executed = subprocess.run([str(self.runner), str(object_path), '--program', *engine],
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
            self.assertEqual((executed.returncode, executed.stdout.decode()),
                             (0, '0\n1 1 1 1\n1\n0 0\n-1 1\n1971-01-01 05:01:01 0 1\n'), executed.stderr)

    def test_a_program_without_streams_does_not_carry_them(self):
        """The stream classes construct the standard streams before `main`;
        a program that names no stream is linked without any of it."""
        texts = {'plain': '#include <cstdio>\n#include <vector>\n'
                          'int main() { std::vector<int> v{1, 2, 3}; std::printf("%zu\\n", v.size()); }\n',
                 'streams': '#include <iostream>\nint main() { std::cout << 3 << std::endl; }\n'}
        sizes = {}
        for name, text in texts.items():
            source = self.scratch / f'carry-{name}.cpp'
            source.write_text(text)
            object_path = self.scratch / f'carry-{name}.smo'
            index = smircc.compile_files([source], object_path, ['-O2', '-std=c++23', '-w'], hosted=True)
            sizes[name] = object_path.stat().st_size
            initializes = any('DoIOSInit' in entry['name'] for entry in index)
            self.assertEqual(initializes, name == 'streams')
            executed = subprocess.run([str(self.runner), str(object_path), '--program'],
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
            self.assertEqual((executed.returncode, executed.stdout), (0, b'3\n'))
        self.assertLess(sizes['plain'] * 2, sizes['streams'])

    def test_a_library_linked_twice_constructs_its_objects_once(self):
        """When only a library handles exceptions, the libraries are linked a
        second time for the runtime under them; that brings no constructor
        again."""
        library_source = self.scratch / 'once-library.cpp'
        library_source.write_text('namespace { volatile int one = 1; int runs;\n'
                                  'struct Counted { Counted() { runs += one; } } counted; }\n'
                                  'int constructions() noexcept {\n'
                                  '  try { throw 5; } catch (int caught) { return runs * 10 + caught; } }\n')
        library = self.scratch / 'once-library.bc'
        smircc.compile_library([library_source], library,
                               ['-O2', '-std=c++23', '-fexceptions', '-fcxx-exceptions'])
        # The program itself neither throws nor catches.
        source = self.scratch / 'once.cpp'
        source.write_text('#include <cstdio>\nint constructions() noexcept;\n'
                          'int main() { std::printf("%d\\n", constructions()); }\n')
        object_path = self.scratch / 'once.smo'
        smircc.compile_files([source], object_path, ['-O2', '-std=c++23', '-w'], libraries=[library], hosted=True)
        executed = subprocess.run([str(self.runner), str(object_path), '--program'],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        self.assertEqual((executed.returncode, executed.stdout), (0, b'15\n'), executed.stderr)

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
        self.assertGreaterEqual(len(matching), 84)


if __name__ == '__main__':
    unittest.main()
