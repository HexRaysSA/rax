#!/usr/bin/env python3
"""Threaded C programs: against their native builds, and at their edges.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v

Each program in `tests/threads` is compiled against the C library (see
sysroot/build_libc.py), whose `pthread.h` and `threads.h` are implemented over
the runtime's thread and wait services, and run with `smir-run --program`,
where every thread of the program is a host thread. A program's output must
not depend on how its threads interleave. It is compared with the output of
the same source built natively with the host's compiler, or, for a program
with a `.stdout` file beside it, with that file: the host of these tests need
not have the threads of ISO C.

The other tests are programs that go wrong: a data race, a pointer into the
stack of a thread that has ended, a deadlock. The engine must report each as
what it is, and never be corrupted by it.

Requires what test_hosted.py requires.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import smircc  # noqa: E402

PROGRAMS = sorted((HERE / 'tests/threads').glob('*.c'))
CRATE = ROOT / 'crates/smir-portable'
LEVELS = ['-O1', '-O2']
# Each program is run this many times at each level: threads interleave
# differently every time.
REPEATS = 3

RACE = r'''
#include <pthread.h>
#include <stdio.h>
enum { THREADS = 4, ROUNDS = 20000 };
static long counter;
static void *add(void *argument) {
  (void)argument;
  for (int round = 0; round < ROUNDS; ++round)
    counter = counter + 1;  /* no lock: updates may be lost */
  return NULL;
}
int main(void) {
  pthread_t threads[THREADS];
  for (int index = 0; index < THREADS; ++index)
    pthread_create(&threads[index], NULL, add, NULL);
  for (int index = 0; index < THREADS; ++index)
    pthread_join(threads[index], NULL);
  printf("%s\n", counter >= ROUNDS && counter <= (long)THREADS * ROUNDS ? "in range" : "out of range");
  return 0;
}
'''

DANGLING = r'''
#include <pthread.h>
#include <stdio.h>
static int *volatile lent;
static void *lend(void *argument) {
  int local = 42;
  (void)argument;
  lent = &local;  /* gone when the thread ends */
  return NULL;
}
int main(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, lend, NULL);
  pthread_join(thread, NULL);
  printf("joined\n");
  fflush(stdout);
  return *lent;
}
'''

DEADLOCK = r'''
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
static pthread_mutex_t first = PTHREAD_MUTEX_INITIALIZER, second = PTHREAD_MUTEX_INITIALIZER;
static atomic_int held;
static void *other(void *argument) {
  (void)argument;
  pthread_mutex_lock(&second);
  atomic_store(&held, 1);
  pthread_mutex_lock(&first);  /* main holds it and wants `second` */
  return NULL;
}
int main(void) {
  pthread_t thread;
  pthread_mutex_lock(&first);
  pthread_create(&thread, NULL, other, NULL);
  while (!atomic_load(&held))
    ;
  printf("both held\n");
  fflush(stdout);
  pthread_mutex_lock(&second);
  return 0;
}
'''

LEFT_RUNNING = r'''
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
static atomic_int started;
static void said(void) { printf("handlers ran\n"); }
static void *spin(void *argument) {
  atomic_store(&started, 1);
  for (;;)
    if (argument)
      exit(7);  /* any thread may end the program */
  return NULL;
}
int main(int argc, char **argv) {
  pthread_t thread;
  atexit(said);
  pthread_create(&thread, NULL, spin, argc > 1 ? argv : NULL);
  while (!atomic_load(&started))
    ;
  if (argc > 1)
    pthread_join(thread, NULL);
  printf("main returns\n");
  return 5;
}
'''


class Threads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-threads-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.scratch = Path(cls.directory.name)
        build.build()
        cls.host = os.environ.get('CC', '/usr/bin/clang')
        cargo = subprocess.run(['cargo', 'build', '--offline', '--locked', '--manifest-path',
                                str(CRATE / 'Cargo.toml'), '--bin', 'smir-run'], capture_output=True, text=True)
        if cargo.returncode != 0:
            raise RuntimeError('cannot build smir-run:\n' + cargo.stderr[-4000:])
        cls.runner = CRATE / 'target/debug/smir-run'

    def program(self, object_path, arguments=()):
        """Run a program, interpreted and as native code, which must do the
        same; returns the interpreted run. A report of a run that did not
        complete counts the steps of all threads, which vary, so only what
        ended the run is compared there."""
        def launch(*engine):
            return subprocess.run([str(self.runner), str(object_path), '--program', *engine, '--', *arguments],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=300)

        def ending(executed):
            report = json.loads(executed.stderr) if executed.stderr.startswith(b'{') else executed.stderr
            if isinstance(report, dict):
                report.pop('steps', None)
            return executed.returncode, executed.stdout, report
        interpreted, compiled = launch(), launch('--native')
        self.assertEqual(ending(compiled), ending(interpreted),
                         f'native code differs from the interpreter on {object_path.name}')
        return interpreted

    def compiled(self, name, source, level='-O2'):
        """The object of a program given as text."""
        path = self.scratch / f'{name}.c'
        path.write_text(source)
        object_path = self.scratch / f'{name}.smo'
        smircc.compile_files([path], object_path, [level, '-std=c11'], hosted=True)
        return object_path

    def test_threaded_programs_match_their_native_builds(self):
        self.assertGreaterEqual(len(PROGRAMS), 6)
        total = 0
        for source in PROGRAMS:
            recorded = source.with_suffix('.stdout')
            if recorded.exists():
                expected, status = recorded.read_bytes(), 0
            else:
                native = self.scratch / f'{source.stem}-native'
                compiled = subprocess.run([self.host, '-std=c11', '-O1', '-pthread', '-w', '-o', str(native),
                                           str(source)], capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr[-4000:])
                reference = subprocess.run([str(native)], capture_output=True, timeout=120)
                expected, status = reference.stdout, reference.returncode
            self.assertEqual(status, 0, f'{source.name} fails natively: {expected[-500:]}')
            for level in LEVELS:
                object_path = self.scratch / f'{source.stem}{level}.smo'
                smircc.compile_files([source], object_path, [level, '-std=c11'], hosted=True)
                for attempt in range(REPEATS):
                    with self.subTest(program=source.stem, level=level, attempt=attempt):
                        executed = self.program(object_path)
                        self.assertEqual(executed.stderr, b'')
                        self.assertEqual(executed.stdout, expected)
                        self.assertEqual(executed.returncode, status)
                        total += 1
        print(f'{total} runs of {len(PROGRAMS)} threaded programs match', file=sys.stderr)

    def test_threads_that_share_work_finish_sooner(self):
        # Sixteen parts of one sum, by one thread at a time and by four. The
        # threads only read the array they share, so they do not wait for
        # one another. The best of two runs each, to be robust against a
        # busy machine; on an idle one the four take about a third as long.
        if (os.cpu_count() or 1) < 4:
            self.skipTest('needs four processors')
        object_path = self.scratch / 'together-timed.smo'
        smircc.compile_files([HERE / 'tests/threads/together.c'], object_path, ['-O2', '-std=c11'], hosted=True)

        def best(threads):
            times = []
            for _ in range(2):
                started = time.monotonic()
                executed = self.program(object_path, [str(threads), '60000'])
                times.append(time.monotonic() - started)
                self.assertEqual(executed.returncode, 0, executed.stderr)
            return min(times), executed.stdout

        (alone, first), (together, second) = best(1), best(4)
        self.assertEqual(first, second)
        print(f'four threads take {together / alone:.2f} of the time of one', file=sys.stderr)
        self.assertLess(together, 0.75 * alone)

    def test_a_data_race_loses_updates_and_nothing_else(self):
        # The engine performs every access as one step, so a race can lose
        # an update of the program's but cannot tear a value or harm the run.
        object_path = self.compiled('race', RACE)
        for _ in range(5):
            executed = self.program(object_path)
            self.assertEqual((executed.returncode, executed.stdout, executed.stderr), (0, b'in range\n', b''))

    def test_the_stack_of_a_thread_ends_with_the_thread(self):
        executed = self.program(self.compiled('dangling', DANGLING, '-O0'))
        self.assertEqual(executed.stdout, b'joined\n')
        self.assertEqual(executed.returncode, 125)
        report = json.loads(executed.stderr)
        self.assertEqual((report['status'], report['code']), ('trap', 'memory_lifetime'))

    def test_a_deadlock_is_reported_and_does_not_hang(self):
        started = time.monotonic()
        executed = self.program(self.compiled('deadlock', DEADLOCK))
        self.assertEqual(executed.stdout, b'both held\n')
        self.assertEqual(executed.returncode, 125)
        self.assertEqual(json.loads(executed.stderr)['status'], 'deadlock')
        self.assertLess(time.monotonic() - started, 60)

    def test_the_program_ends_with_its_first_thread_or_when_any_thread_exits(self):
        object_path = self.compiled('left', LEFT_RUNNING)
        # main returns while the other thread still runs: that thread is
        # stopped, and the handlers registered with atexit run.
        executed = self.program(object_path)
        self.assertEqual((executed.returncode, executed.stdout, executed.stderr),
                         (5, b'main returns\nhandlers ran\n', b''))
        # The other thread calls exit while main waits for it.
        executed = self.program(object_path, ['exit'])
        self.assertEqual((executed.returncode, executed.stdout, executed.stderr), (7, b'handlers ran\n', b''))


if __name__ == '__main__':
    unittest.main()
