#!/usr/bin/env python3
"""Executables that carry their runtime: `smirpack.py` against `smir-run`.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_pack.py'

A program is compiled to an object and the object linked, with the launcher
and the runtime's static library, into a program of this machine. Started
like any other program, it must do what the runner does with the object:
write the same, end with the same status, and leave the same files.
"""
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / 'tools/smir-format'))

import runner  # noqa: E402
import smircc  # noqa: E402
import smirpack  # noqa: E402

PROGRAM = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  printf("%d arguments, the last is %s\n", argc - 1, argv[argc - 1]);
  if (argc > 1 && strcmp(argv[1], "abort") == 0)
    abort();
  if (argc > 1 && strcmp(argv[1], "fault") == 0) {
    volatile int *nowhere = 0;
    return *nowhere;
  }
  // What it is given on standard input goes into a file, and what the file
  // then holds comes back.
  char line[64];
  FILE *notes = fopen("notes.txt", "a");
  while (fgets(line, sizeof line, stdin))
    fputs(line, notes);
  fclose(notes);
  notes = fopen("notes.txt", "r");
  int lines = 0;
  while (fgets(line, sizeof line, notes))
    lines++;
  fclose(notes);
  fprintf(stderr, "%d lines\n", lines);
  return 40 + argc;
}
"""


@unittest.skipUnless(platform.system() == 'Darwin', 'executables are made for Mach-O only so far')
class Packed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-pack-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.scratch = Path(cls.directory.name)
        cls.runner = runner.build()
        source = cls.scratch / 'program.c'
        source.write_text(PROGRAM)
        cls.object = cls.scratch / 'program.smo'
        smircc.compile_files([source], cls.object, ['-O2', '-std=c11', '-w'], hosted=True)
        cls.executable = cls.scratch / 'program'
        cls.found = json.loads(smirpack.pack(cls.object, cls.executable))

    def both(self, arguments, stdin=b''):
        """Run the object with the runner and the executable by itself, each in a directory of its own."""
        outcomes = []
        for command in ([str(self.runner), str(self.object), '--program', '--native', '--directory', '.', '--'],
                        [str(self.executable)]):
            with tempfile.TemporaryDirectory(prefix='run-', dir=self.scratch) as root:
                executed = subprocess.run([*command, *arguments], input=stdin, capture_output=True, timeout=120,
                                          cwd=root)
                files = {path.name: path.read_bytes() for path in Path(root).iterdir()}
                outcomes.append((executed.returncode, executed.stdout, executed.stderr, files))
        return outcomes

    def test_the_executable_carries_the_object(self):
        payload = self.object.read_bytes()
        self.assertEqual((self.found['carrier'], self.found['length']), ('macho', len(payload)))
        whole = self.executable.read_bytes()
        self.assertEqual(whole[self.found['offset']:][:len(payload)], payload)
        # The system takes it for a program of its own, signed.
        checked = subprocess.run(['codesign', '--verify', str(self.executable)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        # And the runner runs what it carries, like any carrier.
        with tempfile.TemporaryDirectory(prefix='carried-', dir=self.scratch) as root:
            carried = subprocess.run([str(self.runner), str(self.executable), '--program', '--directory', root,
                                      '--', 'x'], input=b'', capture_output=True, timeout=120)
        self.assertEqual((carried.returncode, carried.stdout), (42, b'1 arguments, the last is x\n'))

    def test_it_runs_as_the_runner_runs_the_object(self):
        for arguments, stdin in (([], b''), (['one', 'two'], b'first\nsecond\n'), (['spaced out', ''], b'only\n')):
            with self.subTest(arguments=arguments):
                run, packed = self.both(arguments, stdin)
                # The program's name is the file it was started as.
                name = lambda text, own: text.replace(str(own).encode(), b'PROGRAM')  # noqa: E731
                self.assertEqual((packed[0], name(packed[1], self.executable), packed[2], packed[3]),
                                 (run[0], name(run[1], self.object), run[2], run[3]))
                self.assertEqual(packed[0], 41 + len(arguments))
        self.assertEqual(self.both(['a'], b'kept\n')[1][3], {'notes.txt': b'kept\n'})

    def test_an_abort_and_a_fault_end_it_as_they_end_a_program(self):
        aborted = subprocess.run([str(self.executable), 'abort'], capture_output=True, timeout=120)
        # Ended by the signal an abort raises, with what it had written.
        self.assertEqual((aborted.returncode, aborted.stdout), (-6, b'1 arguments, the last is abort\n'))
        faulted = subprocess.run([str(self.executable), 'fault'], capture_output=True, timeout=120)
        self.assertEqual((faulted.returncode, faulted.stdout), (125, b'1 arguments, the last is fault\n'))
        report = json.loads(faulted.stderr)
        self.assertEqual((report['reason'], report['trap']['code']), ('trap', 'pointer_provenance'))

    def test_a_changed_executable_does_not_run_its_program(self):
        changed = self.scratch / 'changed'
        whole = bytearray(self.executable.read_bytes())
        whole[self.found['offset'] + 100] ^= 1
        changed.write_bytes(whole)
        changed.chmod(0o755)
        # Signed again, so that the system starts it; the runtime then
        # finds that the object is not the one the locator names.
        subprocess.run(['codesign', '--force', '--sign', '-', str(changed)], check=True, capture_output=True)
        refused = subprocess.run([str(changed)], capture_output=True, timeout=120)
        self.assertEqual((refused.returncode, refused.stdout), (125, b''))
        self.assertEqual(json.loads(refused.stderr)['code'], 'LAUNCH_MODULE')

    def test_only_an_object_is_packed(self):
        text = self.scratch / 'text'
        text.write_text('not an object')
        with self.assertRaises(smirpack.PackError):
            smirpack.pack(text, self.scratch / 'never')
        self.assertFalse((self.scratch / 'never').exists())


if __name__ == '__main__':
    unittest.main()
