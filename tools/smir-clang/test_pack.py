#!/usr/bin/env python3
"""Executables that carry their runtime: `smirpack.py` against `smir-run`.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_pack.py'

A program is compiled to an object and the object linked, with the launcher
and the runtime's static library, into a program of this machine. Started
like any other program, it must do what the runner does with the object:
write the same, end with the same status, and leave the same files.
"""
import json
import os
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

    def test_an_executable_holds_the_modules_its_program_is_linked_with(self):
        """A program compiled apart from two modules it needs, all three in
        one executable, against the runner linking the three objects."""
        sources = HERE / 'tests/modules'
        base, shapes, main = (self.scratch / f'{name}.smo' for name in ('base', 'shapes', 'main'))
        flags = ['-O2', '-std=c11', '-w']
        smircc.compile_files([sources / 'base.c'], base, flags, version=(1, 2))
        smircc.compile_files([sources / 'shapes.c'], shapes, flags, needs=[base])
        smircc.compile_files([sources / 'main.c'], main, flags, hosted=True, needs=[shapes, base])
        executable = self.scratch / 'linked'
        found = json.loads(smirpack.pack(main, executable, [base, shapes]))
        # The file carries the program; the modules are beside it.
        self.assertEqual(found['length'], main.stat().st_size)
        whole = executable.read_bytes()
        for module in (base, shapes):
            self.assertEqual(whole.count(module.read_bytes()), 1)
        for arguments in ([], ['one', 'two']):
            run = subprocess.run([str(self.runner), str(main), '--library', str(shapes), '--library', str(base),
                                  '--program', '--native', '--', *arguments], capture_output=True, timeout=120)
            packed = subprocess.run([str(executable), *arguments], capture_output=True, timeout=120)
            self.assertEqual((packed.returncode, packed.stdout, packed.stderr),
                             (run.returncode, run.stdout, run.stderr))
            self.assertEqual(packed.returncode, 41 + len(arguments))
            self.assertIn(b'counts 1 3\norder 8\n', packed.stdout)
        # A program that needs modules is packed with them or not at all,
        # and with those it needs.
        for libraries, code in (([], 'EXEC_UNLINKED'), ([shapes], 'LINK_DEPENDENCY'),
                                ([shapes, base, self.object], 'LINK_UNUSED')):
            with self.assertRaises(smirpack.PackError) as refused:
                smirpack.pack(main, self.scratch / 'never', libraries)
            self.assertIn(code, str(refused.exception))
            self.assertFalse((self.scratch / 'never').exists())
        # A module of the executable that was changed: the program is not
        # run with it.
        changed = self.scratch / 'linked-changed'
        at = whole.index(base.read_bytes()) + 100
        changed.write_bytes(whole[:at] + bytes([whole[at] ^ 1]) + whole[at + 1:])
        changed.chmod(0o755)
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


# A library that says it is a runtime of some version, and one that says
# nothing.
PRETENDER = r"""
#include "rax_portable_extensions_v1.h"
RaxPortableStatusV1 rax_portable_x1_runtime(RaxPortableRuntimeX1 *runtime) {
  runtime->abi_major = MAJOR;
  runtime->abi_minor = MINOR;
  runtime->revision = 1;
  runtime->profile = PROFILE;
  return 0;
}
"""
SILENT = 'int nothing_of_a_runtime(void) { return 0; }\n'


@unittest.skipUnless(platform.system() == 'Darwin', 'executables are made for Mach-O only so far')
class Installed(unittest.TestCase):
    """Executables that carry their program and find their runtime."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-installed-')
        cls.addClassCleanup(cls.directory.cleanup)
        # The path as the system resolves it, which is what is built in.
        cls.scratch = Path(cls.directory.name).resolve()
        cls.runner = runner.build()
        source = cls.scratch / 'program.c'
        source.write_text(PROGRAM)
        cls.object = cls.scratch / 'program.smo'
        smircc.compile_files([source], cls.object, ['-O2', '-std=c11', '-w'], hosted=True)
        cls.runtime = smirpack.runtime_library()
        # Nothing of these tests reads the system's own record.
        cls.no_record = cls.scratch / 'no-record'

    def packed(self, name, **how):
        """An executable of the program that finds its runtime as `how` says."""
        how.setdefault('record', self.no_record)
        (self.scratch / name).parent.mkdir(parents=True, exist_ok=True)
        smirpack.pack(self.object, self.scratch / name, installed=smirpack.Installed(**how))
        return self.scratch / name

    def started(self, executable, *arguments, **options):
        with tempfile.TemporaryDirectory(prefix='run-', dir=self.scratch) as root:
            return subprocess.run([str(executable), *arguments], input=b'', capture_output=True, timeout=120,
                                  cwd=root, **options)

    def refusal(self, executable, **options):
        """The code an executable refuses to run its program with."""
        executed = self.started(executable, **options)
        self.assertEqual((executed.returncode, executed.stdout), (125, b''), executed.stderr)
        report = json.loads(executed.stderr)
        self.assertEqual((report['status'], report['class']), ('rejected', 'launch'))
        return report['code']

    def pretender(self, name, source, **numbers):
        """A shared library that is no runtime, or none that will do."""
        library = self.scratch / f'{name}.dylib'
        (self.scratch / f'{name}.c').write_text(source)
        subprocess.run([os.environ.get('CC', 'cc'), '-dynamiclib', '-o', str(library), str(self.scratch / f'{name}.c'),
                        '-I', str(smirpack.INTERFACE / 'include'), '-I', str(smirpack.CONTRACT),
                        *(f'-D{key.upper()}={value}' for key, value in numbers.items())],
                       check=True, capture_output=True)
        return library

    def described(self):
        """The runtime as it describes itself: its interface's version and its identity."""
        import ctypes

        class Runtime(ctypes.Structure):
            _fields_ = [('size', ctypes.c_uint32), ('version', ctypes.c_uint32),
                        ('abi_major', ctypes.c_uint32), ('abi_minor', ctypes.c_uint32),
                        ('revision', ctypes.c_uint32), ('profile', ctypes.c_uint32),
                        ('implementation', ctypes.c_uint8 * 32), ('helpers', ctypes.c_uint8 * 32),
                        ('service_catalogs', ctypes.c_uint32), ('reserved0', ctypes.c_uint32),
                        ('services', ctypes.c_uint8 * 32 * 4)]
        runtime = Runtime(size=ctypes.sizeof(Runtime), version=1)
        self.assertEqual(ctypes.sizeof(Runtime), 224)
        self.assertEqual(ctypes.CDLL(str(self.runtime)).rax_portable_x1_runtime(ctypes.byref(runtime)), 0)
        return runtime

    def test_it_runs_with_the_runtime_it_was_built_to_use(self):
        executable = self.packed('explicit', runtime=self.runtime)
        # It holds its program and no runtime: some tens of kilobytes more.
        self.assertLess(executable.stat().st_size, self.object.stat().st_size + 256 * 1024)
        for arguments in ([], ['one', 'two']):
            # Each in a directory of its own, whose files the program has.
            run = self.started(self.runner, str(self.object), '--program', '--native', '--directory', '.', '--',
                               *arguments)
            packed = self.started(executable, *arguments)
            name = lambda text, own: text.replace(str(own).encode(), b'PROGRAM')  # noqa: E731
            self.assertEqual((packed.returncode, name(packed.stdout, executable), packed.stderr),
                             (run.returncode, name(run.stdout, self.object), run.stderr))
            self.assertEqual(packed.returncode, 41 + len(arguments))
        # A fault of the program is reported as by any executable of it.
        faulted = self.started(executable, 'fault')
        self.assertEqual((faulted.returncode, json.loads(faulted.stderr)['trap']['code']),
                         (125, 'pointer_provenance'))

    def test_a_runtime_is_found_beside_the_executable_or_by_the_record(self):
        # Beside it: `../lib/rax` from the directory the executable is in.
        beside = self.packed('prefix/bin/program')
        self.assertEqual(self.refusal(beside), 'LAUNCH_RUNTIME_NONE')
        home = self.scratch / 'prefix/lib/rax'
        home.mkdir(parents=True)
        (home / smirpack.RUNTIME_NAME).write_bytes(self.runtime.read_bytes())
        self.assertEqual(self.started(beside, 'x').returncode, 42)
        # From where the file is, not from the name it was started by.
        (self.scratch / 'elsewhere').mkdir()
        (self.scratch / 'elsewhere/link').symlink_to(beside)
        self.assertEqual(self.started(self.scratch / 'elsewhere/link', 'x').returncode, 42)
        # By the record: a file whose first line is the runtime's path.
        record = self.scratch / 'record'
        recorded = self.packed('recorded', record=record)
        self.assertEqual(self.refusal(recorded), 'LAUNCH_RUNTIME_NONE')
        record.write_text(f'{self.runtime}\nwhatever follows is not read\n')
        self.assertEqual(self.started(recorded, 'x').returncode, 42)
        # A record that names no file, or no absolute path, or nothing.
        for content, code in ((f'{self.scratch}/nowhere.dylib\n', 'LAUNCH_RUNTIME_MISSING'),
                              (f'prefix/lib/rax/{smirpack.RUNTIME_NAME}\n', 'LAUNCH_RUNTIME_MISSING'),
                              ('', 'LAUNCH_RUNTIME_RECORD'), (str(self.runtime), 'LAUNCH_RUNTIME_RECORD')):
            record.write_text(content)
            self.assertEqual(self.refusal(recorded), code, content)

    def test_nothing_but_what_was_configured_is_consulted(self):
        home = self.runtime.parent
        nowhere = self.packed('nowhere')
        # Not the directory it is started in, nor the system's search paths.
        for variable in ('DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH', 'LD_LIBRARY_PATH', 'PATH'):
            executed = subprocess.run([str(nowhere)], capture_output=True, timeout=120, cwd=home,
                                      env={**os.environ, variable: str(home)})
            self.assertEqual((executed.returncode, json.loads(executed.stderr)['code']),
                             (125, 'LAUNCH_RUNTIME_NONE'), variable)
        # The first place that is configured is the one: a runtime that is
        # not there, or will not do, is not passed over for the next.
        good = self.scratch / 'first/lib/rax'
        good.mkdir(parents=True)
        (good / smirpack.RUNTIME_NAME).write_bytes(self.runtime.read_bytes())
        record = self.scratch / 'first-record'
        record.write_text(f'{self.runtime}\n')
        missing = self.packed('first/bin/missing', runtime=self.scratch / 'gone.dylib', record=record)
        self.assertEqual(self.refusal(missing), 'LAUNCH_RUNTIME_MISSING')
        older = self.pretender('older', PRETENDER, major=1, minor=0, profile=2)
        other = self.scratch / 'second/lib/rax'
        other.mkdir(parents=True)
        (other / smirpack.RUNTIME_NAME).write_bytes(older.read_bytes())
        self.assertEqual(self.refusal(self.packed('second/bin/program', record=record)), 'LAUNCH_RUNTIME_VERSION')

    def test_a_runtime_that_will_not_do_does_not_run_the_program(self):
        # An earlier interface, another major version, another profile.
        for name, numbers in (('minor', dict(major=1, minor=0, profile=2)),
                              ('major', dict(major=2, minor=5, profile=2)),
                              ('profile', dict(major=1, minor=1, profile=3))):
            library = self.pretender(name, PRETENDER, **numbers)
            self.assertEqual(self.refusal(self.packed(f'with-{name}', runtime=library)), 'LAUNCH_RUNTIME_VERSION',
                             name)
        # A later interface of the same major version will do as far as
        # that goes; this one has none of the functions.
        later = self.pretender('later', PRETENDER, major=1, minor=9, profile=2)
        self.assertEqual(self.refusal(self.packed('with-later', runtime=later)), 'LAUNCH_RUNTIME_MALFORMED')
        # A library that is no runtime, and a file that is no library.
        silent = self.pretender('silent', SILENT)
        self.assertEqual(self.refusal(self.packed('with-silent', runtime=silent)), 'LAUNCH_RUNTIME_MALFORMED')
        self.assertEqual(self.refusal(self.packed('with-text', runtime=self.object)), 'LAUNCH_RUNTIME_LOAD')
        # The revision and the identity it was built to ask for.
        runtime = self.described()
        self.assertEqual((runtime.abi_major, runtime.abi_minor, runtime.profile), (1, 1, 2))
        identity = bytes(runtime.implementation).hex()
        exact = self.packed('exact', runtime=self.runtime, identity=identity, revision=runtime.revision)
        self.assertEqual(self.started(exact, 'x').returncode, 42)
        another = identity[:-1] + ('0' if identity[-1] != '0' else '1')
        self.assertEqual(self.refusal(self.packed('another', runtime=self.runtime, identity=another)),
                         'LAUNCH_RUNTIME_IDENTITY')
        self.assertEqual(self.refusal(self.packed('newer', runtime=self.runtime, revision=runtime.revision + 1)),
                         'LAUNCH_RUNTIME_VERSION')

    def test_what_is_built_in_is_an_absolute_path_and_an_identity(self):
        for how in (dict(runtime='lib/runtime.dylib'), dict(record='record'), dict(runtime='/with"quote'),
                    dict(identity='abc'), dict(identity='G' * 64)):
            with self.assertRaises(smirpack.PackError, msg=how):
                smirpack.Installed(**how)


if __name__ == '__main__':
    unittest.main()
