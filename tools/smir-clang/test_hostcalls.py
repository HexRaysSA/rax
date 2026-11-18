#!/usr/bin/env python3
"""Programs that call functions of their host: `smircc.py` and the host C
interface, end to end.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_hostcalls.py'

`tests/hostcalls/program.c` declares three functions of its host by link
names of the form `host:NAMESPACE:NAME@VERSION`. The compiler makes each an
import of the module and writes, beside the object, the descriptor a host
registers the function with. `tests/hostcalls/host.c` is such a host: a C
program against the contract's header, linked with the runtime's static
library, which registers the three with those descriptors and runs the
program. One of its functions answers later, from a thread of its own.

The other tests are about what the compiler writes and refuses, and what a
runtime does with such a program when it has no such host.

Requires what test_hosted.py requires.
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
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tools/smir-format'))

import runner  # noqa: E402
import smircc  # noqa: E402
import smirpack  # noqa: E402

SOURCES = HERE / 'tests/hostcalls'
FIXTURE = ROOT / 'crates/smir-portable/tests/interp/programs/hosts.descriptors.json'
NAMES = {'add': 'host:app:add@1', 'tick': 'host:app:tick@1', 'scale': 'host:app.math:scale@3'}


class HostCalls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-hostcalls-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.scratch = Path(cls.directory.name)
        cls.runner = runner.build()
        cls.object = cls.scratch / 'program.smo'
        smircc.compile_files([SOURCES / 'program.c'], cls.object, ['-O2', '-std=c11', '-w'], hosted=True)
        cls.described = json.loads(Path(str(cls.object) + '.hosts.json').read_text())

    def test_the_compiler_writes_one_descriptor_for_a_function_whoever_imports_it(self):
        self.assertEqual(sorted(self.described), sorted(NAMES.values()))
        add = self.described[NAMES['add']]
        self.assertEqual((add['namespace'], add['name'], add['version']), ('app', 'add', 1))
        # The descriptors are those a module authored by hand has for the
        # same three functions: the types in one are numbered by the
        # function, not by the module that imports it.
        authored = json.loads(FIXTURE.read_text())
        for name, link_name in NAMES.items():
            self.assertEqual(self.described[link_name]['descriptor'], authored[name], name)
        # And another module that imports one of them, among other types
        # of its own, quotes the same identity.
        other = self.scratch / 'other.smo'
        (self.scratch / 'other.c').write_text(
            'double scale(double, long long) __asm__("host:app.math:scale@3");\n'
            'struct pair { short first; float second; };\n'
            'double entry(struct pair *given) { return scale(given->second, given->first); }\n')
        smircc.compile_files([self.scratch / 'other.c'], other, ['-O1', '-std=c11', '-w'])
        again = json.loads(Path(str(other) + '.hosts.json').read_text())
        self.assertEqual(again, {NAMES['scale']: dict(self.described[NAMES['scale']],
                                                      signature=again[NAMES['scale']]['signature'])})
        # The module imports each function, quoting its descriptor's
        # identity, and declares the capability to call the host.
        import smir
        roots = smir.records(smircc.object_limits()).decode(self.object.read_bytes()).roots
        imported = {(item['namespace'], item['name'], item['version']): item['descriptor']
                    for item in roots[6]['imports'] if item['kind'] == 'host'}
        self.assertEqual(imported, {(item['namespace'], item['name'], item['version']): item['identity']
                                    for item in self.described.values()})
        self.assertIn('host_value', roots[9]['capabilities'])
        # A program without such functions has no such file.
        plain = self.scratch / 'plain.smo'
        (self.scratch / 'plain.c').write_text('int entry(int x) { return x + 1; }\n')
        smircc.compile_files([self.scratch / 'plain.c'], plain, ['-O1', '-std=c11', '-w'])
        self.assertFalse(Path(str(plain) + '.hosts.json').exists())

    def test_what_is_no_host_function_is_refused_by_the_compiler(self):
        cases = {
            # Memory is not the host's to be given.
            'int peek(const char *) __asm__("host:app:peek@1");\nint entry(void) { return peek("x"); }\n':
                'takes or returns other than integers and floats',
            'char *name(void) __asm__("host:app:name@1");\nchar *entry(void) { return name(); }\n':
                'takes or returns other than integers and floats',
            # A name that is none: no version, no namespace, the runtime's own.
            'int f(int) __asm__("host:app:f");\nint entry(int x) { return f(x); }\n':
                'is not host:NAMESPACE:NAME@VERSION',
            'int f(int) __asm__("host:f@1");\nint entry(int x) { return f(x); }\n':
                'is not host:NAMESPACE:NAME@VERSION',
            'int f(int) __asm__("host:smir.internal:f@1");\nint entry(int x) { return f(x); }\n':
                'is not host:NAMESPACE:NAME@VERSION',
            'int f(int) __asm__("host:app:f@0");\nint entry(int x) { return f(x); }\n':
                'is not host:NAMESPACE:NAME@VERSION',
        }
        for position, (source, message) in enumerate(cases.items()):
            with self.subTest(message=message, source=source.splitlines()[0]):
                path = self.scratch / f'refused{position}.c'
                path.write_text(source)
                with self.assertRaises(smircc.CompileError) as refused:
                    smircc.compile_files([path], self.scratch / f'refused{position}.smo',
                                         ['-O1', '-std=c11', '-w'])
                self.assertIn('E-HOST-BINDING', str(refused.exception))
                self.assertIn(message, str(refused.exception))

    def test_a_runtime_without_the_host_does_not_run_the_program(self):
        for engine in ([], ['--native']):
            executed = subprocess.run([str(self.runner), str(self.object), '--program', *engine],
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
            self.assertEqual((executed.returncode, executed.stdout), (125, b''))
            report = json.loads(executed.stderr)
            self.assertEqual((report['status'], report['code'], report['detail']),
                             ('rejected', 'EXEC_CAPABILITY', 'host_value'))

    @unittest.skipIf(platform.system() == 'Windows', 'the host of this test is built with a Unix C compiler')
    def test_a_host_in_c_has_the_functions_its_program_calls(self):
        _, library = smirpack.tools()
        header = ''.join(
            'static const unsigned char %s_descriptor[] = {%s};\n'
            % (name, ', '.join(str(byte) for byte in bytes.fromhex(self.described[link_name]['descriptor'])))
            for name, link_name in NAMES.items())
        (self.scratch / 'descriptors.h').write_text(header)
        host = self.scratch / 'host'
        system = ['-lSystem', '-lc', '-lm'] if platform.system() == 'Darwin' else ['-lpthread', '-ldl', '-lm']
        compiled = subprocess.run(
            [os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Werror', '-O1', '-o', str(host),
             str(SOURCES / 'host.c'), '-I', str(self.scratch), '-I', str(smirpack.INTERFACE / 'include'),
             '-I', str(smirpack.CONTRACT), str(library), *system], capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr[-3000:])
        executed = subprocess.run([str(host), str(self.object)], stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=120)
        self.assertEqual(executed.stderr, b'')
        self.assertEqual(
            executed.stdout.decode(),
            'add 5\nticks 1 2\nscale 6\n'
            '{"version":1,"reason":"normal","code":41,"thread":1,"trap":null}\n'
            'released 0\nreleased 3\n')
        self.assertEqual(executed.returncode, 0)
        # A host that lacks one of the functions is no host for the program.
        lacking = subprocess.run([str(host), str(self.object), 'lacking'], stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=120)
        self.assertEqual((lacking.returncode, lacking.stdout),
                         (5, b'no program for this host: 8\nreleased 2\n'))


if __name__ == '__main__':
    unittest.main()
