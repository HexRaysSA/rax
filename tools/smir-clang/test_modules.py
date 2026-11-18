#!/usr/bin/env python3
"""Modules compiled apart and linked when they are loaded: `smircc.py --needs`
against `smir-run --library`.

    python3 -B -m unittest discover -s tools/smir-clang -p 'test_modules.py'

The sources in `tests/modules` are compiled to one object each. An object
that calls functions of another names it as a dependency and holds none of
its code; the runner links them into one program before it starts. That
program must write and return what the same sources do when the host's
compiler builds them into one program, on both engines.

The other tests are about what is recorded in an object, what the compiler
refuses, and what the runner refuses when the modules it is given do not
fit.

Requires what test_hosted.py requires.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / 'tools/smir-format'))

import build  # noqa: E402
import runner  # noqa: E402
import smircc  # noqa: E402

SOURCES = HERE / 'tests/modules'
ENGINES = ([], ['--native'])


class Modules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-modules-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.scratch = Path(cls.directory.name)
        build.build()
        cls.runner = runner.build()
        sys.path.insert(0, str(HERE / 'sysroot'))
        import build_libc
        sys.path.pop(0)
        build_libc.build()

    def module(self, name, source, needs=(), hosted=False, version=(1, 0), level='-O2', directory=None):
        """Compile one source, a file of `tests/modules` or C as text, to the
        object of the module `name`, and return where it is."""
        directory = self.scratch / (directory or level)
        directory.mkdir(exist_ok=True)
        if not isinstance(source, Path):
            (directory / f'{name}-source.c').write_text(source)
            source = directory / f'{name}-source.c'
        standard = '-std=c++23' if source.suffix == '.cpp' else '-std=c11'
        smircc.compile_files([source], directory / f'{name}.smo', [level, standard, '-w'], hosted=hosted,
                             needs=needs, version=version)
        return directory / f'{name}.smo'

    def run_program(self, program, libraries, engine=(), arguments=()):
        linked = [item for library in libraries for item in ('--library', str(library))]
        return subprocess.run([str(self.runner), str(program), *linked, '--program', *engine, '--', *arguments],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=300)

    def native(self, name, sources, arguments=()):
        """What the host's own build of the sources as one program does."""
        cxx = any(source.suffix == '.cpp' for source in sources)
        host = os.environ.get('CXX', 'c++') if cxx else os.environ.get('CC', 'cc')
        program = self.scratch / f'{name}-native'
        compiled = subprocess.run([host, '-std=c++2b' if cxx else '-std=c11', '-O1', '-w', '-o', str(program),
                                   *map(str, sources)], capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr[-3000:])
        return subprocess.run([str(program), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=120)

    def refusal(self, program, libraries):
        """The code the runner refuses to start the program with."""
        executed = self.run_program(program, libraries)
        self.assertEqual((executed.returncode, executed.stdout), (125, b''))
        report = json.loads(executed.stderr)
        self.assertEqual(report['status'], 'rejected')
        return report['code']

    def manifest(self, path):
        import smir
        return smir.records(smircc.object_limits()).decode(Path(path).read_bytes()).roots[2]['manifest']

    def three(self, level='-O2'):
        """`base`, `shapes`, which needs it, and the program, which needs both."""
        base = self.module('base', SOURCES / 'base.c', version=(1, 2), level=level)
        shapes = self.module('shapes', SOURCES / 'shapes.c', needs=[base], level=level)
        main = self.module('main', SOURCES / 'main.c', needs=[shapes, base], hosted=True, level=level)
        return base, shapes, main

    def test_modules_compiled_apart_run_as_the_program_compiled_together(self):
        sources = [SOURCES / name for name in ('base.c', 'shapes.c', 'main.c')]
        for level in ('-O0', '-O2'):
            base, shapes, main = self.three(level)
            for arguments in ([], ['one', 'two']):
                reference = self.native('three', sources, arguments)
                self.assertEqual(reference.returncode, 41 + len(arguments))
                # The order the other modules are given in does not matter.
                for libraries in ([shapes, base], [base, shapes]):
                    for engine in ENGINES:
                        with self.subTest(level=level, arguments=arguments, engine=engine,
                                          first=libraries[0].stem):
                            executed = self.run_program(main, libraries, engine, arguments)
                            self.assertEqual((executed.returncode, executed.stdout, executed.stderr),
                                             (reference.returncode, reference.stdout, reference.stderr))

    def test_a_module_may_have_a_c_library_of_its_own(self):
        words = self.module('words', SOURCES / 'words.c', hosted=True)
        talk = self.module('talk', SOURCES / 'talk.c', needs=[words], hosted=True)
        reference = self.native('talk', [SOURCES / 'words.c', SOURCES / 'talk.c'])
        self.assertEqual(reference.returncode, 3)
        for engine in ENGINES:
            with self.subTest(engine=engine):
                executed = self.run_program(talk, [words], engine)
                self.assertEqual((executed.returncode, executed.stdout, executed.stderr),
                                 (reference.returncode, reference.stdout, reference.stderr))
        # The program calls `strlen` and `printf` too: those are its own.
        called = [declared['name'] for declared in self.manifest(talk)['dependencies'][0]['declarations']]
        self.assertEqual(sorted(called), ['announce', 'describe', 'measure', 'release'])

    def test_functions_in_cxx_are_called_by_their_mangled_names(self):
        geometry = self.module('geometry', SOURCES / 'geometry.cpp')
        boxes = self.module('boxes', SOURCES / 'boxes.cpp', needs=[geometry], hosted=True)
        reference = self.native('boxes', [SOURCES / 'geometry.cpp', SOURCES / 'boxes.cpp'])
        self.assertEqual(reference.stdout, b'12 44\n')
        for engine in ENGINES:
            with self.subTest(engine=engine):
                executed = self.run_program(boxes, [geometry], engine)
                self.assertEqual((executed.returncode, executed.stdout, executed.stderr),
                                 (reference.returncode, reference.stdout, reference.stderr))
        called = [declared['name'] for declared in self.manifest(boxes)['dependencies'][0]['declarations']]
        self.assertEqual(sorted(called), ['_ZN8geometry5totalEPKNS_3BoxEi', '_ZNK8geometry3Box4areaEv'])

    def test_an_object_records_what_it_needs_and_holds_none_of_it(self):
        base, shapes, main = self.three()
        # What a module offers: not what it keeps local or hides.
        key, names = smircc.offered(base)
        self.assertEqual(key, {'namespace': 'example', 'name': 'base', 'abi_major': 1, 'abi_minor': 2})
        self.assertEqual(names, ['count', 'ready_value', 'scale'])
        self.assertEqual(self.manifest(base)['dependencies'], [])
        # A function is of the first module that offers it, and only what is
        # called is declared: the version it was built against, or a later.
        needed = self.manifest(main)['dependencies']
        self.assertEqual([(item['slot'], item['key']['name'], item['key']['abi_minor'], item['minimum_minor'],
                           item['maximum_minor'], sorted(declared['name'] for declared in item['declarations']))
                          for item in needed],
                         [(0, 'shapes', 0, 0, None, ['area', 'stored_value', 'ticks']),
                          (1, 'base', 2, 2, None, ['count', 'scale'])])
        # The functions of the other modules are not in the object.
        index = json.loads(Path(str(main) + '.index.json').read_text())
        defined = {entry['name'] for entry in index}
        self.assertIn('main', defined)
        self.assertFalse(defined & {'scale', 'count', 'area', 'ticks', 'stored_value'})
        self.assertLess(shapes.stat().st_size, 16 * 1024)

    def test_a_function_is_the_programs_own_or_of_the_first_module_that_offers_it(self):
        base = self.module('base', SOURCES / 'base.c', directory='own')
        other = self.module('other', 'int scale(int x) { return 7 * x; }\n', directory='own')
        program = ('#include <stdio.h>\nint scale(int);\nlong count(void);\n%s'
                   'int main(void) {\n  printf("%%d %%ld\\n", scale(2), count());\n  return 0;\n}\n')
        # Defined by the program itself: no module is asked for it.
        own = self.module('own', program % 'int scale(int x) { return 100 * x; }\n', needs=[base], hosted=True,
                          directory='own')
        self.assertEqual(self.run_program(own, [base]).stdout, b'200 1\n')
        self.assertEqual([declared['name'] for declared in self.manifest(own)['dependencies'][0]['declarations']],
                         ['count'])
        # Offered by two modules: the first that was named.
        for needs, expected in (([other, base], b'14 1\n'), ([base, other], b'6 1\n')):
            both = self.module(f'first-{needs[0].stem}', program % '', needs=needs, hosted=True, directory='own')
            for engine in ENGINES:
                self.assertEqual(self.run_program(both, [base, other], engine).stdout, expected)
        # Nothing is then called of `other`, which is needed all the same.
        self.assertEqual(self.manifest(both)['dependencies'][1]['declarations'], [])
        self.assertEqual(self.refusal(both, [base]), 'LINK_DEPENDENCY')

    def test_what_does_not_cross_modules_is_refused_by_the_compiler(self):
        base = self.module('base', SOURCES / 'base.c', directory='refused')
        cases = {
            # A function the module hides.
            'int inner(int);\nint entry(int x) { return inner(x); }\n': 'call to undefined function inner',
            # A function no module has.
            'int nowhere(int);\nint entry(int x) { return nowhere(x); }\n': 'call to undefined function nowhere',
            # The address of a function of another module.
            'int scale(int);\nint (*entry(void))(int) { return scale; }\n': 'address of undefined function scale',
            # A variable of another module.
            'extern long shared;\nlong entry(void) { return shared; }\n': 'global variable defined elsewhere: shared',
        }
        for position, (source, message) in enumerate(cases.items()):
            with self.subTest(message=message):
                with self.assertRaises(smircc.CompileError) as refused:
                    self.module(f'case{position}', source, needs=[base], directory='refused')
                self.assertIn(message, str(refused.exception))
        # What is needed is an object.
        with self.assertRaises(smircc.CompileError) as refused:
            self.module('unreadable', 'int entry(void) { return 0; }\n', needs=[SOURCES / 'base.c'],
                        directory='refused')
        self.assertIn('not a module', str(refused.exception))
        # A bitcode library is no module, and needs none.
        command = [sys.executable, '-B', str(HERE / 'smircc.py'), '-c', '--needs', str(base), '-o',
                   str(self.scratch / 'library.bc'), str(SOURCES / 'shapes.c')]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)

    def test_modules_that_do_not_fit_are_refused_when_they_are_loaded(self):
        base, shapes, main = self.three()
        self.assertEqual(self.refusal(main, []), 'EXEC_UNLINKED')
        self.assertEqual(self.refusal(main, [shapes]), 'LINK_DEPENDENCY')
        # An earlier version of a module than the program was built against.
        older = self.module('base', SOURCES / 'base.c', version=(1, 1), directory='older')
        self.assertEqual(self.refusal(main, [shapes, older]), 'LINK_DEPENDENCY')
        # A later one will do.
        newer = self.module('base', SOURCES / 'base.c', version=(1, 5), directory='newer')
        self.assertEqual(self.run_program(main, [shapes, newer]).returncode, 41)
        # But not another major version.
        next_major = self.module('base', SOURCES / 'base.c', version=(2, 2), directory='major')
        self.assertEqual(self.refusal(main, [shapes, next_major]), 'LINK_DEPENDENCY')
        # A module of the name that has a function no longer, or with other
        # parameters.
        text = (SOURCES / 'base.c').read_text()
        without = self.module('base', text.replace('long count(void) { return ++counter; }', ''),
                              version=(1, 2), directory='without')
        self.assertEqual(self.refusal(main, [shapes, without]), 'LINK_UNDEFINED')
        changed = self.module('base', text.replace('int scale(int x)', 'long scale(long x)'), version=(1, 2),
                              directory='changed')
        self.assertEqual(self.refusal(main, [shapes, changed]), 'LINK_TYPE')
        # A module nobody needs.
        geometry = self.module('geometry', SOURCES / 'geometry.cpp')
        self.assertEqual(self.refusal(main, [shapes, base, geometry]), 'LINK_UNUSED')


if __name__ == '__main__':
    unittest.main()
