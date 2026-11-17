"""Pinned source/IR witnesses; no portable emission or source program execution."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from builder import PIN, REPOSITORY, digest

FIXTURES = REPOSITORY / 'docs/specifications/smir/portable/conformance/llvm/record-layout'
OBSERVATIONS = []


class SourceFunctionAddressWitnesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.llvm = Path(os.environ.get('LLVM_REFERENCE_CHECKOUT', '/Users/int/dev/llvm-project'))
        cls.compiler = cls.llvm / 'build/bin/clang'
        head = subprocess.check_output(['git', '-C', str(cls.llvm), 'rev-parse', 'HEAD'],
                                       text=True, timeout=10).strip()
        version = subprocess.check_output([str(cls.compiler), '--version'], text=True, timeout=10)
        if head != PIN or PIN not in version:
            raise ValueError('source function-address compiler/source pin mismatch')
        parent = Path(os.environ.get('SMIR_RECORD_WITNESS_DIR',
                                    '/tmp/rax-portable-smir-01/LLVM/fnaddr-runs')).resolve()
        if parent.is_relative_to(REPOSITORY.resolve()) or parent.is_relative_to(cls.llvm.resolve()):
            raise ValueError('function-address outputs must be outside both source checkouts')
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='source-ir-', dir=parent))
        cls.compiler_hash = digest(cls.compiler)
        cls.sources = {path: digest(path) for path in FIXTURES.glob('source-fnaddr-*.cpp')}
        if len(cls.sources) != 5:
            raise ValueError('exact five source function-address fixtures required')

    @classmethod
    def tearDownClass(cls):
        stable = digest(cls.compiler) == cls.compiler_hash and all(
            digest(path) == before for path, before in cls.sources.items())
        report = dict(scope='Pinned existing-target source/static assertions/AST/IR only; '
                            'no source/native/SMIR execution, portable provenance or ISO legality proof',
                      compiler_sha256=cls.compiler_hash, source_inputs_stable=stable,
                      observations=OBSERVATIONS)
        (cls.output / 'observations.json').write_text(json.dumps(report, indent=2) + '\n')
        assert stable, 'compiler or source changed during function-address witnesses'
        print('Function-address source/IR artifacts retained:', cls.output)

    def compile(self, name, *, optimization=0, define=None, ast=False, reject=False):
        source = FIXTURES / name
        suffix = f'{len(OBSERVATIONS):02}-{source.stem}'
        output = self.output / (suffix + ('.ast.json' if ast else '.ll'))
        argv = [str(self.compiler), '-target', 'x86_64-unknown-linux-gnu', '-std=c++23',
                '-pedantic-errors', '-nostdinc', f'-O{optimization}']
        if define:
            argv.append('-D' + define)
        argv += ['-fsyntax-only', '-Xclang', '-ast-dump=json'] if ast else [
            '-S', '-emit-llvm', '-o', str(output)]
        argv.append(str(source))
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        if ast:
            output.write_text(result.stdout)
        (self.output / (suffix + '.stderr')).write_text(result.stderr)
        observation = dict(argv=argv, source_sha256=digest(source),
                           exit=result.returncode, stderr=result.stderr,
                           output=str(output), output_sha256=digest(output) if output.exists() else None)
        OBSERVATIONS.append(observation)
        self.assertEqual(digest(source), self.sources[source])
        self.assertEqual(result.returncode, 1 if reject else 0, result.stderr)
        return result.stderr if reject else output.read_text()

    @staticmethod
    def pass_signature(ir):
        line = next(line for line in ir.splitlines()
                    if line.startswith('define ') and '@_Z4pass' in line)
        return line.split(' #', 1)[0]

    def test_incomplete_source_address_copy_and_view_casts_need_no_call(self):
        ir = self.compile('source-fnaddr-cross-tu-incomplete.cpp')
        self.assertIn('@address = dso_local global ptr @_Z8function1R, align 8', ir)
        self.assertIn('@null_address = dso_local global ptr null, align 8', ir)
        self.assertRegex(ir, r'declare void @_Z8function1R\(\)')
        self.assertNotRegex(ir, r'(?:call|invoke).*@_Z8function1R')
        self.assertRegex(ir, r'icmp eq ptr ')

    def test_completed_native_declaration_is_not_the_opaque_void_placeholder(self):
        ir = self.compile('source-fnaddr-cross-tu-complete.cpp')
        declaration = next(line for line in ir.splitlines()
                           if line.startswith('declare ') and '@_Z8function1R' in line)
        self.assertRegex(declaration, r'\bi32 @_Z8function1R\(i32')
        self.assertNotRegex(declaration, r'\bvoid @_Z8function1R\(\)')

    def test_cross_tu_pointer_value_abi_is_stable_across_pointee_completion(self):
        incomplete = self.compile('source-fnaddr-cross-tu-incomplete.cpp')
        complete = self.compile('source-fnaddr-cross-tu-complete.cpp')
        self.assertEqual(self.pass_signature(incomplete), self.pass_signature(complete))
        self.assertRegex(self.pass_signature(incomplete), r'\bptr @_Z4pass.*\(ptr noundef')

    def test_array_expression_retains_count_cv_and_stable_pointer_function_type(self):
        ir = self.compile('source-fnaddr-array-expression.cpp')
        functions = [line for line in ir.splitlines() if line.startswith('define ')]
        self.assertEqual(len(functions), 2)
        self.assertTrue(all('noundef ptr ' in line and '(ptr noundef' in line for line in functions))
        self.assertIn('PA3_1R', functions[0])
        ast = json.loads(self.compile('source-fnaddr-array-expression.cpp', ast=True))
        functions = {node['name']: node['type']['qualType'] for node in ast['inner']
                     if node['kind'] == 'FunctionDecl' and node.get('name') in {'before', 'after'}}
        self.assertEqual(functions, {'before': 'P (P)', 'after': 'P (P)'})

    def test_noexcept_weakening_is_accepted_and_declared_type_distinct(self):
        ir = self.compile('source-fnaddr-noexcept.cpp')
        self.assertIn('@weakened = dso_local global ptr @_Z8no_throwi, align 8', ir)
        self.assertIn('@exact = dso_local global ptr @_Z8no_throwi, align 8', ir)

    def test_noexcept_strengthening_is_a_source_rejection(self):
        stderr = self.compile('source-fnaddr-noexcept.cpp',
                              define='RAX_REJECT_NOEXCEPT_STRENGTHENING', reject=True)
        self.assertIn('noexcept', stderr)

    def test_actual_call_with_incomplete_byvalue_source_type_is_rejected(self):
        stderr = self.compile('source-fnaddr-cross-tu-incomplete.cpp',
                              define='RAX_REJECT_INCOMPLETE_CALL', reject=True)
        self.assertIn('incomplete', stderr)

    def test_function_address_arithmetic_is_rejected(self):
        stderr = self.compile('source-fnaddr-cross-tu-incomplete.cpp',
                              define='RAX_REJECT_FUNCTION_ARITHMETIC', reject=True)
        self.assertIn('function', stderr)
        self.assertIn('arithmetic', stderr)

    def test_char_loop_records_integer_transport_without_claiming_provenance(self):
        unoptimized = self.compile('source-fnaddr-char-copy.cpp', optimization=0)
        optimized = self.compile('source-fnaddr-char-copy.cpp', optimization=1)
        self.assertRegex(unoptimized, r'load i8,')
        self.assertRegex(unoptimized, r'store i8 ')
        self.assertNotRegex(unoptimized, r'\bb8\b')
        self.assertRegex(optimized, r'(?:tail )?call noundef i32 %0\(')
        self.assertNotRegex(optimized, r'load i8,|store i8 |\bb8\b')


if __name__ == '__main__':
    unittest.main()
