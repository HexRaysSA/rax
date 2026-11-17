"""Pinned native IR counters; compilation is not SMIR/native source execution."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from builder import PIN, REPOSITORY, digest

FIXTURES = REPOSITORY / 'docs/specifications/smir/portable/conformance/llvm/record-layout'


class NativeBoundaryWitnesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.llvm = Path(os.environ.get('LLVM_REFERENCE_CHECKOUT', '/Users/int/dev/llvm-project'))
        cls.compiler = cls.llvm / 'build/bin/clang'
        head = subprocess.check_output(['git', '-C', str(cls.llvm), 'rev-parse', 'HEAD'],
                                       text=True, timeout=10).strip()
        version = subprocess.check_output([str(cls.compiler), '--version'], text=True, timeout=10)
        if head != PIN or PIN not in version:
            raise ValueError('native boundary witness compiler/source pin mismatch')
        parent = Path(os.environ.get('SMIR_RECORD_WITNESS_DIR',
                                    '/tmp/rax-portable-smir-01/LLVM/record-layout-runs'))
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='native-boundary-', dir=parent))
        cls.compiler_hash = digest(cls.compiler)
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        (cls.output / 'observations.json').write_text(json.dumps(dict(
            scope='Existing-target source/IR compilation only; no source/guest execution',
            compiler_sha256=cls.compiler_hash, observations=cls.observations), indent=2) + '\n')
        assert digest(cls.compiler) == cls.compiler_hash
        print('Native compile-only boundary artifacts retained:', cls.output)

    def compile_ir(self, name):
        source = FIXTURES / name
        original_hash = digest(source)
        output = self.output / (source.stem + '.ll')
        argv = [str(self.compiler), '-target', 'x86_64-unknown-linux-gnu', '-std=c++23',
                '-nostdinc', '-S', '-emit-llvm', str(source), '-o', str(output)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.observations.append(dict(argv=argv, source_sha256=original_hash,
                                      exit=result.returncode, stderr=result.stderr,
                                      ir_sha256=digest(output) if output.exists() else None))
        self.assertEqual(digest(source), original_hash)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_text()

    def test_incomplete_prototype_pointer_address_copy_needs_no_callable_abi(self):
        ir = self.compile_ir('source-incomplete-prototypes.cpp')
        self.assertRegex(ir, r'@_ZTV7Logical = external constant')
        self.assertIn('@null_pointer = dso_local global ptr null, align 8', ir)
        self.assertIn('@address_pointer = dso_local global ptr @_Z8function1R, align 8', ir)
        self.assertRegex(ir, r'declare void @_Z8function1R\(\)')
        self.assertRegex(ir, r'load ptr, ptr @address_pointer, align 8')
        self.assertNotRegex(ir, r'call .*@_Z8function1R')

    def test_native_early_rtti_cache_survives_final_class_definition(self):
        ir = self.compile_ir('source-rtti-cache.cpp')
        pointer = next(line for line in ir.splitlines() if line.startswith('@_ZTIP1F ='))
        source_class = next(line for line in ir.splitlines() if line.startswith('@_ZTI1F ='))
        self.assertIn('internal constant', pointer)
        self.assertIn('i32 8, ptr @_ZTI1F', pointer)
        self.assertIn('__class_type_infoE', source_class)
        self.assertNotIn('__si_class_type_infoE', source_class)
        self.assertNotIn('@_ZTI1B', source_class)
        self.assertIn('@before = dso_local global ptr @_ZTIP1F, align 8', ir)
        self.assertIn('@after = dso_local global ptr @_ZTIP1F, align 8', ir)
        self.assertIn('@direct = dso_local global ptr @_ZTI1F, align 8', ir)

    def test_one_source_structor_has_distinct_complete_and_base_fn_plans(self):
        ir = self.compile_ir('source-structor-plans.cpp')
        shapes = {}
        for line in ir.splitlines():
            match = re.match(r'define .*@(_ZN1A(?:C[12]Ei|D[12]Ev))\((.*?)\)', line)
            if match:
                # Attribute parentheses can precede the end of the argument list.
                arguments = line[line.index('(') + 1:line.index(') unnamed_addr')]
                shapes[match.group(1)] = arguments.split(', ')
        self.assertEqual({key: len(value) for key, value in shapes.items()},
                         {'_ZN1AC1Ei': 2, '_ZN1AC2Ei': 3, '_ZN1AD1Ev': 1, '_ZN1AD2Ev': 2})
        for key in ('_ZN1AC2Ei', '_ZN1AD2Ev'):
            self.assertTrue(shapes[key][1].startswith('ptr noundef '))
        self.assertTrue(shapes['_ZN1AC1Ei'][-1].startswith('i32 noundef '))
        self.assertTrue(shapes['_ZN1AC2Ei'][-1].startswith('i32 noundef '))


if __name__ == '__main__':
    unittest.main()
