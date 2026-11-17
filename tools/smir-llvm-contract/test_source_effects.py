"""Pinned structural IR witnesses; no helper admission, emission or execution."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/source-effects'
INPUTS = (Path(__file__).resolve(), *(FIXTURES / name for name in
          ('README.md', 'effects.ll', 'binding-group.ll', 'byte-relay.cpp')))
LIMIT = ('LLVM structural parser/optimizer and source IR only; no source/native/guest '
         'execution, actual helper registration, descriptor admission, source byte '
         'provenance, ISO legality, SMIR target or compiler-freeze qualification')


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def snapshot():
    return [dict(path=str(path.relative_to(ROOT)), sha256=digest(path),
                 bytes=path.stat().st_size) for path in INPUTS]


def output_parent(path, llvm):
    result = Path(path).resolve()
    if result.is_relative_to(ROOT.resolve()) or result.is_relative_to(llvm.resolve()):
        raise ValueError('source-effect outputs must be outside both source checkouts')
    return result


class SourceEffectWitnesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        primary = os.environ.get('SMIR_LLVM_ROOT')
        compatibility = os.environ.get('LLVM_REFERENCE_CHECKOUT')
        if primary and compatibility and Path(primary).resolve() != Path(compatibility).resolve():
            raise ValueError('conflicting LLVM source checkout overrides')
        cls.llvm = Path(primary or compatibility or '/Users/int/dev/llvm-project').resolve()
        cls.compiler = Path(os.environ.get('SMIR_LLVM_BIN', str(cls.llvm / 'build/bin'))) / 'clang'
        cls.head = cls.source_head()
        version = subprocess.check_output([str(cls.compiler), '--version'], text=True, timeout=10)
        if cls.head != PIN or PIN not in version or not re.search(r'clang version 24\.', version):
            raise ValueError('source-effect compiler/source pin mismatch')
        cls.compiler_hash = digest(cls.compiler)
        cls.before = snapshot()
        parent = output_parent(os.environ.get('SMIR_RECORD_WITNESS_DIR',
                               '/tmp/rax-portable-smir-01/LLVM/source-effect-runs'), cls.llvm)
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='source-effects-', dir=parent))
        cls.observations = []
        cls.tool = dict(path=str(cls.compiler), realpath=str(cls.compiler.resolve()),
                        sha256=cls.compiler_hash, version=version, llvm_head=cls.head)

    @classmethod
    def source_head(cls):
        return subprocess.check_output(['git', '-C', str(cls.llvm), 'rev-parse', 'HEAD'],
                                       text=True, timeout=10).strip()

    @classmethod
    def tearDownClass(cls):
        after = snapshot()
        compiler_after = digest(cls.compiler)
        head_after = cls.source_head()
        stable = cls.before == after and compiler_after == cls.compiler_hash and head_after == cls.head
        report = dict(scope=LIMIT, observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      compiler=cls.tool, compiler_after=compiler_after, llvm_head_after=head_after,
                      inputs_before=cls.before, inputs_after=after, source_inputs_stable=stable,
                      compiler_invocations=len(cls.observations), observations=cls.observations)
        (cls.output / 'observations.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Structural source-effect artifacts retained:', cls.output)
        if not stable:
            raise AssertionError('source-effect inputs/compiler/source HEAD changed during witnesses')

    def compile(self, name, *, optimization=1, source=False, mutation=None, rejection=None):
        fixture = FIXTURES / name
        original = fixture.read_text()
        text = original if mutation is None else mutation(original)
        stem = f'{len(self.observations):02}-{fixture.stem}'
        copied = self.output / (stem + fixture.suffix)
        copied.write_text(text)
        output = self.output / (stem + '.out.ll')
        if source:
            argv = [str(self.compiler), '-target', 'x86_64-unknown-linux-gnu', '-std=c++23',
                    '-pedantic-errors', '-nostdinc', '-S', '-emit-llvm', f'-O{optimization}']
        else:
            argv = [str(self.compiler), '-cc1', '-triple', 'x86_64-unknown-linux-gnu',
                    '-emit-llvm', f'-O{optimization}', '-x', 'ir']
        argv += [str(copied), '-o', str(output)]
        row = dict(fixture=str(fixture.relative_to(ROOT)), fixture_sha256=digest(fixture),
                   input=str(copied), input_sha256=digest(copied), mutated=mutation is not None,
                   argv=argv, expected_rejection=rejection, scope=LIMIT)
        self.observations.append(row)
        (self.output / (stem + '.argv.json')).write_text(json.dumps(argv, indent=2) + '\n')
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            row.update(exit=None, timed_out=True)
            for label, value in [('stdout', error.stdout), ('stderr', error.stderr)]:
                data = value.decode(errors='replace') if isinstance(value, bytes) else value or ''
                (self.output / (stem + '.' + label)).write_text(data)
            self.fail(f'pinned compiler timed out: {argv!r}')
        (self.output / (stem + '.stderr')).write_text(result.stderr)
        (self.output / (stem + '.stdout')).write_text(result.stdout)
        row.update(exit=result.returncode, stderr=result.stderr,
                   output=str(output) if output.exists() else None,
                   output_sha256=digest(output) if output.exists() else None)
        if rejection is not None:
            self.assertNotEqual(result.returncode, 0, 'malformed IR was accepted')
            self.assertIn(rejection, result.stderr)
            row['checked'] = ['expected actual pinned parser/verifier rejection']
            return '', row
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file(), 'successful compiler produced no IR')
        return output.read_text(), row

    def body(self, text, name):
        match = re.search(r'^define[^\n]*@' + re.escape(name) + r'\([^\n]*\)[^\n]*\{\n(.*?)^\}',
                          text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, f'missing actual LLVM function {name}')
        return match.group(1)

    def test_observing_effects_and_descriptor_operands(self):
        text, row = self.compile('effects.ll')
        body = self.body(text, 'observed')
        self.assertEqual(body.count('call addrspace(1)'), 4)
        self.assertIn('%discard = call addrspace(1) i64 @__rax_ir_v1_code_address_expose', body)
        self.assertRegex(body, r'code_bind\([^\n]*ptr @source_call_ref\)')
        self.assertRegex(body, r'code_erase\([^\n]*ptr @execution_ref\)')
        self.assertRegex(text, r'define[^\n]*@observed[^\n]*#(\d+)')
        wrapper = re.search(r'define[^\n]*@observed[^\n]*#(\d+)', text).group(1)
        self.assertRegex(text, r'attributes #' + wrapper + r' = \{[^\n]*noinline[^\n]*optnone')
        declarations = re.findall(r'^declare[^\n]*@__rax_ir_v1_[^\n]*#(\d+)', text, re.MULTILINE)
        self.assertTrue(declarations)
        for identifier in declarations:
            attributes = re.search(r'^attributes #' + identifier + r' = \{([^\n]*)\}',
                                   text, re.MULTILINE).group(1)
            for attribute in ('nounwind', 'nocallback', 'convergent', 'noduplicate', 'memory(readwrite)'):
                self.assertIn(attribute, attributes)
            for attribute in ('speculatable', 'willreturn', 'nosync', 'noundef'):
                self.assertNotIn(attribute, attributes)
        self.assertIn('@observed', self.body(text, 'outer'))
        row['checked'] = ['four observing calls including unused exposure retained',
                          'actual descriptor operands/effects retained', 'noinline+optnone wrapper survives']

    def test_single_journal_begin_returns_new_scope(self):
        text, row = self.compile('effects.ll')
        body = self.body(text, 'begin_publish')
        self.assertRegex(body, r'%scope = call addrspace\(1\) target\("smir.source_scope"\) '
                              r'@__rax_ir_v1_object_begin_root\(ptr @scope_ref, '
                              r'target\("smir.journal"\) %journal, ptr %object\)')
        self.assertIn('target("smir.source_scope") %scope, target("smir.journal") %journal', body)
        self.assertEqual(body.count('@__rax_ir_v1_object_begin_root'), 1)
        self.assertNotIn('scope_enter', body)
        self.assertNotIn('scope_exit', text)
        for path in (ROOT, self.llvm):
            with self.assertRaisesRegex(ValueError, 'outside both source checkouts'):
                output_parent(path / 'must-not-be-created', self.llvm)
        link = self.output / 'checkout-link'
        link.symlink_to(ROOT, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'outside both source checkouts'):
            output_parent(link / 'must-not-be-created', self.llvm)
        row['checked'] = ['one real Journal operand produces new opaque scope before publish',
                          'no invented prior scope or obsolete exit', 'direct/symlink output-root guards reject']

    def test_opaque_binding_aggregate_input_and_return(self):
        text, row = self.compile('binding-group.ll')
        body = self.body(text, 'group_roundtrip')
        self.assertIn('@__rax_ir_v1_codeptr_expose_group.2', body)
        self.assertIn('@__rax_ir_v1_codeptr_recover_group.2', body)
        self.assertEqual(body.count('call addrspace(1)'), 2)
        self.assertRegex(body, r'ret \{ target\("smir.code_binding"\), target\("smir.code_binding"\) \} %recovered')
        self.assertNotIn('alloca', body)
        self.assertNotIn('store ', body)
        row['checked'] = ['two-B aggregate SSA input and return structurally accepted',
                          'one opaque group call per exposure/recovery; no per-lane calls or storage']

    def test_optnone_without_noinline_rejects(self):
        self.compile('effects.ll', optimization=0,
                     mutation=lambda text: text.replace('noinline optnone', 'optnone'),
                     rejection="Attribute 'optnone' requires 'noinline'")

    def test_stored_unsized_binding_rejects(self):
        self.compile('binding-group.ll', optimization=0,
                     mutation=lambda text: 'define void @bad() {\n'
                                           ' %p = alloca target("smir.code_binding")\n ret void\n}\n',
                     rejection='Cannot allocate unsized type')

    def test_vector_of_opaque_binding_rejects(self):
        self.compile('binding-group.ll', optimization=0,
                     mutation=lambda text: 'declare <2 x target("smir.code_binding")> @bad()\n',
                     rejection='invalid vector element type')

    def test_character_relay_exposes_scalar_abi_boundary(self):
        for optimization in (0, 1):
            with self.subTest(optimization=optimization):
                text, row = self.compile('byte-relay.cpp', source=True, optimization=optimization)
                self.assertRegex(text, r'define[^\n]*i8 @relay\(i8')
                self.assertRegex(text, r'declare[^\n]*i8 @external_relay\(i8')
                body = self.body(text, '_Z17copy_via_externalPFiiEi')
                self.assertIn('load i8,', body)
                self.assertIn('store i8 ', body)
                self.assertRegex(body, r'call[^\n]*i8 @external_relay\(i8')
                self.assertRegex(body, r'call[^\n]*i32 %')
                self.assertNotIn('ptrtoint', text)
                row['checked'] = ['external char parameter/result remains i8 at actual ABI boundary',
                                  'i8 loads/stores and indirect call remain without ptrtoint',
                                  'structural gap witness only; no ISO legality/origin-preservation claim']


if __name__ == '__main__':
    unittest.main()
