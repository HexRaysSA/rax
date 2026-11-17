"""Pinned opaque-E outcome IR only; no CPP source issuer or execution proof.

Run with python3 -B -m unittest discover -s tools/smir-llvm-contract
-p test_scope_outcomes.py -v; SMIR_RECORD_WITNESS_DIR selects retained outputs.
"""
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import test_source_effects as effects


FIXTURE = effects.FIXTURES / 'scope-outcomes.ll'
INPUTS = (*effects.INPUTS, Path(__file__).resolve(), FIXTURE)
SCOPE = ('Pinned LLVM opaque-E/six exit declarations/SSA verification only; '
         'deliberately invalid RAX Ref; no actual CPP SourceFacts, scope/lifetime '
         'issuer, journal-view adapter, emitter, native/guest execution or freeze proof')
E = 'target("smir.exception")'
S = 'target("smir.source_scope")'
J = 'target("smir.journal")'
PAIR = '{ ' + E + ', i32 }'


def snapshot():
    return [dict(path=str(path.relative_to(effects.ROOT)), sha256=effects.digest(path),
                 bytes=path.stat().st_size) for path in INPUTS]


class ScopeOutcomeWitnesses(unittest.TestCase):
    @classmethod
    def head(cls):
        return subprocess.check_output(['git', '-C', str(cls.llvm), 'rev-parse', 'HEAD'],
                                       text=True, timeout=10).strip()

    @classmethod
    def setUpClass(cls):
        primary = os.environ.get('SMIR_LLVM_ROOT')
        compatibility = os.environ.get('LLVM_REFERENCE_CHECKOUT')
        if primary and compatibility and Path(primary).resolve() != Path(compatibility).resolve():
            raise ValueError('conflicting outcome witness LLVM checkout overrides')
        cls.llvm = Path(primary or compatibility or '/Users/int/dev/llvm-project').resolve()
        cls.compiler = Path(os.environ.get('SMIR_LLVM_BIN', str(cls.llvm / 'build/bin'))) / 'clang'
        cls.before_head = cls.head()
        version = subprocess.check_output([str(cls.compiler), '--version'], text=True, timeout=10)
        if cls.before_head != effects.PIN or effects.PIN not in version or not re.search(r'clang version 24\.', version):
            raise ValueError('scope outcome compiler/source pin mismatch')
        cls.compiler_hash = effects.digest(cls.compiler)
        cls.before = snapshot()
        parent = effects.output_parent(os.environ.get('SMIR_RECORD_WITNESS_DIR',
                                       '/tmp/rax-portable-smir-01/LLVM/scope-outcome-runs'), cls.llvm)
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='scope-outcomes-', dir=parent))
        cls.observations = []
        cls.tool = dict(path=str(cls.compiler), realpath=str(cls.compiler.resolve()),
                        sha256=cls.compiler_hash, version=version, llvm_head=cls.before_head)

    @classmethod
    def tearDownClass(cls):
        after = snapshot()
        compiler_after, head_after = effects.digest(cls.compiler), cls.head()
        stable = cls.before == after and compiler_after == cls.compiler_hash and head_after == cls.before_head
        report = dict(scope=SCOPE, observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      compiler=cls.tool, compiler_after=compiler_after, llvm_head_after=head_after,
                      inputs_before=cls.before, inputs_after=after, source_inputs_stable=stable,
                      compiler_invocations=len(cls.observations), observations=cls.observations)
        (cls.output / 'observations.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Opaque-E scope-outcome artifacts retained:', cls.output)
        if not stable:
            raise AssertionError('scope outcome seven-file/compiler/source-HEAD guard changed')

    def compile(self, **options):
        text, row = effects.SourceEffectWitnesses.compile(self, FIXTURE.name, **options)
        row['scope'] = SCOPE
        return text, row

    def assert_positive_ir(self, text):
        declarations = re.findall(r'^declare void @__rax_ir_v1_scope_exit\.([^\n]+)', text, re.MULTILINE)
        self.assertEqual(len(declarations), 6)
        for mode in ('normal', 'unwind', 'outward_unwind'):
            for journal in (False, True):
                name = mode + ('.with_journal' if journal else '.no_journal')
                params = ['ptr', S] + ([J] if journal else []) + ([E] if mode == 'unwind' else [])
                declaration = re.search(r'^declare void @__rax_ir_v1_scope_exit\.' + re.escape(name) +
                                        r'\(([^\n]+)\)(?: local_unnamed_addr)? addrspace\(1\) #(\d+)',
                                        text, re.MULTILINE)
                self.assertIsNotNone(declaration, name)
                self.assertEqual(re.sub(r'\s+', '', declaration.group(1)),
                                 re.sub(r'\s+', '', ','.join(params)))
                attrs = re.search(r'^attributes #' + declaration.group(2) + r' = \{([^\n]+)\}',
                                  text, re.MULTILINE).group(1)
                for attr in ('nounwind', 'nocallback', 'convergent', 'noduplicate', 'memory(readwrite)'):
                    self.assertIn(attr, attrs)
                for attr in ('willreturn', 'nosync', 'speculatable', 'noundef'):
                    self.assertNotIn(attr, attrs)
        self.assertEqual(text.count('landingpad ' + PAIR), 6)
        joined = effects.SourceEffectWitnesses.body(self, text, 'joined_exception')
        self.assertIn('%exception = phi ' + E, joined)
        self.assertIn('%selector = phi i32', joined)
        self.assertIn('resume ' + PAIR + ' %joined', joined)
        self.assertIn('scope_exit.unwind.no_journal(ptr @ref, ' + S + ' %scope, ' + E + ' %exception)', joined)
        calls = [line for line in text.splitlines() if 'call addrspace(1) void @__rax_ir_v1_scope_exit.' in line]
        self.assertEqual(len(calls), 12)
        for line in calls:
            self.assertIn('ptr @ref, ' + S + ' %scope', line)
            if 'scope_exit.unwind.' in line:
                self.assertIn(E + ' %exception)', line)
            if 'scope_exit.outward_unwind.' in line:
                self.assertNotIn(E, line)
        for function in ('normal_no_j', 'normal_j', 'unwind_no_j', 'unwind_j',
                         'outward_unwind_no_j', 'outward_unwind_j', 'joined_exception'):
            header = re.search(r'^define[^\n]*@' + function + r'\([^\n]*#(\d+)', text, re.MULTILINE)
            self.assertIsNotNone(header, function)
            self.assertRegex(text, r'attributes #' + header.group(1) + r' = \{[^\n]*noinline[^\n]*optnone')
        self.assertNotRegex(text, r'\b(?:alloca|load|store|ptrtoint|inttoptr|bitcast)\b')

    def test_six_exit_forms_and_opaque_e_edges_at_o0(self):
        text, row = self.compile(optimization=0)
        self.assert_positive_ir(text)
        for root in (effects.ROOT, self.llvm):
            with self.assertRaisesRegex(ValueError, 'outside both source checkouts'):
                effects.output_parent(root / 'must-not-be-created', self.llvm)
        link = self.output / 'checkout-link'
        link.symlink_to(effects.ROOT, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'outside both source checkouts'):
            effects.output_parent(link / 'must-not-be-created', self.llvm)
        row['checked'] = ['six exact exit signatures and opaque E landingpad/phi/resume at O0',
                          'same actual typed E operands, no memory/cast; descriptor unadmitted',
                          'direct and symlink output-root guards reject inside either checkout']

    def test_six_exit_forms_and_opaque_e_edges_at_o1(self):
        text, row = self.compile(optimization=1)
        self.assert_positive_ir(text)
        row['checked'] = ['six exit forms/effects/Ref and opaque E CFG relations retained at O1',
                          'noinline+optnone wrappers, no actual source/Exception issuer proven']

    def test_missing_personality_rejects(self):
        self.compile(optimization=0,
                     mutation=lambda text: text.replace(' personality ptr @portable_personality', ''),
                     rejection='personality')

    def test_inconsistent_resume_type_rejects(self):
        self.compile(optimization=0,
                     mutation=lambda text: text.replace('resume ' + PAIR + ' %pair', 'resume i32 0'),
                     rejection='consistent result type')

    def test_stored_opaque_e_rejects(self):
        self.compile(optimization=0,
                     mutation=lambda text: 'define void @bad() {\n %p = alloca ' + E + '\n ret void\n}\n',
                     rejection='Cannot allocate unsized type')


if __name__ == '__main__':
    unittest.main()
