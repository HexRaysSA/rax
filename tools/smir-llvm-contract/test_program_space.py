"""Actual library-only LLVM structural witnesses, never portable admission."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

import build_program_space_reader as builder
import constant_contract
import gate
from policy import ADDRESS_SPACES, DATALAYOUT, PARAMETERLESS_CARRIERS, PIN
import schema_witness

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'docs/specifications/smir/portable/llvm'
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/program-space'


def digest(path):
    return builder.digest(path)


class Pure(unittest.TestCase):
    def test_coherent_request_target_and_frontend_profile(self):
        target = json.loads((PACKAGE / 'target.json').read_text())
        frontend = json.loads((PACKAGE / 'frontend-contract.json').read_text())
        request = json.loads((FIXTURES.parent / 'request.json').read_text())['base']
        schema = json.loads((PACKAGE / 'request.schema.json').read_text())
        for value in (target, frontend, request):
            self.assertEqual(value['datalayout'], DATALAYOUT)
            self.assertEqual(value['address_spaces'], [0, 1])
        for value in (target, frontend):
            self.assertEqual(value['default_data_address_space'], 0)
            self.assertEqual(value['program_address_space'], 1)
            self.assertEqual(value['program_pointer'], dict(
                size_bits=64, index_bits=64, abi_alignment_bits=64,
                preferred_alignment_bits=64, null_bits=0,
                stable_representation=True, external_state=True))
        self.assertEqual(ADDRESS_SPACES, (0, 1))
        self.assertEqual(gate.validate_request(request), 'draft-request-only')
        schema_witness.validate(request, schema)
        for spaces in ([0], [False, 1], [0, True], [1, 0], [0, 0], [0, 2]):
            with self.subTest(spaces=spaces):
                bad = dict(request, address_spaces=spaces)
                with self.assertRaisesRegex(ValueError, 'E-ADDRESS-SPACE'):
                    gate.validate_request(bad)
                with self.assertRaises(schema_witness.SchemaError):
                    schema_witness.validate(bad, schema)
        with self.assertRaisesRegex(ValueError, 'E-COMPILER-NOT-FROZEN'):
            gate.validate_request(request, for_emission=True)

    def test_new_carriers_have_no_new_execution_or_storage_claim(self):
        rows = json.loads((PACKAGE / 'type-matrix.json').read_text())
        carrier = next(row for row in rows if row['name'] == 'TargetExtTyID')
        self.assertEqual(carrier['parameterless_names'], list(PARAMETERLESS_CARRIERS))
        self.assertFalse(carrier['implemented'])
        self.assertEqual(carrier['fallback_diagnostic'], 'E-TARGET-TYPE')
        config = json.loads((PACKAGE / 'frontend-contract.json').read_text())
        self.assertEqual(config['compiler_parameterless_carriers'], list(PARAMETERLESS_CARRIERS))
        cases = json.loads((FIXTURES / 'cases.json').read_text())['cases']
        self.assertEqual(len(cases), 11)
        self.assertTrue(all(row['portable_admission'] is False for row in cases))

    def test_blockaddress_keeps_existing_diagnostic_contract(self):
        self.assertEqual(constant_contract.POLICY['BlockAddress'],
                         ('optional', 'E-CONSTANT-BLOCK-ADDRESS'))
        rows = json.loads((PACKAGE / 'constant-matrix.json').read_text())['constants']
        row = next(row for row in rows if row['kind'] == 'BlockAddress')
        self.assertEqual(row['disposition'], 'optional')
        self.assertEqual(row['recipe'], 'E-CONSTANT-BLOCK-ADDRESS')

    def test_build_output_guard_precedes_tool_access(self):
        with self.assertRaisesRegex(builder.BuildError, 'outside both source'):
            builder.build('/nonexistent-llvm-checkout', ROOT / 'forbidden-program-space-output')
        llvm = Path('/nonexistent-llvm-checkout')
        with self.assertRaisesRegex(builder.BuildError, 'outside both source'):
            builder.build(llvm, llvm / 'forbidden-program-space-output')


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw_oracle = os.environ.get('SMIR_PROGRAM_SPACE_ORACLE')
        raw_receipt = os.environ.get('SMIR_PROGRAM_SPACE_BUILD_RECEIPT')
        if not raw_oracle or not raw_receipt:
            raise ValueError('actual SMIR_PROGRAM_SPACE_ORACLE and build receipt required; no skipped native tests')
        cls.oracle = Path(raw_oracle).resolve()
        receipt_path = Path(raw_receipt).resolve()
        cls.build_receipt = json.loads(receipt_path.read_text())
        build = cls.build_receipt
        if (build['format'] != 'llvm-program-space-reference-build-v1' or
                build['exit'] != 0 or build['timed_out'] or build['drift'] or
                build['llvm_pin'] != PIN or build['llvm_head_after'] != PIN or
                Path(build['binary']['path']).resolve() != cls.oracle or
                digest(cls.oracle) != build['binary']['sha256']):
            raise ValueError('actual native build receipt/binary mismatch')
        if (Path(build['source']).resolve() != (Path(__file__).parent / 'program_space_reader.cpp').resolve() or
                Path(build['builder']).resolve() != Path(builder.__file__).resolve()):
            raise ValueError('build must consume this actual installed/draft source, not transplanted sources')
        cls.guard = dict(build['input_hashes'])
        cls.guard[str(cls.oracle)] = digest(cls.oracle)
        cls.guard[str(receipt_path)] = digest(receipt_path)
        for path in [Path(__file__), *PACKAGE.glob('*.json'), *FIXTURES.iterdir()]:
            if path.is_file():
                cls.guard[str(path.resolve())] = digest(path)
        for path, sha in cls.guard.items():
            if digest(path) != sha:
                raise ValueError('native/source input changed: ' + path)
        directory = Path(os.environ.get('SMIR_PROGRAM_SPACE_ARTIFACTS', tempfile.gettempdir())).resolve()
        llvm = Path(os.environ.get('SMIR_LLVM_ROOT', '/Users/int/dev/llvm-project')).resolve()
        if directory.is_relative_to(ROOT) or directory.is_relative_to(llvm):
            raise ValueError('program-space artifacts must be outside both checkouts')
        directory.mkdir(parents=True, exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='program-space-', dir=directory))
        cls.rows = []

    @classmethod
    def tearDownClass(cls):
        drift = [path for path, sha in cls.guard.items() if digest(path) != sha]
        report = dict(scope='Actual pinned LLVM library structural checks only. Native freeze/BlockAddress acceptance is not portable semantic admission.',
                      llvm_pin=PIN, input_hashes=cls.guard, drift=drift, rows=cls.rows,
                      portable_admission=False, runtime_authority=False)
        (cls.artifacts / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Program-space artifacts:', cls.artifacts)
        if drift:
            raise AssertionError('program-space inputs changed: ' + repr(drift))

    def invoke(self, name, layout=DATALAYOUT):
        command = [str(self.oracle), str(FIXTURES / name), layout]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        row = dict(case=name, command=command, exit=result.returncode,
                   stdout=result.stdout, stderr=result.stderr)
        self.rows.append(row)
        return result

    def verified(self, name):
        result = self.invoke(name)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['pointer_bits'], 64)
        self.assertEqual(value['index_bits'], 64)
        self.assertEqual(value['abi_alignment_bytes'], 8)
        self.assertEqual(value['preferred_alignment_bytes'], 8)
        self.assertEqual(value['program_address_space'], 1)
        self.assertIs(value['external_state'], True)
        self.assertIs(value['unstable_representation'], False)
        self.assertIs(value['null_zero'], True)
        self.assertIs(value['code_binding_sized'], False)
        self.assertIs(value['source_scope_sized'], False)
        self.assertEqual(value['scope'], 'llvm_structural_only')
        return value

    def test_actual_geometry_transports_and_binding_group(self):
        for name in ['effects.ll', 'binding-group.ll', 'transport.ll']:
            with self.subTest(case=name):
                self.assertEqual(self.verified(name)['blockaddress_address_spaces'], [])

    def test_unsized_memory_vectors_and_cross_space_reject(self):
        cases = {'cross-as-phi.ll': 'defined with type', 'cross-as-eq.ll': 'defined with type',
                 'binding-memory.ll': 'Cannot allocate unsized type',
                 'scope-memory.ll': 'Cannot allocate unsized type',
                 'binding-vector.ll': 'invalid vector element type'}
        for name, diagnostic in cases.items():
            with self.subTest(case=name):
                result = self.invoke(name)
                self.assertIn(result.returncode, (2, 3), result.stderr)
                self.assertIn(diagnostic, result.stderr)

    def test_freeze_upstream_acceptance_is_not_portable_policy(self):
        for name in ['code_binding-freeze-structural-only.ll',
                     'source_scope-freeze-structural-only.ll']:
            with self.subTest(case=name):
                self.verified(name)

    def test_blockaddress_really_uses_program_space_but_keeps_label_domain(self):
        value = self.verified('blockaddress.ll')
        self.assertEqual(value['blockaddress_address_spaces'], [1])
        self.assertEqual(constant_contract.POLICY['BlockAddress'][1], 'E-CONSTANT-BLOCK-ADDRESS')

    def test_actual_reader_mismatch_and_missing_input_fail(self):
        result = self.invoke('transport.ll', DATALAYOUT.removesuffix('-pe1:64:64:64:64-P1'))
        self.assertEqual(result.returncode, 4)
        result = self.invoke('missing-not-a-case.ll')
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
