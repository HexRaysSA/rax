"""Focused first-wave witnesses. Missing LLVM executables fail, never skip."""
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import gate
import inventory
import schema_witness
from policy import DATALAYOUT, INSTRUCTION_RULES, PIN, RULES, TRIPLE
from reference import (
    ContractError, ImmediateUB, Value, binary, branch, layout, llvm_type, select,
)

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'docs/specifications/smir/portable/llvm'
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm'
LLVM = Path(os.environ.get('SMIR_LLVM_ROOT', '/Users/int/dev/llvm-project'))
BIN = Path(os.environ.get('SMIR_LLVM_BIN', str(LLVM / 'build/bin')))


def run(argv):
    result = subprocess.run([str(a) for a in argv], text=True, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(f'{argv!r}: exit {result.returncode}\n{result.stderr}')
    return result.stdout


def fixture_value(width, value):
    return Value(width, kind=value) if isinstance(value, str) else Value(width, value)


class MathematicalWitnesses(unittest.TestCase):
    def test_curated_arithmetic(self):
        cases = json.loads((FIXTURES / 'refinement.json').read_text())['binary']
        self.assertEqual(len(cases), 26)
        for case in cases:
            with self.subTest(case=case):
                a = fixture_value(case['width'], case['a'])
                b = fixture_value(case['width'], case['b'])
                expected = case['expected']
                if 'trap' in expected:
                    with self.assertRaisesRegex(ImmediateUB, expected['trap']):
                        binary(case['op'], a, b, case.get('flags', ()))
                else:
                    actual = binary(case['op'], a, b, case.get('flags', ()))
                    self.assertEqual(actual.kind, expected['kind'])
                    self.assertEqual(actual.bits, expected['bits'])

    def test_integer_width_boundaries(self):
        for width in (1, 2, 7, 8, 16, 32, 64, 65, 127, 128, 65535):
            with self.subTest(width=width):
                maximum = (1 << width) - 1
                self.assertEqual(binary('add', Value(width, maximum), Value(width, 1)), Value(width))
                self.assertEqual(binary('sub', Value(width), Value(width, 1)), Value(width, maximum))
                self.assertEqual(binary('mul', Value(width, maximum), Value(width, maximum)), Value(width, 1))

    def test_exhaustive_i8_division_identity(self):
        # Independent signed arithmetic: Python modulo obeys a different sign
        # rule, so compare mathematical quotient/remainder identities instead.
        count = 0
        for a in range(-128, 128):
            for b in range(-128, 128):
                if b == 0 or (a == -128 and b == -1):
                    continue
                left, right = Value(8, a & 255), Value(8, b & 255)
                q = binary('sdiv', left, right).signed
                r = binary('srem', left, right).signed
                self.assertEqual(a, q * b + r)
                self.assertLess(abs(r), abs(b))
                self.assertTrue(r == 0 or (r < 0) == (a < 0))
                count += 1
        self.assertEqual(count, 65279)

    def test_poison_select_barrier(self):
        self.assertEqual(select(Value(1), Value(8, kind='poison'), Value(8, 9)), Value(8, 9))
        self.assertEqual(select(Value(1, 1), Value(8, 9), Value(8, kind='poison')), Value(8, 9))
        self.assertEqual(select(Value(1, kind='poison'), Value(8, 9), Value(8, 9)).kind, 'poison')

    def test_freeze_preserves_components_and_identity(self):
        elements = [Value(8, 37), Value(8, kind='poison'), Value(8, kind='undef')]
        frozen = [element.freeze() for element in elements]
        self.assertEqual(frozen, [Value(8, 37), Value(8), Value(8)])
        self.assertEqual(binary('xor', frozen[0], frozen[0]), Value(8))

    def test_branch_ub_is_execution_local(self):
        for kind in ('poison', 'undef'):
            with self.assertRaisesRegex(ImmediateUB, 'UB-BRANCH'):
                branch(Value(1, kind=kind))
        self.assertFalse(branch(Value(1)))
        self.assertTrue(branch(Value(1, 1)))

    def test_invalid_flags_and_types_reject(self):
        for op, flags in (('srem', ['exact']), ('add', ['exact']), ('mul', ['nuw', 'nuw'])):
            with self.assertRaisesRegex(ContractError, 'E-OP-FLAGS'):
                binary(op, Value(8), Value(8, 1), flags)
        with self.assertRaisesRegex(ContractError, 'E-TYPE'):
            binary('add', Value(8), Value(16))
        for width in (0, -1, 65536, True):
            with self.assertRaises(ContractError):
                Value(width)
        with self.assertRaises(ContractError):
            Value(8, 256)

    def test_curated_layouts(self):
        cases = json.loads((FIXTURES / 'layout.json').read_text())['cases']
        self.assertEqual(len(cases), 18)
        for case in cases:
            with self.subTest(case=case['name']):
                self.assertEqual(layout(case['type']), (case['size'], case['align'], case['offsets']))

    def test_layout_rejections(self):
        cases = ({'int': 0}, {'float': 80}, {'ptr': 1}, {'byte': 32},
                 {'array': [-1, {'int': 8}]}, {'vector': [0, {'int': 8}]},
                 {'scalable': [4, {'int': 32}]}, {'struct': 'bad'}, {'int': True},
                 {'vector': [3, 7]},
                 {'array': [4294967295, {'array': [4294967295, {'int': 128}]}]})
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ContractError):
                layout(case)


class ContractMatrices(unittest.TestCase):
    def test_instruction_universe_and_coverage(self):
        rows = json.loads((PACKAGE / 'instruction-matrix.json').read_text())
        self.assertEqual(rows, inventory.instructions(LLVM))
        self.assertEqual(len(rows), 69)
        self.assertEqual(len({row['opcode'] for row in rows}), len(rows))
        for row in rows:
            self.assertIn(row['rule'], RULES)
            self.assertFalse(row['implemented'])
        self.assertTrue({'PtrToAddr', 'UncondBr', 'CondBr'} <= {r['name'] for r in rows})

    def test_complete_type_universe(self):
        rows = json.loads((PACKAGE / 'type-matrix.json').read_text())
        self.assertEqual(rows, inventory.types(LLVM))
        self.assertEqual(len(rows), 22)
        lookup = {row['name']: row for row in rows}
        self.assertEqual(lookup['ByteTyID']['rule'], 'raw_shadow')
        self.assertEqual(lookup['ScalableVectorTyID']['rule'], 'E-SCALABLE-TYPE')

    def test_instruction_policy_rejects_unknown_and_duplicate(self):
        original = dict(INSTRUCTION_RULES)
        try:
            INSTRUCTION_RULES['unknown'] = 'UninventedOpcode'
            with self.assertRaisesRegex(ValueError, 'policy drift'):
                inventory.instructions(LLVM)
            INSTRUCTION_RULES['unknown'] = 'Ret'
            with self.assertRaisesRegex(ValueError, 'duplicate instruction'):
                inventory.instructions(LLVM)
        finally:
            INSTRUCTION_RULES.clear()
            INSTRUCTION_RULES.update(original)

    def test_full_tablegen_regeneration(self):
        outputs = inventory.generate(LLVM, BIN / 'llvm-tblgen')
        self.assertEqual(len(outputs), 12)
        for name, generated in outputs.items():
            with self.subTest(name=name):
                self.assertEqual((PACKAGE / name).read_text(), generated)

    def test_intrinsic_and_attribute_fail_closed(self):
        rows = list(csv.DictReader(io.StringIO((PACKAGE / 'intrinsic-matrix.tsv').read_text()), delimiter='\t'))
        self.assertEqual(len(rows), 16601)
        self.assertEqual(len({r['record'] for r in rows}), 16601)
        for row in rows:
            self.assertEqual(row['implemented'], 'false')
            if row['target']:
                self.assertEqual(row['diagnostic'], 'E-TARGET-INTRINSIC')
            if row['disposition'] == 'diagnostic':
                self.assertTrue(row['diagnostic'].startswith('E-'))
        attrs = json.loads((PACKAGE / 'attribute-matrix.json').read_text())
        self.assertEqual(len(attrs), 115)
        self.assertEqual(len({r['record'] for r in attrs}), 115)
        by_name = {r['name']: r for r in attrs}
        for name in ('byval', 'sret', 'inalloca', 'strictfp', 'noundef', 'returns_twice'):
            self.assertNotEqual(by_name[name]['disposition'], 'diagnostic')

    def test_source_manifest_hashes(self):
        manifest = json.loads((PACKAGE / 'sources.json').read_text())
        self.assertEqual(manifest['revision'], PIN)
        self.assertGreater(len(manifest['files']), 60)
        for entry in manifest['files']:
            self.assertEqual(hashlib.sha256((LLVM / entry['path']).read_bytes()).hexdigest(), entry['sha256'])

    def test_target_wide_character_and_atomic_promises(self):
        target = json.loads((PACKAGE / 'target.json').read_text())
        self.assertEqual(target['wint_t_bits'], 32)
        self.assertIs(target['wint_t_signed'], False)
        self.assertEqual(target['weof'], 0xffffffff)
        # Unicode scalar range, including both sides of the surrogate gap,
        # is representable and disjoint from the end-of-file sentinel.
        for scalar in (0, 0xd7ff, 0xe000, 0x10ffff):
            self.assertLess(scalar, target['weof'])
        self.assertNotIn('frozen',target)
        self.assertFalse(target['implemented'])

    def test_upstream_status_separate_from_port_gaps(self):
        gaps = json.loads((PACKAGE / 'upstream-gaps.json').read_text())
        self.assertGreater(gaps['c23']['status_rows'], 50)
        self.assertGreater(len(gaps['c23']['gaps']), 0)
        self.assertGreater(len(gaps['cxx23']['gaps']), 0)
        self.assertGreater(len(gaps['libcxx_cxx23']), 0)
        papers = str(gaps['libcxx_cxx23'])
        self.assertIn('P0881R7', papers)
        self.assertIn('P0533R9', papers)


class RequestGate(unittest.TestCase):
    def setUp(self):
        self.base = json.loads((FIXTURES / 'request.json').read_text())['base']

    def test_all_personality_carrier_combinations(self):
        for personality in ('linux', 'darwin', 'windows'):
            for carrier in ('elf', 'macho', 'pe'):
                request = dict(self.base, personality=personality, carrier=carrier)
                self.assertEqual(gate.validate_request(request), 'draft-request-only')

    def test_curated_request_rejections(self):
        fixture = json.loads((FIXTURES / 'request.json').read_text())
        for case in fixture['reject']:
            with self.subTest(name=case['name']):
                request = dict(self.base, **case['replace'])
                with self.assertRaisesRegex(ContractError, case['error']):
                    gate.validate_request(request)

    def test_independent_request_schema(self):
        schema = json.loads((PACKAGE / 'request.schema.json').read_text())
        self.assertEqual(set(schema['required']), gate.FIELDS)
        self.assertEqual(schema['properties']['datalayout']['const'], DATALAYOUT)
        schema_witness.validate(self.base, schema)
        fixture = json.loads((FIXTURES / 'request.json').read_text())
        for case in fixture['reject']:
            request = dict(self.base, **case['replace'])
            with self.subTest(case=case['name']), self.assertRaises(schema_witness.SchemaError):
                schema_witness.validate(request, schema)
        for field in self.base:
            request = dict(self.base)
            del request[field]
            with self.subTest(missing=field), self.assertRaises(schema_witness.SchemaError):
                schema_witness.validate(request, schema)
        with self.assertRaises(schema_witness.SchemaError):
            schema_witness.validate(dict(self.base, address_spaces=[False]), schema)
        with self.assertRaises(schema_witness.SchemaError):
            schema_witness.validate(self.base, dict(schema, unknownValidationKeyword=True))

    def test_no_emission_even_from_valid_request(self):
        with self.assertRaisesRegex(ContractError, 'E-COMPILER-NOT-FROZEN'):
            gate.validate_request(self.base, for_emission=True)
        request = dict(self.base, compiler_freeze_passed=True)
        with self.assertRaisesRegex(ContractError, 'E-REQUEST-SCHEMA'):
            gate.validate_request(request)

    def test_exact_request_fields_and_types(self):
        for field in self.base:
            request = copy.deepcopy(self.base)
            del request[field]
            with self.subTest(field=field), self.assertRaisesRegex(ContractError, 'E-REQUEST-SCHEMA'):
                gate.validate_request(request)
        for field, value in (('inline_asm', 0), ('address_spaces', [False]),
                             ('operand_bundles', ''), ('module_flags', [])):
            with self.subTest(field=field), self.assertRaises(ContractError):
                gate.validate_request(dict(self.base, **{field: value}))


class LLVMPrimaryWitnesses(unittest.TestCase):
    def test_compiler_and_source_identity(self):
        head = run(['git', '-C', LLVM, 'rev-parse', 'HEAD']).strip()
        self.assertEqual(head, PIN)
        version = run([BIN / 'clang', '--version'])
        self.assertIn(PIN, version)
        self.assertIn('24.0.0git', version)
        self.assertIn('LLVM version', run([BIN / 'opt', '--version']))
        self.assertIn('24.0.0git', run([BIN / 'llvm-tblgen', '--version']))

    def test_pinned_clang_and_independent_opt_refinement_folds(self):
        expected = {'unused_poison': 7, 'unselected_poison': 9, 'freeze_identity': 0,
                    'signed_remainder': -1, 'signed_quotient': -2, 'wrap_add': 0,
                    'overshift_is_deferred': 11, 'lane_poison_barrier': 13,
                    'unselected_undef': 17, 'exact_is_deferred': 19}
        commands = [
            [BIN / 'opt', '-passes=verify,instcombine,verify', '-S',
             FIXTURES / 'refinement.ll', '-o', '-'],
            [BIN / 'clang', '-x', 'ir', '-O1', '-S', '-emit-llvm',
             FIXTURES / 'refinement.ll', '-o', '-'],
        ]
        for argv in commands:
            with self.subTest(executable=str(argv[0])):
                output = run(argv)
                actual = {}
                for name, body in re.findall(r'define [^@]*@(\w+)\([^)]*\)[^{]*\{(.*?)\n\}', output, re.S):
                    matches = re.findall(r'ret i8 (-?\d+)', body)
                    self.assertEqual(len(matches), 1, body)
                    actual[name] = int(matches[0])
                self.assertEqual(actual, expected)

    def test_independent_llvm_datalayout(self):
        cases = json.loads((FIXTURES / 'layout.json').read_text())['cases']
        lines = [f'target datalayout = "{DATALAYOUT}"']
        expected = {}
        for case in cases:
            ty = llvm_type(case['type'])
            name = case['name']
            lines.extend([f'define i64 @size_{name}() {{',
                          f'  %end = getelementptr {ty}, ptr null, i64 1',
                          '  %size = ptrtoint ptr %end to i64', '  ret i64 %size', '}'])
            expected['size_' + name] = case['size']
            lines.extend([f'define i64 @align_{name}() {{',
                          f'  %field = getelementptr {{i8, {ty}}}, ptr null, i64 0, i32 1',
                          '  %align = ptrtoint ptr %field to i64', '  ret i64 %align', '}'])
            expected['align_' + name] = case['align']
            for index, offset in enumerate(case['offsets']):
                lines.extend([f'define i64 @offset_{name}_{index}() {{',
                              f'  %field = getelementptr {ty}, ptr null, i64 0, i32 {index}',
                              '  %offset = ptrtoint ptr %field to i64', '  ret i64 %offset', '}'])
                expected[f'offset_{name}_{index}'] = offset
        with tempfile.TemporaryDirectory(prefix='smir-llvm-layout-') as directory:
            source = Path(directory) / 'layout.ll'
            source.write_text('\n'.join(lines) + '\n')
            output = run([BIN / 'opt', '-passes=verify,instcombine,verify', '-S', source, '-o', '-'])
        self.assertIn(f'target datalayout = \"{DATALAYOUT}\"', output)
        actual = {}
        for name, body in re.findall(r'define i64 @(\w+)\([^)]*\)[^{]*\{(.*?)\n\}', output, re.S):
            matches = re.findall(r'ret i64 (-?\d+)', body)
            self.assertEqual(len(matches), 1, body)
            actual[name] = int(matches[0])
        self.assertEqual(actual, expected)

    def test_clang_existing_abi_language_and_layout_witnesses(self):
        for language, name in (('c23', 'frontend.c'), ('c++23', 'frontend.cpp')):
            with self.subTest(language=language):
                output = run([BIN / 'clang', '-target', 'x86_64-unknown-linux-gnu', '-mlong-double-128',
                              '-std=' + language, '-ffreestanding', '-nostdinc',
                              '-S', '-emit-llvm', FIXTURES / name, '-o', '-'])
                self.assertIn('target triple = "x86_64-unknown-linux-gnu"', output)
                self.assertIn('ret i32', output)
                if name.endswith('.c'):
                    self.assertIn('i65', output)

    def test_clang_bitint_ast_storage_and_access_geometry(self):
        output = run([BIN / 'clang', '-target', 'x86_64-unknown-linux-gnu',
                      '-mlong-double-128', '-std=c23', '-ffreestanding', '-nostdinc',
                      '-S', '-emit-llvm', FIXTURES / 'frontend.c', '-o', '-'])
        definition = re.search(r'^%struct.CharBit65 = type (.+)$', output, re.M)
        self.assertIsNotNone(definition)
        self.assertEqual(definition.group(1), '<{ i8, [7 x i8], i128 }>')
        self.assertRegex(output, r'@clang_storage = [^\n]+align 8')
        self.assertRegex(output, r'load i128, ptr getelementptr [^\n]*@clang_storage, i64 8\), align 8')
        # Use only the emitted memory type in an independent synthetic layout
        # query, with the candidate layout. No host-compiled function is retargeted.
        source = f'''target datalayout = "{DATALAYOUT}"
%struct.CharBit65 = type {definition.group(1)}
define i64 @storage_size() {{
  %p = getelementptr %struct.CharBit65, ptr null, i64 1
  %n = ptrtoint ptr %p to i64
  ret i64 %n
}}
define i64 @field_offset() {{
  %p = getelementptr %struct.CharBit65, ptr null, i64 0, i32 2
  %n = ptrtoint ptr %p to i64
  ret i64 %n
}}
'''
        with tempfile.TemporaryDirectory(prefix='smir-storage-') as directory:
            path = Path(directory) / 'storage.ll'
            path.write_text(source)
            folded = run([BIN / 'opt', '-passes=verify,instcombine,verify', '-S', path, '-o', '-'])
        self.assertIn('ret i64 24', folded)
        self.assertIn('ret i64 8', folded)

    def test_smir_frontend_is_observed_unimplemented(self):
        result = subprocess.run([str(BIN / 'clang'), '-target', TRIPLE, '-std=c23',
                                 '-ffreestanding', '-nostdinc', '-fsyntax-only',
                                 str(FIXTURES / 'frontend.c')], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, 'unknown target triple|unknown target')


if __name__ == '__main__':
    unittest.main()
