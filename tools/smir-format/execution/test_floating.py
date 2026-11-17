"""Exact draft FP fixtures and independent native strict-FP comparison."""
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from common import ROOT, SPEC, Reject
from floating import ARITY, FORMATS, ROUNDING, decode, evaluate


def request(format_name, op, operands, rounding='nearest_even', mode='constrained'):
    return {'revision': 'binary_fp_draft_v1', 'format': format_name, 'op': op,
            'operands': operands, 'mode': mode, 'rounding': rounding,
            'environment': {'rounding': 'nearest_even', 'flags': [], 'traps': []}}


class FloatingTests(unittest.TestCase):
    def test_schema_contract_matches_reference_request_surface(self):
        schema = json.loads((SPEC / 'schema/execution/floating.json').read_text())
        self.assertEqual(set(schema['fields']['format']['enum']), set(FORMATS))
        self.assertEqual(schema['fields']['op']['arity'], ARITY)
        self.assertEqual(set(schema['fields']['rounding']['enum']), ROUNDING | {'dynamic'})

    def test_checked_in_fixtures(self):
        document = json.loads((SPEC / 'conformance/execution/floating.json').read_text())
        accepted = rejected = 0
        for case in document['cases']:
            with self.subTest(case=case['name']):
                if 'reject' in case:
                    with self.assertRaises(Reject) as error:
                        evaluate(case['request'])
                    self.assertEqual(error.exception.code, case['reject'])
                    rejected += 1
                else:
                    self.assertEqual(evaluate(case['request']), case['expected'])
                    accepted += 1
        print(f'FP fixtures: {accepted} accepted, {rejected} rejected; no skips')

    def test_all_formats_exact_identities(self):
        cases = 0
        for name, (exponent_bits, fraction_bits) in FORMATS.items():
            width = 1 + exponent_bits + fraction_bits
            size = width // 8
            bias = (1 << (exponent_bits - 1)) - 1
            one = bias << fraction_bits
            to_hex = lambda value: value.to_bytes(size, 'little').hex()
            for value in [0, 1, (1 << fraction_bits) - 1, 1 << fraction_bits,
                          one, one - 1, one + 1, ((1 << exponent_bits) - 1) << fraction_bits]:
                for sign in [0, 1 << (width - 1)]:
                    bits = value | sign
                    result = evaluate(request(name, 'mul', [to_hex(bits), to_hex(one)]))
                    self.assertEqual(result, {'bits': to_hex(bits), 'flags': []})
                    cases += 1
        self.assertEqual(cases, 80)

    def test_dynamic_rounding_sticky_flags_and_default_isolation(self):
        document = request('binary32', 'add', ['0000803f', '00008033'], 'dynamic')
        document['environment'] = {'rounding': 'upward', 'flags': ['invalid'], 'traps': []}
        self.assertEqual(evaluate(document), {'bits': '0100803f', 'flags': ['inexact', 'invalid']})
        document.update(mode='default', rounding='nearest_even')
        self.assertEqual(evaluate(document), {'bits': '0000803f', 'flags': ['invalid']})

    def test_independent_strict_native_fp(self):
        rng = random.Random(0x4650534d)
        with tempfile.TemporaryDirectory(prefix='rax-smir-fp-') as temporary:
            probe = Path(temporary) / 'fp-probe'
            subprocess.run([os.environ.get('CXX', '/usr/bin/clang++'), '-std=c++20',
                            '-O0', '-frounding-math', '-ffp-contract=off', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'tools/smir-format/execution/fp_probe.cpp'), '-o', str(probe)], check=True)
            lines, expected, before_rounding = [], [], []
            for width, name in [(32, 'binary32'), (64, 'binary64')]:
                exponent_bits, fraction_bits = FORMATS[name]
                infinity = ((1 << exponent_bits) - 1) << fraction_bits
                bias = (1 << (exponent_bits - 1)) - 1
                one = bias << fraction_bits
                values = [0, 1 << (width - 1), 1, (1 << fraction_bits) - 1,
                          1 << fraction_bits, one, one - 1, one + 1, infinity - 1, infinity]
                values += [value | (1 << (width - 1)) for value in values[2:]]
                for rounding in ['nearest_even', 'toward_zero', 'upward', 'downward']:
                    for op in ['add', 'sub', 'mul', 'div', 'fma']:
                        operands = [(a, b, one) for a in values for b in values]
                        operands += [tuple(rng.getrandbits(width) for _ in range(3)) for _ in range(250)]
                        for a, b, c in operands:
                            raw = [value.to_bytes(width // 8, 'little').hex() for value in (a, b, c)]
                            result = evaluate(request(name, op, raw if op == 'fma' else raw[:2], rounding))
                            bits = int.from_bytes(bytes.fromhex(result['bits']), 'little')
                            # The host's NaN payload/sign selection is permitted
                            # to differ. Exact NaN policy has explicit fixtures.
                            if decode(bits, exponent_bits, fraction_bits).kind == 'nan':
                                continue
                            lines.append(f'{width} {op} {rounding} {a:x} {b:x} {c:x}')
                            expected.append((bits, result['flags']))
                            operands_decoded = [decode(value, exponent_bits, fraction_bits)
                                                for value in (a, b, c)]
                            tiny_before = False
                            if all(value.kind == 'finite' for value in operands_decoded):
                                av, bv, cv = [value.value for value in operands_decoded]
                                exact = (av + bv if op == 'add' else av - bv if op == 'sub' else
                                         av * bv if op == 'mul' else av / bv if op == 'div' and bv else
                                         av * bv + cv if op == 'fma' else 0)
                                minimum_normal = decode(1 << fraction_bits, exponent_bits, fraction_bits).value
                                tiny_before = (0 < abs(exact) < minimum_normal and 'inexact' in result['flags']
                                               and 'underflow' not in result['flags'])
                            before_rounding.append(tiny_before)
            result = subprocess.run([str(probe)], input='\n'.join(lines) + '\n',
                                    text=True, capture_output=True, check=True)
            output = result.stdout.splitlines()
            self.assertEqual(len(output), len(expected))
            tininess_differences = 0
            for line, result, (bits, flags), tiny_before in zip(lines, output, expected, before_rounding):
                raw_bits, raw_flags = result.split(' ', 1)
                native_flags = [flag for flag in raw_flags.split(',') if flag]
                self.assertEqual(int(raw_bits, 16), bits, line)
                if tiny_before and native_flags == sorted(flags + ['underflow']):
                    tininess_differences += 1
                else:
                    self.assertEqual(native_flags, flags, line)
            print(f'Native strict-FP witness: {len(expected)} cases, binary32/64, 4 rounding modes, '
                  f'seed 0x4650534d; {tininess_differences} explicit host tininess-before differences; '
                  'NaN result comparison excluded, no skipped tests. This is not full portable fenv parity.')


if __name__ == '__main__':
    unittest.main()
