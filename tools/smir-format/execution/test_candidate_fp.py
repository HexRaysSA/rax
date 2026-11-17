"""Independent exact FP extension witnesses and conversion boundaries."""
from fractions import Fraction
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from common import ROOT
from floating import FORMATS, decode
from candidate.fp import compare, scalar, sqrt_finite


class CandidateFPTests(unittest.TestCase):
    def test_conversion_and_remainder_boundaries(self):
        for fmt, (exponent, fraction) in FORMATS.items():
            bias = (1 << (exponent - 1)) - 1
            one = bias << fraction
            infinity = ((1 << exponent) - 1) << fraction
            for operation, width, bits, expected in [
                    ('fptosi', 8, one, 1), ('fptoui', 8, one, 1),
                    ('fptosi_sat', 8, infinity, 127), ('fptoui_sat', 8, infinity, 255),
                    ('fptosi_sat', 8, infinity | (1 << (exponent + fraction)), 128),
                    ('fptoui_sat', 8, infinity | (1 << (exponent + fraction)), 0)]:
                self.assertEqual(scalar(operation, width, [fmt], [bits])[0], expected)
            self.assertEqual(scalar('fptosi', 8, [fmt], [infinity]), (None, {'invalid'}))
            self.assertEqual(scalar('fptoui_sat', 8, [fmt], [infinity | (1 << (fraction - 1))]), (0, set()))
            self.assertEqual(scalar('sitofp', fmt, [8], [255]), (one | (1 << (exponent + fraction)), set()))
            # sqrt(4)=2 exactly, all specified formats.
            self.assertEqual(scalar('sqrt', fmt, [fmt], [(bias + 2) << fraction]), ((bias + 1) << fraction, set()))
        self.assertEqual(scalar('frem', 'binary32', ['binary32', 'binary32'], [0xc0e00000, 0x40400000]), (0xbf800000, set()))
        self.assertEqual(scalar('fpconvert', 'binary16', ['binary32'], [0x3f800000]), (0x3c00, set()))
        self.assertEqual(scalar('fpconvert', 'binary128', ['binary64'], [0x3ff0000000000000]), (0x3fff << 112, set()))
        self.assertEqual(scalar('fptosi', 8, ['binary32'], [0xc3008000]), (128, {'inexact'}))
        self.assertEqual(scalar('fptosi', 8, ['binary32'], [0x43000000]), (None, {'invalid'}))
        self.assertEqual(scalar('fptoui', 8, ['binary32'], [0xbf000000]), (0, {'inexact'}))

    def test_sqrt_exact_midpoint_inequalities(self):
        # Independent criterion: exact output or adjacent representable numbers
        # bracket sqrt(x); nearest-even lies on correct side of squared midpoint.
        for fmt in ['binary16', 'bfloat16', 'binary32', 'binary64', 'binary128']:
            ebits, fbits = FORMATS[fmt]
            bias = (1 << (ebits - 1)) - 1
            for raw in [1, (1 << fbits) - 1, 1 << fbits, bias << fbits,
                        (bias << fbits) + 1, (bias + 1) << fbits, (((1 << ebits) - 1) << fbits) - 1]:
                value = decode(raw, ebits, fbits).value
                down, _ = sqrt_finite(value, ebits, fbits, 'downward')
                up, _ = sqrt_finite(value, ebits, fbits, 'upward')
                lower, upper = decode(down, ebits, fbits).value, decode(up, ebits, fbits).value
                self.assertLessEqual(lower * lower, value)
                self.assertGreaterEqual(upper * upper, value)
                self.assertLessEqual(up - down, 1)
                nearest, _ = sqrt_finite(value, ebits, fbits, 'nearest_even')
                midpoint_squared = ((lower + upper) / 2)**2
                self.assertEqual(nearest, down if value < midpoint_squared else up if value > midpoint_squared
                                 else down if down % 2 == 0 else up)

    def test_unordered_compare_and_signaling(self):
        nan, one = 0x7fc00001, 0x3f800000
        for predicate in ['ueq', 'une', 'ult', 'ule', 'ugt', 'uge', 'uno', 'true']:
            self.assertEqual(compare(predicate, False, 'binary32', nan, one), (1, set()))
        for predicate in ['oeq', 'one', 'olt', 'ole', 'ogt', 'oge', 'ord', 'false']:
            self.assertEqual(compare(predicate, False, 'binary32', nan, one), (0, set()))
        self.assertEqual(compare('oeq', True, 'binary32', nan, one), (0, {'invalid'}))
        self.assertEqual(compare('oeq', False, 'binary32', 0x7f800001, one), (0, {'invalid'}))

    def test_native_independent_sqrt_frem(self):
        rng = random.Random(0x53515254)
        with tempfile.TemporaryDirectory(prefix='rax-candidate-fp-') as temporary:
            probe = Path(temporary) / 'fp-probe'
            subprocess.run([os.environ.get('CXX', '/usr/bin/clang++'), '-std=c++20', '-O0',
                            '-frounding-math', '-ffp-contract=off', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'tools/smir-format/execution/candidate/fp_probe.cpp'), '-o', str(probe)], check=True)
            lines, expected = [], []
            for width, fmt in [(32, 'binary32'), (64, 'binary64')]:
                ebits, fbits = FORMATS[fmt]
                infinity = ((1 << ebits) - 1) << fbits
                for rounding in ['nearest_even', 'toward_zero', 'upward', 'downward']:
                    values = [0, 1, (1 << fbits) - 1, 1 << fbits, infinity - 1, infinity,
                              1 << (width - 1), 1 << (width - 2)]
                    values += [rng.getrandbits(width) for _ in range(300)]
                    for operation in ['sqrt', 'frem']:
                        for a in values:
                            b = rng.getrandbits(width)
                            formats, args = ([fmt], [a]) if operation == 'sqrt' else ([fmt, fmt], [a, b])
                            bits, flags = scalar(operation, fmt, formats, args, rounding)
                            if decode(bits, ebits, fbits).kind == 'nan':
                                continue
                            lines.append(f'{width} {operation} {rounding} {a:x} {b:x}')
                            expected.append((bits, sorted(flags)))
            output = subprocess.run([str(probe)], input='\n'.join(lines) + '\n', capture_output=True,
                                    text=True, check=True).stdout.splitlines()
            self.assertEqual(len(output), len(expected))
            for line, native, wanted in zip(lines, output, expected):
                bits, flags = native.split(' ', 1)
                self.assertEqual((int(bits, 16), [flag for flag in flags.split(',') if flag]), wanted, line)
            print(f'Candidate FP independent native sqrt/frem:{len(expected)} cases;4 rounding modes;'
                  'seed0x53515254;NaN result policy excluded, no skipped tests')
