"""Single-frontier FP integer-round and executed-step integer-power contracts."""
from fractions import Fraction
import unittest

from floating import FORMATS, round_finite
from candidate.fp import integer_round, powi


class CandidateFPHelperTests(unittest.TestCase):
    def test_integer_round_invalid_suppresses_intermediate_inexact(self):
        for fmt, (ebits, fbits) in FORMATS.items():
            encode = lambda value: round_finite(Fraction(value), 0, ebits, fbits, 'nearest_even')[0]
            for op in ['lrint', 'llrint', 'lround', 'llround']:
                self.assertEqual(integer_round(op, fmt, encode(Fraction(255, 2)), 8), (0, {'invalid'}))
                inf = ((1 << ebits) - 1) << fbits
                for value in [inf, inf | (1 << (fbits - 1)), inf | 1]:
                    self.assertEqual(integer_round(op, fmt, value, 64), (0, {'invalid'}))
            for mode, expected in [('nearest_even', 2), ('nearest_away', 2), ('upward', 2),
                                   ('downward', 1), ('toward_zero', 1)]:
                self.assertEqual(integer_round('lrint', fmt, encode(Fraction(3, 2)), 8, mode), (expected, {'inexact'}))
                self.assertEqual(integer_round('lround', fmt, encode(Fraction(3, 2)), 8, mode), (2, set()))
            self.assertEqual(integer_round('lrint', fmt, encode(Fraction(5, 2)), 8), (2, {'inexact'}))
            self.assertEqual(integer_round('lround', fmt, encode(Fraction(-5, 2)), 8), (253, set()))

    def test_powi_only_executed_steps_and_full_signed_width(self):
        for fmt, (ebits, fbits) in FORMATS.items():
            one = ((1 << (ebits - 1)) - 1) << fbits
            largest = (((1 << ebits) - 1) << fbits) - 1
            snan = (((1 << ebits) - 1) << fbits) | 1
            self.assertEqual(powi(fmt, snan, 0, 32), (one, set(), []))
            self.assertEqual(powi(fmt, largest, 1, 32), (largest, set(), ['multiply']))
            minus_one = one | (1 << (ebits + fbits))
            for width in [1, 8, 32, 64, 129, 513]:
                bits, flags, steps = powi(fmt, minus_one, 1 << (width - 1), width)
                self.assertEqual((bits, flags), (minus_one if width == 1 else one, set()))
                self.assertEqual(steps[-1], 'reciprocal')
                self.assertEqual(steps.count('square'), width - 1)
            self.assertEqual(powi(fmt, 0, (1 << 32) - 1, 32)[1], {'divide_by_zero'})


if __name__ == '__main__':
    unittest.main()
