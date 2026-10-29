"""Strategic checks for the primary decode slicer and exact cube compression."""
import unittest

from a64_fpsimd_allocation import compress
from asl_decode_allocation import enumerate_encoding


def variable(name):
    return {'Var': {'qualifier': 'Any', 'name': name}}


def binary(op, left, right):
    return {'Binary': {'op': op, 'lhs': left, 'rhs': right}}


def encoding(statements, width=2):
    return dict(name='allocation_probe', fields=[dict(name='field', begin=0, width=width)],
                opcode=['Zero'] * (32 - width) + ['Either'] * width, decode=statements)


class StructuralDerivation(unittest.TestCase):
    def test_reaching_assignments_and_mask_case_preserve_rejection(self):
        row = encoding([
            {'VarsDecl': {'ty': {}, 'names': ['size']}},
            {'Case': {'expr': variable('field'), 'alts': [
                dict(patterns=[{'Bits': [False, False]}], guard=None,
                     body=[{'Assign': {'target': variable('size'), 'value': {'LitInt': 7}}}]),
                dict(patterns=None, guard=None,
                     body=[{'Assign': {'target': variable('size'), 'value': {'LitInt': 8}}}]),
            ]}},
            {'If': {'branches': [[binary('Eq', variable('size'), {'LitInt': 7}), ['Undefined']]],
                    'else_body': None}},
        ])
        derived = enumerate_encoding(row)
        self.assertEqual(derived['needed'], ['field'])
        self.assertEqual(derived['accepted'], [1, 2, 3])

    def test_runtime_dependent_rejection_fails_generation(self):
        row = encoding([{'If': {'branches': [[variable('FPCR'), ['Undefined']]], 'else_body': None}}])
        with self.assertRaisesRegex(ValueError, 'runtime/unknown dependency'):
            enumerate_encoding(row)

    def test_uninitialized_reaching_value_has_no_implicit_zero(self):
        row = encoding([
            {'VarsDecl': {'ty': {}, 'names': ['size']}},
            {'If': {'branches': [[binary('Eq', variable('size'), {'LitInt': 0}), ['Undefined']]],
                    'else_body': None}},
        ])
        with self.assertRaises(ValueError):
            enumerate_encoding(row)

    def test_unknown_dependent_feature_fails_generation(self):
        call = {'Call': {'name': {'qualifier': 'Any', 'name': 'HaveUnqualifiedExt'}, 'args': []}}
        row = encoding([{'If': {'branches': [[call, ['Undefined']]], 'else_body': None}}])
        with self.assertRaisesRegex(ValueError, 'dependent function'):
            enumerate_encoding(row)

    def test_redirect_does_not_allocate_the_current_encoding(self):
        self.assertEqual(enumerate_encoding(encoding([{'See': 'other_encoding'}]))['accepted'], [])

    def test_uncovered_case_is_an_error_not_success(self):
        row = encoding([{'Case': {'expr': variable('field'), 'alts': [
            dict(patterns=[{'Bits': [False, False]}], guard=None, body=['Undefined']),
        ]}}])
        with self.assertRaisesRegex(ValueError, 'uncovered case input'):
            enumerate_encoding(row)

    def test_dead_runtime_calculations_do_not_enter_allocation(self):
        row = encoding([{'VarDeclInit': {'name': 'unused', 'ty': {}, 'value': variable('FPCR')}}])
        derived = enumerate_encoding(row)
        self.assertEqual(derived['needed'], [])
        self.assertEqual(derived['positions'], [])
        # No dependent field needs enumeration; the resulting cube must still
        # accept every value of the two irrelevant instruction bits.
        cubes = compress(derived['mask'], derived['accepted'])
        for value in range(4):
            self.assertTrue(any(value & mask == word for mask, word in cubes))

    def test_cube_merges_never_admit_the_excluded_corner(self):
        for accepted in ([0, 3, 5, 6], list(range(7)), list(range(8)), []):
            cubes = compress(7, accepted)
            for value in range(8):
                self.assertEqual(any(value & mask == word for mask, word in cubes), value in accepted)


if __name__ == '__main__':
    unittest.main()
