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


def bitmask_encoding(result_width=64, immediate=True):
    field = variable('field')
    index = lambda bit: {'Index': {'base': field, 'indices': [
        {'Single': {'LitInt': bit}}]}}
    part = lambda high, low: {'Slice': {'base': field, 'slices': [
        {'Range': {'hi': {'LitInt': high}, 'lo': {'LitInt': low}}}]}}
    return encoding([
        {'VarsDecl': {'ty': {'Fun': {'name': 'bits', 'arg': {'LitInt': result_width}}},
                      'names': ['mask']}},
        {'Assign': {'target': {'Tuple': [variable('mask'), 'Ignore']},
                    'value': {'Call': {'name': {'qualifier': 'Any', 'name': 'DecodeBitMasks'},
                                      'args': [index(12), part(5, 0), part(11, 6),
                                               variable('TRUE' if immediate else 'FALSE')]}}}},
    ], width=13)


class StructuralDerivation(unittest.TestCase):
    def test_constant_features_do_not_become_instruction_bit_fields(self):
        row = encoding([{'If': {'branches': [[
            binary('And', variable('future_feature'), variable('current_feature')),
            ['Undefined']]], 'else_body': None}}])
        derived = enumerate_encoding(row, constants={'future_feature': False},
                                     parameters={'current_feature': (32, 1)})
        self.assertEqual(derived['positions'], [32])
        self.assertEqual(derived['accepted'], [0, 1 << 32])

    def test_mask_membership_keeps_every_reserved_size(self):
        membership = {'InSet': {'expr': variable('field'), 'elements': [
            {'Single': {'LitMask': ['Zero', 'Either']}}]}}
        row = encoding([{'If': {'branches': [[membership, ['Undefined']]],
                                'else_body': None}}])
        derived = enumerate_encoding(row)
        self.assertEqual(derived['accepted'], [2, 3])

    def test_unknown_set_element_does_not_silently_drop_a_constraint(self):
        membership = {'InSet': {'expr': variable('field'), 'elements': [
            {'Range': {'lo': {'LitInt': 0}, 'hi': {'LitInt': 1}}}]}}
        row = encoding([{'If': {'branches': [[membership, ['Undefined']]],
                                'else_body': None}}])
        with self.assertRaisesRegex(ValueError, 'unqualified set element'):
            enumerate_encoding(row)

    def test_feature_bits_above_bit_31_survive_cube_compression(self):
        required = (1 << 45) | (1 << 32)
        cubes = compress(required | 3, [required | n for n in range(3)], bits=64)
        for features in (0, 1 << 32, 1 << 45, required):
            for field in range(4):
                word = features | field
                self.assertEqual(any(word & mask == value for mask, value in cubes),
                                 features == required and field != 3)

    def test_boolean_parameter_layout_rejects_overlap_and_non_boolean_width(self):
        for parameters in ({'a': (31, 1)}, {'a': (32, 2)},
                           {'a': (32, 1), 'b': (32, 1)}):
            with self.assertRaisesRegex(ValueError, 'Boolean parameter layout'):
                enumerate_encoding(encoding([]), parameters=parameters)

    def test_unused_bitmask_tuple_retains_intrinsic_decode_rejection(self):
        row = bitmask_encoding()
        derived = enumerate_encoding(row)
        # Arm's 13-bit logical-immediate field has 7,680 allocated patterns.
        # LLVM/QEMU anchors: N=0, imms=48 is legal; imms=63 is reserved
        # for either N value, and imms=62 with N=0 has no legal element size.
        self.assertEqual(derived['assignments'], 8192)
        self.assertEqual(len(derived['accepted']), 7680)
        accepted = set(derived['accepted'])
        for rotation in range(64):
            self.assertIn(48 | (rotation << 6), accepted)
            self.assertNotIn(63 | (rotation << 6), accepted)
            self.assertNotIn(62 | (rotation << 6), accepted)
            self.assertNotIn(4096 | 63 | (rotation << 6), accepted)

    def test_bitfield_masks_do_not_apply_the_logical_all_ones_restriction(self):
        derived = enumerate_encoding(bitmask_encoding(immediate=False))
        self.assertEqual(len(derived['accepted']), 8064)
        self.assertIn(4096 | 63, derived['accepted'])

    def test_bitmask_width_cannot_be_guessed_from_the_function_name(self):
        with self.assertRaisesRegex(ValueError, 'unqualified DecodeBitMasks width'):
            enumerate_encoding(bitmask_encoding(result_width=32))

    def test_tuple_value_can_reach_an_additional_rejection(self):
        row = bitmask_encoding()
        one_per_byte = {'LitBits': [bit == '1' for bit in f'{0x0101010101010101:064b}']}
        row['decode'].append({'If': {'branches': [
            [binary('Eq', variable('mask'), one_per_byte), ['Undefined']]], 'else_body': None}})
        # The byte mask #1 has eight encodings because immr's high three bits
        # do not alter an eight-bit element rotation.
        self.assertEqual(len(enumerate_encoding(row)['accepted']), 7680 - 8)

    def test_aarch32_cannot_inherit_the_qualified_a64_call_contracts(self):
        row = encoding([]) | {'iset': 'A32'}
        with self.assertRaisesRegex(ValueError, 'non-A64 decode context'):
            enumerate_encoding(row)

    def test_unused_unknown_call_has_no_implicit_nonthrowing_contract(self):
        value = {'Call': {'name': {'qualifier': 'Any', 'name': 'MayDecodeUndefined'},
                          'args': [variable('field')]}}
        row = encoding([{'VarDeclInit': dict(name='unused', ty={}, value=value)}])
        with self.assertRaisesRegex(ValueError, 'unqualified.*effect'):
            enumerate_encoding(row)

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
