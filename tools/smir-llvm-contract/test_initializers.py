"""Actual pin source/IR initializers and independent GEP prefix obligations."""
import re
import tempfile
import unittest

from global_initializers import observe
from pointer_contract import gep, normalize_indices
from test_contract import BIN, FIXTURES, run


class InitializerSourceWitnesses(unittest.TestCase):
    def test_c23_cpp23_two_targets_four_pipeline_modes(self):
        with tempfile.TemporaryDirectory(prefix='smir-global-init-') as output:
            rows = observe(BIN / 'clang', output)
        self.assertEqual(len(rows), 160)
        static = {'ptr64', 'bitint33_via64', 'bias'}
        rejected = {'ptr32_direct', 'ptr8_direct'}
        for row in rows:
            with self.subTest(mode=row['mode'], target=row['target'], language=row['language'], case=row['case']):
                if row['case'] in rejected or row['language'] == 'c23' and row['case'] not in static:
                    self.assertNotEqual(row['returncode'], 0)
                else:
                    self.assertEqual(row['returncode'], 0, row['diagnostics'])
                    if row['case'] in static:
                        self.assertIn('ptrtoint', row['initializer'])
                        self.assertFalse(row['dynamic_ctors'])
                    elif row['case'] == 'same_object_delta' and row['mode'] != 'O0':
                        self.assertRegex(row['initializer'], r'global i64 4,')
                    else:
                        self.assertTrue(row['dynamic_ctors'])

    def test_retained_ir_ce_and_wrappers_parse_in_actual_pin(self):
        text = run([BIN/'clang', '-target', 'x86_64-unknown-linux-gnu', '-x', 'ir',
                    '-O0', '-S', '-emit-llvm', FIXTURES/'constant-expressions.ll', '-o', '-'])
        for token in ('sub (i64 ptrtoint', 'add (i64 ptrtoint', 'xor (i64 ptrtoint',
                      'ptrtoint (ptr @a to i7)', 'ptrtoaddr', 'dso_local_equivalent', 'no_cfi'):
            self.assertIn(token, text)

    def test_ordinary_absolute_vtable_retains_inrange_and_pointer_integer(self):
        for target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
            text = run([BIN/'clang++', '-target', target, '-std=c++23', '-O0',
                        '-S', '-emit-llvm', FIXTURES/'relocation-forms.cpp', '-o', '-'])
            self.assertRegex(text, r'@object = .*inrange\(-16, 8\)')
            self.assertRegex(text, r'@address_bits = .*ptrtoint .*i64 4\) to i64')
            self.assertNotIn('@llvm.global_ctors', text)


class ConstantGepPrefixWitnesses(unittest.TestCase):
    def test_same_net_zero_has_distinct_original_poison_promises(self):
        cases = [([(1 << 64, 65, 1)], True), ([(0, 65, 1)], False),
                 ([(1 << 61, 64, 8)], True)]
        for indices, poison in cases:
            offsets, actual = normalize_indices(indices, flags=['nuw'])
            self.assertEqual(offsets, [0])
            self.assertEqual(actual, poison)
            self.assertEqual(gep(1, indices, flags=['nuw']), (1, poison))

    def test_all_zero_exception_does_not_erase_nonzero_index_truncation(self):
        self.assertEqual(normalize_indices([(0, 65, 1)], flags=['inbounds']), ([0], False))
        self.assertEqual(normalize_indices([(1 << 64, 65, 1)], flags=['inbounds']), ([0], True))
        # Independent actual optimizer can refine poison to the concrete base;
        # that is legal and is not evidence that original source promises held.
        text = run([BIN/'clang', '-target', 'x86_64-unknown-linux-gnu', '-x', 'ir',
                    '-O2', '-S', '-emit-llvm', FIXTURES/'gep-prefix.ll', '-o', '-'])
        bodies = re.findall(r'define[^@]+@(?:wide_bad|wide_good|multiply_bad).*?^}', text, re.M|re.S)
        self.assertEqual(len(bodies), 3)
        for body in bodies:
            self.assertIn('ret ptr %base', body)

    def test_ordered_offsets_and_accumulated_overflow_are_not_flattened(self):
        indices = [((1 << 63) - 1, 64, 1), (1, 64, 1), ((1 << 64) - 1, 64, 1)]
        offsets, poison = normalize_indices(indices, flags=['nusw'])
        self.assertEqual(offsets, [(1 << 63) - 1, 1, -1])
        self.assertTrue(poison)
        self.assertEqual(normalize_indices(indices), (offsets, False))
