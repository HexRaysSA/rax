import hashlib
from pathlib import Path
import struct
import unittest

import mmio_double_shift_oracle as oracle
import mmio_shift_oracle as scalar


class DoubleShiftReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = Path(__file__).resolve().parents[2] / 'tests/fixtures/hvf/mmio-double-shifts-v1'
        cls.cases = (fixture / 'cases.bin').read_bytes()
        cls.records = (fixture / 'records.bin').read_bytes()

    def one(self, index):
        return (self.cases[index * 172:(index + 1) * 172],
                b'RAXRM001' + struct.pack('<I', 1)
                + self.records[12 + index * 168:12 + (index + 1) * 168] + b'RM_DONE!')

    def test_collector_reproduces_all_independent_input_bytes(self):
        self.assertEqual(oracle.corpus(), self.cases)
        self.assertEqual(len(self.cases) // 172, 25344)
        self.assertEqual(hashlib.sha256(self.records).hexdigest(),
                         'bdd3818dcc9f7a258a4ec5622957658b04f0031be7cb50b7ec1071a9bffc856c')

    def test_complete_native_capture_satisfies_independent_formulas(self):
        oracle.validate_records(self.cases, self.records)

    def test_scalar_collector_inputs_remain_byte_identical(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/fixtures/hvf/mmio-shifts-v1/cases.bin'
        self.assertEqual(scalar.corpus(), fixture.read_bytes())

    def test_register_neighbor_result_and_defined_flag_corruption_reject(self):
        cases, records = self.one(0)
        for word in [0, 15, 16, 17, 18, 19, 20]:
            corrupted = bytearray(records)
            corrupted[12 + word * 8] ^= 1
            with self.subTest(word=word), self.assertRaises(AssertionError):
                oracle.validate_records(cases, corrupted)

    def test_undefined_flags_are_masked_and_defined_flags_still_reject(self):
        for index in range(len(self.cases) // 172):
            comparison = struct.unpack_from('<I', self.cases, index * 172 + 168)[0]
            if comparison & 0x810 == 0:
                break
        else:
            self.fail('no nonzero multi-bit-count case')
        cases, records = self.one(index)
        undefined = bytearray(records)
        undefined[12 + 20 * 8] ^= 0x10
        undefined[12 + 20 * 8 + 1] ^= 8
        oracle.validate_records(cases, undefined)
        undefined[12 + 20 * 8] ^= 1
        with self.assertRaises(AssertionError):
            oracle.validate_records(cases, undefined)

    def test_record_count_truncation_and_marker_corruption_reject(self):
        cases, records = self.one(0)
        corruptions = [records[:-1], records + b'\0', b'badmagic' + records[8:],
                       records[:8] + struct.pack('<I', 2) + records[12:]]
        for corrupted in corruptions:
            with self.subTest(length=len(corrupted)), self.assertRaises(AssertionError):
                oracle.validate_records(cases, corrupted)


if __name__ == '__main__':
    unittest.main()
