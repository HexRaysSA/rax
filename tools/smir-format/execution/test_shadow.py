"""Per-bit poison, pointer-fragment and overlap conformance against exact rules."""
import unittest
import json

from common import SPEC, Reject
from shadow import Memory, Pointer, Raw, concat, from_document


class ShadowTests(unittest.TestCase):
    def test_checked_in_raw_bit_fixtures(self):
        cases = json.loads((SPEC / 'conformance/execution/raw-bits.json').read_text())['cases']
        for case in cases:
            with self.subTest(case=case['name']):
                if 'reject' in case:
                    with self.assertRaises(Reject) as error:
                        from_document(case['document'])
                    self.assertEqual(error.exception.code, case['reject'])
                else:
                    raw = from_document(case['document'])
                    self.assertEqual(raw.scalar(), case['scalar'])
                    self.assertEqual(raw.freeze().scalar(), case['frozen'])
    def test_split_pointer_reconstruction_and_bit_swaps(self):
        pointer = Pointer('ab' * 32, 0x1234567890abcdef, 7)
        raw = Raw.pointer(pointer)
        rebuilt = concat([raw.slice(0, 32), raw.slice(32, 32)])
        self.assertEqual(rebuilt.as_pointer(), {'kind': 'pointer', 'address': pointer.address,
                                              'identity': pointer.identity, 'generation': 7, 'domain': 'data'})
        swapped = concat([raw.slice(32, 32), raw.slice(0, 32)])
        self.assertIsNone(swapped.as_pointer()['identity'])
        # Equal numerical bits still do not prove correct origin ordering.
        repeated = Raw.pointer(Pointer('cd' * 32, 0x1111111111111111, 1))
        swapped = concat([repeated.slice(32, 32), repeated.slice(0, 32)])
        self.assertEqual(swapped.bits, repeated.bits)
        self.assertIsNone(swapped.as_pointer()['identity'])

    def test_per_bit_freeze_and_scalar_poison_collapse(self):
        raw = Raw.integer(16, 0xabcd, poison=0x000f)
        self.assertEqual(raw.scalar(), {'kind': 'poison'})
        self.assertEqual(raw.slice(8, 8).scalar(), {'kind': 'bits', 'bits': 0xab})
        self.assertEqual(raw.freeze().scalar(), {'kind': 'bits', 'bits': 0xabc0})
        self.assertEqual(raw.poison, 0x000f)

    def test_pointer_and_integer_loads_preserve_or_strip_provenance(self):
        pointer = Pointer('ab' * 32, 0x1020304050607080, 3)
        memory = Memory(24)
        memory.store(0, Raw.pointer(pointer))
        self.assertEqual(memory.load(0, 64).as_pointer()['identity'], pointer.identity)
        self.assertEqual(memory.load(0, 64).scalar(), {'kind': 'bits', 'bits': pointer.address})
        # Re-store integer bits: address preserved, origin intentionally stripped.
        memory.store(8, Raw.integer(64, pointer.address))
        self.assertIsNone(memory.load(8, 64).as_pointer()['identity'])
        memory.move(16, 0, 8)
        self.assertEqual(memory.load(16, 64).as_pointer()['identity'], pointer.identity)

    def test_memmove_snapshots_bits_poison_and_provenance(self):
        memory = Memory(16)
        pointer = Pointer('ab' * 32, 0x0123456789abcdef, 2)
        memory.store(0, Raw.pointer(pointer))
        memory.move(1, 0, 8)
        self.assertEqual(memory.load(1, 64).as_pointer()['identity'], pointer.identity)
        self.assertEqual(memory.load(9, 8).scalar(), {'kind': 'poison'})
        snapshot = memory.load(0, 128)
        with self.assertRaises(Reject):
            memory.move(15, 0, 8)
        self.assertEqual(memory.load(0, 128), snapshot)

    def test_invalid_origin_generation_and_width_rejected(self):
        for width in [0, 65536, True]:
            with self.assertRaises(Reject):
                Raw.integer(width, 0)
        for token in [0, 1, 3, 2**64]:
            with self.assertRaises(Reject):
                Pointer('ab' * 32, token, 1, 'code')
        pointer = Pointer('ab' * 32, 2, 1, 'code')
        raw = Raw.pointer(pointer)
        with self.assertRaises(Reject):
            Raw(64, 3, 0, raw.origins)
        with self.assertRaises(Reject):
            Raw(64, 2, 1, raw.origins)
        with self.assertRaises(Reject):
            Memory(1).store(0, Raw.integer(7, 0))


if __name__ == '__main__':
    unittest.main()
