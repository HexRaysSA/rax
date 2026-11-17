"""Real issued CodeAddress -> eight Raw8 calls/memory -> bind+source entry."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
FOLDER = ROOT/'docs/specifications/smir/portable/conformance/execution/function-addresses/byte-relay'


def child(profile):
    command = [sys.executable, '-B']+(['-O'] if sys.flags.optimize else [])+[str(Path(__file__).resolve()), '--witness', profile]
    run = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if run.returncode:
        raise RuntimeError(run.stdout+run.stderr)
    return json.loads(run.stdout)


class CodeAddressByteRelayTests(unittest.TestCase):
    def assert_rejected(self, profile, expected):
        row = child(profile)
        self.assertEqual(row['outcome'], expected)
        self.assertEqual((row['permits'], row['entries']), (0, 0))
        self.assertTrue(row['original_snapshots_unchanged'])
        self.assertEqual(row['optimize'], sys.flags.optimize)
        return row

    def test_real_issued_address_eight_helpers_memory_bind_and_call_42(self):
        row = child('relay')
        self.assertEqual((row['outcome'], row['return_value']), ('return', 42))
        self.assertEqual((row['helper_entries'], row['helper_returns']), (8, 8))
        self.assertEqual((row['stores'], row['loads']), (8, 9))
        self.assertEqual((row['permits'], row['entries']), (1, 1))
        self.assertTrue(row['reconstruction']['equal_issued_bits'])
        self.assertTrue(row['reconstruction']['same_target'])
        self.assertTrue(row['reconstruction']['same_authority'])
        self.assertEqual(row['reconstruction']['lane_origins'], [1]*8)
        self.assertEqual(row['reconstruction']['numeric_equality'], 1)
        expected = [dict(width=8, bits=(row['issued_bits'] >> (8*i)) & 255,
                         poison=0, undef=0,
                         spans=[dict(offset=0, length=8, source=8*i,
                                     original_target=True, original_authority=True)])
                    for i in range(8)]
        self.assertEqual(row['parameter_fragments'], expected)
        self.assertEqual(row['returned_fragments'], expected)
        self.assertTrue(row['original_snapshots_unchanged'])
        self.assertEqual(row['optimize'], sys.flags.optimize)

    def test_same_bits_mixed_genuine_foreign_origin_cannot_bind(self):
        row = self.assert_rejected('mixed-foreign-equal-bits', 'code_address_invalid')
        self.assertTrue(row['reconstruction']['equal_issued_bits'])
        self.assertFalse(row['reconstruction']['same_target'])
        self.assertEqual((row['helper_entries'], row['helper_returns']), (8, 8))

    def test_entire_genuine_foreign_same_bits_packet_refuses_registry_brand(self):
        row = self.assert_rejected('foreign-equal-bits', 'RT_CODE_REFERENCE')
        self.assertTrue(row['reconstruction']['equal_issued_bits'])
        self.assertFalse(row['reconstruction']['same_target'])
        self.assertEqual(row['registry_rejection'], dict(kind='semantic', code='RT_CODE_REFERENCE'))

    def test_reordered_zero_fragments_keep_bits_but_lose_ordered_origin(self):
        row = self.assert_rejected('reordered-zero-bytes', 'code_address_invalid')
        self.assertTrue(row['reconstruction']['equal_issued_bits'])
        self.assertFalse(row['reconstruction']['same_authority'])

    def test_one_numeric_byte_and_numeric_vector_cannot_restore_origins(self):
        for profile in ('numeric-byte-roundtrip', 'numeric-vector-roundtrip'):
            with self.subTest(profile=profile):
                row = self.assert_rejected(profile, 'code_address_invalid')
                self.assertTrue(row['reconstruction']['equal_issued_bits'])
                self.assertFalse(row['reconstruction']['same_authority'])

    def test_equal_originless_zero_byte_cannot_complete_pointer_origin(self):
        row = self.assert_rejected('originless-zero-byte', 'code_address_invalid')
        self.assertTrue(row['reconstruction']['equal_issued_bits'])
        self.assertFalse(row['reconstruction']['same_target'])

    def test_actual_retirement_and_new_generation_do_not_revive_old_packet(self):
        row = self.assert_rejected('stale-generation', 'code_address_stale')
        self.assertTrue(row['reconstruction']['same_target'])
        self.assertGreater(row['retired_generation']['new_generation'], row['retired_generation']['old_generation'])
        self.assertEqual(row['retired_generation']['retirement_phase'], 'busy_active')

    def test_real_guarded_helper_writes_fault_before_any_binding(self):
        for profile, reason, entries, returns in [('readonly-buffer', 'memory_permission', 1, 0),
                                                  ('short-buffer', 'memory_bounds', 8, 7)]:
            with self.subTest(profile=profile):
                row = self.assert_rejected(profile, reason)
                self.assertEqual((row['helper_entries'], row['helper_returns']), (entries, returns))
                self.assertIsNone(row['reconstruction'])

    def test_fixture_wire_hashes_are_explicit_and_unique(self):
        data = json.loads((FOLDER/'cases.json').read_bytes())
        self.assertEqual(len(data['cases']), 10)
        self.assertEqual(len({r['id'] for r in data['cases']}), 10)
        for row in [data['producer']]+data['cases']:
            wire = bytes.fromhex(row['encoded_hex'])
            self.assertEqual(hashlib.sha256(wire).hexdigest(), row['sha256'])
            self.assertEqual(len(wire), row['bytes'])


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--witness':
        from code_address_bytes.contract import witness
        data = json.loads((FOLDER/'cases.json').read_bytes())
        row = next(r for r in data['cases'] if r['id'] == sys.argv[2])
        print(json.dumps(witness(row['id'], bytes.fromhex(row['encoded_hex']),
                                 bytes.fromhex(data['producer']['encoded_hex'])), sort_keys=True))
    else:
        unittest.main(verbosity=2)
