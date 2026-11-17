"""Checked-in candidate positive/rejection fixtures and independent physical codec."""
import json
import random
import unittest

from common import Reject, SPEC
from candidate.bindings import runtime_package_module
from candidate.context import records
from candidate.machine import Machine
from candidate.verify import verify
from candidate.wire import decode, encode
from candidate_fixtures import cases


class CandidateFixtureTests(unittest.TestCase):
    def test_fixture_reproducibility_and_semantic_results(self):
        document = json.loads((SPEC / 'conformance/execution/candidate/cases.json').read_text())
        self.assertEqual(document, cases())
        for item in document['cases']:
            with self.subTest(case=item['id']):
                roots = [item['sections'][str(number)] for number in [1, 3, 8]]
                expected = item['expected']
                if expected['kind'] == 'reject':
                    with self.assertRaises(Reject) as caught:
                        verify(*roots)
                    self.assertEqual(caught.exception.code, expected['code'])
                else:
                    machine = Machine(verify(*roots))
                    machine.start(0, [])
                    observed = machine.run()
                    self.assertEqual(observed['kind'], expected['kind'])
                    if 'bits' in expected:
                        self.assertEqual(observed['values'][0].data, expected['bits'])
                    if 'reason' in expected:
                        self.assertEqual(observed['reason'], expected['reason'])

    def test_independent_record_codec_all_truncations_and_mutations(self):
        independent = runtime_package_module('wire').PRIMITIVES.RecordCodec(records())
        document = json.loads((SPEC / 'conformance/execution/candidate/portable-identity.json').read_text())
        count, mutation_count = 0, 0
        rng = random.Random(0x534d4952)
        for number, kind in [(1, 'execution_types'), (3, 'execution_functions'), (8, 'execution_exceptions')]:
            root = document['sections'][str(number)]
            payload = encode(kind, root)
            self.assertEqual(payload, independent.encode(kind, root))
            self.assertEqual(decode(kind, payload), independent.decode(kind, payload))
            for end in range(len(payload)):
                with self.assertRaises(Reject):
                    decode(kind, payload[:end])
                with self.assertRaises(ValueError):
                    independent.decode(kind, payload[:end])
                count += 1
            for _ in range(256):
                candidate = bytearray(payload)
                index = rng.randrange(len(candidate))
                candidate[index] ^= 1 << rng.randrange(8)
                outcomes = []
                for decoder in [decode, independent.decode]:
                    try:
                        outcomes.append(('ok', decoder(kind, bytes(candidate))))
                    except ValueError:
                        outcomes.append(('reject', None))
                self.assertEqual(outcomes[0], outcomes[1])
                mutation_count += 1
        print(f'Candidate independent ordered codecs:{count} truncations;{mutation_count} mutations;seed0x534d4952')
        # Independently authored byte derivation, not a round trip.
        self.assertEqual(encode('type', {'kind': 'int', 'id': 7, 'bits': 8}),
                         bytes.fromhex('03696e740700000008000000'))
        self.assertEqual(encode('opt:opt:u8', {'some': None}), b'\x01\x00')


if __name__ == '__main__':
    unittest.main()
