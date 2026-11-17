"""Exact logical exception flow, rejection and binary record tests."""
from copy import deepcopy
import json
import unittest

from codec import decode, encode
from common import SPEC, Reject
from exceptions import Protocol, plan, verify_protocol


class ExceptionTests(unittest.TestCase):
    def fixtures(self):
        return json.loads((SPEC / 'conformance/execution/exceptions.json').read_text())['cases']

    def test_fixtures(self):
        accepted = rejected = 0
        for case in self.fixtures():
            with self.subTest(case=case['name']):
                if 'reject' in case:
                    with self.assertRaises(Reject) as error:
                        plan(case['document'])
                    self.assertEqual(error.exception.code, case['reject'])
                    rejected += 1
                else:
                    self.assertEqual(plan(case['document']), case['events'])
                    accepted += 1
        print(f'Exception protocol fixtures: {accepted} accepted, {rejected} rejected; no native unwind')

    def test_search_has_no_cleanup_and_selected_frame_path_is_specific(self):
        document = self.fixtures()[0]['document']
        events = plan(document)
        first_cleanup = next(index for index, event in enumerate(events) if event['phase'] == 'cleanup')
        self.assertTrue(all(event['phase'] == 'search' for event in events[:first_cleanup]))
        self.assertEqual([event['cleanup'] for event in events if event['phase'] == 'cleanup'], [30, 20, 11])
        self.assertNotIn(10, [event.get('cleanup') for event in events])

    def test_replay_wrong_phase_and_duplicate_release(self):
        document = self.fixtures()[0]['document']
        protocol = Protocol(document)
        with self.assertRaises(Reject):
            protocol.release()
        with self.assertRaises(Reject):
            protocol.commit(protocol.events[-1])
        first = deepcopy(protocol.events[0])
        protocol.commit(first)
        with self.assertRaises(Reject):
            protocol.commit(first)

        for event in protocol.events[protocol.position:]:
            protocol.commit(event)
        protocol.release()
        with self.assertRaises(Reject):
            protocol.release()
        with self.assertRaises(Reject):
            protocol.commit(first)

    def test_display_plan_mutation_does_not_change_committable_event(self):
        protocol = Protocol(self.fixtures()[0]['document'])
        protocol.events[0]['phase'] = 'install'
        with self.assertRaises(Reject):
            protocol.commit(protocol.events[0])
        protocol.events[0]['phase'] = 'cleanup'
        with self.assertRaises(Reject):
            protocol.cleanup_throws()

    def test_throw_during_cleanup_terminates_without_handler_install(self):
        protocol = Protocol(self.fixtures()[0]['document'])
        while protocol.events[protocol.position]['phase'] == 'search':
            protocol.commit(protocol.events[protocol.position])
        protocol.cleanup_throws()
        self.assertEqual(protocol.events[-1], {'phase': 'terminate', 'reason': 'double_exception'})
        protocol.commit(protocol.events[-1])
        self.assertFalse(protocol.caught)
        with self.assertRaises(Reject):
            protocol.release()

    def test_rethrow_identity_and_ownership_transfer(self):
        document = self.fixtures()[0]['document']
        protocol = Protocol(document)
        for event in protocol.events:
            protocol.commit(event)
        next_throw = deepcopy(document)
        next_throw['lease'] += 1
        with self.assertRaises(Reject):
            protocol.rethrow(next_throw)
        next_throw['lease'] = document['lease']
        continuation = protocol.rethrow(next_throw)
        self.assertEqual(continuation.lease, protocol.lease)
        with self.assertRaises(Reject):
            protocol.release()
        with self.assertRaises(Reject):
            protocol.rethrow(next_throw)

    def test_mixed_two_foreign_isas_rejected(self):
        document = deepcopy(self.fixtures()[0]['document'])
        document['frames'][2]['domain'] = 'aarch64'
        with self.assertRaises(Reject) as error:
            verify_protocol(document)
        self.assertEqual(error.exception.code, 'eh_domain')

    def test_binary_protocol_roundtrip_truncation_and_u64(self):
        document = deepcopy(self.fixtures()[0]['document'])
        document['lease'] = 2**64 - 1
        payload = encode('exception_protocol', document)
        self.assertEqual(decode('exception_protocol', payload), document)
        for end in range(len(payload)):
            with self.assertRaises(Reject):
                decode('exception_protocol', payload[:end])
        document['lease'] += 1
        with self.assertRaises(Reject):
            verify_protocol(document)


if __name__ == '__main__':
    unittest.main()
