"""Canonical live-before-frontier IDs including invoke captures and phi edges."""
import unittest

from common import Reject
from candidate.liveness import live_before
from candidate.verify import verify
from test_candidate import block, constant, decl, fixture, operation
from test_candidate_unwind import package


class CandidateLivenessTests(unittest.TestCase):
    def test_frontier_definitions_and_phi_loop_edges(self):
        types, functions, eh = fixture()
        function = functions['functions'][0]
        function['blocks'] = [
            block(0, [constant(0, 2, '01000000'), constant(1, 2, '02000000')], {'op': 'jump', 'target': 1}),
            block(1, [operation('i_add', [decl(3, 2)], [2, 0], flags=[]),
                      constant(4, 0, '00')], {'op': 'cbranch', 'condition': 4, 'true': 1, 'false': 2},
                  [{'result': decl(2, 2), 'incoming': [{'predecessor': 0, 'value': 1}, {'predecessor': 1, 'value': 3}]}]),
            block(2, [], {'op': 'return', 'values': [3]})]
        admitted = verify(types, functions, eh)
        self.assertEqual(live_before(admitted, 0, 0, 0), [])
        self.assertEqual(live_before(admitted, 0, 0, 1), [0])
        self.assertEqual(live_before(admitted, 0, 0, 2), [0, 1])
        self.assertEqual(live_before(admitted, 0, 1, 0), [0, 2])
        self.assertEqual(live_before(admitted, 0, 1, 1), [0, 3])
        self.assertEqual(live_before(admitted, 0, 1, 2), [0, 3, 4])
        self.assertEqual(live_before(admitted, 0, 2, 0), [3])
        with self.assertRaisesRegex(Reject, 'liveness_frontier'):
            live_before(admitted, 0, 1, -1)

    def test_invoke_edge_results_absent_and_capture_retained(self):
        types, functions, eh, dependencies = package()
        admitted = verify(types, functions, eh, dependencies)
        self.assertEqual(live_before(admitted, 0, 0, 0), [0, 1])
        self.assertEqual(live_before(admitted, 0, 1, 0), [2])
        self.assertEqual(live_before(admitted, 0, 2, 0), [])
        # Captured ordinary values remain live even if not call arguments.
        functions['functions'][0]['blocks'][0]['ops'] = [constant(5, 2, '07000000')]
        eh['functions'][0]['actions'][0]['captures'][0]['source']['value'] = 5
        admitted = verify(types, functions, eh, dependencies)
        self.assertEqual(live_before(admitted, 0, 0, 1), [0, 1, 5])


if __name__ == '__main__':
    unittest.main()
