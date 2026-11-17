"""Large source storage metadata stays symbolic; concrete SSA values are bounded."""
import unittest

from common import Reject
from candidate.layouts import Layouts
from candidate.machine import Machine
from candidate.type_system import Types, ref
from candidate.verify import verify
from candidate.wire import encode
from test_candidate import block, decl, fixture, operation

MAX_SOURCE = 2**61 - 1


class CandidateAllocationTypeTests(unittest.TestCase):
    def package(self, extent):
        types, functions, eh = fixture()
        types['types'] += [{'id': 17, 'kind': 'raw', 'bits': 8},
                           {'id': 18, 'kind': 'array', 'element': ref(17), 'count': extent}]
        types['memory_layouts'] = [
            {'id': 0, 'type': ref(17), 'size': 1, 'alignment': 1, 'access_bytes': 1, 'fields': [], 'element': None, 'stride': 0},
            {'id': 1, 'type': ref(18), 'size': extent, 'alignment': 1, 'access_bytes': extent,
             'fields': [], 'element': {'some': ref(0)}, 'stride': 8}]
        return types, functions, eh

    def test_uniform_byte_array_symbolic_zero_large_and_max(self):
        lengths = []
        for count in [0, 1, 2 * 1024 * 1024, 32 * 1024 * 1024, MAX_SOURCE]:
            root, _, _ = self.package(count)
            types = Types(root)
            layout = Layouts(root, types)
            self.assertEqual(types.width(ref(18)), 8 * count)
            self.assertEqual(layout.get(ref(1))['access_bytes'], count)
            self.assertEqual(len(layout.digest(ref(1))), 64)
            lengths.append(len(encode('type', root['types'][-1])))
        self.assertEqual(len(set(lengths)), 1)  # Fixed metadata, independent of extent.
        root, _, _ = self.package(2**61)
        with self.assertRaisesRegex(Reject, 'type_extent'):
            Types(root)

    def test_static_extract_and_resource_before_concrete_materialization(self):
        roots = self.package(MAX_SOURCE)
        function = roots[1]['functions'][0]
        # A poison aggregate need not be expanded to extract one poisoned byte.
        function['blocks'] = [block(0, [operation('constant', [decl(0, 18)], literal={'kind': 'poison'}),
            operation('extract', [decl(1, 17)], [0], indices=[0])], {'op': 'trap', 'reason': 'done'})]
        admitted = verify(*roots)
        machine = Machine(admitted)
        machine.start(0, [])
        result = machine.run()
        self.assertEqual((result['kind'], result['reason']), ('trap', 'done'))
        self.assertEqual(machine.stack[0].values[1].state, 'poison')
        function['blocks'][0]['ops'][0]['literal'] = {'kind': 'zero'}
        machine = Machine(verify(*roots))
        machine.start(0, [])
        self.assertEqual(machine.run()['kind'], 'resource')
        self.assertNotIn(0, machine.stack[0].values)


if __name__ == '__main__':
    unittest.main()
