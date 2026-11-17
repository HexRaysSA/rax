"""Internal service multiresults inside a separately ABI-verified source wrapper."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.type_system import ref
from candidate.values import Value
from test_candidate import block, constant, decl, operation
from test_candidate_context import roots


def service_wrapper():
    candidate = roots()
    services = runtime_package_module('services')
    spec = services.service('memory.map')
    fixed = {'u64': 5, 'u32': 1, 'data_ptr': 4}
    signature = {'id': 201, 'kind': 'function', 'cc': 'portable', 'variadic': False}
    for side, attr in [('params', 'param_noundef'), ('results', 'result_noundef')]:
        signature[side] = [ref(fixed[item['type']]) for item in spec[side]]
        signature[attr] = [item['noundef'] for item in spec[side]]
    candidate[1]['types'] += [signature, {'id': 300, 'kind': 'int', 'bits': 1}]
    imported = {'id': 0, 'kind': 'service', 'namespace': spec['namespace'], 'name': spec['name'],
                'version': 1, 'catalog': services.digest(), 'signature': ref(201), 'abi': None,
                'capability': spec['capability'], 'descriptor': None}
    candidate[6]['imports'] = [imported]
    storage = {'type': ref(1), 'layout': ref(0), 'nominal': None, 'abi_binding': None, 'bytes': 4}
    mode = {'alignment': 4, 'volatile': False, 'order': 'none', 'failure_order': 'none', 'scope': 'process', 'elementwise': False}
    function = candidate[3]['functions'][0]  # Original source signature int(int), all noundef.
    function['blocks'] = [block(0, [constant(1, 5, '1000000000000000'), constant(2, 5, '0800000000000000'),
        constant(3, 1, '03000000'), operation('call', [decl(4, 1), decl(5, 4)], [1, 2, 3],
            target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind'),
        constant(6, 1, '00000000'), operation('icmp', [decl(7, 300)], [4, 6], predicate='eq')],
        {'op': 'cbranch', 'condition': 7, 'true': 1, 'false': 2}),
        block(1, [operation('store', [], [5, 0], storage=storage, mode=mode),
                  operation('load', [decl(8, 17)], [5], storage=storage, mode=mode)], {'op': 'return', 'values': [8]}),
        block(2, [constant(9, 17, 'ffffffff')], {'op': 'return', 'values': [9]})]
    return candidate


class CandidateServiceTests(unittest.TestCase):
    def test_actual_multiresult_primitive_and_separate_source_abi(self):
        candidate = service_wrapper()
        context = RootContext(candidate)
        self.assertEqual(context.verify_abi()['signatures'], 1)
        admitted = context.verify_execution()
        events = []
        def mapping(machine, arguments):
            events.append([value.data for value in arguments])
            pointer = machine.memory.allocate(arguments[0].data, arguments[1].data, source_object=False)
            return [Value(ref(1), 'concrete', 0), Value(ref(4), 'concrete', pointer)]
        machine = Machine(admitted, imports={('self', 0): mapping})
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        self.assertEqual(events, [[16, 8, 3]])
        self.assertFalse(admitted.types.get(ref(201))['result_noundef'][0])
        self.assertTrue(admitted.types.get(ref(12))['result_noundef'][0])

    def test_nonnull_source_abi_and_scalar_pointer_substitution_reject(self):
        candidate = service_wrapper()
        candidate[6]['imports'][0]['abi'] = {'some': ref(0)}
        context = RootContext(candidate)
        context.verify_abi()
        with self.assertRaisesRegex(Reject, 'SERVICE_UNUSED_ABI'):
            context.verify_execution()
        candidate = service_wrapper()
        candidate[1]['types'][-2]['results'][1] = ref(5)  # u64 address is not data_ptr.
        context = RootContext(candidate)
        context.verify_abi()
        with self.assertRaisesRegex(Reject, 'SERVICE_TYPE'):
            context.verify_execution()


if __name__ == '__main__':
    unittest.main()
