"""Call publication, exact code-token signatures and environment value packing."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.context import RootContext
from candidate.machine import Machine, Pending
from candidate.type_system import ref
from candidate.values import Value
from candidate.verify import verify
from test_candidate import block, constant, decl, fixture, operation
from test_candidate_bindings import add_import


class CandidateContinuationTests(unittest.TestCase):
    def test_actual_import_pending_result_never_reenters(self):
        roots, binding = add_import('stack_alloc')
        function = roots[3]['functions'][0]
        function['blocks'][0]['ops'] = [constant(1, 5, '0800000000000000'),
            operation('call', [decl(2, 4)], [1, 1], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind')]
        context = RootContext(roots)
        context.verify_abi()
        admitted = context.verify_execution()
        events = []
        def callback(machine, arguments):
            events.append([value.data for value in arguments])
            return Pending(9)
        machine = Machine(admitted, imports={('self', 0): callback})
        pointer = machine.memory.allocate(8, 8, owner=1)
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 9})
        self.assertNotIn(2, machine.stack[0].values)
        self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 9})
        self.assertEqual(events, [[8, 8]])
        machine.resume(9, [Value(ref(4), 'concrete', pointer)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        with self.assertRaises(Reject):
            machine.resume(9, [Value(ref(4), 'concrete', pointer)])

    def test_retyped_pointer_cannot_call_wrong_signature(self):
        types, functions, eh = fixture()
        callee = deepcopy(functions['functions'][0])
        callee['id'] = 1
        types['types'] += [
            {'id': 17, 'kind': 'function', 'params': [], 'results': [ref(1)], 'cc': 'portable',
             'variadic': False, 'param_noundef': [], 'result_noundef': [True]},
            {'id': 18, 'kind': 'code_ptr', 'signature': ref(17)},
            {'id': 19, 'kind': 'function', 'params': [ref(18)], 'results': [ref(1)], 'cc': 'portable',
             'variadic': False, 'param_noundef': [True], 'result_noundef': [True]}]
        caller = functions['functions'][0]
        caller['signature'], caller['params'] = ref(19), [decl(0, 18)]
        caller['blocks'] = [block(0, [operation('call', [decl(1, 1)], [],
            target={'kind': 'indirect', 'value': 0, 'signature': ref(17)}, unwind='nounwind')],
            {'op': 'return', 'values': [1]})]
        functions['functions'].append(callee)
        machine = Machine(verify(types, functions, eh))
        pointer = machine.register_function(ref(0), ref(1), ref(15))
        machine.start(0, [Value(ref(18), 'concrete', pointer)])
        self.assertEqual(machine.run()['reason'], 'code_token_signature')

    def test_fenv_pack_unpack_and_invalid_no_environment_mutation(self):
        types, functions, eh = fixture()
        types['types'].append({'id': 17, 'kind': 'raw', 'bits': 256})
        signature = types['types'][15]
        signature['results'], signature['result_noundef'] = [ref(11), ref(0)], [False, True]
        function = functions['functions'][0]
        function['blocks'] = [block(0, [operation('fenv_get', [decl(0, 11)]),
            operation('fenv_pack', [decl(1, 17)], [0]),
            operation('fenv_unpack', [decl(2, 11), decl(3, 0)], [1])], {'op': 'return', 'values': [2, 3]})]
        machine = Machine(verify(types, functions, eh), environment={'rounding': 'downward', 'flags': ['denormal'], 'traps': []})
        machine.start(0, [])
        values = machine.run()['values']
        self.assertEqual((values[0].data, values[1].data), (machine.environment, 1))
        function['blocks'][0]['ops'][0:2] = [constant(1, 17, '00' * 32)]  # Invalid revision0 snapshot.
        machine = Machine(verify(types, functions, eh))
        before = deepcopy(machine.environment)
        machine.start(0, [])
        values = machine.run()['values']
        self.assertEqual((values[0].state, values[1].data), ('poison', 0))
        self.assertEqual(machine.environment, before)


if __name__ == '__main__':
    unittest.main()
