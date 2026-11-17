"""Independent registered scalar host descriptors, not artifact self-certificates."""
from copy import deepcopy
import hashlib
import unittest

from common import Reject
from candidate.context import IndependentEvidence, RootContext, records
from candidate.bindings import runtime_package_module
from candidate.machine import Machine, Terminated
from candidate.raw import Raw
from candidate.type_system import ref
from candidate.type_system import Types
from candidate.values import Value
from candidate.wire import encode
from test_candidate import block, decl, operation
from test_candidate_context import roots


def package(raw_argument=False):
    candidate = roots()
    factory_root = {'payload_revision': 2, 'memory_layouts': [], 'types': [
        {'id': 0, 'kind': 'int', 'bits': 32}, {'id': 1, 'kind': 'raw', 'bits': 64},
        {'id': 3, 'kind': 'function', 'params': [ref(1 if raw_argument else 0)], 'results': [ref(0)],
         'cc': 'portable', 'variadic': False, 'param_noundef': [False], 'result_noundef': [False]}]}
    descriptor = {'revision': 1, 'namespace': 'example.host', 'name': 'increment', 'version': 1,
                  'types': encode('execution_types', factory_root).hex(), 'signature': 3}
    raw = encode('runtime_host_descriptor', descriptor, records=records())
    digest = hashlib.sha256(b'SMIR-HOST-V1\0' + raw).hexdigest()
    guest_type = 3 if raw_argument else 17
    signature = {'id': 201, 'kind': 'function', 'params': [ref(guest_type)], 'results': [ref(17)],
        'cc': 'portable', 'variadic': False, 'param_noundef': [False], 'result_noundef': [False]}
    candidate[1]['types'].append(signature)
    candidate[6]['imports'] = [{'id': 0, 'kind': 'host', 'namespace': descriptor['namespace'], 'name': descriptor['name'],
        'version': 1, 'descriptor': digest, 'signature': ref(201), 'capability': 'host_value'}]
    candidate[9] = {'payload_revision': 1, 'capabilities': ['host_value'], 'requirements': [], 'limits': []}
    caller = deepcopy(signature)
    caller['id'] = 202
    candidate[1]['types'].append(caller)
    candidate[3]['functions'].append({'id': 1, 'signature': ref(202), 'abi_signature': None,
        'params': [decl(0, guest_type)], 'entry': 0, 'escape': 'propagate', 'no_return': False,
        'blocks': [block(0, [operation('call', [decl(1, 17)], [0],
            target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind')],
            {'op': 'return', 'values': [1]})]})
    return candidate, IndependentEvidence({}, {}, host_descriptors={digest: raw})


def admitted(candidate, evidence):
    context = RootContext(candidate, evidence)
    context.verify_abi()
    context.verify_execution()
    return context


class CandidateHostTests(unittest.TestCase):
    def test_value_only_host_callback_cannot_supply_terminal_owner_outcome(self):
        candidate, evidence = package()
        context = admitted(candidate, evidence)
        machine = Machine(context.execution_checked, imports={('self', 0): lambda *args: Terminated('process_abort')})
        machine.start(1, [Value(ref(17), 'concrete', 42)])
        with self.assertRaisesRegex(Reject, 'reference_terminal_helper'):
            machine.run()
        self.assertIsNone(machine.finished)

    def test_runtime_factory_independently_joins_registered_execution_graph(self):
        candidate, evidence = package()
        context = admitted(candidate, evidence)
        registry = runtime_package_module('host').Registry(Types)
        descriptor = next(iter(evidence.host_descriptors.values()))
        registration = registry.register(descriptor, lambda arguments: None)
        imported = candidate[6]['imports'][0]
        self.assertIs(registry.admit(imported, context.execution), registration)
        # The registered graph uses ID3; the consuming graph uses ID201. ABI
        # attributes, rather than coincidentally equal local IDs, remain binding.
        changed = deepcopy(candidate)
        changed[1]['types'][-2]['param_noundef'] = [True]
        with self.assertRaisesRegex(ValueError, 'RT_HOST_SIGNATURE_MISMATCH'):
            registry.admit(imported, RootContext(changed).execution)
        with self.assertRaisesRegex(ValueError, 'RT_HOST_DUPLICATE'):
            registry.register(descriptor, lambda arguments: None)

    def test_registered_graph_alias_ids_and_zero_freeze_before_callback(self):
        candidate, evidence = package()
        context = admitted(candidate, evidence)
        seen = []
        def callback(machine, arguments):
            seen.append(arguments[0])
            return [Value(ref(17), 'concrete', (arguments[0].data + 1) & 0xffffffff)]
        machine = Machine(context.execution_checked, imports={('self', 0): callback})
        machine.start(1, [Value(ref(17), 'poison')])
        self.assertEqual(machine.run()['values'][0].data, 1)
        self.assertEqual((seen[0].state, seen[0].data), ('concrete', 0))

    def test_file_declared_digest_is_not_registration_and_attributes_must_match(self):
        candidate, evidence = package()
        with self.assertRaisesRegex(Reject, 'host_descriptor_registry'):
            admitted(candidate, IndependentEvidence({}, {}))
        candidate[1]['types'][-2]['param_noundef'] = [True]
        with self.assertRaisesRegex(Reject, 'host_signature_identity'):
            admitted(candidate, evidence)

    def test_registered_descriptor_snapshot_isolated_from_caller_mutation(self):
        candidate, evidence = package()
        context = RootContext(candidate, evidence)
        evidence.host_descriptors.clear()
        context.verify_abi()
        context.verify_execution()

    def test_raw_known_bits_preserved_and_pointer_origins_rejected_before_host_entry(self):
        candidate, evidence = package(True)
        context = admitted(candidate, evidence)
        seen = []
        def callback(machine, arguments):
            seen.append(arguments[0].data)
            return [Value(ref(17), 'concrete', 42)]
        machine = Machine(context.execution_checked, imports={('self', 0): callback})
        machine.start(1, [Value(ref(3), 'concrete', Raw.integer(64, 0xa5, poison=0x80, undef=0x20))])
        self.assertEqual(machine.run()['values'][0].data, 42)
        self.assertEqual((seen[0].bits, seen[0].poison, seen[0].undef), (5, 0, 0))
        machine = Machine(context.execution_checked, imports={('self', 0): callback})
        pointer = machine.memory.allocate(8, 8)
        machine.start(1, [Value(ref(3), 'concrete', Raw.pointer(pointer))])
        self.assertEqual(machine.run()['reason'], 'host_pointer_origin')
        self.assertEqual(len(seen), 1)
        self.assertEqual(machine.tickets, {})


if __name__ == '__main__':
    unittest.main()
