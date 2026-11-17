"""Actual same-module reference execution using canonical R-issued handles."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest

from candidate.context import RootContext, source_registry_api
from candidate.function_address_contract import source_roots
from candidate.machine import Machine, Frame
from candidate.type_system import ref
from candidate.values import Value, Pointer
from test_candidate import operation, decl, block
from test_candidate_source_calls import ledger

ROOT = Path(__file__).resolve().parents[3]


def registry_api():
    name = '_rax_smir_code_addresses_v1'
    path = ROOT / 'tools/smir-runtime-contract/source_roles/code_addresses.py'
    if name in sys.modules:
        module = sys.modules[name]
        if Path(module.__file__).resolve() != path or module._CODE_ADDRESSES_READY is not True:
            raise RuntimeError('canonical registry identity')
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def source_program(*, raw=True):
    document = source_roots()
    original = deepcopy(document[3]['functions'][0])
    original['id'] = 1
    original['blocks'] = [block(0, [], {'op': 'jump', 'target': 1}),
                          block(1, [], {'op': 'return', 'values': [0]})]
    document[3]['functions'].append(original)
    symbol = deepcopy(document[2]['symbols'][0])
    symbol.update(id=1, name='actual_callee')
    symbol['definition']['some']['target'] = ref(1)
    document[2]['symbols'].append(symbol)
    operations = [operation('address_of', [decl(1, 300)], symbol=ref(1)),
                  operation('code_bind', [decl(2, 301)], [1], plan=ref(0))]
    target = 2
    if raw:
        document[1]['types'].append(dict(id=302, kind='raw', bits=64))
        operations += [operation('bitcast', [decl(3, 302)], [2]),
                       operation('bitcast', [decl(4, 301)], [3]),
                       operation('copy', [decl(5, 301)], [4])]
        target = 5
    operations += [operation('call', [decl(6, 17)], [0],
        target=dict(kind='indirect', value=target, signature=ref(12)),
        unwind='propagate', source_plan={'some': ref(0)})]
    document[3]['functions'][0]['blocks'][0].update(ops=operations, term={'op': 'return', 'values': [6]})
    return document


def admitted(document=None, *, max_work=10**12):
    context = RootContext(source_program() if document is None else document)
    context.verify_abi()
    checked = context.verify_execution()
    budget = ledger(max_work=max_work, max_edges=10**12, max_copied_bytes=10**12)
    source = context.source_registry_context(budget=budget)
    api = registry_api()
    policy = api.RegistryPolicy(max_targets=128, max_permits=128, max_roots=1024,
                                max_activations=128, max_snapshots=32)
    registry = api.CodeRegistry(budget=budget, policy=policy)
    machine = Machine(checked)
    machine.attach_source_registry(registry, source, budget=budget)
    return context, checked, source, registry, budget, machine


class ActualSourceExecutionTests(unittest.TestCase):
    def test_actual_legacy_negative_and_boundary_observations(self):
        for state, kind, reason in [('zero', 'trap', 'code_token_invalid'),
                                    ('undef', 'trap', 'code_token_invalid'),
                                    ('poison', 'language_ub', 'ub_pointer'),
                                    ('originless', 'trap', 'code_address_invalid'),
                                    ('label', 'trap', 'code_address_invalid')]:
            with self.subTest(state=state):
                document = source_program(raw=False)
                operations = document[3]['functions'][0]['blocks'][0]['ops']
                if state == 'label':
                    body = document[3]['functions'][0]['blocks'][0]
                    body['id'] = 1
                    document[3]['functions'][0]['blocks'] = [block(0, [], {'op': 'jump', 'target': 1}), body]
                    first = operation('block_address', [decl(1, 301)], function=0, block=1)
                elif state == 'originless':
                    document[1]['types'].append(dict(id=302, kind='raw', bits=64))
                    first = operation('constant', [decl(1, 302)],
                                      literal={'kind': 'bits', 'value': '0200000000000000'})
                else:
                    first = operation('constant', [decl(1, 301)], literal={'kind': state})
                operations[0] = first
                operations.insert(1, operation('code_erase', [decl(7, 300)], [1]))
                if state == 'originless':
                    operations.insert(1, operation('bitcast', [decl(8, 301)], [1]))
                    operations[2]['operands'] = [8]
                next(node for node in operations if node['op'] == 'code_bind')['operands'] = [7]
                _, _, _, registry, budget, machine = admitted(document)
                machine.start(0, [Value(ref(17), 'concrete', 42)])
                result = machine.run()
                self.assertEqual((result['kind'], result['reason']), (kind, reason), result)
                self.assertEqual(registry._permits, [])
                self.assertEqual(registry._entries, [])
                if state in {'zero', 'undef'}:
                    self.assertEqual(machine.stack[-1].values[7].data.address, 0)
                elif state == 'poison':
                    self.assertEqual(machine.stack[-1].values[7].state, 'poison')

    def test_parked_activation_is_live_but_cannot_observe_current_call(self):
        _, _, source, registry, budget, machine = admitted(source_program(raw=False))
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        # The initial phi phase and three actual operations enter the callee.
        result = machine.run(fuel=4)
        self.assertEqual(result['kind'], 'resource', result)
        self.assertEqual(len(machine.stack), 2)
        parent, child = machine.stack
        fact = machine.source_activation(parent, budget=budget)
        api = source_registry_api()
        self.assertIs(api.source_activation_context(fact, budget=budget), source)
        error = sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError
        with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
            machine.source_call(parent, budget=budget)
        self.assertEqual(machine.run()['values'][0].data, 42)
        with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
            api.validate_source_activation(fact, source=source, budget=budget)

    def test_real_budget_refusal_retains_original_bound_result_without_replay(self):
        _, _, _, registry, budget, machine = admitted(source_program(raw=False))
        original_bind = registry.bind
        committed = []
        def record_commit(*args, **kwargs):
            result = original_bind(*args, **kwargs)
            committed.append((budget._used_work, result))
            return result
        registry.bind = record_commit
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        self.assertEqual(machine.run()['values'][0].data, 42)
        self.assertEqual(len(committed), 1)
        # The independent second run has the actual non-resettable ledger limit
        # exactly at the first run's successful bind commit, before adoption.
        _, _, _, second_registry, second_budget, second = admitted(
            source_program(raw=False), max_work=committed[0][0])
        second.start(0, [Value(ref(17), 'concrete', 42)])
        error = sys.modules['_rax_smir_source_data_v1'].SourceDataError
        with self.assertRaisesRegex(error, 'SOURCE_DATA_RESOURCE'):
            second.run()
        private = source_registry_api()._machine(second)
        pending = private['pending_result']
        self.assertIsNotNone(pending)
        fields = source_registry_api()._fact_fields(pending, type(pending))
        lane = fields['lane']
        self.assertIs(type(lane), registry_api().BoundLane)
        self.assertEqual(len(second_registry._permits), 1)
        self.assertNotIn(2, second.stack[-1].values)
        with self.assertRaisesRegex(error, 'SOURCE_DATA_RESOURCE'):
            second.run()
        self.assertIs(source_registry_api()._machine(second)['pending_result'], pending)
        self.assertIs(fields['lane'], lane)
        self.assertEqual(len(second_registry._permits), 1)
        self.assertIsNone(second.finished)
        self.assertEqual(second_registry._entries, [])

    def test_actual_nonnull_raw_roundtrip_call42_and_shared_pool_publication(self):
        context, checked, source, registry, budget, machine = admitted()
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        result = machine.run()
        self.assertEqual(result['kind'], 'return', result)
        self.assertEqual(result['values'][0].data, 42)
        self.assertEqual(len(machine._source_runtime['entries']), 1)
        entry = machine._source_runtime['entries'][0]
        self.assertIs(entry.source, source)
        self.assertEqual(entry.function['id'], 1)
        # Reading owner counters is diagnostic test evidence, not a constructor.
        self.assertTrue(all(registry._row(owner)['active'] == 0 for owner in registry._owners))
        with self.assertRaisesRegex(registry_api().CodeRegistryError, 'RT_CODE_ENTRY_REPLAY'):
            registry.finish_entry(entry, outcome=object(), budget=budget)
        second = Machine(checked)
        second.attach_source_registry(registry, source, budget=budget)
        first_pointer = machine.register_function(ref(1), ref(1), ref(12))
        second_pointer = second.register_function(ref(1), ref(1), ref(12))
        self.assertEqual(first_pointer.address, second_pointer.address)
        selected_address = registry.address(entry.target, budget=budget)
        self.assertEqual(selected_address.bits, first_pointer.address)
        registry.drop_lane(selected_address, budget=budget)
        label = second.address_operation(dict(op='block_address', function=1, block=1,
            results=[decl(10, 301)], operands=[]))[0].data
        self.assertNotEqual(label.address, first_pointer.address)
        self.assertEqual(label.domain, 'label')
        self.assertIsNotNone(first_pointer.lineage)
        self.assertEqual(machine.next_code, 2)  # Attached machines never allocate this local pool.
        self.assertEqual(second.next_code, 2)

    def test_private_machine_and_frame_identity_reject_equal_fields(self):
        context, checked, source, registry, budget, machine = admitted()
        api = source_registry_api()
        forged = object.__new__(Machine)
        forged.__dict__.update(machine.__dict__)
        error = sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError
        with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
            api.validate_source_machine(forged, source=source, budget=budget)
        other = RootContext(source_program())
        other.verify_abi()
        other_checked = other.verify_execution()
        with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
            api.validate_source_machine(Machine(other_checked), source=source, budget=budget)
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        frame = machine.stack[-1]
        fact = machine.source_activation(frame, budget=budget)
        self.assertIs(api.source_activation_context(fact, budget=budget), source)
        fake_frame = Frame(frame.function, frame.block, frame.values, frame.activation)
        with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
            machine.source_activation(fake_frame, budget=budget)
        with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
            machine.source_call(frame, budget=budget)  # No private dispatch is currently executing.
        for cls in (api.SourceActivation, api.SourceOrdinaryCall, api.SourceEntryOutcome, api.SourceEntryCommit):
            with self.assertRaisesRegex(error, 'SOURCE_REGISTRY_CONTEXT'):
                cls()


if __name__ == '__main__':
    unittest.main()
