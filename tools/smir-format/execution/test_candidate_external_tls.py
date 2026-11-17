"""Actual two-module deployment/selection/TLS joins; reference execution only.

The explicit tls_initialize call models a dedicated frontend's original route.
No initializer is injected into the pure raw-address operation. Registry/module
leases are reference protocol facts, not production admission capabilities.
"""
from copy import deepcopy
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
import unittest

from common import Reject, SPEC
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.raw import Raw
from candidate.type_system import ref
from candidate.values import Value
from test_candidate import block, constant, decl, operation
from test_candidate_bindings import add_import
from test_candidate_storage_join import storage_wrapper


def external_tls_roots():
    provider = storage_wrapper()
    consumer, _ = add_import('tls_address_raw', options={'target': {'some': ref(901, 0)}})
    for name, roots in [('provider', provider), ('consumer', consumer)]:
        roots[2]['manifest']['key']['name'] = name
        roots[2]['symbols'][0]['name'] = name + '_helper'
        roots.setdefault(5, {'payload_revision': 2, 'relocations': [], 'constant_initializers': []})
        roots.setdefault(7, {'payload_revision': 1, 'segments': []})
        roots.setdefault(9, {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []})
    provider[7]['segments'][0]['storage']['id'] = 37
    provider[7]['segments'][0].update(initialization='namespace_dynamic', initializers=[ref(5)])
    provider[6]['imports'][0]['options']['target'] = {'some': ref(37)}
    for symbol in provider[2]['symbols']:
        if symbol['id'] == 1:  # A same-number DATA symbol is not the TLS segment.
            symbol['id'] = 37
        elif symbol['id'] == 3:
            symbol.update(id=74, name='external_tls')
            symbol['definition']['some']['segment'] = 37
    provider[2]['symbols'].sort(key=lambda item: item['id'])
    provider[5]['relocations'][0]['target'] = ref(37)
    provider[3]['functions'][0]['blocks'] = [block(0, [], {'op': 'return', 'values': [0]})]
    provider[1]['types'].append({'id': 500, 'kind': 'function', 'cc': 'portable', 'variadic': False,
        'params': [], 'results': [], 'param_noundef': [], 'result_noundef': []})
    provider[3]['functions'].append({'id': 5, 'signature': ref(500), 'abi_signature': None, 'params': [],
        'entry': 0, 'escape': 'terminate', 'no_return': False,
        'blocks': [block(0, [], {'op': 'return', 'values': []})]})
    provider[2]['manifest']['exports'] = [{'id': 88, 'kind': 'symbol', 'source_linkage': 'c',
        'namespace': 'example', 'name': 'external_tls', 'target': ref(74),
        'execution': {'some': ref(304)}, 'nominal': {'some': ref(1)}, 'abi_signature': None}]
    consumer[1]['types'] += [
        {'id': 202, 'kind': 'function', 'cc': 'portable', 'variadic': False,
         'params': [], 'results': [], 'param_noundef': [], 'result_noundef': []},
        {'id': 306, 'kind': 'array', 'element': ref(9), 'count': 4}]
    consumer[10]['storage_bindings'] = [deepcopy(provider[10]['storage_bindings'][1])]
    consumer[10]['storage_bindings'][0]['id'] = 0
    consumer[2]['manifest']['dependencies'] = [{'slot': 0,
        'key': deepcopy(provider[2]['manifest']['key']), 'minimum_minor': 0, 'maximum_minor': None,
        'site': provider[10]['identity'], 'declarations': [{'id': 901, 'kind': 'symbol',
        'symbol_kind': 'tls', 'source_linkage': 'c', 'namespace': 'example', 'name': 'external_tls',
        'execution': {'some': ref(306)}, 'nominal': {'some': ref(1)}, 'abi_signature': None, 'weak': False}]}]
    initializer = deepcopy(consumer[6]['imports'][0])
    initializer.update(id=1, name='tls_initialize', signature=ref(202))
    consumer[6]['imports'].append(initializer)
    mode = {'alignment': 4, 'volatile': False, 'order': 'none', 'failure_order': 'none',
            'scope': 'process', 'elementwise': False}
    consumer[3]['functions'][0]['blocks'] = [block(0, [
        operation('call', [], [], target={'kind': 'import', 'import': ref(1), 'signature': ref(202)}, unwind='propagate'),
        constant(1, 5, '0000000000000000'),
        operation('call', [decl(2, 4)], [1], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind'),
        operation('load', [decl(3, 17)], [2], storage={'type': ref(17), 'layout': ref(0),
            'nominal': {'some': ref(1)}, 'abi_binding': {'some': ref(0)}, 'bytes': 4}, mode=mode),
        operation('i_add', [decl(4, 17)], [0, 3], flags=[])], {'op': 'return', 'values': [4]})]
    return consumer, provider


def joined_tls():
    # Exercise the independent envelope+record codec and actual content digests.
    # The legacy execution codec may already occupy sys.modules['codec'].
    # Reuse the owner's path-isolated canonical root codec, never mutate imports.
    CandidateCodec = runtime_package_module('wire').PRIMITIVES.CandidateCodec
    codec = CandidateCodec({owner: json.loads((SPEC / 'schema' / owner / 'candidate.json').read_text())
                            for owner in ['execution', 'runtime', 'abi']})
    decoded = [codec.decode(codec.encode(roots)) for roots in external_tls_roots()]
    consumer_id, provider_id = [item.content_digest for item in decoded]
    contexts = {item.content_digest: RootContext(item.roots) for item in decoded}
    for context in contexts.values():
        context.verify_abi()
    runtime, selection, tls = [runtime_package_module(name) for name in ['linking', 'selection', 'tls']]
    consumer, provider = contexts[consumer_id], contexts[provider_id]
    graph = type(consumer.abi_graph)(consumer.abi, consumer_id,
        {a: c.abi for a, c in contexts.items()},
        families={a: runtime.family(c.sections[2]['manifest']['key']) for a, c in contexts.items()})
    def execution(a, x, b, y):
        return contexts[a].types.digest(x) == contexts[b].types.digest(y)
    def nominal(a, x, b, y):
        return graph.boundary_compatible(x, y, a, b)
    def data(a, x, b, y):
        return graph.data_boundary_compatible(x, y, a, b)
    def signature(a, x, b, y):
        return graph.signature_compatible(x, y, a, b)
    def unsupported_comparison(*args):
        raise ValueError('TLS fixture contains no COMDAT/common/body-comparison request')
    runtime_contexts = {a: runtime.Context(site=c.abi['identity'], execution=c.execution, nominal=c.nominal,
        function=c.function, symbol=c.runtime_symbol, execution_equal=c.types.equal,
        nominal_compatible=c.abi_graph.boundary_compatible, storage_layout=c.memory_layout,
        symbol_body=unsupported_comparison, symbol_identity=unsupported_comparison,
        abi_entity=c.abi_entity, target_entity=c.target_entity, native_symbol=c.native_symbol,
        nominal_layout=c.abi_graph.layout, signature_compatible=c.abi_graph.signature_compatible,
        grants=frozenset({'memory'}))  # Explicit trusted fixture policy, not producer authorization.
        for a, c in contexts.items()}
    modules = {a: {n: c.sections[n] for n in runtime.ROOTS} for a, c in contexts.items()}
    order = [provider_id, consumer_id]
    selected = selection.select_definitions(modules, runtime_contexts, order, execution, nominal,
                                           data_compatible=data, signature_compatible=signature)
    deployment = {'payload_revision': 1, 'modules': [
        {'key': contexts[a].sections[2]['manifest']['key'], 'artifact': a} for a in order],
        'edges': [{'source': consumer_id, 'slot': 0, 'target': provider_id, 'entities': [
            {'declaration': 901, 'entity_kind': 'symbol', 'kind': 'export', 'export': 88}]}]}
    bound = runtime.bind_deployment({a: c.sections[2] for a, c in contexts.items()}, deployment,
        execution, nominal, data_compatible=data, signature_compatible=signature)
    registry = tls.Registry({a: {'context': c, 'generation': 9, 'pins': 1, 'phase': 'prepared'}
                             for a, c in contexts.items()})
    binding = registry.bind_external(consumer_id, ref(901, 0), deployment=bound,
                                    selection=selected, contexts=contexts)
    consumer.install_external_tls({(0, 901): (registry, binding)})
    for context in contexts.values():
        context.verify_execution()
    def validate(actual):
        if set(actual) != set(contexts) or any(actual[a] is not contexts[a] for a in contexts):
            raise ValueError('all-root validation must use the original contexts')
        for a, context in actual.items():
            context.assert_snapshot()
            runtime.validate(modules[a], runtime_contexts[a])
    registry.admit_metadata(contexts, validate)
    return consumer, provider, registry, binding, bound, selected


class CandidateExternalTlsTests(unittest.TestCase):
    def test_actual_codec_deployment_selection_and_provider_owned_metadata(self):
        consumer, provider, registry, binding, bound, selected = joined_tls()
        target = consumer.target_entity('tls', ref(901, 0))
        self.assertIs(target.provider_context, provider)
        self.assertIs(deepcopy(target), target)
        self.assertEqual((binding.declaration, binding.symbol, binding.segment), (901, 74, 37))
        self.assertEqual(target['storage']['layout'], {'some': ref(6)})  # PROVIDER namespace.
        self.assertNotIn(('self', 37), consumer.tls_segments)
        self.assertEqual(bound['bindings'][binding.consumer, 0, 901], (binding.provider, 74))
        self.assertEqual(selected.symbol(binding.provider, 74), (binding.provider, 74))
        self.assertEqual(registry.modules[binding.provider]['phase'], 'admitted')
        with self.assertRaisesRegex(Exception, 'RT_TLS_NOT_PUBLISHED'):
            registry.address_external(11, binding, 0)

    def test_two_logical_threads_source_initializer_once_and_worker_migration(self):
        consumer, provider, registry, binding, _, _ = joined_tls()
        machines, pointers, events = {}, {}, []
        def invoke(artifact, function, thread):
            self.assertEqual((artifact, function), (binding.provider, ref(5)))
            initializer = Machine(provider.execution_checked)
            initializer.start(function['id'], [])
            self.assertEqual(initializer.run()['kind'], 'return')
            events.append(('initialize', thread))
        for thread in [11, 12]:
            def raw(machine, values, tid=thread):
                pointer = registry.address_external(tid, binding, values[0].data)
                original = pointers[tid]
                self.assertEqual((pointer.object, pointer.generation, pointer.bits),
                                 (tid, original.generation, original.address))
                self.assertIsNone(original.access_range)  # Object bounds are not LLVM inrange.
                events.append(('raw', tid))
                return [Value(ref(4), 'concrete', original)]
            def initialize(machine, values, tid=thread):
                registry.initialize_external(tid, binding, machine.stack[-1].activation, invoke)
                return []
            machine = Machine(consumer.execution_checked, imports={('self', 0): raw, ('self', 1): initialize})
            machine.memory.next_address = thread * 0x10000
            pointer = machine.memory.allocate(4, 4)
            machine.memory.raw_store(pointer, Raw.integer(32, 8))
            machines[thread], pointers[thread] = machine, pointer
            registry.reserve(thread, binding.provider, 37, {'id': thread, 'generation': pointer.generation,
                'address': pointer.address, 'size': 4, 'live': True})
        lease = registry.begin_initialization(registry.modules, 11)
        self.assertEqual(registry.address_external(11, binding, 0, initialization=lease).bits, pointers[11].address)
        with self.assertRaisesRegex(Exception, 'RT_TLS_NOT_PUBLISHED'):
            registry.address_external(12, binding, 0, initialization=lease)
        registry.publish_initialization(lease)
        # A raw lookup alone neither runs initialization nor mutates its guard.
        before = registry.address_external(11, binding, 0)
        self.assertEqual(events, [])
        for thread in [11, 12]:
            machines[thread].start(0, [Value(ref(17), 'concrete', 27)])
            self.assertEqual(machines[thread].run()['values'][0].data, 35)
            self.assertFalse(registry.initialize_external(thread, binding, 'later-activation', invoke))
        with ThreadPoolExecutor(max_workers=2) as workers:
            after, other = list(workers.map(lambda tid: registry.address_external(tid, binding, 0), [11, 12]))
        self.assertEqual(before, after)
        self.assertNotEqual(after.bits, other.bits)
        self.assertEqual(events, [('initialize', 11), ('raw', 11), ('initialize', 12), ('raw', 12)])

    def test_forged_wrong_consumer_generation_and_reservation_reject(self):
        consumer, provider, registry, binding, _, _ = joined_tls()
        with self.assertRaisesRegex(Exception, 'RT_TLS_BINDING_AUTHORITY'):
            registry.metadata_external(replace(binding))
        clone = RootContext(consumer.sections)
        clone.verify_abi()
        with self.assertRaisesRegex(Exception, 'RT_TLS_BINDING_CONSUMER'):
            clone.install_external_tls({(0, 901): (registry, binding)})
        with self.assertRaisesRegex(Exception, 'RT_TLS_BINDING_CONSUMER'):
            registry.metadata_external(binding, consumer, ref(900, 0))
        registry.modules[binding.provider]['phase'] = 'published'
        with self.assertRaisesRegex(Exception, 'RT_TLS_UNRESERVED'):
            registry.address_external(11, binding, 0)
        registry.modules[binding.provider]['generation'] += 1
        with self.assertRaisesRegex(Exception, 'RT_TLS_PROVIDER_STALE'):
            consumer.target_entity('tls', ref(901, 0))
        with self.assertRaisesRegex(Exception, 'RT_TLS_PROVIDER_STALE'):
            registry.address_external(11, binding, 0)

    def test_source_child_authorization_and_failed_constructor_lease_drain(self):
        consumer, provider, registry, binding, _, _ = joined_tls()
        for thread in [11, 12]:
            registry.reserve(thread, binding.provider, 37, {'id': thread, 'generation': 1,
                'address': thread * 0x10000, 'size': 4, 'live': True})
        lease = registry.begin_initialization(registry.modules, 11)
        with self.assertRaisesRegex(Exception, 'RT_TLS_NOT_PUBLISHED'):
            registry.address_external(12, binding, 0, initialization=lease)
        # Trusted reference adapter for actual source-created/captured entry.
        # This is not a serialized TID/capability or native std::thread witness.
        registry.delegate_initialization(lease, 11, 12)
        with ThreadPoolExecutor(max_workers=1) as worker:
            captured = worker.submit(registry.address_external, 12, binding, 0, initialization=lease).result()
        self.assertEqual(captured.bits, 12 * 0x10000)
        registry.retain_escape(lease, captured)
        registry.fail_initialization(lease)
        with self.assertRaisesRegex(Exception, 'RT_TLS_INIT_NOT_QUIESCENT'):
            registry.finish_failed_cleanup(lease)
        self.assertEqual(registry.address_external(12, binding, 0, initialization=lease), captured)
        registry.complete_child(lease, 12)
        with self.assertRaisesRegex(Exception, 'RT_TLS_INIT_NOT_QUIESCENT'):
            registry.finish_failed_cleanup(lease)
        registry.release_escape(lease, captured)
        registry.finish_failed_cleanup(lease)
        self.assertEqual(registry.modules[binding.provider]['phase'], 'dead')
        self.assertFalse(registry.slots[12, binding.provider, 37]['live'])


if __name__ == '__main__':
    unittest.main()
