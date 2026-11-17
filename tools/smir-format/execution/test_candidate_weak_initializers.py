"""Actual fixed-link absence proofs, not numeric-zero symbol certificates."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

from common import Reject, SPEC
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.values import Pointer
from candidate.type_system import ref
from test_candidate import decl, operation
from test_candidate_initializers import initializer_roots, evaluate
from test_candidate_storage_join import reference_image, storage_wrapper


def weak_modules(kind):
    code = kind == 'function'
    ops = [operation('address_of', [decl(0, 600 if code else 4)], symbol=ref(901, 0)),
           operation('ptrtoint', [decl(1, 5)], [0])]
    consumer = initializer_roots(ops, extra_types=[{'id': 600, 'kind': 'code_ptr', 'signature': ref(12)}] if code else [])
    provider = storage_wrapper()
    for name, roots in [('consumer', consumer), ('provider', provider)]:
        roots[2]['manifest']['key']['name'] = name
        roots[2]['symbols'][0]['name'] = name + '_helper'
    consumer[2]['manifest']['dependencies'] = [{'slot': 0, 'key': deepcopy(provider[2]['manifest']['key']),
        'minimum_minor': 0, 'maximum_minor': None, 'site': provider[10]['identity'], 'declarations': [
            {'id': 901, 'kind': 'symbol', 'symbol_kind': kind, 'source_linkage': 'cpp' if code else 'c',
             'namespace': 'example', 'name': 'missing_' + kind, 'execution': {'some': ref(12 if code else 304)},
             'nominal': {'some': ref(12 if code else 1)}, 'abi_signature': {'some': ref(0)} if code else None,
             'weak': True}]}]
    CandidateCodec = runtime_package_module('wire').PRIMITIVES.CandidateCodec
    codec = CandidateCodec({owner: json.loads((SPEC / 'schema' / owner / 'candidate.json').read_text())
                           for owner in ['execution', 'runtime', 'abi']})
    decoded = [codec.decode(codec.encode(roots)) for roots in [consumer, provider]]
    contexts = {item.content_digest: RootContext(item.roots) for item in decoded}
    for context in contexts.values():
        context.verify_abi(); context.verify_execution()
    consumer_id, provider_id = [item.content_digest for item in decoded]
    runtime, selection, reservations = [runtime_package_module(name) for name in ['linking', 'selection', 'reservations']]
    consumer, provider = contexts[consumer_id], contexts[provider_id]
    graph = type(consumer.abi_graph)(consumer.abi, consumer_id, {a: c.abi for a, c in contexts.items()},
        families={a: runtime.family(c.sections[2]['manifest']['key']) for a, c in contexts.items()})
    def execution(a, x, b, y):
        return contexts[a].types.digest(x) == contexts[b].types.digest(y)
    def nominal(a, x, b, y):
        return graph.boundary_compatible(x, y, a, b)
    def data(a, x, b, y):
        return graph.data_boundary_compatible(x, y, a, b)
    def signature(a, x, b, y):
        return graph.signature_compatible(x, y, a, b)
    def unsupported(*args):
        raise ValueError('Weak initializer witness has no COMDAT/common body comparison')
    bindings = {a: runtime.Context(site=c.abi['identity'], execution=c.execution, nominal=c.nominal,
        function=c.function, symbol=c.runtime_symbol, execution_equal=c.types.equal,
        nominal_compatible=c.abi_graph.boundary_compatible, storage_layout=c.memory_layout,
        symbol_body=unsupported, symbol_identity=unsupported, abi_entity=c.abi_entity,
        target_entity=c.target_entity, native_symbol=c.native_symbol, nominal_layout=c.abi_graph.layout,
        signature_compatible=c.abi_graph.signature_compatible, grants=frozenset({'memory'}))
        for a, c in contexts.items()}
    modules = {a: {n: c.sections[n] for n in runtime.ROOTS} for a, c in contexts.items()}
    for a in contexts:
        runtime.validate(modules[a], bindings[a])
    order = [provider_id, consumer_id]
    selected = selection.select_definitions(modules, bindings, order, execution, nominal,
        data_compatible=data, signature_compatible=signature)
    deployment = {'payload_revision': 1, 'modules': [
        {'key': contexts[a].sections[2]['manifest']['key'], 'artifact': a} for a in order],
        'edges': [{'source': consumer_id, 'slot': 0, 'target': provider_id, 'entities': [
            {'kind': 'weak_null', 'entity_kind': 'symbol', 'declaration': 901}]}]}
    registry = reservations.Symbols(contexts, selected, deployment, execution, nominal,
                                   signature_compatible=signature, data_compatible=data)
    return consumer, registry


class CandidateWeakInitializerTests(unittest.TestCase):
    def test_actual_missing_weak_data_and_function_return_zero_without_exposure(self):
        for kind in ['data', 'function']:
            with self.subTest(kind=kind):
                context, registry = weak_modules(kind)
                proof = registry.reserve_weak(context, ref(901, 0))
                machine = reference_image(context)
                symbols = {**machine.symbols, ('dependency', 0, 901): proof}
                result = evaluate(context, machine, ref(9), symbols=symbols)
                self.assertEqual(result.value.data, 0)
                self.assertTrue(all(byte.bits == byte.poison == byte.undef == 0 and not byte.origins for byte in result.bytes))
                self.assertEqual((result.data_exposed, result.code_exposed), (frozenset(), frozenset()))
                self.assertEqual(machine.code_pointers, {})
                with self.assertRaisesRegex(Reject, 'initializer_(object|code)_reservation'):
                    evaluate(context, machine, ref(9), symbols={**symbols, ('dependency', 0, 901):
                        Pointer(0, domain='data' if kind == 'data' else 'code')})

    def test_issued_absence_rejects_forged_cap_wrong_reference_and_cloned_context(self):
        context, registry = weak_modules('data')
        proof = registry.reserve_weak(context, ref(901, 0))
        machine = reference_image(context)
        with self.assertRaisesRegex(Exception, 'RT_WEAK_AUTHORITY'):
            evaluate(context, machine, ref(9), symbols={**machine.symbols, ('dependency', 0, 901): replace(proof)})
        clone = RootContext(context.sections)
        clone.verify_abi(); clone.verify_execution()
        with self.assertRaisesRegex(Exception, 'RT_WEAK_CONSUMER'):
            evaluate(clone, reference_image(clone), ref(9), symbols={**machine.symbols, ('dependency', 0, 901): proof})
        with self.assertRaisesRegex(Exception, 'RT_WEAK_CONSUMER'):
            registry.verify_weak(proof, context, ref(900, 0))

    def test_same_accepted_provider_snapshot_mutation_invalidates_absence_proof(self):
        context, registry = weak_modules('data')
        proof = registry.reserve_weak(context, ref(901, 0))
        provider = next(candidate for candidate in registry.contexts.values() if candidate is not context)
        provider.sections[2]['manifest']['key']['name'] = 'tampered'
        with self.assertRaisesRegex(Reject, 'context_snapshot_changed'):
            evaluate(context, reference_image(context), ref(9), symbols={('dependency', 0, 901): proof})


if __name__ == '__main__':
    unittest.main()
