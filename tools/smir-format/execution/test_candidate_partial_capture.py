"""Actual ABI capture graph -> runtime partial builder -> SEM live validation."""
from copy import deepcopy
import json
import unittest

from common import Reject, SPEC
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.live import Registry as LiveRegistry, validate
from candidate.type_system import ref
from candidate.values import Pointer
from test_candidate_journal_factory import capture_factory
from test_candidate_storage_join import reference_image
from candidate_fixtures import declared_abi_source


class CandidatePartialCaptureTests(unittest.TestCase):
    def test_actual_formal_environment_survives_detach_without_retagging_opaque_journal(self):
        codec = runtime_package_module('wire').PRIMITIVES.CandidateCodec({owner:
            json.loads((SPEC / 'schema' / owner / 'candidate.json').read_text())
            for owner in ['execution', 'runtime', 'abi']})
        roots = capture_factory()
        roots[10]['journals'][0]['params'][0]['id'] = 17
        roots[10]['journals'][0]['params'][1]['id'] = 3
        decoded = codec.decode(codec.encode(roots))
        context = RootContext(decoded.roots)
        context.verify_abi(); context.verify_execution()
        machine = reference_image(context)
        source = machine.symbols[('self', 1)]
        storage = machine.memory.objects[source.origin]
        # Trusted reference translation from actual reserved SEM object to the
        # runtime's numeric object registry. This is not an artifact certificate.
        objects = {1: {'address': source.address, 'size': storage['size'],
                       'generation': source.generation, 'live': True}}
        pointer = Pointer(source.address, 1, source.generation)
        module = decoded.content_digest
        def program(owner, reference):
            self.assertEqual(owner, module)
            return (owner, reference['id']), context.abi_entity('journal', reference)
        def nominal(owner, reference):
            self.assertEqual(owner, module)
            return context.nominal(reference)
        pointer_facts = LiveRegistry(pointers={('data', 1, source.generation): {'live': True}})
        thread_for_activation = {101: 11, 201: 12}
        def value_check(owner, value, activation):
            self.assertEqual(owner, module)
            return validate(value, context.types, pointer_facts, thread_for_activation[activation], activation)
        lifetimes = runtime_package_module('lifetimes').Registry(objects, program, {1: {'live': True}})
        builders = runtime_package_module('partials').Registry(lifetimes, lambda owner: context.types,
            nominal, value_check, modules={module: {'generation': 1, 'pins': 1}})
        captures = [{'parameter': 17, 'value': {'type': ref(17), 'payload': {'kind': 'scalar', 'bits': '2a000000'}}},
            {'parameter': 3, 'value': {'type': ref(4), 'payload': {'kind': 'pointer', 'address': source.address,
                'object': {'some': 1}, 'generation': source.generation, 'domain': 'data', 'range': None, 'binding_permit': None}}}]
        counts = [{'slot': 0, 'count': 1}]
        old_owner = {'thread': 11, 'activation': 101, 'generation': 1, 'instance': 7}
        new_owner = {'thread': 12, 'activation': 201, 'generation': 1, 'instance': 8}
        with self.assertRaisesRegex(ValueError, 'RT_PARTIAL_CAPTURES'):
            builders.begin(module, ref(0), pointer, old_owner, list(reversed(captures)), counts, [1])
        wrong_type = deepcopy(captures)
        wrong_type[0]['value'] = deepcopy(captures[1]['value'])
        with self.assertRaisesRegex(ValueError, 'RT_PARTIAL_CAPTURE_TYPE'):
            builders.begin(module, ref(0), pointer, old_owner, wrong_type, counts, [1])
        old = builders.begin(module, ref(0), pointer, old_owner, captures, counts, [1])
        saved = builders.detach(old, old_owner)
        self.assertEqual(saved['captures'], captures)
        self.assertEqual(saved['completed'], [])  # No fabricated constructor completion.
        with self.assertRaisesRegex(ValueError, 'RT_PARTIAL_JOURNAL'):
            builders.detach(old, old_owner)
        fresh = builders.begin(module, ref(0), pointer, new_owner, deepcopy(captures), counts, [1])
        self.assertIsNot(fresh, old)
        self.assertNotEqual(fresh.identity, old.identity)
        checkpoint = builders.snapshot(fresh, new_owner, transition=2)
        self.assertEqual(checkpoint['captures'], captures)
        self.assertEqual(checkpoint['event_sequences'], [])
        self.assertEqual(checkpoint['state']['entries'], [])
        # Project the actual issued active-owner facts, not snapshot numerical IDs.
        active = builders.active[id(fresh)]['owner']
        handles = {('journal', old.identity, 1): {'live': False, 'thread': 11, 'activation': 101},
                   ('journal', fresh.identity, active['generation']): {'live': True,
                       'thread': active['thread'], 'activation': active['activation']}}
        registry = LiveRegistry(handles=handles)
        value = {'type': ref(600), 'payload': {'kind': 'handle', 'kind_name': 'journal',
                 'identity': fresh.identity, 'generation': active['generation']}}
        validate(value, context.types, registry, 12, 201)
        with self.assertRaisesRegex(Reject, 'live_handle_owner'):
            validate(value, context.types, registry, 11, 101)
        stale = deepcopy(value); stale['payload']['identity'] = old.identity
        with self.assertRaisesRegex(Reject, 'live_handle_owner'):
            validate(stale, context.types, registry, 11, 101)
        builders.detach(fresh, new_owner)
        cleanup_owner = {**new_owner, 'instance': 9}
        cleanup = builders.claim_partial(pointer, cleanup_owner)
        cleanup_state = builders.snapshot(cleanup, cleanup_owner, transition=3)
        self.assertEqual(cleanup_state['captures'], captures)
        self.assertEqual(builders.cleanup_order(cleanup, cleanup_owner), [])
        self.assertEqual(builders.finish_cleanup(cleanup, cleanup_owner)['phase'], 'dead')
        # Capture metadata remains a value after lifetime end; it cannot keep
        # source storage alive or authorize another construction/destruction.
        objects[1]['live'] = False
        pointer_facts.pointers[('data', 1, source.generation)]['live'] = False
        validate(captures[1]['value'], context.types, pointer_facts, 12, 201)
        with self.assertRaisesRegex(ValueError, 'RT_PARTIAL_POINTER'):
            builders.begin(module, ref(0), pointer, new_owner, captures, counts, [1])

    def test_actual_matching_abi_exception_capture_rejects_present_opaque_value(self):
        from unittest.mock import patch
        roots = capture_factory()
        abi, _ = declared_abi_source()
        # The actual producer supplies the builtin lease nominal and layout.
        roots[10]['types'].append(deepcopy(next(t for t in abi['types'] if t['id'] == 7)))
        roots[10]['types'].sort(key=lambda t: t['id'])
        roots[10]['layouts'].append(deepcopy(next(t for t in abi['layouts'] if t['id'] == 7)))
        roots[10]['layouts'].sort(key=lambda t: t['id'])
        roots[10]['journals'][0]['params'] = [{'id': 17, 'type': ref(7)}]
        signature = next(t for t in roots[1]['types'] if t['id'] == 601)
        signature.update(params=[ref(4), ref(7)], param_noundef=[False, False])
        codec = runtime_package_module('wire').PRIMITIVES.CandidateCodec({owner:
            json.loads((SPEC / 'schema' / owner / 'candidate.json').read_text())
            for owner in ['execution', 'runtime', 'abi']})
        decoded = codec.decode(codec.encode(roots))
        context = RootContext(decoded.roots)
        context.verify_abi(); context.verify_execution()
        machine = reference_image(context)
        source = machine.symbols[('self', 1)]
        module = decoded.content_digest
        objects = {1: {'address': source.address, 'size': 4, 'generation': source.generation, 'live': True}}
        def program(owner, reference):
            self.assertEqual(owner, module)
            return (owner, reference['id']), context.abi_entity('journal', reference)
        def nominal(owner, reference):
            self.assertEqual(owner, module)
            return context.nominal(reference)
        def value_check(owner, value, activation):
            self.assertEqual(owner, module)
            return validate(value, context.types, LiveRegistry(), 11, activation)
        lifetimes = runtime_package_module('lifetimes').Registry(objects, program, {1: {'live': True}})
        builders = runtime_package_module('partials').Registry(lifetimes, lambda owner: context.types,
            nominal, value_check, modules={module: {'generation': 1, 'pins': 1}})
        value = {'type': ref(7), 'payload': {'kind': 'poison'}}
        value_check(module, value, 101)  # Valid typed opaque SSA value; no fabricated handle.
        owner = {'thread': 11, 'activation': 101, 'generation': 1, 'instance': 7}
        self.assertTrue(context.types.equal(value['type'], context.nominal(ref(7))['execution']['some']))
        with patch.object(context.types, 'contains_value_kind', wraps=context.types.contains_value_kind) as predicate:
            with self.assertRaisesRegex(ValueError, 'RT_PARTIAL_CAPTURE_TYPE'):
                builders.begin(module, ref(0), Pointer(source.address, 1, source.generation), owner,
                    [{'parameter': 17, 'value': value}], [{'slot': 0, 'count': 1}], [1])
            predicate.assert_called_once()
        self.assertEqual(builders.items, {})


if __name__ == '__main__':
    unittest.main()
