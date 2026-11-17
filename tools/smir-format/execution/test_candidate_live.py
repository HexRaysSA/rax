"""Live values are typed state, never self-issued pointer or handle authority."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.bindings import runtime_package_module
from candidate.live import Registry, validate
from candidate.type_system import Types, ref
from test_candidate import fixture


class CandidateLiveTests(unittest.TestCase):
    def test_runtime_owner_rethrow_issues_new_thread_facade_before_live_projection(self):
        runtime = runtime_package_module('exceptions')
        objects = {1: {'live': True, 'address': 4096, 'size': 4, 'alignment': 4, 'generation': 1},
                   2: {'live': True, 'address': 8192, 'size': 32, 'alignment': 8, 'generation': 1}}
        # Trusted reference facts, not native metadata or an artifact producer.
        owner = runtime.Registry(1, objects, lambda token: token == 'default',
                                 lambda payload, certificate: certificate == ('fixture.T', 1), 'default')
        original = owner.allocate(11, object_id=1, nominal='fixture.T', destructor='fixture.dtor', proxy_object=2)

        def projection(facade):
            # This oracle never reuses IDs. The fixture factory chooses id as
            # generation; file data cannot populate the registered thread facts.
            handles = {('exception', identity, identity): {'live': fact['refs'] > 0,
                       'thread': fact['thread']} for identity, fact in owner.facades.items()}
            value = {'type': ref(10), 'payload': {'kind': 'handle', 'kind_name': 'exception',
                     'identity': facade.identity, 'generation': facade.identity}}
            return value, Registry(handles=handles)

        value, registry = projection(original)
        validate(value, self.types, registry, 11)
        with self.assertRaisesRegex(Reject, 'live_handle_owner'):
            validate(value, self.types, registry, 12)
        with self.assertRaisesRegex(ValueError, 'RT_EH_STALE_FACADE'):
            owner.object_address(runtime.Facade(original.process, original.identity, 12), 12)
        pointer = owner.object_address(original, 11)
        owner.complete_construction(original, 11, ('fixture.T', 1))
        owner.raise_initial(original, 11)
        owner.select_catch(original, 11, pointer)
        owner.begin_catch(original, 11)
        retained = owner.current_owner(11)
        owner.end_catch(original, 11)
        fresh = owner.owner_rethrow(retained, 12)
        self.assertNotEqual(fresh.identity, original.identity)
        self.assertEqual(owner.object_address(fresh, 12), pointer)
        value, registry = projection(fresh)
        validate(value, self.types, registry, 12)
        with self.assertRaisesRegex(Reject, 'live_handle_owner'):
            validate(value, self.types, registry, 11)

    def setUp(self):
        self.types = Types(fixture()[0])
        self.registry = Registry(pointers={('data', 1, 2): {'live': False}},
            handles={('journal', 7, 3): {'live': True, 'thread': 11, 'activation': 19}})

    def test_tombstone_range_limit_and_no_authority_mint(self):
        pointer = {'type': ref(7), 'payload': {'kind': 'pointer', 'address': 2**64 - 1,
            'object': {'some': 1}, 'generation': 2, 'domain': 'data',
            'range': {'some': {'lower': 2**64 - 1, 'upper': 0, 'upper_is_limit': True, 'empty': False}},
            'binding_permit': None}}
        self.assertEqual(validate(pointer, self.types, self.registry, 11), pointer)
        invalid = deepcopy(pointer)
        invalid['payload']['range']['some']['upper'] = 1
        with self.assertRaisesRegex(Reject, 'live_range_limit_encoding'):
            validate(invalid, self.types, self.registry, 11)
        invalid = deepcopy(pointer)
        invalid['payload']['generation'] = 3
        with self.assertRaisesRegex(Reject, 'live_pointer_registry'):
            validate(invalid, self.types, self.registry, 11)
        self.assertEqual(len(self.registry.pointers), 1)

    def test_raw_origin_bits_and_component_poison(self):
        raw = {'type': ref(4), 'payload': {'kind': 'raw', 'bits': '1000000000000000',
            'poison': '0000000000000000', 'undef': '0000000000000000', 'origins': [
            {'offset': 0, 'length': 64, 'object': {'some': 1}, 'generation': 2, 'pointer_bits': 16,
             'source_bit': 0, 'domain': 'data', 'range': None, 'binding_permit': None}]}}
        validate(raw, self.types, self.registry, 11)
        raw['payload']['bits'] = '1100000000000000'
        with self.assertRaisesRegex(Reject, 'live_origin_bits'):
            validate(raw, self.types, self.registry, 11)
        aggregate = {'type': ref(9), 'payload': {'kind': 'aggregate', 'elements': [
            {'type': ref(1), 'payload': {'kind': 'poison'}},
            {'type': ref(2), 'payload': {'kind': 'scalar', 'bits': '2a000000'}}]}}
        validate(aggregate, self.types, self.registry, 11)
        aggregate['payload']['elements'][1]['type'] = ref(1)
        with self.assertRaisesRegex(Reject, 'live_component_type'):
            validate(aggregate, self.types, self.registry, 11)

    def test_handle_thread_activation_and_generation(self):
        value = {'type': ref(14), 'payload': {'kind': 'handle', 'kind_name': 'journal', 'identity': 7, 'generation': 3}}
        validate(value, self.types, self.registry, 11, 19)
        with self.assertRaisesRegex(Reject, 'live_handle_owner'):
            validate(value, self.types, self.registry, 12, 19)
        with self.assertRaisesRegex(Reject, 'live_handle_activation'):
            validate(value, self.types, self.registry, 11, 20)
        value['payload']['generation'] = 4
        with self.assertRaisesRegex(Reject, 'live_handle_registry'):
            validate(value, self.types, self.registry, 11, 19)

    def test_binding_permit_numbers_do_not_restore_authority(self):
        from candidate.memory import GuestFault
        value = {'type': ref(16), 'payload': {'kind': 'pointer', 'address': 2,
                 'object': {'some': 1}, 'generation': 2, 'domain': 'code', 'range': None,
                 'binding_permit': {'some': 7}}}
        with self.assertRaises(GuestFault) as caught:
            validate(value, self.types, self.registry, 11)
        self.assertEqual(caught.exception.code, 'code_address_unavailable')
        self.assertFalse(caught.exception.language_ub)
        value['payload']['binding_permit'] = {'some': 0}
        with self.assertRaisesRegex(Reject, 'live_binding_permit'):
            validate(value, self.types, self.registry, 11)


if __name__ == '__main__':
    unittest.main()
