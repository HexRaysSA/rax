"""Boundary, interleaving and independent-host witness checks. Missing C++ fails."""
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from bridge import BridgeCall, verify_bridge
from catalog import BY_NAME, verify_import
from check import SPEC, check_fixtures, check_sources
from link import (admit_code_token, apply_relocations, initialization_order,
                  relocate, resolve)
from memory import ByteMemory, CAS_FAILURES, verify_access
from package import decode_locator, encode_locator, select_runtime
from protocols import (CodePublication, CodeRegistry, EffectFrontier, MemoryLifetime, ModuleLifetime,
                       WaitQueue, Workers, verify_state)
from schema import ContractError, SCHEMAS, audit_schema, canonical, decode
from process import Termination, encode_jmp_buffer, longjmp, verify_termination
from services import to_nanoseconds, validate_request

HERE = Path(__file__).resolve().parent


def fixture(name):
    return json.loads((SPEC / 'conformance/runtime' / f'{name}.json').read_text())['document']


class ContractTests(unittest.TestCase):
    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(ContractError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_fixture_corpus(self):
        counts = check_fixtures()
        self.assertEqual(sum(counts.values()), 87)
        for surface in ('memory', 'link', 'package', 'state', 'carrier'):
            self.assertGreater(counts[surface, 'accepted'], 0)
            self.assertGreater(counts[surface, 'rejected'], 0)

    def test_primary_source_hashes(self):
        self.assertEqual(check_sources(), 8)

    def test_canonical_transport(self):
        document = {'x': [0, 2**64 - 1, -2**63, None, False, '\u00e9', '\n']}
        encoded = canonical(document)
        self.assertEqual(decode(encoded), document)
        for invalid in (b'{"x":1,"x":2}', b'{"x": 1}', b'{"x":1}\n',
                        b'{"x":1.0}', b'{"x":1e0}', b'{"x":-0}', b'{"x":NaN}',
                        b'{"x":"\\ud800"}', b'\xff'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ContractError):
                    decode(invalid)
        with self.assertRaises(ContractError):
            canonical({'value': 0.0})
        deep = 0
        for _ in range(65):
            deep = [deep]
        self.assert_code('DOCUMENT_DEPTH', canonical, deep)

    def test_every_atomic_order_combination(self):
        base = fixture('access-acquire')
        orders = ['none', 'relaxed', 'acquire', 'release', 'acq_rel', 'seq_cst']
        failures = ['none', 'relaxed', 'acquire', 'seq_cst']
        count = 0
        for kind in ('load', 'store', 'exchange', 'compare_exchange', 'fetch_add',
                     'fetch_sub', 'fetch_and', 'fetch_or', 'fetch_xor'):
            for order, failure in itertools.product(orders, failures):
                request = {**base, 'kind': kind, 'order': order, 'failure_order': failure}
                if order == 'none':
                    expected = kind in {'load', 'store'} and failure == 'none'
                elif kind == 'compare_exchange':
                    expected = failure in CAS_FAILURES[order]
                elif failure != 'none':
                    expected = False
                elif kind == 'load':
                    expected = order in {'relaxed', 'acquire', 'seq_cst'}
                elif kind == 'store':
                    expected = order in {'relaxed', 'release', 'seq_cst'}
                else:
                    expected = True
                try:
                    verify_access(request)
                    actual = True
                except ContractError:
                    actual = False
                self.assertEqual(actual, expected, request)
                count += 1
        self.assertEqual(count, 216)

    def test_guarded_alias_revocation(self):
        memory = MemoryLifetime()
        memory.map('A', 'backing')
        memory.map('B', 'backing')
        memory.acquire('A', 1, 'worker-1')
        memory.acquire('B', 1, 'worker-2')
        memory.revoke('A')
        self.assert_code('MAPPING_CLOSED', memory.acquire, 'A', 1, 'late')
        self.assert_code('GUARDS_ACTIVE', memory.unmap, 'A')
        memory.release('worker-1')
        memory.unmap('A')
        self.assert_code('BACKING_REFERENCED', memory.reclaim, 'backing')
        memory.revoke('B')
        self.assert_code('GUARDS_ACTIVE', memory.unmap, 'B')
        memory.release('worker-2')
        memory.unmap('B')
        memory.reclaim('backing')
        self.assert_code('BACKING_REUSED_ID', memory.map, 'new', 'backing')

    def test_stale_generation_and_exhaustion(self):
        memory = MemoryLifetime()
        memory.map('A', 'backing')
        self.assert_code('STALE_GENERATION', memory.acquire, 'A', 0, 'guard')
        memory.mappings['A'].generation = 2**64 - 1
        self.assert_code('GENERATION_EXHAUSTED', memory.revoke, 'A')
        self.assertEqual(memory.mappings['A'].state, 'open')

    def test_every_guard_release_revoke_order(self):
        for schedule in itertools.permutations(('revoke', 'release', 'unmap', 'reclaim')):
            memory = MemoryLifetime()
            memory.map('A', 'backing')
            memory.acquire('A', 1, 'g')
            for event in schedule:
                try:
                    {'revoke': lambda: memory.revoke('A'),
                     'release': lambda: memory.release('g'),
                     'unmap': lambda: memory.unmap('A'),
                     'reclaim': lambda: memory.reclaim('backing')}[event]()
                except ContractError:
                    continue
                if 'backing' in memory.reclaimed:
                    self.assertEqual(memory.mappings['A'].state, 'unmapped', schedule)
                    self.assertFalse(memory.guards, schedule)

    def test_module_leases_all_kinds(self):
        module = ModuleLifetime()
        for kind in ModuleLifetime.KINDS:
            module.acquire(kind, kind)
        module.retire()
        self.assert_code('MODULE_CLOSED', module.acquire, 'external', 'frame')
        module.acquire('nested', 'callback', parent='frame')
        self.assert_code('LEASES_ACTIVE', module.finalize)
        module.release('nested')
        for kind in ModuleLifetime.KINDS:
            module.release(kind)
        module.finalize()
        module.reclaim()
        self.assertEqual(module.state, 'retired')
        self.assert_code('MODULE_CLOSED', module.acquire, 'stale', 'code')

    def test_finalizer_failure_pins_module(self):
        module = ModuleLifetime()
        module.retire()
        module.finalize()
        module.reclaim(False)
        self.assertEqual(module.state, 'failed_pinned')
        self.assert_code('MODULE_STATE', module.reclaim)

    def test_cancel_completion_all_interleavings(self):
        for schedule in itertools.permutations(('complete', 'cancel', 'duplicate')):
            effect = EffectFrontier()
            ticket = effect.begin()
            wins = 0
            for event in schedule:
                if event == 'cancel':
                    wins += effect.cancel(ticket)
                else:
                    wins += effect.complete(ticket, 7)
            self.assertEqual(wins, 1, schedule)
            self.assertEqual(effect.next_operation, 1)
            self.assertIn(effect.effects, (0, 1))
            self.assertEqual(effect.resume()[0], 1)
            self.assert_code('TICKET_UNKNOWN', effect.complete, ticket, 7)

    def test_irreversible_effect_cannot_be_cancelled(self):
        effect = EffectFrontier()
        ticket = effect.begin()
        self.assertTrue(effect.reserve(ticket))
        self.assertFalse(effect.cancel(ticket))
        self.assert_code('TICKET_PENDING', effect.resume)
        self.assertTrue(effect.complete(ticket, 9))
        self.assertFalse(effect.complete(ticket, 10))
        self.assertEqual(effect.resume(), (1, 9))
        self.assertEqual(effect.effects, 1)

    def test_wait_check_and_wake_orders(self):
        for schedule in itertools.permutations(('wait', 'wake', 'cancel')):
            queue = WaitQueue(0)
            for event in schedule:
                if event == 'wait':
                    queue.wait('T', 0)
                elif event == 'wake':
                    queue.store_wake(1, 1)
                else:
                    queue.cancel('T')
            self.assertFalse(queue.waiters, schedule)

    def test_per_module_type_identity_required(self):
        first = fixture('link-basic')
        second = copy.deepcopy(first)
        second['module']['identity'] = 'b' * 64
        self.assert_code('SIGNATURE_IDENTITY_REQUIRED', resolve, [first, second])
        identities = {(b['module']['identity'], t): f'{t:064x}'
                      for b in (first, second) for t in b['module']['type_ids']}
        self.assert_code('DUPLICATE_STRONG', resolve, [first, second], identities)
        for symbol in second['symbols']:
            symbol['binding'] = 'weak'
        result = resolve([first, second], identities)
        self.assertTrue(all(value[0] == first['module']['identity'] for value in result.values()))
        for symbol in first['symbols']:
            symbol['binding'] = 'weak'
        result = resolve([second, first], identities)
        self.assertTrue(all(value[0] == second['module']['identity'] for value in result.values()))
        # Same local type ID with a different semantic signature is a distinct symbol.
        identities[(second['module']['identity'], 0)] = 'f' * 64
        self.assertEqual(len(resolve([first, second], identities)), 3)

    def test_dependency_init_order_and_cycle(self):
        first = fixture('link-basic')
        second = copy.deepcopy(first)
        second['module']['identity'] = 'b' * 64
        first['dependencies'] = [{key: second['module'][key] for key in ('identity', 'abi', 'profile')}]
        self.assertEqual(initialization_order([first, second]), [('b' * 64, 0), ('a' * 64, 0)])
        second['dependencies'] = [{key: first['module'][key] for key in ('identity', 'abi', 'profile')}]
        self.assert_code('DEPENDENCY_CYCLE', initialization_order, [first, second])
        self.assert_code('MISSING_DEPENDENCY', initialization_order, [first])

    def test_all_import_descriptors_and_signature_shapes(self):
        for entry in BY_NAME.values():
            descriptor = {key: entry[key] for key in
                          ('namespace', 'name', 'capability', 'blocking', 'cancellation',
                           'reentry', 'buffers')}
            descriptor.update(id=0, signature=0)
            verify_import(descriptor, (entry['params'], entry['results']))
            self.assert_code('IMPORT_SIGNATURE', verify_import, descriptor, ([], []))
        self.assertEqual(len(BY_NAME), 18)

    def test_callable_token_parity_and_null(self):
        for valid in (2, 4, 2**64 - 2):
            self.assertEqual(admit_code_token(valid), valid)
        for invalid in (0, 1, 3, 2**64 - 1, 2**64, -2, True):
            self.assert_code('CODE_TOKEN', admit_code_token, invalid)

    def test_snapshot_stale_generation(self):
        state = fixture('state-running')
        verify_state(state, 1, {'a' * 64: 1})
        self.assert_code('STALE_MEMORY_GENERATION', verify_state, state, 2)
        self.assert_code('STALE_MODULE_GENERATION', verify_state, state, 1, {'a' * 64: 2})

    def test_locator_corruption_and_overlap(self):
        payload = b'framing is not admission'
        carrier = b'\0' * 64 + payload
        record = encode_locator(64, payload)
        self.assertEqual(decode_locator(record, carrier, (0, 64)), payload)
        for index in range(64):
            corrupted = bytearray(record)
            corrupted[index] ^= 1
            with self.assertRaises(ContractError, msg=str(index)):
                decode_locator(bytes(corrupted), carrier, (0, 64))
        self.assert_code('LOCATOR_OVERLAP', decode_locator, encode_locator(0, carrier),
                         carrier, (0, 64))

    def test_runtime_discovery_fails_on_first_candidate(self):
        manifest = fixture('package-installed')
        good = {'arch': 'x86_64', 'os': 'linux', 'abi_major': 0, 'abi_minor': 1,
                'revision': 1, 'identity': 'c' * 64, 'capabilities': ['clock']}
        self.assertEqual(select_runtime([good], manifest, 'x86_64', 'linux'), good)
        bad = {**good, 'abi_major': 1}
        self.assert_code('RUNTIME_VERSION', select_runtime, [bad, good], manifest,
                         'x86_64', 'linux')
        self.assert_code('BOOTSTRAP_ARCH', select_runtime, [good], manifest, 'aarch64', 'linux')
        self.assert_code('RUNTIME_NOT_FOUND', select_runtime, [], manifest, 'x86_64', 'linux')


    def test_code_token_allocation_stale_signature_and_exhaustion(self):
        registry = CodeRegistry()
        module = 'a' * 64
        signature = 'b' * 64
        first = registry.publish(module, 1, signature, 0)
        self.assertEqual(first, 2)
        self.assertEqual(registry.publish(module, 1, signature, 1), 4)
        self.assertEqual(registry.lookup(first, {module: 1}, signature), (module, 1, 0, 'function'))
        self.assert_code('CODE_TOKEN_STALE', registry.lookup, first, {module: 2}, signature)
        self.assert_code('CODE_SIGNATURE', registry.lookup, first, {module: 1}, 'c' * 64)
        registry.next_sequence = 2**63 - 1
        self.assertEqual(registry.publish(module, 1, signature, 2), 2**64 - 2)
        self.assert_code('CODE_TOKEN_EXHAUSTED', registry.publish, module, 1, signature, 3)

    def test_relocation_token_binding_and_no_partial_publication(self):
        bundle = fixture('link-basic')
        bundle['relocations'][0].update(kind='function_token', target=0)
        module = bundle['module']['identity']
        signature = 'b' * 64
        identities = {(module, 0): signature}
        registry = CodeRegistry()
        token = registry.publish(module, 1, signature, 0)
        bindings = {0: {'value': token, 'module': module, 'generation': 1}}
        patched = apply_relocations(bundle, bindings, registry, {module: 1}, identities)
        self.assertEqual(patched['data', 0][:8], token.to_bytes(8, 'little'))
        self.assertEqual(bundle['data'][0]['bytes'], '00' * 16)
        self.assert_code('BINDING_STALE', apply_relocations, bundle, bindings, registry,
                         {module: 2}, identities)
        bundle['relocations'][0]['addend'] = 1
        self.assert_code('TOKEN_RELOCATION', apply_relocations, bundle, bindings, registry,
                         {module: 1}, identities)
        bundle['relocations'][0]['addend'] = 0
        bindings[0]['value'] = 3
        self.assert_code('CODE_TOKEN', apply_relocations, bundle, bindings, registry,
                         {module: 1}, identities)

    def test_comdat_group_identity_content_and_indivisible_selection(self):
        first = fixture('link-basic')
        second = copy.deepcopy(first)
        second['module']['identity'] = 'b' * 64
        content = b'normalized whole-group semantics supplied by admission'
        group = hashlib.sha256(content).hexdigest()
        for bundle in (first, second):
            for symbol in bundle['symbols']:
                symbol['comdat'] = group
        identities = {(b['module']['identity'], t): f'{t:064x}'
                      for b in (first, second) for t in b['module']['type_ids']}
        self.assert_code('COMDAT_CONTENT_REQUIRED', resolve, [first, second], identities)
        contents = {(b['module']['identity'], group): content for b in (first, second)}
        result = resolve([first, second], identities, contents)
        self.assertTrue(all(value[0] == 'a' * 64 for value in result.values()))
        second['symbols'][1]['comdat'] = None
        self.assert_code('COMDAT_MEMBERS', resolve, [first, second], identities, contents)
        second['symbols'][1]['comdat'] = group
        contents[('b' * 64, group)] = b'changed body'
        self.assert_code('COMDAT_CONTENT_HASH', resolve, [first, second], identities, contents)

    def test_data_relocation_bounds_and_storage_limit(self):
        bundle = fixture('link-basic')
        module = bundle['module']['identity']
        bindings = {1: {'value': 4096, 'module': module, 'generation': 1}}
        registry = CodeRegistry()
        for offset in (0, 16):
            bundle['relocations'][0]['addend'] = offset
            result = apply_relocations(bundle, bindings, registry, {module: 1}, {})
            self.assertEqual(int.from_bytes(result['data', 0][:8], 'little'), 4096 + offset)
        for offset in (-1, 17):
            bundle['relocations'][0]['addend'] = offset
            self.assert_code('RELOCATION_TARGET_BOUNDS', apply_relocations,
                             bundle, bindings, registry, {module: 1}, {})
        self.assert_code('STORAGE_LIMIT', apply_relocations,
                         bundle, bindings, registry, {module: 1}, {}, 1)


    def process_fixture(self, name):
        return json.loads((SPEC / 'conformance/runtime/process' / f'{name}.json').read_text())['document']

    def test_fresh_host_process_private_shared_restore_witness(self):
        snapshot = self.process_fixture('clone-quiescent')
        with tempfile.TemporaryDirectory(prefix='smir-clone-',
                                         dir=os.environ.get('SMIR_RUNTIME_TMPDIR')) as directory:
            snapshot_path = Path(directory) / 'snapshot.json'
            snapshot_path.write_text(json.dumps(snapshot))
            shared_path = Path(directory) / 'shared.bin'
            shared_path.write_bytes(b'parent')
            result = subprocess.run([sys.executable, str(HERE / 'process_witness.py'),
                                     str(snapshot_path), str(shared_path)],
                                    capture_output=True, text=True, check=True, timeout=10)
            child = json.loads(result.stdout)
            self.assertNotEqual(child['host_pid'], os.getpid())
            self.assertEqual(child['threads'], [201])
            self.assertEqual(child['position'], snapshot['normal'])
            self.assertEqual(child['private_first_byte'], 0xfe)
            self.assertEqual(snapshot['backings'][0]['bytes'], '01020304')
            self.assertEqual(shared_path.read_bytes(), b'childt')
            self.assertEqual(child['pending_signals'], '')

    def test_nonlocal_buffer_lifetime_and_result(self):
        record = self.process_fixture('nonlocal-live')
        buffer = encode_jmp_buffer(record)
        self.assertEqual(len(buffer), 64)
        frame = fixture('state-running')['frames'][0]
        frames, value = longjmp(record, buffer, 100, 1, [frame], 0)
        self.assertEqual(value, 1)
        self.assertEqual(frames[0]['position'], record['position'])
        self.assertEqual(frames[0]['locals'][0]['bits'], '01000000')
        self.assertEqual(frame['position']['next_operation'], 0)
        self.assert_code('JMP_WRONG_THREAD', longjmp, record, buffer, 100, 2, [frame], 5)
        stale = copy.deepcopy(frame)
        stale['module_generation'] = 2
        self.assert_code('JMP_DEAD_FRAME', longjmp, record, buffer, 100, 1, [stale], 5)
        self.assert_code('JMP_DEAD_FRAME', longjmp, record, buffer, 100, 1, [], 5)
        for index in range(64):
            corrupted = bytearray(buffer)
            corrupted[index] ^= 1
            self.assert_code('JMP_BUFFER_MISMATCH', longjmp, record, bytes(corrupted),
                             100, 1, [frame], 5)
        frame['ticket'] = {'state': 'irrevocable'}
        self.assert_code('JMP_PENDING_EFFECT', longjmp, record, buffer, 100, 1, [frame], 5)

    def test_exit_claim_once_reverse_order_and_reentrant_registration(self):
        document = self.process_fixture('termination-normal')
        registry = Termination(document)
        second = copy.deepcopy(document['registrations'][0])
        second['function_token'] = 4
        sequence = registry.register(second)
        self.assertEqual(sequence, 2)
        self.assertEqual(registry.claim()['sequence'], 2)
        self.assert_code('TERMINATION_REENTRY', registry.claim)
        self.assertEqual(registry.register(second), 3)
        registry.complete(2)
        self.assertEqual(registry.claim()['sequence'], 3)
        registry.complete(3)
        self.assertEqual(registry.claim()['sequence'], 1)
        registry.complete(1)
        self.assertIsNone(registry.claim())
        self.assert_code('TERMINATION_COMPLETION', registry.complete, 1)

    def test_independent_tls_finalizers_and_quick_exit_selection(self):
        document = self.process_fixture('termination-normal')
        registry = Termination(document)
        entry = document['registrations'][0]
        for thread in (1, 2):
            registry.register({**entry, 'kind': 'tls', 'thread': thread})
        first = registry.claim(thread=1)
        second = registry.claim(thread=2)
        self.assertNotEqual(first['sequence'], second['sequence'])
        verify_termination(registry.document)
        registry.complete(first['sequence'])
        registry.complete(second['sequence'])
        registry.document['phase'] = 'quick_exit'
        quick = registry.register({**entry, 'kind': 'quick_exit'})
        self.assertEqual(registry.claim()['sequence'], quick)
        registry.complete(quick)
        self.assertIsNone(registry.claim())


    def bridge_fixture(self):
        return json.loads((SPEC / 'conformance/runtime/bridge/bridge-ready.json').read_text())['document']

    def bridge_call(self):
        document = self.bridge_fixture()
        modules = {identity: ModuleLifetime() for identity in
                   (document['source_module'], document['target_module'])}
        call = BridgeCall(document, modules)
        call.start()
        call.foreign_returned({'address': 4096, 'bytes': 8, 'backing_generation': 1})
        return call, modules

    def conversion_frontier(self):
        return {'module': 'a' * 64, 'function': 3, 'activation': 2,
                'position': {'block': 10, 'next_operation': 1, 'predecessor': None}}

    def test_bridge_conversion_success_retains_leases_until_cleanup_commit(self):
        call, modules = self.bridge_call()
        self.assertEqual(call.document['normal_publications'], 0)
        self.assertEqual(call.document['position'], call.document['call_position'])
        for module in modules.values():
            module.retire()
            self.assert_code('LEASES_ACTIVE', module.finalize)
        call.begin_conversion(self.conversion_frontier())
        call.converted([{'id': 0, 'type': 0, 'bits': '01000000'}])
        sequence = call.suspend(self.conversion_frontier())
        verify_bridge(call.document)
        call.resume(1, 1, sequence)
        self.assertEqual(call.document['normal_publications'], 0)
        for module in modules.values():
            self.assert_code('LEASES_ACTIVE', module.finalize)
        call.cleanup_complete()
        self.assertEqual(call.document['position'], call.document['normal'])
        self.assertEqual(call.document['normal_publications'], 1)
        self.assertEqual(call.document['native_calls'], 1)
        for module in modules.values():
            module.finalize()
            module.reclaim()
        self.assert_code('BRIDGE_STAGE', call.cleanup_complete)
        self.assert_code('BRIDGE_STAGE', call.start)

    def test_bridge_conversion_throw_unwinds_once_and_preserves_exception_owner(self):
        call, modules = self.bridge_call()
        call.begin_conversion(self.conversion_frontier())
        for module in modules.values():
            module.retire()
        call.raise_exception(17, 'a' * 64)
        call.cleanup_complete()
        self.assertEqual(call.document['stage'], 'unwind_ready')
        self.assertEqual(call.document['position'], call.document['unwind'])
        self.assertEqual(call.document['normal_publications'], 0)
        self.assertEqual(call.document['native_calls'], 1)
        self.assertEqual(call.document['source_result'], [])
        modules['b' * 64].finalize()
        self.assert_code('LEASES_ACTIVE', modules['a' * 64].finalize)
        call.release_exception()
        modules['a' * 64].finalize()
        self.assert_code('BRIDGE_EXCEPTION_RELEASE', call.release_exception)

    def test_bridge_conversion_suspend_resume_does_not_reenter_native(self):
        call, modules = self.bridge_call()
        frontier = self.conversion_frontier()
        call.begin_conversion(frontier)
        sequence = call.suspend(frontier)
        verify_bridge(call.document)
        self.assert_code('BRIDGE_SUSPENDED', call.start)
        self.assert_code('BRIDGE_WRONG_THREAD', call.resume, 2, 1, sequence)
        self.assert_code('BRIDGE_STALE_GENERATION', call.resume, 1, 2, sequence)
        self.assertEqual(call.resume(1, 1, sequence), ('conversion_pending', frontier))
        self.assert_code('BRIDGE_STALE_RESUME', call.resume, 1, 1, sequence)
        call.converted([])
        call.cleanup_complete()
        self.assertEqual(call.document['native_calls'], 1)
        self.assertEqual(call.document['normal_publications'], 1)
        self.assertTrue(all(not module.leases for module in modules.values()))

    def test_bridge_conversion_cancellation_is_recorded_deferred_without_replay(self):
        call, modules = self.bridge_call()
        call.begin_conversion(self.conversion_frontier())
        self.assertTrue(call.request_cancel())
        self.assertFalse(call.request_cancel())
        self.assertEqual(call.document['cancellation'], 'deferred')
        call.converted([])
        call.cleanup_complete()
        self.assertEqual(call.document['native_calls'], 1)
        self.assertEqual(call.document['normal_publications'], 1)
        self.assertTrue(all(not module.leases for module in modules.values()))

    def test_bridge_foreign_raise_and_cleanup_throw_paths(self):
        call, modules = self.bridge_call()
        # Standalone native raise comes before result conversion; use a fresh entry.
        document = self.bridge_fixture()
        other_modules = {identity: ModuleLifetime() for identity in modules}
        foreign = BridgeCall(document, other_modules)
        foreign.start()
        foreign.raise_exception(7, 'b' * 64)
        foreign.cleanup_complete()
        self.assertEqual(foreign.document['native_calls'], 1)
        self.assertEqual(foreign.document['normal_publications'], 0)
        foreign.release_exception()
        call.begin_conversion(self.conversion_frontier())
        call.converted([])
        call.raise_exception(11, 'a' * 64)  # required normal cleanup throws
        self.assertEqual(call.document['normal_publications'], 0)
        call.raise_exception(12, 'b' * 64)  # cleanup throws while unwinding
        self.assertEqual(call.document['stage'], 'terminated')
        self.assertEqual(call.document['native_calls'], 1)
        self.assertTrue(all(module.leases for module in modules.values()))

    def test_unwind_cleanup_can_own_worker_or_block_with_retained_exception(self):
        state = fixture('state-running')
        state['frames'][0].update(status='unwinding', exception=2)
        verify_state(state)
        blocked = fixture('state-pending')
        blocked['frames'][0].update(status='unwinding', exception=2)
        verify_state(blocked)

    def test_immediate_exit_invokes_no_module_or_tls_finalizers(self):
        document = self.process_fixture('termination-normal')
        registry = Termination(document)
        entry = document['registrations'][0]
        registry.register({**entry, 'kind': 'cxa'})
        registry.register({**entry, 'kind': 'tls', 'thread': 1})
        registry.document['phase'] = 'immediate_exit'
        self.assertIsNone(registry.claim())
        self.assertIsNone(registry.claim(module='a' * 64))
        self.assertIsNone(registry.claim(thread=1))
        self.assertTrue(all(r['state'] == 'pending' for r in registry.document['registrations']))

    def test_service_argument_boundaries(self):
        valid = [('memory.map', [1, 1, 0], None),
                 ('file.open', [4096, 1, 3, 0o644], {0: b'x'}),
                 ('file.read', [1, 0, 0], None),
                 ('entropy.fill', [0, 0], None),
                 ('module.open', [4096, 64], {0: b'a' * 64}),
                 ('thread.spawn', [2, 0, 0], None),
                 ('sync.wait32', [4096, 0, 2**64 - 1], None)]
        for name, arguments, buffers in valid:
            self.assertTrue(validate_request(name, arguments, buffers))
        invalid = [('file.open', [4096, 1, 0, 0], {0: b'x'}, 'SERVICE_OPEN_FLAGS'),
                   ('file.open', [4096, 1, 9, 0], {0: b'x'}, 'SERVICE_OPEN_FLAGS'),
                   ('file.open', [4096, 1, 3, 0o1000], {0: b'x'}, 'SERVICE_OPEN_MODE'),
                   ('file.open', [4096, 1, 3, 0], {0: b'\xff'}, 'SERVICE_INPUT_UTF8'),
                   ('memory.protect', [4096, 1, 4], None, 'SERVICE_PERMISSIONS'),
                   ('clock.now', [2], None, 'SERVICE_CLOCK'),
                   ('clock.now', [True], None, 'SERVICE_TYPE'),
                   ('entropy.fill', [4096, 1048577], None, 'SERVICE_BUFFER_LIMIT'),
                   ('thread.spawn', [3, 0, 0], None, 'CODE_TOKEN'),
                   ('thread.spawn', [2, 0, 16383], None, 'SERVICE_STACK_SIZE'),
                   ('sync.wait32', [4097, 0, 0], None, 'SERVICE_WAIT_ADDRESS'),
                   ('module.open', [4096, 64], {0: b'z' * 64}, 'SERVICE_MODULE_IDENTITY')]
        for name, arguments, buffers, code in invalid:
            self.assert_code(code, validate_request, name, arguments, buffers)
        self.assertEqual(to_nanoseconds(1, 1), 1000000001)
        self.assertEqual(to_nanoseconds(18446744073, 709551615), 2**64 - 1)
        self.assert_code('CLOCK_OVERFLOW', to_nanoseconds, 18446744073, 709551616)
        self.assert_code('CLOCK_REPRESENTATION', to_nanoseconds, 0, 1000000000)

    def test_worker_exclusivity_parallel_ownership_and_safepoints(self):
        workers = Workers([1, 2, 3])
        workers.start(1, 100)
        workers.start(2, 101)
        self.assert_code('THREAD_NOT_RUNNABLE', workers.start, 1, 102)
        self.assert_code('WORKER_BUSY', workers.start, 3, 100)
        epoch = workers.request_stop()
        self.assertFalse(workers.all_stopped(epoch))
        workers.publish(1, 'stopped')
        self.assertFalse(workers.all_stopped(epoch))
        workers.publish(2, 'blocked')
        self.assertTrue(workers.all_stopped(epoch))
        self.assertTrue(workers.wake(2))
        self.assertFalse(workers.wake(2))
        self.assert_code('SAFEPOINT_ACTIVE', workers.start, 2, 102)
        workers.resume(epoch)
        workers.start(2, 102)
        self.assertEqual(workers.threads[2]['owner'], 102)
        self.assert_code('SAFEPOINT_STALE', workers.all_stopped, epoch - 1)

    def test_native_publication_sealing_and_reader_reclamation(self):
        for missing in range(6):
            code = CodePublication()
            flags = [True] * 6
            flags[missing] = False
            self.assert_code('CODE_NOT_SEALED', code.seal, *flags)
            self.assertEqual(code.state, 'writable')
        code = CodePublication()
        code.seal(True, True, True, True, True, True)
        code.publish()
        code.enter('native-frame')
        code.enter('callback-return')
        code.invalidate()
        self.assert_code('CODE_ENTRY_CLOSED', code.enter, 'late')
        self.assert_code('CODE_READERS_ACTIVE', code.reclaim)
        code.leave('native-frame')
        self.assert_code('CODE_READERS_ACTIVE', code.reclaim)
        code.leave('callback-return')
        code.reclaim()
        self.assertEqual(code.state, 'retired')
        stale = CodePublication()
        stale.seal(True, True, True, True, True, True)
        stale.invalidate()
        self.assert_code('CODE_STATE', stale.publish)

    def test_cross_mapping_memory_fault_has_no_partial_store(self):
        memory = ByteMemory()
        memory.add_backing('first', b'abcd')
        memory.add_backing('second', b'efgh')
        memory.map(4096, 4, 'first')
        memory.map(4100, 4, 'second', permissions=1)
        request = fixture('access-unaligned-ordinary')
        request.update(kind='store', address=4098, width=4)
        self.assert_code('MEMORY_PERMISSION', memory.store, request, b'WXYZ')
        self.assertEqual(memory.backings['first'], b'abcd')
        self.assertEqual(memory.backings['second'], b'efgh')
        request['kind'] = 'load'
        self.assertEqual(memory.load(request), b'cdef')
        request.update(address=4102, width=4)
        self.assert_code('MEMORY_UNMAPPED', memory.load, request)

    def test_whole_memory_store_and_alias_visibility(self):
        memory = ByteMemory()
        memory.add_backing('object', b'abcdefgh')
        memory.map(4096, 8, 'object')
        memory.map(8192, 8, 'object')
        request = fixture('access-unaligned-ordinary')
        request.update(kind='store', address=8194, width=4)
        memory.store(request, b'WXYZ')
        request.update(kind='load', address=4096, width=8)
        self.assertEqual(memory.load(request), b'abWXYZgh')
        self.assertEqual(memory.backings['object'], b'abWXYZgh')

    def test_schema_subset_audit_rejects_ignored_validation_keywords(self):
        expected = {
            'bridge.schema.json', 'carrier.schema.json', 'clone.schema.json',
            'link.schema.json', 'memory.schema.json', 'nonlocal.schema.json',
            'package.schema.json', 'state.schema.json', 'termination.schema.json',
            'union_prestore_reference.schema.json',
            'union_nested_reference.schema.json',
        }
        paths = {path.name: path for path in SCHEMAS.glob('*.schema.json')}
        self.assertEqual(set(paths), expected)
        for name in sorted(expected):
            with self.subTest(schema=name):
                document = json.loads(paths[name].read_text())
                audit_schema(document)
                self.assert_code('SCHEMA_KEYWORD', audit_schema,
                                 dict(document, multipleOf=2))
                nested = copy.deepcopy(document)
                nested.setdefault('$defs', {})['ignored_keyword_probe'] = {
                    'type': 'integer', 'multipleOf': 2,
                }
                self.assert_code('SCHEMA_KEYWORD', audit_schema, nested)
        self.assert_code('SCHEMA_KEYWORD', audit_schema,
                         {'type': 'integer', 'multipleOf': 2})
        self.assert_code('SCHEMA_OBJECT_DEFINITION', audit_schema,
                         {'type': 'object', 'properties': {'x': {'type': 'integer'}},
                          'required': [], 'additionalProperties': False})

    def test_deep_dependency_chain_has_no_host_recursion_limit(self):
        base = fixture('link-basic')
        bundles = []
        for index in range(1300):
            bundle = copy.deepcopy(base)
            bundle['module']['identity'] = f'{index:064x}'
            if index < 1299:
                bundle['dependencies'] = [{'identity': f'{index + 1:064x}',
                                           'abi': bundle['module']['abi'],
                                           'profile': bundle['module']['profile']}]
            bundles.append(bundle)
        ordered = initialization_order(bundles)
        self.assertEqual(len(ordered), 1300)
        self.assertEqual(ordered[0][0], f'{1299:064x}')
        self.assertEqual(ordered[-1][0], f'{0:064x}')

    def test_effect_sequence_exhaustion_and_access_limit(self):
        effect = EffectFrontier()
        effect.sequence = 2**64 - 1
        self.assert_code('TICKET_EXHAUSTED', effect.begin)
        request = fixture('access-unaligned-ordinary')
        request['width'] = 1048576
        verify_access(request)
        request['width'] += 1
        self.assert_code('ACCESS_LIMIT', verify_access, request)
        queue = WaitQueue()
        self.assert_code('WAKE_COUNT', queue.store_wake, 0, -1)
        self.assert_code('WAIT_VALUE', queue.wait, 'T', True)


class IndependentCppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='smir-runtime-',
                                                    dir=os.environ.get('SMIR_RUNTIME_TMPDIR'))
        cls.addClassCleanup(cls.directory.cleanup)
        cls.probe = Path(cls.directory.name) / 'independent'
        command = [os.environ.get('CXX', '/usr/bin/clang++'), '-std=c++20', '-pthread',
                   '-Wall', '-Wextra', '-Werror', str(HERE / 'independent.cpp'),
                   '-o', str(cls.probe)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)

    def test_independent_relocation_arithmetic(self):
        random_source = random.Random(0x52554e54494d45)
        cases = list(itertools.product((0, 1, 2**32 - 1, 2**32, 2**63, 2**64 - 1),
                                       (-2**63, -1, 0, 1, 2**63 - 1), (4, 8)))
        cases += [(random_source.randrange(2**64), random_source.randrange(-2**63, 2**63),
                   random_source.choice((4, 8))) for _ in range(128)]
        accepted = rejected = 0
        for base, addend, width in cases:
            result = subprocess.run([str(self.probe), 'relocate', str(base), str(addend),
                                     str(width)], capture_output=True, text=True, timeout=10)
            try:
                expected = relocate(base, addend, width).hex()
            except ContractError:
                self.assertEqual((result.returncode, result.stdout), (2, 'OVERFLOW\n'))
                rejected += 1
            else:
                self.assertEqual((result.returncode, result.stdout.strip()), (0, expected))
                accepted += 1
        print(f'Independent relocations: {accepted} accepted, {rejected} rejected; seed=0x52554e54494d45')

    def test_independent_locator_layout(self):
        payload = b'portable metadata; no execution'
        record = encode_locator(0x123456789, payload)
        result = subprocess.run([str(self.probe), 'locator', record.hex()],
                                check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.strip(),
                         f'{0x123456789} {len(payload)} {hashlib.sha256(payload).hexdigest()}')

    def test_actual_parallel_host_witness(self):
        result = subprocess.run([str(self.probe), 'parallel'], check=True,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.stdout.strip(),
                         'parallel_workers=2 alias_updates=20000 completion_races=200 passed')
        print(result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
