"""Actual owner-release helper + runtime lifecycle oracle + SEM continuation.

Object/type/completion/handler facts below are trusted reference fixtures. They
are not a native producer or compiled C++ witness. The test joins actual catalog
admission and registry protocol to typed control transfer, without fake Deps.
"""
import unittest

from candidate.bindings import runtime_package_module
from candidate.machine import Machine, Pending, Terminated
from candidate.raw import Raw
from candidate.type_system import ref
from candidate.values import Value
from test_candidate import block, constant, decl, operation
from test_candidate_bindings import add_import, admit
from test_candidate_eh_bindings import function, signature


def caller():
    roots, _ = add_import('eh_owner_release')
    roots[1]['types'].append(signature(302, [4], [17]))
    roots[3]['functions'].append(function(1, 302, [decl(0, 4)], [block(0, [
        operation('call', [], [0], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)},
                  unwind='propagate'), constant(1, 17, '09000000')], {'op': 'return', 'values': [1]})]))
    return admit(roots)


class CandidateExceptionOwnerTests(unittest.TestCase):
    def test_last_owner_destructor_return_or_throw_preserves_typed_frontier_once(self):
        runtime = runtime_package_module('exceptions')
        for mode in ['returns', 'throws', 'pending_throws']:
            with self.subTest(mode=mode):
                context = caller()
                events, pending = [], []
                state = {}

                def handler(token):
                    # Registry.terminate establishes the CAUSING implicit catch.
                    cause = state['registry'].current_owner(1)
                    events.append(('handler', token, state['registry'].uncaught(1), cause.object))

                def destructor(symbol):
                    events.append(('destructor', symbol))
                    if mode != 'returns':
                        registry = state['registry']
                        failure = registry.allocate(1, object_id=3, nominal='Failure',
                                                    destructor='Failure::~Failure', proxy_object=4)
                        registry.complete_construction(failure, 1, ('Failure', 'initialized'))
                        raise runtime.Raised(registry.raise_initial(failure, 1))

                def cleanup_outcome(cleanup):
                    registry = state['registry']
                    failed = registry.run_cleanup(cleanup, destructor, thread=1, handler_call=handler)
                    return Terminated('owner_destructor_abort') if failed else []

                def release(machine, arguments):
                    self.assertEqual(arguments[0].data, state['proxy_pointer'])
                    events.append(('release',))
                    cleanup = state['registry'].owner_release(state['owner'])
                    self.assertIsNotNone(cleanup)
                    state['cleanup'] = cleanup
                    if mode == 'pending_throws':
                        pending.append(cleanup)
                        return Pending(73)
                    return cleanup_outcome(cleanup)

                machine = Machine(context.execution_checked, imports={('self', 0): release})
                pointers = {identity: machine.memory.allocate(size, align)
                            for identity, size, align in [(1, 4, 4), (2, 32, 8), (3, 4, 4), (4, 32, 8)]}
                objects = {identity: {'live': True, 'address': pointer.address, 'generation': pointer.generation,
                                     'size': size, 'alignment': align}
                           for (identity, size, align), pointer in zip(
                               [(1, 4, 4), (2, 32, 8), (3, 4, 4), (4, 32, 8)], pointers.values())}
                registry = runtime.Registry(1, objects, lambda token: token == 'fixture.terminate',
                    lambda payload, certificate: certificate == (payload['nominal'], 'initialized'), 'fixture.terminate')
                original = registry.allocate(1, object_id=1, nominal='T', destructor='T::~T', proxy_object=2)
                registry.complete_construction(original, 1, ('T', 'initialized'))
                registry.raise_initial(original, 1)
                registry.select_catch(original, 1, registry.object_address(original, 1))
                registry.begin_catch(original, 1)
                owner = registry.current_owner(1)
                self.assertIsNone(registry.end_catch(original, 1))  # Retained owner keeps T alive.
                machine.memory.raw_store(pointers[2], Raw.integer(256,
                    int.from_bytes(registry.proxies[2]['header'], 'little')))
                state.update(registry=registry, owner=owner, proxy_pointer=pointers[2])
                machine.start(1, [Value(ref(4), 'concrete', pointers[2])])
                outcome = machine.run()
                if mode == 'pending_throws':
                    self.assertEqual(outcome, {'kind': 'suspended', 'ticket': 73})
                    self.assertEqual(machine.run(), outcome)
                    self.assertEqual(events, [('release',)])
                    terminal = cleanup_outcome(pending.pop())
                    machine.resume(73, terminal=terminal)
                    outcome = machine.run()
                cleanup = state['cleanup']
                payload = registry.payloads[cleanup.payload]
                self.assertEqual((cleanup.state, payload['state'], payload['destructor_entries']),
                                 ('completed', 'dead', 1))
                self.assertEqual(events[:2], [('release',), ('destructor', 'T::~T')])
                if mode == 'returns':
                    self.assertEqual(outcome['values'][0].data, 9)
                    self.assertFalse(registry.aborted)
                    self.assertEqual(len(events), 2)
                else:
                    self.assertEqual(outcome, {'kind': 'terminate', 'reason': 'owner_destructor_abort'})
                    self.assertEqual(events[2], ('handler', 'fixture.terminate', 0, 4))
                    self.assertTrue(registry.aborted)
                    self.assertEqual(machine.stack[0].position, 0)
                    self.assertNotIn(1, machine.stack[0].values)
                    self.assertEqual(list(machine.tickets.values()), ['terminal'])
                    self.assertEqual(machine.search_log, [])  # Never redispatches a fake Raised.


if __name__ == '__main__':
    unittest.main()
