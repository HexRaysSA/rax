"""Component-level typed cleanup protocol witnesses, not foreign ABI evidence."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.machine import Machine, Pending, Raised, Terminated
from candidate.operations import Dependencies
from candidate.type_system import ref
from candidate.values import Value
from candidate.verify import verify
from test_candidate import block, constant, decl, fixture


def package(journal=False):
    types, functions, eh = fixture()
    signature = types['types'][15]
    signature['params'] = [ref(10), ref(2)]
    signature['param_noundef'] = [True, True]
    caller = functions['functions'][0]
    caller['params'] = [decl(0, 10), decl(1, 2)]
    caller['blocks'] = [block(0, [], {'op': 'invoke', 'target': {'kind': 'direct', 'function': ref(1), 'signature': ref(15)},
        'operands': [0, 1], 'normal': {'target': 1, 'results': [decl(2, 2)]},
        'unwind': {'target': 2, 'exception': decl(3, 10)}, 'region': 1}),
        block(1, [], {'op': 'return', 'values': [2]}),
        block(2, [constant(4, 2, '09000000')], {'op': 'return', 'values': [4]})]
    callee = deepcopy(caller)
    callee['id'] = 1
    callee['blocks'] = [block(0, [], {'op': 'throw', 'exception': 0, 'region': None})]
    functions['functions'].append(callee)
    captures = [{'parameter': 0, 'type': ref(2), 'source': {'kind': 'value', 'value': 1}},
                {'parameter': 1, 'type': ref(10), 'source': {'kind': 'exception'}}]
    if journal:
        captures.append({'parameter': 2, 'type': ref(14), 'source': {'kind': 'journal', 'program': ref(0)}})
    eh['functions'] = [{'function': 0, 'actions': [
        {'id': 0, 'program': ref(0), 'recipe': ref(0), 'captures': captures},
        {'id': 1, 'program': ref(0), 'recipe': ref(1), 'captures': [captures[0]]}], 'regions': [
        {'id': 0, 'parent': None, 'blocks': [0], 'exit_actions': [], 'escape': 'continue', 'handlers': [
            {'id': 7, 'selector': 8, 'kind': 'catch_all', 'nominal': None, 'entry': 2,
             'cleanup_actions': [1], 'catch_copy': None}]},
        {'id': 1, 'parent': {'some': 0}, 'blocks': [0], 'exit_actions': [0], 'handlers': [], 'escape': 'continue'}]}]
    # These maps isolate the execution verifier's already-admitted interface.
    # Full cross-section admission uses test_candidate_context's real ABI roots.
    dependencies = Dependencies(nominals={('self', i): {'execution': {'some': ref(t)}}
        for i, t in [(0, 2), (1, 10), (2, 14)]}, cleanup_programs={('self', 0): {'id': 0}},
        actions={('self', 0): {'params': [{'id': i, 'type': ref(i)} for i in range(3 if journal else 2)], 'results': []},
                 ('self', 1): {'params': [{'id': 0, 'type': ref(0)}], 'results': []}})
    return types, functions, eh, dependencies


class CandidateUnwindTests(unittest.TestCase):
    def test_cleanup_terminal_outcome_never_commits_action_results_or_replays(self):
        for result in [Terminated('cleanup_abort'), Pending(71)]:
            events = []
            def first(*args):
                events.append('first')
                return result
            machine, _ = self.machine({('self', 0): first, ('self', 1): lambda *args: events.append('second') or []})
            outcome = machine.run()
            if isinstance(result, Pending):
                self.assertEqual(outcome, {'kind': 'suspended', 'ticket': 71})
                machine.resume(71, terminal=Terminated('cleanup_abort'))
                outcome = machine.run()
            self.assertEqual(outcome, {'kind': 'terminate', 'reason': 'cleanup_abort'})
            self.assertEqual(machine.unwind_state['position'], 0)
            self.assertEqual(machine.unwind_state['results'], [])
            self.assertEqual(events, ['first'])

    def machine(self, adapters, journal=False):
        types, functions, eh, dependencies = package(journal)
        machine = Machine(verify(types, functions, eh, dependencies), action_adapters=adapters)
        exception = machine.handle(ref(10), {'nominal': ('self', 0)}, owner=1)
        machine.start(0, [exception, Value(ref(2), 'concrete', 42)])
        return machine, exception

    def test_search_before_cleanup_and_suspension_never_replays(self):
        events = []
        def first(machine, captures, exception):
            events.append(('first', captures[0].data, captures[1] == exception))
            self.assertEqual(machine.search_log, [((1, 1), (1, 0))])
            return Pending(71)
        def second(machine, captures, exception):
            events.append(('second', captures[0].data))
            return []
        machine, exception = self.machine({('self', 0): first, ('self', 1): second})
        self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 71})
        self.assertNotIn(2, machine.stack[0].values)  # No invoke normal results.
        self.assertNotIn(3, machine.stack[0].values)  # Unwind edge not committed yet.
        with self.assertRaises(Reject):
            machine.resume(72, [])
        machine.resume(71, [])
        result = machine.run()
        self.assertEqual(result['values'][0].data, 9)
        self.assertEqual(events, [('first', 42, True), ('second', 42)])
        self.assertEqual(machine.catch_contexts[1]['handler']['id'], 7)
        with self.assertRaises(Reject):
            machine.resume(71, [])

    def test_cleanup_raise_terminates_and_wrong_edge_capture_rejects(self):
        machine, _ = self.machine({('self', 0): lambda m, a, e: Raised(e), ('self', 1): lambda *args: []})
        self.assertEqual(machine.run(), {'kind': 'terminate', 'reason': 'cleanup_throws'})
        types, functions, eh, dependencies = package()
        eh['functions'][0]['actions'][0]['captures'][0]['source']['value'] = 2
        with self.assertRaisesRegex(Reject, 'ssa_dominance'):
            verify(types, functions, eh, dependencies)
        eh['functions'][0]['actions'][0]['captures'][0]['source']['value'] = 1
        eh['functions'][0]['actions'][0]['captures'].pop()
        with self.assertRaisesRegex(Reject, 'cleanup_capture_bijection'):
            verify(types, functions, eh, dependencies)

    def test_journal_instance_binding_checks_owner_program_and_generation(self):
        observed = []
        def cleanup(machine, captures, exception):
            observed.append(captures[2].data.identity)
            return []
        machine, _ = self.machine({('self', 0): cleanup, ('self', 1): lambda *args: []}, True)
        wrong = machine.handle(ref(14), {'program': ('self', 0)}, owner=999)
        with self.assertRaisesRegex(Reject, 'journal_capture_owner_program'):
            machine.bind_journal(1, 0, 2, wrong)
        actual = machine.handle(ref(14), {'program': ('self', 0), 'parent_instance': (17, 0, 3)}, owner=1)
        machine.bind_journal(1, 0, 2, actual)
        with self.assertRaisesRegex(Reject, 'journal_capture_duplicate_binding'):
            machine.bind_journal(1, 0, 2, actual)
        self.assertEqual(machine.run()['values'][0].data, 9)
        self.assertEqual(observed, [actual.data.identity])

    def test_nounwind_escape_is_language_ub(self):
        types, functions, eh, dependencies = package()
        functions['functions'][1]['escape'] = 'nothrow'
        machine = Machine(verify(types, functions, eh, dependencies),
                          action_adapters={('self', 0): lambda *args: [], ('self', 1): lambda *args: []})
        exception = machine.handle(ref(10), {'nominal': ('self', 0)})
        machine.start(0, [exception, Value(ref(2), 'concrete', 42)])
        self.assertEqual(machine.run(), {'kind': 'language_ub', 'reason': 'ub_nounwind'})

    def test_poison_or_undef_throw_is_guest_ub_before_search(self):
        for state in ['poison', 'undef']:
            types, functions, eh, dependencies = package()
            types['types'][15]['param_noundef'][0] = False
            machine = Machine(verify(types, functions, eh, dependencies),
                              action_adapters={('self', 0): lambda *args: [], ('self', 1): lambda *args: []})
            machine.start(0, [Value(ref(10), state), Value(ref(2), 'concrete', 42)])
            self.assertEqual(machine.run(), {'kind': 'language_ub', 'reason': 'ub_exception_handle',
                'activation': 2, 'function': 1, 'block': 0, 'operation': 0})
            self.assertEqual(machine.search_log, [])

    def test_canonical_cleanup_return_and_tail_obligations(self):
        types, functions, eh, dependencies = package()
        functions['functions'][1]['blocks'][0]['term'] = {'op': 'cleanup_return', 'exception': None, 'region': None}
        with self.assertRaisesRegex(Reject, 'cleanup_requires_explicit_exception'):
            verify(types, functions, eh, dependencies)
        types, functions, eh, dependencies = package()
        functions['functions'][0]['blocks'][0]['term'] = {'op': 'tailcall',
            'target': {'kind': 'direct', 'function': ref(1), 'signature': ref(15)}, 'operands': [0, 1], 'source_plan': None}
        # Keep all blocks reachable: remove now-unused invoke edge blocks.
        functions['functions'][0]['blocks'] = functions['functions'][0]['blocks'][:1]
        eh['functions'][0]['regions'][0]['handlers'] = []
        with self.assertRaisesRegex(Reject, 'tail_protected_region'):
            verify(types, functions, eh, dependencies)


if __name__ == '__main__':
    unittest.main()
