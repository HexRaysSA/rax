"""Actual ABI/candidate helper roots for journal and catch ticket continuations."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.machine import Machine, Pending, Terminated
from candidate.type_system import ref
from candidate.values import Value
from test_candidate import block, constant, decl, operation
from test_candidate_bindings import add_import, admit


def signature(identifier, params, results):
    return {'id': identifier, 'kind': 'function', 'params': [ref(item) for item in params],
            'results': [ref(item) for item in results], 'param_noundef': [False] * len(params),
            'result_noundef': [True] * len(results), 'variadic': False, 'cc': 'portable'}


def function(identifier, sig, params, blocks):
    return {'id': identifier, 'signature': ref(sig), 'abi_signature': None, 'params': params,
            'entry': 0, 'escape': 'propagate', 'no_return': False, 'blocks': blocks}


def journal_package():
    roots, binding = add_import('journal_advance', 'construct_begin', abi={'some': ref(0)})
    roots[1]['types'] += [{'id': 300, 'kind': 'journal'}, signature(302, [300], [17])]
    roots[10]['journals'] = [{'id': 0, 'signature': 0, 'params': [], 'slots': [
        {'id': 0, 'type': ref(1), 'offset': 0, 'extent': 4, 'align': 4, 'parent': None,
         'role': 'root', 'count': 1, 'stride': 4, 'count_source': None, 'constructor': None,
         'destructor': None, 'destructor_kind': 'none', 'covers': [], 'owner': 0,
         'dependencies': [], 'child_program': None}], 'normal_order': [0], 'exception_order': [0]}]
    node = operation('journal', [], [0, 1, 2], action='construct_begin', program=ref(0),
                     helper={'kind': 'import', 'import': ref(0), 'signature': ref(201)})
    roots[3]['functions'].append(function(1, 302, [decl(0, 300)], [block(0,
        [constant(1, 1, '00000000'), constant(2, 5, '0000000000000000'), node,
         constant(3, 17, '09000000')], {'op': 'return', 'values': [3]})]))
    return roots, binding, node


class CandidateEHBindingTests(unittest.TestCase):
    def test_terminate_handler_requires_actual_fixed_void_function_shape(self):
        for name in ['eh_get_terminate', 'eh_set_terminate']:
            roots, binding = add_import(name)
            admit(roots)
            target = next(item for item in roots[1]['types'] if item['id'] == 300)
            target.update(params=[ref(17)], param_noundef=[False])
            with self.assertRaisesRegex(Reject, 'RT_HELPER_TERMINATE_SIGNATURE'):
                admit(roots)
            target.update(params=[], param_noundef=[])
            binding['abi'] = {'some': ref(0)}
            with self.assertRaisesRegex(Reject, 'UNUSED_ABI'):
                admit(roots)

    def test_return_capable_release_declared_termination_never_advances_caller(self):
        roots, _ = add_import('eh_release')
        roots[1]['types'].append(signature(302, [7], [17]))
        roots[3]['functions'].append(function(1, 302, [decl(0, 7)], [block(0, [
            operation('call', [], [0], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)},
                      unwind='propagate'), constant(1, 17, '09000000')], {'op': 'return', 'values': [1]})]))
        context = admit(roots)
        for result in [[], Terminated('owner_destructor_abort'), Pending(19)]:
            events = []
            def adapter(*args):
                events.append('release')
                return result
            machine = Machine(context.execution_checked, imports={('self', 0): adapter})
            exception = machine.handle(ref(7), {'nominal': ('self', 1)})
            machine.start(1, [exception])
            outcome = machine.run()
            if isinstance(result, Pending):
                self.assertEqual(outcome, {'kind': 'suspended', 'ticket': 19})
                machine.resume(19, terminal=Terminated('owner_destructor_abort'))
                outcome = machine.run()
            if result == []:
                self.assertEqual(outcome['values'][0].data, 9)
            else:
                self.assertEqual(outcome, {'kind': 'terminate', 'reason': 'owner_destructor_abort'})
                self.assertEqual(machine.stack[0].position, 0)
                self.assertNotIn(1, machine.stack[0].values)
                self.assertEqual(list(machine.tickets.values()), ['terminal'])
            self.assertEqual(events, ['release'])

    def test_fixed_return_internal_helper_cannot_claim_terminal_completion(self):
        roots, _ = add_import('stack_alloc')
        roots[1]['types'].append(signature(302, [], [17]))
        roots[3]['functions'].append(function(1, 302, [], [block(0, [
            constant(0, 5, '0800000000000000'), operation('call', [decl(1, 4)], [0, 0],
                target={'kind': 'import', 'import': ref(0), 'signature': ref(201)}, unwind='nounwind'),
            constant(2, 17, '09000000')], {'op': 'return', 'values': [2]})]))
        context = admit(roots)
        machine = Machine(context.execution_checked, imports={('self', 0): lambda *args: Terminated('process_abort')})
        machine.start(1, [])
        with self.assertRaisesRegex(Reject, 'reference_terminal_helper'):
            machine.run()
        self.assertIsNone(machine.finished)
        self.assertNotIn(1, machine.stack[0].values)

    def test_nonreturning_terminal_outcome_has_no_results_or_unwind_publication(self):
        roots, _ = add_import('eh_raise')
        roots[1]['types'].append(signature(302, [7], [17]))
        roots[3]['functions'].append(function(1, 302, [decl(0, 7)], [block(0, [
            operation('call', [], [0], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)},
                      unwind='propagate'), constant(1, 17, '09000000')], {'op': 'return', 'values': [1]})]))
        context = admit(roots)
        for result in [Terminated('process_abort'), Pending(19)]:
            entries = []
            def adapter(machine, arguments):
                entries.append(1)
                return result
            machine = Machine(context.execution_checked, imports={('self', 0): adapter})
            exception = machine.handle(ref(7), {'nominal': ('self', 1)})
            machine.start(1, [exception])
            outcome = machine.run()
            if isinstance(result, Pending):
                self.assertEqual(outcome, {'kind': 'suspended', 'ticket': 19})
                with self.assertRaisesRegex(Reject, 'effect_resume_outcome'):
                    machine.resume(19, exception=exception, terminal=Terminated('process_abort'))
                machine.resume(19, terminal=Terminated('process_abort'))
                outcome = machine.run()
                with self.assertRaisesRegex(Reject, 'effect_resume_ticket'):
                    machine.resume(19, terminal=Terminated('process_abort'))
            self.assertEqual(outcome, {'kind': 'terminate', 'reason': 'process_abort'})
            self.assertEqual(list(machine.tickets.values()), ['terminal'])
            self.assertEqual(machine.stack[0].position, 0)
            self.assertNotIn(1, machine.stack[0].values)
            self.assertEqual(machine.search_log, [])
            self.assertEqual(entries, [1])

    def test_raising_helper_cannot_return_or_resume_normally(self):
        roots, _ = add_import('eh_raise')
        roots[1]['types'].append(signature(302, [7], [17]))
        roots[3]['functions'].append(function(1, 302, [decl(0, 7)], [block(0, [
            operation('call', [], [0], target={'kind': 'import', 'import': ref(0), 'signature': ref(201)},
                      unwind='propagate'), constant(1, 17, '09000000')], {'op': 'return', 'values': [1]})]))
        context = admit(roots)
        for result in [[], Pending(19)]:
            machine = Machine(context.execution_checked, imports={('self', 0): lambda *args: result})
            exception = machine.handle(ref(7), {'nominal': ('self', 1)})
            machine.start(1, [exception])
            with self.assertRaisesRegex(Reject, 'reference_helper_completion'):
                if isinstance(result, Pending):
                    self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 19})
                    machine.resume(19, [])
                else:
                    machine.run()
            self.assertEqual(machine.stack[0].position, 0)
            self.assertNotIn(1, machine.stack[0].values)

    def test_exact_journal_program_contract_and_pending_resume(self):
        roots, binding, node = journal_package()
        context = admit(roots)
        events = []
        def transition(machine, arguments):
            events.append([arguments[1].data, arguments[2].data])
            return Pending(77)
        machine = Machine(context.execution_checked, imports={('self', 0): transition})
        journal = machine.handle(ref(300), {'program': ('self', 0)}, owner=1)
        machine.start(1, [journal])
        self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 77})
        self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 77})
        machine.resume(77, [])
        self.assertEqual(machine.run()['values'][0].data, 9)
        self.assertEqual(events, [[0, 0]])
        binding['contract'] = 'construct_commit'
        with self.assertRaisesRegex(Reject, 'journal_helper_binding'):
            admit(roots)
        binding['contract'] = 'construct_begin'
        node['recipe'] = node.pop('program')
        with self.assertRaisesRegex(Reject, 'shape'):
            admit(roots)

    def test_actual_begin_end_catch_names_selected_context_and_ticket(self):
        roots, begin = add_import('eh_begin_catch')
        roots[1]['types'] += [signature(202, [7], []), signature(303, [7], [17])]
        end = deepcopy(begin)
        end.update(id=1, name='eh_end_catch', signature=ref(202))
        roots[6]['imports'].append(end)
        invoke = {'op': 'invoke', 'target': {'kind': 'direct', 'function': ref(2), 'signature': ref(303)},
                  'operands': [0], 'normal': {'target': 1, 'results': [decl(1, 17)]},
                  'unwind': {'target': 2, 'exception': decl(2, 7)}, 'region': 0}
        roots[3]['functions'] += [function(1, 303, [decl(0, 7)], [block(0, [], invoke),
            block(1, [], {'op': 'return', 'values': [1]}), block(2, [
                operation('catch_begin', [decl(3, 4)], [2], handler=0,
                          helper={'kind': 'import', 'import': ref(0), 'signature': ref(201)}),
                operation('catch_end', [], [2], helper={'kind': 'import', 'import': ref(1), 'signature': ref(202)}),
                constant(4, 17, '09000000')], {'op': 'return', 'values': [4]})]),
            function(2, 303, [decl(0, 7)], [block(0, [], {'op': 'throw', 'exception': 0, 'region': None})])]
        roots[8]['functions'] = [{'function': 1, 'actions': [], 'regions': [
            {'id': 0, 'parent': None, 'blocks': [0], 'exit_actions': [], 'escape': 'continue', 'handlers': [
                {'id': 0, 'selector': 1, 'kind': 'catch_all', 'nominal': None, 'entry': 2,
                 'cleanup_actions': [], 'catch_copy': None}]}]}]
        context = admit(roots)
        events = []
        def enter(machine, arguments):
            events.append('begin')
            return Pending(19)
        def leave(machine, arguments):
            events.append('end')
            return []
        machine = Machine(context.execution_checked, imports={('self', 0): enter, ('self', 1): leave})
        pointer = machine.memory.allocate(4, 4)
        exception = machine.handle(ref(7), {'nominal': ('self', 1)})
        machine.start(1, [exception])
        self.assertEqual(machine.run(), {'kind': 'suspended', 'ticket': 19})
        self.assertFalse(machine.catch_contexts[1]['entered'])
        machine.resume(19, [Value(ref(4), 'concrete', pointer)])
        self.assertEqual(machine.run()['values'][0].data, 9)
        self.assertEqual(events, ['begin', 'end'])
        self.assertNotIn(1, machine.catch_contexts)


if __name__ == '__main__':
    unittest.main()
