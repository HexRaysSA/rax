"""Synthetic controller/progress witnesses; no real ABI/runtime admission."""
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest
from source_frontier_reference import Budget, Controller, Event, ProtocolError, Resource, SyntheticHandle, CONTRACT_SHA256

VECTORS = Path(__file__).resolve().parents[3] / 'docs/specifications/smir/portable/conformance/execution/source-frontier-vectors.json'


def policy(**changes):
    values = dict(work=100000, edges=100000, copied_bytes=100000, max_depth=8)
    values.update(changes)
    return Budget(**values)


def model(**changes):
    controller = Controller(budget=policy(**changes))
    return controller, controller.activation()


def drive(c, f):
    trace = []
    for _ in range(64):
        status = c.step(f)
        trace.append(status)
        if status in ('done', 'waiting'):
            return trace
    raise RuntimeError('test driver bound exceeded')


def labels(c, a):
    return [c._get(h).label for h in c._get(a).stack]


def creation(j, reverse=False):
    begin = Event('begin', 'obj', journal=j)
    publish = Event('publish', 'obj', within='obj', journal=j)
    exit = Event('exit', 'obj', within='obj')
    return (begin, exit, publish) if reverse else (begin, publish, exit)


def vector(name):
    # Fixture programs are self-contained controller commands, not source code.
    document = json.loads(VECTORS.read_text())
    case = next(case for case in document['cases'] if case['name'] == name)
    c = Controller(budget=policy())
    values, result = {}, {}

    def resolve(value):
        if type(value) is str and value.startswith('@'):
            return values[value[1:]]
        if type(value) is list:
            return tuple(resolve(child) for child in value)
        return value

    for action in case['actions']:
        op = action['op']
        if op == 'activation':
            values[action['out']] = c.activation()
        elif op == 'journal':
            values[action['out']] = c.journal(values[action['activation']])
        elif op == 'existing_anchor':
            values[action['out']] = c.existing_anchor()
        elif op == 'attachment':
            values[action['out']] = c.attachment(values[action['activation']], values[action['anchor']], mode=action['mode'])
        elif op == 'frontier':
            events = tuple(Event(**{key: resolve(value) for key, value in row.items()}) for row in action['events'])
            values[action['out']] = c.frontier(values[action['activation']], locator=action['locator'], events=events,
                arguments=resolve(action.get('arguments', [])), results=resolve(action.get('results', [])), instruction=action.get('instruction', 'site'))
            last = values[action['out']]
        elif op == 'drive':
            try:
                trace = drive(c, values[action['frontier']])
            except ProtocolError as error:
                result['error'] = error.code
                if not action.get('continue_after_error', False):
                    break
            else:
                if action.get('record_trace', True):
                    result.setdefault('trace', []).extend(trace)
        elif op == 'step':
            result.setdefault('trace', []).append(c.step(values[action['frontier']]))
        elif op == 'pending':
            values[action['out']] = c._get(values[action['frontier']]).pending
        elif op == 'release':
            c.release(values[action['ticket']])
        elif op == 'outcome':
            result['outcome'] = list(c._get(values[action['ticket']]).outcome)
        elif op == 'remember_scope':
            values[action['out']] = c._get(values['a']).scopes[action['scope']]
        elif op == 'compare':
            same = values[action['left']] is values[action['right']]
            result[action['result']] = same if action['equal'] else not same
        elif op == 'anchor_states':
            result['anchor_states'] = [row[3].state for row in c._records.values() if row[0].kind == 'anchor']
        elif op == 'anchor_state':
            result['anchor_state'] = c._get(values[action['anchor']]).state
        elif op == 'journal_count':
            result['journal_count'] = sum(row[0].kind == 'journal' for row in c._records.values())
        else:
            raise ValueError('unknown fixture action: ' + op)
    result.update(cursor=c._get(last).cursor, scopes=c.scope_count, anchors=c.anchor_count,
                  effects=c.effect_count, arguments=c.argument_evaluations, stack=labels(c, values['a']))
    return result


class SourceFrontierReferenceTests(unittest.TestCase):
    def test_committed_independent_vectors(self):
        document = json.loads(VECTORS.read_text())
        self.assertTrue(document['synthetic'])
        self.assertEqual(document['contract_sha256'], CONTRACT_SHA256)
        for case in document['cases']:
            with self.subTest(case=case['name']):
                self.assertEqual(vector(case['name']), case['expected'])

    def test_complete_static_vector_and_current_selection(self):
        c, a = model()
        events = (Event('enter', 'p', subject='inline_lifecycle'), Event('enter', 'child', within='p', subject='inline_lifecycle'))
        f = c.frontier(a, locator='pre_op', events=events)
        self.assertIs(c._get(f).candidates, events)
        self.assertEqual(drive(c, f), ['progress', 'done'])
        self.assertEqual(labels(c, a), ['p', 'child'])

    def test_single_begin_and_published_anchor_survives_scope_exit(self):
        c, a = model()
        j = c.journal(a)
        f = c.frontier(a, locator='normal_post', events=creation(j), results=(j,))
        self.assertEqual(labels(c, a), [])
        c.step(f)
        scope = c._get(c._get(a).stack[-1])
        self.assertIs(scope.journal, j)
        self.assertEqual((c.scope_count, c.anchor_count), (1, 1))
        drive(c, f)
        self.assertEqual(c._get(scope.anchor).state, 'published')
        self.assertEqual(labels(c, a), [])

    def test_missing_unreturned_wrong_owner_j_no_scope_or_anchor(self):
        for mode in ('missing', 'unreturned', 'wrong_owner'):
            c, a = model()
            j = None if mode == 'missing' else c.journal(c.activation() if mode == 'wrong_owner' else a)
            results = () if mode in ('missing', 'unreturned') else (j,)
            f = c.frontier(a, locator='normal_post', events=(Event('begin', 'x', journal=j),), results=results)
            with self.subTest(mode=mode), self.assertRaisesRegex(ProtocolError, 'MODEL_RETURNED_J_REQUIRED|MODEL_JOURNAL_OWNER'):
                c.step(f)
            self.assertEqual((c._get(f).cursor, c.scope_count, c.anchor_count), (0, 0, 0))

    def test_reused_journal_rejects_new_anchor(self):
        c, a = model()
        j = c.journal(a)
        f = c.frontier(a, locator='normal_post', events=creation(j), results=(j,))
        drive(c, f)
        f = c.frontier(a, locator='normal_post', events=creation(j), results=(j,))
        with self.assertRaisesRegex(ProtocolError, 'MODEL_JOURNAL_REPLAY'):
            c.step(f)
        self.assertEqual(c.anchor_count, 1)

    def test_formal_attach_same_anchor_no_j_and_transfer_replay(self):
        c, a = model()
        anchor = c.existing_anchor()
        t = c.attachment(a, anchor, mode='incoming')
        event = Event('attach', 'arg', subject='existing_object', anchor=anchor, attachment=t)
        f = c.frontier(a, locator='entry', events=(event,), arguments=(anchor,))
        drive(c, f)
        self.assertIs(c._get(c._get(a).stack[-1]).anchor, anchor)
        self.assertEqual((c.anchor_count, c.scope_count), (1, 1))
        self.assertFalse(any(r[0].kind == 'journal' for r in c._records.values()))
        f = c.frontier(a, locator='pre_op', events=(Event('exit', 'arg', within='arg', subject='existing_object'),))
        drive(c, f)
        self.assertEqual(c._get(anchor).state, 'published')
        f = c.frontier(a, locator='entry', events=(event,), arguments=(anchor,))
        with self.assertRaisesRegex(ProtocolError, 'MODEL_ATTACHMENT_REPLAY'):
            c.step(f)

    def test_attach_requires_original_result_coordinate(self):
        c, a = model()
        anchor = c.existing_anchor()
        t = c.attachment(a, anchor, mode='returned')
        f = c.frontier(a, locator='invoke_normal', events=(Event('attach', 'result', subject='existing_object', anchor=anchor, attachment=t),))
        with self.assertRaisesRegex(ProtocolError, 'MODEL_ATTACHMENT_COORDINATE'):
            c.step(f)
        self.assertFalse(c._get(t)['used'])

    def test_pending_effect_retains_outcome_arguments_and_blocks_new_frontier(self):
        c, a = model()
        f = c.frontier(a, locator='pre_op', events=(Event('effect', wait=True),), arguments=('original', 4), results=(9,))
        self.assertEqual(c.step(f), 'waiting')
        t = c._get(f).pending
        outcome = c._get(t).outcome
        for _ in range(7):
            self.assertEqual(c.step(f), 'waiting')
        self.assertEqual((c.effect_count, c.argument_evaluations, c._get(f).cursor), (1, 1, 0))
        self.assertIs(c._get(t).outcome, outcome)
        self.assertEqual(c._get(f).arguments, ('original', 4))
        with self.assertRaisesRegex(ProtocolError, 'MODEL_FRONTIER_PENDING'):
            c.frontier(a, locator='pre_op', events=())
        c.release(t)
        self.assertEqual(c.step(f), 'done')
        with self.assertRaisesRegex(ProtocolError, 'MODEL_TICKET_REPLAY'):
            c.release(t)
        with self.assertRaisesRegex(ProtocolError, 'MODEL_FRONTIER_REPLAY'):
            c.step(f)

    def test_duplicate_claim_and_cancel_cannot_forget_owner(self):
        c, a = model()
        anchor = c.existing_anchor()
        f = c.frontier(a, locator='pre_op', events=(Event('claim_effect', anchor=anchor, wait=True),))
        c.step(f)
        t = c._get(f).pending
        with self.assertRaisesRegex(ProtocolError, 'MODEL_CANCEL_REQUIRES_OWNER_CLEANUP'):
            c.cancel(f)
        self.assertIs(c._get(anchor).claimed, t)
        c.release(t)
        c.step(f)
        f = c.frontier(a, locator='pre_op', events=(Event('claim_effect', anchor=anchor),))
        with self.assertRaisesRegex(ProtocolError, 'MODEL_CLAIM_DUPLICATE'):
            c.step(f)
        self.assertEqual((c.claim_count, c.effect_count, c._get(f).cursor), (1, 1, 0))

    def test_forged_wrong_controller_stale_and_completed_handles(self):
        c, a = model()
        copied = SyntheticHandle(a.issuer, a.kind, a.serial, a.generation)
        _, foreign = model()
        for h, code in [(copied, 'MODEL_FORGED_HANDLE'), (foreign, 'MODEL_WRONG_CONTROLLER')]:
            with self.assertRaisesRegex(ProtocolError, code):
                c.frontier(h, locator='pre_op', events=())
        for serial in [True, [], 10 ** 2000]:
            malformed = SyntheticHandle(a.issuer, a.kind, serial, 1)
            with self.assertRaisesRegex(ProtocolError, 'MODEL_FORGED_HANDLE'):
                c.frontier(malformed, locator='pre_op', events=())
        f = c.frontier(a, locator='pre_op', events=())
        c.step(f)
        with self.assertRaisesRegex(ProtocolError, 'MODEL_FRONTIER_REPLAY'):
            c.step(f)
        c.retire(a)
        with self.assertRaisesRegex(ProtocolError, 'MODEL_STALE_HANDLE'):
            c.frontier(a, locator='pre_op', events=())

    def test_scope_loop_persists_but_actual_creation_loop_is_fresh(self):
        persistent = vector('loop_persistent_scope')
        self.assertTrue(persistent['different_receipt'])
        self.assertTrue(persistent['same_scope'])
        self.assertEqual(persistent['scopes'], 1)
        self.assertTrue(vector('loop_real_creation')['different_scope'])

    def test_normal_publish_exit_order_is_observable(self):
        reversed = vector('reverse_publish_exit')
        self.assertEqual((reversed['error'], reversed['cursor'], reversed['stack']), ('MODEL_UNPUBLISHED', 1, ['obj']))
        self.assertEqual(vector('publish_then_exit')['stack'], [])

    def test_explicit_unwind_e_and_outward_private_none(self):
        for locator, some in [('pre_op', False), ('pre_op', True), ('unwind_exit', False)]:
            c, a = model()
            f = c.frontier(a, locator='pre_op', events=(Event('enter', 'p', subject='inline_lifecycle'),))
            c.step(f)
            e = c.exception(a)
            f = c.frontier(a, locator=locator, events=(Event('exit', 'p', within='p', subject='inline_lifecycle', outcome='unwind', exception=e if some else None),), exception=e)
            if locator == 'pre_op' and not some:
                with self.assertRaisesRegex(ProtocolError, 'MODEL_EXCEPTION_REQUIRED'):
                    c.step(f)
            else:
                self.assertEqual(c.step(f), 'done')
                self.assertEqual(labels(c, a), [])

    def test_static_locator_errors_even_on_inactive_selectors(self):
        c, a = model()
        for event in [Event('begin', 'x', within='inactive'), Event('enter', 'x', within='inactive'), Event('attach', 'x', within='inactive')]:
            with self.assertRaisesRegex(ProtocolError, 'MODEL_EVENT_LOCATOR|MODEL_SCOPE_SUBJECT'):
                c.frontier(a, locator='pre_op', events=(event,))
        self.assertIsNone(c._get(a).frontier)

    def test_physical_entry_cannot_invent_missing_incoming_lineage(self):
        c, a = model()
        with self.assertRaisesRegex(ProtocolError, 'MODEL_INCOMING_SELECTOR_REQUIRED'):
            c.frontier(a, locator='entry', events=(Event('enter', 'physical', subject='physical_lifecycle'),))
        f = c.frontier(a, locator='entry', events=(Event('enter', 'physical', within='incoming', subject='physical_lifecycle'),))
        with self.assertRaisesRegex(ProtocolError, 'MODEL_INCOMING_TICKET_REQUIRED'):
            c.step(f)
        self.assertEqual((c._get(f).cursor, c.scope_count), (0, 0))

    def test_zero_small_and_depth_quotas_leave_event_cursor_unchanged(self):
        for changes in [dict(work=0), dict(edges=0), dict(copied_bytes=0)]:
            with self.assertRaises(Resource):
                Controller(budget=policy(**changes))
        c, a = model(max_depth=1)
        with self.assertRaises(Resource):
            c.frontier(a, locator='pre_op', events=(), arguments=((1,),))
        f = c.frontier(a, locator='pre_op', events=(Event('enter', 'p', subject='inline_lifecycle'), Event('enter', 'c', within='p', subject='inline_lifecycle')))
        c.step(f)
        with self.assertRaises(Resource):
            c.step(f)
        self.assertEqual((c._get(f).cursor, labels(c, a)), (1, ['p']))

    def test_precommit_vs_postcommit_resource_no_effect_replay(self):
        probe, a = model()
        probe.frontier(a, locator='pre_op', events=(Event('effect'),))
        startup = probe.budget.used[0]
        for allowance, committed in [(5, 0), (6, 1)]:
            c, a = model(work=startup + allowance)
            f = c.frontier(a, locator='pre_op', events=(Event('effect'),))
            for _ in range(3):
                with self.assertRaises(Resource):
                    c.step(f)
                self.assertEqual((c._get(f).cursor, c.effect_count), (0, committed))
            if committed:
                t = c._get(c._get(f).pending)
                self.assertEqual(t.outcome, ('synthetic_committed', 1))
                self.assertFalse(t.consumed)

    def test_static_metadata_handles_and_budget_cannot_be_reinitialized(self):
        c, a = model()
        e = Event('effect')
        for operation in [lambda: c.budget.__init__(work=999, edges=999, copied_bytes=999, max_depth=8), lambda: c.__init__(budget=policy()), lambda: a.__init__(None, 'anchor', 1, 1), lambda: e.__init__('begin')]:
            with self.assertRaises(AttributeError):
                operation()
        with self.assertRaises(FrozenInstanceError):
            e.op = 'begin'


if __name__ == '__main__':
    unittest.main()
