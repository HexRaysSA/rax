"""Focused tests of the synthetic retirement state machine, not a native runtime."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

import retirement_core as M

VECTORS = Path(__file__).resolve().parents[2] / 'docs/specifications/smir/portable/conformance/runtime/retirement-core-vectors.json'


def ledger(**changes):
    policy = dict(max_work=1_000_000, max_edges=1_000_000, max_bytes=1_000_000)
    policy.update(changes)
    return M.Budget(**policy)


def execute(case, fault=()):
    """Finite driver explicitly completes activities and releases external roots.

    Retrying a model Resource uses the original cumulative ledger. The driver
    supplies finite completion; it proves neither fairness nor native progress.
    """
    budget = ledger(refuse_at=fault)
    refusals = 0

    def retry(fn, *args, **kwargs):
        nonlocal refusals
        try:
            return fn(*args, **kwargs)
        except M.ModelError as error:
            if error.code != 'MODEL_RESOURCE':
                raise
            refusals += 1
            return fn(*args, **kwargs)

    controller = retry(M.Controller, budget=budget)
    owners = [retry(controller.owner) for _ in range(case['owners'])]
    selected = tuple(owners[i] for i in case['selected'])
    roots = []
    for holder, target in case['roots']:
        roots.append(retry(controller.root, owners[holder], owners[target]))
    for target in case['external']:
        external = retry(controller.external)
        roots.append(retry(controller.root, external, owners[target]))
    activities = [(i, retry(controller.activity, owners[i])) for i in case['active']]
    tx = retry(controller.close, selected)
    if activities:
        result = retry(controller.poll, tx)
        if result.phase != 'busy_active':
            raise RuntimeError('fini was not blocked by actual active handles')
        state = retry(controller.inspect, tx)
        if any(row[1] for row in state['owners']):
            raise RuntimeError('fini entered before quiescence')
        for index, activity in activities:
            roots.append(retry(controller.root, owners[index], selected[0], actor=activity))
            retry(controller.finish_activity, activity)
    cleanup_number, changed, busy = 0, False, 0
    for _ in range(100):
        result = retry(controller.poll, tx)
        if result.phase == 'cleanup':
            owner_index = case['selected'][cleanup_number]
            context = retry(controller.begin_cleanup, result.work)
            child = retry(controller.cleanup_activity, context, owners[owner_index])
            for holder, target in case['fini_roots']:
                if holder == owner_index:
                    roots.append(retry(controller.root, owners[holder], owners[target], actor=child))
            if retry(controller.finish_cleanup, context).phase != 'busy_children':
                raise RuntimeError('cleanup child did not retain its context')
            if retry(controller.poll, tx).phase != 'busy_cleanup':
                raise RuntimeError('cleanup completion was published before child drain')
            retry(controller.finish_activity, child)
            finished = retry(controller.finish_cleanup, context)
            if finished.phase != 'cleanup_done':
                raise RuntimeError('unexpected cleanup completion')
            cleanup_number += 1
        elif result.phase == 'snapshot':
            if case['mutate_snapshot'] and not changed:
                retry(controller.drop_root, roots[0])
                changed = True
            disposed = retry(controller.dispose, tx, result.snapshot)
            if disposed.phase not in ('disposed', 'retry'):
                raise RuntimeError('unexpected disposal result')
        elif result.phase == 'busy_external':
            busy += 1
            # Each actual returned root is explicitly released by this driver.
            for root in result.blockers:
                retry(controller.drop_root, root)
        elif result.phase == 'reclaimed':
            state = retry(controller.inspect, tx)
            if state['stage'] != 'reclaimed' or any(row != ('retired', 1, 0, 0)
                                                       for row in state['owners']):
                raise RuntimeError('unsafe reclamation or replayed fini')
            if bool(state['retries']) != bool(case['mutate_snapshot']):
                raise RuntimeError('root revision retry was not observed')
            for index, owner in enumerate(owners):
                if index not in case['selected'] and retry(controller.owner_state, owner) != 'alive':
                    raise RuntimeError('implicit owner-set expansion')
            return budget.attempts, refusals, busy, state
        else:
            raise RuntimeError('unexpected finite-driver phase: ' + result.phase)
    raise RuntimeError('finite reference driver exceeded its explicit bound')


class RetirementCoreTests(unittest.TestCase):
    def setUp(self):
        self.budget = ledger()
        self.c = M.Controller(budget=self.budget)

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(M.ModelError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def ready(self, owners=None):
        if owners is None:
            owners = (self.c.owner(),)
        tx = self.c.close(owners)
        for _ in owners:
            work = self.c.poll(tx).work
            context = self.c.begin_cleanup(work)
            self.assertEqual(self.c.finish_cleanup(context).phase, 'cleanup_done')
        return tx, self.c.poll(tx).snapshot

    def test_explicit_budget_and_immutable_policy(self):
        with self.assertRaises(TypeError):
            M.Controller()
        self.error('MODEL_BUDGET_REQUIRED', M.Controller, budget=True)
        self.error('MODEL_CONTROLLER_RESET', self.c.__init__, budget=ledger())
        for value in (True, -1, 1.0, None):
            self.error('MODEL_BUDGET_POLICY', ledger, max_work=value)
        self.error('MODEL_BUDGET_RESET', self.budget.__init__, max_work=1, max_edges=1, max_bytes=1)
        with self.assertRaises(AttributeError):
            self.budget._used = (0, 0, 0)
        self.error('MODEL_RESOURCE', M.Controller, budget=ledger(max_work=0))

    def test_atomic_multidimensional_charge(self):
        budget = ledger(max_work=5, max_edges=2, max_bytes=7)
        budget.charge(work=4, edges=1, copied_bytes=3)
        self.error('MODEL_RESOURCE', budget.charge, work=1, edges=2, copied_bytes=1)
        self.assertEqual(budget.used, (4, 1, 3))
        budget.charge(work=1, edges=1, copied_bytes=4)
        self.assertEqual(budget.used, (5, 2, 7))
        self.error('MODEL_BUDGET_ARGUMENT', budget.charge, work=True)

    def test_issued_identity_and_namespace(self):
        owner = self.c.owner()
        with self.assertRaises(TypeError):
            M.Handle()
        for fake in (True, owner.number, {}, object.__new__(M.Handle)):
            self.error('MODEL_HANDLE', self.c.owner_state, fake)
        forged = object.__new__(M.Handle)
        for field in M.Handle.__slots__:
            object.__setattr__(forged, field, getattr(owner, field))
        self.error('MODEL_HANDLE', self.c.owner_state, forged)
        other = M.Controller(budget=ledger()).owner()
        self.error('MODEL_HANDLE', self.c.owner_state, other)
        self.error('MODEL_NAMESPACE', self.c.owner_state, self.c.external())
        self.error('MODEL_HANDLE', self.c.close, ([],))
        self.error('MODEL_DUPLICATE_OWNER', self.c.close, (owner, owner))
        self.assertEqual(self.c.owner_state(owner), 'alive')

    def test_preclose_resource_does_not_close_owner(self):
        budget = ledger(refuse_at=(4,))
        c = M.Controller(budget=budget)
        owner = c.owner()
        self.error('MODEL_RESOURCE', c.close, (owner,))
        self.assertEqual(c.owner_state(owner), 'alive')
        tx = c.close((owner,))
        self.assertEqual(c.inspect(tx)['stage'], 'active')

    def test_active_before_fini_and_live_root_mutation(self):
        owner = self.c.owner()
        activity = self.c.activity(owner)
        tx = self.c.close((owner,))
        self.assertEqual(self.c.poll(tx).phase, 'busy_active')
        self.assertEqual(self.c.inspect(tx)['owners'], (('closing', 0, 0, 1),))
        root = self.c.root(owner, owner, actor=activity)
        self.c.drop_root(root)
        self.c.finish_activity(activity)
        self.error('MODEL_STALE', self.c.finish_activity, activity)
        self.assertEqual(self.c.poll(tx).phase, 'cleanup')
        self.error('MODEL_ENTRY_CLOSED', self.c.activity, owner)

    def test_dormant_self_pin_does_not_block_fini(self):
        owner = self.c.owner()
        root = self.c.root(owner, owner)
        tx, snapshot = self.ready((owner,))
        self.assertEqual(self.c.dispose(tx, snapshot).count, 1)
        self.assertEqual(self.c.poll(tx).phase, 'reclaimed')
        self.error('MODEL_STALE', self.c.drop_root, root)
        self.error('MODEL_STALE', self.c.owner_state, owner)
        self.assertEqual(self.c.poll(tx).phase, 'reclaimed')

    def test_cleanup_child_drain_and_one_shot_context(self):
        owner = self.c.owner()
        tx = self.c.close((owner,))
        work = self.c.poll(tx).work
        context = self.c.begin_cleanup(work)
        self.error('MODEL_CLEANUP_REPLAY', self.c.begin_cleanup, work)
        child = self.c.cleanup_activity(context, owner)
        self.c.root(owner, owner, actor=child)
        self.assertEqual(self.c.finish_cleanup(context).phase, 'busy_children')
        self.assertEqual(self.c.poll(tx).phase, 'busy_cleanup')
        self.c.finish_activity(child)
        self.c.finish_cleanup(context)
        self.error('MODEL_STALE', self.c.finish_cleanup, context)
        self.error('MODEL_STALE', self.c.begin_cleanup, work)
        snapshot = self.c.poll(tx).snapshot
        self.assertEqual(self.c.dispose(tx, snapshot).count, 1)

    def test_cleanup_failure_does_not_replay_or_reclaim(self):
        owner = self.c.owner()
        tx = self.c.close((owner,))
        work = self.c.poll(tx).work
        context = self.c.begin_cleanup(work)
        self.c.fail_cleanup(context)
        self.assertEqual(self.c.poll(tx).phase, 'failed_cleanup')
        self.assertEqual(self.c.inspect(tx)['owners'], (('closing', 1, 0, 0),))
        self.error('MODEL_CLEANUP_REPLAY', self.c.begin_cleanup, work)
        self.error('MODEL_CLEANUP_STATE', self.c.finish_cleanup, context)

    def test_current_membership_revision_and_publication_closure(self):
        owner = self.c.owner()
        root = self.c.root(owner, owner)
        tx, snapshot = self.ready((owner,))
        self.error('MODEL_PUBLICATION_CLOSED', self.c.root, owner, owner)
        self.c.drop_root(root)
        self.assertEqual(self.c.dispose(tx, snapshot).phase, 'retry')
        self.error('MODEL_STALE', self.c.dispose, tx, snapshot)
        fresh = self.c.poll(tx).snapshot
        self.assertIsNot(fresh, snapshot)
        self.assertEqual(self.c.dispose(tx, fresh).count, 0)
        self.assertEqual(self.c.poll(tx).phase, 'reclaimed')

    def test_owned_disposal_precedes_external_pin_drain(self):
        owner = self.c.owner()
        self.c.root(owner, owner)
        external = self.c.root(self.c.external(), owner)
        tx, snapshot = self.ready((owner,))
        self.assertEqual(self.c.dispose(tx, snapshot).count, 1)
        status = self.c.poll(tx)
        self.assertEqual(status.phase, 'busy_external')
        self.assertEqual(status.blockers, (external,))
        self.assertEqual(self.c.inspect(tx)['owners'], (('closing', 1, 0, 0),))
        self.c.drop_root(external)
        self.assertEqual(self.c.poll(tx).phase, 'reclaimed')

    def test_unselected_cleanup_owner_rejected(self):
        a, b = self.c.owner(), self.c.owner()
        tx = self.c.close((a,))
        context = self.c.begin_cleanup(self.c.poll(tx).work)
        self.error('MODEL_OWNER', self.c.cleanup_activity, context, b)
        self.error('MODEL_OWNER_REQUIRED', self.c.root, a, a)
        self.error('MODEL_HANDLE', self.c.root, a, a, actor=True)
        self.assertEqual(self.c.owner_state(b), 'alive')

    def test_actual_snapshot_and_generation_required(self):
        owner = self.c.owner()
        tx, snapshot = self.ready((owner,))
        other = M.Controller(budget=ledger())
        o = other.owner()
        other_tx = other.close((o,))
        self.error('MODEL_HANDLE', other.dispose, other_tx, snapshot)
        self.error('MODEL_HANDLE', self.c.dispose, tx, snapshot.number)
        self.c.dispose(tx, snapshot)
        self.error('MODEL_STALE', self.c.dispose, tx, snapshot)

    def test_quota_exhaustion_does_not_reopen_or_replay(self):
        # Initial controller/owner/close fit; the first post-close poll does not.
        budget = ledger(max_work=71)
        c = M.Controller(budget=budget)
        owner = c.owner()
        tx = c.close((owner,))
        used = budget.used
        self.error('MODEL_RESOURCE', c.poll, tx)
        self.assertGreaterEqual(budget.used[0], used[0])
        self.assertEqual(c._rows[owner]['state'], 'closing')
        self.assertEqual(c._rows[owner]['fini_entries'], 0)
        self.error('MODEL_RESOURCE', c.poll, tx)
        self.assertEqual(c._rows[owner]['state'], 'closing')

    def test_deterministic_vector_reproduction(self):
        before = VECTORS.read_bytes()
        self.assertEqual(json.loads(before), M.vector_document())
        completed = subprocess.run([sys.executable, '-B', str(Path(M.__file__).resolve()),
                                    '--check-vectors', '--vectors', str(VECTORS)],
                                   check=True, text=True, capture_output=True)
        self.assertIn('7 deterministic model vectors', completed.stdout)
        self.assertEqual(VECTORS.read_bytes(), before)

    def test_long_owner_traversal_is_precharged(self):
        budget = ledger(max_edges=65)
        controller = M.Controller(budget=budget)
        owners = tuple(controller.owner() for _ in range(64))
        used = budget.used
        self.error('MODEL_RESOURCE', controller.close, owners)
        self.assertEqual(budget.used[1:], used[1:])
        self.assertTrue(all(controller._rows[o]['state'] == 'alive' for o in owners))

    def test_revision_retries_exhaust_original_ledger(self):
        budget = ledger(max_work=2000)
        controller = M.Controller(budget=budget)
        owner = controller.owner()
        roots = [controller.root(owner, owner) for _ in range(16)]
        tx = controller.close((owner,))
        context = controller.begin_cleanup(controller.poll(tx).work)
        controller.finish_cleanup(context)
        retries = 0
        with self.assertRaises(M.ModelError) as caught:
            while roots:
                snapshot = controller.poll(tx).snapshot
                controller.drop_root(roots.pop())
                self.assertEqual(controller.dispose(tx, snapshot).phase, 'retry')
                retries += 1
        self.assertEqual(caught.exception.code, 'MODEL_RESOURCE')
        self.assertGreater(retries, 0)
        self.assertEqual(controller._rows[owner]['state'], 'closing')
        self.assertEqual(controller._rows[owner]['fini_entries'], 1)
        self.assertLessEqual(budget.used[0], 2000)

    def test_all_strategic_vectors(self):
        cases = json.loads(VECTORS.read_text())['cases']
        self.assertEqual(len(cases), 7)
        for case in cases:
            with self.subTest(case=case['name']):
                _, refusals, busy, _ = execute(case)
                self.assertEqual(refusals, 0)
                self.assertEqual(bool(busy), bool(case['external']) or case['name'] == 'unselected-holder')

    def test_resource_at_every_observed_charge_frontier(self):
        frontiers = 0
        for case in json.loads(VECTORS.read_text())['cases']:
            attempts, _, _, expected = execute(case)
            for ordinal in range(1, attempts + 1):
                with self.subTest(case=case['name'], ordinal=ordinal):
                    _, refusals, _, actual = execute(case, (ordinal,))
                    self.assertEqual(refusals, 1)
                    self.assertEqual(actual, expected)
                    frontiers += 1
        print('resource fault frontiers:', frontiers, '; vectors: 7; finite driver only')


if __name__ == '__main__':
    unittest.main()
