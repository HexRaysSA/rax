"""Standalone synthetic retirement protocol, not SMIR or native authority.

All handles are model-controller-issued. Work/edge/byte units are logical model
quotas, not CPU instructions or Python allocator capacity. No user callback,
source-code entry, native code, ABI proof or shared CodeAddress registry is run.
"""
from dataclasses import dataclass
from functools import wraps
import argparse
import hashlib
import json
from pathlib import Path
from threading import RLock


class ModelError(Exception):
    def __init__(self, code, kind='semantic'):
        self.code, self.kind = code, kind
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise ModelError(code)


class Budget:
    """Explicit cumulative ledger; refusals change no consumed dimension.

    refuse_at is bounded fault injection at charge-attempt ordinals, not an
    allocator experiment, quota refill or reset. Already consumed work remains.
    """
    __slots__ = ('_limits', '_used', '_attempt', '_faults', '_lock')

    def __init__(self, *, max_work, max_edges, max_bytes, refuse_at=()):
        if hasattr(self, '_limits'):
            raise ModelError('MODEL_BUDGET_RESET', 'resource')
        values = (max_work, max_edges, max_bytes)
        if any(type(n) is not int or n < 0 for n in values) or \
                type(refuse_at) is not tuple or len(refuse_at) > 64 or \
                any(type(n) is not int or not 0 < n < 2**64 for n in refuse_at):
            raise ModelError('MODEL_BUDGET_POLICY', 'resource')
        object.__setattr__(self, '_limits', values)
        object.__setattr__(self, '_used', (0, 0, 0))
        object.__setattr__(self, '_attempt', 0)
        object.__setattr__(self, '_faults', refuse_at)
        object.__setattr__(self, '_lock', RLock())

    def __setattr__(self, name, value):
        raise AttributeError('model budget cannot be reset')

    @property
    def used(self):
        return self._used

    @property
    def attempts(self):
        return self._attempt

    def charge(self, *, work=0, edges=0, copied_bytes=0):
        counts = (work, edges, copied_bytes)
        if any(type(n) is not int or n < 0 for n in counts):
            raise ModelError('MODEL_BUDGET_ARGUMENT', 'resource')
        with self._lock:
            attempt = self._attempt + 1
            object.__setattr__(self, '_attempt', attempt)
            following = tuple(a + b for a, b in zip(self._used, counts))
            if attempt in self._faults or any(a > b for a, b in zip(following, self._limits)):
                raise ModelError('MODEL_RESOURCE', 'resource')
            object.__setattr__(self, '_used', following)


class Handle:
    __slots__ = ('_issuer', '_number', '_generation', '_kind')

    def __new__(cls, *args, **kwargs):
        raise TypeError('synthetic handles are controller-issued')

    def __setattr__(self, name, value):
        raise AttributeError('immutable synthetic handle')

    @property
    def kind(self):
        return self._kind

    @property
    def number(self):
        return self._number

    @property
    def generation(self):
        return self._generation

    def __repr__(self):
        return f'<model-only {self._kind} {self._number}:{self._generation}>'


@dataclass(frozen=True)
class Status:
    phase: str
    work: object = None
    snapshot: object = None
    blockers: tuple = ()
    count: int = 0


def atomic(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            self._budget.charge(work=8)
            return method(self, *args, **kwargs)
    return wrapped


class Controller:
    """Synthetic owner/reference graph. No public numeric ID is a capability.

    Each issued row consumes 128 logical metadata bytes. Snapshots additionally
    reserve eight logical bytes per retained handle; container edges are charged.
    Calls are serialized model transitions, not a qualified parallel runtime.
    """
    def __init__(self, *, budget):
        require(not hasattr(self, '_rows'), 'MODEL_CONTROLLER_RESET')
        require(type(budget) is Budget, 'MODEL_BUDGET_REQUIRED')
        budget.charge(work=16, edges=1, copied_bytes=64)
        self._budget, self._lock = budget, RLock()
        self._issuer, self._rows, self._next = object(), {}, 1

    def _walk(self, n, *, copied_bytes=0):
        self._budget.charge(work=16 + n * (n.bit_length() + 2),
                            edges=n, copied_bytes=copied_bytes)

    def _new(self, kind, **record):
        require(self._next < 2**64, 'MODEL_HANDLE_EXHAUSTED')
        self._budget.charge(work=8, edges=1, copied_bytes=128)
        handle = object.__new__(Handle)
        for key, value in (('_issuer', self._issuer), ('_number', self._next),
                           ('_generation', 1), ('_kind', kind)):
            object.__setattr__(handle, key, value)
        self._rows[handle] = dict(record, kind=kind, generation=1)
        self._next += 1
        return handle

    def _get(self, handle, kind):
        require(type(handle) is Handle and getattr(handle, '_issuer', None) is self._issuer
                and handle in self._rows, 'MODEL_HANDLE')
        record = self._rows[handle]
        require(handle.generation == record['generation'], 'MODEL_STALE')
        require(record['kind'] == kind, 'MODEL_NAMESPACE')
        return record

    def _consume(self, handle):
        self._rows[handle]['generation'] += 1

    @atomic
    def owner(self):
        return self._new('owner', state='alive', roots=set(), pins=set(), active=set(),
                         revision=0, publication=True, fini_entries=0, fini_done=False)

    @atomic
    def external(self):
        return self._new('external')

    @atomic
    def activity(self, owner):
        record = self._get(owner, 'owner')
        require(record['state'] == 'alive', 'MODEL_ENTRY_CLOSED')
        handle = self._new('activity', owner=owner, context=None)
        record['active'].add(handle)
        return handle

    def _actor(self, actor, holder):
        if type(actor) is Handle and getattr(actor, '_kind', None) == 'context':
            context = self._get(actor, 'context')
        else:
            activity = self._get(actor, 'activity')
            if activity['context'] is None:
                require(activity['owner'] is holder, 'MODEL_OWNER')
                return
            context = self._get(activity['context'], 'context')
        self._walk(len(context['owners']))
        require(context['state'] == 'running' and holder in context['owners'], 'MODEL_OWNER')

    @atomic
    def root(self, holder, target, *, actor=None):
        require(type(holder) is Handle, 'MODEL_HANDLE')
        kind = getattr(holder, '_kind', None)
        require(kind in ('owner', 'external'), 'MODEL_NAMESPACE')
        storage = self._get(holder, kind)
        destination = self._get(target, 'owner')
        require(destination['state'] != 'retired', 'MODEL_TARGET_RETIRED')
        if holder.kind == 'owner':
            require(storage['publication'], 'MODEL_PUBLICATION_CLOSED')
            if storage['state'] != 'alive':
                require(actor is not None, 'MODEL_OWNER_REQUIRED')
                self._actor(actor, holder)
        handle = self._new('root', holder=holder, target=target)
        if holder.kind == 'owner':
            storage['roots'].add(handle)
            storage['revision'] += 1
        destination['pins'].add(handle)
        return handle

    def _drop(self, root):
        row = self._get(root, 'root')
        holder, target = row['holder'], row['target']
        if holder.kind == 'owner':
            owner = self._rows[holder]
            owner['roots'].remove(root)
            owner['revision'] += 1
        self._rows[target]['pins'].remove(root)
        self._consume(root)

    @atomic
    def drop_root(self, root):
        self._get(root, 'root')
        self._drop(root)

    @atomic
    def finish_activity(self, activity):
        record = self._get(activity, 'activity')
        if record['context'] is None:
            self._rows[record['owner']]['active'].remove(activity)
        else:
            self._get(record['context'], 'context')['children'].remove(activity)
        self._consume(activity)

    @atomic
    def close(self, owners):
        require(type(owners) is tuple and len(owners) > 0, 'MODEL_OWNER_SET')
        self._walk(len(owners), copied_bytes=8 * len(owners))
        for owner in owners:
            require(self._get(owner, 'owner')['state'] == 'alive', 'MODEL_ALREADY_RETIRING')
        require(len(set(owners)) == len(owners), 'MODEL_DUPLICATE_OWNER')
        transaction = self._new('retirement', owners=owners, stage='active', works={},
                                snapshot=None, disposed=0, retries=0)
        for owner in owners:
            self._rows[owner]['state'] = 'closing'
        return transaction

    @atomic
    def poll(self, transaction):
        tx = self._get(transaction, 'retirement')
        owners = tx['owners']
        self._walk(len(owners))
        if tx['stage'] == 'reclaimed':
            return Status('reclaimed')
        if tx['stage'] == 'active':
            count = sum(len(self._rows[o]['active']) for o in owners)
            self._walk(count, copied_bytes=8 * count)
            active = tuple(a for o in owners for a in self._rows[o]['active'])
            if active:
                return Status('busy_active', blockers=active)
            tx['stage'] = 'fini'
        if tx['stage'] == 'fini':
            for owner in owners:
                if self._rows[owner]['fini_done']:
                    continue
                if owner not in tx['works']:
                    tx['works'][owner] = self._new('work', transaction=transaction,
                                                  owner=owner, state='new', context=None)
                work = tx['works'][owner]
                state = self._rows[work]['state']
                return Status('cleanup' if state == 'new' else
                              'failed_cleanup' if state == 'failed' else 'busy_cleanup', work=work)
            tx['stage'] = 'roots'
        if tx['stage'] == 'roots':
            if tx['snapshot'] is None:
                count = sum(len(self._rows[o]['roots']) for o in owners)
                self._walk(count + len(owners), copied_bytes=8 * (count + len(owners)))
                roots = tuple(sorted((r for o in owners for r in self._rows[o]['roots']),
                                     key=lambda r: r.number))
                revisions = tuple(self._rows[o]['revision'] for o in owners)
                snapshot = self._new('snapshot', transaction=transaction,
                                     roots=roots, revisions=revisions)
                for owner in owners:
                    self._rows[owner]['publication'] = False
                tx['snapshot'] = snapshot
            return Status('snapshot', snapshot=tx['snapshot'])
        require(tx['stage'] == 'external', 'MODEL_PHASE')
        count = sum(len(self._rows[o]['pins']) for o in owners)
        self._walk(count, copied_bytes=8 * count)
        pins = tuple(p for o in owners for p in self._rows[o]['pins'])
        if pins:
            return Status('busy_external', blockers=pins)
        for owner in owners:
            row = self._rows[owner]
            require(row['fini_done'] and not row['publication'] and not row['roots']
                    and not row['active'] and not row['pins'], 'MODEL_RECLAIM_CONDITION')
        for owner in owners:
            self._rows[owner]['state'] = 'retired'
            self._consume(owner)
        tx['stage'] = 'reclaimed'
        return Status('reclaimed')

    @atomic
    def begin_cleanup(self, work):
        row = self._get(work, 'work')
        tx = self._get(row['transaction'], 'retirement')
        self._walk(len(tx['owners']))
        require(tx['stage'] == 'fini' and row['state'] == 'new', 'MODEL_CLEANUP_REPLAY')
        require(all(not self._rows[o]['active'] for o in tx['owners']), 'MODEL_NOT_QUIESCENT')
        context = self._new('context', work=work, owners=tx['owners'],
                            state='running', children=set())
        row.update(state='running', context=context)
        self._rows[row['owner']]['fini_entries'] += 1
        return context

    @atomic
    def cleanup_activity(self, context, owner):
        row = self._get(context, 'context')
        self._walk(len(row['owners']))
        require(row['state'] == 'running' and owner in row['owners'], 'MODEL_OWNER')
        self._get(owner, 'owner')
        activity = self._new('activity', owner=owner, context=context)
        row['children'].add(activity)
        return activity

    @atomic
    def finish_cleanup(self, context):
        row = self._get(context, 'context')
        require(row['state'] == 'running', 'MODEL_CLEANUP_STATE')
        self._walk(len(row['children']), copied_bytes=8 * len(row['children']))
        if row['children']:
            return Status('busy_children', blockers=tuple(row['children']))
        work = self._get(row['work'], 'work')
        require(work['state'] == 'running', 'MODEL_CLEANUP_REPLAY')
        work['state'] = 'done'
        row['state'] = 'done'
        self._rows[work['owner']]['fini_done'] = True
        self._consume(context)
        self._consume(row['work'])
        return Status('cleanup_done')

    @atomic
    def fail_cleanup(self, context):
        row = self._get(context, 'context')
        require(row['state'] == 'running', 'MODEL_CLEANUP_STATE')
        row['state'] = 'failed'
        self._get(row['work'], 'work')['state'] = 'failed'

    @atomic
    def dispose(self, transaction, snapshot):
        tx = self._get(transaction, 'retirement')
        shot = self._get(snapshot, 'snapshot')
        require(tx['stage'] == 'roots' and tx['snapshot'] is snapshot and
                shot['transaction'] is transaction, 'MODEL_SNAPSHOT')
        self._walk(len(shot['roots']) * (1 + len(tx['owners'])) + len(tx['owners']),
                   copied_bytes=8 * len(tx['owners']))
        revisions = tuple(self._rows[o]['revision'] for o in tx['owners'])
        if revisions != shot['revisions']:
            self._consume(snapshot)
            tx['snapshot'] = None
            tx['retries'] += 1
            return Status('retry')
        for root in shot['roots']:
            require(self._get(root, 'root')['holder'] in tx['owners'], 'MODEL_EXTERNAL_DISCARD')
        for root in shot['roots']:
            self._drop(root)
        tx['disposed'] += len(shot['roots'])
        self._consume(snapshot)
        tx.update(snapshot=None, stage='external')
        return Status('disposed', count=len(shot['roots']))

    @atomic
    def inspect(self, transaction):
        tx = self._get(transaction, 'retirement')
        self._walk(len(tx['owners']), copied_bytes=32 * len(tx['owners']))
        return {'stage': tx['stage'], 'disposed': tx['disposed'], 'retries': tx['retries'],
                'owners': tuple((self._rows[o]['state'], self._rows[o]['fini_entries'],
                                 len(self._rows[o]['roots']), len(self._rows[o]['active']))
                                for o in tx['owners'])}

    @atomic
    def owner_state(self, owner):
        return self._get(owner, 'owner')['state']


def vector_document():
    return {'format': 'synthetic-retirement-v1', 'scope': 'reference only; no SMIR/native authority',
            'contract_sha256': '30dcb6ebb867bccd680089ed40a5e14822995962a45a68d4bab8314aeb22e92c',
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'cases': [
                {'name': 'empty', 'owners': 1, 'selected': [0], 'roots': [], 'active': [],
                 'external': [], 'fini_roots': [], 'mutate_snapshot': False},
                {'name': 'self-dormant', 'owners': 1, 'selected': [0], 'roots': [[0, 0]],
                 'active': [], 'external': [], 'fini_roots': [], 'mutate_snapshot': False},
                {'name': 'blocked-add-root', 'owners': 1, 'selected': [0], 'roots': [],
                 'active': [0], 'external': [], 'fini_roots': [[0, 0]], 'mutate_snapshot': False},
                {'name': 'external-pin', 'owners': 1, 'selected': [0], 'roots': [[0, 0]],
                 'active': [], 'external': [0], 'fini_roots': [], 'mutate_snapshot': False},
                {'name': 'joint-mutual', 'owners': 2, 'selected': [0, 1],
                 'roots': [[0, 1], [1, 0]], 'active': [1], 'external': [],
                 'fini_roots': [[0, 0], [1, 1]], 'mutate_snapshot': False},
                {'name': 'unselected-holder', 'owners': 2, 'selected': [0],
                 'roots': [[1, 0], [0, 1]], 'active': [], 'external': [],
                 'fini_roots': [], 'mutate_snapshot': False},
                {'name': 'revision-retry', 'owners': 1, 'selected': [0],
                 'roots': [[0, 0]], 'active': [], 'external': [],
                 'fini_roots': [[0, 0]], 'mutate_snapshot': True}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write-vectors', action='store_true')
    group.add_argument('--check-vectors', action='store_true')
    parser.add_argument('--vectors', type=Path, required=True)
    args = parser.parse_args()
    data = json.dumps(vector_document(), indent=2) + '\n'
    if args.write_vectors:
        args.vectors.write_text(data)
    elif args.vectors.read_text() != data:
        raise ModelError('MODEL_VECTOR_DRIFT')
    print('7 deterministic model vectors; no runtime/native execution')


if __name__ == '__main__':
    main()
