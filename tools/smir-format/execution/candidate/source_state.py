"""Conditional source history/current-cell reference; no runtime/source authority.

Explicit model tables stand for original source anchor/schedule/cell hypotheses.
Only verify() is a proposed local API. It never executes an SMIR envelope.
"""
from dataclasses import dataclass, field, replace
from copy import deepcopy
import hashlib
import json
from math import gcd
from pathlib import Path

from candidate.source_lifetimes import ContractError, preflight, shape

SCHEMA = Path(__file__).resolve().parents[4] / 'docs/specifications/smir/portable/schema/execution/source_state.json'
U64 = 2**64 - 1
MAX_RANGES = 4096


class SourceStateError(ValueError):
    def __init__(self, code, detail='', kind='semantic'):
        self.code, self.detail, self.kind = code, detail, kind
        super().__init__(code + (': ' + detail if detail else ''))


def need(condition, code, detail=''):
    if not condition:
        raise SourceStateError(code, detail)


@dataclass(frozen=True)
class StaticSourceState:
    anchors: tuple
    initialization: tuple
    current: tuple
    ended: tuple
    checked_steps: int
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


@dataclass(frozen=True)
class _Range:
    source_anchor: str
    object_generation: int
    cleanup_schedule: str
    pattern: str
    first: int
    count: int
    lifetime_generation: int
    ordinal_first: int
    ordinal_step: int

    @property
    def stop(self):
        return self.first + self.count

    @property
    def last_ordinal(self):
        return self.ordinal_first + (self.count - 1) * self.ordinal_step

    @property
    def domain(self):
        return self.source_anchor, self.object_generation, self.cleanup_schedule

    def frozen(self):
        return tuple(getattr(self, field) for field in self.__dataclass_fields__)


@dataclass(frozen=True)
class _State:
    history: dict
    current: tuple
    ended: tuple
    published: frozenset


def _intersects(left, right, budget):
    """Exact finite AP collision, charged before bounded <=256-bit arithmetic."""
    budget.charge(work=4096, edges=1, copied_bytes=256)
    a, n, s = left.ordinal_first, left.count, left.ordinal_step
    b, m, t = right.ordinal_first, right.count, right.ordinal_step
    if n == 1:
        return a == b if m == 1 else b <= a <= right.last_ordinal and (a - b) % t == 0
    if m == 1:
        return a <= b <= left.last_ordinal and (b - a) % s == 0
    lower, upper = max(a, b), min(left.last_ordinal, right.last_ordinal)
    if lower > upper:
        return False
    divisor = gcd(s, t)
    if (b - a) % divisor:
        return False
    modulus = s // divisor * t
    residue = (a + s * (((b - a) // divisor * pow(s // divisor, -1, t // divisor)) %
                       (t // divisor))) % modulus
    first = residue + max(0, -((residue - lower) // modulus)) * modulus
    return first <= upper


class _Model:
    def __init__(self, document, budget):
        self.budget, self.steps = budget, 0
        self.anchors = self.index(document['anchors'])
        self.schedules = self.index(document['schedules'])
        self.patterns = self.index(document['patterns'])
        self.actions = document['actions']
        self.contract()
        history = self.index(document['initialization'], key='pattern')
        need(set(history) == set(self.patterns), 'SS_HISTORY_MEMBERSHIP')
        budget.charge(work=len(history), copied_bytes=128 * len(history))
        prefixes = {}
        for identity, row in history.items():
            pattern = self.pattern(identity, row)
            need(row['initialization_schedule'] == pattern['initialization_schedule'], 'SS_SCHEDULE_MEMBERSHIP')
            need(row['initialized_prefix'] <= pattern['required_prefix'], 'SS_HISTORY_SELECTION')
            prefixes[identity] = row['initialized_prefix']
        need(len(document['current']) + len(document['ended']) <= MAX_RANGES, 'SS_RANGE_RESOURCE')
        budget.charge(work=len(document['current']) + len(document['ended']),
                      copied_bytes=256 * (len(document['current']) + len(document['ended'])))
        current = tuple(_Range(**row) for row in document['current'])
        ended = tuple(_Range(**row) for row in document['ended'])
        budget.charge(work=len(self.anchors), copied_bytes=64 * len(self.anchors))
        published = frozenset(row['id'] for row in self.anchors.values() if row['stage'] == 'published')
        self.state = _State(prefixes, current, ended, published)
        self.validate(self.state)

    def index(self, rows, key='id'):
        self.budget.charge(work=len(rows), edges=len(rows), copied_bytes=128 * len(rows))
        result = {}
        for row in rows:
            need(row[key] not in result, 'SS_DUPLICATE')
            result[row[key]] = row
        return result

    def get(self, table, identity):
        need(identity in table, 'SS_REFERENCE', str(identity))
        return table[identity]

    def anchor(self, row):
        anchor = self.get(self.anchors, row['source_anchor'])
        need(anchor['object_generation'] == row['object_generation'], 'SS_OBJECT_GENERATION')
        return anchor

    def pattern(self, identity, row):
        self.anchor(row)
        pattern = self.get(self.patterns, identity)
        need((pattern['source_anchor'], pattern['object_generation']) ==
             (row['source_anchor'], row['object_generation']), 'SS_PATTERN_ANCHOR')
        return pattern

    def contract(self):
        for anchor in self.anchors.values():
            owner = self.get(self.anchors, anchor['complete_owner'])
            need(owner['complete_owner'] == owner['id'] and anchor['object_generation'] > 0,
                 'SS_ANCHOR')
        self.budget.charge(work=4 * len(self.patterns), edges=2 * len(self.patterns),
                           copied_bytes=256 * len(self.patterns))
        memberships, canonical, initial_schedules = {}, set(), set()
        self.budget.charge(work=2 * len(self.schedules), copied_bytes=128 * len(self.schedules))
        for schedule in self.schedules.values():
            self.anchor(schedule)
            if schedule['kind'] == 'initialization':
                need(schedule['source_anchor'] not in initial_schedules, 'SS_INITIALIZATION_SCHEDULE')
                initial_schedules.add(schedule['source_anchor'])
            self.budget.charge(work=2 * len(schedule['patterns']), copied_bytes=64 * len(schedule['patterns']))
            need(len(set(schedule['patterns'])) == len(schedule['patterns']), 'SS_DUPLICATE')
            memberships[schedule['id']] = set(schedule['patterns'])
        for pattern in self.patterns.values():
            self.anchor(pattern)
            identity = pattern['source_anchor'], pattern['object_generation'], pattern['canonical_cell']
            need(identity not in canonical, 'SS_CANONICAL_CELL_DUPLICATE')
            canonical.add(identity)
            need(pattern['required_prefix'] in {0, pattern['count']}, 'SS_HISTORY_SELECTION')
            for kind in ('initialization', 'cleanup'):
                schedule = self.get(self.schedules, pattern[kind + '_schedule'])
                need(schedule['kind'] == kind and schedule['source_anchor'] == pattern['source_anchor'] and
                     schedule['object_generation'] == pattern['object_generation'] and
                     pattern['id'] in memberships[schedule['id']], 'SS_SCHEDULE_MEMBERSHIP')
        for schedule in self.schedules.values():
            for identity in schedule['patterns']:
                pattern = self.get(self.patterns, identity)
                need(pattern[schedule['kind'] + '_schedule'] == schedule['id'], 'SS_SCHEDULE_MEMBERSHIP')

    def validate(self, state):
        rows = state.current + state.ended
        need(len(rows) <= MAX_RANGES, 'SS_RANGE_RESOURCE')
        self.budget.charge(work=len(rows) * max(1, len(rows).bit_length()),
                          edges=len(rows), copied_bytes=64 * len(rows))
        ordered = sorted(rows, key=lambda row: (row.source_anchor, row.object_generation, row.pattern, row.first))
        previous = None
        for row in ordered:
            pattern = self.pattern(row.pattern, row.__dict__)
            need(row.cleanup_schedule == pattern['cleanup_schedule'], 'SS_SCHEDULE_MEMBERSHIP')
            need(row.count > 0 and row.first + row.count <= pattern['count'], 'SS_RANGE_BOUNDS')
            need(row.lifetime_generation > 0 and row.ordinal_first > 0 and
                 (row.ordinal_step == 0 if row.count == 1 else row.ordinal_step > 0) and
                 row.last_ordinal <= U64, 'SS_ORDINAL')
            key = row.source_anchor, row.object_generation, row.pattern
            if previous is not None and previous[0] == key:
                need(previous[1] <= row.first, 'SS_CELL_OVERLAP')
            previous = key, row.stop
        live = state.current
        self.budget.work(len(live) * len(live))
        for i, left in enumerate(live):
            for j in range(i + 1, len(live)):
                right = live[j]
                if left.domain == right.domain:
                    need(not _intersects(left, right, self.budget), 'SS_ORDINAL_COLLISION')
        self.budget.work(len(self.patterns) + len(self.anchors))
        for pattern in self.patterns.values():
            if pattern['source_anchor'] in state.published:
                need(state.history[pattern['id']] == pattern['required_prefix'], 'SS_INITIALIZATION_INCOMPLETE')

    def request(self, step):
        pattern = self.pattern(step['pattern'], step)
        need(step['cleanup_schedule'] == pattern['cleanup_schedule'], 'SS_SCHEDULE_MEMBERSHIP')
        need(step['count'] > 0 and step['first'] + step['count'] <= pattern['count'], 'SS_RANGE_BOUNDS')
        return pattern

    def sliced(self, row, start, stop, generation=None):
        self.budget.charge(work=16, copied_bytes=256)
        return replace(row, first=start, count=stop - start,
                       lifetime_generation=row.lifetime_generation if generation is None else generation,
                       ordinal_first=row.ordinal_first + (start - row.first) * row.ordinal_step,
                       ordinal_step=row.ordinal_step if stop - start > 1 else 0)

    def take(self, rows, step, generation):
        self.request(step)
        self.budget.charge(work=len(rows) * max(1, len(rows).bit_length()), copied_bytes=128 * len(rows))
        rows = sorted(rows, key=lambda row: (row.pattern, row.first))
        start, stop, cursor = step['first'], step['first'] + step['count'], step['first']
        kept, taken = [], []
        for row in rows:
            if row.pattern != step['pattern'] or row.source_anchor != step['source_anchor'] or row.stop <= start or row.first >= stop:
                kept.append(row)
                continue
            need(row.object_generation == step['object_generation'] and row.lifetime_generation == generation,
                 'SS_STALE_LIFETIME')
            first, last = max(start, row.first), min(stop, row.stop)
            need(first == cursor, 'SS_CURRENT_HOLE')
            taken.append(self.sliced(row, first, last))
            if row.first < first:
                kept.append(self.sliced(row, row.first, first))
            if last < row.stop:
                kept.append(self.sliced(row, last, row.stop))
            cursor = last
        need(cursor == stop, 'SS_CURRENT_HOLE')
        return tuple(kept), tuple(taken)

    def apply(self, step):
        """Commit only after all action checks/allocations and candidate validation."""
        before = self.state
        self.budget.charge(work=16, edges=4, copied_bytes=256)
        history, current, ended, published = before.history, before.current, before.ended, before.published
        kind = step['kind']
        if kind == 'initialize':
            pattern = self.pattern(step['pattern'], step)
            need(step['source_anchor'] not in published, 'SS_HISTORY_AFTER_PUBLICATION')
            need(step['initialization_schedule'] == pattern['initialization_schedule'], 'SS_SCHEDULE_MEMBERSHIP')
            need(history[step['pattern']] < step['next_prefix'] <= pattern['required_prefix'], 'SS_HISTORY_PROGRESS')
            self.budget.charge(work=len(history), copied_bytes=128 * len(history))
            history = dict(history)
            history[step['pattern']] = step['next_prefix']
        elif kind in {'end', 'cleanup'}:
            current, removed = self.take(current, step, step['lifetime_generation'])
            if kind == 'cleanup':
                domain = step['source_anchor'], step['object_generation'], step['cleanup_schedule']
                self.budget.work(len(current) + len(removed))
                lowest = min(row.ordinal_first for row in removed)
                need(all(row.domain != domain or row.last_ordinal < lowest for row in current), 'SS_CLEANUP_ORDER')
            self.budget.charge(work=len(ended) + len(removed), copied_bytes=64 * (len(ended) + len(removed)))
            ended = ended + removed
        elif kind == 'replace':
            self.request(step)
            need(step['old_lifetime_generation'] < U64 and step['new_lifetime_generation'] ==
                 step['old_lifetime_generation'] + 1, 'SS_LIFETIME_GENERATION')
            ended, removed = self.take(ended, step, step['old_lifetime_generation'])
            self.budget.charge(work=len(current) + len(removed), copied_bytes=320 * (len(current) + len(removed)))
            added = tuple(replace(row, lifetime_generation=step['new_lifetime_generation']) for row in removed)
            current = current + added
        elif kind == 'observe':
            pattern = self.pattern(step['pattern'], step)
            need(step['index'] < pattern['count'], 'SS_RANGE_BOUNDS')
            self.budget.work(len(current))
            need(any(row.pattern == step['pattern'] and row.source_anchor == step['source_anchor'] and
                     row.first <= step['index'] < row.stop and row.lifetime_generation == step['lifetime_generation']
                     for row in current), 'SS_STALE_LIFETIME')
        else:  # Closed schema admits only publish here.
            need(kind == 'publish', 'SS_ACTION')
            self.anchor(step)
            schedule = self.get(self.schedules, step['initialization_schedule'])
            need(schedule['kind'] == 'initialization' and schedule['source_anchor'] == step['source_anchor'] and
                 schedule['object_generation'] == step['object_generation'], 'SS_SCHEDULE_MEMBERSHIP')
            need(step['source_anchor'] not in published, 'SS_PUBLICATION_REPLAY')
            self.budget.work(len(self.patterns))
            need(all(prefix == self.patterns[identity]['required_prefix'] for identity, prefix in history.items()
                     if self.patterns[identity]['source_anchor'] == step['source_anchor']), 'SS_INITIALIZATION_INCOMPLETE')
            self.budget.charge(work=len(published), copied_bytes=64 * (len(published) + 1))
            published = published | {step['source_anchor']}
        candidate = _State(history, current, ended, published)
        self.validate(candidate)
        self.state, self.steps = candidate, self.steps + 1

    def run(self):
        for step in self.actions:
            self.apply(step)
        state = self.state
        count = len(self.anchors) + len(state.history) + len(state.current) + len(state.ended)
        self.budget.charge(work=count * max(1, count.bit_length()), copied_bytes=512 * count)
        return StaticSourceState(
            tuple(sorted((a['id'], a['object_generation'], a['complete_owner'], a['id'] in state.published)
                         for a in self.anchors.values())), tuple(sorted(state.history.items())),
            tuple(sorted(row.frozen() for row in state.current)), tuple(sorted(row.frozen() for row in state.ended)),
            self.steps, ('actual original source anchor/schedule/class/path/canonical-cell membership',
                         'actual initialization/end/reconstruction/cleanup source effects and definedness',
                         'actual object/allocation/alias generations and view/claim/J/scope admission',
                         'conditional labels and ranges issue no source or runtime authority'))


def verify(document, *, budget):
    """Validate the new UNBOUND model with a genuine caller-owned cumulative budget."""
    try:
        preflight(document, budget)
        size = SCHEMA.stat().st_size
        need(size <= 256 * 1024, 'SS_SCHEMA_RESOURCE')
        budget.charge(work=8 * size, copied_bytes=8 * size)
        with SCHEMA.open('rb') as stream:
            source = stream.read(size + 1)
        need(len(source) == size, 'SS_SCHEMA_CHANGED')
        schema = json.loads(source)
        captured = deepcopy(document)  # Preflight charges bounded input-node/string storage.
        shape(schema, captured, schema['$defs'], budget)
        result = _Model(captured, budget).run()
        budget.charge(work=4 * size, copied_bytes=2 * size)
        with SCHEMA.open('rb') as stream:
            after = stream.read(size + 1)
        need(hashlib.sha256(after).digest() == hashlib.sha256(source).digest(), 'SS_SCHEMA_CHANGED')
        return result
    except ContractError as error:
        kind = 'resource' if error.code == 'SL_RESOURCE' else error.kind
        raise SourceStateError(error.code.replace('SL_', 'SS_', 1), error.detail, kind) from error
