"""Closed, explicitly UNBOUND normal-scope association protocol reference.

Rows are conditional hypotheses, never actual SourceFacts or runtime issuers.
RetainedCall remains unavailable; no guest instruction/effect is executed here.
"""
from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/runtime/normal_scope_outcomes.json'
MAX_NODES = 200000
MAX_BYTES = 8 * 1024 * 1024
MAX_PERMITS = 4096
MAX_SCHEMA_BYTES = 256 * 1024
EXPECTED_SCHEMA_SHA256 = 'bd54702cfb5362f3f8ffacce52f00be176283c88a0482bafe77176a562fc3b9e'


class ContractError(ValueError):
    def __init__(self, code, detail='', kind='semantic'):
        self.code, self.detail, self.kind = code, detail, kind
        super().__init__(code + (': ' + detail if detail else ''))


def need(value, code, detail='', kind='semantic'):
    if not value:
        raise ContractError(code, detail, kind)


def source_api():
    name = '_rax_smir_source_data_v1'
    path = ROOT / 'tools/smir-runtime-contract/source_roles/source_data.py'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
    actual = getattr(module, '__file__', None)
    need(type(actual) is str and Path(actual).resolve() == path.resolve(), 'NSO_SOURCE_API_MODULE')
    return module


def capture(value, budget):
    """Bound before allocating; input aliases cannot mutate the model snapshot."""
    ancestors = set()
    used = [0, 0]
    def visit(item, depth):
        budget.charge(work=2, edges=1, copied_bytes=64)
        used[0] += 1; used[1] += 64
        need(used[0] <= MAX_NODES and used[1] <= MAX_BYTES and
             depth <= min(64, budget.max_depth), 'NSO_RESOURCE', kind='resource')
        kind = type(item)
        if kind is str:
            need(len(item) <= 4096, 'NSO_RESOURCE', kind='resource')
            budget.charge(work=len(item), copied_bytes=4 * len(item)); used[1] += 4 * len(item)
            need(used[1] <= MAX_BYTES, 'NSO_RESOURCE', kind='resource')
            return item
        if kind is int:
            need(item.bit_length() <= 64, 'NSO_INTEGER_RANGE')
            return item
        if item is None or kind is bool:
            return item
        need(kind in (dict, list), 'NSO_SHAPE')
        need(id(item) not in ancestors, 'NSO_CYCLE')
        ancestors.add(id(item))
        try:
            budget.charge(work=len(item), edges=len(item), copied_bytes=16 * len(item))
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            need(all(type(key) is str for key in item), 'NSO_SHAPE')
            return {visit(key, depth + 1): visit(child, depth + 1) for key, child in item.items()}
        finally:
            ancestors.remove(id(item))
    return visit(value, 0), used[1] + used[0] * 16


def shape(rule, value, definitions, budget):
    budget.work(2)
    if '$ref' in rule:
        return shape(definitions[rule['$ref'].rsplit('/', 1)[1]], value, definitions, budget)
    if 'anyOf' in rule:
        branches = rule['anyOf']
        if value is None:
            chosen = [branch for branch in branches if branch.get('type') == 'null']
        elif type(value) is dict:
            chosen = [branch for branch in branches if branch.get('properties', {}).get('kind', {}).get('const') == value.get('kind')]
        else:
            chosen = [branch for branch in branches if '$ref' in branch]
        need(len(chosen) == 1, 'NSO_SHAPE')
        return shape(chosen[0], value, definitions, budget)
    if 'const' in rule:
        need(type(value) is type(rule['const']) and value == rule['const'], 'NSO_SHAPE')
    if 'enum' in rule:
        need(type(value) is str and value in rule['enum'], 'NSO_SHAPE')
    kind = rule.get('type')
    if kind == 'integer':
        need(type(value) is int and rule['minimum'] <= value <= rule['maximum'], 'NSO_SHAPE')
    elif kind == 'string':
        need(type(value) is str and re.fullmatch(rule['pattern'], value) is not None, 'NSO_SHAPE')
    elif kind == 'null':
        need(value is None, 'NSO_SHAPE')
    elif kind == 'object':
        need(type(value) is dict and set(value) == set(rule['required']), 'NSO_SHAPE')
        budget.charge(work=len(value), edges=len(value))
        for name, child in rule['properties'].items():
            shape(child, value[name], definitions, budget)
    elif kind == 'array':
        need(type(value) is list and len(value) <= rule['maxItems'], 'NSO_SHAPE')
        budget.charge(work=len(value), edges=len(value))
        for child in value:
            shape(rule['items'], child, definitions, budget)


@dataclass(frozen=True)
class ConditionalResult:
    conditional_document_digest: str
    model_schema_digest: str
    closed_scopes: tuple
    live_journals: tuple
    checked_events: int
    unresolved: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


class ConditionalModel:
    """Serial protocol hypotheses; not a private owner, permit or guest engine."""
    def __init__(self, document, *, budget):
        need(type(budget) is source_api().SourceQueryBudget, 'NSO_BUDGET_IDENTITY')
        self.budget = budget
        self.document, self.copy_cost = capture(document, budget)
        # Charge the bounded data capture BEFORE opening or reading it. The
        # extra byte detects growth after stat without an unbounded read.
        size = SCHEMA.stat().st_size
        need(0 < size <= MAX_SCHEMA_BYTES, 'NSO_SCHEMA_RESOURCE', kind='resource')
        budget.charge(work=size + 1, copied_bytes=4 * (size + 1))
        with SCHEMA.open('rb') as source:
            schema_bytes = source.read(size + 1)
        need(len(schema_bytes) == size and hashlib.sha256(schema_bytes).hexdigest() ==
             EXPECTED_SCHEMA_SHA256, 'NSO_SCHEMA_IDENTITY')
        self.schema = json.loads(schema_bytes)
        shape(self.schema, self.document, self.schema['$defs'], budget)
        self.schema_digest = hashlib.sha256(schema_bytes).hexdigest()
        budget.charge(work=4 * self.copy_cost, copied_bytes=2 * self.copy_cost)
        self.document_digest = self._digest(self.document)
        contexts = self.document['contexts']
        budget.charge(work=len(contexts), edges=len(contexts), copied_bytes=64 * len(contexts))
        need(len(contexts) == len(set(contexts)), 'NSO_DUPLICATE')
        self.contexts = set(contexts)
        for table in ['owners', 'objects', 'journals', 'views', 'scopes', 'handoffs', 'receipts']:
            rows = self.document[table]
            budget.charge(work=len(rows), edges=len(rows), copied_bytes=128 * len(rows))
            index = {row['id']: row for row in rows}
            need(len(index) == len(rows), 'NSO_DUPLICATE')
            setattr(self, table, index)
        self.permits = {}
        self.revision = 0
        self.checked_events = 0
        self._validate()
        self._state_digest = self._digest(self._state())
        self._protocol_digest = self._digest(self.document)

    @staticmethod
    def _digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()

    @property
    def state_digest(self):
        return self._state_digest

    def _state(self):
        return {name: self.document[name] for name in ['owners', 'objects', 'journals', 'views', 'scopes']}

    def _get(self, table, key):
        need(key in table, 'NSO_REFERENCE')
        return table[key]

    def _association(self, row):
        scope = self._get(self.scopes, row['scope'])
        view = self._get(self.views, row['view'])
        need(scope['view'] == view['id'] and row['scope_generation'] == scope['generation'], 'NSO_ASSOCIATION')
        need(row['program'] == view['program'] and row['object'] == view['object'] and
             row['object_generation'] == view['object_generation'] and row['owner'] == view['owner'] and
             row['owner_generation'] == view['owner_generation'], 'NSO_ASSOCIATION')
        return scope, view

    def _validate(self):
        for owner in self.owners.values():
            need(owner['context'] in self.contexts, 'NSO_CONTEXT')
        for obj in self.objects.values():
            need(obj['context'] in self.contexts, 'NSO_CONTEXT')
        for view in self.views.values():
            owner = self._get(self.owners, view['owner']); obj = self._get(self.objects, view['object'])
            need(view['program']['context'] == owner['context'] == obj['context'], 'NSO_CONTEXT')
            need(view['owner_generation'] == owner['generation'] and view['object_generation'] == obj['generation'], 'NSO_GENERATION')
            if view['state'] == 'live':
                journal = self._get(self.journals, view['journal'])
                need(journal['state'] == 'live' and journal['view'] == view['id'], 'NSO_CURRENT_JOURNAL')
            else:
                need(view['journal'] is None, 'NSO_CURRENT_JOURNAL')
        for journal in self.journals.values():
            view = self._get(self.views, journal['view'])
            need(journal['owner'] == view['owner'] and journal['owner_generation'] == view['owner_generation'], 'NSO_JOURNAL_OWNER')
            if journal['state'] == 'live':
                need(view['state'] == 'live' and view['journal'] == journal['id'], 'NSO_CURRENT_JOURNAL')
        for scope in self.scopes.values():
            self._get(self.views, scope['view'])
        for row in self.handoffs.values():
            scope, view = self._association(row)
            journal = self._get(self.journals, row['current_journal'])
            need(journal['view'] == view['id'] and journal['owner'] == view['owner'], 'NSO_ASSOCIATION')
            holder = row['holder']
            if holder['kind'] == 'scope':
                retained = self._get(self.scopes, holder['scope'])
                need(retained['id'] != scope['id'] and retained['view'] == view['id'] and
                     retained['generation'] == holder['generation'], 'NSO_RETAINED_HOLDER')
            else:
                need(holder['owner'] == view['owner'] and holder['owner_generation'] == view['owner_generation'], 'NSO_RETAINED_HOLDER')
        for row in self.receipts.values():
            _, view = self._association(row)
            journal = self._get(self.journals, row['input_journal'])
            need(journal['view'] == view['id'] and journal['state'] == 'consumed', 'NSO_TERMINAL_RECEIPT')
            if row['kind'] == 'published':
                need(view['state'] == 'published' and view['mode'] == 'construct' and view['program']['view'] == 'complete', 'NSO_TERMINAL_RECEIPT')
            else:
                need(view['state'] == 'view_completed', 'NSO_TERMINAL_RECEIPT')
                need((row['kind'] == 'destruction_completed' and view['mode'] == 'destroy') or
                     (row['kind'] == 'view_completed' and view['mode'] == 'construct' and view['program']['view'] == 'nonvirtual'), 'NSO_TERMINAL_RECEIPT')

    def _charge_step(self):
        count = sum(len(getattr(self, table)) for table in ['owners', 'objects', 'journals', 'views', 'scopes', 'handoffs', 'receipts'])
        self.budget.charge(work=64 + 4 * self.copy_cost, edges=16 + count, copied_bytes=2 * self.copy_cost + 512)

    def _check(self, event):
        self._validate()
        scope = self._get(self.scopes, event['scope']); view = self.views[scope['view']]
        need(scope['state'] == 'open', 'NSO_SCOPE_REPLAY')
        need(scope['generation'] == event['generation'], 'NSO_GENERATION')
        need((scope['subject'] == 'physical') == (event['location'] == 'return_exit'), 'NSO_SITE_MATRIX')
        owner = self.owners[view['owner']]
        need(owner['state'] in ('active', 'retained'), 'NSO_OWNER_LIVENESS')
        if event['evidence'] is None:
            raise ContractError('NSO_NORMAL_OUTCOME_UNAVAILABLE', kind='unavailable')
        if event['journal'] is None:
            need(view['state'] in ('published', 'view_completed'), 'NSO_TERMINAL_RECEIPT')
            evidence = self._get(self.receipts, event['evidence'])
        else:
            need(view['state'] == 'live' and view['journal'] == event['journal'] and
                 self.journals[event['journal']]['state'] == 'live', 'NSO_CURRENT_JOURNAL')
            evidence = self._get(self.handoffs, event['evidence'])
            need(evidence['current_journal'] == event['journal'], 'NSO_CURRENT_JOURNAL')
            holder = evidence['holder']
            if scope['subject'] == 'physical':
                need(holder['kind'] == 'call', 'NSO_PHYSICAL_RETENTION')
            if holder['kind'] == 'scope':
                retained = self.scopes[holder['scope']]
                need(retained['state'] == 'open' and retained['generation'] == holder['generation'], 'NSO_RETAINED_HOLDER')
            else:
                # Representation and known owner/association checks still precede
                # this absent exact source-return-retention contract.
                need(evidence['scope'] == scope['id'] and evidence['frontier'] == event['frontier'], 'NSO_ASSOCIATION')
                raise ContractError('NSO_RETAINED_CALL_CONTRACT', kind='unavailable')
        need(evidence['scope'] == scope['id'] and evidence['scope_generation'] == scope['generation'] and
             evidence['view'] == view['id'] and evidence['frontier'] == event['frontier'], 'NSO_ASSOCIATION')
        return scope

    def preflight(self, event):
        captured, _ = capture(event, self.budget)
        shape(self.schema['$defs']['event'], captured, self.schema['$defs'], self.budget)
        need(captured['kind'] == 'preflight', 'NSO_EVENT')
        self._charge_step()
        self._check(captured)
        observed = self._digest(self.document)
        need(observed == self._protocol_digest, 'NSO_STALE_IDENTITY')
        need(captured['permit'] not in self.permits, 'NSO_PERMIT_REPLAY')
        need(len(self.permits) < MAX_PERMITS, 'NSO_RESOURCE', kind='resource')
        self.permits[captured['permit']] = {'event': captured, 'revision': self.revision, 'observed': observed, 'consumed': False}
        return captured['permit']

    def commit(self, permit):
        need(type(permit) is str and len(permit) <= 128, 'NSO_PERMIT')
        self.budget.work(len(permit) + 1)
        self._charge_step()
        row = self._get(self.permits, permit)
        need(not row['consumed'], 'NSO_PERMIT_REPLAY')
        scope = self._check(row['event'])
        need(row['revision'] == self.revision, 'NSO_STALE_PERMIT')
        need(self._digest(self.document) == row['observed'] == self._protocol_digest, 'NSO_STALE_IDENTITY')
        need(self.revision < 2**64 - 1, 'NSO_RESOURCE', kind='resource')
        # All logical work/copy quota has been charged. Only projection/once
        # bookkeeping changes; original owner/view/J/object state is retained.
        row['consumed'] = True
        scope['state'] = 'closed'
        self.revision += 1
        self._state_digest = self._digest(self._state())
        self._protocol_digest = self._digest(self.document)

    def run(self):
        for event in self.document['events']:
            if event['kind'] == 'preflight':
                self.preflight(event)
            else:
                self.commit(event['permit'])
            self.checked_events += 1
        count = len(self.scopes) + len(self.journals)
        self.budget.charge(work=count * (count.bit_length() + 1), edges=count, copied_bytes=64 * count)
        return ConditionalResult(self.document_digest, self.schema_digest,
            tuple(sorted(key for key, scope in self.scopes.items() if scope['state'] == 'closed')),
            tuple(sorted(key for key, journal in self.journals.items() if journal['state'] == 'live')),
            self.checked_events,
            ('All original source/ABI/normal outcomes/owner retention are explicit conditional assumptions.',
             'No actual CPP alias/claim/view/Journal/Scope/runtime issuer or typed source association is supplied.',
             'Initialization history/current masks and source legality require their separately checked original contracts.',
             'RetainedCall source-return-retention contract is unassigned and cannot succeed.'))


def verify(document, *, budget):
    return ConditionalModel(document, budget=budget).run()
