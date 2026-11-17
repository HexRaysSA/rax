"""Unbound compiler requirements and conditional lifetime protocol verification.

No result is a SourceFact, ObjectClaim, JournalView, Scope or execution admission.
ABI coverage/geometry and source-trait witness tables are explicit hypotheses.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from candidate.source_data_projection import source_api

SCHEMA = Path(__file__).resolve().parents[4] / 'docs/specifications/smir/portable/schema/execution/source_lifetimes.json'
MAX_NODES = 200000
MAX_BYTES = 8 * 1024 * 1024
U64_MAX = 2**64 - 1


class ContractError(ValueError):
    """Local draft diagnostic; no shared public error ID is allocated."""
    def __init__(self, code, detail='', kind='semantic'):
        self.code, self.detail, self.kind = code, detail, kind
        super().__init__(code + (': ' + detail if detail else ''))


def fail(code, detail='', kind='semantic'):
    raise ContractError(code, detail, kind)


def need(condition, code, detail=''):
    if not condition:
        fail(code, detail)


@dataclass(frozen=True)
class StaticLifetimeObligations:
    producer: tuple
    abi: tuple
    runtime: tuple
    implicit_created: tuple
    checked_steps: int
    pending: tuple
    binding: str = 'unbound'
    runtime_authority: bool = False
    source_fact_authority: bool = False


def preflight(value, budget):
    need(type(budget) is source_api().SourceQueryBudget, 'SL_BUDGET_IDENTITY')
    stack, ancestors, nodes, copied = [(value, 0, False)], set(), 0, 0
    while stack:
        item, depth, leaving = stack.pop()
        if leaving:
            ancestors.remove(id(item))
            continue
        nodes += 1
        budget.charge(work=2, edges=1, copied_bytes=64)
        need(nodes <= MAX_NODES and depth <= min(64, budget.max_depth), 'SL_RESOURCE')
        kind = type(item)
        if kind is str:
            need(len(item) <= 4096, 'SL_RESOURCE')
            copied += 4 * len(item)
            budget.charge(work=len(item), copied_bytes=4 * len(item))
        elif kind in (dict, list):
            need(id(item) not in ancestors, 'SL_INPUT_CYCLE')
            need(len(item) <= 65536, 'SL_RESOURCE')
            ancestors.add(id(item))
            stack.append((item, depth, True))
            if kind is dict:
                need(all(type(key) is str for key in item), 'SL_SHAPE')
                for key, child in item.items():
                    stack.append((child, depth + 1, False))
                    stack.append((key, depth + 1, False))
            else:
                stack.extend((child, depth + 1, False) for child in item)
        else:
            need(kind in (int, bool, type(None)), 'SL_SHAPE')
        need(copied <= MAX_BYTES, 'SL_RESOURCE')


def shape(rule, value, definitions, budget, depth=0):
    budget.charge(work=2, edges=1)
    need(depth <= min(96, budget.max_depth), 'SL_RESOURCE')
    if '$ref' in rule:
        return shape(definitions[rule['$ref'].split('/')[-1]], value, definitions, budget, depth + 1)
    if 'anyOf' in rule:
        for alternative in rule['anyOf']:
            try:
                shape(alternative, value, definitions, budget, depth + 1)
                return
            except ContractError as error:
                if error.code != 'SL_SHAPE':
                    raise
        fail('SL_SHAPE', 'no closed variant matches')
    if 'const' in rule:
        need(type(value) is type(rule['const']) and value == rule['const'], 'SL_SHAPE')
    if 'enum' in rule:
        need(any(type(value) is type(choice) and value == choice for choice in rule['enum']), 'SL_SHAPE')
    kind = rule.get('type')
    classes = {'object': dict, 'array': list, 'integer': int, 'string': str,
               'boolean': bool, 'null': type(None)}
    if kind is not None:
        need(type(value) is classes[kind], 'SL_SHAPE', kind)
    if kind == 'object':
        need(set(value) == set(rule['required']) and rule['additionalProperties'] is False, 'SL_SHAPE')
        for key, child in value.items():
            shape(rule['properties'][key], child, definitions, budget, depth + 1)
    elif kind == 'array':
        need(len(value) <= rule['maxItems'], 'SL_SHAPE')
        for child in value:
            shape(rule['items'], child, definitions, budget, depth + 1)
    elif kind == 'integer':
        need(rule['minimum'] <= value <= rule['maximum'], 'SL_SHAPE')
    elif kind == 'string':
        need(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', 4096), 'SL_SHAPE')
        need('pattern' not in rule or re.fullmatch(rule['pattern'], value) is not None, 'SL_SHAPE')


def index(rows, budget, key='id'):
    budget.charge(work=len(rows), edges=len(rows), copied_bytes=64 * len(rows))
    result = {}
    for row in rows:
        identity = key(row) if callable(key) else row[key]
        need(identity not in result, 'SL_DUPLICATE', str(identity))
        result[identity] = row
    return result


def select(rows, identity):
    need(identity in rows, 'SL_REFERENCE', str(identity))
    return rows[identity]


def equivalent(left, right):
    return left == right  # Original context/namespace/qref expectations, never provider aliases.


class Verifier:
    def __init__(self, document, budget):
        self.budget = budget
        self.contract, self.witness = document['contract'], deepcopy(document['witness'])
        contract = self.contract
        self.contexts = index(contract['contexts'], budget)
        self.programs = index(contract['program_requirements'], budget)
        self.bindings = index(contract['object_bindings'], budget)
        self.ends = index(contract['end_sites'], budget)
        self.implicit = index(contract['implicit_sets'], budget)
        self.exits = index(contract['scope_exits'], budget)
        self.patterns = index(self.witness['cell_models'], budget)
        self.models = index(self.witness['program_models'], budget, 'program')
        state = self.witness['initial']
        self.allocations = index(state['allocations'], budget)
        self.objects = index(state['objects'], budget)
        self.aliases = index(state['aliases'], budget)
        self.views = index(state['views'], budget)
        self.scopes = index(state['scopes'], budget)
        self.frames = index(state['frames'], budget)
        self.cells = index(state['cells'], budget, lambda row: (row['owner'], row['cell']))
        self.journals, self.receipts, self.claims, self.tickets, self.frontiers = {}, {}, {}, {}, {}
        self.propagations = set()
        self.completed_implicit = []
        self.trapped = False
        self.validate_contract()
        self.counts = self.cell_counts()
        self.validate_initial()

    def external(self, value, namespace, context=None):
        select(self.contexts, value['context'])
        need(value['namespace'] == namespace, 'SL_NAMESPACE', namespace)
        need(context is None or value['context'] == context, 'SL_CONTEXT')
        return value

    def validate_contract(self):
        original_programs = set()
        for program in self.programs.values():
            context = self.external(program['program'], 'Journal')['context']
            self.external(program['source_class'], 'Nominal', context)
            self.external(program['coverage'], 'CppCoverage', context)
            identity = (context, json.dumps(program['program']['reference'], sort_keys=True))
            self.budget.charge(work=len(identity[1]), copied_bytes=len(identity[1]))
            need(identity not in original_programs, 'SL_PROGRAM_IDENTITY')
            original_programs.add(identity)
        for binding in self.bindings.values():
            context = self.external(binding['function'], 'Function')['context']
            self.external(binding['source_class'], 'Nominal', context)
            self.external(binding['source_path'], 'CppSourcePath', context)
            origin = binding['origin']
            if 'plan' in origin:
                self.external(origin['plan'], 'CallSignature', context)
                need(origin['plan']['reference']['module']['kind'] == 'self', 'SL_PLAN_SELF')
            if origin['kind'] in {'retained_alias', 'transparent_replacement', 'launder'}:
                source = origin.get('source_value', origin.get('previous_value'))
                need(source != binding['value'], 'SL_ALIAS_SELF')
        for end in self.ends.values():
            binding = select(self.bindings, end['binding'])
            kind, effect = end['effect']['kind'], end['effect']
            location = end['location']['kind']
            if kind == 'destructor_preentry':
                need(end['stage'] == 'ordinary_end' and end['reason'] == 'scope_end' and
                     location in {'pre_op', 'pre_terminator'}, 'SL_END_FRONTIER')
                self.external(effect['plan'], 'CallSignature', binding['function']['context'])
            elif kind == 'trivial_end':
                need(end['stage'] == 'ordinary_end' and end['reason'] == 'scope_end' and
                     location in {'pre_op', 'pre_terminator'}, 'SL_END_FRONTIER')
            elif kind in {'reuse_commit', 'deallocation_commit'}:
                need(end['stage'] == 'ordinary_end' and location in {'normal_post', 'invoke_normal'} and
                     end['reason'] == ('reuse' if kind == 'reuse_commit' else 'storage_release'),
                     'SL_END_FRONTIER')
            else:
                need(end['stage'] in {'destructive_retire', 'failed_construction_retire'} and
                     location in {'normal_post', 'invoke_normal'}, 'SL_END_FRONTIER')
                select(self.programs, effect['program'])
        for implicit in self.implicit.values():
            binding = select(self.bindings, implicit['binding'])
            self.external(implicit['source_class'], 'Nominal', binding['function']['context'])
            need(equivalent(binding['source_class'], implicit['source_class']), 'SL_IMPLICIT_TYPE')
        for site in self.exits.values():
            self.external(site['function'], 'Function')
            mode, journal_mode = site['helper'].split('.')
            need((site['journal'] is not None) == (journal_mode == 'with_journal'), 'SL_EXIT_JOURNAL')
            kind, subject = site['location']['kind'], site['subject']
            if mode == 'normal':
                allowed = {'return_exit'} if subject == 'physical' else {'pre_op', 'pre_terminator', 'normal_post'}
                need(site['exception'] is None, 'SL_EXIT_EXCEPTION')
            elif mode == 'unwind':
                allowed = {'unwind_exit'} if subject == 'physical' else {'invoke_unwind', 'unwind_exit', 'pre_op', 'pre_terminator'}
                need(site['exception'] is not None, 'SL_EXIT_EXCEPTION')
            else:
                allowed = {'unwind_exit'}
                need(site['exception'] is None, 'SL_EXIT_EXCEPTION')
            need(kind in allowed, 'SL_EXIT_LOCATOR')
            need(site['scope_value'] not in {site['journal'], site['exception']} and
                 (site['journal'] is None or site['journal'] != site['exception']), 'SL_EXIT_SSA_TYPE')

    def cell_counts(self):
        counts, visiting = {}, set()
        def visit(identity, depth):
            self.budget.charge(work=4, edges=1)
            need(depth <= min(64, self.budget.max_depth), 'SL_RESOURCE')
            need(identity not in visiting, 'SL_CELL_CYCLE')
            if identity in counts:
                return counts[identity]
            cell = select(self.patterns, identity)
            visiting.add(identity)
            if cell['parent'] is None:
                need(cell['role'] == 'root' and cell['repeat'] == 1, 'SL_CELL_ROOT')
                total = 1
            else:
                need(cell['role'] != 'root', 'SL_CELL_ROOT')
                total = visit(cell['parent'], depth + 1) * cell['repeat']
            need(total <= U64_MAX, 'SL_CELL_COUNT')
            need(cell['role'] == 'union_member' or cell['union_selected'] is None, 'SL_UNION_SELECTION')
            visiting.remove(identity)
            counts[identity] = total
            return total
        for identity in self.patterns:
            visit(identity, 0)
        return counts

    def implicit_created(self, identity):
        select(self.implicit, identity)
        created, active_union = {}, {}
        def visit(cell_id):
            self.budget.charge(work=4, edges=1)
            if cell_id in created:
                return created[cell_id]
            cell = self.patterns[cell_id]
            parent = cell['parent']
            available = 1 if parent is None else visit(parent)
            live = bool(available and cell['implicit_eligible'])
            if live and cell['role'] == 'union_member':
                if cell['union_selected'] is None:
                    fail('SL_IMPLICIT_UNION_SELECTION', kind='unavailable')
                live = cell['union_selected']
                if live:
                    need(parent not in active_union, 'SL_UNION_SELECTION')
                    active_union[parent] = cell_id
            created[cell_id] = self.counts[cell_id] if live else 0
            return created[cell_id]
        for cell_id in self.patterns:
            visit(cell_id)
        need(all(cell['implicit_eligible'] for cell in self.patterns.values() if cell['parent'] is None),
             'SL_IMPLICIT_ROOT')
        return tuple((cell, count) for cell, count in created.items())

    def binding(self, identity):
        return select(self.bindings, identity)

    def model(self, view):
        return select(self.models, view['program'])

    def coverage(self, view):
        return self.model(view)['coverage']

    def view_association(self, view):
        obj = select(self.objects, view['object'])
        frame = select(self.frames, view['owner'])
        program = select(self.programs, view['program'])
        self.external(program['program'], 'Journal', frame['context'])
        need(view['generation'] == obj['object_generation'] and obj['state'] != 'ended' and
             view['scope_generation'] > 0, 'SL_GENERATION')
        need(equivalent(self.binding(obj['binding'])['source_class'], program['source_class']), 'SL_VIEW_CLASS')
        need(view['program'] in self.models, 'SL_REFERENCE')
        need(obj['offset'] + self.model(view)['extent_bytes'] <= self.allocations[obj['allocation']]['size'],
             'SL_EXTENT')
        self.budget.work(len(self.coverage(view)))
        for cell in self.coverage(view):
            need((obj['complete_owner'], cell) in self.cells, 'SL_CELL_STATE_MISSING')
        return obj, frame, program

    def covered_states(self, view):
        self.budget.work(len(self.cells) + len(self.coverage(view)))
        owner = self.objects[view['object']]['complete_owner']
        coverage = set(self.coverage(view))
        return [state for (object_id, cell), state in self.cells.items()
                if object_id == owner and cell in coverage]

    def validate_initial(self):
        for model in self.models.values():
            program = select(self.programs, model['program'])
            need(model['extent_bytes'] > 0, 'SL_ZERO_NV_VIEW' if program['view'] == 'nonvirtual' else 'SL_EXTENT')
            self.budget.work(2 * len(model['coverage']))
            need(len(set(model['coverage'])) == len(model['coverage']), 'SL_DUPLICATE')
            for cell_id in model['coverage']:
                cell = select(self.patterns, cell_id)
                current = cell
                while current['parent'] is not None:
                    self.budget.work(2)
                    need(program['view'] != 'nonvirtual' or current['role'] != 'virtual_base', 'SL_NV_VIRTUAL_COVERAGE')
                    current = self.patterns[current['parent']]
                need(program['view'] != 'nonvirtual' or cell['role'] != 'virtual_base', 'SL_NV_VIRTUAL_COVERAGE')
        for frame in self.frames.values():
            self.external(frame['function'], 'Function', frame['context'])
            need(frame['generation'] > 0, 'SL_GENERATION')
        for allocation in self.allocations.values():
            need(allocation['generation'] > 0 and allocation['address'] > 0 and
                 allocation['address'] + allocation['size'] <= U64_MAX, 'SL_ALLOCATION')
        for obj in self.objects.values():
            ancestors, current = set(), obj
            while current['parent'] is not None:
                self.budget.work(4)
                need(current['id'] not in ancestors, 'SL_OBJECT_PARENT_CYCLE')
                need(len(ancestors) < min(64, self.budget.max_depth), 'SL_RESOURCE')
                ancestors.add(current['id'])
                current = select(self.objects, current['parent'])
            binding = self.binding(obj['binding'])
            allocation = select(self.allocations, obj['allocation'])
            need(obj['allocation_generation'] == allocation['generation'] and obj['object_generation'] > 0,
                 'SL_GENERATION')
            owner = select(self.objects, obj['complete_owner'])
            need(owner['complete_owner'] == owner['id'], 'SL_COMPLETE_OWNER')
            need(obj['offset'] <= allocation['size'], 'SL_EXTENT')
            need((obj['parent'] is None) == (obj['parent_cell'] is None) and
                 (binding['role'] == 'complete') == (obj['parent'] is None), 'SL_PARENT')
            if obj['parent'] is not None:
                parent = select(self.objects, obj['parent'])
                cell = select(self.patterns, obj['parent_cell'])
                roles = {'virtual_base', 'nonvirtual_base'} if binding['role'] == 'base' else {'member', 'element', 'union_member'}
                need(cell['role'] in roles and obj['allocation'] == parent['allocation'] and
                     obj['offset'] >= parent['offset'], 'SL_PARENT')
            if binding['role'] == 'base':
                need(obj['parent'] is not None and obj['complete_owner'] == self.objects[obj['parent']]['complete_owner'],
                     'SL_COMPLETE_OWNER')
            else:
                need(obj['complete_owner'] == obj['id'], 'SL_COMPLETE_OWNER')
            if obj['implicit_set'] is not None:
                self.completed_implicit.append((obj['id'], self.implicit_created(obj['implicit_set'])))
            if obj['claim'] is not None:
                need(obj['state'] == 'destroying' and obj['claim'] not in self.claims, 'SL_CLAIM')
                self.budget.work(len(self.views))
                owners = {view['owner'] for view in self.views.values()
                          if view['object'] == obj['id'] and view['mode'] == 'destroy'}
                need(len(owners) == 1, 'SL_CLAIM_OWNER')
                self.claims[obj['claim']] = {'object': obj['id'], 'owner': next(iter(owners)),
                                            'generation': obj['object_generation']}
        for alias in self.aliases.values():
            self.binding(alias['binding'])
            select(self.objects, alias['object'])
            need(alias['owner_generation'] > 0, 'SL_ALIAS_ACTIVATION')
        for view in self.views.values():
            obj, frame, program = self.view_association(view)
            need((view['state'] == 'live') == (view['journal'] is not None), 'SL_JOURNAL')
            if view['journal'] is not None:
                self.fresh_journal(view['journal'], view['id'])
            if view['cleanup_receipt'] is not None:
                need(view['state'] in {'failed_cleared', 'view_completed', 'published'}, 'SL_RECEIPT')
                self.new_receipt(view['cleanup_receipt'], view['id'], view['state'], view['exception'])
        for scope in self.scopes.values():
            select(self.frames, scope['owner'])
            need(scope['generation'] > 0, 'SL_GENERATION')
            need(scope['view'] is not None or scope['subject'] != 'source_object', 'SL_SOURCE_OBJECT_ENTRY')
            if scope['view'] is not None:
                view = select(self.views, scope['view'])
                need(view['owner'] == scope['owner'] and view['object'] == scope['object'], 'SL_SCOPE_VIEW')
            if scope['object'] is not None:
                select(self.objects, scope['object'])
        for state in self.cells.values():
            owner = select(self.objects, state['owner'])
            need(owner['complete_owner'] == owner['id'] and state['generation'] == owner['object_generation'],
                 'SL_CELL_GENERATION')
            count = select(self.counts, state['cell'])
            need(state['completed'] <= count and ((state['completed'] == 0) == (state['ordinal'] == 0)), 'SL_COMPLETION')

    def fresh_journal(self, journal, view):
        need(journal not in self.journals, 'SL_JOURNAL_REPLAY')
        self.journals[journal] = {'view': view, 'live': True}

    def current(self, identity, journal):
        view = select(self.views, identity)
        need(view['state'] == 'live' and view['journal'] == journal, 'SL_STALE_JOURNAL')
        record = select(self.journals, journal)
        need(record['live'] and record['view'] == identity, 'SL_JOURNAL_OWNER')
        obj = self.objects[view['object']]
        need(view['generation'] == obj['object_generation'] and obj['state'] != 'ended', 'SL_GENERATION')
        select(self.frames, view['owner'])
        return view

    def consume_journal(self, view):
        self.journals[view['journal']]['live'] = False
        view['journal'] = None

    def new_receipt(self, identity, view, kind, exception):
        need(identity not in self.receipts, 'SL_RECEIPT_REPLAY')
        self.receipts[identity] = {'view': view, 'kind': kind, 'exception': exception}

    def alias(self, identity, owner):
        alias = select(self.aliases, identity)
        frame = select(self.frames, owner)
        need(alias['owner'] == owner and alias['owner_generation'] == frame['generation'] and
             equivalent(self.binding(alias['binding'])['function'], frame['function']), 'SL_ALIAS_ACTIVATION')
        obj = select(self.objects, alias['object'])
        allocation = select(self.allocations, obj['allocation'])
        need(alias['generation'] == obj['object_generation'] and alias['allocation_generation'] == allocation['generation']
             and obj['allocation_generation'] == allocation['generation'] and obj['state'] != 'ended', 'SL_STALE_ALIAS')
        source, target = self.binding(alias['binding']), self.binding(obj['binding'])
        need(equivalent(source['source_class'], target['source_class']) and
             equivalent(source['source_path'], target['source_path']) and source['role'] == target['role'], 'SL_ALIAS_SOURCE')
        return alias, obj

    def writable(self, view, cell):
        self.budget.work(len(self.coverage(view)))
        need(cell in self.coverage(view), 'SL_COVERAGE')
        self.budget.work(len(self.tickets) + 1)
        for ticket in self.tickets.values():
            self.budget.work(len(self.coverage(self.views[ticket['child']])))
            need(not (ticket['state'] == 'pending' and ticket['parent'] == view['id'] and
                      cell in self.coverage(self.views[ticket['child']])), 'SL_SUSPENDED_COVERAGE')

    def terminal(self, view, kind, receipt, exception=None):
        self.budget.work(len(self.tickets))
        need(not any(ticket['parent'] == view['id'] and ticket['state'] == 'pending'
                     for ticket in self.tickets.values()), 'SL_PENDING_CHILD')
        self.consume_journal(view)
        view['state'], view['cleanup_receipt'], view['exception'] = kind, receipt, exception
        self.new_receipt(receipt, view['id'], kind, exception)

    def run(self):
        for step in self.witness['actions']:
            self.budget.charge(work=8, edges=4, copied_bytes=128)
            need(not self.trapped, 'SL_AFTER_TRAP')
            name = step['kind']
            getattr(self, 'event_' + name)(step)
        self.budget.work(4 * (len(self.tickets) + len(self.frontiers) + len(self.scopes) + len(self.programs)))
        pending = tuple(sorted(identity for identity, ticket in self.tickets.items() if ticket['state'] == 'pending'))
        pending += tuple(sorted(identity for identity, frontier in self.frontiers.items() if frontier['pending'] is not None or frontier['cancelled']))
        pending += tuple(sorted(scope['pending'] for scope in self.scopes.values() if scope['pending'] is not None))
        return StaticLifetimeObligations(
            ('original source/class/eligibility/replacement truth', 'final CFG/SSA/original E and literal helper mapping'),
            tuple(sorted(self.programs)),
            ('actual object/alias allocation+source generations and source-path issuer',
             'actual program/coverage/view/claim/current-J/scope owner issuer',
             'actual atomic call-preentry claim and post-effect retirement/revocation',
             'actual retained frontier/cancellation/cleanup/exception outcome'),
            tuple(self.completed_implicit), len(self.witness['actions']), pending)

    def frontier_state(self, identity):
        frontier = select(self.frontiers, identity)
        frame = select(self.frames, frontier['owner'])
        need(frame['generation'] == frontier['generation'], 'SL_FRONTIER_OWNER')
        return frontier

    def leaving_frontiers(self, owner):
        self.budget.work(len(self.frontiers))
        for frontier in self.frontiers.values():
            if frontier['owner'] == owner:
                need(frontier['closed'] or (frontier['pending'] is None and not frontier['suspended'] and
                     not frontier['cancelled'] and frontier['next'] == len(frontier['candidates'])),
                     'SL_FRONTIER_EXIT')
                frontier['closed'] = True

    def event_frame_exit(self, step):
        owner = step['frame']
        select(self.frames, owner)
        self.budget.work(len(self.scopes) + len(self.views))
        need(not any(scope['owner'] == owner and scope['state'] == 'open' for scope in self.scopes.values()), 'SL_OPEN_SCOPE')
        need(not any(view['owner'] == owner and view['state'] == 'live' for view in self.views.values()), 'SL_LIVE_JOURNAL_EXIT')
        self.leaving_frontiers(owner)
        del self.frames[owner]

    def event_assign(self, step):
        _, obj = self.alias(step['alias'], step['owner'])
        need(obj['state'] == 'alive', 'SL_OBJECT_STATE')  # No generation or anchor change.

    def event_claim_destroy(self, step):
        alias, obj = self.alias(step['alias'], step['owner'])
        end = select(self.ends, step['end_site'])
        need(end['binding'] == alias['binding'] and end['effect']['kind'] == 'destructor_preentry', 'SL_END_EFFECT')
        select(self.frames, step['owner'])
        if step['preflight'] == 'rejected':
            return  # Conditional failed preflight has no claim/state publication.
        need(obj['state'] == 'alive' and obj['claim'] is None and step['claim'] not in self.claims, 'SL_CLAIM_REPLAY')
        obj['state'], obj['claim'] = 'destroying', step['claim']
        self.claims[step['claim']] = {'object': obj['id'], 'owner': step['owner'],
                                       'generation': obj['object_generation']}

    def event_bind_destroy(self, step):
        view = select(self.views, step['view'])
        obj = self.objects[view['object']]
        claim = select(self.claims, step['claim'])
        need(view['state'] == 'unbound' and view['mode'] == 'destroy' and obj['state'] == 'destroying' and
             obj['claim'] == step['claim'] and claim['object'] == obj['id'] and
             claim['owner'] == view['owner'] and claim['generation'] == obj['object_generation'], 'SL_CLAIM')
        self.fresh_journal(step['journal'], view['id'])
        view['state'], view['journal'] = 'live', step['journal']

    def event_end_object(self, step):
        alias, obj = self.alias(step['alias'], step['owner'])
        end = select(self.ends, step['end_site'])
        need(end['binding'] == alias['binding'], 'SL_END_BINDING')
        effect, stage = end['effect']['kind'], end['stage']
        if effect == 'destructor_preentry':
            fail('SL_END_DUPLICATE_CLAIM', 'ordinary end is the original claim transaction')
        if stage in {'destructive_retire', 'failed_construction_retire'}:
            need(obj['state'] == ('destroying' if stage == 'destructive_retire' else 'constructing'), 'SL_OBJECT_STATE')
            self.budget.work(len(self.views))
            matching = [view for view in self.views.values() if view['object'] == obj['id'] and
                        view['program'] == end['effect']['program'] and
                        view['state'] in ({'view_completed', 'failed_cleared'} if stage == 'destructive_retire' else {'failed_cleared'})]
            required_view = 'nonvirtual' if self.binding(obj['binding'])['role'] == 'base' else 'complete'
            need(len(matching) == 1 and self.programs[matching[0]['program']]['view'] == required_view, 'SL_END_RECEIPT')
        else:
            need(obj['state'] == 'alive', 'SL_OBJECT_STATE')
            self.budget.work(len(self.views))
            need(not any(view['object'] == obj['id'] and view['state'] == 'live' for view in self.views.values()), 'SL_END_CLEANUP')
        self.budget.work(len(self.views) + len(self.tickets))
        need(not any(view['object'] == obj['id'] and view['state'] == 'live' for view in self.views.values()),
             'SL_END_CLEANUP')
        need(not any(ticket['state'] == 'pending' and self.views[ticket['parent']]['object'] == obj['id']
                     for ticket in self.tickets.values()), 'SL_END_CLEANUP')
        if effect == 'deallocation_commit':
            allocation = self.allocations[obj['allocation']]
            need(step['next_allocation_generation'] is not None and allocation['generation'] < U64_MAX and
                 step['next_allocation_generation'] == allocation['generation'] + 1, 'SL_ALLOCATION_GENERATION')
            self.budget.work(len(self.objects))
            need(not any(other['allocation'] == obj['allocation'] and other['id'] != obj['id'] and
                         other['state'] != 'ended' for other in self.objects.values()), 'SL_RELEASE_CURRENT_OBJECTS')
            allocation['generation'] = step['next_allocation_generation']
        else:
            need(step['next_allocation_generation'] is None, 'SL_ALLOCATION_GENERATION')
        obj['state'] = 'ended'

    def event_replace_object(self, step):
        old_alias = select(self.aliases, step['old_alias'])
        old = self.objects[old_alias['object']]
        new, alias = step['new_object'], step['new_alias']
        frame = select(self.frames, step['owner'])
        need(alias['owner'] == step['owner'] and alias['owner_generation'] == frame['generation'] and
             equivalent(self.binding(alias['binding'])['function'], frame['function']), 'SL_ALIAS_ACTIVATION')
        need(old['state'] == 'ended' and new['id'] not in self.objects and alias['id'] not in self.aliases,
             'SL_REPLACEMENT')
        need(old['allocation'] == new['allocation'] and old['allocation_generation'] == new['allocation_generation'] and
             old['offset'] == new['offset'] and old['object_generation'] < U64_MAX and
             new['object_generation'] == old['object_generation'] + 1, 'SL_GENERATION')
        need(equivalent(self.binding(old['binding'])['source_class'], self.binding(new['binding'])['source_class']),
             'SL_REPLACEMENT_TYPE')
        need(alias['object'] == new['id'] and alias['generation'] == new['object_generation'] and
             alias['allocation_generation'] == new['allocation_generation'], 'SL_ALIAS_SOURCE')
        need(new['state'] == 'alive' and new['claim'] is None, 'SL_REPLACEMENT')
        need(new['complete_owner'] == new['id'] and new['parent'] is None and new['parent_cell'] is None,
             'SL_COMPLETE_OWNER')
        self.budget.work(4 * len(step['rebind_aliases']))
        need(len(set(step['rebind_aliases'])) == len(step['rebind_aliases']), 'SL_DUPLICATE')
        rebind = [select(self.aliases, identity) for identity in step['rebind_aliases']]
        need(all(existing['object'] == old['id'] and
                 existing['generation'] == old['object_generation'] and
                 existing['allocation_generation'] == old['allocation_generation'] for existing in rebind),
             'SL_REPLACEMENT_ALIAS')
        need(step['source_proof'] == 'transparent_replacement' or not rebind, 'SL_REPLACEMENT_ALIAS')
        source, target = self.binding(alias['binding']), self.binding(new['binding'])
        need(equivalent(source['source_class'], target['source_class']) and
             equivalent(source['source_path'], target['source_path']) and source['role'] == target['role'], 'SL_ALIAS_SOURCE')
        need(new['allocation_generation'] == self.allocations[new['allocation']]['generation'], 'SL_STALE_ALIAS')
        # Legality/reachability/elision truth is an explicit external producer obligation.
        self.objects[new['id']], self.aliases[alias['id']] = new, alias
        if step['source_proof'] == 'transparent_replacement':
            for existing in rebind:
                existing['object'], existing['generation'] = new['id'], new['object_generation']

    def event_delegate(self, step):
        parent, child = select(self.views, step['parent']), step['child']
        need(parent['state'] == 'live' and child['id'] not in self.views and step['ticket'] not in self.tickets,
             'SL_DELEGATION')
        need(child['object'] == parent['object'] and child['generation'] == parent['generation'] and
             child['state'] == 'live' and child['journal'] is not None, 'SL_DELEGATION_CLAIM')
        self.view_association(child)
        model = self.model(child)
        self.budget.work(len(model['coverage']) + len(self.coverage(parent)))
        need(set(model['coverage']) <= set(self.coverage(parent)), 'SL_COVERAGE')
        self.fresh_journal(child['journal'], child['id'])
        self.views[child['id']] = child
        self.tickets[step['ticket']] = {'parent': parent['id'], 'child': child['id'], 'state': 'pending'}

    def event_fail_partial(self, step):
        view = self.current(step['view'], step['old_journal'])
        ticket = select(self.tickets, step['failed_ticket'])
        need(ticket['parent'] == view['id'] and ticket['state'] == 'unwind' and
             ticket['exception'] == step['exception'], 'SL_FAILED_CHILD')
        need(step['new_journal'] not in self.journals, 'SL_JOURNAL_REPLAY')
        self.consume_journal(view)
        self.fresh_journal(step['new_journal'], view['id'])
        view['journal'], view['exception'], view['mode'] = step['new_journal'], step['exception'], 'partial_cleanup'
        ticket['state'] = 'consumed'

    def event_cleanup(self, step):
        view = self.current(step['view'], step['journal'])
        need(view['mode'] in {'destroy', 'partial_cleanup'}, 'SL_CLEANUP_PHASE')
        self.writable(view, step['cell'])
        candidates = [state for state in self.covered_states(view) if state['completed']]
        need(candidates, 'SL_CLEANUP_EMPTY')
        current = max(candidates, key=lambda state: state['ordinal'])
        need(current['cell'] == step['cell'] and 0 < step['count'] <= current['completed'], 'SL_CLEANUP_ORDER')
        current['completed'] -= step['count']
        if current['completed'] == 0:
            current['ordinal'] = 0

    def event_finish_cleanup(self, step):
        view = self.current(step['view'], step['journal'])
        need(view['mode'] == 'partial_cleanup' and view['exception'] == step['exception'], 'SL_EXCEPTION')
        need(not any(state['completed'] for state in self.covered_states(view)),
             'SL_CLEANUP_INCOMPLETE')
        self.terminal(view, 'failed_cleared', step['receipt'], step['exception'])

    def event_complete_view(self, step):
        view = self.current(step['view'], step['journal'])
        need(self.programs[view['program']]['view'] == 'nonvirtual' or view['mode'] == 'destroy', 'SL_VIEW_PUBLICATION')
        need(view['mode'] in {'construct', 'destroy'}, 'SL_VIEW_OUTCOME')
        if view['mode'] == 'construct':
            need(all(state['completed'] == self.counts[state['cell']] for state in self.covered_states(view)),
                 'SL_INITIALIZATION_INCOMPLETE')
        if view['mode'] == 'destroy':
            need(not any(state['completed'] for state in self.covered_states(view)),
                 'SL_CLEANUP_INCOMPLETE')
        self.terminal(view, 'view_completed', step['receipt'])

    def event_publish(self, step):
        view = self.current(step['view'], step['journal'])
        obj = self.objects[view['object']]
        need(view['mode'] == 'construct' and self.programs[view['program']]['view'] == 'complete' and
             obj['state'] == 'constructing' and obj['complete_owner'] == obj['id'], 'SL_VIEW_PUBLICATION')
        expected = dict(self.implicit_created(obj['implicit_set'])) if obj['implicit_set'] is not None else self.counts
        need(all(state['completed'] == expected[state['cell']] for state in self.covered_states(view)),
             'SL_INITIALIZATION_INCOMPLETE')
        self.budget.work(len(self.tickets))
        need(not any(ticket['parent'] == view['id'] and ticket['state'] == 'pending' for ticket in self.tickets.values()),
             'SL_PENDING_CHILD')
        self.terminal(view, 'published', step['receipt'])
        obj['state'] = 'alive'

    def event_rejoin(self, step):
        ticket = select(self.tickets, step['ticket'])
        need(ticket['state'] == 'pending', 'SL_REJOIN_REPLAY')
        child = self.views[ticket['child']]
        receipt = select(self.receipts, step['receipt'])
        expected = 'view_completed' if step['outcome'] == 'normal' else 'failed_cleared'
        need(receipt['view'] == child['id'] and receipt['kind'] == expected and child['state'] == expected,
             'SL_REJOIN_OUTCOME')
        need(receipt['exception'] == step['exception'], 'SL_EXCEPTION')
        ticket['state'], ticket['exception'] = step['outcome'], step['exception']

    def event_scope_exit(self, step):
        scope, site = select(self.scopes, step['scope']), select(self.exits, step['exit_site'])
        need(scope['state'] == 'open' and scope['subject'] == site['subject'], 'SL_SCOPE_REPLAY')
        frame = select(self.frames, scope['owner'])
        need(step['generation'] == scope['generation'] and scope['declaration'] == site['scope'] and
             scope['value'] == site['scope_value'], 'SL_SCOPE_GENERATION')
        need(equivalent(frame['function'], site['function']), 'SL_SCOPE_FUNCTION')
        need((step['journal'] is not None) == (site['journal'] is not None) and
             (step['exception'] is not None) == (site['exception'] is not None), 'SL_EXIT_OPTIONS')
        mode = site['helper'].split('.')[0]
        view = None if scope['view'] is None else self.views[scope['view']]
        if step['journal'] is not None:
            need(view is not None, 'SL_EXIT_JOURNAL')
            self.current(view['id'], step['journal'])
            if mode == 'normal':
                fail('SL_EXIT_NORMAL_JOURNAL_OUTCOME', kind='unavailable')
            need(view['exception'] is not None, 'SL_EXIT_OUTCOME')
            need(scope['pending'] is not None and scope['exception'] == view['exception'], 'SL_EXIT_RETAINED_OWNER')
        elif view is not None:
            expected = {'view_completed', 'published'} if mode == 'normal' else {'failed_cleared'}
            need(view['state'] in expected, 'SL_EXIT_OUTCOME')
        else:
            need((scope['subject'] == 'existing_object' and mode == 'normal') or
                 (scope['subject'] in {'physical', 'inline'} and mode != 'normal' and
                  scope['pending'] is not None and scope['exception'] is not None), 'SL_EXIT_OUTCOME')
        current_exception = scope['exception'] if view is None else view['exception']
        if mode == 'unwind':
            need(current_exception == step['exception'], 'SL_EXCEPTION')
            need(step['propagation'] is None, 'SL_EXCEPTION')
        elif mode == 'outward_unwind':
            need(step['propagation'] == current_exception and step['propagation'] is not None,
                 'SL_PRIVATE_PROPAGATION')
        else:
            need(step['exception'] is None and step['propagation'] is None, 'SL_EXCEPTION')
        scope['state'] = 'closed'

    def event_frontier(self, step):
        frame = select(self.frames, step['owner'])
        need(step['id'] not in self.frontiers and step['generation'] == frame['generation'], 'SL_FRONTIER_REPLAY')
        self.budget.work(2 * len(step['candidates']))
        need(len(set(step['candidates'])) == len(step['candidates']), 'SL_DUPLICATE')
        self.frontiers[step['id']] = {**step, 'next': 0, 'pending': None, 'suspended': False, 'cancelled': False,
                                      'used_tickets': set(), 'closed': False}

    def event_select(self, step):
        frontier = self.frontier_state(step['frontier'])
        need(not frontier['closed'] and not frontier['suspended'] and not frontier['cancelled'] and frontier['pending'] is None and
             step['index'] == frontier['next'] and step['index'] < len(frontier['candidates']) and
             step['ticket'] not in frontier['used_tickets'], 'SL_FRONTIER_CURSOR')
        frontier['pending'] = step['ticket']
        frontier['used_tickets'].add(step['ticket'])

    def event_commit_event(self, step):
        frontier = self.frontier_state(step['frontier'])
        need(not frontier['closed'] and not frontier['suspended'] and frontier['pending'] == step['ticket'], 'SL_EFFECT_REPLAY')
        frontier['pending'] = None
        frontier['next'] += 1

    def event_suspend(self, step):
        frontier = self.frontier_state(step['frontier'])
        need(not frontier['closed'] and not frontier['suspended'], 'SL_SUSPEND_REPLAY')
        frontier['suspended'] = True

    def event_resume(self, step):
        frontier = self.frontier_state(step['frontier'])
        frame = select(self.frames, step['owner'])
        need(not frontier['closed'] and frame['generation'] == step['generation'] and
             frontier['suspended'] and frontier['owner'] == step['owner'] and frontier['generation'] == step['generation'],
             'SL_RESUME_CONTEXT')
        frontier['suspended'] = False

    def event_cancel(self, step):
        frontier = self.frontier_state(step['frontier'])
        need(not frontier['closed'] and not frontier['cancelled'], 'SL_CANCEL_REPLAY')
        frontier['cancelled'] = True

    def event_finish_cancel(self, step):
        frontier = self.frontier_state(step['frontier'])
        need(frontier['cancelled'] and frontier['pending'] is None, 'SL_CANCEL_PENDING')
        self.budget.work(len(self.views) + len(self.tickets))
        need(not any(view['state'] == 'live' and view['owner'] == frontier['owner'] for view in self.views.values()),
             'SL_CANCEL_CLEANUP')
        need(not any(ticket['state'] == 'pending' for ticket in self.tickets.values()), 'SL_CANCEL_CLEANUP')
        frontier['cancelled'], frontier['closed'] = False, True

    def event_nonlocal_exit(self, step):
        owner = step['owner']
        select(self.frames, owner)
        self.budget.work(len(self.views) + len(self.tickets) + len(self.scopes))
        need(not any(view['owner'] == owner and view['state'] == 'live' for view in self.views.values()),
             'SL_NONLOCAL_CLEANUP')
        need(not any(ticket['state'] == 'pending' for ticket in self.tickets.values()), 'SL_NONLOCAL_CLEANUP')
        need(not any(scope['owner'] == owner and scope['state'] == 'open' for scope in self.scopes.values()),
             'SL_NONLOCAL_CLEANUP')
        self.leaving_frontiers(owner)
        del self.frames[owner]

    def event_trap(self, step):
        self.trapped = True  # Preserve all destructive/pending state; never restore Alive.


def verify(document, *, budget):
    """Check conditional static requirements; return no actual runtime authority."""
    preflight(document, budget)
    size = SCHEMA.stat().st_size
    budget.charge(work=size, copied_bytes=size)
    need(size <= 256 * 1024, 'SL_SCHEMA_RESOURCE')
    source = SCHEMA.read_bytes()
    digest = hashlib.sha256(source).digest()
    schema = json.loads(source)
    try:
        shape(schema, document, schema['$defs'], budget)
        result = Verifier(document, budget).run()
    finally:
        need(hashlib.sha256(SCHEMA.read_bytes()).digest() == digest, 'SL_SCHEMA_CHANGED')
    return result
