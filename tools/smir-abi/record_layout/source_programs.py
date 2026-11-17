"""Unbound compiler source-program descriptors, not executable SMIR admission.

Exact schema is schema/abi/source_programs.json. Original association checks
compare genuine captured source inputs; extended CPP producer/CFG/runtime facts
remain explicit obligations. No private fact, Journal, claim or scope is issued.
"""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re

from layout import MAX_ALIGN, MAX_OBJECT
from .materialization import _api
from . import source_program_cost as P

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/abi/source_programs.json'
MAX_BYTES = 8 << 20
U64 = (1 << 64) - 1


def fail(code, detail='', kind='semantic'):
    raise _api().SourceDataError(kind, code, detail)


def need(value, code, detail=''):
    if not value:
        fail(code, detail)


def ledger(budget):
    need(type(budget) is _api().SourceQueryBudget, 'ABI_SP_BUDGET')


def capture(value, budget, *, cost_profile=None):
    """Precharge bounded input storage before serialization/deep-copy allocation."""
    P.capture(value,budget,cost_profile)
    pending = [(value, 1)]; total = 0
    budget.charge(work=1, edges=1, copied_bytes=64)
    while pending:
        item, depth = pending.pop()
        if depth > budget.max_depth:
            fail('SOURCE_DATA_RESOURCE', 'source-program depth', 'resource')
        budget.work(1)
        if type(item) is dict:
            need(len(item) <= 64 and all(type(k) is str and len(k) <= 4096 for k in item), 'ABI_SP_SHAPE')
            amount = 2 + sum(12 * len(k) + 8 for k in item)
            budget.charge(work=len(item), edges=len(item), copied_bytes=64 * len(item) + amount)
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            need(len(item) <= 4096, 'ABI_SP_SHAPE')
            amount = 2 + len(item)
            budget.charge(edges=len(item), copied_bytes=64 * len(item) + amount)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= 4096, 'ABI_SP_SHAPE')
            amount = 12 * len(item) + 2
            budget.charge(work=len(item), copied_bytes=amount)
        elif type(item) is int:
            need(0 <= item <= U64, 'ABI_SP_SHAPE'); amount = 24
        elif item is None or type(item) is bool:
            amount = 5
        else:
            fail('ABI_SP_SHAPE')
        total += amount
        if total > MAX_BYTES:
            fail('SOURCE_DATA_RESOURCE', 'source-program input bound', 'resource')
    budget.charge(work=total, copied_bytes=3 * total)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def shape(schema, value, definitions, budget, depth=1, *, cost_profile=None):
    P.schema_node(schema,value,budget,cost_profile)
    budget.work(1)
    if depth > budget.max_depth:
        fail('SOURCE_DATA_RESOURCE', 'schema depth', 'resource')
    allowed = {'$schema', '$id', '$comment', '$defs', '$ref', 'oneOf', 'anyOf', 'type',
               'properties', 'required', 'additionalProperties', 'items', 'maxItems',
               'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'const', 'enum'}
    if set(schema) - allowed:
        raise RuntimeError('unsupported source-program schema keyword')
    if '$ref' in schema:
        return shape(definitions[schema['$ref'].removeprefix('#/$defs/')], value, definitions, budget, depth,cost_profile=cost_profile)
    alternatives = schema.get('oneOf', schema.get('anyOf'))
    if alternatives is not None:
        accepted = 0
        for child in alternatives:
            try:
                shape(child, value, definitions, budget, depth,cost_profile=cost_profile)
                accepted += 1
            except _api().SourceDataError as error:
                if error.code != 'ABI_SP_SHAPE':
                    raise
        need(accepted == 1 if 'oneOf' in schema else accepted >= 1, 'ABI_SP_SHAPE')
    if 'const' in schema:
        need(type(value) is type(schema['const']) and value == schema['const'], 'ABI_SP_SHAPE')
    if 'enum' in schema:
        need(any(type(value) is type(v) and value == v for v in schema['enum']), 'ABI_SP_SHAPE')
    kind = schema.get('type')
    types = {'object': dict, 'array': list, 'integer': int, 'string': str, 'boolean': bool, 'null': type(None)}
    if kind:
        need(type(value) is types[kind], 'ABI_SP_SHAPE')
    if kind == 'object':
        need(set(value) == set(schema['required']) and schema['additionalProperties'] is False, 'ABI_SP_SHAPE')
        for key, child in value.items():
            shape(schema['properties'][key], child, definitions, budget, depth + 1,cost_profile=cost_profile)
    elif kind == 'array':
        need(len(value) <= schema['maxItems'], 'ABI_SP_SHAPE')
        for child in value:
            shape(schema['items'], child, definitions, budget, depth + 1,cost_profile=cost_profile)
    elif kind == 'integer':
        need(schema['minimum'] <= value <= schema['maximum'], 'ABI_SP_SHAPE')
    elif kind == 'string':
        need(schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 4096), 'ABI_SP_SHAPE')
        need('pattern' not in schema or re.fullmatch(schema['pattern'], value) is not None, 'ABI_SP_SHAPE')


def index(rows, budget, *, cost_profile=None):
    P.collection(budget,cost_profile,len(rows))
    budget.charge(work=len(rows), edges=len(rows), copied_bytes=96 * len(rows))
    result = {r['id']: r for r in rows}
    need(len(result) == len(rows), 'ABI_SP_DUPLICATE_ID')
    return result


def product(extents, budget):
    total = 1
    for extent in extents:
        budget.work(1)
        need(extent >= 1 and total <= U64 // extent, 'ABI_SP_ARRAY_OVERFLOW')
        total *= extent
    return total


def power_alignment(value):
    need(1 <= value <= MAX_ALIGN and value & (value - 1) == 0, 'ABI_SP_ALIGNMENT')


def view(program):
    return 'nonvirtual' if program['variant'].startswith('base_') else 'complete'


def ctor(program):
    return program['variant'].endswith('_constructor')


def dtor(program):
    return program['variant'].endswith('_destructor')


def source_key(source):
    reference = source['nominal']; module = reference['module']
    return (source['context'], module['kind'], module.get('slot'), reference['id'])


@dataclass(frozen=True, slots=True)
class SourceProgramObligations:
    document_digest: str
    coverage: tuple
    array_progress: tuple
    implicit_patterns: tuple
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class OriginalSourceAssociations:
    descriptor: SourceProgramObligations
    stamp: object
    context_id: int
    checks: tuple
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class DeferredSourceCheck:
    code: str
    context_id: int
    subject_kind: str
    subject_id: int
    path: tuple[int, ...]
    edge_index: int | None


@dataclass(frozen=True, slots=True)
class DeferredOriginalSourceAssociations:
    descriptor: SourceProgramObligations
    owner: object
    stamp: object
    context_id: int
    checks: tuple[tuple[str, int], ...]
    deferred: tuple[DeferredSourceCheck, ...]
    unselected_deferred: tuple[DeferredSourceCheck, ...]
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


class Checker:
    def __init__(self, document, budget, *, deferred=False, cost_profile=None):
        P.tick(budget,cost_profile,work=17,copy=1536)
        ledger(budget); self.b = budget
        P.active(cost_profile,budget);self.cost_profile=cost_profile
        self.d, self.digest = capture(document,budget,cost_profile=cost_profile)
        if cost_profile is None:
            budget.charge(work=SCHEMA.stat().st_size,copied_bytes=4*SCHEMA.stat().st_size)
            schema=json.loads(SCHEMA.read_text())
        else:
            _,schema=P.load_schema(SCHEMA,'a664b73c055a6d405cd468cff23f50b9dadb67a338bc1e765013a75731469030',budget,cost_profile)
        shape(schema,self.d,schema['$defs'],budget,cost_profile=cost_profile)
        P.source_profile(self.d,budget,cost_profile)
        self.contexts, self.records, self.methods, self.cleanups, self.programs = (
            index(self.d[name],budget,cost_profile=cost_profile) for name in ('contexts', 'records', 'methods', 'cleanups', 'programs'))
        self.slots = {}; self.coverage = {}; self.patterns = []; self.obligations = []
        self.progress = []
        self.deferred_mode = deferred; self.deferred = []

    def defer(self, code, context, subject, identifier, path=(), edge=None):
        P.tick(self.b,self.cost_profile,work=10,copy=64)
        if self.deferred_mode:
            self.b.charge(work=1 + len(path), edges=1, copied_bytes=192 + 32 * len(path))
            self.deferred.append(DeferredSourceCheck(code, context, subject, identifier, tuple(path), edge))

    def obligation(self, *value):
        P.tick(self.b,self.cost_profile,work=7,copy=0)
        self.b.charge(work=1, copied_bytes=64 + 32 * len(value)); self.obligations.append(tuple(value))

    def source(self, source):
        P.tick(self.b,self.cost_profile,work=6,copy=0)
        P.collection(self.b,self.cost_profile,len(self.contexts))
        need(source['context'] in self.contexts, 'ABI_SP_SOURCE_CONTEXT')

    def method(self, identifier, record, kind):
        P.tick(self.b,self.cost_profile,work=12,copy=0)
        P.collection(self.b,self.cost_profile,len(self.methods))
        need(identifier in self.methods, 'ABI_SP_METHOD_REFERENCE')
        method = self.methods[identifier]
        need(method['record'] == record and method['kind'] == kind, 'ABI_SP_METHOD_ASSOCIATION')
        return method

    def records_and_methods(self):
        P.tick(self.b,self.cost_profile,work=310,copy=832)
        identities = set()
        for record in self.records.values():
            P.row(self.b,self.cost_profile,record,ops=307,native=12)
            self.b.work(1); self.source(record['source']); key = source_key(record['source'])
            need(key not in identities, 'ABI_SP_SOURCE_IDENTITY'); identities.add(key)
            power_alignment(record['alignment']); power_alignment(record['nonvirtual_alignment'])
            need(0 < record['complete_size'] <= MAX_OBJECT and
                 record['complete_size'] % record['alignment'] == 0 and
                 record['nonvirtual_size'] <= record['complete_size'], 'ABI_SP_GEOMETRY')
            self.slots[record['id']] = index(record['slots'],self.b,cost_profile=self.cost_profile)
            declarations = set(); paths = set()
            for slot in record['slots']:
                P.row(self.b,self.cost_profile,slot,ops=307,native=12)
                self.b.work(1); self.source(slot['source']); power_alignment(slot['alignment'])
                need(slot['source']['context'] == record['source']['context'], 'ABI_SP_SOURCE_CONTEXT')
                need(slot['kind'] == 'member' or not slot['array_extents'], 'ABI_SP_BASE_ARRAY')
                need((slot['element_kind'] == 'record') == (slot['element_record'] is not None), 'ABI_SP_ELEMENT_KIND')
                if slot['element_record'] is not None:
                    need(slot['element_record'] in self.records, 'ABI_SP_RECORD_REFERENCE')
                    child = self.records[slot['element_record']]
                    need(child['source']['context'] == slot['source']['context'], 'ABI_SP_SOURCE_CONTEXT')
                    need(slot['array_extents'] or source_key(slot['source']) == source_key(child['source']), 'ABI_SP_ELEMENT_SOURCE')
                    need(slot['kind'] == 'member' or not child['traits']['final'], 'ABI_SP_FINAL_BASE')
                else:
                    need(slot['kind'] == 'member', 'ABI_SP_BASE_TYPE')
                count = product(slot['array_extents'], self.b)
                need(slot['offset_bits'] <= U64 - slot['width_bits'] and
                     slot['offset_bits'] + slot['width_bits'] <= 8 * record['complete_size'], 'ABI_SP_GEOMETRY')
                need(slot['width_bits'] == 0 or count <= slot['width_bits'], 'ABI_SP_ARRAY_GEOMETRY')
                if slot['array_extents']:
                    need(slot['width_bits'] > 0 and slot['width_bits'] % count == 0 and
                         slot['width_bits'] // count >= 8 and slot['width_bits'] % 8 == 0,
                         'ABI_SP_ARRAY_GEOMETRY')
                declaration = slot['kind'], slot['declaration_index']
                need(declaration not in declarations, 'ABI_SP_SLOT_DECLARATION'); declarations.add(declaration)
                need(bool(slot['paths']), 'ABI_SP_SOURCE_PATH')
                for path in slot['paths']:
                    P.row(self.b,self.cost_profile,path,ops=307,native=12)
                    self.b.charge(work=len(path), edges=len(path), copied_bytes=64 * len(path))
                    key = tuple((p['kind'], p['declaration_index'], p['virtual']) for p in path)
                    need(key and key not in paths, 'ABI_SP_SOURCE_PATH'); paths.add(key)
                    last = path[-1]
                    need((last['kind'] == 'member') == (slot['kind'] == 'member') and
                         (slot['kind'] == 'virtual_base' or last['declaration_index'] == slot['declaration_index']) and
                         (last['virtual'] if slot['kind'] == 'virtual_base' else not last['virtual']), 'ABI_SP_SOURCE_PATH')
                    need(all(not p['virtual'] for p in path if p['kind'] == 'member'), 'ABI_SP_SOURCE_PATH')
                need((slot['destruction'] == 'none') == (slot['destructor'] is None), 'ABI_SP_DESTRUCTOR')
                if slot['element_record'] is not None:
                    child = self.records[slot['element_record']]
                    need(child['traits']['destructor_trivial'] or slot['destructor'] is not None or
                         child['traits']['destructor_deleted'], 'ABI_SP_DESTRUCTOR_REQUIRED')
                if slot['destructor'] is not None:
                    need(slot['element_record'] is not None, 'ABI_SP_DESTRUCTOR')
                    m = self.method(slot['destructor'], slot['element_record'], 'destructor')
                    need(not m['deleted'] and not m['parameters'] and
                         slot['destruction'] == ('complete' if slot['kind'] == 'member' else 'base'), 'ABI_SP_DESTRUCTOR')
            self.obligation('original_record_traits_layout_paths', record['id'], *source_key(record['source']))
        method_coordinates = set()
        for method in self.methods.values():
            P.row(self.b,self.cost_profile,method,ops=307,native=12)
            self.b.work(1); need(method['record'] in self.records, 'ABI_SP_RECORD_REFERENCE')
            coordinate = method['record'], method['declaration_index']
            need(coordinate not in method_coordinates, 'ABI_SP_METHOD_IDENTITY'); method_coordinates.add(coordinate)
            need(not(method['trivial'] and method['user_provided']), 'ABI_SP_METHOD_TRAITS')
            need(method['kind'] != 'destructor' or not method['parameters'], 'ABI_SP_DESTRUCTOR_PARAMETERS')
            for parameter in method['parameters']:
                P.row(self.b,self.cost_profile,parameter,ops=307,native=12)
                self.source(parameter)
                need(parameter['context'] == self.records[method['record']]['source']['context'], 'ABI_SP_SOURCE_CONTEXT')
            self.obligation('original_method_signature_traits', method['id'])
        # Every by-value record edge is acyclic; no sizeof/address heuristic.
        P.collection(self.b,self.cost_profile,len(self.slots))
        self.acyclic({r: [s['element_record'] for s in slots.values() if s['element_record'] is not None]
                      for r, slots in self.slots.items()}, 'ABI_SP_RECURSIVE_SUBOBJECT')
        for record in self.records.values():
            P.row(self.b,self.cost_profile,record,ops=307,native=12)
            P.collection(self.b,self.cost_profile,len(self.methods),len('constructor')+8)
            t = record['traits']; eligible = any(m['eligible'] and m['trivial'] and not m['deleted']
                for m in self.methods.values() if m['record'] == record['id'] and m['kind'] == 'constructor')
            self.b.work(len(self.methods))
            need(not(t['destructor_user_provided'] and t['destructor_trivial']), 'ABI_SP_DESTRUCTOR_TRAITS')
            implicit = ((t['aggregate'] and not t['destructor_user_provided']) or
                (t['destructor_trivial'] and not t['destructor_deleted'] and (eligible or
                 (t['pending_default'] and t['trivial_default'] and not t['nontrivial_default']) or
                 (t['pending_copy'] and t['trivial_copy'] and not t['copy_deleted']) or
                 (t['pending_move'] and t['trivial_move'] and not t['move_deleted']))))
            need(t['implicit_lifetime'] == implicit, 'ABI_SP_IMPLICIT_TRAIT')

    def acyclic(self, edges, code):
        P.tick(self.b,self.cost_profile,work=29,copy=896)
        P.collection(self.b,self.cost_profile,len(edges))
        for start in edges:
            active = set(); done = set(); stack = [(start, False)]
            self.b.charge(edges=1, copied_bytes=64)
            while stack:
                P.collection(self.b,self.cost_profile,len(active)+len(done)+len(stack)+1)
                self.b.work(1); node, leave = stack.pop()
                if leave:
                    active.remove(node); done.add(node); continue
                need(node not in active, code)
                if node in done:
                    continue
                active.add(node); stack.append((node, True))
                children = edges[node]
                self.b.charge(edges=len(children), copied_bytes=96 * (len(children) + 1))
                stack.extend((child, False) for child in children)

    def cleanup_programs(self):
        P.tick(self.b,self.cost_profile,work=291,copy=1600)
        canonical = set(); original_programs = set()
        for cleanup in self.cleanups.values():
            P.row(self.b,self.cost_profile,cleanup,ops=290,native=10)
            self.b.work(1); need(cleanup['record'] in self.records, 'ABI_SP_RECORD_REFERENCE')
            record = self.records[cleanup['record']]; key = cleanup['record'], cleanup['view']
            need(key not in canonical, 'ABI_SP_CANONICAL_CLEANUP'); canonical.add(key)
            original = cleanup['journal_program']; module = original['module']
            original_key = (record['source']['context'], module['kind'], module.get('slot'), original['id'])
            need(original_key not in original_programs, 'ABI_SP_JOURNAL_PROGRAM_ALIAS'); original_programs.add(original_key)
            P.collection(self.b,self.cost_profile,len(record['slots']))
            slots = [s for s in record['slots'] if cleanup['view'] == 'complete' or s['kind'] != 'virtual_base']
            self.b.charge(work=len(slots), copied_bytes=64 * len(slots))
            P.collection(self.b,self.cost_profile,len(slots))
            slots.sort(key=lambda s: ({'virtual_base': 0, 'nonvirtual_base': 1, 'member': 2}[s['kind']], s['declaration_index']))
            expected = [] if record['record_kind'] == 'union' else [s['id'] for s in slots]
            need(cleanup['slots'] == expected, 'ABI_SP_COVERAGE')
            if cleanup['destructor'] is None:
                need(record['traits']['destructor_trivial'], 'ABI_SP_DESTRUCTOR_REQUIRED')
            else:
                method = self.method(cleanup['destructor'], record['id'], 'destructor')
                need(not method['deleted'] and method['trivial'] == record['traits']['destructor_trivial'], 'ABI_SP_DESTRUCTOR')
            self.coverage[cleanup['id']] = tuple(cleanup['slots'])
            self.obligation('original_cleanup_signature_program', cleanup['id'])
        pending_unavailable = []
        for program in self.programs.values():
            P.row(self.b,self.cost_profile,program,ops=290,native=10)
            self.b.work(1); need(program['record'] in self.records and program['cleanup'] in self.cleanups, 'ABI_SP_PROGRAM_REFERENCE')
            record = self.records[program['record']]; cleanup = self.cleanups[program['cleanup']]
            need(cleanup['record'] == record['id'] and cleanup['view'] == view(program), 'ABI_SP_PROGRAM_VIEW')
            if cleanup['view'] == 'nonvirtual' and record['nonvirtual_size'] == 0:
                pending_unavailable.append('ABI_CC_CPP_ZERO_NV_VIEW')
                self.defer('ABI_CC_CPP_ZERO_NV_VIEW', record['source']['context'], 'program', program['id'])
            if cleanup['view'] == 'nonvirtual':
                for slot_id in cleanup['slots']:
                    P.row(self.b,self.cost_profile,slot_id,ops=290,native=10)
                    slot = self.slots[record['id']][slot_id]
                    need(slot['offset_bits'] + slot['width_bits'] <= 8 * record['nonvirtual_size'], 'ABI_SP_NV_GEOMETRY')
            variant = program['variant']; method = None
            if ctor(program) or dtor(program) or variant == 'trivial_init':
                method = self.method(program['method'], record['id'], 'destructor' if dtor(program) else 'constructor')
                need(not method['deleted'] and method['eligible'], 'ABI_SP_METHOD_UNUSABLE')
            elif variant in ('aggregate_init', 'implicit_lifetime'):
                need(program['method'] is None, 'ABI_SP_CONSTRUCTORLESS')
            elif program['method'] is not None:
                method = self.method(program['method'], record['id'], 'constructor')
                need(not method['deleted'] and method['eligible'], 'ABI_SP_METHOD_UNUSABLE')
            if dtor(program):
                need(program['method'] == cleanup['destructor'], 'ABI_SP_CLEANUP_METHOD')
            if variant == 'trivial_init':
                need(method['trivial'], 'ABI_SP_TRIVIAL_CONSTRUCTOR')
            if variant == 'aggregate_init':
                need(record['traits']['aggregate'], 'ABI_SP_AGGREGATE')
            if variant == 'implicit_lifetime':
                need(record['traits']['implicit_lifetime'], 'ABI_SP_IMPLICIT_INELIGIBLE')
            if record['traits']['abstract'] and view(program) == 'complete' and not dtor(program):
                fail('ABI_SP_ABSTRACT_COMPLETE')
            if program['implementation'] is not None:
                need(method is not None and method['has_definition'], 'ABI_SP_IMPLEMENTATION')
                self.obligation('original_function_call_signature_execution_vtt', program['id'])
            if method is not None and not method['trivial'] and not method['has_definition']:
                pending_unavailable.append('ABI_SP_METHOD_DEFINITION_UNAVAILABLE')
                self.defer('ABI_SP_METHOD_DEFINITION_UNAVAILABLE', record['source']['context'], 'program', program['id'])
            selected = program['union_selection']
            need(selected is None or (record['record_kind'] == 'union' and selected in self.slots[record['id']] and
                 self.slots[record['id']][selected]['kind'] == 'member'), 'ABI_SP_UNION_SELECTION')
            expected = list(cleanup['slots'])
            if record['record_kind'] == 'union':
                expected = [] if selected is None or dtor(program) else [selected]
            elif selected is not None:
                fail('ABI_SP_UNION_SELECTION')
            if dtor(program):
                expected.reverse()
            if program['delegate'] is not None:
                need(ctor(program) or variant == 'deleting_destructor', 'ABI_SP_DELEGATION_KIND')
                need(program['steps'] == [], 'ABI_SP_DELEGATION_STEPS')
            else:
                need(variant != 'deleting_destructor', 'ABI_SP_DELETING_DELEGATE')
                need(program['steps'] == expected, 'ABI_SP_STEP_ORDER')
            self.obligation('actual_source_body_frontiers_per_program_view', program['id'])
        P.collection(self.b,self.cost_profile,len(self.programs))
        edges = {p: [] for p in self.programs}
        for program in self.programs.values():
            P.row(self.b,self.cost_profile,program,ops=290,native=10)
            delegate = program['delegate']
            if delegate is None:
                continue
            need(delegate['target'] in self.programs and delegate['target'] != program['id'], 'ABI_SP_DELEGATION_TARGET')
            target = self.programs[delegate['target']]
            need(target['record'] == program['record'] and
                 target['variant'] == ('complete_destructor' if program['variant'] == 'deleting_destructor' else program['variant']), 'ABI_SP_DELEGATION_VARIANT')
            if ctor(program):
                need(target['method'] != program['method'], 'ABI_SP_DELEGATION_METHOD')
            source_slots = self.coverage[program['cleanup']]; target_slots = self.coverage[target['cleanup']]
            maps = delegate['cell_map']; self.b.work(len(maps))
            need(len(maps) == len(target_slots) and len({m['child'] for m in maps}) == len(maps) and
                 all(m['child'] == m['parent'] and m['child'] in target_slots and m['parent'] in source_slots for m in maps), 'ABI_SP_DELEGATION_COVERAGE')
            edges[program['id']].append(target['id'])
        self.acyclic(edges, 'ABI_SP_DELEGATION_CYCLE')
        return pending_unavailable

    def progress_checks(self):
        P.tick(self.b,self.cost_profile,work=50,copy=640)
        seen = set()
        for row in self.d['array_progress']:
            P.row(self.b,self.cost_profile,row,ops=49,native=1)
            self.b.work(1); need(row['program'] in self.programs, 'ABI_SP_PROGRAM_REFERENCE')
            program = self.programs[row['program']]; slots = self.slots[program['record']]
            need(row['slot'] in slots and row['slot'] in self.coverage[program['cleanup']], 'ABI_SP_PROGRESS_SLOT')
            slot = slots[row['slot']]; need(bool(slot['array_extents']), 'ABI_SP_PROGRESS_ARRAY')
            key = row['program'], row['slot']; need(key not in seen, 'ABI_SP_PROGRESS_DUPLICATE'); seen.add(key)
            count = product(slot['array_extents'], self.b)
            pending = row['pending']; completed = row['completed']
            valid = pending is None or (pending == completed < count if row['phase'] == 'construction' else
                                        completed > 0 and pending == completed - 1)
            need(completed <= count and valid, 'ABI_SP_ARRAY_PROGRESS')
            self.progress.append((row['program'], row['slot'], count, row['phase'], completed, pending))

    def implicit_sets(self):
        P.tick(self.b,self.cost_profile,work=120,copy=3200)
        selections = {}; used = set(); missing = []
        for row in self.d['implicit_selections']:
            P.row(self.b,self.cost_profile,row,ops=119,native=4)
            self.b.work(1); need(row['program'] in self.programs and self.programs[row['program']]['variant'] == 'implicit_lifetime', 'ABI_SP_IMPLICIT_SELECTION_PROGRAM')
            record = self.records[self.programs[row['program']]['record']]
            for identifier in row['path']:
                self.b.work(1); need(identifier in self.slots[record['id']], 'ABI_SP_IMPLICIT_SELECTION_PATH')
                child = self.slots[record['id']][identifier]['element_record']
                need(child is not None, 'ABI_SP_IMPLICIT_SELECTION_PATH'); record = self.records[child]
            need(record['record_kind'] == 'union' and (row['selected_member'] is None or row['selected_member'] in self.slots[record['id']]), 'ABI_SP_UNION_SELECTION')
            key = row['program'], tuple(row['path']); need(key not in selections, 'ABI_SP_UNION_SELECTION'); selections[key] = row['selected_member']
        for program in self.programs.values():
            P.row(self.b,self.cost_profile,program,ops=119,native=4)
            if program['variant'] != 'implicit_lifetime':
                continue
            stack = [(program['record'], (), ())]
            self.b.charge(edges=1, copied_bytes=96)
            while stack:
                record_id, path, extents = stack.pop(); self.b.work(1)
                if len(path) > self.b.max_depth:
                    fail('SOURCE_DATA_RESOURCE', 'implicit source path depth', 'resource')
                record = self.records[record_id]
                self.b.reserve_bytes(96 + 32 * (len(path) + len(extents)))
                self.patterns.append((program['id'], path, extents, 'record', record_id))
                slots = record['slots']
                if record['record_kind'] == 'union':
                    key = program['id'], path
                    if key not in selections:
                        missing.append('ABI_SP_UNION_SELECTION_UNAVAILABLE')
                        self.defer('ABI_SP_UNION_SELECTION_UNAVAILABLE', record['source']['context'], 'program', program['id'], path)
                        continue
                    used.add(key); selected = selections[key]
                    slots = [] if selected is None else [self.slots[record_id][selected]]
                for slot in slots:
                    P.row(self.b,self.cost_profile,slot,ops=119,native=4)
                    self.b.work(1); p = path + (slot['id'],); dimensions = extents + tuple(slot['array_extents'])
                    self.b.charge(edges=1, copied_bytes=128 + 32 * (len(p) + len(dimensions)))
                    product(dimensions, self.b)
                    if slot['array_extents']:
                        self.patterns.append((program['id'], p, dimensions, 'array', None))
                    kind = slot['element_kind']
                    if kind in ('scalar', 'pointer'):
                        self.patterns.append((program['id'], p, dimensions, kind, None))
                    elif kind == 'record':
                        child = self.records[slot['element_record']]
                        if child['traits']['implicit_lifetime']:
                            stack.append((child['id'], p, dimensions))
                    elif kind == 'unsupported':
                        missing.append('ABI_SP_ELEMENT_ELIGIBILITY_UNAVAILABLE')
                        self.defer('ABI_SP_ELEMENT_ELIGIBILITY_UNAVAILABLE', record['source']['context'], 'program', program['id'], p)
        need(used == set(selections), 'ABI_SP_UNUSED_UNION_SELECTION')
        return missing

    def run(self):
        P.tick(self.b,self.cost_profile,work=67,copy=1152)
        self.records_and_methods(); unavailable = self.cleanup_programs(); self.progress_checks()
        unavailable.extend(self.implicit_sets())
        # Mapped AST identities must be unique, even before optional oracle data.
        seen = set(); ast_records = set()
        for row in self.d['ast_bindings']:
            P.row(self.b,self.cost_profile,row,ops=66,native=9)
            self.b.work(1); need(row['record'] in self.records and row['record'] not in seen and
                 row['ast_record'] not in ast_records, 'ABI_SP_AST_BINDING')
            seen.add(row['record']); ast_records.add(row['ast_record'])
            for name, table in (('methods', self.methods), ('programs', self.programs)):
                P.row(self.b,self.cost_profile,table,ops=66,native=9)
                local = set(); foreign = set(); key = name[:-1]; astkey = 'ast_' + key
                for binding in row[name]:
                    P.row(self.b,self.cost_profile,binding,ops=66,native=9)
                    self.b.work(1); identifier = binding[key]
                    need(identifier in table and table[identifier]['record'] == row['record'] and identifier not in local and binding[astkey] not in foreign, 'ABI_SP_AST_BINDING')
                    local.add(identifier); foreign.add(binding[astkey])
        if unavailable and not self.deferred_mode:
            fail(unavailable[0], kind='unavailable')
        self.obligation('actual_original_extended_cpp_traits_and_source_truth')
        self.obligation('actual_cfg_ssa_and_retained_source_frontiers')
        self.obligation('actual_runtime_claim_view_scope_and_once_only_delegation_issuer')
        P.collection(self.b,self.cost_profile,len(self.coverage)+len(self.progress)+len(self.patterns)+len(self.obligations),256)
        return SourceProgramObligations(self.digest, tuple((i, v) for i, v in self.coverage.items()),
            tuple(self.progress), tuple(self.patterns), tuple(self.obligations))


def verify(document, *, budget, cost_profile=None):
    return Checker(document,budget,cost_profile=cost_profile).run()


def check_source_associations(document,owner,context_id,*,budget,cost_profile=None):
    """Compare represented joins to genuine S014 raw input; never issue AbiFacts."""
    return _check_source_associations(document, owner, context_id, budget=budget,deferred=False,cost_profile=cost_profile)


def check_source_associations_deferred(document,owner,context_id,*,budget,cost_profile=None):
    """Complete represented selected checks and return inert, tagged evidence gaps."""
    return _check_source_associations(document, owner, context_id, budget=budget,deferred=True,cost_profile=cost_profile)


def _check_source_associations(document,owner,context_id,*,budget,deferred,cost_profile=None):
    from candidate.context import RootContext
    ledger(budget); need(type(owner) is RootContext, 'ABI_SP_ORIGINAL_CONTEXT')
    checker=Checker(document,budget,deferred=deferred,cost_profile=cost_profile);report=checker.run()
    need(type(context_id) is int and context_id in checker.contexts, 'ABI_SP_SOURCE_CONTEXT')
    stamp = RootContext.prepare_source_data(owner, budget=budget)
    context=checker.contexts[context_id];roots=owner.sections;key=roots[2]['manifest']['key']
    P.row(budget,cost_profile,context,ops=412,native=17)
    P.row(budget,cost_profile,key,ops=412,native=17)
    need(context['family'] == {k: key[k] for k in ('namespace', 'name', 'abi_major')} and
         context['abi_root'] == dict(stamp.root_digests)[10].hex() and
         context['module_root'] == dict(stamp.root_digests)[2].hex(), 'ABI_SP_ORIGINAL_IDENTITY')
    # This is declared original site agreement, not TU identity or AbiFacts.
    need(context['abi_site'] == roots[10]['identity'] == roots[2]['manifest']['site'], 'ABI_SP_ORIGINAL_SITE')
    nominal = index(roots[10]['types'],budget,cost_profile=cost_profile); layouts = index(roots[10]['layouts'],budget,cost_profile=cost_profile)
    execution = index(roots[1]['types'],budget,cost_profile=cost_profile); functions = index(roots[3]['functions'],budget,cost_profile=cost_profile)
    plans = index(roots[10]['signatures'],budget,cost_profile=cost_profile); journals = index(roots[10]['journals'],budget,cost_profile=cost_profile); checks = []

    def selfref(reference,table):
        P.collection(budget,cost_profile,len(table))
        need(reference['module'] == {'kind': 'self'} and reference['id'] in table, 'ABI_SP_ORIGINAL_REFERENCE')
        return table[reference['id']]

    def actual_source(source):
        need(source['context'] == context_id, 'ABI_SP_ORIGINAL_REFERENCE')
        reference = source['nominal']
        if reference['module']['kind'] == 'dependency':
            dependencies = roots[2]['manifest']['dependencies']; budget.work(len(dependencies))
            dependency = next((d for d in dependencies if d['slot'] == reference['module']['slot']), None)
            need(dependency is not None, 'ABI_SP_ORIGINAL_REFERENCE')
            budget.work(len(dependency['declarations']))
            declaration = next((d for d in dependency['declarations'] if d['id'] == reference['id']), None)
            need(declaration is not None and declaration['kind'] == 'nominal' and declaration['nominal'] is not None, 'ABI_SP_ORIGINAL_REFERENCE')
            reference = declaration['nominal']['some']
        return selfref(reference, nominal)

    for record in checker.records.values():
        P.row(budget,cost_profile,record,ops=412,native=17)
        if record['source']['context'] != context_id:
            continue
        budget.work(1); actual = actual_source(record['source'])
        need(actual['kind'] == 'record' and actual['identity']['entity'] == record['name'] and actual['layout'] is not None, 'ABI_SP_ORIGINAL_RECORD')
        need(actual['layout']['some'] in layouts, 'ABI_SP_ORIGINAL_LAYOUT')
        layout=layouts[actual['layout']['some']]
        P.row(budget,cost_profile,actual,ops=412,native=17)
        P.row(budget,cost_profile,layout,ops=412,native=17)
        need((layout['size'], layout['nonvirtual_size'], layout['align'], layout['nonvirtual_align']) ==
             tuple(record[n] for n in ('complete_size', 'nonvirtual_size', 'alignment', 'nonvirtual_alignment')), 'ABI_SP_ORIGINAL_LAYOUT')
        for slot in record['slots']:
            P.row(budget,cost_profile,slot,ops=412,native=17)
            budget.work(1); declared = actual_source(slot['source'])
            leaf = declared; extents = []
            while leaf['kind'] == 'array':
                budget.charge(work=1, edges=1, copied_bytes=32)
                need(len(extents) < 16 and leaf['extent'] is not None and len(leaf['elements']) == 1, 'ABI_SP_ORIGINAL_SLOT')
                extents.append(leaf['extent']['some']); leaf = selfref(leaf['elements'][0], nominal)
            need(extents == slot['array_extents'], 'ABI_SP_ORIGINAL_SLOT')
            expected_kind = ('record' if leaf['kind'] == 'record' else 'reference' if leaf['kind'] == 'reference' else
                             'pointer' if leaf['kind'] == 'pointer' else 'scalar' if leaf['kind'] in ('scalar', 'bitint', 'enum') else 'unsupported')
            need(expected_kind == slot['element_kind'], 'ABI_SP_ORIGINAL_SLOT')
            if slot['element_record'] is not None:
                need(leaf['id'] == actual_source(checker.records[slot['element_record']]['source'])['id'], 'ABI_SP_ORIGINAL_SLOT')
            for path_index, path in enumerate(slot['paths']):
                current = actual; complete = True
                for edge_index, edge in enumerate(path):
                    budget.work(1)
                    if current['record_input'] is None:
                        if not deferred:
                            fail('ABI_SP_SOURCE_PATH_UNAVAILABLE', kind='unavailable')
                        checker.defer('ABI_SP_SOURCE_PATH_UNAVAILABLE', context_id, 'record', record['id'], (slot['id'], path_index), edge_index)
                        complete = False
                        break
                    selected = current['record_input']['some']
                    rows = selected['fields' if edge['kind'] == 'member' else 'bases']
                    need(edge['declaration_index'] < len(rows), 'ABI_SP_ORIGINAL_PATH')
                    item = rows[edge['declaration_index']]
                    need(edge['kind'] == 'member' or item['virtual'] == edge['virtual'], 'ABI_SP_ORIGINAL_PATH')
                    current = selfref(item['type'], nominal)
                if complete:
                    need(current['id'] == declared['id'], 'ABI_SP_ORIGINAL_PATH')
            # All paths are original declaration coordinates; deeper/virtual joins
            # retain explicit checked-layout/CPP metadata obligations below.
            if len(slot['paths']) == 1 and len(slot['paths'][0]) == 1 and slot['kind'] == 'member':
                fields = layout['fields']; budget.work(len(fields))
                field = next((f for f in fields if f['declaration_index'] == slot['declaration_index']), None)
                need(field is not None and field['name'] == slot['name'] and field['type'] == slot['source']['nominal'] and
                     (field['offset_bits'], field['width_bits']) == (slot['offset_bits'], slot['width_bits']), 'ABI_SP_ORIGINAL_SLOT')
        checks.append(('original_record_layout_direct_fields', record['id']))
        for method in checker.methods.values():
            P.row(budget,cost_profile,method,ops=412,native=17)
            if method['record'] != record['id']:
                continue
            budget.work(1); need(method['declaration_index'] < len(actual['methods']), 'ABI_SP_ORIGINAL_METHOD')
            source = actual['methods'][method['declaration_index']]
            need(source['name'] == method['name'] and source['signature'] == method['signature'] and source['noexcept'] == method['noexcept'], 'ABI_SP_ORIGINAL_METHOD')
            prototype = selfref(method['signature'], nominal)
            P.row(budget,cost_profile,prototype,ops=412,native=17)
            need(prototype['kind'] == 'function' and prototype['extent'] == {'some': len(method['parameters'])} and
                 len(prototype['elements']) == len(method['parameters']) + 1 and
                 prototype['elements'][:-1] == [p['nominal'] for p in method['parameters']] and
                 selfref(prototype['elements'][-1], nominal)['kind'] == 'void' and
                 ('noexcept' in prototype['flags']) == method['noexcept'], 'ABI_SP_ORIGINAL_SIGNATURE')
            checks.append(('original_source_method_signature', method['id']))
    for cleanup in checker.cleanups.values():
        P.row(budget,cost_profile,cleanup,ops=412,native=17)
        if checker.records[cleanup['record']]['source']['context'] != context_id:
            continue
        budget.work(1)
        if cleanup['journal_program']['module']['kind'] == 'dependency':
            if not deferred:
                fail('ABI_SP_DEP_JOURNAL_UNAVAILABLE', kind='unavailable')
            selfref(cleanup['signature'], plans)
            checker.defer('ABI_SP_DEP_JOURNAL_UNAVAILABLE', context_id, 'cleanup', cleanup['id'])
            continue
        program = selfref(cleanup['journal_program'], journals)
        selfref(cleanup['signature'], plans)
        need(program['signature'] == cleanup['signature']['id'], 'ABI_SP_ORIGINAL_JOURNAL_SIGNATURE')
        checks.append(('original_journal_program_call_signature', cleanup['id']))
    for program in checker.programs.values():
        P.row(budget,cost_profile,program,ops=412,native=17)
        record = checker.records[program['record']]
        if record['source']['context'] != context_id or program['implementation'] is None:
            continue
        budget.work(1); impl = program['implementation']; function = selfref(impl['function'], functions)
        plan = selfref(impl['call_signature'], plans); fn = selfref(impl['execution'], execution)
        method = checker.methods[program['method']]
        need(fn['kind'] == 'function' and function['signature'] == impl['execution'] and
             function['abi_signature'] == {'some': impl['call_signature']} and plan['execution'] == impl['execution'] and
             plan['function_type'] == method['signature'] and plan['vtt'] == impl['uses_vtt'], 'ABI_SP_ORIGINAL_IMPLEMENTATION')
        checks.append(('original_function_call_signature_execution_vtt', program['id']))
    # Recheck original source bytes after every join; caller-mutated indexes and
    # owner methods were never used as evidence.
    need(RootContext.prepare_source_data(owner, budget=budget) is stamp, 'ABI_SP_ORIGINAL_CONTEXT')
    budget.reserve_bytes(128 * len(checks))
    obligations = report.obligations + (('extended_cpp_traits_paths_source_body_not_bound_by_ABI3', context_id),)
    if deferred:
        count = len(checker.deferred)
        budget.charge(work=count * (count.bit_length() + 1), edges=count,
                      copied_bytes=256 * count + 256)
        P.collection(budget,cost_profile,count,128);P.collection(budget,cost_profile,count,128)
        key = lambda x: (x.context_id, x.subject_kind, x.subject_id, x.path,
                         -1 if x.edge_index is None else x.edge_index, x.code)
        ordered = sorted(set(checker.deferred), key=key)
        selected = tuple(x for x in ordered if x.context_id == context_id)
        unselected = tuple(x for x in ordered if x.context_id != context_id)
        return DeferredOriginalSourceAssociations(report, owner, stamp, context_id, tuple(checks),
                                                  selected, unselected, obligations)
    return OriginalSourceAssociations(report, stamp, context_id, tuple(checks), obligations)


def ast_links(ast, records, methods, programs, types, budget):
    """Independent neutral-oracle relation checks, including unmapped records."""
    owners = set()
    for typ in types.values():
        budget.work(1)
        need(typ['element_record'] is None or typ['element_record'] in records, 'ABI_SP_AST_ORACLE')
        need(all(int(n) <= (1 << 63) - 1 for n in typ['array_extents']), 'ABI_SP_AST_ORACLE')
        need((typ['kind'] == 'array') == bool(typ['array_extents']) and
             (typ['kind'] == 'array' or (typ['kind'] == 'record') == (typ['element_record'] is not None)), 'ABI_SP_AST_ORACLE')
    for method in methods.values():
        budget.work(1 + len(method['parameters']))
        need(method['record'] in records and all(t in types for t in method['parameters']), 'ABI_SP_AST_ORACLE')
    for program in programs.values():
        budget.work(1)
        need(program['source_method'] in methods and program['owner_label'] == 'program_' + str(program['id']) and
             program['owner_label'] not in owners, 'ABI_SP_AST_ORACLE'); owners.add(program['owner_label'])
        method = methods[program['source_method']]; constructor = program['variant'].endswith('constructor')
        need(method['record'] == program['source_record'] and method['has_definition'] and not method['implicit'] and
             method['name'].rsplit('::', 1)[-1].startswith('~') != constructor and
             program['coverage'] == ('complete' if program['variant'].startswith('complete_') else 'nonvirtual'), 'ABI_SP_AST_ORACLE')
        need(constructor or not method['parameters'], 'ABI_SP_AST_ORACLE')
        delegate = program['delegate']
        expected = ('matching_variant_after_target_completion' if delegate is not None else
                    'reverse_completed_prefix' if constructor else 'body_then_reverse_covered')
        need(program['cleanup'] == expected, 'ABI_SP_AST_ORACLE')
        if delegate is not None:
            need(constructor and not program['steps'] and delegate['target_method'] in methods and
                 delegate['target_method'] != program['source_method'] and
                 delegate['target_variant'] == program['variant'], 'ABI_SP_AST_ORACLE')
            target = methods[delegate['target_method']]
            need(target['record'] == program['source_record'] and not target['name'].rsplit('::', 1)[-1].startswith('~'), 'ABI_SP_AST_ORACLE')
        last_initializer = -1
        for position, step in enumerate(program['steps']):
            budget.work(1)
            need(step['order'] == position and step['declaring_record'] == program['source_record'] and step['type'] in types and
                 (program['coverage'] == 'complete' or step['kind'] != 'virtual_base') and
                 ((step['destruction'] == 'none') == (step['destructor_method'] is None)) and
                 (constructor or step['initializer'] is None), 'ABI_SP_AST_ORACLE')
            need(step['array_progress'] == ('symbolic_prefix_reverse_cleanup' if types[step['type']]['array_extents'] else 'none'), 'ABI_SP_AST_ORACLE')
            if step['initializer'] is not None:
                initializer = step['initializer']
                need(initializer['sema_index'] > last_initializer and
                     (initializer['written'] or initializer['textual_index'] is None), 'ABI_SP_AST_ORACLE')
                last_initializer = initializer['sema_index']
            if step['destructor_method'] is not None:
                need(step['destructor_method'] in methods, 'ABI_SP_AST_ORACLE')
                destructor = methods[step['destructor_method']]
                need(destructor['record'] == types[step['type']]['element_record'] and not destructor['parameters'] and
                     destructor['name'].rsplit('::', 1)[-1].startswith('~') and
                     step['destruction'] == ('complete' if step['kind'] == 'member' else 'base'), 'ABI_SP_AST_ORACLE')


def compare_ast(document, ast_report, *, budget):
    """Compare independent actual AST evidence through explicit unbound mappings."""
    checker = Checker(document, budget); report = checker.run()
    ast, _ = capture(ast_report, budget)
    # Validate the separate LLVM schema with the same closed interpreter/ledger.
    path = ROOT / 'docs/specifications/smir/portable/llvm/source-program-witness.schema.json'
    budget.charge(work=path.stat().st_size, copied_bytes=4 * path.stat().st_size)
    schema = json.loads(path.read_text()); shape(schema, ast, schema['$defs'], budget)
    records = index(ast['records'], budget); methods = index(ast['methods'], budget)
    programs = index(ast['programs'], budget); types = index(ast['types'], budget)
    ast_links(ast, records, methods, programs, types, budget)
    method_map = {}; program_map = {}; record_map = {}
    for row in checker.d['ast_bindings']:
        need(row['ast_record'] in records and checker.records[row['record']]['name'] == records[row['ast_record']]['name'], 'ABI_SP_AST_RECORD')
        record_map[row['record']] = row['ast_record']
        for binding in row['methods']:
            budget.work(1); method_map[binding['method']] = binding['ast_method']
        for binding in row['programs']:
            budget.work(1); program_map[binding['program']] = binding['ast_program']
    for local, foreign in method_map.items():
        budget.work(1); need(foreign in methods, 'ABI_SP_AST_METHOD'); m = checker.methods[local]; a = methods[foreign]
        need(a['record'] == record_map[m['record']] and a['name'] == m['name'] and a['has_definition'] == m['has_definition'] and
             (a['name'].rsplit('::', 1)[-1].startswith('~') == (m['kind'] == 'destructor')) and
             len(a['parameters']) == len(m['parameters']), 'ABI_SP_AST_METHOD')
        checker.obligation('ast_parameter_original_nominal_binding', local)
    need(bool(record_map) and bool(method_map) and bool(program_map), 'ABI_SP_AST_EMPTY_COMPARISON')
    for local, foreign in program_map.items():
        budget.work(1); need(foreign in programs, 'ABI_SP_AST_PROGRAM'); p = checker.programs[local]; a = programs[foreign]
        need(a['source_record'] == record_map[p['record']] and a['source_method'] == method_map.get(p['method']) and
             a['variant'] == p['variant'] and a['coverage'] == view(p), 'ABI_SP_AST_PROGRAM')
        if p['delegate'] is None:
            need(a['delegate'] is None and len(a['steps']) == len(p['steps']), 'ABI_SP_AST_STEPS')
            for identifier, step in zip(p['steps'], a['steps']):
                budget.work(1); slot = checker.slots[p['record']][identifier]
                need(step['kind'] == slot['kind'] and step['declaration_index'] == slot['declaration_index'] and
                     step['member'] == slot['name'] and step['destruction'] == slot['destruction'] and
                     step['destructor_method'] == method_map.get(slot['destructor']) and step['type'] in types and
                     tuple(int(n) for n in types[step['type']]['array_extents']) == tuple(slot['array_extents']), 'ABI_SP_AST_STEPS')
                if slot['element_record'] is not None:
                    need(types[step['type']]['element_record'] == record_map.get(slot['element_record']), 'ABI_SP_AST_ELEMENT')
                checker.obligation('ast_slot_original_nominal_binding', local, identifier)
        else:
            target = checker.programs[p['delegate']['target']]
            need(not a['steps'] and a['delegate'] is not None and
                 a['delegate']['target_method'] == method_map.get(target['method']) and
                 a['delegate']['target_variant'] == target['variant'] and a['delegate']['owner_relation'] == 'distinct_program', 'ABI_SP_AST_DELEGATE')
    for identifier in checker.programs.keys() - program_map.keys():
        checker.obligation('ast_unmatched_descriptor_program', identifier)
    for identifier in programs.keys() - set(program_map.values()):
        checker.obligation('ast_unmatched_oracle_program', identifier)
    return SourceProgramObligations(report.document_digest, report.coverage, report.array_progress,
        report.implicit_patterns, tuple(checker.obligations))
