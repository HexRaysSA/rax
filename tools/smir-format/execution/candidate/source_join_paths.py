"""Canonical original-source joins and exact symbolic coverage; always UNBOUND.

Public ABI canonical-path APIs remain the source oracle. No private fact,
Journal/scope/generation, source alias or execution permission is issued.
"""
from dataclasses import dataclass, field
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys

from candidate import source_join as J
from candidate.context import RootContext

ROOT = Path(__file__).resolve().parents[4]
SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/execution/source_join_paths.json'
SCHEMA_SHA256 = '63954a86d9954c8b735433c3b45806f5b77cd3b4e1db9964b5639493386f3484'
U64 = (1 << 64) - 1
OriginalOwnerInput = J.OriginalOwnerInput
OriginalContextBinding = J.OriginalContextBinding


class JoinError(J.JoinError):
    pass


def need(condition, code, detail=''):
    if not condition:
        raise JoinError(code, detail)


def capture(value, budget):
    """Bounded immutable input snapshot, charging before traversal/allocation."""
    nodes = 0
    size = 0
    active = set()

    def visit(item, depth):
        nonlocal nodes, size
        budget.charge(work=2, edges=1, copied_bytes=64)
        nodes += 1
        size += 64
        if nodes > 200000 or size > 8 * 1024 * 1024 or depth > min(128, budget.max_depth):
            raise JoinError('SJX_RESOURCE', kind='resource')
        if type(item) is str:
            need(len(item) <= 4096, 'SJX_SHAPE')
            budget.charge(work=4 * len(item), copied_bytes=12 * len(item))
            try:
                item.encode('utf-8', errors='strict')
            except UnicodeEncodeError as error:
                raise JoinError('SJX_SHAPE', 'invalid UTF8') from error
            size += 12 * len(item)
            if size > 8 * 1024 * 1024:
                raise JoinError('SJX_RESOURCE', kind='resource')
            return item
        if type(item) is int:
            need(item.bit_length() <= 64, 'SJX_SHAPE')
            return item
        if item is None or type(item) is bool:
            return item
        need(type(item) in (dict, list) and id(item) not in active, 'SJX_SHAPE')
        budget.charge(work=len(item), edges=len(item), copied_bytes=32 * len(item))
        active.add(id(item))
        try:
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            need(all(type(key) is str for key in item), 'SJX_SHAPE')
            return {visit(key, depth + 1): visit(child, depth + 1) for key, child in item.items()}
        finally:
            active.remove(id(item))

    result = visit(value, 0)
    return result, size + 32 * nodes


def shape(rule, value, definitions, budget, depth=0):
    budget.charge(work=2, edges=1)
    if depth > min(128, budget.max_depth):
        raise JoinError('SJX_RESOURCE', kind='resource')
    if '$ref' in rule:
        return shape(definitions[rule['$ref'].rsplit('/', 1)[1]], value, definitions, budget, depth)
    if 'anyOf' in rule:
        for alternative in rule['anyOf']:
            try:
                shape(alternative, value, definitions, budget, depth)
                return
            except JoinError as error:
                if error.code != 'SJX_SHAPE':
                    raise
        raise JoinError('SJX_SHAPE')
    if 'const' in rule:
        need(type(value) is type(rule['const']) and value == rule['const'], 'SJX_SHAPE')
    if 'enum' in rule:
        need(any(type(value) is type(x) and value == x for x in rule['enum']), 'SJX_SHAPE')
    kind = rule.get('type')
    if kind:
        need(type(value) is {'object': dict, 'array': list, 'integer': int,
                            'string': str, 'boolean': bool, 'null': type(None)}[kind], 'SJX_SHAPE')
    if kind == 'object':
        need(set(value) == set(rule['required']), 'SJX_SHAPE')
        for key, child in value.items():
            shape(rule['properties'][key], child, definitions, budget, depth + 1)
    elif kind == 'array':
        need(rule.get('minItems', 0) <= len(value) <= rule['maxItems'], 'SJX_SHAPE')
        for child in value:
            shape(rule['items'], child, definitions, budget, depth + 1)
    elif kind == 'integer':
        need(rule['minimum'] <= value <= rule['maximum'], 'SJX_SHAPE')
    elif kind == 'string':
        need(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', 4096), 'SJX_SHAPE')
        need('pattern' not in rule or re.fullmatch(rule['pattern'], value) is not None, 'SJX_SHAPE')


def schema_bytes(budget):
    length = SCHEMA.stat().st_size
    need(0 < length <= 256 * 1024, 'SJX_SCHEMA_LIMIT')
    budget.charge(work=8 * length, copied_bytes=8 * length)
    with SCHEMA.open('rb') as stream:
        raw = stream.read(length + 1)
    need(len(raw) == length and hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256, 'SJX_SCHEMA_IDENTITY')
    return raw


def api():
    module = J.abi_api()
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(ROOT / 'tools/smir-abi'))
        result = importlib.import_module(module.__package__ + '.source_paths')
    finally:
        sys.path[:] = previous
    need(Path(result.__file__).resolve() == (ROOT / 'tools/smir-abi/record_layout/source_paths.py').resolve(), 'SJX_ABI_MODULE')
    return result


def index(rows, budget, key='id'):
    budget.charge(work=len(rows), edges=len(rows), copied_bytes=128 * len(rows))
    result = {}
    for row in rows:
        identity = row[key] if isinstance(row, dict) else getattr(row, key)
        need(identity not in result, 'SJX_REFERENCE', 'duplicate ' + key)
        result[identity] = row
    return result


def get(table, key):
    need(key in table, 'SJX_REFERENCE', str(key))
    return table[key]


def qkey(reference):
    module = reference['module']
    return module['kind'], module.get('slot'), reference['id']


def volume(extents, budget):
    result = 1
    budget.work(len(extents) + 1)
    for extent in extents:
        need(type(extent) is int and 0 < extent <= U64 // result, 'SJX_CARDINALITY')
        result *= extent
    return result


def partition(extents, boxes, budget):
    """Included disjoint integer boxes + exact cardinality; no extent loops."""
    need(type(extents) is tuple and 1 <= len(extents) <= 16 and type(boxes) is tuple and len(boxes) <= 4096, 'SJX_COVERAGE_ELEMENT_TARGET')
    count = len(boxes)
    budget.charge(work=(count * count + count + 1) * (len(extents) + 1), copied_bytes=64 * count)
    target = volume(extents, budget)
    for box in boxes:
        need(type(box) is tuple and len(box) == len(extents), 'SJX_COVERAGE_ELEMENT_TARGET')
        for pair, extent in zip(box, extents):
            need(type(pair) is tuple and len(pair) == 2, 'SJX_COVERAGE_ELEMENT_TARGET')
            first, size = pair
            need(type(first) is int and type(size) is int and 0 <= first < extent and 0 < size <= extent - first, 'SJX_COVERAGE_ELEMENT_TARGET')
    for i, left in enumerate(boxes):
        for right in boxes[i + 1:]:
            need(not all(max(a, c) < min(a + b, c + d) for (a, b), (c, d) in zip(left, right)), 'SJX_COVERAGE_OVERLAP')
    total = 0
    for box in boxes:
        total += volume(tuple(size for first, size in box), budget)
        need(total <= U64, 'SJX_CARDINALITY')
    need(total == target, 'SJX_COVERAGE_GAP')
    return target


def pattern_shape(pattern):
    return (pattern.canonical_skeleton,
            tuple((a.position, a.array_declaration, a.extent) for a in pattern.axes),
            pattern.leaf_kind, pattern.most_derived_skeleton,
            pattern.offset_constant_bits, pattern.offset_coefficients_bits, pattern.width_bits,
            pattern.addressable, pattern.covered, pattern.root_view, pattern.leaf_view)


def same_pattern(left, right):
    return pattern_shape(left) == pattern_shape(right) and left.axes == right.axes


def intersects(left, right, budget):
    budget.work(4 + len(left.axes) + len(right.axes))
    if left.canonical_skeleton != right.canonical_skeleton or len(left.axes) != len(right.axes):
        return False
    return all((a.position, a.array_declaration, a.extent) == (b.position, b.array_declaration, b.extent)
               and max(a.first, b.first) < min(a.first + a.count, b.first + b.count)
               for a, b in zip(left.axes, right.axes))


@dataclass(frozen=True)
class CoverageCertificate:
    program: str
    slot: int
    mode: str
    principal: object
    terminal_demand: object
    covered_cardinality: int
    contributors: tuple

    def __post_init__(self):
        need(self.mode in ('whole_slot', 'slot_elements'), 'SJX_COVERAGE_KIND')
        need(type(self.covered_cardinality) is int and 0 < self.covered_cardinality <= U64, 'SJX_CARDINALITY')
        if self.mode == 'whole_slot':
            need(self.terminal_demand is None and self.covered_cardinality == 1 and len(self.contributors) == 1, 'SJX_CARDINALITY')
        else:
            need(self.terminal_demand is not None and bool(self.contributors), 'SJX_CARDINALITY')
            count = 1
            for axis in self.terminal_demand.axes:
                need(axis.first == 0 and axis.count == axis.extent and 0 < axis.extent <= U64 // count, 'SJX_CARDINALITY')
                count *= axis.extent
            need(bool(self.terminal_demand.axes) and count == self.covered_cardinality, 'SJX_CARDINALITY')


@dataclass(frozen=True)
class JoinedCanonicalSourceRequirements:
    document_digest: str
    abi_descriptor_digest: str
    bindings: tuple
    programs: tuple
    path_reports: tuple
    coverage_certificates: tuple
    unselected_deferred: tuple
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


def path_document(program, selectors):
    return dict(format='original-source-paths', revision=1, binding='unbound', runtime_authority=False,
                source_fact_authority=False, root=program['source_class'], view=program['view'], selectors=selectors)


def slot_selector(slot, label, budget):
    budget.work(len(slot['paths']))
    edges = sum(len(route) for route in slot['paths'])
    budget.charge(work=edges, copied_bytes=96 * edges + 128 * len(slot['paths']))
    routes = [[dict(kind=e['kind'], declaration_index=e['declaration_index'],
                    **({} if e['kind'] == 'member' else dict(virtual=e['virtual']))) for e in route] for route in slot['paths']]
    return dict(label=label, declared_leaf=slot['source']['nominal'], routes=routes)


def array_terminal(owner, nominal, budget):
    roots = owner.sections
    types = index(roots[10]['types'], budget)
    dependencies = index(roots[2]['manifest']['dependencies'], budget, 'slot')

    def resolve(reference):
        if reference['module']['kind'] == 'dependency':
            declarations = index(get(dependencies, reference['module']['slot'])['declarations'], budget)
            declaration = get(declarations, reference['id'])
            need(declaration['kind'] == 'nominal' and declaration['nominal'] is not None, 'SJX_REFERENCE')
            reference = declaration['nominal']['some']
        need(reference['module'] == {'kind': 'self'}, 'SJX_REFERENCE')
        return get(types, reference['id'])

    item = resolve(nominal)
    extents = []
    while item['kind'] == 'array':
        budget.charge(work=8, edges=1, copied_bytes=64)
        need(len(extents) < 16 and len(item['elements']) == 1, 'SJX_COVERAGE_ELEMENT_TARGET')
        if item['extent'] is None:
            return None
        extents.append(item['extent']['some'])
        item = resolve(item['elements'][0])
    need(bool(extents), 'SJX_COVERAGE_ELEMENT_TARGET')
    volume(tuple(extents), budget)
    return tuple(extents), dict(module={'kind': 'self'}, id=item['id'])


def verify(document, abi_document, *, original_owners, budget, expected_bindings=None):
    need(type(budget) is J.source_api().SourceQueryBudget, 'SJX_BUDGET_IDENTITY')
    need(type(original_owners) is tuple and len(original_owners) <= 256 and all(type(x) is OriginalOwnerInput for x in original_owners), 'SJX_OWNER_INPUT')
    if expected_bindings is not None:
        need(type(expected_bindings) is tuple and len(expected_bindings) <= 256 and all(type(x) is OriginalContextBinding for x in expected_bindings), 'SJX_PRIOR_BINDING')
    data, bound = capture(document, budget)
    abi, abi_bound = capture(abi_document, budget)
    raw = schema_bytes(budget)
    schema = json.loads(raw)
    shape(schema, data, schema['$defs'], budget)
    contexts = index(data['contexts'], budget)
    owners = index(original_owners, budget, 'context')
    need(set(contexts) == set(owners) and bool(contexts), 'SJX_OWNER_INPUT')
    need(len({c['abi_context'] for c in contexts.values()}) == len(contexts), 'SJX_REFERENCE')
    programs = index(data['programs'], budget)
    cells = index(data['cells'], budget)
    source_api = J.abi_api()
    paths_api = api()
    bindings = []
    selected_gaps = []
    unselected = []
    associations = {}
    for label, context in contexts.items():
        owner = owners[label].owner
        need(type(owner) is RootContext, 'SJX_OWNER_INPUT')
        report = source_api.check_source_associations_deferred(abi, owner, context['abi_context'], budget=budget)
        stamp = report.stamp
        budget.charge(work=len(stamp.root_digests), copied_bytes=128 * len(stamp.root_digests))
        need(context['schema_digest'] == stamp.schema_digest.hex() and context['roots'] == [dict(section=n, digest=h.hex()) for n, h in stamp.root_digests], 'SJX_SOURCE_COORDINATES')
        declared = get(index(abi['contexts'], budget), context['abi_context'])
        need(context['family'] == declared['family'] and context['abi_site'] == declared['abi_site'], 'SJX_SOURCE_COORDINATES')
        associations[label] = report
        bindings.append(OriginalContextBinding(label, owner, stamp))
        budget.charge(work=len(report.deferred) + len(report.unselected_deferred), copied_bytes=256 * (len(report.deferred) + len(report.unselected_deferred)))
        selected_gaps.extend(('association', label, gap) for gap in report.deferred)
        unselected.extend(report.unselected_deferred)
    if expected_bindings is not None:
        prior = index(expected_bindings, budget, 'context')
        need(set(prior) == set(contexts), 'SJX_PRIOR_BINDING')
        for binding in bindings:
            old = prior[binding.context]
            need(old.owner is binding.owner and old.stamp is binding.stamp, 'SJX_PRIOR_BINDING')
    records = index(abi['records'], budget)
    cleanups = index(abi['cleanups'], budget)
    budget.charge(work=len(programs) + len(cells), copied_bytes=128 * (len(programs) + len(cells)))
    by_program = {label: [] for label in programs}
    for cell in cells.values():
        get(programs, cell['program'])
        by_program[cell['program']].append(cell)
    reports = []
    certificates = []
    keys = set()
    for label, program in programs.items():
        context = get(contexts, program['context'])
        owner = owners[program['context']].owner
        association = associations[program['context']]
        cleanup = get(cleanups, program['abi_cleanup'])
        record = get(records, cleanup['record'])
        need(record['source']['context'] == context['abi_context'] and record['source']['nominal'] == program['source_class'], 'SJX_PROGRAM_KEY')
        need(cleanup['journal_program'] == program['original_journal'] and cleanup['signature'] == program['cleanup_signature'] and cleanup['view'] == program['view'], 'SJX_PROGRAM_KEY')
        key = association.stamp.context_anchor, qkey(program['original_journal']), program['view']
        need(key not in keys, 'SJX_PROGRAM_KEY')
        keys.add(key)
        rows = by_program[label]
        budget.charge(work=64 * (len(rows) + len(cleanup['slots']) + 1), copied_bytes=4096 * (len(rows) + len(cleanup['slots']) + 1))
        anchors = [cell for cell in rows if cell['coverage']['kind'] == 'anchor']
        need(len(anchors) == 1 and anchors[0]['selector'] == dict(declared_leaf=program['source_class'], routes=[[]]) and anchors[0]['leaf_view'] == program['view'], 'SJX_ANCHOR')
        syntactic = set()
        for cell in rows:
            routes = cell['selector']['routes']
            budget.work(len(routes))
            edge_count = sum(len(route) for route in routes)
            budget.charge(work=edge_count, copied_bytes=192 * edge_count + 128 * len(routes))
            signature = tuple(sorted(tuple((step['kind'], step.get('declaration_index'), step.get('virtual'),
                None if step['kind'] != 'element' else step['selection']['first'],
                None if step['kind'] != 'element' else step['selection']['count']) for step in route) for route in routes))
            need(signature not in syntactic, 'SJX_CELL_DUPLICATE')
            syntactic.add(signature)
        slots = index(record['slots'], budget)
        claims = {slot: [] for slot in cleanup['slots']}
        for cell in rows:
            coverage = cell['coverage']
            if coverage['kind'] in ('whole_slot', 'slot_elements'):
                need(coverage['slot'] in claims, 'SJX_COVERAGE_SLOT')
                claims[coverage['slot']].append(cell)
        for slot, contributors in claims.items():
            need(bool(contributors), 'SJX_COVERAGE_MISSING')
            modes = {cell['coverage']['kind'] for cell in contributors}
            need(len(modes) == 1, 'SJX_COVERAGE_MIXED')
            need('whole_slot' not in modes or len(contributors) == 1, 'SJX_CELL_DUPLICATE')
        selectors = [dict(label=cell['id'], **cell['selector']) for cell in rows]
        resolved = paths_api.resolve_source_paths(owner, path_document(program, selectors), budget=budget)
        contributing = [dict(label=cell['id'], **cell['selector']) for cell in rows if cell['coverage']['kind'] != 'observe']
        covered = paths_api.check_source_coverage(abi, path_document(program, contributing), owner, context['abi_context'], cleanup['id'], budget=budget)
        need(resolved.owner is owner and resolved.stamp is association.stamp and covered.owner is owner and covered.stamp is association.stamp and covered.program_key == key, 'SJX_PROGRAM_KEY')
        reports.extend(((label, 'cells', resolved), (label, 'membership', covered)))
        for gap in resolved.deferred:
            budget.charge(work=1, copied_bytes=256)
            selected_gaps.append(('path', program['context'], label, gap))
        for gap in covered.deferred:
            budget.charge(work=1, copied_bytes=256)
            selected_gaps.append(('membership', program['context'], label, gap))
        patterns = index(resolved.patterns, budget, 'label')
        budget.charge(work=len(covered.memberships), copied_bytes=128 * len(covered.memberships))
        memberships = {name: slot for name, role, slot in covered.memberships}
        for cell in rows:
            if cell['id'] not in patterns:
                continue
            pattern = patterns[cell['id']]
            budget.charge(work=32 + len(pattern.axes), copied_bytes=256)
            need(pattern.root_view == program['view'] and pattern.leaf_view == cell['leaf_view'], 'SJX_LEAF_VIEW')
            need(cell['geometry'] == dict(offset_constant_bits=pattern.offset_constant_bits, offset_coefficients_bits=list(pattern.offset_coefficients_bits), width_bits=pattern.width_bits), 'SJX_GEOMETRY')
            if cell['coverage']['kind'] in ('whole_slot', 'slot_elements'):
                need(pattern.addressable, 'SJX_COVERAGE_KIND')
                need(memberships.get(cell['id']) == cell['coverage']['slot'], 'SJX_COVERAGE_SLOT')
        for i, left in enumerate(resolved.patterns):
            for right in resolved.patterns[i + 1:]:
                need(not intersects(left, right, budget), 'SJX_CELL_DUPLICATE')
        demands = [slot_selector(get(slots, slot), 'slot' + str(slot), budget) for slot in cleanup['slots']]
        demand_report = paths_api.resolve_source_paths(owner, path_document(program, demands), budget=budget)
        need(demand_report.owner is owner and demand_report.stamp is association.stamp, 'SJX_PROGRAM_KEY')
        reports.append((label, 'demands', demand_report))
        demand_patterns = index(demand_report.patterns, budget, 'label')
        for gap in demand_report.deferred:
            budget.charge(work=1, copied_bytes=256)
            selected_gaps.append(('demand', program['context'], label, gap))
        for slot, contributors in claims.items():
            mode = contributors[0]['coverage']['kind']
            principal = demand_patterns.get('slot' + str(slot))
            wanted = None
            extent = None
            if mode == 'slot_elements':
                terminal = array_terminal(owner, slots[slot]['source']['nominal'], budget)
                if terminal is None:
                    selected_gaps.append(('terminal', program['context'], label, slot, 'ABI_PATH_ARRAY_EXTENT_UNAVAILABLE'))
                else:
                    extent, leaf = terminal
                    selector = slot_selector(slots[slot], 'terminal' + str(slot), budget)
                    selector['declared_leaf'] = leaf
                    budget.charge(work=len(selector['routes']) * (len(extent) + 1), copied_bytes=256 * len(selector['routes']) * (len(extent) + 1))
                    for route in selector['routes']:
                        route.extend(dict(kind='element', selection=dict(first=0, count=e)) for e in extent)
                    terminal_report = paths_api.resolve_source_paths(owner, path_document(program, [selector]), budget=budget)
                    need(terminal_report.owner is owner and terminal_report.stamp is association.stamp, 'SJX_PROGRAM_KEY')
                    reports.append((label, 'terminal' + str(slot), terminal_report))
                    for gap in terminal_report.deferred:
                        budget.charge(work=1, copied_bytes=256)
                        selected_gaps.append(('terminal', program['context'], label, gap))
                    if terminal_report.patterns:
                        wanted = terminal_report.patterns[0]
            # A canonical cell may have compatible nominal rows with different
            # local IDs. Ask the original public resolver to check every actual
            # contributor against the independently demanded DECLARED type.
            # Removing an ID comparison alone would lose this obligation.
            expected_leaf = slots[slot]['source']['nominal'] if mode == 'whole_slot' else None if extent is None else leaf
            compatible_count = 0
            if expected_leaf is not None:
                budget.charge(work=len(contributors), copied_bytes=512 * len(contributors))
                compatible_selectors = [dict(label=cell['id'], declared_leaf=expected_leaf,
                    routes=cell['selector']['routes']) for cell in contributors]
                compatibility = paths_api.resolve_source_paths(owner, path_document(program, compatible_selectors), budget=budget)
                need(compatibility.owner is owner and compatibility.stamp is association.stamp, 'SJX_PROGRAM_KEY')
                reports.append((label, 'compatible' + str(slot), compatibility))
                compatible_count = len(compatibility.patterns)
                for gap in compatibility.deferred:
                    budget.charge(work=1, copied_bytes=256)
                    selected_gaps.append(('compatible', program['context'], label, gap))
            available = [patterns[cell['id']] for cell in contributors if cell['id'] in patterns]
            budget.charge(work=len(contributors), copied_bytes=128 * len(contributors))
            if mode == 'whole_slot':
                if principal is not None:
                    for pattern in available:
                        need(same_pattern(pattern, principal), 'SJX_COVERAGE_ELEMENT_TARGET')
                cardinality = 1
            elif wanted is not None:
                for pattern in available:
                    need(pattern_shape(pattern) == pattern_shape(wanted), 'SJX_COVERAGE_ELEMENT_TARGET')
                    for selected, full in zip(pattern.axes, wanted.axes):
                        need(0 <= selected.first < full.extent and 0 < selected.count <= full.extent - selected.first, 'SJX_COVERAGE_ELEMENT_TARGET')
                cardinality = None
                if len(available) == len(contributors):
                    cardinality = partition(extent, tuple(tuple((a.first, a.count) for a in pattern.axes) for pattern in available), budget)
            else:
                cardinality = None
            if principal is not None and len(available) == len(contributors) == compatible_count and cardinality is not None:
                budget.charge(work=len(contributors) + 16, copied_bytes=512 + 128 * len(contributors))
                certificates.append(CoverageCertificate(label, slot, mode, principal, wanted, cardinality, tuple(cell['id'] for cell in contributors)))
    for binding in bindings:
        need(RootContext.prepare_source_data(binding.owner, budget=budget) is binding.stamp, 'SJX_SOURCE_CONTEXT')
    need(schema_bytes(budget) == raw, 'SJX_SCHEMA_CHANGED')
    if selected_gaps:
        budget.charge(work=2048 * len(selected_gaps), copied_bytes=2048 * len(selected_gaps))
        raise JoinError('SJX_SOURCE_EVIDENCE_UNAVAILABLE', repr(tuple(selected_gaps)), kind='unavailable')
    document_digest = J.digest(data, bound, budget)
    abi_digest = J.digest(abi, abi_bound, budget)
    need(all(report.descriptor.document_digest == abi_digest for report in associations.values()), 'SJX_ABI_DESCRIPTOR_CHANGED')
    budget.charge(work=len(reports) + len(certificates) + len(unselected), copied_bytes=256 * (len(reports) + len(certificates) + len(unselected)))
    return JoinedCanonicalSourceRequirements(document_digest, abi_digest, tuple(bindings), tuple(programs), tuple(reports), tuple(certificates), tuple(unselected),
        ('Static canonical cleanup-domain proof only; no array/element identity or runtime progress substitution.',
         'Actual source traits/CFG/phase/carrier/private issuers and execution admission remain separate.'))
