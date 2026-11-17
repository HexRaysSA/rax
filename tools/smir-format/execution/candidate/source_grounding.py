"""Original-source geometry and finite normal CFG compiler constraints.

No private source fact, source object identity or execution permission is issued.
"""
from dataclasses import dataclass, field
from candidate.context import RootContext
from candidate import source_join_paths as P
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[4]
SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/execution/source_grounding.json'
SCHEMA_SHA256 = '285830daf7f5bdeabe16952d2b6f565437e92d3d2e62d8195f33057930d4840a'
GRAMMAR_PINS = {'runtime/source_contracts.json': '6cc14282b8f3f8c0113cb9e4d965b320cd4269d6a30c57cd8e88068e27de6654', 'execution/source_join_paths.json': '63954a86d9954c8b735433c3b45806f5b77cd3b4e1db9964b5639493386f3484', 'abi/source_programs.json': 'a664b73c055a6d405cd468cff23f50b9dadb67a338bc1e765013a75731469030'}

class GroundingError(ValueError):
    def __init__(self, code, detail='', kind=None):
        if kind is None:
            if code in {'CG_RESOURCE', 'CG_STATE_LIMIT'}:
                kind = 'resource'
            elif code.endswith('_UNAVAILABLE') or code in {
                'CG_PROJECTION_OPERATION_REQUIRED', 'CG_RUNTIME_INDEX_BOUND_REQUIRED',
                'CG_LIFECYCLE_SOURCE_IMPLEMENTATION_REQUIRED', 'CG_CONTEXT_PROFILE',
                'CG_JOURNAL_HIERARCHY_REQUIRED', 'CG_JOURNAL_METHOD_REQUIRED',
                'CG_S_SELECT_SPLIT_REQUIRED', 'CG_ADOPTION_EXISTING_PROTOCOL_UNAVAILABLE'}:
                kind = 'unavailable'
            elif code in {'CG_SHAPE', 'CG_TABLE', 'CG_LINK_ID', 'CG_LINK_LABEL',
                          'CG_BINDING_SHAPE', 'CG_JOURNAL_MAPPING_SHAPE',
                          'CG_SCOPE_SHAPE', 'CG_BUDGET', 'CG_OWNER'}:
                kind = 'input'
            else:
                kind = 'semantic'
        self.code, self.kind, self.detail = code, kind, detail
        super().__init__(code + (': ' + detail if detail else ''))

def need(test, code, detail=''):
    if not test:
        raise GroundingError(code, detail)

@dataclass(frozen=True)
class GroundedConstraints:
    owner: object
    stamp: object
    canonical_bindings: tuple
    checked_journals: tuple
    path_functions: tuple
    deferred: tuple
    binding: str = field(default='unbound', init=False)
    source_fact_authority: bool = field(default=False, init=False)
    runtime_authority: bool = field(default=False, init=False)
    active_v3_verified: bool = field(default=False, init=False)

def runtime_api():
    """Lazy public package import; never shadow the legacy execution codec."""
    directory = ROOT / 'tools/smir-runtime-contract/source_contracts'
    name = 'source_contracts'
    loaded = sys.modules.get(name)
    if loaded is not None:
        need(getattr(loaded, '__file__', None) is not None and
             Path(loaded.__file__).resolve() == (directory / '__init__.py').resolve(),
             'CG_RUNTIME_MODULE')
        return loaded
    spec = importlib.util.spec_from_file_location(name, directory / '__init__.py',
                                                submodule_search_locations=[str(directory)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def bounded_schema_read(path, budget):
    size = path.stat().st_size
    if not 0 < size <= 256 * 1024:
        raise GroundingError('CG_RESOURCE', 'schema size', kind='resource')
    budget.charge(work=8 * size, copied_bytes=8 * size)
    with path.open('rb') as stream:
        raw = stream.read(size + 1)
    need(len(raw) == size, 'CG_SCHEMA_CHANGED')
    return raw


def schema_bytes(budget):
    raw = bounded_schema_read(SCHEMA, budget)
    need(hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256, 'CG_SCHEMA_IDENTITY')
    for relative, expected in GRAMMAR_PINS.items():
        source = bounded_schema_read(ROOT / 'docs/specifications/smir/portable/schema' / relative, budget)
        need(hashlib.sha256(source).hexdigest() == expected, 'CG_NESTED_SCHEMA_IDENTITY', relative)
    return raw


def shape(rule, value, definitions, budget, depth=0):
    """Closed JSON Schema subset used by the three exact pinned input grammars."""
    budget.charge(work=2, edges=1)
    if depth > min(128, budget.max_depth):
        raise GroundingError('CG_RESOURCE', 'schema traversal depth', kind='resource')
    if '$ref' in rule:
        name = rule['$ref'].rsplit('/', 1)[-1]
        return shape(definitions[name], value, definitions, budget, depth)
    for combinator in ('anyOf', 'oneOf'):
        if combinator in rule:
            matches = 0
            for alternative in rule[combinator]:
                try:
                    shape(alternative, value, definitions, budget, depth)
                    matches += 1
                except GroundingError as error:
                    if error.code != 'CG_SHAPE':
                        raise
            need(matches >= 1 if combinator == 'anyOf' else matches == 1, 'CG_SHAPE')
    if 'const' in rule:
        need(type(value) is type(rule['const']) and value == rule['const'], 'CG_SHAPE')
    if 'enum' in rule:
        need(any(type(value) is type(item) and value == item for item in rule['enum']), 'CG_SHAPE')
    kind = rule.get('type')
    if kind is not None:
        expected = {'object': dict, 'array': list, 'integer': int, 'string': str,
                    'boolean': bool, 'null': type(None)}[kind]
        need(type(value) is expected, 'CG_SHAPE')
    if kind == 'object':
        budget.charge(work=len(value), edges=len(value))
        properties = rule.get('properties', {})
        need(set(rule.get('required', ())) <= set(value), 'CG_SHAPE')
        if rule.get('additionalProperties') is False:
            need(set(value) <= set(properties), 'CG_SHAPE')
        for key, child in value.items():
            if key in properties:
                shape(properties[key], child, definitions, budget, depth + 1)
    elif kind == 'array':
        need(rule.get('minItems', 0) <= len(value) <= rule.get('maxItems', 4096), 'CG_SHAPE')
        for child in value:
            shape(rule['items'], child, definitions, budget, depth + 1)
    elif kind == 'integer':
        need(rule.get('minimum', 0) <= value <= rule.get('maximum', (1 << 64) - 1), 'CG_SHAPE')
    elif kind == 'string':
        budget.work(len(value))
        need(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', 4096), 'CG_SHAPE')
        need('pattern' not in rule or re.fullmatch(rule['pattern'], value) is not None, 'CG_SHAPE')


def local_shape(data, budget):
    """Validate local rows before their IDs or labels are used as dictionary keys."""
    need(type(data) is dict and set(data) ==
         {'format', 'revision', 'carrier', 'source_join', 'abi_programs',
          'bindings', 'scopes', 'lifecycles'}, 'CG_SHAPE')
    tables = [('bindings', {'function', 'binding', 'root_binding', 'program', 'cell'},
               ('function', 'binding', 'root_binding')),
              ('scopes', {'function', 'scope', 'program', 'journal_cells'}, ('function', 'scope')),
              ('lifecycles', {'function', 'scope', 'method', 'program'},
               ('function', 'scope', 'method', 'program'))]
    for name, fields, ids in tables:
        rows = data[name]
        need(type(rows) is list and len(rows) <= 4096, 'CG_TABLE')
        budget.charge(work=8 * len(rows), copied_bytes=128 * len(rows))
        for row in rows:
            need(type(row) is dict and set(row) == fields, 'CG_SHAPE')
            need(all(type(row[key]) is int and 0 <= row[key] < 2**32 - 1 for key in ids), 'CG_LINK_ID')
            for key in (('program', 'cell') if name == 'bindings' else ('program',) if name == 'scopes' else ()):
                need(row[key] is None or type(row[key]) is str and 0 < len(row[key]) <= 128, 'CG_LINK_LABEL')
            if name == 'scopes':
                cells = row['journal_cells']
                need(type(cells) is list and len(cells) <= 4096, 'CG_TABLE')
                budget.charge(work=4 * len(cells), copied_bytes=64 * len(cells))
                for cell in cells:
                    need(type(cell) is dict and set(cell) == {'slot', 'cell'}, 'CG_JOURNAL_MAPPING_SHAPE')
                    need(type(cell['slot']) is int and 0 <= cell['slot'] < 2**32 - 1 and
                         type(cell['cell']) is str and 0 < len(cell['cell']) <= 128,
                         'CG_JOURNAL_MAPPING_SHAPE')


def require_item(table, key):
    need(key in table, 'CG_REFERENCE', repr(key))
    return table[key]


def indexed(rows, budget, key=lambda r:r['id']):
    need(type(rows) is list and len(rows) <= 4096, 'CG_TABLE')
    budget.charge(work=len(rows), edges=len(rows), copied_bytes=256*len(rows))
    out = {}
    for row in rows:
        k = key(row)
        need(k not in out, 'CG_DUPLICATE')
        out[k] = row
    return out

def verify_root_chains(bindings, links, budget):
    """Finite original same-function origin forest; never runtime alias identity."""
    budget.charge(work=8 * len(bindings), edges=len(bindings),
                  copied_bytes=256 * len(bindings))
    for key, link in links.items():
        need(set(link) == {'function', 'binding', 'root_binding', 'program', 'cell'},
             'CG_BINDING_SHAPE')
        need(all(type(link[n]) is int and 0 <= link[n] < 2**32 - 1
                 for n in ('function', 'binding', 'root_binding')), 'CG_LINK_ID')
        need(all(link[n] is None or type(link[n]) is str and 0 < len(link[n]) <= 128
                 for n in ('program', 'cell')), 'CG_LINK_LABEL')
        need((key[0], link['root_binding']) in bindings, 'CG_ROOT_CUSTODY')
    terminals = {}
    color = {}
    root_kinds = {'incoming_parameter', 'incoming_alias', 'created',
                  'returned_result', 'returned_parameter'}
    for start in bindings:
        if start in terminals:
            continue
        current = start
        walk = []
        while current not in terminals:
            budget.charge(work=8, edges=1, copied_bytes=128)
            need(current in bindings and current in links, 'CG_ROOT_CUSTODY')
            need(color.get(current, 0) != 1, 'CG_ROOT_CUSTODY', 'origin cycle')
            color[current] = 1
            walk.append(current)
            origin = bindings[current]['origin']
            if origin['kind'] in root_kinds:
                need(links[current]['root_binding'] == current[1], 'CG_ROOT_CUSTODY')
                terminals[current] = current
                break
            need(origin['kind'] == 'retained_alias', 'CG_PROJECTION_OPERATION_REQUIRED')
            current = (current[0], origin['binding'])
        terminal = terminals[current]
        for node in reversed(walk):
            budget.charge(work=4, copied_bytes=64)
            need(links[node]['root_binding'] == terminal[1], 'CG_ROOT_CUSTODY')
            terminals[node] = terminal
            color[node] = 2
    return terminals


def phase_key(site):
    return tuple(sorted(site.items()))

def prove_paths(function, contract, budget, *, source_observers=False):
    """Finite abstraction: aliases retain freshness, never resolve latest slot.

    Worst-case states exponential; each retained state is explicitly precharged.
    Unsupported EH selectors refuse rather than count as successful paths.
    """
    need(type(source_observers) is bool, 'CG_OBSERVER_PROFILE')
    # New operations must not be silently omitted by the legacy helper mode.
    for block in function['blocks']:
        budget.charge(work=4, edges=1)
        for operation in block['ops']:
            budget.charge(work=4, edges=1)
            if operation['op'] == 'source_journal_observe':
                need(source_observers, 'CG_OBSERVER_PROFILE_UNAVAILABLE')
    fid = function['id']
    budget.charge(work=sum(len(v) for v in contract.values() if type(v) is list),copied_bytes=256)
    local = lambda name:[r for r in contract[name] if r['function'] == fid]
    scopes = indexed(local('scopes'), budget)
    values = indexed(local('scope_values'), budget)
    exits = indexed(local('exits'), budget)
    returns = indexed(local('returns'), budget)
    # Precharge and index once; each path exit must not rescan all returns.
    budget.charge(work=4 * len(returns), edges=len(returns),
                  copied_bytes=128 * len(returns))
    returns_by_exit = {}
    for returned in returns.values():
        returns_by_exit.setdefault(returned['exit'], []).append(returned)
    adoptions = indexed(local('adoptions'), budget)
    blocks = indexed(function['blocks'], budget)
    events = {}
    moves = {}
    for row in local('phase_sites'):
        need(row['selector']['kind'] == 'always', 'CG_SELECTOR_UNAVAILABLE')
        events.setdefault(phase_key(row['site']), []).append(row)
    for row in values.values():
        origin = row['origin']
        if origin['kind'] in ('copy', 'select'):
            moves.setdefault(phase_key(origin['site']), []).append(row)
        else:
            need(origin['kind'] in ('enter', 'phi'), 'CG_S_ORIGIN')
    # Every unsupported terminator, including unreachable metadata, is explicit.
    need(all(b['term']['op'] in ('jump', 'cbranch', 'return', 'unreachable') for b in blocks.values()), 'CG_CFG_EDGE_UNAVAILABLE')
    pending = [(function['entry'], None, (), (), ())]
    seen = set()
    states = 0
    while pending:
        block_id, predecessor, live_tuple, alias_tuple, choices_tuple = pending.pop()
        budget.charge(work=8 * (1 + len(live_tuple) + len(alias_tuple) + len(choices_tuple)))
        state = block_id, predecessor, live_tuple, alias_tuple, choices_tuple
        if state in seen:
            continue
        need(len(seen) < 65536, 'CG_STATE_LIMIT')
        budget.charge(work=64+len(alias_tuple)+len(choices_tuple)+len(values)+len(blocks[block_id]['ops'])+len(blocks[block_id]['phis']), edges=1,
                      copied_bytes=512+128*(len(alias_tuple)+len(live_tuple)+len(choices_tuple)))
        seen.add(state)
        states += 1
        live, aliases, choices = set(live_tuple), dict(alias_tuple), dict(choices_tuple)
        block = blocks[block_id]
        # Parallel S phis read the predecessor snapshot.
        incoming = dict(aliases)
        for row in values.values():
            origin = row['origin']
            if origin['kind'] == 'phi' and origin['block'] == block_id:
                budget.charge(work=4 * len(origin['incoming']),
                              edges=len(origin['incoming']),
                              copied_bytes=64 * len(origin['incoming']))
                selected = [x for x in origin['incoming'] if x['predecessor'] == predecessor]
                need(len(selected) == 1, 'CG_S_PHI_EDGE')
                need(selected[0]['value'] in incoming, 'CG_S_UNDEFINED')
                aliases[row['id']] = incoming[selected[0]['value']]
        for phi in block['phis']:
            choices.pop(phi['result']['id'], None)
        def require_value(identifier):
            need(identifier in aliases, 'CG_S_UNDEFINED')
            slot, fresh = aliases[identifier]
            need(fresh and slot in live, 'CG_S_STALE')
            return slot
        def at(site):
            key = phase_key(site)
            for row in events.get(key, ()):
                budget.charge(work=8+len(aliases), copied_bytes=64*len(aliases))
                within = row['within']
                if within['kind'] == 'scope':
                    require_value(within['value'])
                else:
                    need(within['kind'] == 'outside', 'CG_WITHIN_UNAVAILABLE')
                event = row['event']; kind = event['kind']
                if kind in ('enter_root','object_begin_root','object_attach_returned','object_attach_incoming','object_begin_child','enter_child','enter_same_root'):
                    slot = event['scope']
                    declared_within = scopes[slot]['within']
                    if declared_within['kind'] == 'scope':
                        require_value(declared_within['value'])
                    else:
                        need(declared_within['kind'] == 'outside', 'CG_WITHIN_UNAVAILABLE')
                    need(declared_within == within, 'CG_SCOPE_ENTER_WITHIN')
                    need(slot not in live, 'CG_SCOPE_REENTER_LIVE')
                    for identifier, (old, fresh) in list(aliases.items()):
                        if old == slot:
                            aliases[identifier] = old, False
                    live.add(slot)
                    aliases[scopes[slot]['enter_value']] = slot, True
                elif kind == 'scope_exit':
                    exit = exits[event['exit']]
                    slot = require_value(exit['scope_value'])
                    matches = returns_by_exit.get(exit['id'], ())
                    need(len(matches) <= 1 and all(r['scope'] == slot for r in matches), 'CG_RETURN_SCOPE')
                    need(exit['outcome']['kind'] in ('normal_no_journal','normal_retained_scope','normal_retained_call'), 'CG_EXIT_UNAVAILABLE')
                    if exit['outcome']['kind'] == 'normal_retained_scope':
                        receiver_slot = require_value(exit['outcome']['retained_scope_value'])
                        need(receiver_slot != slot, 'CG_RETAINED_SELF')
                    live.remove(slot)
                    for identifier,(old,fresh) in list(aliases.items()):
                        if old == slot:
                            aliases[identifier] = old,False
                elif kind == 'scope_value':
                    row = values[event['value']]
                    origin = row['origin']
                    if origin['kind'] == 'copy':
                        need(origin['source'] in aliases, 'CG_S_UNDEFINED')
                        aliases[row['id']] = aliases[origin['source']]
                    elif origin['kind'] == 'select':
                        need(origin['condition'] in choices, 'CG_S_SELECT_SPLIT_REQUIRED')
                        source = origin['if_true'] if choices[origin['condition']] else origin['if_false']
                        need(source in aliases, 'CG_S_UNDEFINED')
                        aliases[row['id']] = aliases[source]
                    require_value(event['value'])
                elif kind in ('publish','activate','bind_journal','child_commit'):
                    require_value(event['scope_value'])
                elif kind == 'call':
                    for identifier in event['return_adoptions']:
                        budget.charge(work=8, copied_bytes=128)
                        receiver = adoptions[identifier]['receiver']
                        if receiver['kind'] == 'existing':
                            require_value(receiver['value'])
                            raise GroundingError('CG_ADOPTION_EXISTING_PROTOCOL_UNAVAILABLE')
                elif kind != 'call_returned':
                    raise GroundingError('CG_EVENT_UNAVAILABLE', kind)
        at(dict(kind='entry',block=block_id))
        for index, op in enumerate(block['ops']):
            at(dict(kind='pre_op',block=block_id,index=index))
            if op['op'] == 'source_journal_observe':
                budget.charge(work=8, edges=1, copied_bytes=32)
                value = op.get('scope_value')
                need(type(value) is int and 0 <= value < 0xffffffff, 'CG_OBSERVER_OPERATION')
                require_value(value)
            budget.charge(work=4 * len(op['results']), edges=len(op['results']))
            for result in op['results']:
                choices.pop(result['id'], None)
            if op['op'] == 'constant' and len(op['results']) == 1 and op.get('literal',{}).get('kind') == 'bits':
                digits = op['literal']['value']
                budget.charge(work=4 * len(digits), copied_bytes=8 * len(digits))
                choices[op['results'][0]['id']] = bool(int(digits, 16))
            at(dict(kind='normal_post',block=block_id,index=index))
        at(dict(kind='pre_terminator',block=block_id))
        term = block['term']; kind = term['op']
        if kind == 'return':
            at(dict(kind='return_exit',block=block_id))
            budget.charge(work=4 * len(live) * (len(live).bit_length() + 1),
                          copied_bytes=64 * len(live))
            need(not live, 'CG_SCOPE_RETURN_LEAK', str(sorted(live)))
            continue
        if kind == 'unreachable':
            continue
        if kind == 'jump':
            successors = [(term['target'], choices)]
        else:
            condition = term['condition']
            possibilities = (choices[condition],) if condition in choices else (False,True)
            budget.charge(work=4 * len(possibilities) * len(choices),
                          copied_bytes=128 * len(possibilities) * len(choices))
            successors = [(term['true'] if choice else term['false'], dict(choices)) for choice in possibilities]
            for (_, branch), choice in zip(successors, possibilities):
                branch[condition] = choice
        for target, branch in successors:
            sort_work = sum(n * (n.bit_length() + 1)
                            for n in (len(aliases), len(live), len(branch)))
            budget.charge(work=8 + 4 * sort_work, edges=1,
                          copied_bytes=128 + 128 * (len(aliases) + len(live) + len(branch)))
            pending.append((target,block_id,tuple(sorted(live)),tuple(sorted(aliases.items())),tuple(sorted(branch.items()))))
    return states

def ground(owner, request, *, budget):
    need(type(owner) is RootContext, 'CG_OWNER')
    need(type(budget) is P.J.source_api().SourceQueryBudget, 'CG_BUDGET')
    stamp = RootContext.prepare_source_data(owner, budget=budget)
    schema_raw = schema_bytes(budget)
    try:
        data, _ = P.capture(request,budget)
    except P.JoinError as error:
        raise GroundingError('CG_RESOURCE' if error.kind == 'resource' else 'CG_SHAPE', str(error), kind='resource' if error.kind == 'resource' else 'input') from error
    local_shape(data, budget)
    schema = json.loads(schema_raw)
    shape(schema, data, schema['$defs'], budget)
    need(set(data) == {'format','revision','carrier','source_join','abi_programs','bindings','scopes','lifecycles'} and
         data['format'] == 'draft-carrier-static-grounding' and type(data['revision']) is int and data['revision'] == 1,'CG_SHAPE')
    # Public R verifier receives raw carrier and original owner, not an unbound report.
    constraints=runtime_api().verify(owner,data['carrier'],budget=budget)
    contract = data['carrier']['contract']
    key = lambda row:(row['function'],row['id'])
    bindings = indexed(contract['bindings'],budget,key)
    scopes = indexed(contract['scopes'],budget,key)
    links = indexed(data['bindings'],budget,lambda r:(r['function'],r['binding']))
    scope_links = indexed(data['scopes'],budget,lambda r:(r['function'],r['scope']))
    need(set(links)==set(bindings) and set(scope_links)==set(scopes),'CG_EXHAUSTION')
    verify_root_chains(bindings, links, budget)
    join = data['source_join']
    need(len(join['contexts']) == 1, 'CG_CONTEXT_PROFILE')
    joined=P.verify(join,data['abi_programs'],original_owners=(P.OriginalOwnerInput(join['contexts'][0]['id'],owner),),budget=budget)
    need(len(joined.bindings)==1 and joined.bindings[0].owner is owner and joined.bindings[0].stamp is stamp,'CG_ORIGINAL_CONTEXT')
    programs = indexed(join['programs'],budget)
    cells = indexed(join['cells'],budget)
    nominals = indexed(owner.sections[10]['types'],budget)
    journals = indexed(owner.sections[10]['journals'],budget)
    paths = P.api()
    canonical = {}
    binding_docs = {}
    for k,binding in bindings.items():
        link=links[k]
        need(set(link)=={'function','binding','root_binding','program','cell'},'CG_BINDING_SHAPE')
        need(all(type(link[n]) is int and 0<=link[n]<2**32-1 for n in ('function','binding','root_binding')),'CG_LINK_ID')
        need(all(link[n] is None or type(link[n]) is str and 0<len(link[n])<=128 for n in ('program','cell')),'CG_LINK_LABEL')
        root=bindings.get((k[0],link['root_binding']))
        need(root is not None,'CG_ROOT_BINDING')
        origin=binding['origin']
        if origin['kind'] in ('retained_alias','projected_alias','transparent_replacement','launder'):
            parent_id=origin.get('binding',origin.get('old_binding'))
            need((k[0],parent_id) in links and links[k[0],parent_id]['root_binding']==link['root_binding'],'CG_ROOT_CUSTODY')
            # Exact projection/source API semantics are not inferred from geometry.
            need(origin['kind']=='retained_alias','CG_PROJECTION_OPERATION_REQUIRED')
        else:
            need(link['root_binding']==k[1],'CG_ROOT_CUSTODY')
        subject=binding['subject']; route=[]
        budget.charge(work=4 * len(subject['edges']), copied_bytes=128 * len(subject['edges']))
        for edge in subject['edges']:
            if edge['kind']=='element':
                need(edge['index']['kind']=='constant','CG_RUNTIME_INDEX_BOUND_REQUIRED')
                route.append(dict(kind='element',selection=dict(first=edge['index']['value'],count=1)))
            else:
                route.append(dict(edge))
        selector=dict(label='binding',declared_leaf=binding['source_class'],routes=[route])
        doc=dict(format='original-source-paths',revision=1,binding='unbound',runtime_authority=False,source_fact_authority=False,
                 root=subject['root_nominal'],view=subject['root_view'],selectors=[selector])
        report=paths.resolve_source_paths(owner,doc,budget=budget)
        need(not report.deferred and len(report.patterns)==1,'CG_CANONICAL_UNAVAILABLE')
        pattern=report.patterns[0]
        need(pattern.leaf_view==subject['required_leaf_view'],'CG_LEAF_VIEW')
        nominal=nominals[binding['static_pointer_type']['id']]
        need(nominal['kind'] in ('pointer','reference') and len(nominal['elements'])==1,'CG_POINTER_TYPE')
        # Public declared-leaf check enforces semantic source type equivalence.
        pointed=dict(doc,root=nominal['elements'][0],view=subject['required_leaf_view'],selectors=[dict(label='pointee',declared_leaf=binding['source_class'],routes=[[]])])
        pointee_report=paths.resolve_source_paths(owner,pointed,budget=budget)
        need(not pointee_report.deferred and len(pointee_report.patterns)==1,'CG_POINTEE_UNAVAILABLE')
        need((link['program'] is None)==(link['cell'] is None),'CG_CELL_LINK')
        if link['program'] is not None:
            program=require_item(programs, link['program']);cell=require_item(cells, link['cell'])
            need(cell['program']==program['id'],'CG_CELL_PROGRAM')
            cell_doc=P.path_document(program,[dict(label='cell',**cell['selector'])])
            relation=paths.compare_source_paths(owner,doc,'binding',cell_doc,'cell',budget=budget)
            need(relation.relation=='equal' and relation.same_coverage_view,'CG_CELL_SUBJECT')
        canonical[k]=pattern
        binding_docs[k]=doc
    for k,binding in bindings.items():
        if binding['origin']['kind']=='retained_alias':
            parent=(k[0],binding['origin']['binding'])
            relation=paths.compare_source_paths(owner,binding_docs[k],'binding',binding_docs[parent],'binding',budget=budget)
            need(relation.relation=='equal' and relation.same_coverage_view,'CG_ALIAS_SUBJECT')
    checked=[]
    for k,scope in scopes.items():
        link=scope_links[k]
        need(set(link)=={'function','scope','program','journal_cells'},'CG_SCOPE_SHAPE')
        need(all(type(link[n]) is int and 0<=link[n]<2**32-1 for n in ('function','scope')),'CG_LINK_ID')
        need(link['program'] is None or type(link['program']) is str and 0<len(link['program'])<=128,'CG_LINK_LABEL')
        need((scope['program'] is None)==(link['program'] is None),'CG_JOURNAL_LINK')
        if link['program'] is None:
            need(not link['journal_cells'],'CG_JOURNAL_LINK');continue
        program=require_item(programs, link['program'])
        need(scope['program']==program['original_journal'] and scope['view']==program['view'],'CG_JOURNAL_IDENTITY')
        binding_link=links.get((k[0],scope['binding']))
        need(binding_link is not None and binding_link['program']==program['id'] and require_item(cells, binding_link['cell'])['coverage']['kind']=='anchor','CG_SCOPE_ROOT_BINDING')
        journal=journals[scope['program']['id']]
        mapping=indexed(link['journal_cells'],budget,lambda r:r['slot'])
        need(set(mapping)=={s['id'] for s in journal['slots']},'CG_JOURNAL_EXHAUSTION')
        for mapping_row in mapping.values():
            need(set(mapping_row)=={'slot','cell'} and type(mapping_row['slot']) is int and 0<=mapping_row['slot']<2**32-1,'CG_JOURNAL_MAPPING_SHAPE')
        for slot in journal['slots']:
            need(slot['constructor'] is None and slot['destructor'] is None and slot['destructor_kind']=='none','CG_JOURNAL_METHOD_REQUIRED')
            need(slot['count']==1 and slot['parent'] is None and not slot['covers'] and not slot['dependencies'] and slot['child_program'] is None and slot['count_source'] is None,'CG_JOURNAL_HIERARCHY_REQUIRED')
            cell=require_item(cells, mapping[slot['id']]['cell'])
            need(cell['program']==program['id'],'CG_JOURNAL_CELL_PROGRAM')
            need(slot['role']!='root' or cell['coverage']['kind']=='anchor','CG_JOURNAL_ROOT_ANCHOR')
            selector=dict(label='journal',declared_leaf=slot['type'],routes=cell['selector']['routes'])
            report=paths.resolve_source_paths(owner,P.path_document(program,[selector]),budget=budget)
            need(not report.deferred and len(report.patterns)==1,'CG_JOURNAL_PATH')
            p=report.patterns[0]
            need(not p.axes and p.offset_constant_bits==8*slot['offset'] and p.width_bits==8*slot['extent'] and slot['stride']==slot['extent'],'CG_JOURNAL_GEOMETRY')
            budget.charge(work=len(owner.sections[10]['layouts']))
            layout=next(x for x in owner.sections[10]['layouts'] if x['id']==nominals[slot['type']['id']]['layout']['some'])
            need(layout['align']==slot['align'],'CG_JOURNAL_ALIGNMENT')
            checked.append((k[0],k[1],slot['id']))
    lifecycle_rows = indexed(data['lifecycles'], budget,
                             lambda row: (row['function'], row['scope']))
    abi_methods = indexed(data['abi_programs']['methods'], budget)
    abi_programs = indexed(data['abi_programs']['programs'], budget)
    for key, row in lifecycle_rows.items():
        require_item(scopes, key)
        require_item(abi_methods, row['method'])
        require_item(abi_programs, row['program'])
    need(type(data['lifecycles']) is list,'CG_LIFECYCLE_SHAPE')
    need(not data['lifecycles'] and all(s['lifecycle'] is None for s in scopes.values()),'CG_LIFECYCLE_SOURCE_IMPLEMENTATION_REQUIRED')
    # Metadata omission is not evidence that an actual Journal helper had no scope effect.
    imports=indexed(owner.sections[6]['imports'],budget)
    phase_rows=contract['phase_sites']
    budget.charge(work=4 * len(owner.sections[3]['functions']))
    for function in owner.sections[3]['functions']:
        budget.charge(work=4 * len(function['blocks']))
        for block in function['blocks']:
            budget.charge(work=4 * len(block['ops']))
            for op_index,operation in enumerate(block['ops']):
                target=operation.get('target',{})
                if operation['op']!='call' or target.get('kind')!='import':
                    continue
                reference=target['import']
                need(reference['module']=={'kind':'self'},'CG_HELPER_DOMAIN')
                name=imports[reference['id']]['name']
                if name not in ('journal_begin','journal_publish_object'):
                    continue
                budget.charge(work=8+len(phase_rows),copied_bytes=128*len(phase_rows))
                accepted=('object_begin_root','object_begin_child') if name=='journal_begin' else ('publish',)
                matches=[p for p in phase_rows if p['function']==function['id'] and
                    p['site']==dict(kind='normal_post',block=block['id'],index=op_index) and p['event']['kind'] in accepted]
                need(len(matches)==1,'CG_HELPER_SCOPE_COVERAGE',name)
    functions=[]
    for function in owner.sections[3]['functions']:
        states=prove_paths(function,contract,budget)
        functions.append((function['id'],states))
    need(RootContext.prepare_source_data(owner,budget=budget) is stamp,'CG_SOURCE_CHANGED')
    need(schema_bytes(budget) == schema_raw, 'CG_SCHEMA_CHANGED')
    obligations=('CG_TERMINAL_TRAP_RECLAMATION_NOT_PROVED','CG_NORMAL_CFG_ONLY','CG_EFFECTIVE_CV_SOURCE_API_NOT_PROVED','CG_PRIVATE_AUTHORITY_NOT_ISSUED','CG_LIFECYCLE_NOT_SUPPORTED')
    budget.charge(work=len(constraints.deferred)+len(joined.obligations)+len(joined.unselected_deferred),copied_bytes=2048*(len(constraints.deferred)+len(joined.obligations)+len(joined.unselected_deferred)+4))
    # Preserve upstream gaps; this finite normal-path proof does not erase broader obligations.
    sort_sizes = (len(canonical), len(checked), len(functions),
                  len(obligations) + len(constraints.deferred) + len(joined.obligations) +
                  len(joined.unselected_deferred))
    budget.charge(work=8 * sum(n * (n.bit_length() + 1) for n in sort_sizes),
                  copied_bytes=128 * sum(sort_sizes))
    deferred=tuple(sorted(set(obligations)|set(constraints.deferred)|set(joined.obligations)|{repr(x) for x in joined.unselected_deferred}))
    return GroundedConstraints(owner,stamp,tuple(sorted(canonical)),tuple(sorted(checked)),tuple(sorted(functions)),deferred)
