"""Actual admitted execution records -> independently comparable compiler view.

This is a projection, never an admission or producer-identity authority. All
cross-root identities must come from the same admission transaction. No LLVM
backend or guest execution is implemented here.
"""
from collections import deque
import hashlib
import json
from pathlib import Path
import struct

from canonical import canonical_function, digest, json_bytes, require

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/execution/candidate.json'


def entity_key(reference):
    module = reference['module']
    return (('self', reference['id']) if module['kind'] == 'self'
            else ('dependency', module['slot'], reference['id']))


def project_function(function, eh, types, entity_identity, recipes=None):
    """Project actual admitted function/EH records; O(N**2 + identity costs) worst-case.

    types is the actual SEM Types object. entity_identity(namespace, reference)
    resolves function/import/symbol/signature/nominal/layout/storage_binding/
    journal/recipe in actual admitted roots, returning lowercase SHA256 hex.
    recipes maps qualified recipe keys to admitted ABI adapter_recipe records.
    CFG/value/region/formal IDs carry no semantic identity; constants do.
    """
    records = json.loads(SCHEMA.read_text())['records']
    recipes = {} if recipes is None else recipes

    def exact_shape(kind, node):
        if kind.startswith('vec:'):
            require(type(node) is list, 'COMPARE_RECORD_SEQUENCE')
            for item in node:
                exact_shape(kind[4:], item)
        elif kind.startswith('opt:'):
            require(node is None or (type(node) is dict and set(node) == {'some'}),
                    'COMPARE_OPTION')
            if node is not None:
                exact_shape(kind[4:], node['some'])
        elif kind in records:
            record = records[kind]
            discriminator = record.get('discriminator')
            fields = (record['variants'].get(node.get(discriminator)) if discriminator else record['fields'])
            require(fields is not None and set(node) == {n for n, _ in fields} |
                    ({discriminator} if discriminator else set()), 'COMPARE_RECORD_FIELDS')
            for name, child in fields:
                exact_shape(child, node[name])
    exact_shape('function', function)
    exact_shape('eh_function', eh)
    require(eh['function'] == function['id'], 'COMPARE_EH_FUNCTION')
    blocks = {b['id']: b for b in function['blocks']}
    require(len(blocks) == len(function['blocks']), 'COMPARE_DUPLICATE_BLOCK')

    def edges(term):
        op = term['op']
        require(op != 'indirect_branch', 'E-COMPARE-BLOCK-ADDRESS')
        if op == 'jump':
            return [('jump', term['target'])]
        if op == 'cbranch':
            return [('false', term['false']), ('true', term['true'])]
        if op == 'switch':
            # Actual literal hex is little-endian; successor role uses numeric
            # fixed-width big-endian hex, without changing the literal payload.
            return [('default', term['default'])] + [
                ('case_' + bytes.fromhex(c['value'])[::-1].hex(), c['target'])
                for c in term['cases']]
        if op == 'invoke':
            return [('normal', term['normal']['target']), ('unwind', term['unwind']['target'])]
        return []

    pending, order, reached = deque([function['entry']]), [], {function['entry']}
    while pending:
        identity = pending.popleft()
        require(identity in blocks, 'COMPARE_BLOCK_REFERENCE')
        order.append(identity)
        for _, target in sorted(edges(blocks[identity]['term'])):
            if target not in reached:
                reached.add(target)
                pending.append(target)
    # Current actual SEM admission rejects unreachable blocks. Do not silently
    # discard one if this projection is accidentally used on a different root.
    require(reached == set(blocks), 'COMPARE_UNREACHABLE')
    bmap, vmap = {old: n for n, old in enumerate(order)}, {}

    def declare(decl):
        require(decl['id'] not in vmap, 'COMPARE_DUPLICATE_VALUE')
        vmap[decl['id']] = len(vmap)
    for param in function['params']:
        declare(param)
    for identity in order:
        block = blocks[identity]
        for phi in block['phis']:
            declare(phi['result'])
        for operation in block['ops']:
            require(operation['op'] != 'block_address', 'E-COMPARE-BLOCK-ADDRESS')
            for result in operation['results']:
                declare(result)
        if block['term']['op'] == 'invoke':
            for result in block['term']['normal']['results']:
                declare(result)
            declare(block['term']['unwind']['exception'])

    def value(identity):
        require(identity in vmap, 'COMPARE_VALUE_REFERENCE')
        return {'$ref': 'value', 'id': vmap[identity]}

    def block(identity):
        require(identity in bmap, 'COMPARE_BLOCK_REFERENCE')
        return {'$ref': 'block', 'id': bmap[identity]}

    def entity(namespace, reference):
        identity = types.digest(reference) if namespace == 'type' else entity_identity(namespace, reference)
        return {'$ref': 'type' if namespace == 'type' else 'symbol', 'id': digest(identity)}

    def optional(node, transform):
        require(node is None or (type(node) is dict and set(node) == {'some'}), 'COMPARE_OPTION')
        return None if node is None else {'some': transform(node['some'])}

    def declaration(decl):
        return {'id': vmap[decl['id']], 'type': digest(types.digest(decl['type']))}

    regions = {r['id']: r for r in eh['regions']}
    actions = {a['id']: a for a in eh['actions']}
    require(len(regions) == len(eh['regions']) and len(actions) == len(eh['actions']), 'COMPARE_EH_DUPLICATE')

    def action_content(action):
        recipe = recipes.get(entity_key(action['recipe']))
        require(recipe is not None, 'COMPARE_RECIPE_METADATA')
        formals = {p['id']: n for n, p in enumerate(recipe['params'])}
        require(len(formals) == len(recipe['params']), 'COMPARE_FORMALS')
        captures = []
        for capture in action['captures']:
            require(capture['parameter'] in formals, 'COMPARE_CAPTURE_FORMAL')
            source = capture['source']
            if source['kind'] == 'value':
                source = {'kind': 'value', 'value': value(source['value'])}
            elif source['kind'] == 'journal':
                source = {'kind': 'journal', 'program': entity('journal', source['program'])}
            else:
                require(source == {'kind': 'exception'}, 'COMPARE_CAPTURE_SOURCE')
            captures.append({'parameter': formals[capture['parameter']],
                             'type': entity('type', capture['type']), 'source': source})
        require({c['parameter'] for c in captures} == set(range(len(formals)))
                and len(captures) == len(formals), 'COMPARE_CAPTURE_BIJECTION')
        return {'program': entity('journal', action['program']),
                'recipe': entity('recipe', action['recipe']),
                'captures': sorted(captures, key=lambda c: c['parameter'])}

    contents = {identity: action_content(a) for identity, a in actions.items()}
    rmap, amap, hmap = {}, {}, {}
    handler_owner = {h['id']: r['id'] for r in regions.values() for h in r['handlers']}

    def action_ref(identity):
        require(identity in actions, 'COMPARE_ACTION_REFERENCE')
        if identity not in amap:
            amap[identity] = len(amap)
        return amap[identity]

    def visit_region(identity):
        require(identity in regions, 'COMPARE_REGION_REFERENCE')
        if identity in rmap:
            return
        parent = regions[identity]['parent']
        if parent is not None:
            visit_region(parent['some'])
        rmap[identity] = len(rmap)

    def depth(identity):
        seen = set()
        while identity is not None:
            require(identity in regions and identity not in seen, 'COMPARE_REGION_CYCLE')
            seen.add(identity)
            parent = regions[identity]['parent']
            identity = None if parent is None else parent['some']
        return len(seen)

    # Region membership is an admitted ancestor chain. Visit that chain for
    # each canonical block, then explicit op/terminator references in source order.
    for identity in order:
        for r in sorted((r for r in regions.values() if identity in r['blocks']),
                        key=lambda r: depth(r['id'])):
            visit_region(r['id'])
        for op in [*blocks[identity]['ops'], blocks[identity]['term']]:
            if 'handler' in op:
                require(op['handler'] in handler_owner, 'COMPARE_HANDLER_REFERENCE')
                visit_region(handler_owner[op['handler']])
            if 'region' in op:
                region = op['region'] if type(op['region']) is int else (None if op['region'] is None else op['region']['some'])
                if region is not None:
                    visit_region(region)

    def region_key(identity):
        r = regions[identity]
        # Remaining empty/unreferenced regions still participate in comparison.
        # Stable semantic content breaks ties; identical unused records are
        # interchangeable. Their original record numbers never enter the key.
        return json_bytes({'depth': depth(identity), 'blocks': sorted(bmap[b] for b in r['blocks']),
            'escape': r['escape'], 'actions': [contents[a] for a in r['exit_actions']],
            'handlers': [{'kind': h['kind'], 'selector': h['selector'],
                'entry': bmap[h['entry']],
                'nominal': optional(h['nominal'], lambda x: entity('nominal', x)),
                'actions': [contents[a] for a in h['cleanup_actions']],
                'copy': optional(h['catch_copy'], lambda x: contents[x])} for h in r['handlers']]})
    for level in sorted({depth(r) for r in regions}):
        candidates = [r for r in regions if depth(r) == level and r not in rmap]
        def remaining_key(r):
            parent = regions[r]['parent']
            return (-1 if parent is None else rmap[parent['some']], region_key(r))
        for identity in sorted(candidates, key=remaining_key):
            visit_region(identity)
    normalized_regions = []
    for identity in sorted(rmap, key=rmap.get):
        r = regions[identity]
        handlers = []
        exits = [action_ref(a) for a in r['exit_actions']]
        for h in r['handlers']:
            require(h['id'] not in hmap, 'COMPARE_HANDLER_DUPLICATE')
            hmap[h['id']] = len(hmap)
            handlers.append({'id': hmap[h['id']],
                'selector': h['selector'], 'kind': h['kind'],
                'nominal': optional(h['nominal'], lambda x: entity('nominal', x)),
                'entry': block(h['entry']), 'cleanup_actions': [action_ref(a) for a in h['cleanup_actions']],
                'catch_copy': optional(h['catch_copy'], action_ref)})
        normalized_regions.append({'id': rmap[identity], 'parent': optional(r['parent'], lambda x: rmap[x]),
            'blocks': [block(b) for b in sorted(r['blocks'], key=bmap.get)],
            'exit_actions': exits, 'handlers': handlers, 'escape': r['escape']})
    for identity in sorted(actions, key=lambda x: json_bytes(contents[x])):
        action_ref(identity)
    eh_node = {'function': {'escape': function['escape'], 'no_return': function['no_return'],
                 'abi_signature': optional(function['abi_signature'], lambda x: entity('signature', x))},
               'regions': normalized_regions,
               'actions': [dict(id=amap[a], **contents[a]) for a in sorted(amap, key=amap.get)]}
    eh_bytes = json_bytes(eh_node)
    region_prefix = hashlib.sha256(b'SMIR-COMPARE-REGION-V1\0' + eh_bytes)

    def region_ref(identity):
        require(identity in rmap, 'COMPARE_REGION_REFERENCE')
        hasher = region_prefix.copy()
        hasher.update(struct.pack('<I', rmap[identity]))
        return {'$ref': 'region', 'id': hasher.hexdigest()}

    namespaces = {'type': 'type', 'signature': 'type', 'function': 'function',
        'import': 'import', 'symbol': 'symbol', 'layout': 'layout', 'nominal': 'nominal',
        'abi_binding': 'storage_binding', 'program': 'journal', 'recipe': 'recipe'}

    def walk(kind, node, parent='', field='', opcode=''):
        if kind.startswith('vec:'):
            return [walk(kind[4:], x, parent, field, opcode) for x in node]
        if kind.startswith('opt:'):
            return optional(node, lambda x: walk(kind[4:], x, parent, field, opcode))
        if kind == 'entity_ref':
            namespace = namespaces.get(field)
            if field == 'binding':
                namespace = 'symbol' if opcode == 'tls_address' else 'nominal'
            require(namespace is not None, 'COMPARE_ENTITY_NAMESPACE')
            return entity(namespace, node)
        if kind in records:
            record = records[kind]
            discriminator = record.get('discriminator')
            variant = node.get(discriminator) if discriminator else None
            fields = record['variants'].get(variant) if discriminator else record['fields']
            require(fields is not None, 'COMPARE_VARIANT')
            require(set(node) == {name for name, _ in fields} | ({discriminator} if discriminator else set()),
                    'COMPARE_RECORD_FIELDS')
            result = {discriminator: variant} if discriminator else {}
            for name, child in fields:
                result[name] = walk(child, node[name], kind, name, variant or opcode)
            return result
        if kind == 'u32':
            if field == 'operands' or (parent == 'target' and field == 'value'):
                return value(node)
            if parent == 'terminator':
                if field in {'condition', 'index', 'values', 'exception'}:
                    return value(node)
                if field in {'target', 'true', 'false', 'default'}:
                    return block(node)
            if parent in {'normal_edge', 'unwind_edge', 'switch_case'} and field == 'target':
                return block(node)
            if field == 'region':
                return region_ref(node)
            if field == 'handler':
                require(node in hmap, 'COMPARE_HANDLER_REFERENCE')
                return hmap[node]
        return node

    output = []
    for identity in order:
        b = blocks[identity]
        ops = []
        for op in [*b['ops'], b['term']]:
            term = op is b['term']
            payload = walk('terminator' if term else 'operation', op)
            payload.pop('op')
            outs = [] if term else op['results']
            payload.pop('results', None)
            if term and op['op'] == 'invoke':
                outs = op['normal']['results'] + [op['unwind']['exception']]
                payload['normal'].pop('results')
                payload['unwind'].pop('exception')
            ops.append({'op': op['op'], 'outs': [declaration(d) for d in outs], 'payload': payload})
        output.append({'id': bmap[identity], 'phis': [
            {'out': declaration(p['result']), 'incoming': [
                {'block': bmap[x['predecessor']], 'value': vmap[x['value']]}
                for x in sorted(p['incoming'], key=lambda x: bmap[x['predecessor']])]} for p in b['phis']],
            'ops': ops[:-1], 'term': ops[-1],
            'edges': [{'role': role, 'target': bmap[target]} for role, target in edges(b['term'])]})
    return {'revision': 'llvm-comparison-v1', 'signature': digest(types.digest(function['signature'])),
            'params': [declaration(p) for p in function['params']], 'entry': bmap[function['entry']],
            'blocks': output, 'regions': eh_node, 'block_addresses': False}


def canonical_candidate_function(function, eh, types, entity_identity, recipes=None):
    return canonical_function(project_function(function, eh, types, entity_identity, recipes))
