"""Independent normalized comparison-view and whole-group selection oracle.

Inputs are admitted compiler comparison views specified with LLVM (R007/INT011).
This never authenticates a producer digest or replaces execution/ABI admission.
"""
from collections import deque
import json

from .errors import exact, require, uint


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf8')


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'RT_COMDAT_DIGEST')
    return value


def function_body(source):
    """Alpha-normalize tagged SSA/CFG, retaining constants; O(N log N), O(N)."""
    exact(source, ['revision', 'signature', 'params', 'entry', 'blocks', 'regions', 'block_addresses'])
    require(source['revision'] == 'llvm-comparison-v1' and source['block_addresses'] is False,
            'RT_COMDAT_VIEW')
    digest(source['signature'])
    blocks = {}
    for block in source['blocks']:
        exact(block, ['id', 'phis', 'ops', 'term', 'edges'])
        identity = uint(block['id'], 32)
        require(identity not in blocks, 'RT_COMDAT_BLOCK')
        roles = set()
        for edge in block['edges']:
            exact(edge, ['role', 'target'])
            require(type(edge['role']) is str and edge['role'] not in roles, 'RT_COMDAT_EDGE')
            uint(edge['target'], 32)
            roles.add(edge['role'])
        blocks[identity] = block
    require(source['entry'] in blocks, 'RT_COMDAT_ENTRY')
    pending, reached, order = deque([source['entry']]), {source['entry']}, []
    while pending:
        identity = pending.popleft()
        order.append(identity)
        for edge in sorted(blocks[identity]['edges'], key=lambda item: item['role']):
            require(edge['target'] in blocks, 'RT_COMDAT_BLOCK_REF')
            if edge['target'] not in reached:
                reached.add(edge['target'])
                pending.append(edge['target'])
    bmap = {identity: index for index, identity in enumerate(order)}
    vmap = {}

    def declaration(value):
        exact(value, ['id', 'type'])
        identity = uint(value['id'], 32)
        require(identity not in vmap, 'RT_COMDAT_VALUE')
        digest(value['type'])
        vmap[identity] = len(vmap)
        return {'id': vmap[identity], 'type': value['type']}

    params = [declaration(value) for value in source['params']]
    output = []
    for identity in order:
        block = blocks[identity]
        phis = []
        for phi in block['phis']:
            exact(phi, ['out', 'incoming'])
            phis.append({'out': declaration(phi['out']), 'incoming': phi['incoming']})
        operations = []
        for operation in [*block['ops'], block['term']]:
            exact(operation, ['op', 'outs', 'payload'])
            require(type(operation['op']) is str, 'RT_COMDAT_OPCODE')
            operations.append({'op': operation['op'], 'outs': [declaration(v) for v in operation['outs']],
                               'payload': operation['payload']})
        output.append({'id': bmap[identity], 'phis': phis, 'ops': operations[:-1],
                       'term': operations[-1], 'edges': sorted(
                           [{'role': e['role'], 'target': bmap[e['target']]} for e in block['edges']],
                           key=lambda item: item['role'])})

    def rewrite(node, depth=0):
        require(depth <= 128, 'RT_COMDAT_DEPTH')
        if type(node) is dict:
            if '$ref' in node:
                exact(node, ['$ref', 'id'])
                role, identity = node['$ref'], node['id']
                if role in {'value', 'block'}:
                    table = vmap if role == 'value' else bmap
                    require(type(identity) is int and identity in table, 'RT_COMDAT_REFERENCE')
                    return {'$ref': role, 'id': table[identity]}
                require(role in {'type', 'symbol', 'region'}, 'RT_COMDAT_REFERENCE_KIND')
                return {'$ref': role, 'id': digest(identity)}
            return {key: rewrite(value, depth + 1) for key, value in node.items() if key != 'debug'}
        if type(node) is list:
            return [rewrite(value, depth + 1) for value in node]
        require(type(node) in {str, int, bool, type(None)}, 'RT_COMDAT_NODE')
        return node

    for block in output:
        for phi in block['phis']:
            pairs, seen = [], set()
            for incoming in phi['incoming']:
                exact(incoming, ['block', 'value'])
                old_block, old_value = incoming['block'], incoming['value']
                uint(old_block, 32)
                uint(old_value, 32)
                if old_block not in bmap:
                    continue
                require(old_block not in seen and old_value in vmap, 'RT_COMDAT_PHI')
                seen.add(old_block)
                pairs.append({'block': bmap[old_block], 'value': vmap[old_value]})
            phi['incoming'] = sorted(pairs, key=lambda item: item['block'])
        for operation in [*block['ops'], block['term']]:
            operation['payload'] = rewrite(operation['payload'])
    return canonical({'revision': 'llvm-comparison-v1', 'signature': source['signature'],
                      'params': params, 'blocks': output, 'regions': rewrite(source['regions'])})


def select(groups):
    """Whole groups with ABI checks independent of bodies; O(B+G log G)."""
    require(type(groups) is list and groups, 'RT_COMDAT_EMPTY')
    checked, ordinals, key = [], set(), None
    for group in groups:
        exact(group, ['key', 'selection', 'key_symbol', 'members', 'input_ordinal'])
        require(type(group['key']) is str and group['key'], 'RT_COMDAT_KEY')
        if key is None:
            key = group['key']
        require(group['key'] == key, 'RT_COMDAT_KEY')
        ordinal = uint(group['input_ordinal'], 32)
        require(ordinal not in ordinals, 'RT_COMDAT_ORDINAL')
        ordinals.add(ordinal)
        require(group['selection'] in {'any', 'exactmatch', 'largest', 'samesize',
                                      'noduplicates', 'nodeduplicate'}, 'RT_COMDAT_SELECTION')
        members = {}
        for member in group['members']:
            exact(member, ['symbol', 'abi', 'kind', 'extent', 'body', 'extent_policy'])
            require(type(member['symbol']) is str and member['symbol'] and
                    member['symbol'] not in members, 'RT_COMDAT_MEMBER')
            digest(member['abi'])
            require(member['kind'] in {'function', 'data', 'tls'} and
                    member['extent_policy'] in {'fixed', 'selected_definition'}, 'RT_COMDAT_MEMBER')
            uint(member['extent'])
            require(type(member['body']) is bytes, 'RT_COMDAT_BODY')
            if member['kind'] == 'function':
                require(member['extent'] == len(member['body']), 'RT_COMDAT_FUNCTION_EXTENT')
            members[member['symbol']] = member
        require(members and group['key_symbol'] in members, 'RT_COMDAT_KEY_SYMBOL')
        checked.append((group, members))
    kinds = {group['selection'] for group, _ in checked}
    require(len(kinds) == 1 or kinds <= {'any', 'largest'}, 'RT_COMDAT_MIXED_SELECTION')
    kind = 'largest' if 'largest' in kinds else next(iter(kinds))
    checked.sort(key=lambda pair: pair[0]['input_ordinal'])
    first, baseline = checked[0]
    union = dict(baseline)
    for group, members in checked[1:]:
        require(group['key_symbol'] == first['key_symbol'], 'RT_COMDAT_KEY_SYMBOL')
        for name, member in members.items():
            if name not in union:
                union[name] = member
                continue
            before = union[name]
            require(all(member[field] == before[field] for field in ['abi', 'kind', 'extent_policy']),
                    'RT_COMDAT_ABI')
            if member['kind'] != 'function' and member['extent_policy'] == 'fixed':
                require(member['extent'] == before['extent'], 'RT_COMDAT_EXTENT')
    if kind == 'noduplicates':
        require(len(checked) == 1, 'RT_COMDAT_DUPLICATE')
    if kind == 'nodeduplicate':
        return [group['input_ordinal'] for group, _ in checked]
    if kind == 'exactmatch':
        require(all(members == baseline for _, members in checked[1:]), 'RT_COMDAT_EXACTMATCH')
    extents = [members[group['key_symbol']]['extent'] for group, members in checked]
    if kind == 'samesize':
        require(len(set(extents)) == 1, 'RT_COMDAT_SAMESIZE')
    if kind == 'largest':
        return [max(checked, key=lambda pair: pair[1][pair[0]['key_symbol']]['extent'])[0]['input_ordinal']]
    return [first['input_ordinal']]
