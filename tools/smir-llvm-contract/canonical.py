"""Draft canonical content and COMDAT references; never executable admission.

Function input is an explicit compiler comparison view, not LLVM or SMIR wire.
All semantic references are tagged, so numeric constants are never renamed.
"""
from collections import deque
import hashlib
import json
import struct

from reference import ContractError


def require(condition, code):
    if not condition:
        raise ContractError(code)


def keys(value, expected):
    require(type(value) is dict and value.keys() == set(expected.split()), 'CANON_FIELDS')


def uint(value, bits=32):
    require(type(value) is int and 0 <= value < 1 << bits, 'CANON_INTEGER')
    return value


def text(value):
    require(type(value) is str, 'CANON_TEXT')
    try:
        value.encode('utf8', errors='strict')
    except UnicodeError as error:
        raise ContractError('CANON_UTF8') from error
    return value


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'CANON_DIGEST')
    return value


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf8')


def module_identity(sections, own_identity, own_offset):
    """Hash verified canonical section bytes; own_offset is section2 digest offset.

    Does not parse payloads or attest canonicality. Caller must use the accepted
    section2 schema to obtain the one identity field and verify self-reference tags.
    """
    require(type(sections) is dict and set(sections) == set(range(1, 11)), 'HASH_SECTIONS')
    require(all(type(k) is int for k in sections), 'HASH_SECTION_ID')
    require(type(own_identity) is bytes and len(own_identity) == 32, 'HASH_IDENTITY')
    uint(own_offset, 64)
    for payload in sections.values():
        require(type(payload) is bytes, 'HASH_PAYLOAD')
        uint(len(payload), 64)
    manifest = sections[2]
    require(own_offset + 32 <= len(manifest), 'HASH_IDENTITY_BOUNDS')
    require(manifest[own_offset:own_offset + 32] == own_identity, 'HASH_IDENTITY_FIELD')
    normalized = manifest[:own_offset] + bytes(32) + manifest[own_offset + 32:]
    hasher = hashlib.sha256(b'SMIR0.2\0' + struct.pack('<I', 2))
    for section_id in range(1, 11):
        payload = normalized if section_id == 2 else sections[section_id]
        hasher.update(struct.pack('<HQ', section_id, len(payload)))
        hasher.update(payload)
    return hasher.hexdigest()


def canonical_function(function):
    """Alpha-normalize an explicitly typed comparison view in O(N log N).

    Inputs contain blocks/operations with tagged payload refs. Unreachable blocks
    are excluded, permitted only when block addresses are absent. Semantic/type/
    region/dominance verification belongs to the producer before this comparison.
    This function separately rejects missing/duplicate reference declarations.
    """
    keys(function, 'revision signature params entry blocks regions block_addresses')
    require(function['revision'] == 'llvm-comparison-v1', 'CANON_REVISION')
    require(function['block_addresses'] is False, 'CANON_BLOCK_ADDRESS')
    digest(function['signature'])
    require(type(function['blocks']) is list and type(function['params']) is list,
            'CANON_SEQUENCE')
    blocks = {}
    for block in function['blocks']:
        keys(block, 'id phis ops term edges')
        identifier = uint(block['id'])
        require(identifier not in blocks, 'CANON_DUPLICATE_BLOCK')
        require(type(block['edges']) is list and all(type(e) is dict for e in block['edges']),
                'CANON_EDGES')
        seen_roles = set()
        for edge in block['edges']:
            keys(edge, 'role target')
            require(text(edge['role']) not in seen_roles, 'CANON_DUPLICATE_EDGE')
            seen_roles.add(edge['role'])
            uint(edge['target'])
        blocks[identifier] = block
    entry = uint(function['entry'])
    require(entry in blocks, 'CANON_ENTRY')
    order = []
    discovered = {entry}
    pending = deque([entry])
    while pending:
        identifier = pending.popleft()
        order.append(identifier)
        # Roles are canonical names: jump, true, false, default, case_<hex>,
        # normal, unwind. Lexical sort fixes traversal independently of source IDs.
        for edge in sorted(blocks[identifier]['edges'], key=lambda e: e['role']):
            target = edge['target']
            require(target in blocks, 'CANON_BLOCK_REF')
            if target not in discovered:
                discovered.add(target)
                pending.append(target)
    block_ids = {identifier: index for index, identifier in enumerate(order)}
    value_ids = {}

    def declare(declaration):
        keys(declaration, 'id type')
        identifier = uint(declaration['id'])
        digest(declaration['type'])
        require(identifier not in value_ids, 'CANON_DUPLICATE_VALUE')
        value_ids[identifier] = len(value_ids)
        return {'id': value_ids[identifier], 'type': declaration['type']}

    params = [declare(p) for p in function['params']]
    normalized = []
    for identifier in order:
        block = blocks[identifier]
        require(type(block['phis']) is list and type(block['ops']) is list, 'CANON_SEQUENCE')
        phis = []
        for phi in block['phis']:
            keys(phi, 'out incoming')
            phis.append({'out': declare(phi['out']), 'incoming': phi['incoming']})
        operations = []
        for operation in [*block['ops'], block['term']]:
            keys(operation, 'op outs payload')
            text(operation['op'])
            require(type(operation['outs']) is list, 'CANON_SEQUENCE')
            operations.append({'op': operation['op'],
                               'outs': [declare(d) for d in operation['outs']],
                               'payload': operation['payload']})
        normalized.append({'id': block_ids[identifier], 'phis': phis,
                           'ops': operations[:-1], 'term': operations[-1],
                           'edges': sorted([{'role': e['role'], 'target': block_ids[e['target']]}
                                            for e in block['edges']], key=lambda e: e['role'])})

    def rewrite(node, depth=0):
        require(depth <= 128, 'CANON_DEPTH')
        if type(node) is dict:
            if '$ref' in node:
                keys(node, '$ref id')
                kind, identifier = node['$ref'], node['id']
                if kind in ('value', 'block'):
                    uint(identifier)
                    table = value_ids if kind == 'value' else block_ids
                    require(identifier in table, 'CANON_REFERENCE')
                    return {'$ref': kind, 'id': table[identifier]}
                require(kind in ('type', 'symbol', 'region'), 'CANON_REFERENCE_KIND')
                # Type/symbol/region identities already independently normalized.
                return {'$ref': kind, 'id': digest(identifier)}
            return {text(k): rewrite(v, depth + 1) for k, v in node.items() if k != 'debug'}
        if type(node) is list:
            return [rewrite(v, depth + 1) for v in node]
        require(type(node) in (str, int, bool, type(None)), 'CANON_NODE')
        if type(node) is str:
            text(node)
        return node

    for block in normalized:
        for phi in block['phis']:
            require(type(phi['incoming']) is list, 'CANON_PHI')
            incoming = []
            seen = set()
            for pair in phi['incoming']:
                keys(pair, 'block value')
                old_block, old_value = pair['block'], pair['value']
                uint(old_block)
                uint(old_value)
                if old_block not in block_ids:
                    continue  # Predecessor removed with unreachable CFG.
                require(old_block not in seen and old_value in value_ids, 'CANON_PHI')
                seen.add(old_block)
                incoming.append({'block': block_ids[old_block], 'value': value_ids[old_value]})
            phi['incoming'] = sorted(incoming, key=lambda i: i['block'])
        for op in [*block['ops'], block['term']]:
            op['payload'] = rewrite(op['payload'])
    return json_bytes({'revision': 'llvm-comparison-v1', 'signature': function['signature'],
                       'params': params, 'blocks': normalized,
                       'regions': rewrite(function['regions'])})


def select_comdat(groups):
    """Select whole groups; O(total content bytes + groups log groups)."""
    require(type(groups) is list and groups, 'COMDAT_EMPTY')
    names, ordinals, checked = set(), set(), []
    for group in groups:
        keys(group, 'key selection key_symbol members input_ordinal')
        text(group['key'])
        require(group['key'], 'COMDAT_KEY')
        ordinal = uint(group['input_ordinal'])
        require(ordinal not in ordinals, 'COMDAT_ORDINAL')
        ordinals.add(ordinal)
        require(group['selection'] in ('any', 'exactmatch', 'largest', 'samesize',
                                      'noduplicates', 'nodeduplicate'), 'COMDAT_SELECTION')
        require(type(group['members']) is list and group['members'], 'COMDAT_MEMBERS')
        members = {}
        for member in group['members']:
            keys(member, 'symbol abi kind extent body extent_policy')
            symbol = text(member['symbol'])
            require(symbol not in members, 'COMDAT_DUPLICATE_MEMBER')
            digest(member['abi'])
            require(member['kind'] in ('function', 'data', 'tls'), 'COMDAT_KIND')
            uint(member['extent'], 64)
            require(type(member['body']) is bytes, 'COMDAT_BODY')
            if member['kind'] == 'function':
                require(member['extent'] == len(member['body']), 'COMDAT_CODE_EXTENT')
            require(member['extent_policy'] in ('fixed', 'selected_definition'), 'COMDAT_EXTENT_POLICY')
            members[symbol] = member
        require(group['key_symbol'] in members, 'COMDAT_KEY_SYMBOL')
        names.add(group['key'])
        checked.append((group, members))
    require(len(names) == 1, 'COMDAT_GROUP_KEY')
    selections = {g['selection'] for g, _ in checked}
    # Match LLVM LinkModules mixing Any/Largest; other mixed kinds reject.
    require(len(selections) == 1 or selections <= {'any', 'largest'}, 'COMDAT_SELECTION_MISMATCH')
    kind = 'largest' if 'largest' in selections else next(iter(selections))
    checked.sort(key=lambda item: item[0]['input_ordinal'])
    first, first_members = checked[0]
    known_members = dict(first_members)
    for group, members in checked[1:]:
        require(group['key_symbol'] == first['key_symbol'], 'COMDAT_MEMBERS_MISMATCH')
        if kind == 'exactmatch':
            require(members.keys() == first_members.keys(), 'COMDAT_MEMBERS_MISMATCH')
        for symbol in members.keys() & known_members.keys():
            before, after = known_members[symbol], members[symbol]
            require(all(before[k] == after[k] for k in ('abi', 'kind', 'extent_policy')),
                    'COMDAT_ABI_MISMATCH')
            if before['kind'] != 'function' and before['extent_policy'] == 'fixed':
                require(before['extent'] == after['extent'], 'COMDAT_EXTENT_MISMATCH')
        known_members.update(members)
    if kind == 'noduplicates':
        require(len(checked) == 1, 'COMDAT_DUPLICATE')
    if kind == 'nodeduplicate':
        return [g['input_ordinal'] for g, _ in checked]
    if kind == 'exactmatch':
        for _, members in checked[1:]:
            require(members == first_members, 'COMDAT_EXACTMATCH')
    key_sizes = [members[group['key_symbol']]['extent'] for group, members in checked]
    if kind == 'samesize':
        require(len(set(key_sizes)) == 1, 'COMDAT_SAMESIZE')
    if kind == 'largest':
        winner = max(checked, key=lambda item: item[1][item[0]['key_symbol']]['extent'])
        return [winner[0]['input_ordinal']]
    return [first['input_ordinal']]
