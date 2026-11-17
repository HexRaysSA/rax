"""Exact structural type-graph witness; distinct from source ABI layout/identity."""
from common import Limits, check_shape, require
from verify import unique_map

FLOAT_WIDTHS = {'binary16': 16, 'bfloat16': 16, 'binary32': 32,
                'binary64': 64, 'binary128': 128}
SCALARS = {'int', 'raw', 'float', 'data_ptr', 'code_ptr'}


def children(item, storage=False):
    kind = item['kind']
    if kind in {'array', 'vector'}:
        return [item['element']]
    if kind == 'struct':
        return item['fields']
    if not storage and kind == 'code_ptr':
        return [item['signature']]
    if not storage and kind == 'function':
        return item['params'] + item['results']
    return []


def verify_types(document, limits=Limits(), max_logical_bits=64 * 1024 * 1024):
    check_shape('extended_types', document, limits)
    require(document['revision'] == 'execution_types_draft_v1', 'type_revision')
    types = unique_map(document['types'], 'extended types', ordered=True)
    require(0 < len(types) <= 65535, 'type_limit')
    for item in types.values():
        kind = item['kind']
        require(all(child in types for child in children(item)), 'type_reference')
        if kind in {'int', 'raw'}:
            require(1 <= item['bits'] <= min(65535, limits.max_bits), 'type_width')
        elif kind == 'float':
            require(item['format'] in FLOAT_WIDTHS, 'type_float')
        elif kind == 'data_ptr':
            require(item['space'] == 'guest_data', 'type_space')
        elif kind == 'code_ptr':
            require(types[item['signature']]['kind'] == 'function', 'type_signature')
        elif kind == 'vector':
            require(1 <= item['count'] <= 65535 and types[item['element']]['kind'] in SCALARS,
                    'type_vector')
        elif kind in {'array', 'struct'}:
            require(all(types[child]['kind'] != 'function' for child in children(item)), 'type_value')
        elif kind == 'function':
            require(item['variadic'] in {'yes', 'no'} and item['cc'] == 'portable', 'type_signature')
            require(all(types[child]['kind'] != 'function' for child in children(item)), 'type_signature')
            for values, attributes in [('params', 'param_noundef'), ('results', 'result_noundef')]:
                require(len(item[values]) == len(item[attributes])
                        and set(item[attributes]) <= {'yes', 'no'}, 'type_signature')
    # Iterative DFS rejects by-value cycles without recursion on guest graphs.
    widths, active = {}, set()
    for root in types:
        pending = [(root, False)]
        while pending:
            identifier, finish = pending.pop()
            if identifier in widths:
                continue
            item = types[identifier]
            kind = item['kind']
            if not finish:
                require(identifier not in active, 'type_cycle')
                active.add(identifier)
                pending.append((identifier, True))
                pending.extend((child, False) for child in reversed(children(item, storage=True)))
                continue
            active.remove(identifier)
            if kind in {'int', 'raw'}:
                width = item['bits']
            elif kind == 'float':
                width = FLOAT_WIDTHS[item['format']]
            elif kind in {'data_ptr', 'code_ptr'}:
                width = 64
            elif kind in {'array', 'vector'}:
                width = item['count'] * widths[item['element']]
            elif kind == 'struct':
                width = sum(widths[child] for child in item['fields'])
            else:
                width = 0  # Signatures are descriptors, never first-class values.
            require(width <= max_logical_bits, 'type_limit', 'logical SSA bit extent')
            widths[identifier] = width
    return types, widths


def equivalent(left, left_id, right, right_id):
    """Coinductive equality of previously admitted deterministic type graphs.

    Local numeric IDs never establish cross-module equivalence. Recursive code
    pointer signatures compare by labeled graph bisimulation, with visited pairs.
    """
    pending = [(left_id, right_id)]
    seen = set()
    while pending:
        pair = pending.pop()
        if pair in seen:
            continue
        seen.add(pair)
        require(pair[0] in left and pair[1] in right, 'type_reference')
        a, b = left[pair[0]], right[pair[1]]
        if a['kind'] != b['kind']:
            return False
        excluded = {'id', 'element', 'fields', 'signature', 'params', 'results'}
        if ({key: value for key, value in a.items() if key not in excluded}
                != {key: value for key, value in b.items() if key not in excluded}):
            return False
        ac, bc = children(a), children(b)
        if len(ac) != len(bc):
            return False
        # Preserve parameter/result partition, not just the flattened edge list.
        if a['kind'] == 'function' and len(a['params']) != len(b['params']):
            return False
        pending.extend(zip(ac, bc))
    return True
