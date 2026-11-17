"""OWNCOORD finite factory profile. No guessed whole-factory work coefficient."""
from common import require

MAX_OBJECT_BYTES = 4096
MAX_VALUE_BITS = 8 * MAX_OBJECT_BYTES


def metrics(roots, payload_bytes, budget):
    """Bound cardinality and numeric extents before any inherited factory."""
    require(payload_bytes <= 1024 * 1024, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    pending = [(roots, 0)]
    nodes = records = 0
    while pending:
        item, depth = pending.pop()
        budget.charge(work=4, edges=1, copied_bytes=32)
        nodes += 1
        require(nodes <= 8192 and depth <= 64, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        if type(item) in (dict, list):
            budget.charge(work=4 * len(item), edges=len(item), copied_bytes=32 * len(item))
            require(len(item) <= 256, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            if type(item) is dict:
                records += 1
                pending.extend((x, depth + 1) for x in item.values())
            else:
                pending.extend((x, depth + 1) for x in item)
    require(records <= 1024, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    physical = roots[1]['types']; nominal = roots[10]['types']
    functions = roots[3]['functions']
    require(all(len(f['params']) <= 16 for f in functions),
            'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    blocks = sum(len(f['blocks']) for f in functions)
    values = sum(len(f['params']) + sum(len(b['phis']) + sum(1 + len(op['results'])
                 for op in b['ops']) for b in f['blocks']) for f in functions)
    require(len(physical) <= 64 and len(nominal) <= 16 and len(functions) <= 4 and
            blocks <= 64 and values <= 256, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    require(not roots[8]['functions'], 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    require(not roots[2]['manifest']['dependencies'] and not roots[10]['bridges'],
            'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    require(all(all(domain[name] == 'portable' for name in ('isa','abi','personality'))
                for domain in roots[10]['domains']), 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    require(len(roots[6]['imports']) <= 8 and len(roots[10]['journals']) <= 4,
            'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    for row in roots[6]['imports']:
        require(row['kind'] == 'internal' and row['name'] in
                ('journal_begin', 'journal_advance', 'journal_publish_object'),
                'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    nominal_index = {row['id']: row for row in nominal}
    for row in nominal:
        require(row['kind'] in ('void','scalar','pointer','reference','function','record') and
                row['bits'] <= 128 and len(row['methods']) <= 8 and
                not any(method['virtual'] for method in row['methods']), 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        if row['kind'] in ('pointer', 'reference'):
            require(row['bits'] == 64, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        if row['kind'] == 'function':
            require(len(row['elements']) <= 17, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        if row['kind'] == 'record':
            source = row['record_input']
            require(source is not None and not source['some']['bases'] and
                    not source['some']['dynamic'] and not source['some']['polymorphic'] and
                    len(source['some']['fields']) <= 8, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            explicit = source['some']['explicit_align']
            require(explicit is None or explicit['some'] <= MAX_OBJECT_BYTES, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            for field in source['some']['fields']:
                for name, bound in (('explicit_align', MAX_OBJECT_BYTES), ('bit_width', 128)):
                    optional = field[name]
                    require(optional is None or optional['some'] <= bound, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
                reference = field['type']
                require(reference['module'] == {'kind':'self'} and
                        reference['id'] in nominal_index and
                        nominal_index[reference['id']]['kind'] == 'scalar', 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    maximum = 0
    for row in roots[10]['layouts']:
        require(row['size'] <= MAX_OBJECT_BYTES and row['align'] <= MAX_OBJECT_BYTES and
                not row['bases'] and not row['vptrs'], 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        maximum = max(maximum, row['size'])
        for field in row['fields']:
            require(field['offset_bits'] <= MAX_VALUE_BITS and
                    field['width_bits'] <= MAX_VALUE_BITS, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    for row in roots[1]['memory_layouts']:
        require(row['size'] <= MAX_OBJECT_BYTES and row['access_bytes'] <= MAX_OBJECT_BYTES,
                'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        maximum = max(maximum, row['size'])
    for row in roots[10]['storage_bindings']:
        require(row['access_bytes'] <= MAX_OBJECT_BYTES and
                row['view_offset_bits'] <= MAX_VALUE_BITS and
                row['view_width_bits'] <= MAX_VALUE_BITS, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    for plan in roots[10]['signatures']:
        require(len(plan['lowered_params']) <= 16 and len(plan['lowered_results']) <= 8,
                'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    for row in roots[10]['journals']:
        require(len(row['slots']) <= 64 and len(row['params']) <= 16, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        for slot in row['slots']:
            require(slot['parent'] is None and slot['child_program'] is None and
                    slot['count_source'] is None and not slot['covers'] and
                    not slot['dependencies'] and slot['count'] * slot['stride'] <= MAX_OBJECT_BYTES,
                    'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            require(slot['count'] <= 1024 and
                    all(slot[k] <= MAX_OBJECT_BYTES for k in ('offset','extent','stride','align')),
                    'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    table = {row['id']: row for row in physical}
    widths, costs = {}, {}
    active = set()
    for row in physical:
        if row['kind'] == 'function':
            require(len(row['params']) <= 16 and len(row['results']) <= 8, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    for root in table:
        pending = [(root, False)]
        while pending:
            identifier, after = pending.pop()
            budget.charge(work=16, edges=1, copied_bytes=64)
            if identifier in widths:
                continue
            require(identifier in table, 'V3_TYPE_REFERENCE')
            row = table[identifier]; kind = row['kind']
            children = ([row['element']] if kind in ('array','vector') else
                        row['fields'] if kind == 'struct' else [])
            require(len(children) <= 8 if kind == 'struct' else True, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            child_ids = []
            for child in children:
                require(child['module'] == {'kind':'self'} and child['id'] in table,
                        'V3_TYPE_REFERENCE')
                child_ids.append(child['id'])
            if not after:
                require(identifier not in active, 'V3_TYPE_VALUE_CYCLE')
                active.add(identifier); pending.append((identifier, True))
                pending.extend((child, False) for child in reversed(child_ids))
                continue
            active.remove(identifier)
            if kind in ('int','raw'):
                require(1 <= row['bits'] <= (128 if kind == 'int' else MAX_VALUE_BITS),
                        'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE'); width = row['bits']
            elif kind == 'float':
                from .type_system import FLOATS
                require(row['format'] in FLOATS, 'V3_TYPE_FORMAT')
                width = FLOATS[row['format']]
            elif kind in ('data_ptr','code_ptr','code_address'):
                width = 64
            elif kind in ('array','vector'):
                require(row['count'] <= (16 if kind == 'vector' else 1024), 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
                width = row['count'] * widths[child_ids[0]]
            elif kind == 'struct':
                width = sum(widths[x] for x in child_ids)
            else:
                width = 0
            cost = (1 + row['count'] * costs[child_ids[0]] if kind in ('array','vector') else
                    1 + sum(costs[x] for x in child_ids) if kind == 'struct' else 1)
            require(width <= MAX_VALUE_BITS and cost <= 8192, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            widths[identifier], costs[identifier] = width, cost
    return dict(tree_nodes=nodes, semantic_records=records, payload_bytes=payload_bytes,
                maximum_object_bytes=maximum, physical_types=len(physical),
                nominal_types=len(nominal), functions=len(functions), blocks=blocks, values=values)

