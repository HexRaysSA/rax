"""Semantic admission for the isolated integer-core reference model.

No envelope, runtime module, memory, host code pointer or existing SMIR IR is
accepted here. Every run re-verifies the entire input, including dead operands.
"""
from common import Limits, bit_pattern, check_shape, require

ARITHMETIC = {'add', 'sub', 'mul', 'shl', 'lshr', 'ashr', 'udiv', 'sdiv',
              'urem', 'srem', 'and', 'or', 'xor'}
PREDICATES = {'eq', 'ne', 'ult', 'ule', 'ugt', 'uge', 'slt', 'sle', 'sgt', 'sge'}


def unique_map(items, name, ordered=False):
    identifiers = [item['id'] for item in items]
    require(len(identifiers) == len(set(identifiers)), 'duplicate', name)
    if ordered:
        require(identifiers == sorted(identifiers), 'order', name)
    return {item['id']: item for item in items}


def outputs(operation):
    return operation['outs'] if operation['op'] == 'call' else [operation['out']]


def operands(operation):
    op = operation['op']
    if op in ARITHMETIC or op == 'icmp':
        return [operation['a'], operation['b']]
    if op in {'copy', 'freeze', 'trunc', 'zext', 'sext'}:
        return [operation['value']]
    if op == 'select':
        return [operation['cond'], operation['true'], operation['false']]
    if op == 'call':
        return operation['args']
    return []


def successors(term):
    if term['op'] == 'br':
        return {term['target']}
    if term['op'] == 'cbr':
        return {term['true'], term['false']}
    if term['op'] == 'switch':
        return {term['default']} | {item['target'] for item in term['cases']}
    return set()


def term_operands(term):
    if term['op'] == 'cbr':
        return [term['cond']]
    if term['op'] == 'switch':
        return [term['index']]
    if term['op'] == 'return':
        return term['values']
    if term['op'] == 'tailcall':
        return term['args']
    return []


def verify(module, limits=Limits()):
    check_shape('module', module, limits)
    require(module['revision'] == 'integer_core_draft_v1', 'revision')
    types = unique_map(module['types'], 'types', ordered=True)
    require(types, 'type', 'empty type table')
    widths = []
    for item in types.values():
        require(1 <= item['bits'] <= min(65535, limits.max_bits), 'type', 'integer width')
        widths.append(item['bits'])
    require(len(set(widths)) == len(widths), 'type', 'duplicate structural integer type')
    functions = unique_map(module['functions'], 'functions', ordered=True)
    require(0 < len(functions) <= limits.max_functions, 'limit', 'function count')
    for function in functions.values():
        for declaration in function['params']:
            require(declaration['type'] in types, 'type', 'parameter type')
        require(all(result in types for result in function['results']), 'type', 'result type')
    for function in functions.values():
        verify_function(function, functions, types, limits)
    return module


def verify_function(function, functions, types, limits):
    blocks = unique_map(function['blocks'], 'blocks', ordered=True)
    require(0 < len(blocks) <= limits.max_blocks, 'limit', 'block count')
    entry = function['entry']
    require(entry in blocks, 'cfg', 'entry block')
    predecessors = {identifier: set() for identifier in blocks}
    for block in blocks.values():
        for target in successors(block['term']):
            require(target in blocks, 'cfg', 'branch target')
            predecessors[target].add(block['id'])
    require(not predecessors[entry] and not blocks[entry]['phis'], 'cfg',
            'entry must have no predecessor or phi')
    reached = set()
    pending = [entry]
    while pending:
        identifier = pending.pop()
        if identifier not in reached:
            reached.add(identifier)
            pending.extend(successors(blocks[identifier]['term']))
    require(reached == set(blocks), 'cfg', 'unreachable block: canonicalize before emission')

    # Bitsets keep the witness finite and avoid a set object per CFG edge.
    bits = {identifier: 1 << index for index, identifier in enumerate(blocks)}
    dominators = {identifier: (bits[entry] if identifier == entry else (1 << len(blocks)) - 1)
                  for identifier in blocks}
    changed = True
    while changed:
        changed = False
        for identifier in blocks:
            if identifier == entry:
                continue
            common = (1 << len(blocks)) - 1
            for predecessor in predecessors[identifier]:
                common &= dominators[predecessor]
            updated = bits[identifier] | common
            if updated != dominators[identifier]:
                dominators[identifier] = updated
                changed = True

    definitions = {}

    def define(declaration, block, index):
        identifier = declaration['id']
        require(identifier not in definitions, 'duplicate', 'activation-local value')
        require(declaration['type'] in types, 'type', 'value declaration')
        definitions[identifier] = (declaration['type'], block, index)

    for declaration in function['params']:
        define(declaration, None, -1)
    for block in blocks.values():
        for phi in block['phis']:
            define(phi['out'], block['id'], -1)
        for index, operation in enumerate(block['ops']):
            for declaration in outputs(operation):
                define(declaration, block['id'], index)

    def use(identifier, block, index):
        require(identifier in definitions, 'reference', 'unknown value')
        type_id, origin, position = definitions[identifier]
        if origin is not None:
            require((origin == block and position < index)
                    or (origin != block and dominators[block] & bits[origin]),
                    'dominance', f'value {identifier} at block {block}')
        return type_id

    def type_of(identifier):
        require(identifier in definitions, 'reference', 'unknown value')
        return definitions[identifier][0]

    def width(identifier):
        return types[type_of(identifier)]['bits']

    def call_shape(operation, expected_results=None):
        require(operation['callee'] in functions, 'call', 'unknown callee')
        callee = functions[operation['callee']]
        require([type_of(value) for value in operation['args']]
                == [parameter['type'] for parameter in callee['params']],
                'call', 'argument signature')
        result_types = ([out['type'] for out in operation['outs']]
                        if expected_results is None else expected_results)
        require(result_types == callee['results'], 'call', 'result signature')

    for block in blocks.values():
        identifier = block['id']
        for phi in block['phis']:
            incoming = [item['block'] for item in phi['incoming']]
            require(len(incoming) == len(set(incoming))
                    and set(incoming) == predecessors[identifier], 'phi', 'predecessor bijection')
            for item in phi['incoming']:
                predecessor = item['block']
                require(use(item['value'], predecessor, len(blocks[predecessor]['ops']))
                        == phi['out']['type'], 'type', 'phi incoming')
        for index, operation in enumerate(block['ops']):
            for value in operands(operation):
                use(value, identifier, index)
            op = operation['op']
            if op == 'call':
                call_shape(operation)
                continue
            result = operation['out']['type']
            result_width = types[result]['bits']
            if op == 'const':
                bit_pattern(operation['bits'], result_width)
            elif op in {'copy', 'freeze'}:
                require(result == type_of(operation['value']), 'type', op)
            elif op in {'trunc', 'zext', 'sext'}:
                source_width = width(operation['value'])
                require((result_width < source_width if op == 'trunc'
                         else result_width > source_width), 'type', 'conversion direction')
            elif op in ARITHMETIC or op == 'icmp':
                operand_type = type_of(operation['a'])
                require(type_of(operation['b']) == operand_type, 'type', 'binary operands')
                require((result_width == 1 if op == 'icmp' else result == operand_type),
                        'type', 'binary result')
                if op == 'icmp':
                    require(operation['predicate'] in PREDICATES, 'predicate')
            elif op == 'select':
                require(width(operation['cond']) == 1 and type_of(operation['true']) == result
                        and type_of(operation['false']) == result, 'type', 'select')
            if 'flags' in operation:
                flags = operation['flags']
                allowed = {'nsw', 'nuw'} if op in {'add', 'sub', 'mul', 'shl'} else {'exact'}
                require(flags == sorted(set(flags)) and set(flags) <= allowed, 'flags', op)
        term = block['term']
        for value in term_operands(term):
            use(value, identifier, len(block['ops']))
        if term['op'] == 'cbr':
            require(width(term['cond']) == 1, 'type', 'branch condition')
        elif term['op'] == 'switch':
            case_values = [bit_pattern(case['bits'], width(term['index'])) for case in term['cases']]
            require(case_values == sorted(set(case_values)), 'switch', 'distinct sorted cases')
        elif term['op'] == 'return':
            require([type_of(value) for value in term['values']] == function['results'],
                    'type', 'return signature')
        elif term['op'] == 'tailcall':
            call_shape(term, function['results'])
