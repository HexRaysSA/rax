"""Independent arbitrary-precision reference semantics, isolated from RAX runtime.

Undef and freeze use the deterministic zero refinement. This is one permitted
execution, not a universal quantification over LLVM's nondeterministic choices.
"""
from dataclasses import dataclass, field

from common import Limits, bit_pattern, require
from verify import verify


@dataclass(frozen=True)
class Value:
    kind: str
    bits: int = 0


POISON = Value('poison')
UNDEF = Value('undef')


class Trap(Exception):
    def __init__(self, code):
        self.code = code


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def integer(op, width, a, b=None, flags=(), predicate=None):
    """Mathematical bitvector operation, with deferred poison and precise UB."""
    modulus = 1 << width
    mask = modulus - 1
    if op == 'freeze':
        return a if a.kind == 'bits' else Value('bits', 0)
    if op == 'copy':
        return a
    if op in {'udiv', 'sdiv', 'urem', 'srem'}:
        if b.kind == 'poison':
            raise Trap('ub_poison_divisor')
        if b.bits == 0:
            raise Trap('ub_div_zero')
        if op in {'sdiv', 'srem'} and b.bits == mask:
            if a.kind == 'poison' or a.bits == 1 << (width - 1):
                raise Trap('ub_signed_div_overflow')
    if a.kind == 'poison' or (b is not None and b.kind == 'poison'):
        return POISON
    # Each undef use is independently refined to zero, rather than inventing
    # dependence between values from a shared host register or memory location.
    av = a.bits
    bv = b.bits if b is not None else 0
    sa, sb = signed(av, width), signed(bv, width)
    if op in {'shl', 'lshr', 'ashr'} and bv >= width:
        return POISON
    if op == 'add':
        unsigned_result, signed_result = av + bv, sa + sb
    elif op == 'sub':
        unsigned_result, signed_result = av - bv, sa - sb
    elif op == 'mul':
        unsigned_result, signed_result = av * bv, sa * sb
    elif op == 'shl':
        unsigned_result, signed_result = av << bv, sa * (1 << bv)
    elif op in {'lshr', 'ashr'}:
        if 'exact' in flags and av & ((1 << bv) - 1):
            return POISON
        return Value('bits', (av >> bv if op == 'lshr' else sa >> bv) & mask)
    elif op in {'udiv', 'urem'}:
        quotient, remainder = divmod(av, bv)
        if 'exact' in flags and remainder:
            return POISON
        return Value('bits', quotient if op == 'udiv' else remainder)
    elif op in {'sdiv', 'srem'}:
        quotient = abs(sa) // abs(sb)
        if (sa < 0) != (sb < 0):
            quotient = -quotient
        remainder = sa - quotient * sb
        if 'exact' in flags and remainder:
            return POISON
        return Value('bits', (quotient if op == 'sdiv' else remainder) & mask)
    elif op in {'and', 'or', 'xor'}:
        result = {'and': lambda: av & bv, 'or': lambda: av | bv,
                  'xor': lambda: av ^ bv}[op]()
        return Value('bits', result)
    elif op == 'icmp':
        left, right = (sa, sb) if predicate.startswith('s') else (av, bv)
        relation = predicate[1:] if predicate[0] in {'s', 'u'} else predicate
        result = {'eq': left == right, 'ne': left != right,
                  'lt': left < right, 'le': left <= right,
                  'gt': left > right, 'ge': left >= right}[relation]
        return Value('bits', int(result))
    else:
        raise ValueError(f'internal unsupported arithmetic {op}')
    if 'nuw' in flags and not 0 <= unsigned_result < modulus:
        return POISON
    if 'nsw' in flags and not -(1 << (width - 1)) <= signed_result < 1 << (width - 1):
        return POISON
    return Value('bits', unsigned_result & mask)


@dataclass
class Frame:
    function: dict
    block: int
    values: dict
    predecessor: int | None = None
    position: int = -1
    waiting: list = field(default_factory=list)


def run(module, entry, arguments, fuel=100_000, max_frames=1024, limits=Limits()):
    """Re-verify before executing any instruction; no cached mutable admission.

    Returns logical results/trap or an external reference-resource stop. It does
    not execute envelope bytes, native code, imports, memory or exception code.
    """
    verify(module, limits)
    require(type(fuel) is int and fuel >= 0 and type(max_frames) is int and max_frames >= 1,
            'limit', 'execution budget')
    types = {item['id']: item['bits'] for item in module['types']}
    functions = {item['id']: item for item in module['functions']}
    require(type(entry) is int and entry in functions, 'entry', 'entry function')
    function = functions[entry]
    require(isinstance(arguments, list) and len(arguments) == len(function['params']),
            'argument', 'entry arity')
    from common import check_shape
    check_shape('vec:hex', arguments, limits)
    initial = [Value('bits', bit_pattern(text, types[param['type']]))
               for param, text in zip(function['params'], arguments)]

    def activate(callee, args):
        return Frame(callee, callee['entry'],
                     {param['id']: value for param, value in zip(callee['params'], args)})

    stack = [activate(function, initial)]
    block_maps = {item['id']: {block['id']: block for block in item['blocks']}
                  for item in functions.values()}
    value_widths = {item['id']: {declaration['id']: types[declaration['type']]
                               for declaration in declarations(item)}
                    for item in functions.values()}
    steps = 0

    def stop(kind, code):
        frame = stack[-1]
        return {'kind': kind, 'code': code, 'function': frame.function['id'],
                'block': frame.block, 'operation': frame.position, 'steps': steps,
                'stack': [{'function': item.function['id'], 'block': item.block,
                           'operation': item.position} for item in stack]}

    def branch(frame, target):
        frame.predecessor, frame.block, frame.position = frame.block, target, -1

    def concrete_condition(value):
        if value.kind != 'bits':
            raise Trap('ub_control_value')
        return value.bits

    while stack:
        frame = stack[-1]
        block = block_maps[frame.function['id']][frame.block]
        if steps == fuel:
            return stop('limit', 'fuel')
        steps += 1
        if frame.position == -1:
            # Snapshot all incoming values before replacing any phi result.
            incoming = {}
            for phi in block['phis']:
                source = next(item['value'] for item in phi['incoming']
                              if item['block'] == frame.predecessor)
                incoming[phi['out']['id']] = frame.values[source]
            frame.values.update(incoming)
            frame.position = 0
            continue
        try:
            if frame.position < len(block['ops']):
                operation = block['ops'][frame.position]
                op = operation['op']
                if op == 'call':
                    if len(stack) == max_frames:
                        return stop('limit', 'frames')
                    args = [frame.values[value] for value in operation['args']]
                    frame.waiting = operation['outs']
                    stack.append(activate(functions[operation['callee']], args))
                    continue
                out = operation['out']
                width = types[out['type']]
                if op == 'const':
                    value = Value('bits', bit_pattern(operation['bits'], width))
                elif op in {'poison', 'undef'}:
                    value = POISON if op == 'poison' else UNDEF
                elif op in {'copy', 'freeze'}:
                    value = integer(op, width, frame.values[operation['value']])
                elif op in {'trunc', 'zext', 'sext'}:
                    value = frame.values[operation['value']]
                    if value.kind != 'poison':
                        source_width = value_widths[frame.function['id']][operation['value']]
                        converted = signed(value.bits, source_width) if op == 'sext' else value.bits
                        value = Value('bits', converted & ((1 << width) - 1))
                elif op == 'select':
                    condition = frame.values[operation['cond']]
                    value = (POISON if condition.kind == 'poison' else
                             frame.values[operation['true'] if condition.bits else operation['false']])
                else:
                    a = frame.values[operation['a']]
                    b = frame.values[operation['b']]
                    operand_width = width
                    if op == 'icmp':
                        operand_width = value_widths[frame.function['id']][operation['a']]
                    value = integer(op, operand_width, a, b, operation.get('flags', ()),
                                    operation.get('predicate'))
                frame.values[out['id']] = value
                frame.position += 1
                continue
            term = block['term']
            op = term['op']
            if op == 'return':
                values = [frame.values[value] for value in term['values']]
                if len(stack) == 1:
                    results = []
                    for value, type_id in zip(values, frame.function['results']):
                        result = {'kind': value.kind}
                        if value.kind == 'bits':
                            result['bits'] = value.bits.to_bytes((types[type_id] + 7) // 8, 'little').hex()
                        results.append(result)
                    return {'kind': 'return', 'values': results, 'steps': steps}
                stack.pop()
                caller = stack[-1]
                caller.values.update({out['id']: value for out, value in zip(caller.waiting, values)})
                caller.waiting = []
                caller.position += 1
            elif op == 'tailcall':
                args = [frame.values[value] for value in term['args']]
                stack[-1] = activate(functions[term['callee']], args)
            elif op == 'br':
                branch(frame, term['target'])
            elif op == 'cbr':
                condition = concrete_condition(frame.values[term['cond']])
                branch(frame, term['true'] if condition else term['false'])
            elif op == 'switch':
                index = concrete_condition(frame.values[term['index']])
                target = term['default']
                for case in term['cases']:
                    if int.from_bytes(bytes.fromhex(case['bits']), 'little') == index:
                        target = case['target']
                        break
                branch(frame, target)
            else:
                raise Trap('explicit' if op == 'trap' else 'ub_unreachable')
        except Trap as error:
            return stop('trap', error.code)


def declarations(function):
    yield from function['params']
    for block in function['blocks']:
        for phi in block['phis']:
            yield phi['out']
        for operation in block['ops']:
            if operation['op'] == 'call':
                yield from operation['outs']
            else:
                yield operation['out']
