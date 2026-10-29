"""Derive structural A64 FP/SIMD allocation from pinned primary decode ASTs.

All feature predicates are true here. This derives allocation, not a CPU's
selected extension profile. Unknown dependent constructs stop generation.
"""
import dataclasses

HAVE = {
    'HaveFP16MulNoRoundingToFP32Ext', 'HaveFP16Ext', 'HaveSM3Ext',
    'HaveSHA1Ext', 'HaveDOTPExt', 'HaveFCADDExt', 'HaveAESExt',
    'HaveQRDMLAHExt', 'HaveSM4Ext', 'HaveSHA3Ext', 'HaveFrintExt',
    'HaveFJCVTZSExt', 'HaveSHA256Ext', 'HaveSHA512Ext',
    'HaveBit128PMULLExt',
}


def variables(value):
    if isinstance(value, list):
        return set().union(*(variables(x) for x in value)) if value else set()
    if not isinstance(value, dict):
        return set()
    if 'Var' in value:
        return {value['Var']['name']} - {'TRUE', 'FALSE'}
    return set().union(*(variables(x) for x in value.values()))


def slice_block(statements, needed):
    needed = set(needed)
    kept = []
    for statement in reversed(statements):
        if isinstance(statement, str):
            assert statement == 'Undefined', statement
            kept.append(statement)
            continue
        kind, value = next(iter(statement.items()))
        if kind == 'See':
            kept.append(statement)
        elif kind in ('Assign', 'VarDeclInit', 'ConstDecl'):
            name = value['target']['Var']['name'] if kind == 'Assign' else value['name']
            if name in needed:
                needed.remove(name)
                needed |= variables(value['value'])
                kept.append(statement)
        elif kind == 'VarsDecl':
            if needed.intersection(value['names']):
                needed.difference_update(value['names'])
                kept.append(statement)
        elif kind == 'If':
            branches = []
            incoming = set()
            for condition, body in value['branches']:
                selected, dependencies = slice_block(body, needed)
                branches.append((condition, selected))
                incoming |= dependencies | variables(condition)
            otherwise, dependencies = slice_block(value['else_body'] or [], needed)
            incoming |= dependencies
            if otherwise or any(body for _, body in branches):
                kept.append({'If': {'branches': branches, 'else_body': otherwise}})
                needed = incoming
        elif kind == 'Case':
            alternatives = []
            incoming = set()
            has_default = False
            for alternative in value['alts']:
                selected, dependencies = slice_block(alternative['body'], needed)
                incoming |= dependencies | variables(alternative['guard'])
                has_default |= alternative['patterns'] is None
                alternatives.append(dict(alternative, body=selected))
            if any(alt['body'] for alt in alternatives):
                if not has_default:
                    incoming |= needed
                kept.append({'Case': {'expr': value['expr'], 'alts': alternatives}})
                needed = incoming | variables(value['expr'])
        else:
            raise ValueError(('unqualified statement', kind))
    return list(reversed(kept)), needed


@dataclasses.dataclass(frozen=True)
class Bits:
    value: int
    width: int


@dataclasses.dataclass(frozen=True)
class Mask:
    value: int
    mask: int
    width: int


def number(value):
    return value.value if isinstance(value, Bits) else value


def match(left, right):
    if isinstance(right, Mask):
        assert isinstance(left, Bits) and left.width == right.width
        return left.value & right.mask == right.value
    if isinstance(left, Mask):
        return match(right, left)
    if isinstance(left, Bits) and isinstance(right, Bits):
        assert left.width == right.width, (left, right)
    return number(left) == number(right)


def evaluate(expr, env):
    kind, data = next(iter(expr.items()))
    if kind == 'LitInt':
        return data
    if kind == 'LitBits':
        return Bits(int(''.join('1' if bit else '0' for bit in data), 2), len(data))
    if kind == 'LitMask':
        return Mask(int(''.join('1' if bit == 'One' else '0' for bit in data), 2),
                    int(''.join('0' if bit == 'Either' else '1' for bit in data), 2), len(data))
    if kind == 'Var':
        name = data['name']
        if name in ('TRUE', 'FALSE'):
            return name == 'TRUE'
        return env[name]
    if kind == 'Call':
        name = data['name']['name']
        if name in HAVE:
            assert not data['args']
            return True
        args = [evaluate(arg, env) for arg in data['args']]
        if name == 'UInt':
            assert len(args) == 1
            return number(args[0])
        if name == 'LowestSetBit':
            value = args[0]
            assert isinstance(value, Bits)
            return (value.value & -value.value).bit_length() - 1 if value.value else value.width
        if name == 'HighestSetBit':
            return number(args[0]).bit_length() - 1
        raise ValueError(('dependent function', name))
    if kind == 'Unary':
        value = evaluate(data['operand'], env)
        if data['op'] == 'Not':
            assert isinstance(value, bool)
            return not value
        assert data['op'] == 'Neg'
        return -number(value)
    if kind == 'Binary':
        op = data['op']
        left = evaluate(data['lhs'], env)
        if op == 'And' and not left:
            return False
        if op == 'Or' and left:
            return True
        right = evaluate(data['rhs'], env)
        if op == 'Eq':
            return match(left, right)
        if op == 'Ne':
            return not match(left, right)
        if op == 'And':
            assert isinstance(left, bool) and isinstance(right, bool)
            return left and right
        if op == 'Or':
            assert isinstance(left, bool) and isinstance(right, bool)
            return left or right
        if op == 'BitConcat':
            assert isinstance(left, Bits) and isinstance(right, Bits)
            return Bits((left.value << right.width) | right.value, left.width + right.width)
        left, right = number(left), number(right)
        operators = {'Add': lambda: left + right, 'Sub': lambda: left - right,
                     'Mul': lambda: left * right, 'Shl': lambda: left << right,
                     'Shr': lambda: left >> right, 'Gt': lambda: left > right,
                     'Ge': lambda: left >= right, 'Lt': lambda: left < right,
                     'Le': lambda: left <= right}
        if op not in operators:
            raise ValueError(('dependent operator', op))
        return operators[op]()
    if kind == 'If':
        for condition, value in data['branches']:
            if evaluate(condition, env):
                return evaluate(value, env)
        return evaluate(data['else_branch'], env)
    if kind in ('Slice', 'Index'):
        value = evaluate(data['base'], env)
        assert isinstance(value, Bits)
        result = Bits(0, 0)
        for item in data.get('slices', data.get('indices')):
            form, bounds = next(iter(item.items()))
            if form == 'Single':
                low = high = number(evaluate(bounds, env))
            elif form == 'Range':
                low = number(evaluate(bounds['lo'], env))
                high = number(evaluate(bounds['hi'], env))
            else:
                raise ValueError(('dependent slice', form))
            assert 0 <= low <= high < value.width, (low, high, value)
            width = high - low + 1
            result = Bits((result.value << width) | ((value.value >> low) & ((1 << width) - 1)),
                          result.width + width)
        return result
    raise ValueError(('dependent expression', kind))


class Reject(Exception):
    pass


def execute(statements, env):
    for statement in statements:
        if statement == 'Undefined':
            raise Reject()
        kind, data = next(iter(statement.items()))
        if kind == 'See':
            raise Reject()
        if kind == 'VarsDecl':
            for name in data['names']:
                env.pop(name, None)
        elif kind in ('Assign', 'VarDeclInit', 'ConstDecl'):
            name = data['target']['Var']['name'] if kind == 'Assign' else data['name']
            env[name] = evaluate(data['value'], env)
        elif kind == 'If':
            for condition, body in data['branches']:
                if evaluate(condition, env):
                    execute(body, env)
                    break
            else:
                execute(data['else_body'] or [], env)
        elif kind == 'Case':
            value = evaluate(data['expr'], env)
            for alt in data['alts']:
                hits = alt['patterns'] is None or any(match(value, evaluate(
                    {'LitBits' if 'Bits' in pat else 'LitMask': next(iter(pat.values()))}, env))
                    for pat in alt['patterns'])
                if hits and (alt['guard'] is None or evaluate(alt['guard'], env)):
                    execute(alt['body'], env)
                    break
            else:
                raise ValueError(('uncovered case input', value))
        else:
            raise ValueError(('sliced statement', kind))



def enumerate_encoding(enc):
    """Enumerate every assignment of every instruction bit reaching rejection."""
    code, needed = slice_block(enc['decode'], set())
    fields = {f['name']: (f['begin'], f['width']) for f in enc['fields']}
    unknown = needed - fields.keys()
    if unknown:
        raise ValueError((enc['name'], 'runtime/unknown dependency', unknown))
    pattern = ''.join({'Zero': '0', 'One': '1', 'Either': 'x'}[x] for x in enc['opcode'])
    mask = int(''.join('0' if x == 'x' else '1' for x in pattern), 2)
    base = int(pattern.replace('x', '0'), 2)
    positions = sorted({b for n in needed for b in range(fields[n][0], sum(fields[n]))
                        if not mask & (1 << b)})
    if len(positions) > 16:
        raise ValueError((enc['name'], 'unqualified enumeration width', positions))
    accepted = []
    for value in range(1 << len(positions)):
        word = base | sum(((value >> j) & 1) << bit for j, bit in enumerate(positions))
        env = {n: Bits((word >> low) & ((1 << width) - 1), width)
               for n, (low, width) in fields.items()}
        try:
            execute(code, env)
        except Reject:
            continue
        except Exception as error:
            raise ValueError((enc['name'], hex(word), error)) from error
        accepted.append(word)
    return dict(name=enc['name'], mask=mask, value=base, needed=sorted(needed),
                positions=positions, assignments=1 << len(positions),
                accepted=accepted)
