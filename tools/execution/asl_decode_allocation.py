"""Derive A64 allocation from pinned primary decode ASTs.

Legacy feature predicates describe structural allocation. Explicit Boolean
parameters model selected modern profiles. Unknown dependent constructs stop
generation rather than becoming implicit support.
"""
import dataclasses

HAVE = {
    'HaveFP16MulNoRoundingToFP32Ext', 'HaveFP16Ext', 'HaveSM3Ext',
    'HaveSHA1Ext', 'HaveDOTPExt', 'HaveFCADDExt', 'HaveAESExt',
    'HaveQRDMLAHExt', 'HaveSM4Ext', 'HaveSHA3Ext', 'HaveFrintExt',
    'HaveFJCVTZSExt', 'HaveSHA256Ext', 'HaveSHA512Ext',
    'HaveBit128PMULLExt',
    'HaveSVE',
}

# Only calls with qualified nonthrowing contracts may disappear with a dead
# result. DecodeBitMasks is deliberately separate: its UNDEFINED conditions
# are observable even when neither returned mask reaches a later condition.
PURE_CALLS = {
    'UInt', 'SInt', 'Int', 'LowestSetBit', 'HighestSetBit', 'HighestSetBitNZ',
    'FPOne', 'FPPointFive', 'FPTwo', 'FPRoundingMode', 'VFPExpandImm', 'FPCR',
    # Qualified A64 callers use two-bit rounding modes, bounded bit strings
    # and nonnegative replication counts. AdvSIMDExpandImm's reserved case
    # is specific to AArch32; this module derives A64 allocation only.
    'FPDecodeRounding', 'AdvSIMDExpandImm', 'Replicate', 'Zeros',
    'IsFeatureImplemented',
}


def variables(value):
    if isinstance(value, list):
        return set().union(*(variables(x) for x in value)) if value else set()
    if not isinstance(value, dict):
        return set()
    if 'Var' in value:
        return {value['Var']['name']} - {'TRUE', 'FALSE'}
    return set().union(*(variables(x) for x in value.values()))


def assignment_names(target):
    if target == 'Ignore':
        return set()
    if isinstance(target, dict) and 'Var' in target:
        return {target['Var']['name']}
    if isinstance(target, dict) and 'Tuple' in target:
        return set().union(*(assignment_names(x) for x in target['Tuple']))
    raise ValueError(('unqualified assignment target', target))


def may_reject(value):
    if isinstance(value, list):
        return any(may_reject(x) for x in value)
    if not isinstance(value, dict):
        return False
    if 'Call' in value:
        call = value['Call']
        name = call['name']['name']
        if name not in HAVE | PURE_CALLS | {'DecodeBitMasks'}:
            raise ValueError(('unqualified call effect', name))
        nested = any(may_reject(x) for x in call['args'])
        return name == 'DecodeBitMasks' or nested
    return any(may_reject(x) for x in value.values())


def declared_widths(statements):
    widths = {}
    constants = {}
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        kind, value = next(iter(statement.items()))
        if kind == 'ConstDecl' and 'LitInt' in value.get('value', {}):
            constants[value['name']] = value['value']['LitInt']
        if kind not in ('VarsDecl', 'VarDeclInit', 'ConstDecl'):
            continue
        ty = value.get('ty', {}).get('Fun', {})
        argument = ty.get('arg', {})
        width = argument.get('LitInt', constants.get(argument.get('Var', {}).get('name')))
        if ty.get('name') == 'bits' and width is not None:
            for name in value.get('names', [value.get('name')]):
                widths[name] = width
    return widths


def slice_block(statements, needed):
    needed = set(needed)
    kept = []
    widths = declared_widths(statements)
    for statement in reversed(statements):
        if isinstance(statement, str):
            assert statement == 'Undefined', statement
            kept.append(statement)
            continue
        kind, value = next(iter(statement.items()))
        if kind == 'See':
            kept.append(statement)
        elif kind in ('Assign', 'VarDeclInit', 'ConstDecl'):
            names = assignment_names(value['target']) if kind == 'Assign' else {value['name']}
            rejects = may_reject(value['value'])
            if names.intersection(needed) or rejects:
                needed.difference_update(names)
                needed |= variables(value['value'])
                call = value['value'].get('Call', {})
                if call.get('name', {}).get('name') == 'DecodeBitMasks':
                    # The qualified primary SVE call has a declared bits(64)
                    # destination. Do not guess an implicit generic width.
                    result_widths = {widths.get(name) for name in names}
                    if result_widths != {64}:
                        raise ValueError(('unqualified DecodeBitMasks width', result_widths))
                    call = dict(call, result_width=64)
                    value = dict(value, value={'Call': call})
                    statement = {kind: value}
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
    if kind == 'InSet':
        # The qualified SVE decode clauses use literal singleton masks such
        # as size IN {'0x'}. Other set element forms need their own contract.
        elements = data['elements']
        if any(not isinstance(item, dict) or set(item) != {'Single'}
               for item in elements):
            raise ValueError(('unqualified set element', elements))
        value = evaluate(data['expr'], env)
        return any(match(value, evaluate(item['Single'], env)) for item in elements)
    if kind == 'Call':
        name = data['name']['name']
        if name in HAVE:
            assert not data['args']
            return True
        args = [evaluate(arg, env) for arg in data['args']]
        if name == 'IsFeatureImplemented':
            if len(args) != 1 or not (isinstance(args[0], bool)
                    or isinstance(args[0], Bits) and args[0].width == 1):
                raise ValueError('unqualified feature predicate argument')
            return bool(number(args[0]))
        if name == 'UInt':
            assert len(args) == 1
            return number(args[0])
        if name == 'DecodeBitMasks':
            if data.get('result_width') != 64 or len(args) != 4:
                raise ValueError('unqualified DecodeBitMasks call')
            imm_n, imms, immr, immediate = args
            if not (isinstance(imm_n, Bits) and imm_n.width == 1
                    and isinstance(imms, Bits) and imms.width == 6
                    and isinstance(immr, Bits) and immr.width == 6
                    and isinstance(immediate, bool)):
                raise ValueError('unqualified DecodeBitMasks argument types')
            length = ((imm_n.value << 6) | (~imms.value & 63)).bit_length() - 1
            if length < 1:
                raise Reject()
            levels = (1 << length) - 1
            s, r = imms.value & levels, immr.value & levels
            if immediate and s == levels:
                raise Reject()
            size = 1 << length
            element = (1 << (s + 1)) - 1
            element = ((element >> r) | (element << (size - r))) & ((1 << size) - 1)
            top = (1 << (((s - r) & levels) + 1)) - 1
            wmask = sum(element << offset for offset in range(0, 64, size))
            tmask = sum(top << offset for offset in range(0, 64, size))
            return Bits(wmask, 64), Bits(tmask, 64)
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
            if isinstance(value, Bits):
                return Bits(value.value ^ ((1 << value.width) - 1), value.width)
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


def assign(target, value, env):
    if target == 'Ignore':
        return
    if isinstance(target, dict) and 'Var' in target:
        env[target['Var']['name']] = value
        return
    if isinstance(target, dict) and 'Tuple' in target:
        targets = target['Tuple']
        if not isinstance(value, tuple) or len(targets) != len(value):
            raise ValueError('unqualified tuple assignment shape')
        for item, part in zip(targets, value):
            assign(item, part, env)
        return
    raise ValueError(('unqualified assignment target', target))


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
            target = data['target'] if kind == 'Assign' else {'Var': {'name': data['name']}}
            assign(target, evaluate(data['value'], env), env)
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



def enumerate_encoding(enc, *, constants=None, parameters=None):
    """Enumerate every assignment of every instruction bit reaching rejection."""
    if enc.get('iset', 'A64') != 'A64':
        raise ValueError('unqualified non-A64 decode context')
    code, needed = slice_block(enc['decode'], set())
    fields = {f['name']: (f['begin'], f['width']) for f in enc['fields']}
    constants = constants or {}
    parameters = parameters or {}
    if fields.keys() & parameters.keys() or (fields.keys() | parameters.keys()) & constants.keys():
        raise ValueError('overlapping decode fields, parameters or constants')
    positions_used = [low for low, width in parameters.values()]
    if (any(not 32 <= low < 64 or width != 1 for low, width in parameters.values())
            or len(set(positions_used)) != len(positions_used)):
        raise ValueError('unqualified Boolean parameter layout')
    fields |= parameters
    unknown = needed - fields.keys() - constants.keys()
    if unknown:
        raise ValueError((enc['name'], 'runtime/unknown dependency', unknown))
    pattern = ''.join({'Zero': '0', 'One': '1', 'Either': 'x'}[x] for x in enc['opcode'])
    mask = int(''.join('0' if x == 'x' else '1' for x in pattern), 2)
    base = int(pattern.replace('x', '0'), 2)
    positions = sorted({b for n in needed - constants.keys()
                        for b in range(fields[n][0], sum(fields[n]))
                        if not mask & (1 << b)})
    if len(positions) > 16:
        raise ValueError((enc['name'], 'unqualified enumeration width', positions))
    accepted = []
    for value in range(1 << len(positions)):
        word = base | sum(((value >> j) & 1) << bit for j, bit in enumerate(positions))
        env = {n: Bits((word >> low) & ((1 << width) - 1), width)
               for n, (low, width) in fields.items()}
        env.update(constants)
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
