"""Independent mathematical witnesses, isolated from RAX and LLVM execution."""
from dataclasses import dataclass


class ContractError(ValueError):
    pass


class ImmediateUB(ContractError):
    pass


@dataclass(frozen=True)
class Value:
    width: int
    bits: int = 0
    kind: str = 'concrete'

    def __post_init__(self):
        if type(self.width) is not int or not 1 <= self.width <= 65535:
            raise ContractError('E-WIDTH')
        if self.kind not in ('concrete', 'poison', 'undef'):
            raise ContractError('E-VALUE')
        if type(self.bits) is not int or not 0 <= self.bits < 1 << self.width:
            raise ContractError('E-BITS')

    @property
    def signed(self):
        sign = 1 << (self.width - 1)
        return self.bits - (1 << self.width) if self.bits & sign else self.bits

    def refine_undef(self):
        return Value(self.width) if self.kind == 'undef' else self

    def freeze(self):
        return Value(self.width) if self.kind != 'concrete' else self

    def output(self):
        return {'kind': self.kind, 'width': self.width, 'bits': self.bits}


def binary(op, left, right, flags=()):
    if left.width != right.width:
        raise ContractError('E-TYPE')
    allowed = {
        'add': {'nuw', 'nsw'}, 'sub': {'nuw', 'nsw'}, 'mul': {'nuw', 'nsw'},
        'shl': {'nuw', 'nsw'}, 'lshr': {'exact'}, 'ashr': {'exact'},
        'udiv': {'exact'}, 'sdiv': {'exact'}, 'urem': set(), 'srem': set(),
        'and': set(), 'or': {'disjoint'}, 'xor': set(),
    }
    if op not in allowed or len(flags) != len(set(flags)) or set(flags) - allowed[op]:
        raise ContractError('E-OP-FLAGS')
    left, right = left.refine_undef(), right.refine_undef()
    w = left.width
    mask = (1 << w) - 1
    poison = Value(w, kind='poison')
    # Immediate UB in the divisor precedes ordinary deferred-poison transfer.
    if op in ('udiv', 'sdiv', 'urem', 'srem'):
        if right.kind == 'poison' or right.bits == 0:
            raise ImmediateUB('UB-DIVISOR')
        if op in ('sdiv', 'srem') and right.signed == -1:
            if left.kind == 'poison' or left.signed == -(1 << (w - 1)):
                raise ImmediateUB('UB-SIGNED-DIVISION')
    if left.kind == 'poison' or right.kind == 'poison':
        return poison
    a, b = left.bits, right.bits
    sa, sb = left.signed, right.signed
    if op in ('shl', 'lshr', 'ashr') and b >= w:
        return poison
    if op in ('add', 'sub', 'mul', 'shl'):
        if op == 'add':
            result, signed_result = a + b, sa + sb
        elif op == 'sub':
            result, signed_result = a - b, sa - sb
        elif op == 'mul':
            result, signed_result = a * b, sa * sb
        else:
            result, signed_result = a << b, sa << b
        if 'nuw' in flags and not 0 <= result <= mask:
            return poison
        if 'nsw' in flags and not -(1 << (w - 1)) <= signed_result < 1 << (w - 1):
            return poison
    elif op in ('lshr', 'ashr'):
        if 'exact' in flags and a & ((1 << b) - 1):
            return poison
        result = a >> b if op == 'lshr' else sa >> b
    elif op in ('udiv', 'urem'):
        quotient, remainder = divmod(a, b)
        if 'exact' in flags and remainder:
            return poison
        result = quotient if op == 'udiv' else remainder
    elif op in ('sdiv', 'srem'):
        quotient = abs(sa) // abs(sb)
        if (sa < 0) != (sb < 0):
            quotient = -quotient
        remainder = sa - quotient * sb
        if 'exact' in flags and remainder:
            return poison
        result = quotient if op == 'sdiv' else remainder
    elif op == 'and':
        result = a & b
    elif op == 'or':
        if 'disjoint' in flags and a & b:
            return poison
        result = a | b
    else:
        result = a ^ b
    return Value(w, result & mask)


def select(condition, when_true, when_false):
    if condition.width != 1 or when_true.width != when_false.width:
        raise ContractError('E-TYPE')
    if condition.kind == 'poison':
        return Value(when_true.width, kind='poison')
    condition = condition.refine_undef()
    return (when_true if condition.bits else when_false).refine_undef()


def branch(condition):
    if condition.width != 1:
        raise ContractError('E-TYPE')
    if condition.kind != 'concrete':
        raise ImmediateUB('UB-BRANCH')
    return condition.bits != 0


def align_up(size, alignment):
    return (size + alignment - 1) // alignment * alignment


def checked_size(size):
    if size > (1 << 64) - 1:
        raise ContractError('E-LAYOUT-SIZE')
    return size


def layout(ty):
    """Independent subset of candidate LLVM DataLayout; sizes in bytes.

    Returns (allocation size, ABI alignment, field offsets). It describes LLVM
    storage, not Clang source _BitInt layout. Unsized/scalable/raw-byte reject.
    """
    if type(ty) is not dict or len(ty) != 1:
        raise ContractError('E-LAYOUT-TYPE')
    kind, value = next(iter(ty.items()))
    if kind == 'int':
        if type(value) is not int or not 1 <= value <= 65535:
            raise ContractError('E-LAYOUT-WIDTH')
        # Smallest explicit integer alignment >= width, else largest entry.
        bits = next((n for n in (1, 8, 16, 32, 64, 128) if n >= value), 128)
        alignment = max(1, bits // 8)
        return align_up((value + 7) // 8, alignment), alignment, []
    if kind == 'float':
        if value not in (16, 32, 64, 128):
            raise ContractError('E-LAYOUT-FLOAT')
        return value // 8, value // 8, []
    if kind == 'ptr':
        if type(value) is not int or value != 0:
            raise ContractError('E-ADDRESS-SPACE')
        return 8, 8, []
    if kind == 'array':
        if type(value) is not list or len(value) != 2:
            raise ContractError('E-LAYOUT-ARRAY')
        count, element = value
        if type(count) is not int or not 0 <= count <= (1 << 32) - 1:
            raise ContractError('E-LAYOUT-COUNT')
        size, alignment, _ = layout(element)
        return checked_size(count * size), alignment, []
    if kind == 'vector':
        if type(value) is not list or len(value) != 2:
            raise ContractError('E-LAYOUT-VECTOR')
        count, element = value
        if type(count) is not int or not 1 <= count <= 64:
            raise ContractError('E-LAYOUT-COUNT')
        if type(element) is not dict or list(element) not in (['int'], ['float']):
            raise ContractError('E-LAYOUT-VECTOR-ELEMENT')
        width = next(iter(element.values()))
        layout(element)  # Validate the scalar element.
        store_size = (count * width + 7) // 8
        alignment = 1 << (store_size - 1).bit_length()
        return align_up(store_size, alignment), alignment, []
    if kind in ('struct', 'packed'):
        if type(value) is not list:
            raise ContractError('E-LAYOUT-STRUCT')
        cursor, alignment, offsets = 0, 1, []
        for field in value:
            size, field_align, _ = layout(field)
            if kind == 'packed':
                field_align = 1
            cursor = align_up(cursor, field_align)
            offsets.append(cursor)
            cursor = checked_size(cursor + size)
            alignment = max(alignment, field_align)
        return checked_size(align_up(cursor, alignment)), alignment, offsets
    raise ContractError('E-LAYOUT-UNSUPPORTED')


def llvm_type(ty):
    kind, value = next(iter(ty.items()))
    if kind == 'int':
        return f'i{value}'
    if kind == 'float':
        return {16: 'half', 32: 'float', 64: 'double', 128: 'fp128'}[value]
    if kind == 'ptr':
        return 'ptr'
    if kind == 'array':
        return f'[{value[0]} x {llvm_type(value[1])}]'
    if kind == 'vector':
        return f'<{value[0]} x {llvm_type(value[1])}>'
    fields = ', '.join(llvm_type(field) for field in value)
    return '<{ ' + fields + ' }>' if kind == 'packed' else '{ ' + fields + ' }'
