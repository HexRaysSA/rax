"""Independent rounding/classification edges from pinned LLVM LangRef."""
from fractions import Fraction

from canonical import require
from reference import Value


def round_integer(value, mode):
    require(isinstance(value, Fraction), 'FP_EXACT_VALUE')
    numerator, denominator = value.numerator, value.denominator
    floor, remainder = divmod(numerator, denominator)
    if mode == 'downward':
        return floor
    if mode == 'upward':
        return floor + bool(remainder)
    if mode == 'toward_zero':
        return -((-numerator) // denominator) if numerator < 0 else numerator // denominator
    require(mode in ('nearest_even', 'nearest_away'), 'FP_ROUNDING')
    if 2 * remainder < denominator:
        return floor
    if 2 * remainder > denominator:
        return floor + 1
    if mode == 'nearest_even':
        return floor if floor % 2 == 0 else floor + 1
    return floor if numerator < 0 else floor + 1


def to_integer(value, width, *, signed=True, operation='fptosi', rounding='nearest_even'):
    """Returns value and mathematically raised flags; fenv commit is separate.

    l[r]int/lround overflow is a concrete freeze(poison) refinement, not poison.
    Ordinary fptosi/ui preserves deferred poison on nonrepresentability.
    """
    require(type(width) is int and 1 <= width <= 65535, 'FP_INT_WIDTH')
    require(operation in ('fptosi','fptoui','lrint','llrint','lround','llround','saturating'), 'FP_INT_OPERATION')
    minimum = -(1 << (width - 1)) if signed else 0
    maximum = (1 << (width - (1 if signed else 0))) - 1
    finite = isinstance(value, Fraction)
    if finite:
        mode = ('nearest_away' if operation in ('lround','llround') else
                rounding if operation in ('lrint','llrint') else 'toward_zero')
        integer = round_integer(value, mode)
        invalid = not minimum <= integer <= maximum
    else:
        require(value in ('nan','+inf','-inf'), 'FP_EXACT_VALUE')
        invalid = True
        integer = 0
    if invalid:
        if operation == 'saturating':
            integer = (0 if value == 'nan' else minimum if value == '-inf' else
                       maximum if value == '+inf' else min(max(integer, minimum), maximum))
            return Value(width, integer % (1 << width)), set()
        if operation in ('lrint','llrint','lround','llround'):
            return Value(width), {'invalid'}
        return Value(width, kind='poison'), {'invalid'}
    flags = {'inexact'} if value != integer and operation not in ('lround','llround') else set()
    return Value(width, integer % (1 << width)), flags


def fpclass(bits, exponent_bits, fraction_bits, mask):
    """Ten LLVM FPClassTest bit positions, no host FP or signaling NaN use."""
    width = 1 + exponent_bits + fraction_bits
    require(type(bits) is int and 0 <= bits < 1 << width, 'FP_BITS')
    require(type(mask) is int and 0 <= mask <= 0x3ff, 'FP_CLASS_MASK')
    sign = bits >> (width - 1)
    fraction = bits & ((1 << fraction_bits) - 1)
    exponent = (bits >> fraction_bits) & ((1 << exponent_bits) - 1)
    if exponent == (1 << exponent_bits) - 1:
        if fraction:
            kind = 0x002 if fraction & (1 << (fraction_bits - 1)) else 0x001
        else:
            kind = 0x004 if sign else 0x200
    elif exponent == 0:
        kind = (0x010 if sign else 0x080) if fraction else (0x020 if sign else 0x040)
    else:
        kind = 0x008 if sign else 0x100
    return bool(kind & mask)
