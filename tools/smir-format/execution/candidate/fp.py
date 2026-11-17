"""Complete scalar binary FP core: exact sqrt/remainder/conversion mathematics."""
from fractions import Fraction
from math import isqrt

from common import require
from floating import FORMATS, decode, evaluate, round_finite, scale2


def integer_round(operation, format_name, bits, width, rounding='nearest_even'):
    """One atomic lrint/lround contract; no intermediate FP environment effects."""
    require(operation in {'lrint', 'llrint', 'lround', 'llround'} and 1 <= width <= 2**23,
            'fp_integer_round')
    value = decode(bits, *FORMATS[format_name])
    if value.kind != 'finite':
        return 0, {'invalid'}
    selected = 'nearest_away' if operation in {'lround', 'llround'} else rounding
    magnitude = abs(value.value)
    integer, remainder = divmod(magnitude.numerator, magnitude.denominator)
    if remainder:
        if selected in {'nearest_even', 'nearest_away'}:
            difference = 2 * remainder - magnitude.denominator
            integer += difference > 0 or (difference == 0 and (selected == 'nearest_away' or integer & 1))
        elif (selected == 'upward' and value.value > 0) or (selected == 'downward' and value.value < 0):
            integer += 1
    result = -integer if value.value < 0 else integer
    if not -(1 << (width - 1)) <= result < 1 << (width - 1):
        return 0, {'invalid'}
    flags = {'inexact'} if operation in {'lrint', 'llrint'} and value.value != result else set()
    return result % (1 << width), flags


def powi(format_name, base, exponent_bits, width, rounding='nearest_even', max_steps=100000):
    """Executed-step sequence, including full-width signed MIN magnitude.

    Returns result, union of flags and step names. Flags are data until the
    caller performs its single source-operation commit/diagnostic frontier.
    """
    require(1 <= width <= 2**23 and 0 <= exponent_bits < 1 << width, 'fp_powi_exponent')
    exponent = exponent_bits - (1 << width) if exponent_bits >> (width - 1) else exponent_bits
    magnitude = abs(exponent)
    require(magnitude.bit_length() * 2 + 1 <= max_steps, 'reference_resource', 'powi steps')
    ebits, fbits = FORMATS[format_name]
    one = ((1 << (ebits - 1)) - 1) << fbits
    result, current, flags, steps = one, base, set(), []
    while magnitude:
        if magnitude & 1:
            result, raised = scalar('mul', format_name, [format_name, format_name], [result, current], rounding)
            flags |= raised
            steps.append('multiply')
        magnitude >>= 1
        if magnitude:
            current, raised = scalar('mul', format_name, [format_name, format_name], [current, current], rounding)
            flags |= raised
            steps.append('square')
    if exponent < 0:
        result, raised = scalar('div', format_name, [format_name, format_name], [one, result], rounding)
        flags |= raised
        steps.append('reciprocal')
    return result, flags, steps


def sqrt_finite(value, exponent_bits, fraction_bits, rounding):
    if not value:
        return 0, set()
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < scale2(Fraction(1), exponent):
        exponent -= 1
    exponent //= 2
    bias = (1 << (exponent_bits - 1)) - 1
    quantum = max(exponent, 1 - bias) - fraction_bits
    scaled = scale2(value, -2 * quantum)
    floor = isqrt(scaled.numerator // scaled.denominator)
    exact = floor * floor * scaled.denominator == scaled.numerator
    rounded = floor
    if not exact:
        if rounding in {'nearest_even', 'nearest_away'}:
            difference = 4 * scaled.numerator - scaled.denominator * (2 * floor + 1)**2
            if difference > 0 or (difference == 0 and (rounding == 'nearest_away' or floor & 1)):
                rounded += 1
        elif rounding == 'upward':
            rounded += 1
    bits, flags = round_finite(scale2(Fraction(rounded), quantum), 0,
                               exponent_bits, fraction_bits, 'nearest_even')
    if not exact:
        flags.add('inexact')
        if bits >> fraction_bits == 0:
            flags.add('underflow')
    return bits, flags


def scalar(operation, destination, source_formats, values, rounding='nearest_even'):
    """Return (raw result bits or None for poison, newly raised exception set).

    destination is float-format name or integer bit width. Integer conversions
    use source bits and operation signedness. Environment commit/trap ordering
    is handled by the coherent evaluator, never the host fenv.
    """
    if operation in {'sitofp', 'uitofp'}:
        source_width = source_formats[0]
        integer = values[0]
        if operation == 'sitofp' and integer & (1 << (source_width - 1)):
            integer -= 1 << source_width
        return round_finite(Fraction(integer), 0, *FORMATS[destination], rounding)
    source_format = source_formats[0]
    ebits, fbits = FORMATS[source_format]
    decoded = [decode(value, *FORMATS[fmt]) for value, fmt in zip(values, source_formats)]
    a = decoded[0]
    if operation in {'minimum', 'maximum', 'minnum', 'maxnum', 'minimumnum', 'maximumnum'}:
        b = decoded[1]
        flags = {'invalid'} if a.signaling or b.signaling else set()
        if a.kind == 'nan' or b.kind == 'nan':
            if operation in {'minimum', 'maximum'} or a.kind == b.kind == 'nan':
                nan = a if a.kind == 'nan' else b
                return nan.bits | (1 << (fbits - 1)), flags
            return (b.bits if a.kind == 'nan' else a.bits), flags
        maximum = operation.startswith('max')
        if a.kind == b.kind == 'finite' and a.value == b.value == 0:
            return (a.bits & b.bits if maximum else a.bits | b.bits), flags
        rank = lambda value: (-1 if value.sign else 1, 0) if value.kind == 'inf' else (0, value.value)
        take_a = rank(a) >= rank(b) if maximum else rank(a) <= rank(b)
        return (a.bits if take_a else b.bits), flags
    if operation in {'fptosi', 'fptoui', 'fptosi_sat', 'fptoui_sat'}:
        signed = operation in {'fptosi', 'fptosi_sat'}
        minimum = -(1 << (destination - 1)) if signed else 0
        maximum = (1 << (destination - int(signed))) - 1
        saturated = operation.endswith('_sat')
        if a.kind == 'finite':
            magnitude = abs(a.value.numerator) // a.value.denominator
            result = -magnitude if a.value < 0 else magnitude
            if minimum <= result <= maximum:
                return result & ((1 << destination) - 1), {'inexact'} if a.value != result else set()
        elif a.kind == 'nan':
            return (0, set()) if saturated else (None, {'invalid'})
        else:
            result = minimum - 1 if a.sign else maximum + 1
        if saturated:
            return min(max(result, minimum), maximum) & ((1 << destination) - 1), set()
        return None, {'invalid'}
    if operation == 'fpconvert':
        de, df = FORMATS[destination]
        if a.kind == 'inf':
            return (a.sign << (de + df)) | (((1 << de) - 1) << df), set()
        if a.kind == 'nan':
            payload = values[0] & ((1 << (fbits - 1)) - 1)
            payload = payload >> (fbits - df) if fbits >= df else payload << (df - fbits)
            bits = (a.sign << (de + df)) | (((1 << de) - 1) << df) | (1 << (df - 1)) | payload
            return bits, {'invalid'} if a.signaling else set()
        return round_finite(a.value, a.sign, de, df, rounding)
    if operation in {'sqrt', 'frem'}:
        flags = {'invalid'} if any(value.signaling for value in decoded) else set()
        infinity = ((1 << ebits) - 1) << fbits
        preferred_nan = infinity | (1 << (fbits - 1))
        nan = next((value for value in decoded if value.kind == 'nan'), None)
        if nan:
            return nan.bits | (1 << (fbits - 1)), flags
        if operation == 'sqrt':
            if a.sign and (a.kind == 'inf' or a.value < 0):
                return preferred_nan, {'invalid'}
            if a.kind == 'inf' or a.value == 0:
                return a.bits, flags
            bits, raised = sqrt_finite(a.value, ebits, fbits, rounding)
            return bits, flags | raised
        b = decoded[1]
        if a.kind == 'inf' or (b.kind == 'finite' and b.value == 0):
            return preferred_nan, {'invalid'}
        if b.kind == 'inf' or a.value == 0:
            return a.bits, flags
        quotient = abs(a.value / b.value)
        quotient = quotient.numerator // quotient.denominator
        if (a.value < 0) != (b.value < 0):
            quotient = -quotient
        bits, raised = round_finite(a.value - quotient * b.value, a.sign, ebits, fbits, rounding)
        return bits, flags | raised
    require(destination == source_format and all(fmt == source_format for fmt in source_formats), 'fp_types')
    raw = [value.to_bytes((1 + ebits + fbits) // 8, 'little').hex() for value in values]
    result = evaluate({'revision': 'binary_fp_draft_v1', 'format': source_format, 'op': operation,
                       'operands': raw, 'mode': 'constrained', 'rounding': rounding,
                       'environment': {'rounding': rounding, 'flags': [], 'traps': []}})
    return int.from_bytes(bytes.fromhex(result['bits']), 'little'), set(result['flags'])


def compare(predicate, signaling, format_name, left, right):
    a, b = decode(left, *FORMATS[format_name]), decode(right, *FORMATS[format_name])
    unordered = a.kind == 'nan' or b.kind == 'nan'
    flags = {'invalid'} if a.signaling or b.signaling or (signaling and unordered) else set()
    rank = lambda value: (-1 if value.sign else 1, 0) if value.kind == 'inf' else (0, value.value)
    if predicate == 'false':
        result = False
    elif predicate == 'true':
        result = True
    elif predicate == 'ord':
        result = not unordered
    elif predicate == 'uno':
        result = unordered
    else:
        relation = predicate[1:]
        ordered = False
        if not unordered:
            av, bv = rank(a), rank(b)
            ordered = {'eq': av == bv, 'ne': av != bv, 'lt': av < bv,
                       'le': av <= bv, 'gt': av > bv, 'ge': av >= bv}[relation]
        result = unordered if predicate.startswith('u') and unordered else ordered
    return int(result), flags
