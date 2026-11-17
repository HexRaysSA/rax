"""Exact rational oracle for the proposed binary floating-point core.

No host floating-point arithmetic or host fenv participates. This is a local
draft witness, not a hosted-library implementation or production FP admission.
"""
from dataclasses import dataclass
from fractions import Fraction

from common import HEX, require

FORMATS = {'binary16': (5, 10), 'bfloat16': (8, 7), 'binary32': (8, 23),
           'binary64': (11, 52), 'binary128': (15, 112)}
ROUNDING = {'nearest_even', 'nearest_away', 'toward_zero', 'upward', 'downward'}
STATUS = {'invalid', 'divide_by_zero', 'overflow', 'underflow', 'inexact'}
ARITY = {'add': 2, 'sub': 2, 'mul': 2, 'div': 2, 'fma': 3,
         'neg': 1, 'abs': 1, 'copysign': 2}


def scale2(value, exponent):
    return value * (1 << exponent) if exponent >= 0 else value / (1 << -exponent)


@dataclass(frozen=True)
class Decoded:
    bits: int
    sign: int
    kind: str
    value: Fraction = Fraction(0)
    signaling: bool = False


def decode(bits, exponent_bits, fraction_bits):
    sign = bits >> (exponent_bits + fraction_bits)
    exponent = (bits >> fraction_bits) & ((1 << exponent_bits) - 1)
    fraction = bits & ((1 << fraction_bits) - 1)
    if exponent == (1 << exponent_bits) - 1:
        return Decoded(bits, sign, 'inf' if fraction == 0 else 'nan',
                       signaling=bool(fraction and not (fraction & (1 << (fraction_bits - 1)))))
    bias = (1 << (exponent_bits - 1)) - 1
    significand = fraction if exponent == 0 else (1 << fraction_bits) + fraction
    magnitude = scale2(Fraction(significand), (exponent or 1) - bias - fraction_bits)
    return Decoded(bits, sign, 'finite', -magnitude if sign else magnitude)


def round_integer(value, mode, sign):
    quotient, remainder = divmod(value.numerator, value.denominator)
    increment = False
    if remainder:
        if mode in {'nearest_even', 'nearest_away'}:
            twice = 2 * remainder
            increment = (twice > value.denominator or
                         (twice == value.denominator and (mode == 'nearest_away' or quotient & 1)))
        elif mode == 'upward':
            increment = not sign
        elif mode == 'downward':
            increment = bool(sign)
    return quotient + int(increment), bool(remainder)


def round_finite(value, zero_sign, exponent_bits, fraction_bits, mode):
    """Correctly round an exact rational with tininess detected after rounding."""
    sign = int(value < 0) if value else zero_sign
    sign_bit = sign << (exponent_bits + fraction_bits)
    if not value:
        return sign_bit, set()
    magnitude = abs(value)
    bias = (1 << (exponent_bits - 1)) - 1
    minimum_exponent = 1 - bias
    maximum_exponent = bias
    exponent = magnitude.numerator.bit_length() - magnitude.denominator.bit_length()
    if magnitude < scale2(Fraction(1), exponent):
        exponent -= 1
    quantum_exponent = max(exponent, minimum_exponent) - fraction_bits
    significand, inexact = round_integer(scale2(magnitude, -quantum_exponent), mode, sign)
    if significand >= 1 << (fraction_bits + 1):
        exponent += 1
        significand >>= 1
    if exponent > maximum_exponent:
        infinity = (mode in {'nearest_even', 'nearest_away'}
                    or (mode == 'upward' and not sign) or (mode == 'downward' and sign))
        magnitude_bits = (((1 << exponent_bits) - 1) << fraction_bits if infinity else
                          (((1 << exponent_bits) - 2) << fraction_bits) | ((1 << fraction_bits) - 1))
        return sign_bit | magnitude_bits, {'overflow', 'inexact'}
    flags = {'inexact'} if inexact else set()
    if significand < 1 << fraction_bits:
        if inexact:
            flags.add('underflow')
        return sign_bit | significand, flags
    # Rounding a subnormal up to the minimum normal must not signal underflow.
    encoded_exponent = max(exponent, minimum_exponent) + bias
    return sign_bit | (encoded_exponent << fraction_bits) | (significand - (1 << fraction_bits)), flags


def evaluate(request):
    require(isinstance(request, dict) and set(request) == {
        'revision', 'format', 'op', 'operands', 'mode', 'rounding', 'environment'}, 'fp_shape')
    require(request['revision'] == 'binary_fp_draft_v1', 'fp_revision')
    for key, allowed in [('format', FORMATS), ('op', ARITY),
                         ('mode', {'default', 'constrained'}), ('rounding', ROUNDING | {'dynamic'})]:
        require(isinstance(request[key], str) and request[key] in allowed, 'fp_shape', key)
    env = request['environment']
    require(isinstance(env, dict) and set(env) == {'rounding', 'flags', 'traps'}, 'fp_shape', 'environment')
    require(isinstance(env['rounding'], str) and env['rounding'] in ROUNDING, 'fp_shape', 'rounding')
    require(isinstance(env['flags'], list) and all(isinstance(flag, str) for flag in env['flags'])
            and env['flags'] == sorted(set(env['flags'])) and set(env['flags']) <= STATUS,
            'fp_shape', 'flags')
    require(env['traps'] == [], 'fp_capability', 'enabled FP traps not admitted')
    require(request['mode'] != 'default' or request['rounding'] == 'nearest_even',
            'fp_environment', 'default mode fixed nearest-even')
    exponent_bits, fraction_bits = FORMATS[request['format']]
    size = (1 + exponent_bits + fraction_bits) // 8
    raw = request['operands']
    require(isinstance(raw, list) and len(raw) == ARITY[request['op']], 'fp_shape', 'arity')
    require(all(isinstance(item, str) and len(item) == 2 * size and HEX.fullmatch(item)
                for item in raw), 'fp_shape', 'raw bits')
    values = [decode(int.from_bytes(bytes.fromhex(item), 'little'), exponent_bits, fraction_bits)
              for item in raw]
    op = request['op']
    mode = ('nearest_even' if request['mode'] == 'default' else
            env['rounding'] if request['rounding'] == 'dynamic' else request['rounding'])
    sign_mask = 1 << (exponent_bits + fraction_bits)
    infinity = ((1 << exponent_bits) - 1) << fraction_bits
    preferred_nan = infinity | (1 << (fraction_bits - 1))
    flags = set()
    result = None
    if op in {'neg', 'abs', 'copysign'}:
        result = (values[0].bits ^ sign_mask if op == 'neg' else
                  values[0].bits & ~sign_mask if op == 'abs' else
                  (values[0].bits & ~sign_mask) | (values[1].sign * sign_mask))
    else:
        if any(value.signaling for value in values):
            flags.add('invalid')
        a, b = values[:2]
        product_invalid = (op in {'mul', 'fma'} and
                           ((a.kind == 'inf' and b.kind == 'finite' and b.value == 0)
                            or (b.kind == 'inf' and a.kind == 'finite' and a.value == 0)))
        if product_invalid:
            flags.add('invalid')
        nan = next((value for value in values if value.kind == 'nan'), None)
        if nan is not None:
            result = nan.bits | (1 << (fraction_bits - 1))
        elif product_invalid:
            result = preferred_nan
        elif op in {'add', 'sub'}:
            bsign = b.sign ^ int(op == 'sub')
            if a.kind == 'inf' or b.kind == 'inf':
                if a.kind == b.kind == 'inf' and a.sign != bsign:
                    result, flags = preferred_nan, flags | {'invalid'}
                else:
                    result = infinity | ((a.sign if a.kind == 'inf' else bsign) * sign_mask)
            else:
                exact = a.value + (b.value if op == 'add' else -b.value)
                zero_sign = a.sign if a.value == b.value == 0 and a.sign == bsign else int(mode == 'downward')
                result, rounded = round_finite(exact, zero_sign, exponent_bits, fraction_bits, mode)
                flags |= rounded
        elif op in {'mul', 'div'}:
            sign = a.sign ^ b.sign
            if op == 'div' and ((a.kind == b.kind == 'inf')
                                or (a.kind == b.kind == 'finite' and a.value == b.value == 0)):
                result, flags = preferred_nan, flags | {'invalid'}
            elif a.kind == 'inf' or (op == 'mul' and b.kind == 'inf'):
                result = infinity | sign * sign_mask
            elif op == 'div' and b.kind == 'inf':
                result = sign * sign_mask
            elif op == 'div' and b.value == 0:
                result, flags = infinity | sign * sign_mask, flags | {'divide_by_zero'}
            else:
                exact = a.value * b.value if op == 'mul' else a.value / b.value
                result, rounded = round_finite(exact, sign, exponent_bits, fraction_bits, mode)
                flags |= rounded
        elif op == 'fma':
            c = values[2]
            product_sign = a.sign ^ b.sign
            if a.kind == 'inf' or b.kind == 'inf':
                if c.kind == 'inf' and c.sign != product_sign:
                    result, flags = preferred_nan, flags | {'invalid'}
                else:
                    result = infinity | product_sign * sign_mask
            elif c.kind == 'inf':
                result = c.bits
            else:
                product = a.value * b.value
                exact = product + c.value
                zero_sign = (product_sign if product == c.value == 0 and product_sign == c.sign
                             else int(mode == 'downward'))
                result, rounded = round_finite(exact, zero_sign, exponent_bits, fraction_bits, mode)
                flags |= rounded
    retained = set(env['flags'])
    if request['mode'] == 'constrained':
        retained |= flags
    return {'bits': result.to_bytes(size, 'little').hex(), 'flags': sorted(retained)}
