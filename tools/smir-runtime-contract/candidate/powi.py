"""Full-width signed powi sequence oracle; pure FP callbacks return (bits, flags)."""
from .errors import require


def evaluate(value, exponent, width, *, one, multiply, divide):
    require(type(width) is int and width>=1 and type(exponent) is int and
            -(1<<(width-1))<=exponent<(1<<(width-1)), 'RT_POWI_EXPONENT')
    remaining=abs(exponent)
    result,flags=one,0
    # Only operations selected by this sequence execute. In particular no final
    # unused square, unchosen product, or reciprocal for nonnegative exponent.
    while remaining:
        if remaining&1:
            result,raised=multiply(result,value)
            flags|=raised
        remaining>>=1
        if remaining:
            value,raised=multiply(value,value)
            flags|=raised
    if exponent<0:
        result,raised=divide(one,result)
        flags|=raised
    return result,flags
