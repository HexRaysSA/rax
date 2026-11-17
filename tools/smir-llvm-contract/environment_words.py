"""LLVM-CC027 target-private integer FP environments, not C source storage."""
from canonical import require

ROUND = {'nearest_even':0, 'downward':0x400, 'upward':0x800, 'toward_zero':0xC00}
FLT_ROUNDS = {'toward_zero':0, 'nearest_even':1, 'upward':2, 'downward':3}


def word(value, width=64):
    require(width == 64, 'E-LLVM-ENV-WIDTH')
    require(type(value) is int and 0 <= value < 2**64, 'LLVM_ENV_WORD')
    return value


def encode(rounding, flags=0, *, mode=False, width=64):
    require(rounding in ROUND and type(flags) is int and 0 <= flags <= 63, 'LLVM_ENV_VALUE')
    return word(ROUND[rounding] | (0 if mode else flags), width)


def decode(value, *, mode=False, width=64):
    value=word(value,width)
    require(value & ~(0xC00 if mode else 0xC3F) == 0, 'LLVM_ENV_RESERVED')
    rounding=next(name for name,bits in ROUND.items() if bits == value & 0xC00)
    return rounding, (0 if mode else value & 63)


def get_rounding(rounding):
    require(rounding in FLT_ROUNDS,'LLVM_ENV_ROUNDING')
    return FLT_ROUNDS[rounding]


def set_rounding(code):
    require(type(code) is int and code in FLT_ROUNDS.values(), 'E-LLVM-AMBIENT-ROUNDING')
    return next(name for name,value in FLT_ROUNDS.items() if value==code)


def restore(state, value, *, mode=False):
    """Reference single commit. Validation happens before returning new state.

    Immutable (rounding,flags) is guest state only; private diagnostic policy is
    outside this value. Caller retains original tuple unchanged on rejection.
    """
    rounding, flags=decode(value,mode=mode)
    return rounding, state[1] if mode else flags
