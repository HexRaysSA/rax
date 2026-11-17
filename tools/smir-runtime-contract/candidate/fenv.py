"""INT-010 revision2 C23 source environment, separate from VM diagnostics."""
from dataclasses import dataclass, replace
import struct

from .errors import Reject, require

FLAGS = {'divide_by_zero': 1, 'inexact': 2, 'invalid': 4, 'overflow': 8,
         'underflow': 16, 'denorm': 32}
ROUNDS = {0: 'nearest_even', 0x400: 'downward', 0x800: 'upward', 0xc00: 'toward_zero'}
PRIORITY = ['invalid', 'divide_by_zero', 'overflow', 'underflow', 'inexact']
ENV = struct.Struct('<IIIIQQ')
MODE = struct.Struct('<IIQ')


class Diagnostic(Reject):
    def __init__(self, cause):
        self.cause = cause
        super().__init__('RT_FP_DIAGNOSTIC', cause)


def mask(value):
    require(type(value) is int and 0 <= value <= 63, 'RT_FENV_MASK')
    return value


@dataclass
class Environment:
    rounding: int = 0
    flags: int = 0

    def check(self):
        require(type(self.rounding) is int and self.rounding in ROUNDS, 'RT_FENV_ROUND')
        mask(self.flags)
        return self

    def encode(self):
        self.check()
        return ENV.pack(1, self.rounding, self.flags, 0, 0, 0)

    def mode(self):
        self.check()
        return MODE.pack(self.rounding, 0, 0)

    @classmethod
    def decode(cls, payload):
        require(type(payload) is bytes and len(payload) == ENV.size, 'RT_FENV_EXTENT')
        revision, rounding, flags, traps, control, reserved = ENV.unpack(payload)
        require(revision == 1 and traps == control == reserved == 0, 'RT_FENV_RESERVED')
        return cls(rounding, flags).check()


class Fenv:
    def __init__(self, environment=None, diagnostic_mask=0):
        self.environment = replace(environment) if environment else Environment()
        self.environment.check()
        require(type(diagnostic_mask) is int and 0 <= diagnostic_mask <= 31, 'RT_FP_POLICY')
        self.diagnostic_mask = diagnostic_mask
        self.errno = 0

    def _diagnose(self, raised):
        enabled = raised & self.diagnostic_mask
        for name in PRIORITY:
            if enabled & FLAGS[name]:
                raise Diagnostic(name)

    def getenv(self):
        return self.environment.encode()

    def setenv(self, payload):
        proposed = Environment.decode(payload)
        self.environment = proposed
        # Source restore never changes private diagnostic policy or raises flags.

    def set_snapshot(self, payload, contract='default'):
        proposed = Environment.decode(payload)
        require(contract in {'default', 'mode_only'}, 'RT_FENV_CONTRACT')
        if contract == 'mode_only':
            self.environment.rounding = proposed.rounding
        else:
            self.environment = proposed

    def word(self, mode_only=False):
        return self.environment.rounding | (0 if mode_only else self.environment.flags)

    def set_word(self, value, mode_only=False):
        require(type(value) is int and 0 <= value < 2**64 and
                value & ~(0xc00 if mode_only else 0xc3f) == 0, 'RT_FENV_WORD')
        proposed = Environment(value & 0xc00, value & 63).encode()
        self.set_snapshot(proposed, 'mode_only' if mode_only else 'default')

    def rounding_code(self):
        return {0xc00: 0, 0: 1, 0x800: 2, 0x400: 3}[self.environment.rounding]

    def set_rounding_code(self, value):
        require(type(value) is int and value in {0, 1, 2, 3}, 'RT_FENV_AMBIENT_ROUNDING')
        self.environment.rounding = {0: 0xc00, 1: 0, 2: 0x800, 3: 0x400}[value]

    def getmode(self):
        return self.environment.mode()

    def setmode(self, payload):
        require(type(payload) is bytes and len(payload) == MODE.size, 'RT_FENV_EXTENT')
        rounding, traps, control = MODE.unpack(payload)
        require(traps == control == 0, 'RT_FENV_RESERVED')
        proposed = Environment(rounding, self.environment.flags).check()
        self.environment = proposed

    def hold(self, writer):
        # Writer must preflight/commit the complete32-B guest destination. Its
        # failure occurs before the source environment can be changed.
        previous = self.getenv()
        writer(previous)
        self.environment.flags = 0
        return previous

    def update(self, payload):
        proposed = Environment.decode(payload)
        prior = self.environment.flags
        self.environment = proposed
        self.raise_flags(prior)

    def test(self, selected):
        return self.environment.flags & mask(selected)

    def clear(self, selected):
        self.environment.flags &= ~mask(selected)

    def set_flags(self, value, selected):
        mask(value)
        mask(selected)
        self.environment.flags = ((self.environment.flags & ~selected) | (value & selected))

    def setexcept(self, selected):
        self.environment.flags |= mask(selected)

    def raise_flags(self, selected):
        self.environment.flags |= mask(selected)
        self._diagnose(selected)  # DENORM deliberately absent from diagnostic map.

    def arithmetic(self, result, raised, mode='constrained'):
        require(mode in {'llvm_default', 'constrained', 'c_fenv'}, 'RT_FP_MODE')
        require(type(raised) is int and 0 <= raised <= 31, 'RT_FP_ARITHMETIC_FLAGS')
        if mode != 'llvm_default':
            self.environment.flags |= raised
            self._diagnose(raised)
        return result

    def wrapper(self, operation, *arguments):
        """C integer return wrapper; validation failure=1, errno preserved.

        Guest memory faults and configured VM diagnostics are not C return errors
        and are propagated by their separate checked-memory/diagnostic path.
        """
        original_errno = self.errno
        try:
            getattr(self, operation)(*arguments)
        except Diagnostic:
            raise
        except Reject:
            return 1
        finally:
            self.errno = original_errno
        return 0


DEFAULT_ENV = Environment().encode()
DEFAULT_MODE = Environment().mode()
# These bytes initialize ordinary readonly __rax_default_fenv/femode guest data
# symbols. No address, sentinel or host pointer gets special access authority.
