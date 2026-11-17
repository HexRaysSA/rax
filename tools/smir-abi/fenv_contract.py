"""Exact portable saved FP environment; independent of host fenv macros/state."""

import struct

from layout import ABIError, require

FE = {'divide_by_zero': 1, 'inexact': 2, 'invalid': 4, 'overflow': 8,
      'underflow': 16, 'denorm': 32}
ALL = 63
ROUND = {'nearest_even': 0, 'downward': 0x400, 'upward': 0x800, 'toward_zero': 0xc00}
ENV = struct.Struct('<IIIIQQ')
MODE = struct.Struct('<IIQ')
DEFAULT_ENV = ENV.pack(1, 0, 0, 0, 0, 0)
DEFAULT_MODE = MODE.pack(0, 0, 0)
PRIORITY = ['invalid', 'divide_by_zero', 'overflow', 'underflow', 'inexact']


class FEnvTrap(ABIError):
    def __init__(self, cause):
        self.cause = cause
        super().__init__('ABI_CC_FENV_TRAP:' + cause)


def mask(value):
    require(type(value) is int and 0 <= value <= ALL, 'ABI_CC_FENV_MASK')
    return value


class Environment:
    @property
    def diagnostic_policy(self):
        return self._diagnostic_policy

    @diagnostic_policy.setter
    def diagnostic_policy(self, value):
        require(type(value) is int and 0 <= value <= 31, 'ABI_CC_FENV_DIAGNOSTIC_MASK')
        self._diagnostic_policy = value

    def __init__(self):
        self.round = 0
        self.flags = 0
        self.diagnostic_policy = 0

    def get_env(self):
        return ENV.pack(1, self.round, self.flags, 0, 0, 0)

    def set_env(self, snapshot):
        require(isinstance(snapshot, bytes) and len(snapshot) == ENV.size, 'ABI_CC_FENV_SNAPSHOT')
        version, rounding, flags, traps, control, reserved = ENV.unpack(snapshot)
        require(version == 1 and rounding in ROUND.values() and traps == control == reserved == 0,
                'ABI_CC_FENV_CONTROL')
        mask(flags)
        self.round, self.flags = rounding, flags

    def get_mode(self):
        return MODE.pack(self.round, 0, 0)

    def set_mode(self, snapshot):
        require(isinstance(snapshot, bytes) and len(snapshot) == MODE.size, 'ABI_CC_FENV_SNAPSHOT')
        rounding, traps, reserved = MODE.unpack(snapshot)
        require(rounding in ROUND.values() and traps == reserved == 0, 'ABI_CC_FENV_CONTROL')
        self.round = rounding

    def test(self, selected):
        return self.flags & mask(selected)

    def clear(self, selected):
        self.flags &= ~mask(selected)

    def raise_flags(self, selected):
        self.flags |= mask(selected)
        self._trap(selected)

    def set_except(self, selected):
        self.flags |= mask(selected)

    def _trap(self, raised):
        for name in PRIORITY:
            if self.diagnostic_policy & raised & FE[name]:
                raise FEnvTrap(name)

    def set_flags(self, value, selected):
        value, selected = mask(value), mask(selected)
        self.flags = (self.flags & ~selected) | (value & selected)

    def arithmetic_flags(self, names):
        require(set(names) <= FE.keys() - {'denorm'}, 'ABI_CC_FENV_ARITHMETIC_FLAG')
        raised = sum(FE[name] for name in set(names))
        self.flags |= raised
        self._trap(raised)

    def hold(self):
        snapshot = self.get_env()
        self.flags = 0
        return snapshot

    def update(self, snapshot):
        raised = self.flags
        self.set_env(snapshot)
        self.raise_flags(raised)
