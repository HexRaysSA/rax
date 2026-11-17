"""INT-010 revision2 lossless C23 source snapshots, separate from VM policy."""
import struct

from common import require
from candidate.raw import Raw

FLAG_CODES = {'divide_by_zero': 1, 'inexact': 2, 'invalid': 4, 'overflow': 8, 'underflow': 16, 'denormal': 32}
ROUND_CODES = {'nearest_even': 0, 'downward': 0x400, 'upward': 0x800, 'toward_zero': 0xc00}


def mask(flags):
    require(type(flags) is list and flags == sorted(set(flags)) and set(flags) <= set(FLAG_CODES), 'fenv_flags')
    return sum(FLAG_CODES[flag] for flag in flags)


def names(bits):
    require(type(bits) is int and 0 <= bits <= 63, 'fenv_mask')
    return sorted(flag for flag, code in FLAG_CODES.items() if bits & code)


def pack(environment):
    require(type(environment) is dict and set(environment) == {'rounding', 'flags', 'traps'}
            and environment['rounding'] in ROUND_CODES and environment['traps'] == [], 'fenv_snapshot')
    return struct.pack('<IIIIQQ', 1, ROUND_CODES[environment['rounding']], mask(environment['flags']), 0, 0, 0)


def unpack(data):
    require(type(data) is bytes and len(data) == 32, 'fenv_extent')
    revision, rounding, sticky, traps, control, reserved = struct.unpack('<IIIIQQ', data)
    require(revision == 1 and rounding in ROUND_CODES.values() and sticky <= 63
            and traps == control == reserved == 0, 'fenv_snapshot')
    return {'rounding': next(name for name, code in ROUND_CODES.items() if code == rounding),
            'flags': names(sticky), 'traps': []}


def word(environment, mode_only=False):
    pack(environment)  # Validate the entire source snapshot before projection.
    return ROUND_CODES[environment['rounding']] | (0 if mode_only else mask(environment['flags']))


def from_word(bits, mode_only=False):
    allowed = 0xc00 if mode_only else 0xc3f
    require(type(bits) is int and 0 <= bits < 2**64 and not bits & ~allowed, 'invalid_fenv')
    rounding = next(name for name, code in ROUND_CODES.items() if code == bits & 0xc00)
    return {'rounding': rounding, 'flags': [] if mode_only else names(bits & 63), 'traps': []}


def set_snapshot(machine, snapshot, mode_only=False):
    pack(snapshot)
    if mode_only:
        # Preserve CURRENT flags at the commit frontier, not a stale snapshot.
        machine.environment['rounding'] = snapshot['rounding']
    else:
        from copy import deepcopy
        machine.environment = deepcopy(snapshot)


def get_rounding(environment):
    pack(environment)
    return {'toward_zero': 0, 'nearest_even': 1, 'upward': 2, 'downward': 3}[environment['rounding']]


def rounding_snapshot(code):
    require(type(code) is int and code in {0, 1, 2, 3}, 'invalid_fenv')
    return {'rounding': {0: 'toward_zero', 1: 'nearest_even', 2: 'upward', 3: 'downward'}[code],
            'flags': [], 'traps': []}


class SourceFenv:
    """Logical C API adapter with ordinary guarded memory and failure atomicity.

    Invalid argument/snapshot returns nonzero without errno/state changes. Memory
    access faults stay guest memory faults. VM diagnostic policy is never saved,
    cleared or restored by these source APIs.
    """
    def __init__(self, machine):
        self.machine = machine

    def read(self, pointer, size, alignment):
        raw = self.machine.memory.raw_load(pointer, size, alignment)
        # Select zero per undef bit; poison source object is invalid snapshot.
        if raw.poison:
            return None
        return (raw.bits & ~raw.undef).to_bytes(size, 'little')

    def write(self, pointer, data, alignment):
        self.machine.memory.raw_store(pointer, Raw.integer(8 * len(data), int.from_bytes(data, 'little')), alignment)

    def getenv(self, pointer, hold=False):
        self.machine.memory.guard(pointer, 32, 8)
        data = pack(self.machine.environment)
        self.write(pointer, data, 8)
        if hold:
            self.machine.environment['flags'] = []
        return 0

    def setenv(self, pointer, update=False):
        data = self.read(pointer, 32, 8)
        if data is None:
            return 1
        from common import Reject
        try:
            environment = unpack(data)
        except Reject:
            return 1
        raised = set(self.machine.environment['flags']) if update else set()
        self.machine.environment = environment
        if update:
            self.machine.fp_commit({'environment': 'constrained', 'exceptions': 'strict'}, raised)
        return 0

    def getmode(self, pointer):
        self.machine.memory.guard(pointer, 16, 8)
        data = struct.pack('<IIQ', ROUND_CODES[self.machine.environment['rounding']], 0, 0)
        self.write(pointer, data, 8)
        return 0

    def setmode(self, pointer):
        data = self.read(pointer, 16, 8)
        if data is None:
            return 1
        rounding, traps, control = struct.unpack('<IIQ', data)
        if rounding not in ROUND_CODES.values() or traps or control:
            return 1
        self.machine.environment['rounding'] = next(name for name, code in ROUND_CODES.items() if code == rounding)
        return 0

    def setround(self, code):
        if type(code) is not int or code not in ROUND_CODES.values():
            return 1
        self.machine.environment['rounding'] = next(name for name, value in ROUND_CODES.items() if value == code)
        return 0

    def flag_operation(self, action, selected, value=0):
        if type(selected) is not int or not 0 <= selected <= 63 or type(value) is not int or not 0 <= value <= 63:
            return 1
        current = mask(self.machine.environment['flags'])
        if action == 'test':
            return current & selected
        if action == 'clear':
            current &= ~selected
        elif action == 'setflag':
            current = (current & ~selected) | (value & selected)
        elif action in {'set', 'raise'}:
            current |= selected
        else:
            raise ValueError('unknown source fenv action')
        self.machine.environment['flags'] = names(current)
        if action == 'raise':
            self.machine.fp_commit({'environment': 'constrained', 'exceptions': 'strict'}, set(names(selected)))
        return 0
