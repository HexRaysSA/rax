"""Arbitrary-storage-width atomic reference with exact byte/shadow transactions.

This is a serial schedule oracle, independent of production RAX and native
lock-free claims. The independent C++ witness checks arithmetic and flag progress.
"""
from dataclasses import dataclass

from .errors import require, uint

ORDERS = {0: 'relaxed', 1: 'acquire', 2: 'acquire', 3: 'release',
          4: 'acq_rel', 5: 'seq_cst'}
FAILURE_ORDERS = {0, 1, 2, 5}
RMW = {'add', 'sub', 'and', 'or', 'xor', 'nand', 'smin', 'smax', 'umin', 'umax',
       'uinc_wrap', 'udec_wrap', 'usub_cond', 'usub_sat'}


@dataclass(frozen=True)
class Transfer:
    bits: bytes
    poison: bytes
    undef: bytes
    origins: tuple = ()

    def check(self, size=None):
        require(type(self.bits) is bytes and type(self.poison) is bytes and
                type(self.undef) is bytes, 'RT_TRANSFER_BYTES')
        require(len(self.bits) == len(self.poison) == len(self.undef) and
                (size is None or len(self.bits) == size), 'RT_TRANSFER_EXTENT')
        require(all(not (p & u) for p, u in zip(self.poison, self.undef)), 'RT_SHADOW_OVERLAP')
        return self

    @classmethod
    def concrete(cls, bits):
        return cls(bits, bytes(len(bits)), bytes(len(bits)))

    def refinement(self):
        return int.from_bytes(bytes(b & ~(p | u) for b, p, u in
                                    zip(self.bits, self.poison, self.undef)), 'little')


class Atomics:
    def __init__(self, maximum_bytes=1048576):
        uint(maximum_bytes)
        require(maximum_bytes > 0, 'RT_ATOMIC_QUOTA')
        self.maximum_bytes = maximum_bytes
        self.cells = {}
        self.sequence = 0
        self.events = []

    def register(self, backing, offset, value, alignment=1):
        value.check()
        require(value.bits and len(value.bits) <= self.maximum_bytes, 'RT_ATOMIC_QUOTA')
        uint(offset)
        require(type(alignment) is int and alignment > 0 and alignment & (alignment - 1) == 0
                and offset % alignment == 0, 'RT_ATOMIC_ALIGNMENT')
        key = (backing, offset)
        require(key not in self.cells, 'RT_ATOMIC_EXISTS')
        require(all(backing != b or offset + len(value.bits) <= at or
                    at + len(other.bits) <= offset
                    for (b, at), other in self.cells.items()), 'RT_ATOMIC_OVERLAP')
        self.cells[key] = value
        return key

    def _admit(self, key, kind, order, failure=None, scope='process'):
        require(key in self.cells, 'RT_ATOMIC_UNMAPPED')
        require(type(order) is int and order in ORDERS, 'RT_ATOMIC_ORDER')
        require(scope in {'process', 'system', 'singlethread'}, 'RT_ATOMIC_SCOPE')
        if kind == 'load':
            require(order in {0, 1, 2, 5}, 'RT_ATOMIC_LOAD_ORDER')
        elif kind == 'store':
            require(order in {0, 3, 5}, 'RT_ATOMIC_STORE_ORDER')
        if kind == 'compare_exchange':
            require(type(failure) is int and failure in FAILURE_ORDERS, 'RT_ATOMIC_FAILURE_ORDER')
        else:
            require(failure is None, 'RT_ATOMIC_FAILURE_ORDER')
        return self.cells[key]

    def _commit(self, key, kind, order, written):
        self.sequence += 1
        self.events.append((self.sequence, key, kind, ORDERS[order], written))

    def load(self, key, order, scope='process'):
        old = self._admit(key, 'load', order, scope=scope)
        self._commit(key, 'load', order, False)
        return old

    def store(self, key, desired, order, scope='process'):
        old = self._admit(key, 'store', order, scope=scope)
        desired.check(len(old.bits))
        self.cells[key] = desired
        self._commit(key, 'store', order, True)

    def exchange(self, key, desired, order, scope='process'):
        old = self._admit(key, 'exchange', order, scope=scope)
        desired.check(len(old.bits))
        self.cells[key] = desired
        self._commit(key, 'exchange', order, True)
        return old

    def compare_exchange(self, key, expected, desired, order, failure, *, mask=None,
                         weak=False, scope='process'):
        old = self._admit(key, 'compare_exchange', order, failure, scope)
        expected.check(len(old.bits))
        desired.check(len(old.bits))
        require(type(weak) is bool, 'RT_ATOMIC_WEAK')
        mask = bytes([255]) * len(old.bits) if mask is None else mask
        require(type(mask) is bytes and len(mask) == len(old.bits), 'RT_ATOMIC_MASK')
        compare = int.from_bytes(mask, 'little')
        success = old.refinement() & compare == expected.refinement() & compare
        if success:
            self.cells[key] = desired
        self._commit(key, 'compare_exchange', order if success else failure, success)
        return old, success

    def rmw(self, key, operation, operand, order, *, precision=None, scope='process'):
        old = self._admit(key, 'rmw', order, scope=scope)
        require(operation in RMW, 'RT_ATOMIC_RMW')
        operand.check(len(old.bits))
        width = len(old.bits) * 8 if precision is None else precision
        require(type(width) is int and 0 < width <= len(old.bits) * 8, 'RT_ATOMIC_PRECISION')
        mask = (1 << width) - 1
        a, b = old.refinement() & mask, operand.refinement() & mask
        signed = lambda n: n - (1 << width) if n & (1 << (width - 1)) else n
        if operation == 'add': result = a + b
        elif operation == 'sub': result = a - b
        elif operation == 'and': result = a & b
        elif operation == 'or': result = a | b
        elif operation == 'xor': result = a ^ b
        elif operation == 'nand': result = ~(a & b)
        elif operation == 'smin': result = a if signed(a) < signed(b) else b
        elif operation == 'smax': result = a if signed(a) > signed(b) else b
        elif operation == 'umin': result = min(a, b)
        elif operation == 'umax': result = max(a, b)
        elif operation == 'uinc_wrap': result = 0 if a >= b else a + 1
        elif operation == 'udec_wrap': result = b if a == 0 or a > b else a - 1
        elif operation == 'usub_cond': result = a - b if a >= b else a
        else: result = max(a - b, 0)
        poisoned = (int.from_bytes(old.poison, 'little') |
                    int.from_bytes(operand.poison, 'little')) & mask != 0
        bits = (result & mask).to_bytes(len(old.bits), 'little')
        shadow = mask.to_bytes(len(old.bits), 'little') if poisoned else bytes(len(old.bits))
        self.cells[key] = Transfer(bits, shadow, bytes(len(old.bits)))
        self._commit(key, 'rmw', order, True)
        return old

    def fence(self, order, scope='process'):
        require(type(order) is int and order in {0, 1, 2, 3, 4, 5}, 'RT_ATOMIC_FENCE_ORDER')
        require(scope in {'process', 'system', 'singlethread'}, 'RT_ATOMIC_SCOPE')
        if order == 0:return
        self._commit(None, 'fence', order, False)

    def rmw_float(self, key, operation, operand, order, *, kernel, environment,
                  mode='llvm_default', scope='process'):
        """Pure FP kernel supplies exact bits/flags; one atomic result frontier.

        On enabled diagnostic only sticky flags commit; memory and observed SSA
        result remain before the operation. No retry/replay has occurred.
        """
        old = self._admit(key, 'rmw', order, scope=scope)
        require(operation in {'fadd', 'fsub', 'fmax', 'fmin', 'fmaximum', 'fminimum',
                              'fmaximumnum', 'fminimumnum'}, 'RT_ATOMIC_RMW')
        operand.check(len(old.bits))
        if any(old.poison) or any(operand.poison):
            desired = Transfer(bytes(len(old.bits)), bytes([255]) * len(old.bits), bytes(len(old.bits)))
        else:
            bits, flags = kernel(operation, old.refinement(), operand.refinement())
            require(type(bits) is int and 0 <= bits < 1 << (8 * len(old.bits)), 'RT_ATOMIC_FP_BITS')
            environment.arithmetic(bits, flags, mode)
            desired = Transfer.concrete(bits.to_bytes(len(old.bits), 'little'))
        self.cells[key] = desired
        self._commit(key, 'rmw_float', order, True)
        return old

    @staticmethod
    def is_lock_free(size, address):
        uint(size)
        uint(address)
        return False
