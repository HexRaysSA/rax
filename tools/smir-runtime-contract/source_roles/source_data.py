"""S-PROD014REV2 process-local source syntax, quotas and checked bounded reads.

Load this exact file once as ``_rax_smir_source_data_v1``. The producer owns
charged schema/root capture and namespace/storage checks. These records neither
issue private Rust facts nor authorize execution, relocation or native access.
Counters use exact mathematical integers; source offsets remain u64 byte counts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import chain, repeat
from sys import maxsize as _HOST_SIZE_MAX
from threading import Lock as _Lock
from typing import Callable, TypeAlias


class SourceDataError(ValueError):
    """Stable reference error; kind/code/detail cannot change after issuance."""
    __slots__ = ('_kind', '_code', '_detail')

    def __init__(self, kind: str, code: str, detail: str = ''):
        if hasattr(self, '_kind'):
            raise AttributeError('immutable source-data error')
        if kind not in ('semantic', 'unavailable', 'resource') or \
                type(code) is not str or type(detail) is not str:
            raise ValueError('invalid SourceDataError construction')
        object.__setattr__(self, '_kind', kind)
        object.__setattr__(self, '_code', code)
        object.__setattr__(self, '_detail', detail)
        super().__init__(code + (': ' + detail if detail else ''))

    def __setattr__(self, name, value):
        if name in ('kind', 'code', 'detail', '_kind', '_code', '_detail'):
            raise AttributeError('immutable source-data error')
        super().__setattr__(name, value)

    def __str__(self):
        return self._code + (': ' + self._detail if self._detail else '')

    @property
    def kind(self):
        return self._kind

    @property
    def code(self):
        return self._code

    @property
    def detail(self):
        return self._detail


def _fail(kind, code, detail=''):
    raise SourceDataError(kind, code, detail)


def _nonnegative(value):
    return type(value) is int and value >= 0


class SourceQueryBudget:
    """One non-resettable ledger; concurrent charges commit all dimensions.

    Units are logical work, graph/container edges and new payload bytes, not
    processor instructions or allocator capacity. max_depth bounds producer
    traversal and must be enforced before descent by the charged producer.
    """
    __slots__ = ('_max_work', '_max_edges', '_max_copied_bytes', '_max_depth',
                 '_used_work', '_used_edges', '_used_copied_bytes', '_charge_lock')

    def __init__(self, *, max_work, max_edges, max_copied_bytes, max_depth):
        if hasattr(self, '_max_work'):
            _fail('resource', 'SOURCE_DATA_BUDGET', 'ledger already initialized')
        if not all(_nonnegative(n) for n in
                   (max_work, max_edges, max_copied_bytes, max_depth)) or \
                not 1 <= max_depth <= 128:
            _fail('resource', 'SOURCE_DATA_BUDGET')
        object.__setattr__(self, '_charge_lock', _Lock())
        for name, value in (('_max_work', max_work), ('_max_edges', max_edges),
                            ('_max_copied_bytes', max_copied_bytes),
                            ('_max_depth', max_depth), ('_used_work', 0),
                            ('_used_edges', 0), ('_used_copied_bytes', 0)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError('source-data budget has no reset or policy mutation')

    def __delattr__(self, name):
        raise AttributeError('source-data budget has no reset or policy mutation')

    @property
    def max_work(self):
        return self._max_work

    @property
    def max_edges(self):
        return self._max_edges

    @property
    def max_copied_bytes(self):
        return self._max_copied_bytes

    @property
    def max_depth(self):
        return self._max_depth

    def charge(self, *, work=0, edges=0, copied_bytes=0):
        if not all(_nonnegative(n) for n in (work, edges, copied_bytes)):
            _fail('resource', 'SOURCE_DATA_BUDGET')
        # Exact sums cannot wrap. The innermost lock covers every read, check
        # and store; no source traversal or user callback runs while it is held.
        with self._charge_lock:
            next_work = self._used_work + work
            next_edges = self._used_edges + edges
            next_bytes = self._used_copied_bytes + copied_bytes
            if next_work > self._max_work or next_edges > self._max_edges or \
                    next_bytes > self._max_copied_bytes:
                _fail('resource', 'SOURCE_DATA_RESOURCE')
            object.__setattr__(self, '_used_work', next_work)
            object.__setattr__(self, '_used_edges', next_edges)
            object.__setattr__(self, '_used_copied_bytes', next_bytes)

    def work(self, n):
        self.charge(work=n)

    def edges(self, n):
        self.charge(edges=n)

    def reserve_bytes(self, n):
        self.charge(copied_bytes=n)


Ref: TypeAlias = tuple[str, int] | tuple[str, int, int]


@dataclass(frozen=True, slots=True)
class FrozenRecord:
    # Construction/freezing is producer-charged. No hidden recursive walk.
    fields: tuple[tuple[str, FrozenWire], ...]

    def field(self, name: str) -> FrozenWire:
        if type(name) is not str or type(self.fields) is not tuple:
            _fail('semantic', 'SOURCE_DATA_RECORD')
        found = False
        result = None
        for row in self.fields:
            if type(row) is not tuple or len(row) != 2 or type(row[0]) is not str:
                _fail('semantic', 'SOURCE_DATA_RECORD')
            if row[0] == name:
                if found or type(row[1]) not in (type(None), bool, int, str,
                                               tuple, FrozenRecord):
                    _fail('semantic', 'SOURCE_DATA_RECORD')
                found, result = True, row[1]
        if not found:
            _fail('semantic', 'SOURCE_DATA_RECORD', name)
        return result


FrozenWire: TypeAlias = None | bool | int | str | tuple['FrozenWire', ...] | FrozenRecord


@dataclass(frozen=True, slots=True)
class SourceStamp:
    context_anchor: object
    schema_digest: bytes
    root_digests: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True, slots=True)
class DependencyOwner:
    slot: int
    key: FrozenRecord
    minimum_minor: int
    maximum_minor: int | None
    site: bytes


@dataclass(frozen=True, slots=True)
class DeclaredPatch:
    tag: str
    source_kind: str
    source: Ref
    ordinal: int
    start: int
    end: int
    record: FrozenRecord


@dataclass(frozen=True, slots=True)
class DependencySourceData:
    tag: str
    stamp: SourceStamp
    symbol: Ref
    owner: DependencyOwner
    slot: int
    declaration: int
    offset: int
    length: int
    expected: FrozenRecord


@dataclass(frozen=True, slots=True, init=False)
class LocalSourceData:
    tag: str
    stamp: SourceStamp
    symbol: Ref
    symbol_record: FrozenRecord
    storage: Ref
    offset: int
    length: int
    symbol_extent: int
    backing_extent: int
    symbol_alignment: int
    backing_alignment: int
    prefix: memoryview
    zero_tail_bytes: int
    patches: tuple[DeclaredPatch, ...]
    _budget: SourceQueryBudget = field(repr=False, compare=False)
    _check_snapshot: Callable[..., None] = field(repr=False, compare=False)

    def __new__(cls, *args, **kwargs):
        raise TypeError('LocalSourceData requires the checked producer SPI')

    def read(self, relative_offset, length, *, budget):
        if budget is not self._budget:
            _fail('semantic', 'SOURCE_DATA_CONTEXT')
        budget.work(16)
        self._check_snapshot(stamp=self.stamp, budget=budget)
        if not _u64(relative_offset) or not _u64(length) or \
                relative_offset + length > (1 << 64) - 1 or \
                relative_offset + length > self.length:
            _fail('semantic', 'RT_METADATA_EXTENT')
        # Charge before payload allocation; temporary views/iterators are edges.
        budget.charge(work=length, copied_bytes=length)
        if length > _HOST_SIZE_MAX:
            _fail('resource', 'SOURCE_DATA_RESOURCE', 'result exceeds host byte size')
        prefix_length = min(length, max(0, len(self.prefix) - relative_offset))
        try:
            if prefix_length == 0:
                return bytes(length)
            if prefix_length == length:
                budget.edges(1)
                return self.prefix[relative_offset:relative_offset + length].tobytes()
            budget.edges(4)  # subview, its iterator, zero iterator, chain
            return bytes(chain(self.prefix[relative_offset:relative_offset + prefix_length],
                               repeat(0, length - prefix_length)))
        except (MemoryError, OverflowError) as error:
            # Only bounded output construction is translated; snapshot errors
            # and unrelated producer/programming exceptions are not caught.
            raise SourceDataError('resource', 'SOURCE_DATA_RESOURCE',
                                  'host byte allocation unavailable') from error


def _u64(value):
    return type(value) is int and 0 <= value < (1 << 64)


def _self_ref(value):
    return type(value) is tuple and len(value) == 2 and type(value[0]) is str and \
        value[0] == 'self' and \
        type(value[1]) is int and 0 <= value[1] < (1 << 32)


def _make_local_source_data(*, stamp, symbol, symbol_record, storage, offset,
                            length, symbol_extent, backing_extent,
                            symbol_alignment, backing_alignment, prefix,
                            zero_tail_bytes, patches, budget, check_snapshot):
    """Accepted reader SPI. Caller has already checked/captured actual source.

    Fixed structural work only; no deep prefix/patch/snapshot scan at work32.
    The retained bound callback verifies original context/schema/roots on reads.
    """
    if type(budget) is not SourceQueryBudget:
        _fail('resource', 'SOURCE_DATA_BUDGET')
    budget.charge(work=32, edges=1)
    if type(stamp) is not SourceStamp or not _self_ref(symbol) or \
            not _self_ref(storage) or type(symbol_record) is not FrozenRecord or \
            type(patches) is not tuple or not callable(check_snapshot) or \
            not all(_u64(n) for n in (offset, length, symbol_extent,
                                     backing_extent, symbol_alignment,
                                     backing_alignment, zero_tail_bytes)) or \
            length == 0 or offset + length > (1 << 64) - 1 or \
            offset + length > backing_extent or symbol_extent != backing_extent:
        _fail('semantic', 'SOURCE_DATA_RECORD')
    if type(prefix) is not memoryview or not prefix.readonly or \
            prefix.ndim != 1 or prefix.itemsize != 1 or prefix.format != 'B' or \
            not prefix.c_contiguous or type(prefix.obj) is not bytes or \
            len(prefix) + zero_tail_bytes != length:
        _fail('semantic', 'SOURCE_DATA_RECORD')
    view = object.__new__(LocalSourceData)
    object.__setattr__(view, 'tag', 'local')
    object.__setattr__(view, 'stamp', stamp)
    object.__setattr__(view, 'symbol', symbol)
    object.__setattr__(view, 'symbol_record', symbol_record)
    object.__setattr__(view, 'storage', storage)
    object.__setattr__(view, 'offset', offset)
    object.__setattr__(view, 'length', length)
    object.__setattr__(view, 'symbol_extent', symbol_extent)
    object.__setattr__(view, 'backing_extent', backing_extent)
    object.__setattr__(view, 'symbol_alignment', symbol_alignment)
    object.__setattr__(view, 'backing_alignment', backing_alignment)
    object.__setattr__(view, 'prefix', prefix)
    object.__setattr__(view, 'zero_tail_bytes', zero_tail_bytes)
    object.__setattr__(view, 'patches', patches)
    object.__setattr__(view, '_budget', budget)
    object.__setattr__(view, '_check_snapshot', check_snapshot)
    return view
