"""Unconsumed pure source-typed integers and originless address data.

These values contain no target, authority, permit, exposure, activation or runtime
fact. Quotas count logical work/edges/retained bytes, not allocator capacity.
"""
import importlib.util
from pathlib import Path
import sys
from threading import RLock
import weakref

if __name__ != '_rax_smir_code_values_v1':
    raise ImportError('CODE_VALUE_MODULE_IDENTITY')

_ROOT = Path(__file__).resolve().parents[3]
_LOCK = RLock()
_ISSUED = {}


class CodeValueError(Exception):
    __slots__ = ('_kind', '_code', '_detail')

    def __init__(self, kind, code, detail=''):
        if hasattr(self, '_kind'):
            raise AttributeError('immutable code-value error')
        if kind not in ('semantic', 'resource') or type(code) is not str or type(detail) is not str:
            raise TypeError('invalid code-value error')
        object.__setattr__(self, '_kind', kind)
        object.__setattr__(self, '_code', code)
        object.__setattr__(self, '_detail', detail)
        super().__init__(code)

    def __setattr__(self, name, value):
        if name in ('kind', 'code', 'detail', '_kind', '_code', '_detail'):
            raise AttributeError('immutable code-value error')
        super().__setattr__(name, value)

    def __delattr__(self, name):
        raise AttributeError('immutable code-value error')

    kind = property(lambda self: self._kind)
    code = property(lambda self: self._code)
    detail = property(lambda self: self._detail)

    def __str__(self):
        return self._code + (': ' + self._detail if self._detail else '')


def _require(condition, code):
    if not condition:
        raise CodeValueError('semantic', code)


def _load(name, relative):
    path = (_ROOT / relative).resolve()
    with _LOCK:
        if name in sys.modules:
            module = sys.modules[name]
            _require(getattr(module, '__file__', None) is not None and
                     Path(module.__file__).resolve() == path, 'CODE_VALUE_MODULE_IDENTITY')
            return module
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
        return module


_SD = _load('_rax_smir_source_data_v1', 'tools/smir-runtime-contract/source_roles/source_data.py')
_BUDGET = _SD.SourceQueryBudget
_SD_ERROR = _SD.SourceDataError
_CALL = _load('_rax_smir_source_call_v1',
              'tools/smir-format/execution/candidate/source_call_projection.py')
_CALL_CLASS = _CALL.SourceCallContext
_CALL_VALIDATE = _CALL.validate_source_call_context


def _budget(budget):
    _require(sys.modules.get('_rax_smir_source_data_v1') is _SD and
             _SD.SourceQueryBudget is _BUDGET and _SD.SourceDataError is _SD_ERROR,
             'CODE_VALUE_MODULE_IDENTITY')
    if type(budget) is not _BUDGET or any(
            type(getattr(budget, name, None)) is not int
            for name in ('max_work', 'max_edges', 'max_copied_bytes', 'max_depth',
                         '_used_work', '_used_edges', '_used_copied_bytes')):
        raise _SD_ERROR('resource', 'SOURCE_DATA_BUDGET')
    return budget


def _view(context, budget):
    _require(sys.modules.get('_rax_smir_source_call_v1') is _CALL and
             _CALL.SourceCallContext is _CALL_CLASS and
             _CALL.validate_source_call_context is _CALL_VALIDATE and
             getattr(_CALL, '_SOURCE_CALL_READY', False) is True,
             'CODE_VALUE_MODULE_IDENTITY')
    # Canonical validator checks private issuance, actual context/stamp/budget,
    # original verified digests and active schema; preserve its exact errors.
    return _CALL_VALIDATE(context, budget=budget)


def _local(value, kind=None):
    _require(type(value) in (IntegerLane, AddressLane), 'CODE_VALUE_IDENTITY')
    entry = _ISSUED.get(id(value))
    _require(entry is not None and entry[0]() is value and
             getattr(value, '_record', None) is entry[1], 'CODE_VALUE_IDENTITY')
    _require(kind is None or type(value) is kind, 'CODE_VALUE_KIND')
    return entry[1]


class _Lane:
    __slots__ = ('_record', '__weakref__')

    def __new__(cls, *args, **kwargs):
        raise CodeValueError('semantic', 'CODE_VALUE_CONSTRUCTOR')

    def __init__(self, *args, **kwargs):
        raise CodeValueError('semantic', 'CODE_VALUE_CONSTRUCTOR')

    def __setattr__(self, name, value):
        raise AttributeError('immutable pure code value')

    def __delattr__(self, name):
        raise AttributeError('immutable pure code value')

    def __copy__(self):
        _local(self)
        return self  # Immutable alias, not allocation or additional authority.

    def __deepcopy__(self, memo):
        _local(self)
        return self

    state = property(lambda self: _local(self)[0])
    width = property(lambda self: _local(self)[2])

    def bits(self, *, budget):
        record = _validate(self, budget)
        _require(record[0] == 'concrete', 'CODE_VALUE_NONCONCRETE')
        budget.charge(work=1 + (record[2] + 7) // 8)
        if record[3] is not None:
            _view(record[3], budget)
        return record[1]


class IntegerLane(_Lane):
    __slots__ = ()
    context = property(lambda self: _local(self, IntegerLane)[3])
    reference = property(lambda self: _local(self, IntegerLane)[4])
    local_reference = property(lambda self: _local(self, IntegerLane)[5])


class AddressLane(_Lane):
    __slots__ = ()


def _validate(value, budget, kind=None):
    budget = _budget(budget)
    budget.work(8)
    record = _local(value, kind)
    _require(record[6] is budget, 'CODE_VALUE_BUDGET_CONTEXT')
    if record[3] is not None:
        _view(record[3], budget)
    return record


def validate_integer(value, *, budget):
    _validate(value, budget, IntegerLane)
    return value


def validate_address(value, *, budget):
    _validate(value, budget, AddressLane)
    return value


def _issue(cls, record):
    value = object.__new__(cls)
    object.__setattr__(value, '_record', record)
    identifier = id(value)

    def discard(reference):
        with _LOCK:
            old = _ISSUED.get(identifier)
            if old is not None and old[0] is reference:
                del _ISSUED[identifier]

    reference = weakref.ref(value, discard)
    with _LOCK:
        _ISSUED[identifier] = (reference, record)
    return value


def _integer(context, reference, state, bits, budget):
    budget = _budget(budget)
    _view(context, budget)
    source = context.record('execution', reference, budget=budget)
    _require(source.record['kind'] == 'int', 'CODE_VALUE_INTEGER_TYPE')
    width = source.record['bits']
    _require(type(width) is int and 1 <= width <= 2**23, 'CODE_VALUE_INTEGER_TYPE')
    size = (width + 7) // 8
    # Conservative retained-width quota is charged even for a zero/unknown lane;
    # no width-sized mask or shifted integer is constructed to check a range.
    budget.charge(work=16 + size, edges=8, copied_bytes=192 + size)
    if state == 'concrete':
        _require(type(bits) is int and bits >= 0 and bits.bit_length() <= width,
                 'CODE_VALUE_INTEGER_RANGE')
    else:
        _require(bits is None, 'CODE_VALUE_STATE')
    record = (state, bits, width, context, source.original_reference,
              source.local_reference, budget)
    _view(context, budget)
    return _issue(IntegerLane, record)


def integer(bits, context, integer, *, budget):
    return _integer(context, integer, 'concrete', bits, budget)


def integer_poison(context, integer, *, budget):
    return _integer(context, integer, 'poison', None, budget)


def integer_undef(context, integer, *, budget):
    return _integer(context, integer, 'undef', None, budget)


def _address(state, bits, budget):
    budget = _budget(budget)
    budget.charge(work=16, edges=4, copied_bytes=128)
    if state == 'concrete':
        _require(type(bits) is int and 0 <= bits < 2**64, 'CODE_VALUE_ADDRESS_RANGE')
    else:
        _require(bits is None, 'CODE_VALUE_STATE')
    return _issue(AddressLane, (state, bits, 64, None, None, None, budget))


def originless(bits, *, budget):
    return _address('concrete', bits, budget)


def null(*, budget):
    return originless(0, budget=budget)


def poison(*, budget):
    return _address('poison', None, budget)


def undef(*, budget):
    return _address('undef', None, budget)


_CODE_VALUES_READY = True
