"""API6 isolated reference views, not comparator or executable admission proofs.

Canonical initialization is serialized. Trusted Python implementation mutation is
outside this reference contract; untrusted records cannot issue view identities.
"""
import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import sys
import weakref

if __name__ != '_rax_smir_source_call_v1':
    raise ImportError('SOURCE_CALL_MODULE_IDENTITY')

ROOT = Path(__file__).resolve().parents[4]
_TOKEN = object()
_ISSUED = {}  # id -> original associations; no equality or strong view/context pin.
_TABLES = {'nominal': (10, 'types'), 'signature': (10, 'signatures'),
           'recipe': (10, 'recipes'), 'layout': (10, 'layouts'),
           'domain': (10, 'domains'), 'execution': (1, 'types')}


def _error(code, detail=''):
    module = sys.modules.get('_rax_smir_call_comparison_errors_v1')
    path = (ROOT / 'tools/smir-abi/function_address/errors.py').resolve()
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != path or
            getattr(module, '_CANONICAL_INITIALIZED', False) is not True):
        raise RuntimeError('CALL_COMPARISON_MODULE_IDENTITY')
    raise module.CallComparisonError('semantic', code, detail)


def _context(context):
    cls = type(context)
    module = sys.modules.get(cls.__module__)
    path = (ROOT / 'tools/smir-format/execution/candidate/context.py').resolve()
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != path or getattr(module, 'RootContext', None) is not cls):
        _error('ABI_CC_CONTEXT', 'actual RootContext required')
    if context.sections[3]['payload_revision'] == 3:
        from candidate import root3_context as V3
        V3.require_abi(context)
    if context.abi_checked is not True:
        _error('ABI_CC_CONTEXT', 'prior ABI verification required')
    # An alias of actual context.py still imports the actual execution Types.
    types = cls.__init__.__globals__['Types']
    owner = sys.modules.get(types.__module__)
    if (owner is None or getattr(owner, '__file__', None) is None or
            Path(owner.__file__).resolve() != (path.parent / 'type_system.py').resolve()):
        _error('ABI_CC_CONTEXT', 'execution package identity')
    package = types.__module__.rpartition('.')[0]
    projection = importlib.import_module(package + '.source_data_projection')
    wire = importlib.import_module(package + '.wire')
    for actual, filename in ((projection, 'source_data_projection.py'), (wire, 'wire.py')):
        if getattr(actual, '__file__', None) is None or Path(actual.__file__).resolve() != path.parent / filename:
            _error('ABI_CC_CONTEXT', 'capture implementation path')
    return projection


@dataclass(frozen=True, slots=True, eq=False, init=False)
class _SourceCallStamp:
    identity: object
    schema_digest: bytes
    root_digests: tuple

    def __init__(self, identity, schema_digest, root_digests):
        if hasattr(self, 'identity'):
            raise AttributeError('immutable source-call stamp')
        for name, value in (('identity', identity), ('schema_digest', schema_digest),
                            ('root_digests', root_digests)):
            object.__setattr__(self, name, value)


class _ImmutableMapping(Mapping):
    __slots__ = ('_record', '_api', '_budget')

    def __init__(self, record, api, budget):
        if hasattr(self, '_record'):
            raise AttributeError('immutable source-call record')
        object.__setattr__(self, '_record', record)
        object.__setattr__(self, '_api', api)
        object.__setattr__(self, '_budget', budget)

    def __setattr__(self, name, value):
        raise AttributeError('immutable source-call record')

    def __delattr__(self, name):
        raise AttributeError('immutable source-call record')

    def __getitem__(self, name):
        if type(name) is not str:
            raise KeyError(name)
        self._budget.work(len(name) + len(self._record.fields))
        for key, value in self._record.fields:
            if key == name:
                return _wrap(value, self._api, self._budget)
        raise KeyError(name)

    def __iter__(self):
        size = len(self._record.fields)
        self._budget.charge(work=size, edges=size, copied_bytes=8 * size)
        return iter(tuple(name for name, _ in self._record.fields))

    def __len__(self):
        return len(self._record.fields)


def _wrap(value, api, budget):
    budget.work(1)
    if type(value) is api.FrozenRecord:
        budget.charge(edges=3, copied_bytes=64)
        return _ImmutableMapping(value, api, budget)
    if type(value) is tuple:
        budget.charge(work=len(value), edges=len(value), copied_bytes=8 * len(value))
        return tuple(_wrap(child, api, budget) for child in value)
    return value


@dataclass(frozen=True, slots=True, eq=False, init=False)
class SourceCallRecord:
    original_reference: Mapping
    local_reference: Mapping
    record: Mapping

    def __init__(self, original_reference, local_reference, record):
        if hasattr(self, 'record'):
            raise AttributeError('immutable source-call record')
        for name, value in (('original_reference', original_reference),
                            ('local_reference', local_reference), ('record', record)):
            object.__setattr__(self, name, value)


class SourceCallContext:
    __slots__ = ('_context', '_projection', '_stamp', '_roots', '_budget', '__weakref__')

    def __new__(cls, token=None, *args):
        if token is not _TOKEN or cls is not SourceCallContext:
            _error('ABI_CC_CONTEXT', 'no public view constructor')
        return object.__new__(cls)

    def __init__(self, token, context, projection, stamp, roots, budget):
        if hasattr(self, '_context'):
            _error('ABI_CC_CONTEXT', 'view already initialized')
        for name, value in (('_context', context), ('_projection', projection),
                            ('_stamp', stamp), ('_roots', roots), ('_budget', budget)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError('immutable source-call context')

    def __delattr__(self, name):
        raise AttributeError('immutable source-call context')

    def record(self, namespace, reference, *, budget):
        validate_source_call_context(self, budget=budget)
        if type(namespace) is not str:
            _error('ABI_CC_ENTITY_NAMESPACE')
        budget.work(len(namespace) + 1)
        if namespace not in _TABLES:
            _error('ABI_CC_ENTITY_NAMESPACE', 'unknown namespace')
        original, kind, identifier, slot = _reference(self, reference, budget)
        local = original
        if kind == 'dependency':
            if namespace in ('recipe', 'layout', 'domain'):
                _error('ABI_CC_ENTITY_NAMESPACE', namespace)
            dependency = _lookup(self._roots[2].field('manifest').field('dependencies'),
                                 slot, budget, 'slot')
            declaration = _lookup(dependency.field('declarations'), identifier, budget)
            category = declaration.field('kind')
            if namespace == 'nominal':
                permitted = category == 'nominal'
            elif namespace == 'execution':
                permitted = category in ('type', 'function', 'symbol')
            else:
                permitted = category in ('function', 'symbol')
            if category == 'symbol':
                permitted = permitted and declaration.field('symbol_kind') in ('function', 'import', 'data', 'tls')
                if namespace == 'signature':
                    permitted = permitted and declaration.field('symbol_kind') in ('function', 'import')
            if not permitted:
                _error('ABI_CC_ENTITY_NAMESPACE', namespace)
            field = {'nominal': 'nominal', 'signature': 'abi_signature', 'execution': 'execution'}[namespace]
            expected = declaration.field(field)
            if expected is None:
                _error('ABI_CC_ENTITY_REFERENCE', 'missing consumer expectation')
            local = expected.field('some')
            if local.field('module').field('kind') != 'self':
                _error('ABI_CC_ENTITY_REFERENCE', 'expectation must be SELF')
            identifier = local.field('id')
        section, table = _TABLES[namespace]
        code = 'ABI_CC_TYPE_REFERENCE' if namespace == 'execution' else 'ABI_CC_ENTITY_REFERENCE'
        selected = _lookup(self._roots[section].field(table), identifier, budget, code=code)
        api = self._projection.source_api()
        budget.charge(work=1, edges=3, copied_bytes=64)
        result = SourceCallRecord(_wrap(original, api, budget), _wrap(local, api, budget),
                                  _wrap(selected, api, budget))
        validate_source_call_context(self, budget=budget)
        return result

    def site(self, *, budget):
        validate_source_call_context(self, budget=budget)
        result = _wrap(self._roots[10].field('site'), self._projection.source_api(), budget)
        validate_source_call_context(self, budget=budget)
        return result

    def module_family(self, *, budget):
        validate_source_call_context(self, budget=budget)
        key = self._roots[2].field('manifest').field('key')
        namespace, name, major = key.field('namespace'), key.field('name'), key.field('abi_major')
        budget.charge(work=len(namespace) + len(name) + 4, edges=3,
                      copied_bytes=32 + 4 * (len(namespace) + len(name)))
        result = (namespace, name, major)
        validate_source_call_context(self, budget=budget)
        return result


def _lookup(rows, identifier, budget, key='id', code='ABI_CC_ENTITY_REFERENCE'):
    budget.charge(work=len(rows), edges=len(rows))
    for row in rows:
        if row.field(key) == identifier:
            return row
    _error(code)


def _reference(view, reference, budget):
    budget.charge(work=16, edges=8, copied_bytes=128)
    allowed = (dict, _ImmutableMapping)
    if type(reference) not in allowed or len(reference) != 2 or set(reference) != {'module', 'id'}:
        _error('ABI_CC_ENTITY_REFERENCE')
    module, identifier = reference['module'], reference['id']
    if type(module) not in allowed or type(identifier) is not int or not 0 <= identifier < 0xffffffff:
        _error('ABI_CC_ENTITY_REFERENCE')
    kind = module.get('kind')
    if type(kind) is not str:
        _error('ABI_CC_ENTITY_REFERENCE')
    budget.work(len(kind))
    if kind == 'self' and len(module) == 1:
        slot = None
    elif kind == 'dependency' and len(module) == 2 and set(module) == {'kind', 'slot'}:
        slot = module['slot']
        if type(slot) is not int or not 0 <= slot < 0xffffffff:
            _error('ABI_CC_ENTITY_REFERENCE')
    else:
        _error('ABI_CC_ENTITY_REFERENCE')
    api = view._projection.source_api()
    fields = (('kind', kind),) if slot is None else (('kind', kind), ('slot', slot))
    frozen = api.FrozenRecord((('module', api.FrozenRecord(fields)), ('id', identifier)))
    return frozen, kind, identifier, slot


def _varargs(roots, budget):
    rows = roots[10].field('signatures')
    budget.charge(work=len(rows), edges=len(rows))
    for signature in rows:
        option = signature.field('varargs')
        if option is None:
            continue
        module = option.field('some').field('table_module')
        if module.field('kind') == 'dependency':
            _lookup(roots[2].field('manifest').field('dependencies'), module.field('slot'), budget, 'slot')
        elif module.field('kind') != 'self':
            _error('ABI_CC_ENTITY_REFERENCE', 'varargs table module')


def _issue(context, *, budget):
    projection = _context(context)
    budget = projection._budget(budget)
    budget.charge(work=16, edges=8, copied_bytes=512)
    schema, digest = (projection._schema(budget, context=context)
                      if context.sections[3]['payload_revision'] == 3 else projection._schema(budget))
    roots, digests = projection._roots(context, schema, budget, True)
    if any(context._root_hashes.get(section) != value for section, value in digests):
        projection._fail('context_snapshot_changed')
    _varargs(roots, budget)
    stamp = _SourceCallStamp(object(), digest, digests)
    view = SourceCallContext(_TOKEN, context, projection, stamp, roots, budget)
    identity = id(view)

    def discard(reference):
        entry = _ISSUED.get(identity)
        if entry is not None and entry[0] is reference:
            del _ISSUED[identity]

    _ISSUED[identity] = (weakref.ref(view, discard), weakref.ref(context),
                         stamp, projection, budget, roots)
    return view


def validate_source_call_context(value, *, budget):
    if type(value) is not SourceCallContext:
        _error('ABI_CC_CONTEXT', 'canonical issued view required')
    issued = _ISSUED.get(id(value))
    if issued is None or issued[0]() is not value:
        _error('ABI_CC_CONTEXT', 'unissued view')
    if (issued[1]() is not value._context or issued[2] is not value._stamp or
            issued[3] is not value._projection or issued[4] is not value._budget or
            issued[5] is not value._roots):
        _error('ABI_CC_CONTEXT', 'original view association')
    projection = value._projection
    budget = projection._budget(budget)
    if budget is not value._budget:
        _error('ABI_CC_CONTEXT', 'view budget association')
    if _context(value._context) is not projection:
        _error('ABI_CC_CONTEXT', 'capture implementation changed')
    budget.work(16)
    schema, digest = (projection._schema(budget, context=value._context)
                      if value._context.sections[3]['payload_revision'] == 3 else projection._schema(budget))
    if digest != value._stamp.schema_digest:
        projection._fail('SOURCE_DATA_SCHEMA')
    _, roots = projection._roots(value._context, schema, budget, False)
    if roots != value._stamp.root_digests or any(value._context._root_hashes.get(s) != d for s, d in roots):
        projection._fail('context_snapshot_changed')
    return value


_SOURCE_CALL_READY = True
