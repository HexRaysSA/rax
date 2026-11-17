"""Charged, phase-independent declared source capture (S-PROD014 REV2).

The frozen values and canonical bytes come from the same grammar walk. Queries
use that immutable capture after rechecking all actual roots and active grammar.
No ABI/metadata facts, relocated bytes or executable authority are issued here.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from common import require
from .wire import HEX, INTEGERS, SCHEMA, TOKEN

ROOT = Path(__file__).resolve().parents[4]
ROOT_NAMES = {1: 'execution_types', 2: 'runtime_symbols', 3: 'execution_functions',
              4: 'runtime_data', 5: 'runtime_relocations', 6: 'runtime_imports',
              7: 'runtime_tls', 8: 'execution_exceptions', 9: 'runtime_capabilities',
              10: 'abi_contract'}
MAX_U64 = (1 << 64) - 1


def source_api():
    """One exact private class identity across SEM/ABI/R; no namespace guessing."""
    name = '_rax_smir_source_data_v1'
    path = (ROOT / 'tools/smir-runtime-contract/source_roles/source_data.py').resolve()
    if name in sys.modules:
        module = sys.modules[name]
        require(getattr(module, '__file__', None) is not None and
                Path(module.__file__).resolve() == path, 'SOURCE_DATA_CONTEXT')
        return module
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def _fail(code, detail='', kind='semantic'):
    raise source_api().SourceDataError(kind, code, detail)


def _budget(value):
    if type(value) is not source_api().SourceQueryBudget:
        _fail('SOURCE_DATA_BUDGET', kind='resource')
    return value


def _visit(budget, depth):
    if depth > budget.max_depth:
        _fail('SOURCE_DATA_RESOURCE', 'depth', 'resource')
    budget.charge(work=1, edges=1)


def _hash(budget):
    budget.edges(1)
    return hashlib.sha256()


def _digest(hasher, budget):
    budget.charge(work=32, copied_bytes=32)
    return hasher.digest()


def _emit_integer(hasher, value, width, budget, signed=False):
    budget.charge(work=2 * width, copied_bytes=width)
    hasher.update(value.to_bytes(width, 'little', signed=signed))


def _text_size(value, budget, ascii_only=False):
    budget.work(len(value))
    size = 0
    for char in value:
        number = ord(char)
        require(not 0xd800 <= number <= 0xdfff, 'shape', 'surrogate in UTF8')
        require(not ascii_only or number < 128, 'shape', 'ASCII token')
        size += 1 if number < 128 else 2 if number < 2048 else 3 if number < 65536 else 4
    return size


def _json_string(value, hasher, budget):
    """Precompute the exact ensure_ascii JSON payload size before allocation."""
    budget.work(len(value))
    length = 2
    for char in value:
        number = ord(char)
        length += (2 if char in '\\"\b\f\n\r\t' else 6 if number < 32 or
                   127 <= number <= 0xffff else 12 if number > 0xffff else 1)
    budget.charge(work=2 * length, copied_bytes=2 * length)
    encoded = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    hasher.update(encoded)


def _freeze_json(value, hasher, budget, depth=0):
    """Capture a private grammar and hash its sorted-key compact ASCII JSON."""
    _visit(budget, depth)
    if type(value) is dict:
        budget.charge(work=len(value) * max(1, len(value).bit_length()), edges=2 * len(value))
        require(all(type(key) is str for key in value), 'root_schema_conflict')
        keys = sorted(value)
        result = {}
        hasher.update(b'{')
        for index, key in enumerate(keys):
            if index:
                hasher.update(b',')
            _json_string(key, hasher, budget)
            hasher.update(b':')
            result[key] = _freeze_json(value[key], hasher, budget, depth + 1)
        hasher.update(b'}')
        return result
    if type(value) in (list, tuple):
        budget.edges(2 * len(value))
        result = []
        hasher.update(b'[')
        for index, child in enumerate(value):
            if index:
                hasher.update(b',')
            result.append(_freeze_json(child, hasher, budget, depth + 1))
        hasher.update(b']')
        return tuple(result)
    if type(value) is str:
        _json_string(value, hasher, budget)
        return value
    # Grammar records contain only dict/list/string. Reject unexpected shapes
    # rather than allocating an unbounded integer or float textual encoding.
    _fail('SOURCE_DATA_SCHEMA', 'grammar value')


def _read_schema(path, budget):
    """Bound file/JSON allocations and nesting BEFORE parsing an active schema.

    JSON tree nodes and decoded string bytes are conservatively precharged by
    source byte count. This is a quota bound, not an allocator/CPU measurement.
    """
    size = path.stat().st_size
    budget.charge(work=4 * (size + 1), edges=size + 1,
                  copied_bytes=3 * (size + 1))
    with path.open('rb') as stream:
        raw = stream.read(size + 1)
    if len(raw) != size:
        _fail('SOURCE_DATA_SCHEMA', 'schema changed while reading')
    depth, quoted, escape = 0, False, False
    for byte in raw:
        if quoted:
            if escape:
                escape = False
            elif byte == 92:
                escape = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > budget.max_depth:
                _fail('SOURCE_DATA_RESOURCE', 'schema JSON depth', 'resource')
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        _fail('SOURCE_DATA_SCHEMA', 'invalid active schema JSON: ' + type(error).__name__)


def _schema_equal(left, right, budget, depth=0):
    _visit(budget, depth)
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if len(left) != len(right):
            return False
        for key, child in left.items():
            budget.work(len(key))
            if key not in right or not _schema_equal(child, right[key], budget, depth + 1):
                return False
        return True
    if type(left) in (list, tuple):
        return len(left) == len(right) and all(_schema_equal(a, b, budget, depth + 1)
                                              for a, b in zip(left, right))
    if type(left) is str:
        budget.work(len(left) + len(right))
    return left == right


def _schema_records(document, budget):
    _visit(budget, 0)
    if type(document) is not dict or type(document.get('records')) is not dict:
        _fail('SOURCE_DATA_SCHEMA', 'document records map required')
    return document['records']


def _schema_token(value, budget):
    if type(value) is not str:
        _fail('SOURCE_DATA_SCHEMA', 'grammar token')
    budget.work(len(value))
    if TOKEN.fullmatch(value) is None:
        _fail('SOURCE_DATA_SCHEMA', 'grammar token')


def _audit_kind(kind, records, budget):
    if type(kind) is not str:
        _fail('SOURCE_DATA_SCHEMA', 'field kind')
    budget.work(len(kind))
    offset = 0
    while kind.startswith('vec:', offset) or kind.startswith('opt:', offset):
        _visit(budget, offset // 4)
        offset += 4
    budget.charge(work=len(kind) - offset, copied_bytes=len(kind) - offset)
    leaf = kind[offset:]
    if leaf not in INTEGERS and leaf not in ('bool', 'hex', 'digest32', 'utf8', 'token') and leaf not in records:
        _fail('SOURCE_DATA_SCHEMA', 'unknown field kind')


def _audit_fields(fields, discriminator, records, budget):
    if type(fields) is not list:
        _fail('SOURCE_DATA_SCHEMA', 'ordered fields list')
    budget.charge(work=len(fields), edges=len(fields) + 1)
    names = {discriminator} if discriminator is not None else set()
    for row in fields:
        _visit(budget, 1)
        if type(row) is not list or len(row) != 2:
            _fail('SOURCE_DATA_SCHEMA', 'field name/kind pair')
        name, kind = row
        _schema_token(name, budget)
        if name in names:
            _fail('SOURCE_DATA_SCHEMA', 'duplicate field')
        names.add(name)
        _audit_kind(kind, records, budget)


def _audit_schema(records, budget):
    budget.charge(work=len(records), edges=1)
    for name, record in records.items():
        _visit(budget, 0)
        _schema_token(name, budget)
        if name in INTEGERS or name in ('bool', 'hex', 'digest32', 'utf8', 'token', 'bytes'):
            _fail('SOURCE_DATA_SCHEMA', 'record shadows primitive')
        if type(record) is not dict:
            _fail('SOURCE_DATA_SCHEMA', 'record grammar map')
        if len(record) == 1 and 'fields' in record:
            _audit_fields(record['fields'], None, records, budget)
        elif len(record) == 2 and 'discriminator' in record and 'variants' in record:
            discriminator, variants = record['discriminator'], record['variants']
            _schema_token(discriminator, budget)
            if type(variants) is not dict or not variants:
                _fail('SOURCE_DATA_SCHEMA', 'nonempty variants map')
            budget.work(len(variants))
            for tag, fields in variants.items():
                _schema_token(tag, budget)
                _audit_fields(fields, discriminator, records, budget)
        else:
            _fail('SOURCE_DATA_SCHEMA', 'record fields or discriminator/variants required')


def _schema(budget, *, context=None):
    if context is not None and context.sections[3]['payload_revision'] == 3:
        from . import root3_context as V3
        V3.owner_budget(context, budget)
        return V3.schema(*_schema(budget), budget)
    # Execution SCHEMA is the actual active imported grammar used by RootContext;
    # runtime/ABI grammars are read afresh just as context.records() reads them.
    budget.edges(1)
    merged = {}
    for owner in ('execution', 'runtime', 'abi'):
        document = SCHEMA if owner == 'execution' else _read_schema(
            ROOT / f'docs/specifications/smir/portable/schema/{owner}/candidate.json', budget)
        records = _schema_records(document, budget)
        budget.charge(work=len(records), edges=len(records))
        for name, record in records.items():
            if name in merged:
                if not _schema_equal(merged[name], record, budget):
                    _fail('SOURCE_DATA_SCHEMA', 'conflicting active record')
            merged[name] = record
    _audit_schema(merged, budget)
    if any(root not in merged for root in ROOT_NAMES.values()):
        _fail('SOURCE_DATA_SCHEMA', 'required root grammar missing')
    hasher = _hash(budget)
    frozen = _freeze_json(merged, hasher, budget)
    return frozen, _digest(hasher, budget)


class _WireCapture:
    def __init__(self, records, budget, capture):
        self.records, self.budget, self.capture = records, budget, capture
        self.api = source_api()
        self.hasher = _hash(budget)

    def visit(self, name, item, depth=0):
        budget = self.budget
        _visit(budget, depth)
        if name.startswith('vec:'):
            require(type(item) is list and len(item) <= 0xffffffff, 'shape', name)
            _emit_integer(self.hasher, len(item), 4, budget)
            if self.capture:
                budget.edges(2 * len(item))
                children = []
            for child in item:
                value = self.visit(name[4:], child, depth + 1)
                if self.capture:
                    children.append(value)
            return tuple(children) if self.capture else None
        if name.startswith('opt:'):
            _emit_integer(self.hasher, int(item is not None), 1, budget)
            if item is None:
                return None
            require(type(item) is dict and len(item) == 1 and 'some' in item, 'shape', 'option wrapper')
            child = self.visit(name[4:], item['some'], depth + 1)
            if self.capture:
                budget.edges(3)
                return self.api.FrozenRecord((('some', child),))
            return None
        if name in INTEGERS:
            size, signed = INTEGERS[name]
            minimum = -(1 << (8 * size - 1)) if signed else 0
            maximum = (1 << (8 * size - int(signed))) - 1
            require(type(item) is int and minimum <= item <= maximum, 'shape', name)
            _emit_integer(self.hasher, item, size, budget, signed)
            return item
        if name == 'bool':
            require(type(item) is bool, 'shape', name)
            _emit_integer(self.hasher, int(item), 1, budget)
            return item
        if name in ('hex', 'digest32'):
            require(type(item) is str, 'shape', name)
            budget.work(len(item))
            require(HEX.fullmatch(item) is not None, 'shape', name)
            size = len(item) // 2
            if name == 'digest32':
                require(size == 32, 'shape', name)
            else:
                require(size <= 0xffffffff, 'shape', name)
                _emit_integer(self.hasher, size, 4, budget)
            # Hash bounded pieces, never decode a whole backing just to query8B.
            for start in range(0, len(item), 8192):
                length = min(8192, len(item) - start)
                budget.charge(work=length + length // 2, copied_bytes=length + length // 2)
                self.hasher.update(bytes.fromhex(item[start:start + length]))
            return item
        if name in ('token', 'utf8'):
            require(type(item) is str, 'shape', name)
            size = _text_size(item, budget, name == 'token')
            if name == 'token':
                require(TOKEN.fullmatch(item) is not None, 'shape', name)
            else:
                require(size <= 0xffffffff, 'shape', name)
            _emit_integer(self.hasher, size, 1 if name == 'token' else 4, budget)
            budget.charge(work=2 * size, copied_bytes=size)
            self.hasher.update(item.encode('utf-8'))
            return item
        require(name in self.records and type(item) is dict, 'shape', name)
        grammar = self.records[name]
        discriminator = grammar.get('discriminator')
        if discriminator is None:
            fields = grammar['fields']
            tag = None
        else:
            tag = item.get(discriminator)
            require(type(tag) is str and tag in grammar['variants'], 'shape', name)
            fields = grammar['variants'][tag]
        budget.work(len(fields) + 1)
        require(len(item) == len(fields) + int(discriminator is not None) and
                all(field in item for field, _ in fields), 'shape', name + ' exact fields')
        if self.capture:
            budget.edges(2 * (len(fields) + 1))
            result = []
        if discriminator is not None:
            self.visit('token', tag, depth + 1)
            if self.capture:
                result.append((discriminator, tag))
        for field, kind in fields:
            # Read once: this value is BOTH hashed and frozen by the same walk.
            value = self.visit(kind, item[field], depth + 1)
            if self.capture:
                result.append((field, value))
        return self.api.FrozenRecord(tuple(result)) if self.capture else None


def _roots(context, schema, budget, capture):
    budget.edges(3 * len(ROOT_NAMES))
    present = tuple(section for section in ROOT_NAMES if section in context.sections)
    require(present == tuple(context._root_hashes), 'context_snapshot_changed')
    roots, digests = {}, []
    for section in present:
        walk = _WireCapture(schema, budget, capture)
        from .root3_context import record_name
        value = walk.visit(record_name(context, section), context.sections[section])
        digests.append((section, _digest(walk.hasher, budget)))
        if capture:
            roots[section] = value
    return roots, tuple(digests)


def prepare(context, *, budget):
    budget = _budget(budget)
    if context.source_stamp is not None:
        check_snapshot(context, stamp=context.source_stamp, budget=budget)
        budget.work(16)
        return context.source_stamp
    budget.work(16)
    schema, schema_digest = (_schema(budget, context=context)
                             if context.sections[3]['payload_revision'] == 3 else _schema(budget))
    roots, digests = _roots(context, schema, budget, True)
    require(all(context._root_hashes[section] == digest for section, digest in digests),
            'context_snapshot_changed')
    budget.edges(4)
    stamp = source_api().SourceStamp(object(), schema_digest, digests)
    # Publish only a successful complete immutable source capture.
    context._source_grammar = schema
    context._source_roots = roots
    context._source_budget = budget
    context._source_stamp = stamp
    return stamp


def check_snapshot(context, *, stamp, budget):
    if stamp is not context.source_stamp or stamp is None or budget is not context._source_budget:
        _fail('SOURCE_DATA_CONTEXT')
    budget = _budget(budget)
    schema, digest = (_schema(budget, context=context)
                      if context.sections[3]['payload_revision'] == 3 else _schema(budget))
    if digest != stamp.schema_digest:
        _fail('SOURCE_DATA_SCHEMA')
    _, roots = _roots(context, schema, budget, False)
    if roots != stamp.root_digests:
        _fail('context_snapshot_changed')


def _field(record, name):
    return record.field(name)


def _option(value):
    return None if value is None else value.field('some')


def _lookup(rows, identifier, budget, code):
    budget.work(len(rows))
    for row in rows:
        if row.field('id') == identifier:
            return row
    require(False, code)


def _range(offset, length, code, positive=True):
    require(type(offset) is int and type(length) is int and 0 <= offset <= MAX_U64 and
            0 <= length <= MAX_U64 and (length > 0 or not positive) and
            offset + length <= MAX_U64, code)
    return offset + length


def _reference(context, reference, budget):
    walk = _WireCapture(context._source_grammar, budget, True)
    frozen = walk.visit('entity_ref', reference)
    module = frozen.field('module')
    kind, identifier = module.field('kind'), frozen.field('id')
    budget.edges(1)
    return ('self', identifier) if kind == 'self' else ('dependency', module.field('slot'), identifier)


def query(context, symbol, offset, length, *, budget):
    budget = _budget(budget)
    if context.source_stamp is None:
        _fail('SOURCE_DATA_EVIDENCE_UNAVAILABLE', 'source preparation required', 'unavailable')
    if budget is not context._source_budget:
        _fail('SOURCE_DATA_CONTEXT')
    budget.work(16)
    check_snapshot(context, stamp=context.source_stamp, budget=budget)
    end = _range(offset, length, 'ABI_CC_METADATA_EXTENT')
    reference = _reference(context, symbol, budget)
    roots = context._source_roots
    if reference[0] == 'dependency':
        dependencies = roots[2].field('manifest').field('dependencies')
        budget.work(len(dependencies))
        owner = next((item for item in dependencies if item.field('slot') == reference[1]), None)
        require(owner is not None, 'declaration_reference')
        declared = _lookup(owner.field('declarations'), reference[2], budget, 'declaration_reference')
        require(declared.field('kind') == 'symbol' and declared.field('symbol_kind') == 'data',
                'RT_METADATA_DEFINITION')
        site = owner.field('site')
        budget.charge(work=len(site), copied_bytes=32, edges=2)
        authority = source_api().DependencyOwner(reference[1], owner.field('key'),
            owner.field('minimum_minor'), _option(owner.field('maximum_minor')), bytes.fromhex(site))
        return source_api().DependencySourceData('dependency', context.source_stamp, reference,
            authority, reference[1], reference[2], offset, length, declared)
    declared = _lookup(roots[2].field('symbols'), reference[1], budget, 'symbol_context_reference')
    definition = _option(declared.field('definition'))
    require(declared.field('kind') == 'data' and definition is not None and
            definition.field('kind') == 'data', 'RT_METADATA_DEFINITION')
    storage = _lookup(roots[4].field('segments'), definition.field('segment'), budget, 'metadata_data_reference')
    initial, poison, undef = (storage.field(name) for name in ('initial', 'poison', 'undef'))
    budget.work(12 + len(initial) + len(poison) + len(undef))
    require(len(initial) == len(poison) == len(undef), 'RT_SEGMENT_SHADOW')
    require(all((int(p, 16) & int(u, 16)) == 0 for p, u in zip(poison, undef)), 'RT_SEGMENT_SHADOW')
    extent = len(initial) // 2 + storage.field('zero_fill')
    alignment = storage.field('alignment')
    require(extent <= MAX_U64 and 0 < alignment <= 1 << 63 and alignment & (alignment - 1) == 0,
            'RT_SEGMENT_EXTENT')
    require(storage.field('zero_shadow') in ('defined', 'poison', 'undef'), 'RT_SEGMENT_ZERO_SHADOW')
    require(_option(declared.field('size')) == extent, 'RT_METADATA_SYMBOL_EXTENT')
    require(not storage.field('mutable') and not any(char != '0' for char in poison) and
            not any(char != '0' for char in undef) and
            (storage.field('zero_fill') == 0 or storage.field('zero_shadow') == 'defined'),
            'RT_METADATA_INITIALIZED_READONLY')
    require(end <= extent, 'RT_METADATA_EXTENT')
    if 5 not in roots:
        _fail('SOURCE_DATA_EVIDENCE_UNAVAILABLE', 'source root5 required', 'unavailable')
    patches = _patches(roots, storage.field('id'), offset, end, extent, budget)
    first, last = min(offset, len(initial) // 2), min(end, len(initial) // 2)
    size = last - first
    budget.charge(work=3 * size, copied_bytes=3 * size, edges=2)
    prefix = memoryview(bytes.fromhex(initial[first * 2:last * 2]))
    return source_api()._make_local_source_data(stamp=context.source_stamp, symbol=reference,
        symbol_record=declared, storage=('self', storage.field('id')), offset=offset,
        length=length, symbol_extent=extent, backing_extent=extent,
        symbol_alignment=declared.field('alignment'), backing_alignment=alignment,
        prefix=prefix, zero_tail_bytes=length - size, patches=patches, budget=budget,
        check_snapshot=lambda *, stamp, budget: check_snapshot(context, stamp=stamp, budget=budget))


def _patches(roots, storage, start, end, extent, budget):
    leaves = roots[5].field('relocations')
    constants = roots[5].field('constant_initializers')
    budget.charge(work=len(leaves) + len(constants), edges=2 * (len(leaves) + len(constants)) + 1)
    result = []
    for tag, rows in (('leaf', leaves), ('constant', constants)):
        for ordinal, row in enumerate(rows):
            kind = row.field('source_kind')
            require(kind in ('data', 'tls'), 'RT_RELOCATION_SOURCE')
            if kind != 'data' or row.field('source') != storage:
                continue
            if tag == 'leaf':
                width = row.field('width')
            else:
                reference = row.field('layout')
                require(reference.field('module').field('kind') == 'self', 'RT_INITIALIZER_SELF')
                layout = _lookup(roots[1].field('memory_layouts'), reference.field('id'), budget,
                                 'layout_reference')
                width = layout.field('access_bytes')
            at = row.field('offset')
            finish = _range(at, width, 'RT_PATCH_EXTENT')
            require(finish <= extent, 'RT_RELOCATION_BOUNDS')
            if at < end and start < finish:
                budget.edges(2)
                result.append(source_api().DeclaredPatch(tag, 'data', ('self', storage), ordinal, at, finish, row))
    return tuple(result)
