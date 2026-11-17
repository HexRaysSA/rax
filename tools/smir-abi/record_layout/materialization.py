"""Draft ABI-MATERIALIZATION-CONSUMER-01; declared source images, never authority.

The source ABI graph is input to an ongoing verifier, not an admission result.
A genuine prepared SourceData callback supplies immutable original source bytes.
No ABI/MetadataFacts prerequisite is introduced. N<=1MiB output bytes, V source
nodes, L scalar cells, P patches: O(V+E+N+P*L) plus charged source snapshot work;
O(V+E+N+L+P) image storage. The legacy complete-record compatibility fallback
additionally precharges conservative O(V^4*B) work/O(V^2*B) bytes (B input label
bound). Every new traversal/copy uses the original source ledger.
"""
from dataclasses import dataclass, field
import hashlib
import importlib.util
import math
from pathlib import Path
import sys
from types import MethodType, SimpleNamespace

from candidate_codec import encode
from layout import INTEGER_NAMES, MAX_OBJECT, SCALARS
from nominal import NominalGraph, option, ref
from .checked import CheckedRecords

ROOT = Path(__file__).resolve().parents[3]
MAX_IMAGE = 1 << 20


def _api():
    name = '_rax_smir_source_data_v1'
    path = ROOT / 'tools/smir-runtime-contract/source_roles/source_data.py'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
    if getattr(module, '__file__', None) is None or Path(module.__file__).resolve() != path.resolve():
        raise RuntimeError('ABI_MAT_SOURCE_MODULE_IDENTITY')
    return module


def _fail(code, detail='', kind='semantic'):
    raise _api().SourceDataError(kind, code, detail)


def _need(value, code, detail=''):
    if not value:
        _fail(code, detail)


def _qref(value):
    _need(type(value) is dict and set(value) == {'module', 'id'} and
          type(value['id']) is int and 0 <= value['id'] < 0xffffffff, 'ABI_MAT_REFERENCE')
    module = value['module']
    _need(type(module) is dict, 'ABI_MAT_REFERENCE')
    if module == {'kind': 'self'}:
        return ('self', value['id'])
    _need(set(module) == {'kind', 'slot'} and module['kind'] == 'dependency' and
          type(module['slot']) is int and 0 <= module['slot'] < 0xffffffff, 'ABI_MAT_REFERENCE')
    return ('dependency', module['slot'], value['id'])


def _charge_tree(value, budget, depth=1):
    """Precharge a conservative binary encoding bound before invoking the codec."""
    if depth > budget.max_depth:
        _fail('SOURCE_DATA_RESOURCE', 'materialization tree depth', 'resource')
    budget.work(1)
    if type(value) is dict:
        budget.charge(edges=len(value), copied_bytes=64 + 32 * len(value))
        return 8 + sum(_charge_tree(v, budget, depth + 1) for v in value.values())
    if type(value) in (list, tuple):
        budget.charge(edges=len(value), copied_bytes=16 + 8 * len(value))
        return 8 + sum(_charge_tree(v, budget, depth + 1) for v in value)
    if type(value) is str:
        budget.work(len(value))
        return 8 + 4 * len(value)
    _need(type(value) in (int, bool, type(None)), 'ABI_MAT_SHAPE')
    return 8


def _field(record, name, budget):
    budget.work(len(record.fields))
    return record.field(name)


def _plain(value, budget, depth=1):
    if depth > budget.max_depth:
        _fail('SOURCE_DATA_RESOURCE', 'materialization record depth', 'resource')
    budget.work(1)
    api = _api()
    if type(value) is api.FrozenRecord:
        budget.charge(edges=len(value.fields), copied_bytes=64 + 32 * len(value.fields))
        return {name: _plain(child, budget, depth + 1) for name, child in value.fields}
    if type(value) is tuple:
        budget.charge(edges=len(value), copied_bytes=16 + 8 * len(value))
        return [_plain(child, budget, depth + 1) for child in value]
    if type(value) is str:
        budget.charge(work=len(value), copied_bytes=4 * len(value))
    else:
        _need(type(value) in (int, bool, type(None)), 'ABI_MAT_SHAPE')
        budget.reserve_bytes(8)
    return value


def _same_wire(left, right, budget):
    """Exact primitive categories; Python True==1 is not wire equality."""
    budget.work(1)
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        budget.work(len(left))
        return left.keys() == right.keys() and all(
            _same_wire(child, right[name], budget) for name, child in left.items())
    if type(left) is list:
        budget.work(len(left))
        return len(left) == len(right) and all(
            _same_wire(a, b, budget) for a, b in zip(left, right))
    if type(left) is str:
        budget.work(len(left))
    return left == right


class _LayoutBudget:
    def __init__(self, budget):
        self.budget = budget

    def work(self, n=1):
        self.budget.work(n)

    def reserve(self, n):
        self.budget.reserve_bytes(n)


@dataclass(frozen=True, slots=True)
class DeclaredImage:
    stamp: object
    symbol: tuple
    storage: tuple
    nominal: tuple
    offset: int
    size: int
    alignment: int
    pre_relocation_bytes: bytes
    value_mask: bytes
    declared_leaves: tuple
    state: str
    production_admitted: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class _Cell:
    start: int
    width: int
    kind: str
    entity: str


def _context(context, budget):
    api = _api()
    if type(budget) is not api.SourceQueryBudget:
        _fail('SOURCE_DATA_BUDGET', kind='resource')
    callback = getattr(context, 'source_data', None)
    stamp = getattr(context, 'source_stamp', None)
    ledger = getattr(context, 'source_budget', None)
    if callback is None or stamp is None or ledger is None:
        _fail('ABI_MAT_SOURCE_UNAVAILABLE', kind='unavailable')
    _need(ledger is budget and type(stamp) is api.SourceStamp and type(callback) is MethodType,
          'SOURCE_DATA_CONTEXT')
    budget.work(32)
    owner, function = callback.__self__, callback.__func__
    cls = type(owner)
    module = sys.modules.get(cls.__module__)
    path = ROOT / 'tools/smir-format/execution/candidate/context.py'
    _need(module is not None and getattr(module, '__file__', None) is not None and
          Path(module.__file__).resolve() == path.resolve() and
          getattr(module, 'RootContext', None) is cls and function is cls.source_data and
          owner.source_stamp is stamp, 'SOURCE_DATA_CONTEXT')
    return callback, stamp, owner


def _bound_graph(graph, context, owner, stamp, budget):
    _need(type(graph) is NominalGraph and graph.module_id == context.module, 'ABI_MAT_GRAPH_CONTEXT')
    contract = graph.modules[graph.module_id]
    bound = _charge_tree(contract, budget)
    budget.charge(work=4 * bound, copied_bytes=2 * bound)
    raw = encode('abi_contract', contract)
    budget.charge(work=len(raw), copied_bytes=32)
    _need(hashlib.sha256(raw).digest() == dict(stamp.root_digests).get(10), 'ABI_MAT_GRAPH_CONTEXT')
    manifest = owner.sections[2]['manifest']
    family = manifest['key']
    identity = (family['namespace'], family['name'], family['abi_major'])
    budget.charge(work=len(identity[0]) + len(identity[1]), copied_bytes=128)
    actual_owner = identity[0] + ':' + identity[1] + ':' + str(identity[2])
    _need(graph.module_id == actual_owner and graph.families.get(actual_owner) == identity and
          context.families.get(actual_owner) == identity, 'ABI_MAT_GRAPH_OWNER')
    aliases = {}
    for dependency in manifest['dependencies']:
        budget.work(1)
        for declaration in dependency['declarations']:
            budget.work(1)
            if declaration['kind'] == 'nominal' and declaration['nominal'] is not None:
                expected = declaration['nominal']['some']
                _need(expected['module'] == {'kind': 'self'}, 'ABI_MAT_GRAPH_CONTEXT')
                budget.charge(edges=1, copied_bytes=128)
                aliases[dependency['slot'], declaration['id']] = expected['id']
    count = sum(len(contract[name]) for name in ('types', 'layouts', 'domains'))
    budget.charge(work=count, edges=3 * count, copied_bytes=256 * count + 128 * len(aliases))
    # Rebuild from the bound input. Mutable caller indexes/provider maps are not
    # evidence and never choose the expected source type in this consumer.
    fresh = NominalGraph(contract, actual_owner, families={actual_owner: identity},
                         nominal_expectations={actual_owner: aliases})
    original = fresh.compatible

    def charged_compatible(left, right, left_owner=None, right_owner=None, ignore_top_cv=False):
        budget.work(32)
        am, a = fresh.resolve(left, left_owner)
        bm, b = fresh.resolve(right, right_owner)
        if (am, a['id']) == (bm, b['id']):
            return True  # Reflexivity of the SAME actual bound source node.
        simple = (a['kind'] in {'scalar', 'bitint'} and b['kind'] == a['kind'] and
                  not a['elements'] and not b['elements'])
        n = 1 if simple else len(contract['types']) + 1
        # Legacy coinduction may normalize complete records at each paired node.
        # Precharge a conservative refinement/label bound before that unmetered
        # library call; never create its default independent resource ledger.
        budget.charge(work=16 * n**4 * (bound + 1), copied_bytes=8 * n**2 * (bound + 1))
        return original(left, right, left_owner, right_owner, ignore_top_cv)

    fresh.compatible = charged_compatible
    return fresh


class _ImageTypes:
    def __init__(self, graph, budget):
        self.graph, self.budget = graph, budget
        self.checked = CheckedRecords(graph, _LayoutBudget(budget))
        self.active = set()
        self.cells = []
        self.geometries = {}

    def geometry(self, reference, depth=1):
        b = self.budget
        if depth > b.max_depth:
            _fail('SOURCE_DATA_RESOURCE', 'source layout depth', 'resource')
        b.work(16)
        owner, item = self.graph.resolve(reference)
        identifier = item['id']
        if identifier in self.geometries:
            return self.geometries[identifier]
        _need(identifier not in self.active, 'ABI_CC_VALUE_CYCLE')
        _need('complete' in item['flags'] and item['layout'] is not None,
              'ABI_CC_INCOMPLETE_VALUE')
        b.work(len(self.graph.modules[owner]['domains']))
        domain = next(d for d in self.graph.modules[owner]['domains'] if d['id'] == item['domain'])
        if domain['isa'] != 'portable':
            _fail('ABI_MAT_NATIVE_UNAVAILABLE', kind='unavailable')
        self.active.add(identifier)
        try:
            layout = self.graph.layout(reference)
            size, align = layout['size'], layout['align']
            _need(type(size) is int and 0 <= size <= MAX_OBJECT and type(align) is int and
                  0 < align <= 65536 and align & (align - 1) == 0, 'ABI_MAT_LAYOUT')
            kind = item['kind']
            if kind == 'scalar':
                entity = item['identity']['entity']
                _need(entity in INTEGER_NAMES | {'float', 'double', 'long double', 'nullptr_t'}, 'ABI_MAT_SCALAR')
                expected = SCALARS[entity]
                _need(item['bits'] == (1 if entity in {'bool', '_Bool'} else
                                      expected[0] * 8), 'ABI_MAT_SCALAR')
                _need(item['signed'] == (entity in {'char', 'signed char', 'short', 'int', 'wchar_t',
                      'long', 'long long', 'ptrdiff_t', '__int128'}), 'ABI_MAT_SCALAR')
            elif kind == 'bitint':
                n = item['bits']
                _need(type(n) is int and (2 if item['signed'] else 1) <= n <= 65535, 'ABI_MAT_BITINT')
                q = (n + 7) // 8
                a = min(8, 1 << (q - 1).bit_length())
                expected = ((q + a - 1) // a * a, a)
            elif kind in ('pointer', 'reference'):
                _need(item['bits'] == 64 and len(item['elements']) == 1, 'ABI_MAT_POINTER')
                target = self.graph.resolve(item['elements'][0])[1]
                code = target['kind'] == 'function'
                _need(('code' in item['flags']) == code and item['representation'] ==
                      ('code_address' if code else 'value'), 'ABI_MAT_POINTER')
                expected = (8, 8)
            elif kind == 'enum':
                _need(len(item['elements']) == 1, 'ABI_MAT_ENUM')
                child = self.geometry(item['elements'][0], depth + 1)
                _need(child[1]['kind'] == 'bitint' or child[1]['kind'] == 'scalar' and
                      child[1]['identity']['entity'] in INTEGER_NAMES, 'ABI_MAT_ENUM')
                _need(item['bits'] == child[1]['bits'] and item['signed'] == child[1]['signed'], 'ABI_MAT_ENUM')
                expected = child[0]['size'], child[0]['align']
            elif kind == 'atomic_flag':
                expected = (1, 1)
            elif kind == 'atomic':
                child = self.geometry(item['elements'][0], depth + 1)[0]
                a = child['align'] if child['size'] > 16 else max(child['align'], 1 << (child['size'] - 1).bit_length())
                expected = ((child['size'] + a - 1) // a * a, a)
            elif kind in ('array', 'vector', 'complex'):
                _need(len(item['elements']) == 1, 'ABI_MAT_ELEMENT')
                child = self.geometry(item['elements'][0], depth + 1)[0]
                count = 2 if kind == 'complex' else option(item['extent'])
                _need(type(count) is int and count > 0, 'ABI_CC_ARRAY_COUNT')
                total = child['size'] * count
                if kind == 'vector':
                    _need(1 <= count and 0 < total <= 64, 'ABI_MAT_VECTOR')
                    a = 1 << (total - 1).bit_length()
                    expected = (a, a)
                else:
                    expected = (total, child['align'])
            elif kind == 'record':
                if 'union' in item['flags']:
                    _fail('ABI_MAT_UNION_UNAVAILABLE', 'active source member required', 'unavailable')
                self.checked.verify(reference)
                expected = size, align
            else:
                _fail('ABI_MAT_TYPE_UNAVAILABLE', kind, 'unavailable')
            _need((size, align) == expected, 'ABI_MAT_LAYOUT')
            b.charge(edges=1, copied_bytes=96)
            self.geometries[identifier] = layout, item
            return layout, item
        finally:
            self.active.remove(identifier)

    def cell(self, start, width, kind, entity=''):
        _need(width >= 0, 'ABI_MAT_LAYOUT')
        if width:
            self.budget.charge(work=1, edges=1, copied_bytes=96)
            self.cells.append(_Cell(start, width, kind, entity))

    def visit(self, reference, start=0, limit=None, depth=1):
        layout, item = self.geometry(reference, depth)
        b, kind = self.budget, item['kind']
        b.work(8)
        width = item['bits'] if limit is None else min(item['bits'], limit)
        if kind in ('scalar', 'bitint', 'enum', 'atomic_flag'):
            entity = item['identity']['entity']
            if limit is not None and entity in {'bool', '_Bool'}:
                entity = 'bool_bitfield'  # Adjacent field bits are not bool padding.
            self.cell(start, 1 if kind == 'atomic_flag' else width, kind, entity)
        elif kind in ('pointer', 'reference'):
            target = self.graph.resolve(item['elements'][0])[1]
            category = 'code_address' if target['kind'] == 'function' else 'data_address'
            self.cell(start, 64, kind, category)
        elif kind == 'atomic':
            self.visit(item['elements'][0], start, limit, depth + 1)
        elif kind in ('array', 'vector', 'complex'):
            child = item['elements'][0]
            stride = self.geometry(child, depth + 1)[0]['size'] * 8
            count = 2 if kind == 'complex' else option(item['extent'])
            if stride == 0:
                return  # Empty extension arrays have no value bits to expand.
            b.charge(work=count, edges=count, copied_bytes=16 * count)
            for i in range(count):
                self.visit(child, start + i * stride, None, depth + 1)
        else:
            for field in layout['fields']:
                b.work(1)
                if 'unnamed' not in field['flags'] and field['width_bits']:
                    self.visit(field['type'], start + field['offset_bits'],
                               field['width_bits'] if 'bitfield' in field['flags'] else None, depth + 1)
            for base in layout['bases']:
                b.work(1)
                _need(base['adjustment']['kind'] == 'fixed' and base['offset'] >= 0, 'ABI_MAT_BASE_UNAVAILABLE')
                self.visit(base['type'], start + base['offset'] * 8, None, depth + 1)
            for pointer in layout['vptrs']:
                self.cell(start + pointer['offset'] * 8, 64, 'vptr', 'data_address')


def _mask(cells, size, budget):
    budget.charge(work=size, copied_bytes=2 * size)
    result = bytearray(size)
    for cell in cells:
        _need(0 <= cell.start and cell.start + cell.width <= size * 8, 'ABI_MAT_LAYOUT')
        first, last = cell.start // 8, (cell.start + cell.width + 7) // 8
        budget.work(last - first)
        for index in range(first, last):
            lo, hi = max(cell.start, index * 8) - index * 8, min(cell.start + cell.width, index * 8 + 8) - index * 8
            result[index] |= ((1 << (hi - lo)) - 1) << lo
    return bytes(result)


def _step(step, budget):
    count = len(step['flags'])
    budget.charge(work=256 * count * max(1, count.bit_length()) + 1,
                  edges=count, copied_bytes=64 + 32 * count)
    _need(step['flags'] == sorted(set(step['flags'])) and
          set(step['flags']) <= {'inbounds', 'nuw', 'nusw'} and
          (not step['check_base'] or 'inbounds' in step['flags']), 'ABI_MAT_PATCH_OPTIONS')
    span = option(step['inrange'])
    _need(span is None or span['lower'] <= span['upper'], 'ABI_MAT_PATCH_OPTIONS')


def _target(record, owner, budget):
    reference = _qref(record['target'])
    if reference[0] == 'self':
        rows = owner.sections[2]['symbols']
        budget.work(len(rows))
        target = next((s for s in rows if s['id'] == reference[1]), None)
        _need(target is not None, 'ABI_MAT_PATCH_TARGET')
        kind = target['kind']
        definition = option(target['definition'])
        _need(record['kind'] != 'code_address' or definition is None or
              definition['kind'] != 'native', 'ABI_MAT_NATIVE_TARGET')
    else:
        dependencies = owner.sections[2]['manifest']['dependencies']
        budget.work(len(dependencies))
        dependency = next((d for d in dependencies if d['slot'] == reference[1]), None)
        _need(dependency is not None, 'ABI_MAT_PATCH_TARGET')
        budget.work(len(dependency['declarations']))
        target = next((d for d in dependency['declarations'] if d['id'] == reference[2]), None)
        _need(target is not None and target['kind'] == 'symbol', 'ABI_MAT_PATCH_TARGET')
        kind = target['symbol_kind']
    expected = {'data_address': {'data'}, 'data_integer': {'data'},
        'code_address': {'function', 'function_address', 'import'},
        'function_token': {'function'}, 'function_integer': {'function'},
        'import_token': {'import'}, 'import_integer': {'import'}, 'tls_offset': {'tls'}}
    _need(kind in expected[record['kind']], 'ABI_MAT_PATCH_TARGET')


def _constant_records(view, owner, budget):
    selected = [p for p in view.patches if p.tag == 'constant']
    if not selected:
        return
    if 7 not in owner.sections:
        _fail('SOURCE_DATA_EVIDENCE_UNAVAILABLE', 'original TLS root required for constant metadata', 'unavailable')
    # Reuse the existing independent R metadata validator, never its evaluator
    # or transaction constructors. Every adapter is an actual source resolver.
    name = '_rax_abi_materialization_runtime'
    path = ROOT / 'tools/smir-runtime-contract/candidate/__init__.py'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path,
            submodule_search_locations=[str(path.parent)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    _need(Path(module.__file__).resolve() == path.resolve(), 'ABI_MAT_RUNTIME_MODULE')
    validator = importlib.import_module(name + '.initialization')
    _need(Path(validator.__file__).resolve() == path.parent / 'initialization.py', 'ABI_MAT_RUNTIME_MODULE')
    count = sum(len(owner.sections[n][table]) for n, table in
        ((1, 'types'), (1, 'memory_layouts'), (2, 'symbols'), (5, 'relocations'), (7, 'segments')))
    initialized = sum(len(s['initial']) for s in owner.sections[4]['segments'])
    # Symbol alias paths/type comparisons and cross-write tests are finite. This
    # conservative precharge covers the unmetered legacy validator's upper bound
    # and each temporary bytes.fromhex extent check before it can allocate.
    budget.charge(work=len(selected) * ((count + 1) ** 3 + 4 * initialized),
                  edges=4 * (count + len(selected)),
                  copied_bytes=256 * (count + 1) ** 2 + 4 * initialized * len(selected))
    raw_bound = _charge_tree(owner.sections, budget)
    budget.charge(work=16 * raw_bound + (count + 1) ** 3, copied_bytes=8 * raw_bound)
    # Reconstruct genuine phase-independent resolvers from the bound raw roots.
    # Public derived indexes or instance callback replacements on the caller's
    # RootContext are not constant-body/type/layout evidence. This new context
    # issues NO ABI/execution/SourceData proof and allocates NO new source ledger;
    # original source queries/stamp/ledger remain the only byte authority.
    resolver = type(owner)(owner.sections)
    constants = []
    for patch in selected:
        actual = owner.sections[5]['constant_initializers'][patch.ordinal]
        _need(actual == _plain(patch.record, budget), 'SOURCE_DATA_CONTEXT')
        constants.append(actual)
    roots = dict(owner.sections)
    roots[5] = {**owner.sections[5], 'constant_initializers': constants}
    adapter = SimpleNamespace(storage_layout=resolver.layouts.get, function=resolver.function,
        execution=resolver.types.get, execution_equal=resolver.types.equal)
    validator.validate_records(roots, adapter)


def _patches(view, raw, cells, owner, budget):
    patches = view.patches
    budget.charge(work=len(patches) * (3 * len(cells) + len(patches)),
                  edges=len(patches), copied_bytes=(128 + 16 * len(cells)) * len(patches))
    _constant_records(view, owner, budget)
    occupied, leaves, unavailable = [], [], []
    for patch in patches:
        record = _plain(patch.record, budget)
        lo, hi = patch.start - view.offset, patch.end - view.offset
        _need(all(hi <= a or z <= lo for a, z in occupied), 'ABI_MAT_PATCH_OVERLAP')
        occupied.append((lo, hi))
        if patch.tag == 'constant':
            unavailable.append(('ABI_MAT_CONSTANT_CONTENT_UNAVAILABLE', 'constant program has not executed'))
            continue
        _need(patch.tag == 'leaf', 'ABI_MAT_PATCH_KIND')
        width, precision, kind = record['width'], record['integer_bits'], record['kind']
        integer = kind in {'data_integer', 'function_integer', 'import_integer'}
        _need(kind in {'data_address', 'data_integer', 'tls_offset', 'function_token',
                       'import_token', 'function_integer', 'import_integer', 'code_address'}, 'ABI_MAT_PATCH_KIND')
        _need(width > 0 and (precision > 0 and width == (precision + 7) // 8 if integer else
                            precision == 0 and width in (4, 8)), 'ABI_MAT_PATCH_WIDTH')
        for step in record['derivation']:
            _step(step, budget)
        _step(dict(offset=record['addend'], check_base=record['check_base'],
                   flags=record['flags'], inrange=record['inrange']), budget)
        if kind == 'code_address':
            _need(width == 8 and record['addend'] == 0 and not record['derivation'] and
                  not record['check_base'] and not record['flags'] and record['inrange'] is None,
                  'ABI_MAT_CODE_RELOCATION')
        elif kind not in {'data_address', 'data_integer'}:
            _need(not record['derivation'] and not record['check_base'] and not record['flags'] and
                  record['inrange'] is None, 'ABI_MAT_PATCH_OPTIONS')
            if kind in {'function_token', 'import_token'}:
                _need(width == 8 and record['addend'] == 0, 'ABI_MAT_CODE_RELOCATION')
        _target(record, owner, budget)
        if lo < 0 or hi > len(raw):
            unavailable.append(('ABI_MAT_PARTIAL_PATCH_UNAVAILABLE', 'whole original patch retained'))
            continue
        matching = [c for c in cells if c.start == lo * 8 and
                    c.width == (precision if integer else width * 8)]
        if kind in {'data_address', 'code_address'}:
            # A primary base and its derived class can name the same physical
            # vptr. Equal complete typed-cell coverage does not duplicate a write.
            _need(width == 8 and matching and all(c.entity == kind and
                  c.kind in {'pointer', 'reference', 'vptr'} for c in matching), 'ABI_MAT_PATCH_DESTINATION')
            _need(not any(raw[lo:hi]), 'ABI_MAT_PATCH_PLACEHOLDER')
        elif integer:
            _need(matching and all(c.kind in {'scalar', 'bitint', 'enum'} for c in matching),
                  'ABI_MAT_PATCH_DESTINATION')
            for cell in cells:
                first, last = max(cell.start, lo * 8), min(cell.start + cell.width, hi * 8)
                if first < last and not lo * 8 <= first <= last <= lo * 8 + precision:
                    # A raw integer leaf clears its last-byte nonvalue bits.
                    # A packed source initializer can intentionally cover more
                    # than one bit-field, but its source write association is
                    # absent here. Do not infer either preservation or illegality.
                    unavailable.append(('ABI_MAT_BITFIELD_RELOCATION_UNAVAILABLE',
                                        'source subfield write association required'))
        else:
            unavailable.append(('ABI_MAT_LEGACY_RELOCATION_UNAVAILABLE', kind))
            continue
        leaves.append(patch)
    if unavailable:
        _fail(*unavailable[0], kind='unavailable')
    return tuple(leaves)


def read_materialization(graph, context, nominal, symbol, offset=0, *, budget):
    """Read a source representation view; ready/deferred is never object admission."""
    callback, stamp, owner = _context(context, budget)
    original_nominal = _qref(nominal)
    _qref(symbol)
    first = callback(symbol, offset, 1, budget=budget)
    api = _api()
    if type(first) is api.DependencySourceData:
        _fail('ABI_MAT_DEPENDENCY_UNAVAILABLE', 'original expectation has no provider bytes', 'unavailable')
    _need(type(first) is api.LocalSourceData and first.stamp is stamp, 'SOURCE_DATA_CONTEXT')
    first.read(0, 0, budget=budget)
    fresh = _bound_graph(graph, context, owner, stamp, budget)
    types = _ImageTypes(fresh, budget)
    layout, _ = types.geometry(nominal)
    size, align = layout['size'], layout['align']
    if size == 0:
        _fail('ABI_MAT_ZERO_SIZE_UNAVAILABLE', 'SourceData requires a positive source query', 'unavailable')
    if size > MAX_IMAGE:
        _fail('SOURCE_DATA_RESOURCE', 'materialized image bound1MiB', 'resource')
    for declared in (first.symbol_alignment, first.backing_alignment):
        _need(type(declared) is int and declared > 0 and declared & (declared - 1) == 0, 'ABI_MAT_ALIGNMENT')
    _need(math.gcd(first.symbol_alignment, first.backing_alignment, offset) >= align, 'ABI_MAT_ALIGNMENT')
    types.visit(nominal)
    mask = _mask(types.cells, size, budget)
    view = callback(symbol, offset, size, budget=budget)
    _need(type(view) is api.LocalSourceData and view.stamp is stamp and
          view.symbol == first.symbol and view.storage == first.storage, 'SOURCE_DATA_CONTEXT')
    raw = view.read(0, size, budget=budget)
    try:
        leaves = _patches(view, raw, types.cells, owner, budget)
        budget.charge(work=len(types.cells) * len(leaves), copied_bytes=32 * len(leaves))
        covered = []
        for patch in leaves:
            record = patch.record
            precision = _field(record, 'integer_bits', budget)
            covered.append(((patch.start - offset) * 8,
                            precision or (patch.end - patch.start) * 8))
        for cell in types.cells:
            budget.work(1)
            patched = (cell.start, cell.width) in covered
            if patched:
                continue
            if cell.entity in {'bool', '_Bool'}:
                n = int.from_bytes(raw[cell.start // 8:(cell.start + cell.width + 7) // 8], 'little')
                # A full bool byte must be canonical, unlike ordinary padding.
                _need(n >> (cell.start % 8) in (0, 1), 'ABI_MAT_BOOL_REPRESENTATION')
            if cell.kind in {'pointer', 'reference', 'vptr'} or cell.entity == 'nullptr_t':
                value = int.from_bytes(raw[cell.start // 8:cell.start // 8 + 8], 'little')
                if cell.kind == 'reference' and value == 0:
                    _fail('ABI_MAT_NULL_REFERENCE')
                if cell.entity == 'nullptr_t' and value:
                    _fail('ABI_MAT_NULLPTR_REPRESENTATION')
                if value:
                    _fail('ABI_MAT_POINTER_ORIGIN_UNAVAILABLE', 'nonzero source bits have no declared origin', 'unavailable')
        budget.charge(work=1, edges=3, copied_bytes=192)
        result = DeclaredImage(stamp, view.symbol, view.storage, original_nominal, offset,
            size, align, raw, mask, leaves, 'deferred' if leaves else 'ready')
    finally:
        view.read(0, 0, budget=budget)
        _bound_graph(graph, context, owner, stamp, budget)
    return result


def check_materialization(graph, context, nominal, symbol, expected_bytes,
                          expected_leaves=(), offset=0, *, budget):
    """Compare unbound compiler expectations; no expectation is an authority."""
    image = read_materialization(graph, context, nominal, symbol, offset, budget=budget)
    _need(type(expected_bytes) is bytes and type(expected_leaves) is tuple, 'ABI_MAT_EXPECTATION')
    budget.charge(work=len(expected_bytes), copied_bytes=16 + 8 * len(expected_leaves))
    _need(image.pre_relocation_bytes == expected_bytes, 'ABI_MAT_BYTES_MISMATCH')
    actual = tuple(_plain(p.record, budget) for p in image.declared_leaves)
    _need(len(actual) == len(expected_leaves), 'ABI_MAT_RELOCATION_MISMATCH')
    for a, e in zip(actual, expected_leaves):
        _charge_tree(e, budget)
        _need(_same_wire(a, e, budget), 'ABI_MAT_RELOCATION_MISMATCH')
    # The retained result's own read rechecks actual source; the graph also remains
    # bound to the same original snapshot. No callbacks/booleans replace checks.
    callback, stamp, owner = _context(context, budget)
    callback(symbol, offset, image.size, budget=budget).read(0, 0, budget=budget)
    _bound_graph(graph, context, owner, stamp, budget)
    return image
