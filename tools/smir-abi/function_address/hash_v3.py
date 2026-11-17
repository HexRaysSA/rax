"""Unconsumed HASH-V3-EXISTING-01 REV2 reference implementation.

Input is a source fragment {types, layouts, domains}, not an executable envelope.
Source syntax, references, arity, flags, completeness and layout associations are
checked here. Execution bindings, record geometry, native certificates and source
producer truth still require their independent ABI admission. A digest proves none
of them. The active V2 reader/hasher is neither imported nor replaced.

One explicit Budget covers capture, traversal, sorting and canonical ASCII output.
Inputs must not be mutated concurrently during capture. No host/native execution.
"""

from dataclasses import dataclass
from functools import cmp_to_key
import hashlib


DOMAIN = b'SMIR-NOMINAL-SHAPE-V3\0'
CONTRACT = 'b11fb65c95f80d6b211d78954c7d475e9fff22068ceb51c8f2dadbad81d3fad5'
MAX_ID = (1 << 32) - 2
MAX_OBJECT = (1 << 61) - 1
KINDS = frozenset(('void', 'scalar', 'bitint', 'enum', 'pointer', 'reference',
                  'member_pointer', 'array', 'vector', 'complex', 'record',
                  'atomic', 'function', 'handle', 'atomic_flag', 'snapshot'))
FLAGS = frozenset(('complete', 'union', 'class', 'trivial_copy', 'trivial_destroy',
                   'polymorphic', 'noexcept', 'variadic', 'nonnull', 'code',
                   'signed_char', 'flexible', 'native', 'scoped', 'fixed_base',
                   'c_linkage', 'c_compatible', 'lvalue_ref', 'rvalue_ref'))
EXPR_FLAGS = frozenset(('code', 'variadic', 'noexcept', 'c_linkage',
                       'lvalue_ref', 'rvalue_ref'))


class HashError(ValueError):
    """Local reference diagnostic; not a shared numeric diagnostic registration."""

    def __init__(self, kind, code):
        super().__init__(code)
        self.kind = kind
        self.code = code


def _require(condition, code):
    if not condition:
        raise HashError('semantic', code)


class Budget:
    """Cumulative logical work/edges/allocated payload bytes; no implicit ledger.

    A failed charge leaves all counters unchanged. Bytes count cumulative retained
    or temporary payload allocations conservatively, not Python allocator bytes.
    Depth bounds JSON containers and shortest discovered graph paths; cycles are
    handled by identity before descent. Node limit applies to DEF/EXPR states.
    """

    __slots__ = ('_limits', '_used')

    def __init__(self, *, max_work, max_edges, max_bytes, max_depth, max_nodes):
        values = (max_work, max_edges, max_bytes, max_depth, max_nodes)
        if not all(type(n) is int and n >= 0 for n in values) or not 1 <= max_depth <= 128:
            raise HashError('resource', 'HASH3_BUDGET')
        if hasattr(self, '_limits'):
            raise HashError('resource', 'HASH3_BUDGET')
        object.__setattr__(self, '_limits', values)
        object.__setattr__(self, '_used', [0, 0, 0])

    def __setattr__(self, name, value):
        raise AttributeError('hash budget has no policy/reset mutation')

    @property
    def used(self):
        return tuple(self._used)

    def charge(self, *, work=0, edges=0, size=0):
        values = (work, edges, size)
        if not all(type(n) is int and n >= 0 for n in values):
            raise HashError('resource', 'HASH3_BUDGET')
        result = tuple(a + b for a, b in zip(self._used, values))
        if any(value > limit for value, limit in zip(result, self._limits)):
            raise HashError('resource', 'HASH3_RESOURCE')
        self._used[:] = result

    def depth(self, value):
        if value > self._limits[3]:
            raise HashError('resource', 'HASH3_DEPTH')

    def nodes(self, value):
        if value > self._limits[4]:
            raise HashError('resource', 'HASH3_NODES')


def _budget(value):
    if type(value) is not Budget:
        raise HashError('resource', 'HASH3_BUDGET')
    return value


# Independent closed syntax for the existing source records. No active schema
# import, optional field insertion, producer hash comparison or CPP extensions.
RECORDS = {
    'module_ref': ('kind', {'self': (), 'dependency': (('slot', 'u32'),)}),
    'qref': (('module', 'module_ref'), ('id', 'u32')),
    'identity': (('language', 'token'), ('linkage', 'token'), ('entity', 'utf8'),
                 ('definition', 'digest'), ('library', '?digest'), ('unit', '?digest')),
    'method': (('name', 'utf8'), ('signature', 'qref'), ('virtual', 'bool'),
               ('slot', '?u32'), ('noexcept', 'bool')),
    'enumerator': (('name', 'utf8'), ('value', 'hex')),
    'input_field': (('name', '?utf8'), ('type', 'qref'), ('bit_width', '?u64'),
                    ('explicit_align', '?u32'), ('no_unique_address', 'bool'),
                    ('anonymous', 'bool'), ('access', 'token')),
    'input_base': (('type', 'qref'), ('virtual', 'bool'), ('access', 'token')),
    'input': (('revision', 'u32'), ('kind', 'token'), ('explicit_align', '?u32'),
              ('pod03', 'bool'), ('trivial', 'bool'), ('standard_layout', 'bool'),
              ('polymorphic', 'bool'), ('dynamic', 'bool'), ('empty', 'bool'),
              ('fields', '*input_field'), ('bases', '*input_base')),
    'type': (('id', 'u32'), ('domain', 'u32'), ('identity', 'identity'),
             ('kind', 'token'), ('qualifiers', '*token'), ('bits', 'u32'),
             ('signed', 'bool'), ('elements', '*qref'), ('extent', '?u64'),
             ('representation', 'token'), ('execution', '?qref'), ('layout', '?u32'),
             ('flags', '*token'), ('methods', '*method'), ('enumerators', '*enumerator'),
             ('record_input', '?input')),
    'field': (('declaration_index', 'u32'), ('name', 'utf8'), ('type', 'qref'),
              ('offset_bits', 'u64'), ('width_bits', 'u64'), ('flags', '*token')),
    'adjustment': ('kind', {
        'fixed': (('offset', 'i64'),),
        'virtual': (('vptr_offset', 'u64'), ('slot_bytes', 'i64'), ('addend', 'i64'))}),
    'base': (('type', 'qref'), ('offset', 'u64'), ('virtual', 'bool'),
             ('declaration_index', '?u32'), ('origin_path', '*u32'),
             ('adjustment', 'adjustment')),
    'vptr': (('offset', 'u64'), ('offset_top', 'i64'), ('rtti', '?qref'),
             ('slots', '*qref'), ('vcall_offsets', '*i64'), ('vbase_offsets', '*i64'),
             ('component_order', '*token')),
    'layout': (('id', 'u32'), ('type', 'qref'), ('size', 'u64'), ('align', 'u32'),
               ('data_size', 'u64'), ('nonvirtual_size', 'u64'),
               ('nonvirtual_align', 'u32'), ('fields', '*field'),
               ('bases', '*base'), ('vptrs', '*vptr')),
    'domain': (('id', 'u32'), ('isa', 'token'), ('personality', 'token'),
               ('abi', 'token'), ('compiler', 'digest'), ('runtime', 'digest'),
               ('build', 'digest'), ('library', 'digest'), ('abi_identity', 'digest')),
    'fragment': (('types', '*type'), ('layouts', '*layout'), ('domains', '*domain')),
}


def _keys(value, expected, budget):
    _require(type(value) is dict and len(value) == len(expected), 'HASH3_SHAPE')
    budget.charge(work=4 * len(value))
    _require(all(type(key) is str for key in value), 'HASH3_SHAPE')
    _require(all(name in value for name in expected), 'HASH3_SHAPE')


def _text(value, kind, budget):
    _require(type(value) is str, 'HASH3_SHAPE')
    # UTF-8 scalar scan plus token/hex validation; charge before either scan.
    budget.charge(work=4 * len(value))
    size = 0
    for ch in value:
        n = ord(ch)
        _require(not 0xd800 <= n <= 0xdfff, 'HASH3_UTF8')
        size += 1 if n < 128 else 2 if n < 2048 else 3 if n < 65536 else 4
    if kind == 'token':
        _require(bool(value) and all(ch.isascii() and (ch.isalnum() or ch in '_.-')
                                     for ch in value), 'HASH3_TOKEN')
    if kind in ('digest', 'hex'):
        _require(len(value) % 2 == 0 and all(ch in '0123456789abcdef' for ch in value),
                 'HASH3_HEX')
        _require(kind != 'digest' or len(value) == 64, 'HASH3_DIGEST')
    budget.charge(size=size)
    return value  # Strings are immutable; payload retention is still charged.


def _capture(kind, value, budget, depth=1):
    budget.depth(depth)
    budget.charge(work=1)
    if kind.startswith('?'):
        if value is None:
            return None
        _keys(value, ('some',), budget)
        budget.charge(edges=1, size=32)
        return {'some': _capture(kind[1:], value['some'], budget, depth + 1)}
    if kind.startswith('*'):
        _require(type(value) is list, 'HASH3_SHAPE')
        budget.charge(work=len(value), edges=len(value), size=8 * len(value))
        return [_capture(kind[1:], child, budget, depth + 1) for child in value]
    if kind in ('u32', 'u64', 'i64'):
        low, high = (-(1 << 63), (1 << 63) - 1) if kind == 'i64' else (0, (1 << int(kind[1:])) - 1)
        _require(type(value) is int and low <= value <= high, 'HASH3_INTEGER')
        budget.charge(size=8)
        return value
    if kind == 'bool':
        _require(type(value) is bool, 'HASH3_SHAPE')
        return value
    if kind in ('token', 'utf8', 'digest', 'hex'):
        return _text(value, kind, budget)
    grammar = RECORDS[kind]
    variant = grammar[0] == 'kind'
    if variant:
        _require(type(value) is dict and type(value.get('kind')) is str, 'HASH3_SHAPE')
        tag = _text(value['kind'], 'token', budget)
        _require(tag in grammar[1], 'HASH3_VARIANT')
        fields = grammar[1][tag]
    else:
        fields = grammar
    _keys(value, tuple(name for name, _ in fields) + (('kind',) if variant else ()), budget)
    budget.charge(work=len(fields), edges=len(fields), size=32 + 24 * len(fields))
    result = {'kind': tag} if variant else {}
    for name, child_kind in fields:
        result[name] = _capture(child_kind, value[name], budget, depth + 1)
    if kind == 'qref':
        _id(result['id'])
        if result['module']['kind'] == 'dependency':
            _id(result['module']['slot'])
    return result


def _option(value):
    return None if value is None else value['some']


def _id(value):
    _require(type(value) is int and 0 <= value <= MAX_ID, 'HASH3_ID')
    return value


def _alignment(value):
    _require(1 <= value <= 65536 and value & (value - 1) == 0, 'HASH3_ALIGNMENT')


def _sorted_strings(values, budget):
    budget.charge(work=len(values), size=8 * len(values))
    def compare(a, b):
        budget.charge(work=1 + len(a) + len(b))
        return (a > b) - (a < b)
    return sorted(values, key=cmp_to_key(compare))


def _unique(rows, budget):
    budget.charge(work=len(rows), size=64 * len(rows))
    result = {}
    for record in rows:
        identifier = _id(record['id'])
        _require(identifier not in result, 'HASH3_DUPLICATE_ID')
        result[identifier] = record
    return result


class SourceGraph:
    """Captured mathematical graph. Expectations map (owner,slot,decl) to LOCAL ID.

    No provider SELF transplant or selected-provider dictionary is accepted. Each
    source fragment has its own original namespace. This reference association is
    not a production phase proof. Queries must use the exact constructor ledger.
    """

    def __init__(self, documents, *, expectations, budget):
        self._budget = _budget(budget)
        budget.charge(work=1)
        _require(type(documents) is dict and type(expectations) is dict, 'HASH3_SHAPE')
        budget.charge(work=len(documents), size=128 * len(documents))
        self._documents, self._types, self._layouts, self._domains = {}, {}, {}, {}
        for owner, document in documents.items():
            _text(owner, 'utf8', budget)
            _require(bool(owner), 'HASH3_OWNER')
            captured = _capture('fragment', document, budget)
            self._documents[owner] = captured
            self._types[owner] = _unique(captured['types'], budget)
            self._layouts[owner] = _unique(captured['layouts'], budget)
            self._domains[owner] = _unique(captured['domains'], budget)
        budget.charge(work=len(expectations), size=96 * len(expectations))
        self._expectations = {}
        for key, target in expectations.items():
            _require(type(key) is tuple and len(key) == 3 and type(key[0]) is str,
                     'HASH3_EXPECTATION')
            owner, slot, declaration = key
            _require(owner in self._types, 'HASH3_OWNER')
            _id(slot); _id(declaration); _id(target)
            _require(target in self._types[owner], 'HASH3_REFERENCE')
            self._expectations[key] = target
        self._validate()

    def _resolve(self, owner, reference):
        self._budget.charge(work=1)
        _require(owner in self._types, 'HASH3_OWNER')
        identifier = _id(reference['id'])
        if reference['module']['kind'] == 'dependency':
            key = owner, _id(reference['module']['slot']), identifier
            _require(key in self._expectations, 'HASH3_UNBOUND_DECLARATION')
            identifier = self._expectations[key]
        _require(identifier in self._types[owner], 'HASH3_REFERENCE')
        return owner, identifier

    def _type(self, owner, reference):
        own, identifier = self._resolve(owner, reference)
        return self._types[own][identifier]

    def _validate(self):
        b = self._budget
        for owner, types in self._types.items():
            for item in types.values():
                b.charge(work=1)
                kind, flags = item['kind'], item['flags']
                b.charge(work=sum(map(len, flags)), size=64 * len(flags))
                f = set(flags)
                _require(kind in KINDS and len(flags) == len(f) and
                         f <= FLAGS, 'HASH3_KIND_FLAGS')
                q = item['qualifiers']
                b.charge(work=sum(map(len, q)), size=64 * len(q))
                qualifiers = set(q)
                _require(q == _sorted_strings(q, b) and len(q) == len(qualifiers) and
                         qualifiers <= {'const', 'volatile', 'restrict'}, 'HASH3_QUALIFIERS')
                _require(item['domain'] in self._domains[owner], 'HASH3_DOMAIN')
                identity = item['identity']
                _require(identity['language'] in ('c23', 'cpp23') and identity['entity'] and
                         identity['linkage'] in ('builtin', 'external', 'internal', 'local', 'odr_local'),
                         'HASH3_IDENTITY')
                _require((identity['unit'] is not None) ==
                         (identity['linkage'] in ('internal', 'local')), 'HASH3_UNIT')
                if kind in ('pointer', 'reference', 'member_pointer', 'function', 'array',
                            'vector', 'complex', 'atomic', 'bitint'):
                    _require(identity['linkage'] == 'builtin' and identity['entity'] == kind,
                             'HASH3_CONSTRUCTOR')
                _require(not item['signed'] or kind in ('scalar', 'bitint', 'enum'), 'HASH3_SIGNEDNESS')
                for flag, allowed in (
                    ('union', {'record'}), ('class', {'record'}), ('polymorphic', {'record'}),
                    ('variadic', {'function'}), ('noexcept', {'function'}),
                    ('c_linkage', {'function'}), ('code', {'pointer', 'reference'}),
                    ('flexible', {'array'}), ('scoped', {'enum'}), ('fixed_base', {'enum'}),
                    ('signed_char', {'scalar'}), ('c_compatible', {'record', 'enum'})):
                    _require(flag not in f or kind in allowed, 'HASH3_KIND_FLAGS')
                categories = f & {'lvalue_ref', 'rvalue_ref'}
                _require(len(categories) == 1 if kind == 'reference' else
                         len(categories) <= 1 if kind == 'function' else not categories,
                         'HASH3_REFERENCE_CATEGORY')
                _require('c_linkage' not in f or not categories, 'HASH3_KIND_FLAGS')
                b.charge(size=8 * len(item['elements']))
                children = [self._type(owner, child) for child in item['elements']]
                count = _option(item['extent'])
                if kind in ('pointer', 'reference', 'array', 'vector', 'complex', 'atomic', 'enum'):
                    _require(len(children) == 1, 'HASH3_ARITY')
                elif kind == 'member_pointer':
                    _require(len(children) == 2 and children[0]['kind'] == 'record', 'HASH3_ARITY')
                elif kind == 'function':
                    _require(count is not None and len(children) == count + 1, 'HASH3_ARITY')
                    _require(all(t['kind'] not in ('void', 'function', 'array') for t in children[:-1])
                             and children[-1]['kind'] not in ('function', 'array'), 'HASH3_FUNCTION')
                elif kind != 'record':
                    _require(not children, 'HASH3_ARITY')
                if kind not in ('array', 'vector', 'function'):
                    _require(count is None, 'HASH3_EXTENT')
                if kind == 'vector':
                    _require(count is not None and count > 0, 'HASH3_EXTENT')
                if kind in ('pointer', 'reference'):
                    _require(item['bits'] == 64 and
                             ('code' in f) == (children[0]['kind'] == 'function'), 'HASH3_POINTER')
                if kind == 'bitint':
                    _require((2 if item['signed'] else 1) <= item['bits'] <= 65535, 'HASH3_BITINT')
                complete = 'complete' in f
                layout = _option(item['layout'])
                if kind in ('void', 'function'):
                    _require(layout is None, 'HASH3_NONOBJECT_LAYOUT')
                if kind in ('record', 'array') and not complete:
                    _require(layout is None and item['record_input'] is None and
                             item['execution'] is None and item['representation'] == 'none',
                             'HASH3_INCOMPLETE')
                if kind == 'array':
                    _require(count is None or count > 0, 'HASH3_EXTENT')
                    expected = count is not None and 'complete' in children[0]['flags'] and children[0]['layout'] is not None
                    _require(complete == expected, 'HASH3_ARRAY_COMPLETENESS')
                _require(not complete or kind in ('void', 'function') or layout is not None,
                         'HASH3_LAYOUT_BINDING')
                if layout is not None:
                    _require(layout in self._layouts[owner] and
                             self._resolve(owner, self._layouts[owner][layout]['type']) == (owner, item['id']),
                             'HASH3_LAYOUT_BINDING')
                if kind != 'record':
                    _require(item['record_input'] is None and not item['methods'], 'HASH3_RECORD_INPUT')
                if kind == 'record' and complete and self._domains[owner][item['domain']]['isa'] == 'portable':
                    _require(item['record_input'] is not None, 'HASH3_RECORD_INPUT')
                if item['record_input'] is not None:
                    inp = _option(item['record_input'])
                    _require(inp['revision'] == 1 and inp['kind'] in ('struct', 'class', 'union'), 'HASH3_RECORD_INPUT')
                    _require(('union' in f) == (inp['kind'] == 'union') and
                             ('class' in f) == (inp['kind'] == 'class') and
                             ('polymorphic' in f) == inp['polymorphic'], 'HASH3_RECORD_INPUT')
                    if inp['explicit_align'] is not None:
                        _alignment(_option(inp['explicit_align']))
                    for field in inp['fields']:
                        self._type(owner, field['type'])
                        _require(field['access'] in ('public', 'protected', 'private'), 'HASH3_ACCESS')
                        if field['explicit_align'] is not None:
                            _alignment(_option(field['explicit_align']))
                    for base in inp['bases']:
                        _require(self._type(owner, base['type'])['kind'] == 'record' and
                                 base['access'] in ('public', 'protected', 'private'), 'HASH3_BASE')
                if identity['language'] == 'c23':
                    _require(not item['methods'], 'HASH3_METHOD')
                for method in item['methods']:
                    function = self._type(owner, method['signature'])
                    _require(function['kind'] == 'function' and
                             (method['slot'] is not None) == method['virtual'] and
                             method['noexcept'] == ('noexcept' in function['flags']), 'HASH3_METHOD')
                _require(not item['enumerators'] or kind == 'enum', 'HASH3_ENUM')
                if kind == 'enum':
                    _require(children[0]['kind'] in ('scalar', 'bitint') and
                             children[0]['bits'] == item['bits'] and children[0]['signed'] == item['signed'],
                             'HASH3_ENUM')
                    names = set()
                    for entry in item['enumerators']:
                        b.charge(work=len(entry['name']) + len(entry['value']))
                        _require(entry['name'] not in names and len(entry['value']) == 2 * ((item['bits'] + 7) // 8),
                                 'HASH3_ENUM')
                        if item['bits'] % 8:
                            b.charge(work=2, size=2)
                            _require(int(entry['value'][-2:], 16) < (1 << (item['bits'] % 8)), 'HASH3_ENUM')
                        b.charge(size=64); names.add(entry['name'])
                _require(item['representation'] in ('none', 'value', 'storage', 'signature', 'code_address'),
                         'HASH3_REPRESENTATION')
                _require((item['execution'] is None) == (item['representation'] == 'none'),
                         'HASH3_REPRESENTATION')
            for layout in self._layouts[owner].values():
                b.charge(work=1)
                item = self._type(owner, layout['type'])
                _require(_option(item['layout']) == layout['id'], 'HASH3_LAYOUT_BINDING')
                _alignment(layout['align']); _alignment(layout['nonvirtual_align'])
                _require(0 < layout['size'] <= MAX_OBJECT and layout['size'] % layout['align'] == 0 and
                         layout['data_size'] <= layout['size'] and layout['nonvirtual_size'] <= layout['size'],
                         'HASH3_LAYOUT_EXTENT')
                if self._domains[owner][item['domain']]['isa'] == 'portable' and item['kind'] != 'record':
                    _require(not layout['fields'] and not layout['bases'] and not layout['vptrs'],
                             'HASH3_NONRECORD_LAYOUT')
                for field in layout['fields']:
                    self._type(owner, field['type'])
                    b.charge(work=sum(map(len, field['flags'])), size=64 * len(field['flags']))
                    _require(len(field['flags']) == len(set(field['flags'])) and set(field['flags']) <=
                             {'bitfield', 'unnamed', 'anonymous', 'no_unique_address', 'protected', 'private', 'flexible'},
                             'HASH3_FIELD_FLAGS')
                    _require(field['offset_bits'] + field['width_bits'] <= 8 * layout['size'],
                             'HASH3_FIELD_EXTENT')
                for base in layout['bases']:
                    _require(self._type(owner, base['type'])['kind'] == 'record' and
                             base['offset'] <= layout['size'], 'HASH3_BASE')
                for vptr in layout['vptrs']:
                    order = vptr['component_order']
                    _require(all(k in ('vcall', 'vbase') for k in order) and
                             order.count('vcall') == len(vptr['vcall_offsets']) and
                             order.count('vbase') == len(vptr['vbase_offsets']), 'HASH3_VPTR')
        # By-value cycles are invalid; pointer/prototype syntax cycles are legal.
        active, done = set(), set()
        for owner, types in self._types.items():
            for identifier in types:
                pending = [(owner, identifier, False, 1)]
                while pending:
                    own, current, leave, depth = pending.pop()
                    key = own, current
                    b.charge(work=1)
                    if leave:
                        active.remove(key); done.add(key); continue
                    if key in done:
                        continue
                    _require(key not in active, 'HASH3_VALUE_CYCLE')
                    b.depth(depth); b.charge(size=96)
                    active.add(key); pending.append((own, current, True, depth))
                    item = self._types[own][current]
                    children = item['elements'] if item['kind'] in ('array', 'vector', 'atomic', 'enum', 'complex') else []
                    if item['kind'] == 'record' and item['layout'] is not None:
                        layout = self._layouts[own][_option(item['layout'])]
                        b.charge(size=16 * (len(layout['fields']) + len(layout['bases'])))
                        children = [r['type'] for r in layout['fields'] + layout['bases']]
                    b.charge(edges=len(children), size=48 * len(children))
                    for child in children:
                        child_owner, child_id = self._resolve(own, child)
                        pending.append((child_owner, child_id, False, depth + 1))

    def hash(self, owner, reference, *, budget, view='DEF', ignore_top_cv=False):
        _require(_budget(budget) is self._budget, 'HASH3_CONTEXT')
        _require(view in ('DEF', 'EXPR') and type(ignore_top_cv) is bool, 'HASH3_VIEW')
        _text(owner, 'utf8', budget)
        reference = _capture('qref', reference, budget)
        own, identifier = self._resolve(owner, reference)
        root = own, identifier, view
        budget.nodes(1); budget.charge(size=160)
        keys, indices, labels, edges = [root], {root: 0}, [], []
        cursor = 0
        depths = [1]
        while cursor < len(keys):
            budget.charge(work=1)
            own, identifier, mode = keys[cursor]
            item = self._types[own][identifier]
            label, children = self._label(own, item, mode)
            if cursor == 0 and ignore_top_cv:
                budget.charge(work=len(label['qualifiers']), size=8 * len(label['qualifiers']))
                label['qualifiers'] = [q for q in label['qualifiers'] if q not in ('const', 'volatile')]
            links = []
            budget.charge(edges=len(children), size=8 * len(children))
            for reference, child_mode in children:
                child_owner, child_id = self._resolve(own, reference)
                key = child_owner, child_id, child_mode
                if key not in indices:
                    depth = depths[cursor] + 1
                    budget.depth(depth); budget.nodes(len(keys) + 1)
                    budget.charge(size=160)
                    indices[key] = len(keys); keys.append(key); depths.append(depth)
                links.append(indices[key])
            labels.append(label); edges.append(links); cursor += 1
        encoded = _quotient(labels, edges, budget)
        budget.charge(work=len(DOMAIN) + len(encoded), size=96)
        hasher = hashlib.sha256()
        hasher.update(DOMAIN)
        hasher.update(encoded)
        digest = hasher.hexdigest()
        budget.charge(size=len(DOMAIN) + len(encoded) + 64)
        return HashResult(digest, DOMAIN + encoded, len(labels), sum(map(len, edges)))

    def _label(self, owner, item, mode):
        b = self._budget
        b.charge(work=1, size=512)
        identity = {k: item['identity'][k] for k in ('language', 'linkage', 'entity', 'library', 'unit')}
        label = {'kind': item['kind'], 'qualifiers': item['qualifiers'], 'identity': identity,
                 'abi_identity': self._domains[owner][item['domain']]['abi_identity']}
        if mode == 'EXPR' and item['kind'] in ('record', 'enum'):
            label['node_kind'] = 'nominal_declaration'
            return label, []
        if mode == 'EXPR':
            b.charge(work=len(item['flags']), size=8 * len(item['flags']))
            label.update(node_kind='nominal_expression', bits=item['bits'], signed=item['signed'],
                         extent=item['extent'], semantic_flags=_sorted_strings(
                             [flag for flag in item['flags'] if flag in EXPR_FLAGS], b),
                         element_count=len(item['elements']))
            b.charge(size=24 * len(item['elements']))
            return label, [(child, 'EXPR') for child in item['elements']]
        label.update(node_kind='nominal_definition', bits=item['bits'], signed=item['signed'],
                     extent=item['extent'], flags=_sorted_strings(item['flags'], b),
                     enumerators=item['enumerators'], element_count=len(item['elements']),
                     method_count=len(item['methods']), has_cpp_class=False)
        b.charge(size=96 * len(item['methods']))
        label['methods'] = [{k: m[k] for k in ('name', 'virtual', 'slot', 'noexcept')} for m in item['methods']]
        element_mode = 'EXPR' if item['kind'] in ('pointer', 'reference', 'member_pointer', 'function') else 'DEF'
        b.charge(size=24 * (len(item['elements']) + len(item['methods'])))
        children = [(child, element_mode) for child in item['elements']]
        children.extend((method['signature'], 'EXPR') for method in item['methods'])
        inp = _option(item['record_input'])
        label.update(record_input=None, input_field_count=0, input_base_count=0)
        if inp is not None:
            b.charge(size=256 + 160 * len(inp['fields']) + 64 * len(inp['bases']))
            label['record_input'] = {k: inp[k] for k in ('revision', 'kind', 'explicit_align', 'pod03',
                'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty')}
            label['record_input']['fields'] = [{k: f[k] for k in ('name', 'bit_width', 'explicit_align',
                'no_unique_address', 'anonymous', 'access')} for f in inp['fields']]
            label['record_input']['bases'] = [{k: base[k] for k in ('virtual', 'access')} for base in inp['bases']]
            label.update(input_field_count=len(inp['fields']), input_base_count=len(inp['bases']))
            b.charge(size=24 * (len(inp['fields']) + len(inp['bases'])))
            children.extend((f['type'], 'DEF') for f in inp['fields'])
            children.extend((base['type'], 'DEF') for base in inp['bases'])
        layout_id = _option(item['layout'])
        label.update(layout=None, output_field_count=0, output_base_count=0)
        if layout_id is not None:
            layout = self._layouts[owner][layout_id]
            b.charge(size=256 + 160 * len(layout['fields']) + 160 * len(layout['bases']) + 192 * len(layout['vptrs']))
            label['layout'] = {k: layout[k] for k in ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align')}
            label['layout']['fields'] = [{**{k: f[k] for k in ('declaration_index', 'name', 'offset_bits', 'width_bits')},
                                         'flags': _sorted_strings(f['flags'], b)} for f in layout['fields']]
            label['layout']['bases'] = [{k: base[k] for k in ('offset', 'virtual', 'declaration_index',
                'origin_path', 'adjustment')} for base in layout['bases']]
            label['layout']['vptrs'] = [{**{k: p[k] for k in ('offset', 'offset_top', 'vcall_offsets',
                'vbase_offsets', 'component_order')}, 'slot_count': len(p['slots'])} for p in layout['vptrs']]
            label.update(output_field_count=len(layout['fields']), output_base_count=len(layout['bases']))
            b.charge(size=24 * (len(layout['fields']) + len(layout['bases'])))
            children.extend((f['type'], 'DEF') for f in layout['fields'])
            children.extend((base['type'], 'DEF') for base in layout['bases'])
        b.charge(work=len(children))
        return label, children


@dataclass(frozen=True)
class HashResult:
    digest: str
    preimage: bytes
    states: int
    edges: int


def _ascii(value, budget, depth=1):
    """Exact ensure_ascii JSON without an uncharged json.dumps intermediate."""
    budget.depth(depth); budget.charge(work=1)
    if value is None or type(value) is bool:
        result = b'null' if value is None else b'true' if value else b'false'
        budget.charge(size=len(result))
        return result
    if type(value) is int:
        budget.charge(work=48, size=48)
        return str(value).encode('ascii')
    if type(value) is str:
        # Reserve escaped fragments, reference array, joined string and bytes
        # BEFORE any expansion, including non-BMP surrogate-pair output.
        budget.charge(work=48 * len(value) + 8, size=64 * len(value) + 64)
        chunks = ['"']
        escapes = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}
        for ch in value:
            n = ord(ch)
            if ch in escapes:
                chunks.append(escapes[ch])
            elif 32 <= n < 127:
                chunks.append(ch)
            elif n < 65536:
                chunks.append('\\u%04x' % n)
            else:
                n -= 65536
                chunks.append('\\u%04x\\u%04x' % (0xd800 + (n >> 10), 0xdc00 + (n & 1023)))
        chunks.append('"')
        result = ''.join(chunks).encode('ascii')
        return result
    if type(value) is list:
        budget.charge(work=len(value), size=8 * len(value))
        parts = [_ascii(child, budget, depth + 1) for child in value]
        size = 2 + max(0, len(parts) - 1) + sum(map(len, parts))
        budget.charge(work=3 * size, size=3 * size)
        return b'[' + b','.join(parts) + b']'
    _require(type(value) is dict, 'HASH3_INTERNAL_LABEL')
    budget.charge(size=8 * len(value))
    keys = _sorted_strings(list(value), budget)
    budget.charge(size=8 * len(keys))
    parts = []
    for key in keys:
        k, v = _ascii(key, budget, depth + 1), _ascii(value[key], budget, depth + 1)
        budget.charge(work=2 * (len(k) + len(v) + 1), size=2 * (len(k) + len(v) + 1))
        parts.append(k + b':' + v)
    size = 2 + max(0, len(parts) - 1) + sum(map(len, parts))
    budget.charge(work=3 * size, size=3 * size)
    return b'{' + b','.join(parts) + b'}'


def _quotient(labels, edges, budget):
    budget.charge(size=8 * len(labels))
    encoded = [_ascii(label, budget) for label in labels]
    def compare_labels(a, b):
        budget.charge(work=1 + len(encoded[a]) + len(encoded[b]))
        return (encoded[a] > encoded[b]) - (encoded[a] < encoded[b])
    budget.charge(work=4 * len(labels), size=32 * len(labels))
    order = sorted(range(len(labels)), key=cmp_to_key(compare_labels))
    colors, color, previous = [0] * len(labels), -1, None
    for current in order:
        if previous is None or compare_labels(previous, current):
            color += 1
        colors[current] = color; previous = current
    # Interned label colors retain exact byte equality; no hash-only equality.
    label_colors = colors[:]
    budget.charge(size=8 * len(colors))
    for _ in range(len(labels)):
        budget.charge(work=4 * len(labels) + 2 * sum(map(len, edges)),
                      size=64 * len(labels) + 16 * sum(map(len, edges)))
        signatures = [(label_colors[i], tuple(colors[c] for c in edges[i])) for i in range(len(labels))]
        def compare(a, b):
            budget.charge(work=2 + len(signatures[a][1]) + len(signatures[b][1]))
            return (signatures[a] > signatures[b]) - (signatures[a] < signatures[b])
        order = sorted(range(len(labels)), key=cmp_to_key(compare))
        updated, color, previous = [0] * len(labels), -1, None
        for current in order:
            if previous is None or compare(previous, current):
                color += 1
            updated[current] = color; previous = current
        stable = color + 1 == max(colors, default=-1) + 1
        colors = updated
        if stable:
            break
    budget.charge(work=len(colors), size=128 * len(colors))
    representatives = {}
    for index, color in enumerate(colors):
        representatives.setdefault(color, index)
    order, indices, records = [colors[0]], {colors[0]: 0}, []
    for color in order:
        index = representatives[color]
        budget.charge(work=len(edges[index]) + 1, size=64 + 8 * len(edges[index]))
        children = []
        for child in edges[index]:
            target = colors[child]
            if target not in indices:
                indices[target] = len(order); order.append(target)
            children.append(indices[target])
        records.append({'label': labels[index], 'children': children})
    return _ascii(records, budget)
