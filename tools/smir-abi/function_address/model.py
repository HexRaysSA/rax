"""API6 actual-first ordinary source call compatibility; no runtime authority.

Only canonical privately issued SourceCallContext inputs and one existing S014
budget are accepted. Full paired structures are compared, never their hashes.
P paired graph nodes, F scalar/edge metadata, and Q full source revalidations of
cost S require O(P+F+Q*S) work and O(P+F_live) traversal storage. Quotas are logical
work/edges/payload bytes/depth, not allocator or execution-time guarantees.
"""

from collections.abc import Mapping

from .execution_compare import _source_api, _validate_both, _depth, _fail, same_execution_shape


_DOMAIN = ('isa', 'personality', 'abi', 'abi_identity')
_IDENTITY = ('language', 'linkage', 'entity', 'library', 'unit')
_EXPR_FLAGS = {'code', 'variadic', 'noexcept', 'c_linkage', 'lvalue_ref', 'rvalue_ref'}
_C_ALIASES = {'size_t': 'unsigned long', 'ptrdiff_t': 'long', 'wint_t': 'unsigned int',
              'wchar_t': 'int', 'char8_t': 'unsigned char', 'char16_t': 'unsigned short',
              'char32_t': 'unsigned int'}


def _plain(value, budget, depth=1):
    """Precharged bounded local descriptor copies, including exact UTF-8 size."""
    _depth(budget, depth)
    budget.work(1)
    if isinstance(value, Mapping):
        budget.charge(work=len(value), edges=len(value), copied_bytes=64 + 32 * len(value))
        return {key: _plain(child, budget, depth + 1) for key, child in value.items()}
    if type(value) in (tuple, list):
        budget.charge(work=len(value), edges=len(value), copied_bytes=16 + 8 * len(value))
        return [_plain(child, budget, depth + 1) for child in value]
    if type(value) is str:
        budget.work(len(value))
        size = sum(1 if ord(c) < 128 else 2 if ord(c) < 2048 else 3 if ord(c) < 65536 else 4 for c in value)
        budget.reserve_bytes(size)
    else:
        budget.reserve_bytes(8)
    return value


def _option(value):
    return None if value is None else value['some']


def _ref(identifier, budget):
    budget.charge(work=1, edges=2, copied_bytes=64)
    return {'module': {'kind': 'self'}, 'id': identifier}


def _select(record, names, budget):
    budget.charge(work=len(names), copied_bytes=64 + 32 * len(names))
    return {name: _plain(record[name], budget) for name in names}


class _Comparison:
    def __init__(self, actual, expected, budget):
        budget.charge(work=1, edges=3, copied_bytes=128)
        self.actual, self.expected, self.budget = actual, expected, budget
        self.c_view = False
        self.rows = {}
        self.families = None

    def row(self, view, namespace, reference, *, trusted=False):
        # Only immutable child qrefs previously obtained from genuine rows, or
        # explicit local refs made from checked row IDs, may use this cache.
        # Both public root arguments always go through the real record() parser.
        self.budget.charge(work=16, edges=1, copied_bytes=48)
        module = reference['module'] if trusted else None
        key = ((id(view), namespace, module['kind'], module.get('slot'), reference['id'])
               if trusted else None)
        if key is not None and key in self.rows:
            return self.rows[key]
        result = view.record(namespace, reference, budget=self.budget)
        if key is None:
            module = result.original_reference['module']
            self.budget.reserve_bytes(48)
            key = (id(view), namespace, module['kind'], module.get('slot'), result.original_reference['id'])
        self.budget.charge(work=1, edges=1, copied_bytes=128)
        self.rows[key] = result
        return result

    def local(self, view, namespace, identifier):
        return self.row(view, namespace, _ref(identifier, self.budget), trusted=True).record

    def domain(self, view, record):
        return _select(self.local(view, 'domain', record['domain']), _DOMAIN, self.budget)

    def describe(self, view, item, definition):
        b = self.budget
        b.charge(work=1, copied_bytes=512)
        kind = item['kind']
        label = _select(item, ('kind', 'qualifiers'), b)
        label['identity'] = _select(item['identity'], _IDENTITY, b)
        if label['identity']['linkage'] in ('internal', 'local'):
            if self.families is None:
                b.charge(work=1, edges=2, copied_bytes=32)
                self.families = (self.actual.module_family(budget=b), self.expected.module_family(budget=b))
            if self.families[0] != self.families[1]:
                return None, ()
        label['abi_identity'] = self.local(view, 'domain', item['domain'])['abi_identity']
        if self.c_view:
            if kind in ('reference', 'member_pointer', 'handle', 'snapshot'):
                return None, ()
            label['identity']['language'] = 'c23'
            if kind == 'scalar':
                entity = label['identity']['entity']
                label['identity']['entity'] = _C_ALIASES.get(entity, entity)
        if not definition and kind in ('record', 'enum'):
            label['node_kind'] = 'nominal_declaration'
            return label, ()
        b.charge(work=len(item['flags']), copied_bytes=8 * len(item['flags']))
        flags = sorted(item['flags'])
        if self.c_view:
            flags = [f for f in flags if f not in ('c_linkage', 'c_compatible') and
                     not (kind in ('record', 'enum') and f in ('class', 'fixed_base'))]
        label.update(_select(item, ('bits', 'signed', 'extent'), b))
        elements = item['elements']
        label['element_count'] = len(elements)
        b.charge(edges=len(elements), copied_bytes=24 * len(elements))
        if not definition:
            label.update(node_kind='nominal_expression', semantic_flags=[f for f in flags if f in _EXPR_FLAGS])
            return label, [(child, False) for child in elements]
        label.update(node_kind='nominal_definition', flags=flags,
                     enumerators=_plain(item['enumerators'], b), method_count=len(item['methods']),
                     has_cpp_class=False, record_input=None, input_field_count=0, input_base_count=0,
                     layout=None, output_field_count=0, output_base_count=0)
        child_mode = kind not in ('pointer', 'reference', 'member_pointer', 'function')
        children = [(child, child_mode) for child in elements]
        methods = item['methods']
        b.charge(edges=len(methods), copied_bytes=128 * len(methods))
        label['methods'] = [_select(method, ('name', 'virtual', 'slot', 'noexcept'), b) for method in methods]
        children.extend((method['signature'], False) for method in methods)
        source = _option(item['record_input'])
        if source is not None:
            sf, sb = source['fields'], source['bases']
            label['record_input'] = _select(source, ('revision', 'kind', 'explicit_align', 'pod03',
                'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty'), b)
            label['record_input']['fields'] = [_select(field, ('name', 'bit_width', 'explicit_align',
                'no_unique_address', 'anonymous', 'access'), b) for field in sf]
            label['record_input']['bases'] = [_select(base, ('virtual', 'access'), b) for base in sb]
            label.update(input_field_count=len(sf), input_base_count=len(sb))
            b.charge(edges=len(sf) + len(sb), copied_bytes=24 * (len(sf) + len(sb)))
            children.extend((field['type'], True) for field in sf)
            children.extend((base['type'], True) for base in sb)
            if self.c_view:
                projection = label['record_input']
                if projection['kind'] == 'class':
                    projection['kind'] = 'struct'
                for key in ('pod03', 'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty'):
                    projection[key] = False
        layout_id = _option(item['layout'])
        if layout_id is not None:
            layout = self.local(view, 'layout', layout_id)
            fields, bases, vptrs = layout['fields'], layout['bases'], layout['vptrs']
            if self.c_view and kind in ('record', 'enum'):
                if ('trivial_copy' not in item['flags'] or 'trivial_destroy' not in item['flags'] or
                        item['methods'] or 'scoped' in item['flags'] or
                        item['identity']['language'] == 'cpp23' and 'c_compatible' not in item['flags']):
                    return None, ()
                if kind == 'record' and (not fields or bases or vptrs or any(
                        set(field['flags']) & {'private', 'protected', 'no_unique_address'} for field in fields)):
                    return None, ()
            label['layout'] = _select(layout, ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align'), b)
            label['layout']['fields'] = [_select(field, ('declaration_index', 'name', 'offset_bits',
                                                        'width_bits', 'flags'), b) for field in fields]
            for field in label['layout']['fields']:
                field['flags'].sort()
            label['layout']['bases'] = [_select(base, ('offset', 'virtual', 'declaration_index',
                                                      'origin_path', 'adjustment'), b) for base in bases]
            label['layout']['vptrs'] = [_select(ptr, ('offset', 'offset_top', 'vcall_offsets',
                                                     'vbase_offsets', 'component_order'), b) |
                                      {'slot_count': len(ptr['slots'])} for ptr in vptrs]
            label.update(output_field_count=len(fields), output_base_count=len(bases))
            b.charge(edges=len(fields) + len(bases), copied_bytes=24 * (len(fields) + len(bases)))
            children.extend((field['type'], True) for field in fields)
            children.extend((base['type'], True) for base in bases)
        return label, children

    def source(self, left, right, *, definition=True, root_noexcept=False):
        b = self.budget
        b.charge(work=1, edges=1, copied_bytes=96)
        pending, seen = [(left, right, definition, 1, True)], set()
        while pending:
            ar, br, mode, depth, root = pending.pop()
            a = self.row(self.actual, 'nominal', ar, trusted=True)
            c = self.row(self.expected, 'nominal', br, trusted=True)
            b.charge(work=1, copied_bytes=32)
            pair = a.local_reference['id'], c.local_reference['id'], mode, root and root_noexcept
            if pair in seen:
                continue
            _depth(b, depth)
            al, ae = self.describe(self.actual, a.record, mode)
            bl, be = self.describe(self.expected, c.record, mode)
            if al is None or bl is None:
                return False
            if root and root_noexcept:
                for label in (al, bl):
                    label['flags'] = [f for f in label['flags'] if f != 'noexcept']
            if al != bl or len(ae) != len(be):
                return False
            b.charge(work=1, edges=1, copied_bytes=64)
            seen.add(pair)
            for (ac, am), (bc, bm) in zip(ae, be):
                if am != bm:
                    return False
                b.charge(work=1, edges=1, copied_bytes=40)
                pending.append((ac, bc, am, depth + 1, False))
        return True

    def source_lists(self, left, right):
        if len(left) != len(right):
            return False
        self.budget.charge(work=len(left), edges=len(left))
        return all(self.source(a, b) for a, b in zip(left, right))

    def recipe(self, left, right):
        a, b = _option(left), _option(right)
        if a is None or b is None:
            return a is b
        ar, br = self.local(self.actual, 'recipe', a), self.local(self.expected, 'recipe', b)
        if self.domain(self.actual, ar) != self.domain(self.expected, br):
            return False
        ap, bp = ar['params'], br['params']
        self.budget.charge(work=len(ap) + len(bp), copied_bytes=8 * (len(ap) + len(bp)))
        return self.source_lists([p['type'] for p in ap], [p['type'] for p in bp]) and self.source_lists(ar['results'], br['results'])

    def compare(self, actual_ref, expected_ref):
        a = self.row(self.actual, 'signature', actual_ref).record
        b = self.row(self.expected, 'signature', expected_ref).record
        af = self.row(self.actual, 'nominal', a['function_type'], trusted=True).record
        bf = self.row(self.expected, 'nominal', b['function_type'], trusted=True).record
        if a['this_type'] is not None or b['this_type'] is not None or a['vtt'] or b['vtt']:
            return False
        ad, bd = self.domain(self.actual, af), self.domain(self.expected, bf)
        if ad['isa'] != 'portable' or bd['isa'] != 'portable':
            _fail('unavailable', 'ABI_CC_NATIVE_CALL', 'actual portable-facing ordinary plans required')
        if ad != bd:
            return False
        ac, bc = 'c_linkage' in af['flags'], 'c_linkage' in bf['flags']
        if ac != bc or not a['noexcept'] and b['noexcept']:
            return False
        self.c_view = ac and bc
        if not self.source(a['function_type'], b['function_type'], root_noexcept=True):
            return False
        for name in ('variadic', 'return_noundef'):
            if a[name] != b[name]:
                return False
        if not self.source_lists(a['params'], b['params']) or not self.source_lists(a['lowered_results'], b['lowered_results']):
            return False
        ar, br = _option(a['result']), _option(b['result'])
        if (ar is None) != (br is None) or ar is not None and not self.source(ar, br):
            return False
        ap, bp = a['lowered_params'], b['lowered_params']
        if len(ap) != len(bp):
            return False
        for x, y in zip(ap, bp):
            if _select(x, ('source_index', 'role', 'mode', 'align', 'bytes', 'noundef'), self.budget) != _select(
                    y, ('source_index', 'role', 'mode', 'align', 'bytes', 'noundef'), self.budget):
                return False
            if not self.source(x['source_type'], y['source_type']) or not self.source(x['value_type'], y['value_type']):
                return False
            if not all(self.recipe(x[name], y[name]) for name in ('copy', 'move', 'destroy')):
                return False
        av, bv = _option(a['varargs']), _option(b['varargs'])
        if (av is None) != (bv is None):
            return False
        if av is not None:
            if _select(av, ('header_bytes', 'cookie_scope', 'type_reference'), self.budget) != _select(
                    bv, ('header_bytes', 'cookie_scope', 'type_reference'), self.budget):
                return False
            al = self.local(self.actual, 'layout', av['state_layout'])
            bl = self.local(self.expected, 'layout', bv['state_layout'])
            if not self.source(al['type'], bl['type']):
                return False
        return same_execution_shape(self.actual, a['execution'], self.expected, b['execution'], budget=self.budget)


def ordinary_address_call_compatible(actual_context, actual_reference,
                                     expected_context, expected_reference, *, budget):
    """Actual-first API6 compatibility; boolean grants no provider/entry rights."""
    api = _source_api()
    _validate_both(api, actual_context, expected_context, budget)
    actual_site = _plain(actual_context.site(budget=budget), budget)
    expected_site = _plain(expected_context.site(budget=budget), budget)
    result = False
    if actual_site == expected_site:
        result = _Comparison(actual_context, expected_context, budget).compare(actual_reference, expected_reference)
    _validate_both(api, actual_context, expected_context, budget)
    return result
