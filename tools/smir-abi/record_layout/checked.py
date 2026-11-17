"""Checked ABI2 source binding and independent selected-layout comparison.

Source AST traits are producer facts. This validates representable structural
relationships and derives geometry, not provenance of arbitrary C++ source text.
Native selected geometry is never recomputed using portable TypeInfo.
"""
import re
import factory_meter as M

from layout import ABIError, INTEGER_NAMES, require
from nominal import option, ref
from .model import ArrayType, Budget, Model, ModelError, RecordType, ScalarType

GENERATED = re.compile(r'^\$(anonymous|unnamed)(0|[1-9][0-9]*)$')
ACCESS = {'public', 'protected', 'private'}


def source_input(item):
    return option(item['record_input'])


def field_name(field, index):
    name = option(field['name'])
    return name if name is not None else ('$anonymous' if field['anonymous'] else '$unnamed') + str(index)


def alignment_request(value):
    if value is not None:
        require(0 < value <= 65536 and value & (value - 1) == 0, 'ABI_CC_SOURCE_ALIGNMENT')
    return value


class CheckedRecords:
    def __init__(self, graph, budget=None):
        self.graph = graph
        self.budget = budget or Budget()
        self.records = {}
        self.origins = {}
        self.active = set()
        self.aliases = {}
        self.model = Model(self.records, self.budget)

    def canonical_class(self, owner, item):
        """Canonical declaration identity: erase only top cv, never pointee cv."""
        M.model_row(self.budget,item)
        identity = item['identity']
        domain = next(d for d in self.graph.modules[owner]['domains'] if d['id'] == item['domain'])
        private = self.graph.families[owner] if identity['linkage'] in ('internal', 'local') else None
        return (domain['abi_identity'], identity['language'], identity['linkage'], identity['entity'],
                option(identity['library']), option(identity['unit']), private)

    def bind(self, reference, owner=None, flexible=False):
        self.budget.work()
        owner, item = self.graph.resolve(reference, owner)
        reference = ref(item['id'])  # SELF in this ACTUAL owner, not caller scope.
        kind = item['kind']
        if kind == 'record':
            key = self.canonical_class(owner, item)
            current = owner, item['id']
            if current in self.active:
                raise ABIError('ABI_CC_VALUE_CYCLE')
            if key in self.records:
                previous_owner, previous_id = self.origins[key]
                require(self.graph.compatible(ref(previous_id), ref(item['id']), previous_owner, owner,
                                              ignore_top_cv=True), 'ABI_CC_SOURCE_CLASS_CONFLICT')
                return RecordType(key)
            require(len(self.active) < 128, 'ABI_CC_RECORD_DEPTH')
            self.active.add(current)
            try:
                self.records[key] = self.normalize(owner, item)
                self.origins[key] = current
                self.budget.reserve(256)
            finally:
                self.active.remove(current)
            return RecordType(key)
        if kind == 'array':
            require(len(item['elements']) == 1, 'ABI_CC_ELEMENT_TYPE')
            count = option(item['extent'])
            require(count is not None or flexible, 'ABI_CC_INCOMPLETE_MEMBER')
            return ArrayType(self.bind(item['elements'][0], owner), count)
        require('complete' in item['flags'] and kind not in ('void', 'function', 'handle'),
                'ABI_CC_INCOMPLETE_MEMBER')
        shape = self.graph.layout(reference, owner)
        integral = kind in ('bitint', 'enum') or kind == 'scalar' and item['identity']['entity'] in INTEGER_NAMES
        return ScalarType(shape['size'], shape['align'], item['bits'], integral)

    def normalize(self, owner, item):
        M.model_row(self.budget,item)
        data = source_input(item)
        require(data is not None and data['revision'] == 1, 'ABI_CC_RECORD_INPUT')
        require(data['kind'] in ('struct', 'class', 'union'), 'ABI_CC_RECORD_KIND')
        flags = set(item['flags'])
        require(('union' in flags) == (data['kind'] == 'union') and
                ('class' in flags) == (data['kind'] == 'class') and
                ('polymorphic' in flags) == data['polymorphic'], 'ABI_CC_RECORD_FLAGS')
        cpp = item['identity']['language'] == 'cpp23'
        if not cpp:
            require(data['kind'] != 'class' and not data['bases'] and
                    not any(data[k] for k in ('pod03', 'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty')),
                    'ABI_CC_C_RECORD_TRAITS')
        if data['kind'] == 'union':
            require(not data['bases'] and not data['dynamic'] and not data['polymorphic'], 'ABI_CC_UNION_BASES')
        result = {k: data[k] for k in ('kind', 'pod03', 'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty')}
        result.update(language=item['identity']['language'],
                      explicit_align=alignment_request(option(data['explicit_align'])), fields=[], bases=[])
        self.budget.work(len(data['fields']) + len(data['bases']))
        self.budget.reserve(256 * (len(data['fields']) + len(data['bases'])))
        names = set()
        for index, field in enumerate(data['fields']):
            name, width = option(field['name']), option(field['bit_width'])
            anonymous = field['anonymous']
            require(field['access'] in ACCESS, 'ABI_CC_FIELD_ACCESS')
            require(cpp or field['access'] == 'public', 'ABI_CC_C_FIELD_ACCESS')
            require(cpp or not field['no_unique_address'], 'ABI_CC_C_FIELD_NUA')
            if name is not None:
                require(bool(name) and '\0' not in name, 'ABI_CC_FIELD_NAME')
                require(not GENERATED.fullmatch(name), 'ABI_CC_FIELD_NAME_RESERVED')
                if name.startswith('$capture'):
                    require(name == '$capture' + str(index) and not anonymous and width is None,
                            'ABI_CC_CAPTURE_FIELD_NAME')
                require(name not in names and not anonymous, 'ABI_CC_FIELD_NAME')
                names.add(name)
            else:
                require(width is not None or anonymous, 'ABI_CC_FIELD_UNNAMED')
            _, field_type = self.graph.resolve(field['type'], owner)
            if anonymous:
                require(name is None and width is None and field_type['kind'] == 'record', 'ABI_CC_ANONYMOUS_MEMBER')
                child_input = source_input(field_type)
                require(child_input is not None and (not cpp or child_input['kind'] == 'union'),
                        'ABI_CC_ANONYMOUS_MEMBER')
            flexible = field_type['kind'] == 'array' and option(field_type['extent']) is None
            if flexible:
                require(not cpp and data['kind'] != 'union' and index == len(data['fields']) - 1 and
                        any(option(f['name']) is not None for f in data['fields'][:index]) and
                        width is None and name is not None, 'ABI_CC_FLEXIBLE_MEMBER')
            typ = self.bind(field['type'], owner, flexible)
            if isinstance(typ, RecordType):
                require(not self.records[typ.key].get('flexible'), 'ABI_CC_NESTED_FLEXIBLE')
            if isinstance(typ, ArrayType):
                elem = typ.element
                while isinstance(elem, ArrayType):
                    elem = elem.element
                if isinstance(elem, RecordType):
                    require(not self.records[elem.key].get('flexible'), 'ABI_CC_NESTED_FLEXIBLE')
            request = alignment_request(option(field['explicit_align']))
            if width is not None:
                require(isinstance(typ, ScalarType) and typ.integral and not anonymous and
                        request is None and not field['no_unique_address'], 'ABI_CC_BITFIELD_TYPE')
                require(width > 0 or name is None, 'ABI_CC_BITFIELD_WIDTH')
                require(cpp or width <= typ.value_bits, 'ABI_CC_BITFIELD_WIDTH')
            else:
                require(request is None or request >= self.model.type_layout(typ).align,
                        'ABI_CC_SOURCE_ALIGNMENT_WEAK')
            result['fields'].append(dict(name=name, type=typ, bit_width=width, explicit_align=request,
                                         anonymous=anonymous, no_unique_address=field['no_unique_address'],
                                         access=field['access']))
        direct = set()
        for base in data['bases']:
            require(base['access'] in ACCESS, 'ABI_CC_BASE_ACCESS')
            typ = self.bind(base['type'], owner)
            require(isinstance(typ, RecordType) and typ.key not in direct and
                    self.records[typ.key]['kind'] != 'union', 'ABI_CC_BASE_TYPE')
            direct.add(typ.key)
            result['bases'].append(dict(type=typ, virtual=base['virtual'], access=base['access']))
        has_virtual = any(b['virtual'] or self.records[b['type'].key]['dynamic'] and
                          self.has_virtual_base(b['type'].key) for b in result['bases'])
        inherited_polymorphic = any(self.records[b['type'].key]['polymorphic'] for b in result['bases'])
        declared_virtual = any(method['virtual'] for method in item['methods'])
        require(data['polymorphic'] == (inherited_polymorphic or declared_virtual), 'ABI_CC_POLYMORPHIC_SOURCE')
        require(data['dynamic'] == (data['polymorphic'] or has_virtual), 'ABI_CC_DYNAMIC_SOURCE')
        if data['dynamic']:
            require(not data['empty'] and not data['pod03'] and not data['trivial'] and not data['standard_layout'],
                    'ABI_CC_DYNAMIC_TRAITS')
        if cpp:
            empty = (data['kind'] != 'union' and not data['dynamic'] and
                     all(self.records[b['type'].key]['empty'] for b in result['bases']) and
                     all((f['name'] is None and f['bit_width'] == 0) or
                         (f['bit_width'] is None and f['no_unique_address'] and isinstance(f['type'], RecordType)
                          and self.records[f['type'].key]['empty']) for f in result['fields']))
            require(data['empty'] == empty, 'ABI_CC_EMPTY_SOURCE')
        require(cpp or result['fields'], 'ABI_CC_C_EMPTY_RECORD')
        result['flexible'] = bool(result['fields'] and isinstance(result['fields'][-1]['type'], ArrayType)
                                  and result['fields'][-1]['type'].count is None)
        return result

    def has_virtual_base(self, key):
        self.budget.work()
        return any(b['virtual'] or self.has_virtual_base(b['type'].key) for b in self.records[key]['bases'])

    def paths(self, key):
        """Lexicographically first DFS direct-edge path per virtual identity."""
        answer = {}
        def walk(current, path):
            for index, base in enumerate(self.records[current]['bases']):
                self.budget.work()
                self.budget.reserve(64 + 8 * (len(path) + 1))
                next_path = path + [index]
                if base['virtual']:
                    answer.setdefault(base['type'].key, next_path)
                walk(base['type'].key, next_path)
        walk(key, [])
        return answer

    def vptr_offsets(self, key):
        offsets = set()
        def nonvirtual(current, offset):
            self.budget.work()
            record, layout = self.records[current], self.model.layout(current)
            if record['dynamic']:
                self.budget.reserve(48)
                offsets.add(offset)
            for index, base in enumerate(record['bases']):
                if not base['virtual']:
                    nonvirtual(base['type'].key, offset + layout.bases[index])
        nonvirtual(key, 0)
        for base, offset in self.model.layout(key).vbases.items():
            nonvirtual(base, offset)
        return offsets

    def verify(self, reference, owner=None):
        actual_owner, item = self.graph.resolve(reference, owner)
        typ = self.bind(reference, owner)
        require(isinstance(typ, RecordType), 'ABI_CC_RECORD_INPUT')
        selected = self.graph.layout(reference, owner)
        M.model_row(self.budget,selected)
        try:
            expected = self.model.layout(typ.key)
        except ModelError as error:
            raise ABIError('ABI_CC_RECORD_MODEL:' + str(error)) from error
        actual = tuple(selected[k] for k in ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align'))
        require(actual == (expected.size, expected.align, expected.data_size, expected.nvsize, expected.nvalign),
                'ABI_CC_RECORD_GEOMETRY')
        source = source_input(item)
        require(len(selected['fields']) == len(source['fields']), 'ABI_CC_FIELD_COUNT')
        for index, (field, output, offset) in enumerate(zip(source['fields'], selected['fields'], expected.fields)):
            self.budget.work()
            width = option(field['bit_width'])
            if width is None:
                width = self.model.type_layout(self.records[typ.key]['fields'][index]['type']).size * 8
            flags = []
            if field['bit_width'] is not None:
                flags.append('bitfield')
                if field['name'] is None:flags.append('unnamed')
            if field['anonymous']:flags.append('anonymous')
            if field['no_unique_address']:flags.append('no_unique_address')
            if field['access'] != 'public':flags.append(field['access'])
            if isinstance(self.records[typ.key]['fields'][index]['type'], ArrayType) and \
                    self.records[typ.key]['fields'][index]['type'].count is None:flags.append('flexible')
            require(output['declaration_index'] == index and output['name'] == field_name(field, index) and
                    self.graph.compatible(field['type'], output['type'], actual_owner, actual_owner) and
                    output['offset_bits'] == offset and output['width_bits'] == width and output['flags'] == sorted(flags),
                    'ABI_CC_FIELD_DERIVATION')
        expected_bases = [(index, base['type'].key, expected.bases[index], False, [index])
                          for index, base in enumerate(self.records[typ.key]['bases']) if not base['virtual']]
        paths = self.paths(typ.key)
        expected_bases += [(None, base, offset, True, paths[base]) for base, offset in expected.vbases.items()]
        require(len(selected['bases']) == len(expected_bases), 'ABI_CC_BASE_COUNT')
        for output, (index, base, offset, virtual, path) in zip(selected['bases'], expected_bases):
            output_owner, output_type = self.graph.resolve(output['type'], actual_owner)
            require(self.canonical_class(output_owner, output_type) == base and output['offset'] == offset and
                    output['virtual'] == virtual and option(output['declaration_index']) == index and
                    output['origin_path'] == path, 'ABI_CC_BASE_DERIVATION')
            rule = output['adjustment']
            require(rule['kind'] == ('virtual' if virtual else 'fixed'), 'ABI_CC_BASE_ADJUSTMENT')
            if not virtual:
                require(rule['offset'] == offset, 'ABI_CC_BASE_ADJUSTMENT')
            else:
                require(rule['vptr_offset'] in self.vptr_offsets(typ.key) and rule['slot_bytes'] < 0 and
                        rule['slot_bytes'] % 8 == 0, 'ABI_CC_BASE_VTABLE_ADJUSTMENT')
                from .vtable import components
                ptr = next((v for v in selected['vptrs'] if v['offset'] == rule['vptr_offset']), None)
                require(ptr is not None, 'ABI_CC_BASE_VTABLE_ADJUSTMENT')
                entry = components(ptr, self.budget).get(rule['slot_bytes'])
                require(entry is not None and entry[0] == 'vbase' and
                        ptr['offset'] + entry[1] + rule['addend'] == offset,
                        'ABI_CC_BASE_VTABLE_ADJUSTMENT')
                # Component type/value equality does not identify which source
                # virtual base an equal-valued slot denotes across derived uses.
                require(False, 'ABI_CC_VBASE_TARGET_METADATA_UNAVAILABLE')
        offsets = self.vptr_offsets(typ.key)
        require(len(selected['vptrs']) == len(offsets) and {v['offset'] for v in selected['vptrs']} == offsets,
                'ABI_CC_VPTR_DERIVATION')
        require(all(v['offset_top'] == -v['offset'] for v in selected['vptrs']), 'ABI_CC_VPTR_OFFSET_TOP')
        return expected
