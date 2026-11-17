"""Module-qualified nominal ABI graphs and deterministic logical call lowering."""

import hashlib
import re
import struct
from copy import deepcopy
import factory_meter as M
from types import MappingProxyType

from layout import MAX_OBJECT, SCALARS, align_up, alignment, require

ZERO = '0' * 64
SELF = {'kind': 'self'}


def some(value):
    return {'some': value}


def option(value):
    return None if value is None else value['some']


def ref(identifier, slot=None):
    return {'module': SELF.copy() if slot is None else {'kind': 'dependency', 'slot': slot}, 'id': identifier}


def unique(records, label):
    result = {}
    for record in records:
        require(record['id'] not in result and record['id'] < 0xffffffff, 'ABI_CC_DUPLICATE_' + label)
        result[record['id']] = record
    return result


def unit_identity(namespace, name, major, project_unit_key):
    require(type(major) is int and 0 <= major < 1 << 32, 'ABI_CC_SOURCE_UNIT')
    require(isinstance(project_unit_key, str) and project_unit_key and
            not project_unit_key.startswith(('/', '\\')) and
            re.match(r'[A-Za-z]:', project_unit_key) is None, 'ABI_CC_SOURCE_UNIT')
    output = bytearray(b'rax.source.unit.v1\0')
    for value in (namespace, name, project_unit_key):
        require(isinstance(value, str) and value, 'ABI_CC_SOURCE_UNIT')
        try:
            encoded = value.encode('utf8')
        except UnicodeError:
            require(False, 'ABI_CC_SOURCE_UNIT')
        output.extend(struct.pack('<I', len(encoded)))
        output.extend(encoded)
    output.extend(struct.pack('<I', major))
    return hashlib.sha256(output).hexdigest()


class NominalGraph:
    def __init__(self, contract, module_id, modules=None, bindings=None, families=None,
                 *, nominal_expectations=None, budget=None):
        M.check_budget(budget)
        self.budget=budget
        M.copy_cost(contract,budget)
        if budget is not None:
            require(not modules and not bindings,'ABI_FACTORY_COST_UNAVAILABLE')
            M.charge(budget,work=len(contract['types'])+len(contract['layouts']),copied_bytes=128*(len(contract['types'])+len(contract['layouts'])))
        M.copy_cost(families or {},budget)
        self.module_id = module_id
        self.modules = {**(modules or {}), module_id: contract}
        self.tables = {name: unique(module['types'], 'TYPE') for name, module in self.modules.items()}
        self.layouts = {name: unique(module['layouts'], 'LAYOUT') for name, module in self.modules.items()}
        self.bindings = bindings or {}
        self.families = families or {module: ('unproven_private_owner', module) for module in self.modules}
        # Owner presence selects strict consumer-local routing, including an
        # empty table. Absent owners retain the legacy explicit provider route.
        self.nominal_expectations = None
        if nominal_expectations is not None:
            require(type(nominal_expectations) in (dict, MappingProxyType), 'ABI_CC_UNBOUND_DECLARATION')
            M.collection(budget,len(nominal_expectations))
            captured = {}
            for owner, aliases in nominal_expectations.items():
                require(type(owner) is str and owner in self.tables, 'ABI_CC_TYPE_REFERENCE')
                require(type(aliases) in (dict, MappingProxyType), 'ABI_CC_UNBOUND_DECLARATION')
                M.collection(budget,len(aliases))
                if budget is not None:require(not aliases,'ABI_FACTORY_COST_UNAVAILABLE')
                entries = {}
                for key, target in aliases.items():
                    require(type(key) is tuple and len(key) == 2 and all(
                        type(value) is int and 0 <= value < 0xffffffff for value in key),
                        'ABI_CC_UNBOUND_DECLARATION')
                    require(type(target) is int and 0 <= target < 0xffffffff and
                            target in self.tables[owner], 'ABI_CC_TYPE_REFERENCE')
                    entries[key] = target
                captured[owner] = MappingProxyType(entries)
            self.nominal_expectations = MappingProxyType(captured)

    def __deepcopy__(self, memo):
        # Execution's existing snapshot projection deep-copies a checked graph.
        # The captured owner/tuple/int proxies are wholly immutable; module and
        # table data still follow the ordinary memoized deep-copy behavior.
        M.copy_cost(self.modules,self.budget)
        M.collection(self.budget,sum(len(v)for v in self.tables.values()))
        M.collection(self.budget,sum(len(v)for v in self.layouts.values()))
        result = type(self).__new__(type(self))
        memo[id(self)] = result
        for name, value in self.__dict__.items():
            setattr(result, name, value if name in ('nominal_expectations','budget') else deepcopy(value, memo))
        return result

    def resolve(self, reference, owner=None):
        M.charge(self.budget,work=4,edges=1)
        owner = self.module_id if owner is None else owner
        module, identifier = owner, reference['id']
        if reference['module']['kind'] != 'self':
            if self.nominal_expectations is not None and owner in self.nominal_expectations:
                require(reference['module']['kind'] == 'dependency', 'ABI_CC_UNBOUND_DECLARATION')
                key = reference['module']['slot'], identifier
                require(all(type(value) is int and 0 <= value < 0xffffffff for value in key),
                        'ABI_CC_UNBOUND_DECLARATION')
                aliases = self.nominal_expectations[owner]
                require(key in aliases, 'ABI_CC_UNBOUND_DECLARATION')
                identifier = aliases[key]
            else:
                binding = self.bindings.get(owner, {}).get(reference['module']['slot'])
                require(binding is not None and identifier in binding['types'], 'ABI_CC_UNBOUND_DECLARATION')
                module, identifier = binding['module'], binding['types'][identifier]
        require(module in self.tables and identifier in self.tables[module], 'ABI_CC_TYPE_REFERENCE')
        return module, self.tables[module][identifier]

    def layout(self, reference, owner=None):
        module, item = self.resolve(reference, owner)
        identifier = option(item['layout'])
        require(identifier is not None and identifier in self.layouts[module], 'ABI_CC_INCOMPLETE_VALUE')
        return self.layouts[module][identifier]

    def fingerprint(self, reference, owner=None, ignore_top_cv=False):
        """V3 rooted DEF/EXPR quotient, independent of compiled representations.

        EXPR propagates through every constructor; record/enum references are
        declaration leaves. DEF preserves complete by-value source/layout edges.
        Iterative traversal permits recursive pointers without Python recursion.
        At most4096 states; quotient refinement costs O(V*(V+E)logV) work and
        O(V+E+label bytes) storage, independently checked by the V3 reference.
        """
        from graph_identity import canonical_quotient
        owner = self.module_id if owner is None else owner
        module, item = self.resolve(reference, owner)
        root = (module, item['id'], True)
        pending, labels, edges = [root], {}, {}
        expr_flags = {'code', 'variadic', 'noexcept', 'c_linkage', 'lvalue_ref', 'rvalue_ref'}
        cursor = 0
        while cursor < len(pending):
            key = pending[cursor]
            module, identifier, definition = key
            item = self.tables[module][identifier]
            M.copy_cost(item,self.budget)
            M.collection(self.budget,len(item['flags']),sum(len(x)for x in item['flags']))
            M.collection(self.budget,len(self.modules[module]['domains']))
            domains = {domain['id']: domain for domain in self.modules[module]['domains']}
            require(item['domain'] in domains, 'ABI_CC_TYPE_DOMAIN')
            label = {'kind': item['kind'], 'qualifiers': item['qualifiers'],
                     'abi_identity': domains[item['domain']]['abi_identity'],
                     'identity': {name: item['identity'][name] for name in
                                  ('language', 'linkage', 'entity', 'library', 'unit')}}
            children = []
            if not definition and item['kind'] in ('record', 'enum'):
                label['node_kind'] = 'nominal_declaration'
            elif not definition:
                label.update(node_kind='nominal_expression', bits=item['bits'], signed=item['signed'],
                             extent=item['extent'], semantic_flags=sorted(set(item['flags']) & expr_flags),
                             element_count=len(item['elements']))
                children.extend((child, False) for child in item['elements'])
            else:
                label.update(node_kind='nominal_definition', bits=item['bits'], signed=item['signed'],
                             extent=item['extent'], flags=sorted(item['flags']),
                             enumerators=item['enumerators'], element_count=len(item['elements']),
                             method_count=len(item['methods']), has_cpp_class=False)
                child_definition = item['kind'] not in ('pointer', 'reference', 'member_pointer', 'function')
                children.extend((child, child_definition) for child in item['elements'])
                label['methods'] = [{name: method[name] for name in ('name', 'virtual', 'slot', 'noexcept')}
                                    for method in item['methods']]
                children.extend((method['signature'], False) for method in item['methods'])
                source = option(item['record_input'])
                label.update(record_input=None, input_field_count=0, input_base_count=0)
                if source is not None:
                    label['record_input'] = {name: source[name] for name in
                        ('revision', 'kind', 'explicit_align', 'pod03', 'trivial', 'standard_layout',
                         'polymorphic', 'dynamic', 'empty')}
                    label['record_input']['fields'] = [{name: field[name] for name in
                        ('name', 'bit_width', 'explicit_align', 'no_unique_address', 'anonymous', 'access')}
                        for field in source['fields']]
                    label['record_input']['bases'] = [{name: base[name] for name in ('virtual', 'access')}
                                                      for base in source['bases']]
                    label.update(input_field_count=len(source['fields']), input_base_count=len(source['bases']))
                    children.extend((field['type'], True) for field in source['fields'])
                    children.extend((base['type'], True) for base in source['bases'])
                layout_id = option(item['layout'])
                label.update(layout=None, output_field_count=0, output_base_count=0)
                if layout_id is not None:
                    require(layout_id in self.layouts[module], 'ABI_CC_LAYOUT_REFERENCE')
                    layout = self.layouts[module][layout_id]
                    M.copy_cost(layout,self.budget)
                    label['layout'] = {name: layout[name] for name in
                        ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align')}
                    label['layout']['fields'] = [{**{name: field[name] for name in
                        ('declaration_index', 'name', 'offset_bits', 'width_bits')}, 'flags': sorted(field['flags'])}
                        for field in layout['fields']]
                    label['layout']['bases'] = [{name: base[name] for name in
                        ('offset', 'virtual', 'declaration_index', 'origin_path', 'adjustment')}
                        for base in layout['bases']]
                    label['layout']['vptrs'] = [{**{name: ptr[name] for name in
                        ('offset', 'offset_top', 'vcall_offsets', 'vbase_offsets', 'component_order')},
                        'slot_count': len(ptr['slots'])} for ptr in layout['vptrs']]
                    label.update(output_field_count=len(layout['fields']), output_base_count=len(layout['bases']))
                    children.extend((field['type'], True) for field in layout['fields'])
                    children.extend((base['type'], True) for base in layout['bases'])
            if cursor == 0 and ignore_top_cv:
                label['qualifiers'] = [q for q in label['qualifiers'] if q not in ('const', 'volatile')]
            labels[key], edges[key] = label, []
            M.charge(self.budget,work=8*len(children),edges=len(children),copied_bytes=128*len(children))
            for child, child_definition in children:
                child_module, child_item = self.resolve(child, module)
                child_key = (child_module, child_item['id'], child_definition)
                if child_key not in labels:
                    require(len(labels) < 4096, 'ABI_CC_GRAPH_LIMIT')
                    labels[child_key] = None
                    pending.append(child_key)
                edges[key].append(child_key)
            cursor += 1
        encoded=canonical_quotient(labels,edges,root,budget=self.budget)
        M.charge(self.budget,work=len(encoded)+64,copied_bytes=len(encoded)+128)
        return hashlib.sha256(b'SMIR-NOMINAL-SHAPE-V3\0'+encoded).hexdigest()

    def compatible(self, left, right, left_owner=None, right_owner=None, ignore_top_cv=False):
        """Coinductive source compatibility; incomplete declarations may resolve.

        Function bodies and SSA IDs never establish equality. Complete external
        record/enum definitions require identical ABI declaration graphs. An
        incomplete declaration is not permission for by-value storage/calls.
        """
        pending = [(left, right, left_owner or self.module_id, right_owner or self.module_id)]
        seen = set()
        root_pair = None
        while pending:
            M.collection(self.budget,len(seen)+1)
            ar, br, ao, bo = pending.pop()
            am, a = self.resolve(ar, ao)
            bm, b = self.resolve(br, bo)
            M.copy_cost(a,self.budget);M.copy_cost(b,self.budget)
            pair = am, a['id'], bm, b['id']
            if root_pair is None:
                root_pair = pair
            if pair in seen:
                continue
            seen.add(pair)
            if self.modules[am]['identity'] != self.modules[bm]['identity']:
                return False
            M.copy_cost(self.modules[am]['identity'],self.budget)
            M.copy_cost(self.modules[bm]['identity'],self.budget)
            M.collection(self.budget,len(self.modules[am]['domains']))
            M.collection(self.budget,len(self.modules[bm]['domains']))
            ad = {domain['id']: domain for domain in self.modules[am]['domains']}[a['domain']]
            bd = {domain['id']: domain for domain in self.modules[bm]['domains']}[b['domain']]
            if ad['abi_identity'] != bd['abi_identity']:
                return False
            ai, bi = a['identity'], b['identity']
            if any(ai[key] != bi[key] for key in ('language', 'linkage', 'entity', 'library', 'unit')):
                return False
            if ai['linkage'] in ('internal', 'local'):
                if am not in self.families or bm not in self.families or self.families[am] != self.families[bm]:
                    return False
            if any(a[key] != b[key] for key in ('kind', 'bits', 'signed')):
                return False
            ignored = ignore_top_cv and pair == root_pair
            if not ignored and a['qualifiers'] != b['qualifiers']:
                return False
            ac, bc = 'complete' in a['flags'], 'complete' in b['flags']
            if a['kind'] in ('record', 'enum') and ac and bc:
                if self.fingerprint(ar, ao, ignored) != self.fingerprint(br, bo, ignored):
                    return False
            if a['kind'] not in ('record', 'array') and set(a['flags']) - {'complete', 'trivial_copy', 'trivial_destroy'} != set(b['flags']) - {'complete', 'trivial_copy', 'trivial_destroy'}:
                return False
            if a['kind'] == 'array' and option(a['extent']) is not None and option(b['extent']) is not None:
                if a['extent'] != b['extent']:
                    return False
            if len(a['elements']) != len(b['elements']):
                return False
            M.charge(self.budget,work=4*len(a['elements']),edges=len(a['elements']),copied_bytes=128*len(a['elements']))
            pending.extend((x, y, am, bm) for x, y in zip(a['elements'], b['elements']))
        return True

    def catch_compatible(self, left, right, left_owner=None, right_owner=None):
        """Compare compiler-normalized caught RTTI types, without C projection.

        The frontend supplies the adjusted, reference-stripped caught type.
        Top-level cv is ignored; pointee cv, C++ builtin identities, library
        cohorts and private source ownership remain significant. Raw references,
        arrays and function types are rejected rather than guessed into pointers.
        Complexity is that of compatible; malformed/missing metadata raises ABIError.
        """
        for reference, owner in ((left, left_owner), (right, right_owner)):
            _, item = self.resolve(reference, owner)
            require(item['kind'] not in ('reference', 'array', 'function', 'void'),
                    'ABI_CC_CATCH_NORMALIZATION')
        return self.compatible(left, right, left_owner, right_owner, ignore_top_cv=True)

    def boundary_compatible(self, left, right, left_owner=None, right_owner=None):
        """Link/call ABI check; by-value definitions are mandatory on both sides.

        A function's identity may name an incomplete class declaration; an actual
        by-value crossing cannot use it as allocation/calling-layout evidence.
        Pointer/reference pointees may remain incomplete. O(V+E) after identities.
        """
        left_owner=left_owner or self.module_id
        right_owner=right_owner or self.module_id
        _,left_type=self.resolve(left,left_owner)
        _,right_type=self.resolve(right,right_owner)
        if left_type['kind']==right_type['kind']=='function' and (
                'c_linkage' in left_type['flags'] or 'c_linkage' in right_type['flags']):
            if not ('c_linkage' in left_type['flags'] and 'c_linkage' in right_type['flags']):
                return False
            require(self.budget is None,'ABI_FACTORY_COST_UNAVAILABLE')
            from c_boundary import compatible
            return compatible(self,left,right,left_owner,right_owner)
        if not self.compatible(left,right,left_owner,right_owner):
            return False
        am,a=self.resolve(left,left_owner);bm,b=self.resolve(right,right_owner)
        pending=list(zip(a['elements'],b['elements'])) if a['kind']=='function' else [(left,right)]
        owners=(am,bm) if a['kind']=='function' else (left_owner,right_owner)
        seen=set()
        while pending:
            M.collection(self.budget,len(seen)+1)
            ar,br=pending.pop()
            ao,at=self.resolve(ar,owners[0]);bo,bt=self.resolve(br,owners[1])
            pair=ao,at['id'],bo,bt['id']
            if pair in seen:
                continue
            seen.add(pair)
            if at['kind'] in ('void','function'):
                continue
            if at['layout'] is None or bt['layout'] is None or not (
                    'complete' in at['flags'] and 'complete' in bt['flags']):
                return False
            al=self.layout(ar,owners[0]);bl=self.layout(br,owners[1])
            if (al['size'],al['align'])!=(bl['size'],bl['align']):
                return False
            # Scalar/aggregate children are already compared recursively by
            # compatible(); pointer pointees are intentionally not required here.
        return True

    def data_boundary_compatible(self,left,right,left_owner=None,right_owner=None):
        """Explicit C-linkage DATA view; caller verifies symbol source_linkage=c.

        Provider storage must be complete. A consumer incomplete object/array
        declaration grants address access only, never by-value allocation/load.
        Complete pointer objects may of course point to incomplete pointees.
        """
        left_owner=left_owner or self.module_id
        right_owner=right_owner or self.module_id
        _,provider=self.resolve(right,right_owner)
        if provider['kind'] in ('void','function') or provider['layout'] is None or 'complete' not in provider['flags']:
            return False
        require(self.budget is None,'ABI_FACTORY_COST_UNAVAILABLE')
        from c_boundary import compatible
        return compatible(self,left,right,left_owner,right_owner,address_only=True)

    def signature_compatible(self,left,right,left_owner=None,right_owner=None):
        """Full R034 call_signature comparison, including hidden owner/lifecycle."""
        require(self.budget is None,'ABI_FACTORY_COST_UNAVAILABLE')
        from call_interfaces import compatible
        return compatible(self,left,right,left_owner,right_owner)

    def value_mask(self, reference, owner=None, active=None):
        """Value-representation bits; padding excluded, union uses member OR mask.

        Returns little-endian bytes. No memory read or host type introspection.
        Caller distinguishes generic full-storage C builtins from C++ value CAS.
        """
        owner = owner or self.module_id
        module, item = self.resolve(reference, owner)
        active = set() if active is None else active
        key = module, item['id']
        require(key not in active, 'ABI_CC_VALUE_CYCLE')
        active.add(key)
        layout = self.layout(reference, owner)
        size = layout['size']
        if self.budget is not None:
            require(0<=size<=4096 and item['kind']in('scalar','pointer','reference','record'),'ABI_FACTORY_COST_UNAVAILABLE')
            require(0<=item['bits']<=32768 and not layout['bases'] and not layout['vptrs'],'ABI_FACTORY_COST_UNAVAILABLE')
            M.copy_cost(layout,self.budget)
            for field in layout['fields']:
                M.charge(self.budget,work=1)
                require(0<=field['offset_bits']<=32768 and 0<=field['width_bits']<=32768 and field['offset_bits']+field['width_bits']<=size*8,'ABI_FACTORY_COST_UNAVAILABLE')
            M.charge(self.budget,work=8*(size*8+1),copied_bytes=8*(size+32))
        require(size <= 1024 * 1024, 'ABI_CC_MASK_RESOURCE')
        try:
            if item['kind'] == 'atomic_flag':
                mask = 1
            elif item['kind'] in ('scalar', 'bitint', 'enum', 'pointer', 'reference', 'member_pointer', 'handle', 'snapshot'):
                mask = (1 << item['bits']) - 1
            elif item['kind'] == 'atomic':
                mask = int.from_bytes(self.value_mask(item['elements'][0], module, active), 'little')
            elif item['kind'] in ('array', 'vector', 'complex'):
                element = item['elements'][0]
                child = self.layout(element, module)
                child_mask = int.from_bytes(self.value_mask(element, module, active), 'little')
                count = 2 if item['kind'] == 'complex' else option(item['extent'])
                require(count is not None, 'ABI_CC_INCOMPLETE_VALUE')
                mask = 0
                for index in range(count):
                    mask |= child_mask << (index * child['size'] * 8)
            elif item['kind'] == 'record':
                mask = 0
                for field in layout['fields']:
                    M.charge(self.budget,work=8*(size*8+1),copied_bytes=8*(size+32))
                    child = int.from_bytes(self.value_mask(field['type'], module, active), 'little')
                    if 'bitfield' in field['flags']:
                        child &= (1 << field['width_bits']) - 1
                    mask |= child << field['offset_bits']
                for base in layout['bases']:
                    require(base['adjustment']['kind'] == 'fixed', 'ABI_CC_MASK_DYNAMIC_LAYOUT')
                    child = int.from_bytes(self.value_mask(base['type'], module, active), 'little')
                    mask |= child << (base['adjustment']['offset'] * 8)
                for ptr in layout['vptrs']:
                    mask |= ((1 << 64) - 1) << (ptr['offset'] * 8)
            else:
                require(False, 'ABI_CC_NOT_OBJECT')
            require(mask < 1 << (size * 8), 'ABI_CC_MASK_EXTENT')
            M.charge(self.budget,work=size,copied_bytes=size)
            return mask.to_bytes(size, 'little')
        finally:
            active.remove(key)


def classify(graph, signature):
    """Compute one logical CC: atomic unwrap, records by-copy/sret, typed varargs."""
    M.copy_cost(signature,graph.budget)
    arguments, results = [], []

    def parameter(source, role, source_index=None):
        module, item = graph.resolve(source)
        representation = item
        if item['kind'] == 'atomic':
            _, representation = graph.resolve(item['elements'][0], module)
        require(representation['kind'] not in ('array', 'function', 'void'), 'ABI_CC_UNADJUSTED_PARAMETER')
        layout = graph.layout(source)
        indirect = representation['kind'] == 'record'
        return {'source_index': None if source_index is None else some(source_index), 'role': role,
                'source_type': source, 'mode': 'sret' if role == 'sret' else
                'indirect_copy' if indirect else 'direct', 'align': layout['align'],
                'bytes': layout['size'], 'noundef': True}

    result = option(signature['result'])
    if result is not None:
        module, result_type = graph.resolve(result)
        representation = result_type
        if result_type['kind'] == 'atomic':
            _, representation = graph.resolve(result_type['elements'][0], module)
        if representation['kind'] == 'record':
            arguments.append(parameter(result, 'sret'))
        elif result_type['kind'] != 'void':
            results.append(result)
    this = option(signature['this_type'])
    require(not signature['vtt'] or this is not None, 'ABI_CC_VTT_WITHOUT_THIS')
    if this is not None:
        arguments.append(parameter(this, 'this'))
    if signature['vtt']:
        arguments.append({'role': 'vtt', 'mode': 'direct', 'noundef': True})
    arguments.extend(parameter(source, 'parameter', index) for index, source in enumerate(signature['params']))
    if signature['variadic']:
        arguments.append({'role': 'varargs_arena', 'mode': 'direct', 'noundef': True})
        arguments.append({'role': 'varargs_bytes', 'mode': 'direct', 'noundef': True})
    return arguments, results
