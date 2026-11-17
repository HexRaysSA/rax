"""INT032 source-role reference predicates, not executable admission.

Consumer callbacks follow released R008REV2; predicates implement INT032.
The overall compiler/production freeze remains open.
Callers must supply original-owner metadata from an actual checked ABI graph.
This module neither authenticates original AST truth nor issues phase proofs.
"""
from dataclasses import dataclass


class SourceRoleError(ValueError):
    def __init__(self, code, detail=''):
        if code == 'RT_SOURCE_EVIDENCE_UNAVAILABLE':
            selected = 'RT_HELPER_SOURCE_EVIDENCE_UNAVAILABLE'
        elif code == 'RT_SOURCE_TLS_NOMINAL':
            selected = 'RT_HELPER_SOURCE_COMPATIBILITY'
        elif 'EXECUTION' in code:
            selected = 'RT_HELPER_SOURCE_EXECUTION'
        elif code == 'RT_SOURCE_LAYOUT':
            selected = 'RT_HELPER_SOURCE_LAYOUT'
        elif code == 'RT_SOURCE_RESOURCE':
            selected = code
        else:
            selected = 'RT_HELPER_SOURCE_ROLE'
        self.code = selected
        self.detail = code + (': ' + detail if detail else '')
        super().__init__(selected + ': ' + self.detail)


def require(condition, code):
    if not condition:
        raise SourceRoleError(code)


def option(value):
    if value is None:
        return None
    require(type(value) is dict and set(value) == {'some'}, 'RT_SOURCE_OPTION')
    return value['some']


@dataclass
class Budget:
    """Reference work policy, independent of ABI integer/object-size limits."""
    remaining: int = 65536

    def __post_init__(self):
        require(type(self.remaining) is int and self.remaining >= 0,
                "RT_SOURCE_RESOURCE")

    def charge(self, count=1):
        require(type(count) is int and 0 <= count <= self.remaining,
                'RT_SOURCE_RESOURCE')
        self.remaining -= count


class SourceRoles:
    """Draft R008 adapter over actual admitted source/execution graph resolvers.

    Every input qref remains in the checked owner/declaration scope. The caller
    must preserve that scope for child qrefs; provider-private IDs are not source
    handles. Local work O(visited nodes + fields), bounded before each visit; actual ABI
    resolver/comparison work retains its independent graph bounds. Local space
    O(maximum fixed canonical builtin graph depth), excluding returned metadata.
    No default layout, host type, compatibility or success callback is supplied.
    """
    def __init__(self, nominal, layout, execution, *, compatible=None, budget=None):
        self.nominal = nominal
        self.layout = layout
        self.execution = execution
        self.compatible = compatible
        self.budget = budget if budget is not None else Budget()

    def source(self, reference):
        self.budget.charge()
        require(callable(self.nominal), 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        value = self.nominal(reference)
        require(type(value) is dict, 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        return value

    def allocation(self, reference):
        self.budget.charge()
        require(callable(self.layout), 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        value = self.layout(reference)
        require(type(value) is dict, 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        return value

    def executable(self, reference):
        self.budget.charge()
        require(callable(self.execution), 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        value = self.execution(reference)
        require(type(value) is dict, 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        return value

    def execution_of(self, source):
        reference = option(source['execution'])
        require(reference is not None, 'RT_SOURCE_EXECUTION')
        return self.executable(reference)

    @staticmethod
    def extent(layout, size, alignment):
        require(all(layout[name] == size for name in
                    ('size', 'data_size', 'nonvirtual_size')) and
                layout['align'] == alignment and
                layout['nonvirtual_align'] == alignment, 'RT_SOURCE_LAYOUT')

    @staticmethod
    def complete(source):
        require('complete' in source['flags'], 'RT_SOURCE_INCOMPLETE')

    def atomic_flag(self, reference):
        source = self.source(reference)
        # Known wrong kind is malformed independently of missing geometry.
        require(source['kind'] == 'atomic_flag', 'RT_SOURCE_ATOMIC_FLAG_KIND')
        self.complete(source)
        self.extent(self.allocation(reference), 1, 1)
        execution = self.execution_of(source)
        require(execution['kind'] == 'raw' and execution['bits'] == 8,
                'RT_SOURCE_ATOMIC_FLAG_EXECUTION')

    @staticmethod
    def builtin(source, kind, entity):
        identity = source['identity']
        require(source['kind'] == kind and identity['language'] == 'c23' and
                identity['linkage'] == 'builtin' and identity['entity'] == entity and
                identity['library'] is None and identity['unit'] is None,
                'RT_SOURCE_BUILTIN_IDENTITY')
        require(source['qualifiers'] == [] and source['flags'] ==
                ['complete', 'trivial_copy', 'trivial_destroy'] and
                source['methods'] == [] and source['enumerators'] == [],
                'RT_SOURCE_BUILTIN_SHAPE')

    def unsigned_word(self, reference, bits):
        source = self.source(reference)
        self.builtin(source, 'scalar', 'unsigned int' if bits == 32 else 'unsigned long')
        require(source['bits'] == bits and source['signed'] is False and
                source['elements'] == [] and source['extent'] is None and
                source['record_input'] is None and source['representation'] == 'value',
                'RT_SOURCE_BUILTIN_SCALAR')
        self.extent(self.allocation(reference), bits // 8, bits // 8)
        execution = self.execution_of(source)
        require(execution['kind'] == 'int' and execution['bits'] == bits,
                'RT_SOURCE_BUILTIN_EXECUTION')

    def state_execution(self, execution):
        require(execution['kind'] == 'array' and execution['count'] == 32,
                'RT_SOURCE_BUILTIN_EXECUTION')
        element = self.executable(execution['element'])
        require(element['kind'] == 'raw' and element['bits'] == 8,
                'RT_SOURCE_BUILTIN_EXECUTION')

    def state(self, reference, entity):
        require(entity in ("rax.va_state", "rax.jmp_state"), "RT_SOURCE_BUILTIN_IDENTITY")
        source = self.source(reference)
        self.builtin(source, 'record', entity)
        require(source['bits'] == 0 and source['signed'] is False and
                source['elements'] == [] and source['extent'] is None and
                source['representation'] == 'storage', 'RT_SOURCE_BUILTIN_SHAPE')
        declaration = option(source['record_input'])
        require(declaration is not None, 'RT_SOURCE_BUILTIN_INPUT')
        require(declaration['revision'] == 1 and declaration['kind'] == 'struct' and
                declaration['explicit_align'] is None and declaration['bases'] == [] and
                all(declaration[name] is False for name in
                    ('pod03','trivial','standard_layout','polymorphic','dynamic','empty')),
                'RT_SOURCE_BUILTIN_INPUT')
        expected = [('area',64,0),('cursor',64,8),('limit',64,16),('cookie',64,24)] if entity == 'rax.va_state' else [
            ('revision',32,0),('reserved',32,4),('process',64,8),('checkpoint',64,16),('generation',64,24)]
        layout = self.allocation(reference)
        self.extent(layout, 32, 8)
        require(layout['bases'] == [] and layout['vptrs'] == [] and
                len(layout['fields']) == len(expected) == len(declaration['fields']),
                'RT_SOURCE_BUILTIN_FIELDS')
        for index, ((name,bits,offset), field, selected) in enumerate(
                zip(expected,declaration['fields'],layout['fields'])):
            self.budget.charge()
            require(field['name'] == {'some':name} and field['bit_width'] is None and
                    field['explicit_align'] is None and field['no_unique_address'] is False and
                    field['anonymous'] is False and field['access'] == 'public',
                    'RT_SOURCE_BUILTIN_FIELDS')
            require(selected['declaration_index'] == index and selected['name'] == name and
                    selected['type'] == field['type'] and selected['offset_bits'] == 8 * offset and
                    selected['width_bits'] == bits and selected['flags'] == [],
                    'RT_SOURCE_BUILTIN_FIELDS')
            self.unsigned_word(field['type'],bits)
        self.state_execution(self.execution_of(source))

    def state_wrapper(self, reference, entity):
        source = self.source(reference)
        self.builtin(source,'array','array')
        require(source['bits'] == 0 and source['signed'] is False and
                source['extent'] == {'some':1} and len(source['elements']) == 1 and
                source['record_input'] is None and source['representation'] == 'value',
                'RT_SOURCE_BUILTIN_WRAPPER')
        layout = self.allocation(reference)
        self.extent(layout,32,8)
        require(layout['fields'] == layout['bases'] == layout['vptrs'] == [],
                'RT_SOURCE_BUILTIN_WRAPPER')
        self.state(source['elements'][0],entity)
        execution = self.execution_of(source)
        require(execution['kind'] == 'array' and execution['count'] == 1,
                'RT_SOURCE_BUILTIN_EXECUTION')
        self.state_execution(self.executable(execution['element']))

    def object(self, reference, *, allow_reference=False):
        source = self.source(reference)
        forbidden = {'void','function','handle','snapshot'}
        if not allow_reference:
            forbidden.add('reference')
        require(source['kind'] not in forbidden, 'RT_SOURCE_OBJECT_KIND')
        self.complete(source)
        layout = self.allocation(reference)
        self.execution_of(source)
        if source['kind'] == 'reference':
            self.extent(layout,8,8)
            require(len(source['elements']) == 1 and
                    ('lvalue_ref' in source['flags']) != ('rvalue_ref' in source['flags']),
                    'RT_SOURCE_REFERENCE_CATEGORY')
            self.source(source['elements'][0])  # identity, not referent allocation
            execution = self.execution_of(source)
            require(execution['kind'] == 'data_ptr' and execution['space'] == 'guest_data',
                    'RT_SOURCE_REFERENCE_EXECUTION')
        return source

    def va_arg(self, reference, actual_type):
        source = self.object(reference)
        require(source['kind'] != 'array', 'RT_SOURCE_VA_ARG_KIND')
        if source['kind'] == 'record' and source['identity']['language'] == 'cpp23':
            require({'trivial_copy','trivial_destroy'} <= set(source['flags']),
                    'RT_SOURCE_VA_ARG_NONTRIVIAL')
        expected = self.execution_of(source)
        actual = self.executable(actual_type)
        require(expected['identity'] == actual['identity'] if 'identity' in expected and 'identity' in actual
                else expected == actual, 'RT_SOURCE_VA_ARG_EXECUTION')

    def eh_payload(self, reference):
        source = self.object(reference)
        require(source['kind'] != 'array' and not set(source['qualifiers']) & {'const','volatile'},
                'RT_SOURCE_EH_NORMALIZATION')
        if source['kind'] == 'pointer':
            require(len(source['elements']) == 1, 'RT_SOURCE_EH_POINTER')
            pointee = self.source(source['elements'][0])
            if pointee['kind'] not in ('void','function'):
                self.complete(pointee)

    def tls(self, reference, target_reference):
        self.object(reference,allow_reference=True)
        self.object(target_reference,allow_reference=True)
        self.budget.charge()
        require(callable(self.compatible), 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        require(self.compatible(reference,target_reference), 'RT_SOURCE_TLS_NOMINAL')


def verify_import(record, resolve_abi, source_layout, resolve_type,
                  source_compatible, target=None):
    """Check static source roles; provider/runtime obligations remain separate."""
    reference = option(record['abi'])
    require(reference is not None, 'RT_SOURCE_EVIDENCE_UNAVAILABLE')
    model = SourceRoles(lambda q: resolve_abi('nominal',q),source_layout,
                        resolve_type,compatible=source_compatible)
    name = record['name']
    if name in ('atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear'):
        model.atomic_flag(reference)
    elif name in ('guard_acquire','guard_release','guard_abort',
                  'tls_guard_acquire','tls_guard_release','tls_guard_abort'):
        model.object(reference,allow_reference=True)
    elif name in ('va_start','va_copy','va_end'):
        model.state_wrapper(reference,'rax.va_state')
    elif name in ('setjmp_capture','longjmp_restore'):
        model.state_wrapper(reference,'rax.jmp_state')
    elif name == 'va_arg':
        require(len(record['types']) == 1,'RT_SOURCE_VA_ARG_EXECUTION')
        model.va_arg(reference,record['types'][0])
    elif name == 'eh_allocate':
        model.eh_payload(reference)
    elif name == 'tls_address':
        require(target is not None,'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        if hasattr(target,'metadata'):
            # Issued TLS target validates actual registry/consumer/provider on
            # every access. Project to its checked consumer declaration; raw
            # provider SELF children cannot enter this consumer expected graph.
            metadata = target.metadata()
            declaration = metadata['consumer_context'].runtime_symbol(target.reference)
            target_reference = option(declaration['nominal'])
        else:
            target_reference = option(target['storage']['nominal'])
        require(target_reference is not None,'RT_SOURCE_EVIDENCE_UNAVAILABLE')
        model.tls(reference,target_reference)
    else:
        raise SourceRoleError('RT_SOURCE_UNKNOWN_ROLE',name)
