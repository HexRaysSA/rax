"""Independent INT032 source-role predicates over a checked nominal/exec graph.

This is reference analysis only. No runtime registry, compiled-source truth,
production AbiFacts, import support or execution authority is created here.
"""
from copy import deepcopy
from layout import require
from nominal import option, ref
from execution_shapes import ExecutionShapes

FLAGS=['complete','trivial_copy','trivial_destroy']
STATE_FIELDS={'rax.va_state':[('area',64,0),('cursor',64,8),('limit',64,16),('cookie',64,24)],
              'rax.jmp_state':[('revision',32,0),('reserved',32,4),('process',64,8),
                               ('checkpoint',64,16),('generation',64,24)]}
RAW8=ExecutionShapes([dict(id=0,kind='raw',bits=8)]).digest(ref(0))


class SourceRoles:
    def __init__(self,graph,execution):
        # Private ABI-local adapter: execution(owner,original_owned_qref) returns
        # actual checked execution facts, never a digest supplied by wire input.
        self.graph=graph;self.execution=execution

    def shape(self,owner,item):
        require(item['execution'] is not None,'ABI_SOURCE_ROLE_EXECUTION')
        return self.execution(owner,option(item['execution']))

    def portable(self,owner,item):
        domain=next((d for d in self.graph.modules[owner]['domains'] if d['id']==item['domain']),None)
        require(domain is not None and domain['isa']=='portable','ABI_SOURCE_BUILTIN_DOMAIN')

    def identity(self,item,entity,allow_top_cv=False):
        i=item['identity']
        require(i['language']=='c23' and i['linkage']=='builtin' and i['entity']==entity and
                i['library'] is None and i['unit'] is None and
                (set(item['qualifiers']) <= {'const','volatile'} if allow_top_cv else not item['qualifiers']) and
                item['flags']==FLAGS and not item['methods'] and not item['enumerators'] and
                not item['signed'],'ABI_CC_BUILTIN_STATE')

    def unsigned(self,reference,owner,bits):
        owner,item=self.graph.resolve(reference,owner);reference=ref(item['id']);self.portable(owner,item)
        self.identity(item,'unsigned int' if bits==32 else 'unsigned long')
        require(item['kind']=='scalar' and item['bits']==bits and not item['elements'] and
                item['extent'] is None and item['record_input'] is None and
                item['representation']=='value','ABI_CC_BUILTIN_STATE')
        layout=self.graph.layout(reference,owner)
        require(tuple(layout[k] for k in ('size','align','data_size','nonvirtual_size','nonvirtual_align'))==
                (bits//8,)*5 and not layout['fields'] and not layout['bases'] and not layout['vptrs'],
                'ABI_CC_BUILTIN_STATE')
        shape=self.shape(owner,item)
        require(shape['kind']=='int' and shape['bits']==bits,'ABI_CC_BUILTIN_STATE')

    def state(self,reference,owner,entity,*,base_declaration=False):
        owner,item=self.graph.resolve(reference,owner);reference=ref(item['id']);self.portable(owner,item);self.identity(item,entity,allow_top_cv=base_declaration)
        require(item['kind']=='record' and item['bits']==0 and not item['elements'] and item['extent'] is None and
                item['representation']=='storage','ABI_CC_BUILTIN_STATE')
        source=option(item['record_input'])
        require(source is not None and source['revision']==1 and source['kind']=='struct' and
                source['explicit_align'] is None and not source['bases'] and
                not any(source[k] for k in ('pod03','trivial','standard_layout','polymorphic','dynamic','empty')),
                'ABI_CC_BUILTIN_STATE')
        expected=STATE_FIELDS[entity]
        layout=self.graph.layout(reference,owner)
        require(tuple(layout[k] for k in ('size','align','data_size','nonvirtual_size','nonvirtual_align'))==
                (32,8,32,32,8) and not layout['bases'] and not layout['vptrs'] and
                len(source['fields'])==len(expected)==len(layout['fields']),'ABI_CC_BUILTIN_STATE')
        for index,((name,bits,offset),field,selected) in enumerate(zip(expected,source['fields'],layout['fields'])):
            require(option(field['name'])==name and field['bit_width'] is None and field['explicit_align'] is None and
                    not field['no_unique_address'] and not field['anonymous'] and field['access']=='public',
                    'ABI_CC_BUILTIN_STATE')
            self.unsigned(field['type'],owner,bits)
            require(selected['declaration_index']==index and selected['name']==name and
                    selected['offset_bits']==offset*8 and selected['width_bits']==bits and not selected['flags'] and
                    self.graph.compatible(field['type'],selected['type'],owner,owner),'ABI_CC_BUILTIN_STATE')
        shape=self.shape(owner,item)
        require(shape['kind']=='array' and shape['count']==32 and shape['element_identity']==RAW8,
                'ABI_CC_BUILTIN_STATE')
        return shape

    def wrapper(self,reference,owner,entity):
        owner,item=self.graph.resolve(reference,owner);reference=ref(item['id']);self.portable(owner,item);self.identity(item,'array')
        require(item['kind']=='array' and item['bits']==0 and len(item['elements'])==1 and
                option(item['extent'])==1 and item['record_input'] is None and item['representation']=='value',
                'ABI_CC_BUILTIN_STATE')
        child=self.state(item['elements'][0],owner,entity)
        layout=self.graph.layout(reference,owner)
        require(tuple(layout[k] for k in ('size','align','data_size','nonvirtual_size','nonvirtual_align'))==
                (32,8,32,32,8) and not layout['fields'] and not layout['bases'] and not layout['vptrs'],
                'ABI_CC_BUILTIN_STATE')
        shape=self.shape(owner,item)
        require(shape['kind']=='array' and shape['count']==1 and shape['element_identity']==child['identity'],
                'ABI_CC_BUILTIN_STATE')

    def check(self,name,reference,owner=None,*,type0=None,target=None):
        original_owner=owner or self.graph.module_id
        original_reference=deepcopy(reference)
        owner,item=self.graph.resolve(reference,owner)
        reference=ref(item['id'])
        kind=item['kind']
        if name in ('atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear'):
            require(kind=='atomic_flag','ABI_SOURCE_FLAG_KIND')
            layout=self.graph.layout(reference,owner);shape=self.shape(owner,item)
            require((layout['size'],layout['align'])==(1,1) and shape['kind']=='raw' and shape['bits']==8,
                    'ABI_SOURCE_FLAG_LAYOUT')
        elif name in ('va_start','va_copy','va_end','setjmp_capture','longjmp_restore'):
            self.wrapper(reference,owner,'rax.va_state' if name.startswith('va_') else 'rax.jmp_state')
        elif name in ('tls_address','tls_guard_acquire','tls_guard_release','tls_guard_abort',
                      'guard_acquire','guard_release','guard_abort'):
            require(kind not in ('void','function','handle') and 'complete' in item['flags'],
                    'ABI_SOURCE_GUARDED_VARIABLE')
            self.graph.layout(reference,owner);self.shape(owner,item)
            if name=='tls_address':
                require(target is not None,'ABI_SOURCE_TLS_TARGET')
                target_owner,target_ref=target
                require(self.graph.compatible(reference,target_ref,owner,target_owner,ignore_top_cv=True),
                        'ABI_SOURCE_TLS_TARGET')
        elif name in ('va_arg','eh_allocate'):
            excluded=('void','function','reference','array','handle') + (('snapshot',) if name=='eh_allocate' else ())
            require(kind not in excluded and 'complete' in item['flags'] and (name!='eh_allocate' or not item['qualifiers']),
                    'ABI_SOURCE_PAYLOAD_TYPE')
            self.graph.layout(reference,owner);shape=self.shape(owner,item)
            if name=='va_arg':
                require(type0 is not None,'ABI_SOURCE_VARARG_TYPE0')
                execution_owner,execution_ref=type0
                require(shape['identity']==self.execution(execution_owner,execution_ref)['identity'],
                        'ABI_SOURCE_VARARG_TYPE0')
                if kind=='record':
                    require('trivial_copy' in item['flags'] and 'trivial_destroy' in item['flags'],
                            'ABI_SOURCE_VARARG_NONTRIVIAL')
            elif kind=='pointer':
                require(len(item['elements'])==1,'ABI_SOURCE_EXCEPTION_POINTEE')
                _,pointee=self.graph.resolve(item['elements'][0],owner)
                require(pointee['kind'] in ('void','function') or 'complete' in pointee['flags'],
                        'ABI_SOURCE_EXCEPTION_POINTEE')
        else:
            require(False,'ABI_SOURCE_ROLE_UNKNOWN')
        return {'checked_reference_role':name,'original_owner':original_owner,'original_nominal':original_reference,
                'resolved_source_owner':owner,'nominal_id':item['id'],
                'runtime_or_production_authority':False}
