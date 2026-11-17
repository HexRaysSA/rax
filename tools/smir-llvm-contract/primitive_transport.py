"""LLVM-only primitive transport projection; no runtime import admission/emission."""
from canonical import require

LLVM = {'u8':'i8','u32':'i32','i32':'i32','u64':'i64','i1':'i1',
        'data_ptr':'ptr','code_ptr':'ptr','binary16':'half','bfloat16':'bfloat',
        'binary32':'float','binary64':'double','binary128':'fp128'}
OPAQUE = {'exception','journal','stack_mark','fenv'}


def opaque_carrier(name, parameters=()):
    require(type(name) is str and name.startswith('smir.') and name[5:] in OPAQUE
            and type(parameters) in (tuple,list) and not parameters,'E-TARGET-TYPE')
    return {'kind':name[5:], 'compiler_private':True, 'ordinary_storage':False,
            'requires_admitted_context':True}


def freeze_carrier(kind, *, proven_concrete_valid=False):
    require(kind in OPAQUE,'E-TARGET-TYPE')
    require(kind=='fenv' or proven_concrete_valid,'E-OPAQUE-FREEZE')
    return 'default_snapshot_for_undefined_components' if kind=='fenv' else 'copy_valid_handle'


def llvm_type(value, depth=0):
    require(depth<=64,'PRIMITIVE_TYPE_RESOURCE')
    if type(value) is str:
        require(value in LLVM,'PRIMITIVE_TYPE')
        return LLVM[value]
    require(type(value) is dict and 'kind' in value,'PRIMITIVE_TYPE')
    kind=value['kind']
    if kind in {'int','raw'}:
        require(type(value.get('bits')) is int and 1<=value['bits']<=2**23,'PRIMITIVE_WIDTH')
        return ('i' if kind=='int' else 'b')+str(value['bits'])
    if kind=='float':
        return llvm_type(value['format'],depth+1)
    if kind in {'data_ptr','code_ptr'}:
        return 'ptr'
    if kind in OPAQUE:
        return 'target("smir.'+kind+'")'
    if kind in {'array','vector'}:
        count=value.get('count')
        limit=2**64 if kind=='array' else 2**32
        require(type(count) is int and 0<=count<limit and (kind!='vector' or count>0),'PRIMITIVE_COUNT')
        child=llvm_type(value['element'],depth+1)
        if kind=='vector':
            require(type(value['element']) is dict and value['element'].get('kind') in
                    {'int','raw','float','data_ptr','code_ptr'},'PRIMITIVE_VECTOR_ELEMENT')
        return ('[' if kind=='array' else '<')+str(count)+' x '+child+(']' if kind=='array' else '>')
    require(kind=='struct' and type(value.get('fields')) is list,'PRIMITIVE_TYPE')
    return '{ '+', '.join(llvm_type(field,depth+1) for field in value['fields'])+' }'


def signature(params, results):
    """Input types are instantiated from admitted catalog/context, never C ABI.

    O(P+R) time/space. Opaque-pointer logical kind/signature remains in that
    context; identical LLVM ptr text is not proof of logical type equality.
    """
    require(type(params) is list and type(results) is list, 'PRIMITIVE_SEQUENCE')
    fields=[llvm_type(t) for t in results]
    returns='void' if not fields else fields[0] if len(fields)==1 else '{ '+', '.join(fields)+' }'
    return {'params':[llvm_type(t) for t in params], 'result':returns,
            'logical_params':list(params),'logical_results':list(results),
            'source_abi':None,'variadic':False,'indirect_sret':False}


def declaration(name, params, results):
    require(type(name) is str and name.startswith('__rax_primitive_') and
            all(c.isascii() and (c.isalnum() or c=='_') for c in name), 'PRIMITIVE_NAME')
    plan=signature(params,results)
    return 'declare '+plan['result']+' @'+name+'('+', '.join(plan['params'])+')'


def pack_results(results, count):
    """Reference SSA assembly preserves component poison/origin objects verbatim."""
    require(type(results) is list and type(count) is int and count>=0 and len(results)==count,
            'PRIMITIVE_RESULT_ARITY')
    return None if count==0 else results[0] if count==1 else tuple(results)


def extract_result(value, count, index):
    require(type(count) is int and count>0 and type(index) is int and 0<=index<count,
            'PRIMITIVE_EXTRACT')
    require(count==1 or type(value) is tuple and len(value)==count,'PRIMITIVE_AGGREGATE')
    return value if count==1 else value[index]
