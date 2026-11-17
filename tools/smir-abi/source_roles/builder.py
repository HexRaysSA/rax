"""Accepted ABI034REV2 pure fragments; caller must merge, seal and actually verify."""
from nominal import ZERO, ref, some
from layout import require

SOURCE_KEYS = ('uint32','uint64','va_state','jmp_state','va_list','jmp_buf')
EXECUTION_KEYS = ('uint32','uint64','raw8','state_bytes','list_wrapper')
FLAGS = ['complete','trivial_copy','trivial_destroy']


def identifiers(values, keys):
    require(type(values) is dict and set(values)==set(keys), 'ABI_SOURCE_BUILDER_IDS')
    require(all(type(v) is int and 0<=v<0xffffffff for v in values.values()) and
            len(set(values.values()))==len(values), 'ABI_SOURCE_BUILDER_IDS')


def build_builtin_states(*, source_ids, execution_ids, domain_id):
    identifiers(source_ids,SOURCE_KEYS)
    identifiers(execution_ids,EXECUTION_KEYS)
    require(type(domain_id) is int and 0<=domain_id<0xffffffff,'ABI_SOURCE_BUILDER_DOMAIN')
    types=[];layouts=[]
    def add(key,kind,entity,size,align,execution,bits=0,elements=(),extent=None,fields=()):
        identifier=source_ids[key]
        source_fields=[dict(name=some(name),type=ref(source_ids[child]),bit_width=None,
                            explicit_align=None,no_unique_address=False,anonymous=False,access='public')
                       for name,child,offset,width in fields]
        source_input=None if kind!='record' else some(dict(revision=1,kind='struct',explicit_align=None,
            pod03=False,trivial=False,standard_layout=False,polymorphic=False,dynamic=False,empty=False,
            fields=source_fields,bases=[]))
        types.append(dict(id=identifier,domain=domain_id,identity=dict(language='c23',linkage='builtin',
            entity=entity,definition=ZERO,library=None,unit=None),kind=kind,qualifiers=[],bits=bits,signed=False,
            elements=[ref(source_ids[k]) for k in elements],extent=None if extent is None else some(extent),
            representation='storage' if kind=='record' else 'value',execution=some(ref(execution_ids[execution])),
            layout=some(identifier),flags=FLAGS.copy(),methods=[],enumerators=[],record_input=source_input))
        layouts.append(dict(id=identifier,type=ref(identifier),size=size,align=align,data_size=size,
            nonvirtual_size=size,nonvirtual_align=align,
            fields=[dict(declaration_index=i,name=name,type=ref(source_ids[child]),offset_bits=offset*8,
                         width_bits=width,flags=[]) for i,(name,child,offset,width) in enumerate(fields)],
            bases=[],vptrs=[]))
    add('uint32','scalar','unsigned int',4,4,'uint32',bits=32)
    add('uint64','scalar','unsigned long',8,8,'uint64',bits=64)
    add('va_state','record','rax.va_state',32,8,'state_bytes',fields=[
        (name,'uint64',i*8,64) for i,name in enumerate(('area','cursor','limit','cookie'))])
    add('jmp_state','record','rax.jmp_state',32,8,'state_bytes',fields=[
        ('revision','uint32',0,32),('reserved','uint32',4,32),('process','uint64',8,64),
        ('checkpoint','uint64',16,64),('generation','uint64',24,64)])
    add('va_list','array','array',32,8,'list_wrapper',elements=('va_state',),extent=1)
    add('jmp_buf','array','array',32,8,'list_wrapper',elements=('jmp_state',),extent=1)
    execution_graph=[dict(id=execution_ids['uint32'],kind='int',bits=32),
        dict(id=execution_ids['uint64'],kind='int',bits=64),dict(id=execution_ids['raw8'],kind='raw',bits=8),
        dict(id=execution_ids['state_bytes'],kind='array',element=ref(execution_ids['raw8']),count=32),
        dict(id=execution_ids['list_wrapper'],kind='array',element=ref(execution_ids['state_bytes']),count=1)]
    return dict(types=types,layouts=layouts,execution_graph=execution_graph,
                va_state=ref(source_ids['va_state']),jmp_state=ref(source_ids['jmp_state']),
                va_list=ref(source_ids['va_list']),jmp_buf=ref(source_ids['jmp_buf']))
