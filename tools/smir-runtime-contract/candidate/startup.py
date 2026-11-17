"""Exact CRT entry admission and independently staged guest argv/environment image."""
from .errors import option, require


def validate(function,context):
    signature=context.execution(function['signature'])
    require(signature['kind']=='function' and signature['cc']=='portable' and not signature['variadic']
            and len(signature['params'])==3 and len(signature['results'])==1
            and signature['param_noundef']==[True]*3 and signature['result_noundef']==[True],
            'RT_STARTUP_SIGNATURE')
    definitions=[context.execution(r) for r in signature['params']+signature['results']]
    require(all(definitions[i]['kind']=='int' and definitions[i]['bits']==32 for i in [0,3]) and
            all(definitions[i]['kind']=='data_ptr' and definitions[i]['space']=='guest_data' for i in [1,2]),
            'RT_STARTUP_TYPES')
    require(function['escape']=='terminate' and not function['no_return'],'RT_STARTUP_ESCAPE')
    reference=option(function['abi_signature'])
    require(reference is not None and context.abi_entity is not None,'RT_STARTUP_ABI')
    abi=context.abi_entity('signature',reference)
    require(len(abi['params'])==3 and abi['result'] is not None and abi['this_type'] is None and
            not abi['vtt'] and not abi['variadic'] and abi['varargs'] is None,'RT_STARTUP_ABI')
    source=context.nominal(abi['function_type'])
    require(source['kind']=='function' and 'c_linkage' in source['flags'],'RT_STARTUP_C_LINKAGE')
    def signed_scalar(reference,name,bits):
        value=context.nominal(reference)
        return value['kind']=='scalar' and value['identity']['entity']==name and value['bits']==bits and value['signed']
    require(signed_scalar(abi['params'][0],'int',32) and signed_scalar(option(abi['result']),'int',32),
            'RT_STARTUP_C_TYPES')
    for reference in abi['params'][1:]:
        for _ in range(2):
            pointer=context.nominal(reference)
            require(pointer['kind']=='pointer' and len(pointer['elements'])==1 and not pointer['qualifiers'],
                    'RT_STARTUP_C_POINTERS')
            reference=pointer['elements'][0]
        require(signed_scalar(reference,'char',8),'RT_STARTUP_C_CHAR')
    return function


def utf8(value):
    require(type(value) is str and '\0' not in value,'RT_STARTUP_TEXT')
    try:return value.encode('utf8','strict')
    except UnicodeError:require(False,'RT_STARTUP_UTF8')


def build(program_name,arguments,environment,*,base=65536,quota=16777216):
    """Stage source startup objects; no process/global identity is minted here.

    IDs are local plan identifiers, remapped by actual object factory on commit.
    O(total UTF8 bytes+argument/environment count), same temporary space bound.
    """
    require(type(arguments) is list and type(environment) is list and
            len(arguments)+1<=2**31-1,'RT_STARTUP_ARGUMENTS')
    argv=[utf8(program_name)]+[utf8(value) for value in arguments]
    require(argv[0],'RT_STARTUP_PROGRAM_NAME')
    names=set();env=[]
    for item in environment:
        require(type(item) is dict and set(item)=={'name','value'} and item['name'] and
                item['name'] not in names and '=' not in item['name'],'RT_STARTUP_ENVIRONMENT')
        name,value=utf8(item['name']),utf8(item['value'])
        names.add(item['name']);env.append(name+b'='+value)
    require(type(base) is int and 0<base<2**64 and type(quota) is int and quota>0,'RT_STARTUP_RESOURCE')
    objects=[];cursor=base
    def allocate(payload,alignment=1,origins=()):
        nonlocal cursor
        address=(cursor+alignment-1)&-alignment
        end=address+len(payload)
        require(end<=2**64-1 and end-base<=quota,'RT_STARTUP_RESOURCE')
        identity=len(objects)+1
        record={'object':identity,'generation':1,'address':address,'size':len(payload),
                'alignment':alignment,'kind':'startup','live':True,'bytes':payload.hex(),
                'poison':bytes(len(payload)).hex(),'undef':bytes(len(payload)).hex(),'origins':list(origins)}
        objects.append(record);cursor=end
        return record
    def vector(strings):
        entries=[allocate(text+b'\0') for text in strings]
        payload=b''.join(entry['address'].to_bytes(8,'little') for entry in entries)+bytes(8)
        origins=[{'offset':i*64,'length':64,'object':{'some':entry['object']},'generation':1,
                  'pointer_bits':entry['address'],'source_bit':0,'domain':'data','range':None}
                 for i,entry in enumerate(entries)]
        return allocate(payload,8,origins)
    argv_object=vector(argv);env_object=vector(env)
    return {'argc':len(argv),'argv':argv_object['object'],'envp':env_object['object'],
            'objects':objects,'bytes':cursor-base}


def exit_status(code,host_os):
    require(type(code) is int and -2**31<=code<2**31 and host_os in {'linux','macos','windows'},
            'RT_STARTUP_EXIT_STATUS')
    return code&((1<<32)-1) if host_os=='windows' else code&255
