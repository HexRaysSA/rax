"""Executable portable service admission/preflight, fixed structures and errno maps."""
import hashlib
import json
from pathlib import Path
import struct

from .errors import option, require, uint
from .helpers import match_type
from .wire import validate_shape, decode

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'docs/specifications/smir/portable/schema/runtime'


def catalog():
    return json.loads((BASE/'services-v1.json').read_text())


def digest(document=None):
    raw=json.dumps(catalog() if document is None else document,sort_keys=True,
                   separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    return hashlib.sha256(b'SMIR-SERVICES-V1\0'+raw).hexdigest()


def service(name):
    matches=[row for row in catalog()['records'] if row['name']==name]
    require(len(matches)==1,'RT_SERVICE_UNKNOWN',name)
    return matches[0]


def instantiate(record, resolve_type, resolve_abi):
    validate_shape('runtime_import',record)
    require(record['kind']=='service','RT_SERVICE_IMPORT_KIND')
    spec=service(record['name'])
    require(record['namespace']==spec['namespace'] and record['version']==1 and
            record['catalog']==digest(),'RT_SERVICE_VERSION')
    require(record['capability']==spec['capability'],'RT_SERVICE_CAPABILITY')
    require(record['abi'] is None,'RT_SERVICE_UNUSED_ABI')
    signature=resolve_type(record['signature'])
    require(signature['kind']=='function' and signature['cc']=='portable' and
            signature['variadic'] is False,'RT_SERVICE_SIGNATURE')
    for side,attrs in [('params','param_noundef'),('results','result_noundef')]:
        require(len(signature[side])==len(spec[side]) and signature[attrs]==
                [item['noundef'] for item in spec[side]],'RT_SERVICE_SIGNATURE')
        for expected,reference in zip(spec[side],signature[side]):
            require(match_type(expected['type'],resolve_type(reference),[]),'RT_SERVICE_TYPE')
    namespace=spec['descriptor_namespace']
    descriptor=option(record['descriptor'])
    if namespace=='none':
        require(descriptor is None,'RT_SERVICE_UNUSED_DESCRIPTOR')
    else:
        require(descriptor is not None and resolve_abi is not None,'RT_SERVICE_DESCRIPTOR_REQUIRED')
        admitted=resolve_abi(namespace,descriptor)
        if namespace=='signature':
            source=resolve_abi('nominal',admitted['function_type'])
            lowered=option(source['execution'])
            returned=resolve_type(signature['results'][1])
            require(lowered is not None and returned['kind']=='code_ptr' and
                    match_type('type0',resolve_type(lowered),[resolve_type(returned['signature'])]),
                    'RT_SERVICE_LOOKUP_SIGNATURE')
        else:
            require(admitted['kind'] not in {'void','function'},'RT_SERVICE_LOOKUP_TYPE')
    return spec


def errno_tables():
    return json.loads((BASE/'errno-v1.json').read_text())


def from_personality(domain,value):
    tables=errno_tables()
    require(domain in tables['from_personality'],'RT_ERROR_DOMAIN')
    uint(value,32)
    status=tables['from_personality'][domain].get(str(value),tables['unknown_native_fallback'])
    return {'status':status,'cause':{'domain':domain,'raw':value}}


def to_personality(domain,status):
    tables=errno_tables()
    require(domain in tables['to_personality'],'RT_ERROR_DOMAIN')
    if status==0:
        return 0
    require(type(status) is int and str(status) in tables['to_personality'][domain],
            'RT_ERROR_STATUS')
    return tables['to_personality'][domain][str(status)]['value']


def text(payload,*,empty=False,maximum=4096):
    require(type(payload) is bytes and (empty or payload) and len(payload)<=maximum
            and b'\0' not in payload,'RT_SERVICE_TEXT')
    try:
        return payload.decode('utf8','strict')
    except UnicodeError:
        require(False,'RT_SERVICE_UTF8')


def structure(name,payload):
    spec=catalog()['structures'].get(name)
    require(spec is not None and type(payload) is bytes and len(payload)>=spec['size'],
            'RT_SERVICE_STRUCTURE')
    values=dict(zip(spec['fields'],struct.unpack(spec['format'],payload[:spec['size']])))
    require(all(value==0 or type(value) is bytes and not any(value)
                for field,value in values.items() if 'reserved' in field),'RT_SERVICE_RESERVED')
    if 'revision1' in values:
        require(values['revision1']==1,'RT_SERVICE_STRUCTURE_REVISION')
    if name=='dir_entry':
        require(len(payload)==16+values['utf8_bytes'] and values['kind']<=7,'RT_SERVICE_DIRENT')
        values['name']=text(payload[16:])
    else:
        require(len(payload)==spec['size'],'RT_SERVICE_STRUCTURE')
    if name=='time16':
        require(values['nanoseconds']<1000000000,'RT_SERVICE_NANOSECONDS')
    if name=='file_info128':
        require(values['kind']<=7 and values['mode']&~0o7777==0 and values['flags']&~7==0,
                'RT_SERVICE_FILE_INFO')
        require(all(values[prefix+'_ns']<1000000000 for prefix in ['atime','mtime','ctime']),
                'RT_SERVICE_NANOSECONDS')
        if values['flags']&1:
            require(values['uid']==values['gid']==2**32-1,'RT_SERVICE_FILE_INFO')
        if values['flags']&2:
            require(values['id_low']==values['id_high']==0,'RT_SERVICE_FILE_INFO')
        if values['flags']&4:
            require(all(values[prefix+suffix]==0 for prefix in ['atime','mtime','ctime']
                        for suffix in ['_seconds','_ns']),'RT_SERVICE_FILE_INFO')
    if name=='space32':
        require(values['available']<=values['free']<=values['capacity'],'RT_SERVICE_SPACE')
    return values


def request(name,arguments,*,capabilities,handles,guard,inputs=None,code=None):
    """Preflight only; guard/handle registries must be runtime-owned facts."""
    spec=service(name)
    require(spec['capability'] in capabilities,'RT_SERVICE_CAPABILITY')
    require(type(arguments) is list and len(arguments)==len(spec['params']),'RT_SERVICE_ARITY')
    inputs={} if inputs is None else inputs
    for value,formal in zip(arguments,spec['params']):
        require(type(value) is int,'RT_SERVICE_ARGUMENT')
        kind=formal['type']
        if kind.startswith('i'):
            width=int(kind[1:])
            require(-(1<<(width-1))<=value<(1<<(width-1)),'RT_SERVICE_ARGUMENT')
        else:
            uint(value,int(kind[1:]) if kind.startswith('u') else 64)
    for rule in spec['constraints']:
        kind,index,*extra=rule
        value=arguments[index]
        if kind=='positive':
            require(value>0,'RT_SERVICE_POSITIVE')
        elif kind=='alignment':
            require(value>0 and value&(value-1)==0,'RT_SERVICE_ALIGNMENT')
        elif kind=='mask':
            require(value&~extra[0]==0,'RT_SERVICE_FLAGS')
        elif kind=='enum':
            require(value in extra[0],'RT_SERVICE_ENUM')
        elif kind=='maximum':
            require(value<=extra[0],'RT_SERVICE_LIMIT')
        elif kind=='open_flags':
            require(value&~31==0 and value&3 and (value&24==0 or value&2),'RT_SERVICE_OPEN_FLAGS')
        elif kind=='handle':
            require(value in handles and handles[value]['live'],'RT_SERVICE_HANDLE')
            expected='module' if name.startswith('module.') else 'thread' if name.startswith('thread.') \
                else 'process' if name.startswith('process.') else 'directory' if name=='file.read_dir' else 'file'
            require(handles[value]['kind']==expected,'RT_SERVICE_HANDLE_KIND')
        elif kind=='thread_entry':
            require(code is not None and code(value,'u64(data_ptr)'),'RT_SERVICE_CODE')
        elif kind=='stack_size':
            require(value==0 or 16384<=value<=1073741824 and value%16==0,'RT_SERVICE_STACK')
        elif kind=='address_alignment':
            require(value and value%extra[0]==0,'RT_SERVICE_ALIGNMENT')
        else:
            require(False,'RT_SERVICE_UNKNOWN_RULE',kind)
    spans=[]
    for direction,index,length,kind in spec['buffers']:
        address=arguments[index]
        length=length if kind in {'fixed','optional_fixed'} else arguments[length]
        if kind=='stream':
            length=min(length,65536)
        if kind=='optional_fixed' and address==0:
            continue
        require(address+length<=2**64 and (not length or address!=0),'RT_SERVICE_BUFFER')
        if length:
            require(guard is not None,'RT_SERVICE_GUARD')
            guard(address,length,direction)
        spans.append((address,length,direction))
        if direction=='in':
            data=inputs.get(index,b'' if length==0 else None)
            require(type(data) is bytes and len(data)==length,
                    'RT_SERVICE_INPUT')
            if kind in {'path','name','text','environment_name','locale'}:
                decoded=text(data,empty=kind=='text')
                if kind=='environment_name':
                    require('=' not in decoded,'RT_SERVICE_ENVIRONMENT_NAME')
                if kind=='locale':
                    require(decoded=='C','RT_SERVICE_LOCALE')
            elif kind=='digest':
                require(len(data)==64 and all(c in b'0123456789abcdef' for c in data),'RT_SERVICE_DIGEST')
            elif kind=='spawn':
                spawn=decode('runtime_spawn_spec',data)
                require(spawn['revision']==1,'RT_SERVICE_SPAWN')
                for item in [*spawn['arguments'],spawn['working_directory']]:
                    text(item.encode('utf8'),empty=True,maximum=1048576)
                names=set()
                for item in spawn['environment']:
                    require(item['name'] not in names and item['name'] and '=' not in item['name'],
                            'RT_SERVICE_SPAWN')
                    text(item['name'].encode('utf8'));text(item['value'].encode('utf8'),empty=True)
                    names.add(item['name'])
                require(len(spawn['inherit'])==len(set(spawn['inherit'])) and
                        all(h in handles and handles[h]['live'] for h in spawn['inherit']),
                        'RT_SERVICE_SPAWN_HANDLE')
    return {'name':name,'arguments':arguments[:],'spans':spans}


def result(checked,status,value,*,authority=None):
    uint(status,32)
    require(status==0 or status in set(errno_tables()['portable'].values()),'RT_ERROR_STATUS')
    name,args=checked['name'],checked['arguments']
    spec=service(name)
    require(not spec['terminal'],'RT_SERVICE_NONRETURNING')
    if spec['results'][1]['type'] in {'data_ptr','code_ptr'}:
        validate_shape('execution_live_value',value)
        payload=value['payload']
        domain='data' if spec['results'][1]['type']=='data_ptr' else 'code'
        require(payload['kind']=='pointer' and payload['domain']==domain,'RT_SERVICE_POINTER_RESULT')
        if status:
            require(payload['address']==0 and payload['object'] is None and payload['generation']==0 and
                    payload['range'] is None,'RT_SERVICE_ERROR_POINTER')
        else:
            require(payload['address']!=0 and authority is not None and authority(value),
                    'RT_SERVICE_POINTER_AUTHORITY')
        return status,value
    uint(value)
    require(status==0 or value==0,'RT_SERVICE_ERROR_VALUE')
    if status==0 and name in {'file.read','file.write'}:
        require(value<=min(args[2],65536),'RT_SERVICE_PROGRESS')
    if status==0 and name=='entropy.fill':
        require(value==args[1],'RT_SERVICE_PROGRESS')
    return status,value
