"""Generate exact local JSON schemas from current closed ABI/execution grammars."""
from pathlib import Path
import json,re
HERE=Path(__file__).resolve().parent
from portable_type_paths import foundation
ROOT=foundation()

def obj(properties):
    return dict(type='object',properties=properties,required=list(properties),additionalProperties=False)

def array(items,limit=512):return dict(type='array',items=items,maxItems=limit)
def nullable(item):return dict(anyOf=[dict(type='null'),item])
def integer(maximum=0xffffffff):return dict(type='integer',minimum=0,maximum=maximum)
def text():return dict(type='string',maxLength=1048576)
def constant(value):return dict(const=value)
def generate():
    definitions={}
    def kind(name,prefix,records):
        if name.startswith('opt:'):return nullable(obj(dict(some=kind(name[4:],prefix,records))))
        if name.startswith('vec:'):return array(kind(name[4:],prefix,records),10000)
        if name=='bool':return dict(type='boolean')
        if name in ('token','utf8'):return dict(type='string',maxLength=1048576,**({'pattern':'^[a-z][a-z0-9_]{0,62}$'} if name=='token' else {}))
        if name in ('hex','digest32'):
            return dict(type='string',pattern='^(?:[0-9a-f]{2})*$',minLength=64 if name=='digest32' else 0,maxLength=64 if name=='digest32' else 16*1024*1024)
        m=re.fullmatch('([ui])(8|16|32|64)',name)
        if m:
            bits=int(m[2]);signed=m[1]=='i'
            return dict(type='integer',minimum=-(1<<(bits-1)) if signed else 0,maximum=(1<<(bits-int(signed)))-1)
        if name not in records:raise ValueError('unknown wire grammar '+name)
        return {'$ref':'#/$defs/'+prefix+name}
    for prefix,path in [('abi_','abi/candidate.json'),('exec_','execution/candidate.json')]:
        records=json.loads((ROOT/'docs/specifications/smir/portable/schema'/path).read_text())['records']
        for name,r in records.items():
            if 'variants' in r:
                definitions[prefix+name]=dict(oneOf=[obj({r['discriminator']:constant(tag),**{n:kind(t,prefix,records) for n,t in fields}}) for tag,fields in r['variants'].items()])
            else:definitions[prefix+name]=obj({n:kind(t,prefix,records) for n,t in r['fields']})
    q={'$ref':'#/$defs/abi_qref'}
    digest=dict(type='string',pattern='^[0-9a-f]{64}$',minLength=64,maxLength=64)
    request=obj(dict(language=dict(enum=['c23','cpp23']),source=dict(type='string',minLength=1,maxLength=1048576,pattern='^[\x01-\x7f]*$')))
    request.update({'$schema':'https://json-schema.org/draft/2020-12/schema', 'title':'UNBOUND finite portable type request r1'})
    target=json.loads((ROOT/'docs/specifications/smir/portable/llvm/target.json').read_text())
    product=obj(dict(format=constant('portable-type-projection-draft-r1'),binding=constant('unbound'),
        source_fact_authority=constant(False),semantic_admission=constant(False),runtime_authority=constant(False),library_membership_authority=constant(False),
        language=dict(enum=['c23','cpp23']),abi_identity=digest,
        execution_root={'$ref':'#/$defs/exec_execution_types'},
        abi_fragment=obj(dict(types=array({'$ref':'#/$defs/abi_nominal_type'}),layouts=array({'$ref':'#/$defs/abi_object_layout'}),signatures=array({'$ref':'#/$defs/abi_call_signature'}))),
        emitted_type_relation=array(obj(dict(ast_type=integer(511),nominal=q,execution=nullable(q),layout=nullable(integer(511)),call_plan=nullable(integer(511))))),
        auxiliary_execution_relation=array(obj(dict(vector_ast_type=integer(511),element_ast_type=integer(511),execution=q,reason=constant('numeric_vector_lane')))),
        declarations=array(obj(dict(name=text(),decl_kind=text(),type_id=integer(511),source_offset=integer(1048576)))),
        enum_hooks=array(obj(dict(name=text(),before=text(),after=text(),phase=constant('before_subsequent_declarations')))),
        target=obj(dict(factory_calls=constant(1),triple=constant(target['triple']),datalayout=constant(target['datalayout']),little_endian=constant(True),pointer_bits=constant(64),long_bits=constant(64),long_double_bits=constant(128),long_double_precision=constant(113))),
        limitations=array(text(),32),input=obj(dict(source_sha256=digest,native_sha256=digest,
            virtual_path=dict(enum=['/rax-source-v1/main.c','/rax-source-v1/main.cpp']),source_date_epoch=constant(0),mtime=constant(0)))))
    product.update({'$schema':'https://json-schema.org/draft/2020-12/schema','$defs':definitions,'title':'UNBOUND finite portable AST/type/ABI projection r1'})
    return request,product

if __name__=='__main__':
    for name,value in zip(('portable_type_request.schema.json','portable_type_projection.schema.json'),generate()):
        (HERE/name).write_text(json.dumps(value,indent=2)+'\n')
