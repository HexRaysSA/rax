"""Original finite data-pointer source calls; encoder shared, verifier independent.

Only this package's new fixture prefix may be written; --check is nonwriting.
"""
from pathlib import Path
from copy import deepcopy
import hashlib,importlib.util,json,sys
R=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
OUT=HERE/'ordinary-pointer-fixtures'
spec=importlib.util.spec_from_file_location('pointer_scalar_recipe',HERE/'ordinary_scalar_fixtures.py')
scalar=importlib.util.module_from_spec(spec);spec.loader.exec_module(scalar)
source,ref,some,ZERO,seal,TYPES=scalar.source,scalar.ref,scalar.some,scalar.ZERO,scalar.seal,scalar.TYPES
CandidateCodec,SCHEMAS=scalar.CandidateCodec,scalar.SCHEMAS


def pointer_object(params,result,linkage='cpp'):
 r=deepcopy(scalar.BASE)
 r.update({5:dict(payload_revision=2,relocations=[],constant_initializers=[]),7:dict(payload_revision=1,segments=[]),9:dict(payload_revision=1,capabilities=[],requirements=[],limits=[])})
 values=list(dict.fromkeys(params+([] if result is None else [result])))
 integers=list(dict.fromkeys(x.rstrip('*') for x in values if x.rstrip('*')!='void'))
 ni={name:2000+i for i,name in enumerate(integers)}
 ei={name:1000+TYPES[name][0] for name in integers}
 pointers={name:4000+i for i,name in enumerate(x for x in values if x.endswith('*'))}
 void=2999
 source_types=[];layouts=[]
 def object_layout(sid,size):
  return dict(id=7000+sid,type=ref(sid),size=size,align=size,data_size=size,nonvirtual_size=size,nonvirtual_align=size,fields=[],bases=[],vptrs=[])
 existing={t['id'] for t in r[1]['types']}
 for name in integers:
  bits,sgn=TYPES[name];sid=ni[name]
  if ei[name] not in existing:r[1]['types'].append(dict(id=ei[name],kind='int',bits=bits));existing.add(ei[name])
  source_types.append(source(sid,'scalar',name,bits,sgn,ei[name],7000+sid,flags=['complete','trivial_copy','trivial_destroy']));layouts.append(object_layout(sid,bits//8))
 if result is None or any(x=='void*' for x in pointers):source_types.append(source(void,'void','void'))
 for name,sid in pointers.items():
  pointee=void if name=='void*' else ni[name[:-1]]
  source_types.append(source(sid,'pointer','pointer',64,False,4,7000+sid,elements=[ref(pointee)],flags=['complete','trivial_copy','trivial_destroy']));layouts.append(object_layout(sid,8))
 def nominal(name):return pointers[name] if name.endswith('*') else ni[name]
 def physical(name):return 4 if name.endswith('*') else ei[name]
 def size(name):return 8 if name.endswith('*') else TYPES[name][0]//8
 proto=source(3000,'function','function',elements=[ref(nominal(n)) for n in params]+[ref(void if result is None else nominal(result))],extent=some(len(params)),flags=['complete']+(['c_linkage'] if linkage=='c' else []))
 source_types.append(proto)
 for item in source_types:item['identity']['language']='c23' if linkage=='c' else 'cpp23'
 fn=6000
 r[1]['types'].append(dict(id=fn,kind='function',params=[ref(physical(n)) for n in params],results=[] if result is None else [ref(physical(result))],param_noundef=[True]*len(params),result_noundef=[] if result is None else [True],cc='portable',variadic=False))
 plan=dict(id=0,function_type=ref(3000),params=[ref(nominal(n)) for n in params],result=None if result is None else some(ref(nominal(result))),this_type=None,vtt=False,variadic=False,noexcept=False,lowered_params=[dict(source_index=some(i),role='parameter',source_type=ref(nominal(n)),value_type=ref(nominal(n)),mode='direct',align=size(n),bytes=size(n),noundef=True,copy=None,move=None,destroy=None) for i,n in enumerate(params)],lowered_results=[] if result is None else [ref(nominal(result))],varargs=None,return_noundef=True,execution=ref(fn))
 r[10].update(types=source_types,layouts=layouts,signatures=[plan],storage_bindings=[],journals=[])
 body=r[3]['functions'][0];body.update(signature=ref(fn),abi_signature=some(ref(0)),params=[dict(id=i,type=ref(physical(n))) for i,n in enumerate(params)])
 ops=[]
 if result is None:returns=[]
 elif result in params:returns=[params.index(result)]
 else:
  ops=[dict(op='constant',results=[dict(id=len(params),type=ref(physical(result)))],operands=[],literal=dict(kind='bits',value='00'*size(result)))];returns=[len(params)]
 body['blocks']=[dict(id=0,phis=[],ops=ops,term=dict(op='return',values=returns))]
 r[2]['symbols'][0].update(name='pointer_source',source_linkage=linkage,execution=ref(fn),nominal=some(ref(3000)),abi_signature=some(ref(0)))
 return r


def build():
 cases={}
 def add(name,r,abi='verified-abi',whole='verified-object'):cases[name]=(r,abi,whole)
 for linkage in ('cpp','c'):
  for name in TYPES:add(linkage+'-'+name.replace(' ','-')+'-pointer',pointer_object([name+'*'],name+'*',linkage))
  add(linkage+'-void-pointer',pointer_object(['void*'],'void*',linkage))
  add(linkage+'-mixed',pointer_object(['unsigned char','long*','void*','unsigned long long'],'long*',linkage))
  add(linkage+'-sink',pointer_object(['int*','unsigned short'],None,linkage))
  add(linkage+'-zeroarg-pointer-result',pointer_object([],'int*',linkage))
 r=pointer_object(['long*'],'long*');next(x for x in r[10]['types'] if x['kind']=='function').update(execution=some(ref(6000)),representation='signature');add('explicit-default-fn',r)
 r=pointer_object(['int*'],'int*');p=deepcopy(r[10]['signatures'][0]);p['id']=1;r[10]['signatures'].append(p);add('multiple-original-plans',r)
 r=pointer_object(['unsigned int*'],'unsigned int*');f=deepcopy(next(x for x in r[1]['types'] if x['id']==6000));f['id']=6001;r[1]['types'].append(f);r[2]['symbols'][0]['execution']=ref(6001);add('equal-physical-function-alias',r)
 r=pointer_object(['long*'],'long*');r[10]['signatures'][0]['return_noundef']=False;next(x for x in r[1]['types'] if x['id']==6000)['result_noundef']=[False];add('coherent-result-noundef-false',r)

 # Diagnostics measured through actual independent original-root factories; no predicate mocks.
 for name,mutate in [
  ('bad-pointer-bits',lambda r:next(x for x in r[10]['types'] if x['kind']=='pointer').update(bits=32)),
  ('bad-pointer-layout',lambda r:next(x for x in r[10]['layouts'] if x['type']['id']==4000).update(size=4,align=4,data_size=4,nonvirtual_size=4,nonvirtual_align=4)),
  ('bad-source-index',lambda r:r[10]['signatures'][0]['lowered_params'][0].update(source_index=some(1))),
  ('bad-noundef',lambda r:r[10]['signatures'][0]['lowered_params'][0].update(noundef=False)),
  ('bad-argument-bytes',lambda r:r[10]['signatures'][0]['lowered_params'][0].update(bytes=4)),
  ('bad-argument-alignment',lambda r:r[10]['signatures'][0]['lowered_params'][0].update(align=4)),
 ]:
  r=pointer_object(['int*'],'int*');mutate(r);code='ABI_CC_TYPE_BINDING' if name=='bad-pointer-bits' else 'ABI_CC_LAYOUT_POLICY' if name=='bad-pointer-layout' else 'ABI_CC_CALL_PARAMETER';add(name,r,code,code)
 for name,kind in [('bad-int64-pointer','int'),('bad-raw64-pointer','raw'),('bad-code-address-pointer','code_address')]:
  r=pointer_object(['int*'],'int*');t=dict(id=9100,kind=kind)
  if kind!='code_address':t['bits']=64
  r[1]['types'].append(t);next(x for x in r[10]['types'] if x['kind']=='pointer')['execution']=some(ref(9100))
  add(name,r,'ABI_CC_TYPE_BINDING','ABI_CC_TYPE_BINDING')
 for name,params in [('bad-pointee-signedness',['int*','unsigned int*']),('bad-pointee-rank',['long*','long long*']),('bad-pointee-void',['int*','void*'])]:
  r=pointer_object(params,params[0]);r[10]['signatures'][0]['lowered_params'][0]['value_type']=ref(4001);add(name,r,'ABI_CC_DIRECT_TYPE','ABI_CC_DIRECT_TYPE')
 r=pointer_object(['int*'],'int*');r[3]['functions'][0]['blocks'][0]['term']['values']=[];add('bad-return-arity',r,'verified-abi','return_signature')
 r=pointer_object(['int*'],'int*');r[3]['functions'][0]['blocks'][0]['term']['values']=[999];add('bad-return-ssa',r,'verified-abi','ssa_reference')
 for name,kind in [('retained-qualified-pointer','pointer'),('retained-qualified-pointee','scalar')]:
  r=pointer_object(['int*'],'int*');next(x for x in r[10]['types'] if x['kind']==kind)['qualifiers']=['const'];add(name,r,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 r=pointer_object(['int*'],None);r[10]['signatures'][0]['result']=some(ref(2999));add('retained-some-void',r,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 r=pointer_object(['int*'],'int*');ptr=deepcopy(next(x for x in r[10]['types'] if x['kind']=='pointer'));ptr.update(id=4100,elements=[ref(4000)],layout=some(11100));r[10]['types'].append(ptr)
 layout=deepcopy(next(x for x in r[10]['layouts'] if x['type']['id']==4000));layout.update(id=11100,type=ref(4100));r[10]['layouts'].append(layout)
 proto=next(x for x in r[10]['types'] if x['kind']=='function');proto['elements']=[ref(4100),ref(4100)];plan=r[10]['signatures'][0];plan.update(params=[ref(4100)],result=some(ref(4100)),lowered_results=[ref(4100)]);plan['lowered_params'][0].update(source_type=ref(4100),value_type=ref(4100))
 add('retained-pointer-chain',r,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')

 r=pointer_object(['int*'],'int*');ptr=deepcopy(next(x for x in r[10]['types'] if x['kind']=='pointer'));ptr.update(id=4100,layout=some(11100));r[10]['types'].append(ptr)
 layout=deepcopy(next(x for x in r[10]['layouts'] if x['type']['id']==4000));layout.update(id=11100,type=ref(4100));r[10]['layouts'].append(layout);r[10]['signatures'][0]['lowered_params'][0]['value_type']=ref(4100);add('compatible-source-pointer-alias',r)
 r=pointer_object(['long*'],'long*')
 def rename(x):
  if isinstance(x,dict):
   if set(x)=={'module','id'} and x['module']=={'kind':'self'} and x['id'] in (2000,3000,4000,6000):x['id']+=10000
   else:
    for value in x.values():rename(value)
  elif isinstance(x,list):
   for value in x:rename(value)
 rename(r)
 for x in r[1]['types']:
  if x['id']==6000:x['id']+=10000
 for x in r[10]['types']:
  if x['id'] in (2000,3000,4000):x['id']+=10000
 add('alpha-renamed-source-and-full-function',r)
 for name,kind in [('bad-unused-pointer-row','pointer'),('bad-unused-integer-row','scalar')]:
  r=pointer_object(['int*'],'int*');node=deepcopy(next(x for x in r[10]['types'] if x['kind']==kind));node.update(id=4500,bits=16,layout=some(11500));r[10]['types'].append(node)
  layout=deepcopy(next(x for x in r[10]['layouts'] if x['type']['id']==(4000 if kind=='pointer' else 2000)));layout.update(id=11500,type=ref(4500));r[10]['layouts'].append(layout);add(name,r,'ABI_CC_TYPE_BINDING','ABI_CC_TYPE_BINDING')
 r=pointer_object(['int*'],'int*');next(x for x in r[10]['types'] if x['kind']=='function').update(execution=some(ref(1)),representation='signature');add('bad-default-not-function',r,'ABI_CC_TYPE_BINDING','ABI_CC_TYPE_BINDING')
 cases['original-pointer-diamond']=( {int(k):v for k,v in json.loads((OUT/'original-pointer.source.json').read_text())['sections'].items()},'verified-abi','verified-object')
 original=deepcopy(cases['original-pointer-diamond'][0]);original[3]['functions'][0]['blocks'][3]['phis'][0]['incoming'][0]['value']=999;add('bad-original-phi-ssa',original,'verified-abi','ssa_reference')
 return cases


def main():
 OUT.mkdir(exist_ok=True);cases={};codec=CandidateCodec(SCHEMAS)
 def write(p,data):
  if '--check' in sys.argv:
   if p.read_bytes()!=data:raise RuntimeError('stale original pointer fixture '+str(p))
  else:p.write_bytes(data)
 for name,(r,abi,whole) in build().items():
  data=codec.encode(seal(r));write(OUT/(name+'.smo'),data);cases[name]=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),expected_abi=abi,expected_object=whole)
 paths={Path(scalar.__file__).resolve(),scalar.SPEC/'conformance/execution/candidate/portable-identity.json',OUT/'original-pointer.source.json',*(scalar.SPEC/'schema'/o/'candidate.json' for o in ('abi','execution','runtime'))}
 for module in tuple(sys.modules.values()):
  path=getattr(module,'__file__',None)
  if path is not None:
   path=Path(path).resolve()
   if path.is_relative_to(R) and path.is_file():paths.add(path)
 manifest=dict(input_sha256={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)},generator=str(Path(__file__).resolve().relative_to(R)),generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,object_count=len(cases),encoded_object_bytes=sum(x['bytes'] for x in cases.values()),scope='Original type/source/layout/call/body whole objects; static factory phases distinct, no pointer permissions or execution claim')
 write(OUT/'manifest.json',(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode());print('Original pointer objects',len(cases))
if __name__=='__main__':main()
