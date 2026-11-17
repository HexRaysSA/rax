"""Explicit original scalar ABI declarations, independently encoded whole objects.

Only this new fixture prefix is written; --check compares exact existing bytes.
"""
from pathlib import Path
from copy import deepcopy
import hashlib,json,os,subprocess,sys,time
R=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parent;OUT=HERE/'ordinary-scalar-fixtures'
sys.path.insert(0,str(R/'tools/smir-abi'))
from nominal import NominalGraph,ref,some,ZERO
sys.path.insert(0,str(R/'tools/smir-format'))
from codec import CandidateCodec
SPEC=R/'docs/specifications/smir/portable';SCHEMAS={o:json.loads((SPEC/'schema'/o/'candidate.json').read_text()) for o in ('abi','execution','runtime')}
TYPES={'signed char':(8,True),'unsigned char':(8,False),'short':(16,True),'unsigned short':(16,False),'int':(32,True),'unsigned int':(32,False),'long':(64,True),'unsigned long':(64,False),'long long':(64,True),'unsigned long long':(64,False)}
BASE={int(k):v for k,v in json.loads((SPEC/'conformance/execution/candidate/portable-identity.json').read_text())['sections'].items()}

def source(i,kind,entity,bits=0,signed=False,execution=None,layout=None,elements=(),extent=None,flags=()):
 return dict(id=i,domain=0,identity=dict(language='c23',linkage='builtin',entity=entity,definition=ZERO,library=None,unit=None),kind=kind,qualifiers=[],bits=bits,signed=signed,elements=list(elements),extent=extent,representation='none' if execution is None else 'value',execution=None if execution is None else some(ref(execution)),layout=None if layout is None else some(layout),flags=list(flags),methods=[],enumerators=[],record_input=None)

def scalar_object(params,result,linkage='cpp',some_void=False):
 r=deepcopy(BASE)
 r.update({5:dict(payload_revision=2,relocations=[],constant_initializers=[]),7:dict(payload_revision=1,segments=[]),9:dict(payload_revision=1,capabilities=[],requirements=[],limits=[])})
 names=list(dict.fromkeys(params+([] if result is None else [result])))
 ni={name:2000+i for i,name in enumerate(names)};ei={name:1000+TYPES[name][0] for name in names}
 existing={t['id'] for t in r[1]['types']}
 for name in names:
  if ei[name] not in existing:r[1]['types'].append(dict(id=ei[name],kind='int',bits=TYPES[name][0]));existing.add(ei[name])
 fn=6000;r[1]['types'].append(dict(id=fn,kind='function',params=[ref(ei[n]) for n in params],results=[] if result is None else [ref(ei[result])],param_noundef=[True]*len(params),result_noundef=[] if result is None else [True],cc='portable',variadic=False))
 source_types=[];layouts=[]
 for name in names:
  bits,sgn=TYPES[name];sid=ni[name];lid=7000+sid
  source_types.append(source(sid,'scalar',name,bits,sgn,ei[name],lid,flags=['complete','trivial_copy','trivial_destroy']))
  layouts.append(dict(id=lid,type=ref(sid),size=bits//8,align=bits//8,data_size=bits//8,nonvirtual_size=bits//8,nonvirtual_align=bits//8,fields=[],bases=[],vptrs=[]))
 void=2999
 if result is None:source_types.append(source(void,'void','void'))
 proto=source(3000,'function','function',elements=[ref(ni[n]) for n in params]+[ref(void if result is None else ni[result])],extent=some(len(params)),flags=['complete']+(['c_linkage'] if linkage=='c' else []))
 proto['identity']['language']='c23' if linkage=='c' else 'cpp23'
 source_types.append(proto)
 plan=dict(id=0,function_type=ref(3000),params=[ref(ni[n]) for n in params],result=some(ref(void)) if some_void else None if result is None else some(ref(ni[result])),this_type=None,vtt=False,variadic=False,noexcept=False,lowered_params=[dict(source_index=some(i),role='parameter',source_type=ref(ni[n]),value_type=ref(ni[n]),mode='direct',align=TYPES[n][0]//8,bytes=TYPES[n][0]//8,noundef=True,copy=None,move=None,destroy=None) for i,n in enumerate(params)],lowered_results=[] if result is None else [ref(ni[result])],varargs=None,return_noundef=True,execution=ref(fn))
 r[10].update(types=source_types,layouts=layouts,signatures=[plan],storage_bindings=[],journals=[])
 body=r[3]['functions'][0];body.update(signature=ref(fn),abi_signature=some(ref(0)),params=[dict(id=i,type=ref(ei[n])) for i,n in enumerate(params)])
 operations=[]
 if result is None:returns=[]
 elif result in params:returns=[params.index(result)]
 else:
  operations=[dict(op='constant',results=[dict(id=len(params),type=ref(ei[result]))],operands=[],literal=dict(kind='bits',value=(42).to_bytes(TYPES[result][0]//8,'little').hex()))];returns=[len(params)]
 body['blocks']=[dict(id=0,phis=[],ops=operations,term=dict(op='return',values=returns))]
 r[2]['symbols'][0].update(name='scalar_source',source_linkage=linkage,execution=ref(fn),nominal=some(ref(3000)),abi_signature=some(ref(0)))
 return r

def seal(r):
 g=NominalGraph(r[10],'authored')
 for t in r[10]['types']:t['identity']['definition']=g.fingerprint(ref(t['id'])) if 'complete' in t['flags'] else ZERO
 for table in ('types','layouts','signatures'):r[10][table].sort(key=lambda x:x['id'])
 r[1]['types'].sort(key=lambda x:x['id']);return r


def build():
 cases={}
 def add(name,roots,abi='verified-abi',whole='verified-object'):
  cases[name]=(roots,abi,whole)
 for linkage in ('cpp','c'):
  for name in TYPES:add(linkage+'-'+name.replace(' ','-'),scalar_object([name],name,linkage))
  for name,params,result in [('void',[],None),('sink',['signed char','unsigned short','long long'],None),('mixed',['unsigned char','short','unsigned long long'],'unsigned long long'),('zeroarg-result',[],'unsigned int')]:add(linkage+'-'+name,scalar_object(params,result,linkage))
 add('cpp-some-void',scalar_object([],None,some_void=True),'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 for name,mutate,code in [
  ('bad-signedness',lambda r:r[10]['types'][0].update(signed=True),'ABI_CC_SCALAR_SIGNEDNESS'),
  ('bad-layout',lambda r:r[10]['layouts'][0].update(size=4),'ABI_CC_LAYOUT_EXTENT'),
  ('bad-source-index',lambda r:r[10]['signatures'][0]['lowered_params'][0].update(source_index=some(1)),'ABI_CC_CALL_PARAMETER'),
  ('bad-noundef',lambda r:r[10]['signatures'][0]['lowered_params'][0].update(noundef=False),'ABI_CC_CALL_PARAMETER')]:
  param='unsigned short' if name=='bad-signedness' else 'long' if name=='bad-layout' else 'int'
  x=scalar_object([param],param);mutate(x);add(name,x,code,code)
 x=scalar_object(['int'],'int');x[3]['functions'][0]['blocks'][0]['term']['values']=[];add('bad-return-arity',x,'verified-abi','return_signature')
 x=scalar_object(['long','long long'],'long');x[10]['signatures'][0]['params'][0]=ref(2001);add('bad-samewidth-source',x,'ABI_CC_SOURCE_SIGNATURE','ABI_CC_SOURCE_SIGNATURE')
 x=scalar_object(['unsigned int'],'unsigned int');x[1]['types'].append(dict(id=6001,kind='function',params=[ref(1032)],results=[ref(1032)],cc='portable',variadic=False,param_noundef=[True],result_noundef=[True]));x[2]['symbols'][0]['execution']=ref(6001);add('distinct-equal-full-fn',x)
 x=scalar_object(['long'],'long');x[10]['types'][-1].update(execution=some(ref(6000)),representation='signature');add('explicit-default-fn',x)
 x=scalar_object(['long'],'long');x[10]['signatures'][0]['return_noundef']=False;next(t for t in x[1]['types'] if t['id']==6000)['result_noundef']=[False];add('coherent-return-noundef-false',x)
 x=scalar_object(['unsigned char','long'],'long');other=deepcopy(x[10]['signatures'][0]);other['id']=1;x[10]['signatures'].append(other);add('two-original-plans',x)
 x=scalar_object(['int'],'int');t=deepcopy(x[10]['types'][0]);t.update(id=2500,layout=some(9500));x[10]['types'].append(t);l=deepcopy(x[10]['layouts'][0]);l.update(id=9500,type=ref(2500));x[10]['layouts'].append(l);add('two-original-equal-scalars',x)
 x=scalar_object(['int'],'int');t=deepcopy(x[10]['types'][-1]);t.update(id=3100);x[10]['types'].append(t);p=deepcopy(x[10]['signatures'][0]);p.update(id=1,function_type=ref(3100));x[10]['signatures'].append(p);add('two-original-source-prototypes',x)
 x=scalar_object(['long'],'long');fn=deepcopy(x[3]['functions'][0]);fn['id']=1;x[3]['functions'].append(fn);sym=deepcopy(x[2]['symbols'][0]);sym.update(id=1,name='other',definition=some(dict(kind='function',target=ref(1))));x[2]['symbols'].append(sym);add('two-real-bodies',x)
 x=scalar_object(['unsigned long'],'unsigned long');x[2]['symbols'][0]['definition']=None;add('undefined-original-source',x)
 for name,change in [
  ('plain-char',('char',8,True)),('bool',('bool',1,False)),('char8',('char8_t',8,False)),
  ('size-t',('size_t',64,False)),('int128',('__int128',128,True))]:
  entity,bits,signed=change;x=scalar_object(['int'],'int');t=x[10]['types'][0];t.update(bits=bits,signed=signed);t['identity']['entity']=entity
  execution=1000+bits
  if not any(t['id']==execution for t in x[1]['types']):x[1]['types'].append(dict(id=execution,kind='int',bits=bits))
  t['execution']=some(ref(execution));size=1 if bits==1 else bits//8
  for key in ('size','align','data_size','nonvirtual_size','nonvirtual_align'):x[10]['layouts'][0][key]=size
  p=x[10]['signatures'][0];p['lowered_params'][0].update(align=size,bytes=size)
  f=next(t for t in x[1]['types'] if t['id']==6000);f.update(params=[ref(execution)],results=[ref(execution)])
  x[3]['functions'][0]['params'][0]['type']=ref(execution);add('retained-'+name,x,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 x=scalar_object(['int'],'int');x[10]['types'][0]['qualifiers']=['const'];add('retained-qualified-scalar',x,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 x=scalar_object(['int'],'int');x[10]['types'][-1]['flags'].append('noexcept');x[10]['signatures'][0]['noexcept']=True;x[3]['functions'][0]['escape']='nothrow';add('retained-noexcept',x,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 x=scalar_object(['long'],'long');x[1]['types'].append(dict(id=9001,kind='raw',bits=64));x[10]['types'][0]['execution']=some(ref(9001));f=next(t for t in x[1]['types'] if t['id']==6000);f.update(params=[ref(9001)],results=[ref(9001)]);x[3]['functions'][0]['params'][0]['type']=ref(9001);add('retained-raw-scalar-transport',x,'P2_ABI_VERIFIER_INCOMPLETE','P2_ABI_VERIFIER_INCOMPLETE')
 for entity,expected in [('int','verified-abi'),('long','P2_ABI_VERIFIER_INCOMPLETE')]:
  x=scalar_object([entity],entity);ptr=source(2400,'pointer','pointer',64,False,4,9400,elements=[ref(2000)],flags=['complete','trivial_copy','trivial_destroy']);x[10]['types'].append(ptr);x[10]['layouts'].append(dict(id=9400,type=ref(2400),size=8,align=8,data_size=8,nonvirtual_size=8,nonvirtual_align=8,fields=[],bases=[],vptrs=[]));add('legacy-pointer-'+entity,x,expected,'verified-object' if expected=='verified-abi' else expected)
 return cases


def main():
 cases={};codec=CandidateCodec(SCHEMAS);OUT.mkdir(exist_ok=True)
 def write(path,data):
  if '--check' in sys.argv:
   if path.read_bytes()!=data:raise RuntimeError('stale independent scalar fixture '+str(path))
  else:path.write_bytes(data)
 for name,(roots,abi,whole) in build().items():
  seal(roots);data=codec.encode(roots);write(OUT/(name+'.smo'),data)
  cases[name]=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),expected_abi=abi,expected_object=whole)
 paths={SPEC/'conformance/execution/candidate/portable-identity.json',*(SPEC/'schema'/o/'candidate.json' for o in ('abi','execution','runtime'))}
 for module in tuple(sys.modules.values()):
  value=getattr(module,'__file__',None)
  if value is not None:
   p=Path(value).resolve()
   if p.is_relative_to(R) and p.is_file():paths.add(p)
 manifest=dict(generator=str(Path(__file__).resolve().relative_to(R)),generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),input_sha256={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)},cases=cases,scope='Explicit whole-source scalar objects; expected ABI phase separate from actual full-object factories; no runtime permits/native execution',encoded_object_bytes=sum(c['bytes'] for c in cases.values()),object_count=len(cases))
 write(OUT/'manifest.json',(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode());print('Independent scalar objects',len(cases))

if __name__=='__main__':main()
