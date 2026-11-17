"""Independent source-authored pointer plans; never uses ABI worker fixtures."""
from copy import deepcopy
import json,sys,hashlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
R=Path(__file__).resolve().parents[4]
from ordinary_scalar_fixtures import ordinary,SCALARS,SOURCE,EXECUTION
from fixtures import ref,some,CandidateCodec,SCHEMAS,prepare_declared_abi2_source

def pointer(params=('int*',),result='int*',*,c=False):
 scalar=lambda n:'int' if n.endswith('*') else n
 x=ordinary([scalar(n) for n in params],None if result is None else scalar(result),c=c)
 template=deepcopy(x[10]['types'][0]);layout=deepcopy(x[10]['layouts'][0]);source={};physical={};used={1,12,220}
 for i,n in enumerate(dict.fromkeys([*params,*([] if result is None else [result])])):
  if not n.endswith('*'):source[n]=SOURCE[n];physical[n]=EXECUTION[n];used.add(SOURCE[n]);continue
  pointee=n[:-1];p=220 if pointee=='void' else SOURCE[pointee];used.add(p);s=500+i;e=4000+i
  t=deepcopy(template);t.update(id=s,kind='pointer',bits=64,signed=False,execution=some(ref(e)),layout=some(s),elements=[ref(p)],extent=None,representation='value',flags=['complete','trivial_copy','trivial_destroy']);t['identity'].update(entity='pointer',language='c23' if c else 'cpp23');x[10]['types'].append(t)
  l=deepcopy(layout);l.update(id=s,type=ref(s));
  for k in['size','align','data_size','nonvirtual_size','nonvirtual_align']:l[k]=8
  x[10]['layouts'].append(l);x[1]['types'].append(dict(id=e,kind='data_ptr',space='guest_data'));source[n]=s;physical[n]=e;used.add(s)
 f=next(t for t in x[10]['types'] if t['kind']=='function');f.update(elements=[ref(source[n])for n in params]+[ref(220 if result is None else source[result])])
 p=x[10]['signatures'][0];p.update(params=[ref(source[n])for n in params],result=None if result is None else some(ref(source[result])),lowered_results=[]if result is None else[ref(source[result])])
 for i,(n,l)in enumerate(zip(params,p['lowered_params'])):
  sz=8 if n.endswith('*')else next(b//8 for k,b,_ in SCALARS if k==n);l.update(source_type=ref(source[n]),value_type=ref(source[n]),bytes=sz,align=sz)
 full=next(t for t in x[1]['types']if t['id']==2000);full.update(params=[ref(physical[n])for n in params],results=[]if result is None else[ref(physical[result])])
 fn=x[3]['functions'][0];fn['params']=[dict(id=i,type=ref(physical[n]))for i,n in enumerate(params)];b=fn['blocks'][0];b['ops']=[]
 if result is None:b['term']=dict(op='return',values=[])
 elif result in params:b['term']=dict(op='return',values=[list(params).index(result)])
 else:b['ops']=[dict(op='constant',results=[dict(id=len(params),type=ref(physical[result]))],operands=[],literal=dict(kind='zero'))];b['term']=dict(op='return',values=[len(params)])
 x[10]['types']=[t for t in x[10]['types']if t['id']in used];wanted={t['layout']['some']for t in x[10]['types']if t['layout']is not None};x[10]['layouts']=[l for l in x[10]['layouts']if l['id']in wanted]
 for k in['types','layouts']:x[10][k].sort(key=lambda z:z['id'])
 x[1]['types'].sort(key=lambda z:z['id']);return x

def build():
 cases={}
 def add(n,x,expected='static'):cases[n]=(x,expected)
 for p in[n for n,_,_ in SCALARS]+['void']:
  for c in[False,True]:add(('c-'if c else'cpp-')+p.replace(' ','-')+'-pointer',pointer([p+'*'],p+'*',c=c))
 for c in[False,True]:
  q='c-'if c else'cpp-';add(q+'mixed',pointer(['signed char','unsigned int*','unsigned long','void*'],'unsigned int*',c=c));add(q+'void-return',pointer(['int*'],None,c=c));add(q+'zero-arg-pointer',pointer([],'void*',c=c))
 x=pointer();next(t for t in x[10]['types']if t['kind']=='function').update(execution=None,representation='none');add('explicit-no-default',x)
 x=pointer();x[2]['symbols'][0]['definition']=None;add('undefined-original-source-obligations',x)
 x=pointer();x[10]['types'][-1]['qualifiers']=['const'];add('qualified-pointer-unavailable',x,'unavailable')
 x=pointer();next(t for t in x[10]['types']if t['kind']=='pointer')['elements']=[ref(220)];add('valid-void-pointee',x)
 x=pointer();next(t for t in x[1]['types']if t['id']==4000).update(kind='int',bits=64);next(t for t in x[1]['types']if t['id']==4000).pop('space');add('integer-is-not-pointer',x,'semantic')
 x=pointer();next(t for t in x[10]['types']if t['kind']=='pointer')['bits']=32;add('wrong-pointer-width',x,'semantic')
 x=pointer();x[10]['signatures'][0]['lowered_params'][0]['bytes']=4;add('wrong-pointer-argument-size',x,'semantic')
 x=pointer();x[3]['functions'][0]['blocks'][0]['term']['values']=[1234];add('unknown-return-ssa',x,'semantic')
 x=pointer(['int*','unsigned int*'],'int*');x[10]['signatures'][0]['lowered_params'][0]['value_type']=ref(501);add('same-dataptr-wrong-pointee',x,'semantic')
 x=pointer(['long*','long long*'],'long*');x[10]['signatures'][0]['lowered_params'][0]['value_type']=ref(501);add('same-dataptr-wrong-rank',x,'semantic')
 x=pointer(['int*','void*'],'int*');x[10]['signatures'][0]['lowered_params'][0]['value_type']=ref(501);add('same-dataptr-wrong-void',x,'semantic')
 x=pointer();x[2]['symbols'][0]['visibility']='hidden';add('hidden-symbol-unavailable',x,'unavailable')
 x=pointer();x[10]['signatures'][0]['noexcept']=True;next(t for t in x[10]['types']if t['kind']=='function')['flags']=['complete','noexcept'];add('noexcept-plan-unavailable',x,'unavailable')
 x=pointer();x[10]['signatures'][0]['lowered_params'][0]['source_index']=some(1);add('wrong-source-index',x,'semantic')
 x=pointer();x[3]['functions'][0]['params'][0]['type']=ref(1);add('wrong-body-parameter',x,'semantic')
 return cases
def main():
 from fixture_provenance import provenance,write_bytes,write_text
 O=HERE/'ordinary-pointer-fixtures'
 if '--check' not in sys.argv:O.mkdir(exist_ok=True)
 codec=CandidateCodec(SCHEMAS);manifest={}
 codes={'integer-is-not-pointer':'ABI_CC_TYPE_BINDING','wrong-pointer-width':'ABI_CC_TYPE_BINDING','wrong-pointer-argument-size':'ABI_CC_CALL_PARAMETER','unknown-return-ssa':'ssa_reference','same-dataptr-wrong-pointee':'ABI_CC_DIRECT_TYPE','same-dataptr-wrong-rank':'ABI_CC_DIRECT_TYPE','same-dataptr-wrong-void':'ABI_CC_DIRECT_TYPE','hidden-symbol-unavailable':'P2_METADATA_PROFILE_UNAUDITED','qualified-pointer-unavailable':'P2_ABI_VERIFIER_INCOMPLETE','noexcept-plan-unavailable':'P2_ABI_VERIFIER_INCOMPLETE','wrong-source-index':'ABI_CC_CALL_PARAMETER','wrong-body-parameter':'parameter_signature'}
 for n,(x,e)in build().items():
  prepare_declared_abi2_source(x);raw=codec.encode(x);write_bytes(O/(n+'.smo'),raw);manifest[n]=dict(expected=e,code=codes.get(n),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),content_identity=codec.decode(raw).content_digest)
 inputs=['crates/smir-portable/tests/metadata/ordinary_scalar_fixtures.py','crates/smir-portable/tests/metadata/manifest_symbol_fixtures.py','crates/smir-portable/tests/metadata/fixtures.py','crates/smir-portable/tests/metadata/profile_fixtures.py','docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json']
 write_text(O/'manifest.json',json.dumps(dict(scope=__doc__,provenance=provenance(__file__,inputs,manifest),cases=manifest),indent=2)+'\n')
 print('ordinary pointer independent source objects',len(manifest))
if __name__=='__main__':main()
