"""Draft standalone fixture reproduction. No native body or runtime authority."""
from pathlib import Path
from copy import deepcopy
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[4]
OUT=Path(__file__).with_name('nonordinary-entry-fixtures')
for rel in ['tools/smir-abi','tools/smir-format/execution','tools/smir-format']:sys.path.insert(0,str(ROOT/rel))
from function_address.fixtures import seal
from codec import CandidateCodec
SCHEMAS={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in['abi','execution','runtime']}
codec=CandidateCodec(SCHEMAS)
ref=lambda n:dict(module=dict(kind='self'),id=n)
def original(n):return {int(k):v for k,v in json.loads((OUT/'blueprints'/(n+'.json')).read_bytes())['sections'].items()}
def plan(x):return next(p for p in x[10]['signatures']if p['id']==202)
def body(x):return next(f for f in x[3]['functions']if f['id']==1800)
def typ(x,n):return next(t for t in x[10]['types']if t['id']==n)
def wrong_method(x):typ(x,100)['methods'][0]['signature']=ref(1)
def unknown_method(x):typ(x,100)['methods'][0]['signature']=ref(105)
def ordinary_default(x):typ(x,1501).update(execution={'some':ref(1800)},representation='signature')
def body_call(x):
 f=next(f for f in x[3]['functions']if f['id']==0);block=f['blocks'][0];block['ops'].insert(0,dict(op='constant',results=[dict(id=88,type=ref(1002))],operands=[],literal=dict(kind='zero')));block['ops'].insert(1,dict(op='call',results=[],operands=[88],target=dict(kind='direct',function=ref(1800),signature=ref(1800)),unwind='propagate',source_plan={'some':ref(202)}))
def union(x):typ(x,100)['record_input']['some']['kind']='union';typ(x,100)['flags'].append('union')
mutations=[('wrong-sret-order','method-sret',lambda x:plan(x)['lowered_params'].reverse(),'semantic'),('wrong-noundef','constructor',lambda x:typ(x,1800)if False else next(t for t in x[1]['types']if t['id']==1800)['param_noundef'].__setitem__(0,False),'semantic'),('vtt-without-this','constructor-vtt',lambda x:plan(x).__setitem__('this_type',None),'semantic'),('bad-method-type','constructor',wrong_method,'semantic'),('unmatched-method-declaration','constructor',unknown_method,'unavailable-evidence'),('wrong-body-parameter','constructor',lambda x:body(x)['params'][0].__setitem__('type',ref(1000)),'semantic'),('wrong-body-fullfn','constructor',lambda x:body(x).__setitem__('signature',ref(1001)),'semantic'),('missing-entry-association','constructor',lambda x:body(x).__setitem__('abi_signature',None),'unavailable-evidence'),('no-return-with-return','constructor',lambda x:body(x).__setitem__('no_return',True),'semantic'),('nonordinary-source-call','constructor',body_call,'semantic'),('nonordinary-source-default','constructor',ordinary_default,'semantic'),('unsupported-union','constructor',union,'unavailable-evidence'),('wrong-definition-hash','constructor',lambda x:None,'semantic')]

def nominal(r,n):return next(t for t in r[10]['types']if t['id']==n)
def layout(r,n):return next(t for t in r[10]['layouts']if t['id']==n)
def fields(r,count):
 n=nominal(r,100);d=n['record_input']['some'];base=d['fields'][0];d['fields']=[dict(deepcopy(base),name={'some':'value'+str(i)})for i in range(count)];l=layout(r,100);base=l['fields'][0];l['fields']=[dict(deepcopy(base),declaration_index=i,name='value'+str(i),offset_bits=32*i)for i in range(count)]
 for key in['size','data_size','nonvirtual_size']:l[key]=4*count;layout(r,101)[key]=12*count
 next(t for t in r[1]['types']if t['id']==1010)['bits']=32*count

def array(r,count):
 nominal(r,101)['extent']={'some':count};next(t for t in r[1]['types']if t['id']==1011)['count']=count
 for key in['size','data_size','nonvirtual_size']:layout(r,101)[key]=4*count

def nodes(r,total):
 for i in range(total-len(r[10]['types'])):
  n=10000+i;t=deepcopy(nominal(r,1));t['id']=n;t['layout']={'some':n};r[10]['types'].append(t);l=deepcopy(layout(r,1));l.update(id=n,type=ref(n));r[10]['layouts'].append(l)

boundary_cases=[('boundary-fields8',lambda r:fields(r,8),True),('outside-fields9',lambda r:fields(r,9),False),('boundary-array1024',lambda r:array(r,1024),True),('outside-array1025',lambda r:array(r,1025),False),('boundary-nominals32',lambda r:nodes(r,32),True),('outside-nominals33',lambda r:nodes(r,33),False)]

def outputs():
 out={}
 for name in ['constructor','constructor-vtt','destructor','method-sret']:
  out[name+'.smo']=codec.encode(original(name))
 for name,base,edit,_ in mutations:
  roots=original(base);edit(roots);seal(roots)
  if name=='wrong-definition-hash':typ(roots,100)['identity']['definition']='ff'*32
  out[name+'.smo']=codec.encode(roots)
 for name,edit,_ in boundary_cases:
  roots=original('constructor');edit(roots);seal(roots);out[name+'.smo']=codec.encode(roots)
 return out
def main():
 if sys.argv[1:]not in[[],['--check']]:raise SystemExit('usage: nonordinary_entry_fixtures.py [--check]')
 out=outputs()
 if '--check'in sys.argv:
  for name,data in out.items():
   if not(OUT/name).is_file()or(OUT/name).read_bytes()!=data:raise SystemExit('fixture drift '+name)
  print(json.dumps(dict(checked=len(out),octets=sum(map(len,out.values())))));return
 for name,data in out.items():(OUT/name).write_bytes(data)
 print(json.dumps(dict(written=len(out))))
if __name__=='__main__':main()
