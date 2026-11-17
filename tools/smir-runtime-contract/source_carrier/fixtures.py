"""Deterministic structural compiler fixtures; --check never writes."""
from pathlib import Path
from copy import deepcopy
import hashlib,json,sys
from . import codec as V
from .bindings import PROJECT,C,source_api
sys.path.insert(0,str(PROJECT/'tools/smir-runtime-contract'))
from source_contracts.test_factory import factory,pointer_factory,W
from source_contracts.test_checker import owner,base,scoped
HERE=Path(__file__).resolve().parent
F=PROJECT/'docs/specifications/smir/portable/conformance/runtime/source-carrier'
def budget(**kw):
 d=dict(max_work=10**12,max_edges=10**12,max_copied_bytes=10**12,max_depth=128);d.update(kw);return C.source_api().SourceQueryBudget(**d)
def examples():
 yield 'published-sret',*factory()
 yield 'retained-pointer',*pointer_factory()
 yield 'scoped-phi',owner(),scoped()
 o=owner();d=base()
 for key in d['contract']:
  if key!='revision':d['contract'][key]=[]
 yield 'explicit-empty',o,d

def representative(codec,kind,path='',tag=None,nonnull=False):
 rule=codec.rules.get(path,{})
 if kind.startswith('opt:'):return {'some':representative(codec,kind[4:],path,nonnull=nonnull)}if nonnull else None
 if kind.startswith('vec:'):
  return [representative(codec,kind[4:],path+'[]',nonnull=nonnull)for _ in range(codec.caps.get(path,{}).get('minimum',0))]
 if'anyOf'in rule:
  arms=[r for r in rule['anyOf']if r.get('type')!='null']
  if len(arms)==1:rule=arms[0]
 if 'const'in rule:return rule['const']
 if 'enum'in rule:return rule['enum'][0]
 if kind[0:1]in('u','i')and kind[1:].isdigit():return rule.get('minimum',0)
 if kind=='bool':return False
 if kind=='digest32':return '00'*32
 if kind=='hex':return ''
 if kind in('token','utf8'):return 'x'
 r=codec.records[kind];p=kind;out={}
 if'discriminator'in r:
  key=r['discriminator'];tag=tag or next(iter(r['variants']));out[key]=tag;fs=r['variants'][tag];p+='.'+tag
 else:fs=r['fields']
 for name,t in fs:out[name]=representative(codec,t,p+'.'+name,nonnull=nonnull)
 return out

def products():
 result={};catalog=[]
 for name,o,d in examples():
  roots=deepcopy(o.sections);b=budget();old=V.encode_module(roots,budget=b)
  roots[3]['payload_revision']=3;roots[3]['source_contract']=V.wire_contract(d['contract'],budget=b)
  raw=V.encode_module(roots,budget=b);payload=V.encode_root3(roots[3],budget=b)
  files={name+'.v2.smo':old,name+'.v3.smo':raw,name+'.root3.bin':payload,name+'.raw.json':(json.dumps(d,indent=2)+'\n').encode(),name+'.wire.json':(json.dumps(roots[3],indent=2)+'\n').encode()}
  result.update(files);catalog.append(dict(name=name,module_digest=V.decode_module(raw,budget=b).digest,original_stamp_revision=2,active_v3_verified=False,executable=False,files={n:hashlib.sha256(x).hexdigest()for n,x in files.items()}))
 # Structural observer example only, unsupported for semantic/original-owner relation.
 o,d=pointer_factory();roots=deepcopy(o.sections);roots[3]['payload_revision']=3;roots[3]['source_contract']=V.wire_contract(d['contract'],budget=budget())
 journal=next(t['id']for t in roots[1]['types']if t['kind']=='journal')
 roots[3]['functions'][1]['blocks'][0]['ops'].append(dict(op='source_journal_observe',results=[dict(id=900,type=dict(module=dict(kind='self'),id=journal))],operands=[],scope_value=100,adoption=10))
 observer=V.encode_module(roots,budget=budget());V.decode_module(observer,budget=budget())
 result['observer-structural-only.v3.smo']=observer
 result['empty.root3.bin']=V.encode_root3(dict(payload_revision=3,functions=[],source_contract=V.wire_contract(dict(revision=1,**{n:[]for n in ('bindings','scopes','scope_values','exits','phase_sites','ends','returns','adoptions')}),budget=budget())),budget=budget())
 codec=V.OrderedCodec(budget());rows=[]
 for name,r in sorted(codec.records.items()):
  for tag in r.get('variants',{'':[]})if'discriminator'in r else ['']:
   for nonnull in (False,True):
    value=representative(codec,name,tag=tag or None,nonnull=nonnull);raw=codec.encode(name,value)
    rows.append(dict(kind=name,variant=tag,nullable_profile='all_some'if nonnull else'all_null',value=value,hex=raw.hex()))
 result['grammar-cases.json']=(json.dumps(rows,indent=2)+'\n').encode()
 result['catalog.json']=(json.dumps(dict(format='owncoord-root3-v3-structural-fixtures',revision=1,executable=False,cases=catalog,grammar_cases=len(rows),observer='structural-only; relation must refuse'),indent=2)+'\n').encode()
 return result

def main():
 expected=products();check='--check'in sys.argv
 if not check:F.mkdir(exist_ok=True)
 for name,raw in expected.items():
  if check:
   if(F/name).read_bytes()!=raw:raise SystemExit('fixture drift '+name)
  else:(F/name).write_bytes(raw)
 print(len(expected),'products','checked'if check else'generated')
if __name__=='__main__':main()
