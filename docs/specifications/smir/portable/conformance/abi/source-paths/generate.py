"""Explicit closed native-AST fixture mapping; not a production SMIR emitter."""
from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[7];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools/smir-abi'));sys.path.insert(0,str(ROOT/'tools/smir-format'))
from function_address.fixtures import ordinary,seal,source as nominal,layout
from nominal import ref,some
from codec import CandidateCodec
report=json.loads((HERE/'clang-records.json').read_bytes());original={t['id']:t for t in report['types']};roots=ordinary()
sourceids={i:10000+i for i in original};executionids={i:20000+i for i in original};records={t['record_name']:sourceids[i] for i,t in original.items() if t['kind']=='record'}
def remap(v):
 if type(v) is dict:
  if set(v)=={'module','id'}:
   assert v['module']=={'kind':'self'};return ref(sourceids[v['id']])
  return {k:remap(x) for k,x in v.items()}
 if type(v) is list:return [remap(x) for x in v]
 return v
for identifier,t in original.items():
 sid=sourceids[identifier];size=t['native_size_bits']//8;align=t['native_align_bits']//8
 if t['kind']=='record':
  source=nominal(sid,'record',entity=t['record_name'],layout_id=sid,execution=executionids[identifier],representation='storage',flags=['complete']+(['union'] if t['record_input']['some']['kind']=='union' else []))
  source['record_input']=remap(t['record_input']);raw=remap(t['native_layout']);raw['id']=sid
  raw['vptrs']=[{k:v[k] for k in ('offset','offset_top','vcall_offsets','vbase_offsets','component_order')}|dict(rtti=None,slots=[]) for v in raw['vptrs']]
 elif t['kind']=='array':
  source=nominal(sid,'array',elements=[sourceids[t['element']['id']]],extent=t['count'],layout_id=sid,execution=executionids[identifier],representation='value',flags=['complete'])
  raw=layout(sid,size,align)
 else:
  assert t['kind']=='scalar' and t['spelling']=='int'
  source=nominal(sid,'scalar',bits=32,execution=1,layout_id=sid,representation='value',flags=['complete','trivial_copy','trivial_destroy'],entity='int');source['signed']=True;source['identity']['language']='c23';raw=layout(sid,size,align)
 if t['const']:source['qualifiers'].append('const')
 if t['volatile']:source['qualifiers'].append('volatile')
 roots[10]['types'].append(source);roots[10]['layouts'].append(raw)
 if t['kind']=='record':roots[1]['types'].append(dict(id=executionids[identifier],kind='raw',bits=size*8))
 elif t['kind']=='array':roots[1]['types'].append(dict(id=executionids[identifier],kind='array',element=ref(executionids[t['element']['id']]),count=t['count']))
seal(roots)
schemas={name:json.loads((ROOT/'docs/specifications/smir/portable/schema'/name/'candidate.json').read_bytes()) for name in ('abi','execution','runtime')}
data=CandidateCodec(schemas).encode(roots)
outputs={'source.smo':data,'records.json':(json.dumps(records,sort_keys=True,indent=2)+'\n').encode()}
for name,content in outputs.items():
 path=HERE/name
 if '--check' in sys.argv:
  if path.read_bytes()!=content:raise RuntimeError('stale source-path fixture '+name)
 else:path.write_bytes(content)
print('Original-source fixture',len(data),'B;',len(records),'records; SHA256',hashlib.sha256(data).hexdigest())
