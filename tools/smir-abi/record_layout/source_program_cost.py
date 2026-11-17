"""Fixed finite-lifecycle logical costs; no facts, runtime or native-time bound."""
from pathlib import Path
import hashlib,json
import factory_meter as M
PROFILE='flat_lifecycle_v1'
PATTERNS=frozenset(['^[0-9a-f]{64}$','^[A-Za-z0-9_:-]{1,128}$'])

def active(profile,budget):
 if profile is None:return False
 if type(profile)is not str:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE')
 if budget is None:raise ValueError('ABI_SP_BUDGET')
 M.check_budget(budget)
 if profile!=PROFILE:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE')
 return True

def tick(b,p,work=1,copy=0):
 if active(p,b):b.charge(work=work,copied_bytes=copy)

def collection(b,p,n,width=8):
 if active(p,b):M.collection(b,n,width)

def row(b,p,value,ops=1,native=0):
 """Before one inspected actual block/statement; ops/native are static AST counts.

 Every variable loop has a separate invocation at every actual iteration. The
 plain-tree walk and native passes are charged here before they themselves run.
 This does not prepay other functions or guess total callback counts.
 """
 if not active(p,b):return
 bound,sort=M.json_bound(value,b)
 b.charge(work=(ops+1)*(bound+sort),copied_bytes=bound)
 # Values are bounded descriptors; native compare/set/sort passes in this block
 # cannot compare more entries than the descriptor's actual direct vector sizes.
 if native:
  b.charge(work=1,copied_bytes=64)
  todo=[value]
  while todo:
   b.charge(work=1);v=todo.pop()
   if type(v)is dict:
    n=len(v)
    for _ in range(native):M.collection(b,n,bound)
    b.charge(work=n,edges=n,copied_bytes=64*n);todo.extend(v.values())
   elif type(v)in(list,tuple):
    n=len(v)
    for _ in range(native):M.collection(b,n,bound)
    b.charge(work=n,edges=n,copied_bytes=64*n);todo.extend(v)

def capture(value,b,p):
 if not active(p,b):return
 b.charge(work=1,copied_bytes=64);pending=[(value,1)];nodes=0
 while pending:
  b.charge(work=1);v,depth=pending.pop();nodes+=1
  if depth>64 or nodes>16384:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: input dimensions')
  if type(v)is dict:
   b.charge(work=len(v),edges=len(v),copied_bytes=64*len(v))
   for key in v:
    if type(key)is not str or len(key)>256:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: key')
   pending.extend((x,depth+1)for x in v.values())
  elif type(v)is list:
   b.charge(work=len(v),edges=len(v),copied_bytes=64*len(v));pending.extend((x,depth+1)for x in v)
  elif type(v)is str and len(v)>256:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: text')
 bound,sort=M.json_bound(value,b)
 if bound>1<<20:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: ASCII bound')
 b.charge(work=4*bound+sort,copied_bytes=3*bound+256)

def schema_node(schema,value,b,p):
 if not active(p,b):return
 row(b,p,value,ops=84,native=5)
 b.charge(work=len(schema))
 M.collection(b,len(schema),max((len(k)for k in schema),default=0))
 for field in('required','enum','oneOf','anyOf'):
  v=schema.get(field)
  if v is not None:
   b.charge(work=len(v))
   width=max((len(x)for x in v if type(x)is str),default=0)
   M.collection(b,len(v),width)
 pattern=schema.get('pattern')
 if pattern is not None:
  if pattern not in PATTERNS:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: schema pattern')
  b.charge(work=len(pattern)+4*(len(value)if type(value)is str else 1))

def load_schema(path,pin,b,p):
 if not active(p,b):raise RuntimeError('strict schema loader requires profile')
 path=Path(path);n=path.stat().st_size
 if not 0<n<=1<<20:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: schema size')
 b.charge(work=8*(n+1),copied_bytes=8*(n+1))
 with path.open('rb')as f:raw=f.read(n+1)
 if len(raw)!=n or hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE: schema identity')
 return raw,json.loads(raw)

def source_profile(d,b,p):
 if not active(p,b):return
 def require(x):
  if not x:raise ValueError('ABI_SP_COST_PROFILE_UNAVAILABLE')
 row(b,p,d,ops=134,native=1)
 require(len(d['contexts'])==1 and len(d['records'])<=4 and len(d['methods'])<=8 and len(d['cleanups'])<=8 and len(d['programs'])<=8)
 require(not d['array_progress']and not d['implicit_selections']and not d['ast_bindings'])
 b.charge(work=1,copied_bytes=64);todo=[d];nodes=0
 while todo:
  b.charge(work=1);v=todo.pop();nodes+=1;require(nodes<=16384)
  if type(v)is dict:
   b.charge(work=len(v),edges=len(v),copied_bytes=64*len(v))
   if set(v)=={'module','id'}:require(v['module']=={'kind':'self'})
   todo.extend(v.values())
  elif type(v)is list:b.charge(work=len(v),edges=len(v),copied_bytes=64*len(v));todo.extend(v)
  elif type(v)is str:require(len(v)<=256)
 for r in d['records']:
  row(b,p,r,ops=134,native=1)
  require(r['record_kind']in('struct','class')and all(0<=r[n]<=4096 for n in('complete_size','nonvirtual_size','alignment','nonvirtual_alignment'))and len(r['slots'])<=8)
  for s in r['slots']:
   row(b,p,s,ops=134,native=1)
   require(s['kind']=='member'and s['element_kind']=='scalar'and s['element_record']is None and not s['array_extents']and s['destructor']is None and len(s['paths'])==1 and len(s['paths'][0])==1 and s['paths'][0][0]['kind']=='member'and not s['paths'][0][0]['virtual']and 0<=s['offset_bits']<=32768 and 0<=s['width_bits']<=32768)
 for m in d['methods']:row(b,p,m,ops=134);require(m['kind']in('constructor','destructor')and len(m['parameters'])<=16)
 for q in d['programs']:
  row(b,p,q,ops=134,native=1);require(q['variant']in('complete_constructor','base_constructor','complete_destructor','base_destructor','deleting_destructor')and len(q['steps'])<=8)
  if q['delegate']is not None:require(len(q['delegate']['cell_map'])<=8)

def lifecycle_profile(d,b,p):
 if not active(p,b):return
 source_profile(d['source_programs'],b,p)
 if len(d['links'])>4:raise ValueError('ABI_LC_COST_PROFILE_UNAVAILABLE')
 physical=0
 for scope in d['source_contract']['scopes']:
  row(b,p,scope,ops=24,native=2)
  if scope['lifecycle']is not None:
   physical+=1
   if scope['subject']!='physical' or physical>4:raise ValueError('ABI_LC_COST_PROFILE_UNAVAILABLE')
 for rows in d['source_contract'].values():
  if type(rows)is list and len(rows)>256:raise ValueError('ABI_LC_COST_PROFILE_UNAVAILABLE')
