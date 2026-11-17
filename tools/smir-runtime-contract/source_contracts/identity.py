"""Finite owncoord draft comparator; no registry identity or active body exporter.

Actual ordinary roots/IDs must match byte-structurally; private source IDs admit
joint alpha maps. Unsupported ordinary renaming/providers produce profile error.
This proves only the attached draft static graph, never runtime admission.
"""
from copy import deepcopy
from itertools import permutations
import json
from . import checker as C
TABLES=['bindings','scopes','scope_values','exits','ends','returns','adoptions','phase_sites']

def raw(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def closure(owner,fid,budget,document=None):
 fns={f['id']:f for f in owner.sections[3]['functions']};symbols={x['id']:x for x in owner.sections[2]['symbols']};seen=set();todo=[fid]
 def symbol_function(reference):
  sid=C.qid(reference);visited=set()
  while True:
   C.need(sid in symbols and sid not in visited,'ASC_IDENTITY_SYMBOL_TARGET');visited.add(sid);budget.charge(work=1,edges=1,copied_bytes=64)
   row=symbols[sid];definition=row['definition'];C.need(definition is not None,'ASC_IDENTITY_SYMBOL_TARGET_PROFILE');definition=definition['some']
   if definition['kind']=='alias':sid=C.qid(definition['target']);continue
   if definition['kind']=='function':return C.qid(definition['target'])
   C.need(row['kind']in['data','tls'],'ASC_IDENTITY_SYMBOL_TARGET_PROFILE');return None
 while todo:
  f=todo.pop()
  if f in seen:continue
  C.need(f in fns,'ASC_IDENTITY_FUNCTION');seen.add(f);budget.charge(work=1,edges=1,copied_bytes=128)
  for b in fns[f]['blocks']:
   for op in b['ops']+[b['term']]:
    if op['op']in['call','invoke']:
     target=op['target']
     if target['kind']=='import':
      C.need(any(i['id']==C.qid(target['import'])and i['kind']=='internal'for i in owner.sections[6]['imports']),'ASC_IDENTITY_TARGET_CLOSURE_PROFILE')
     else:C.need(target['kind']=='direct'and target['function']['module']=={'kind':'self'},'ASC_IDENTITY_TARGET_CLOSURE_PROFILE');todo.append(target['function']['id'])
    if op['op']=='address_of':
     target=symbol_function(op['symbol'])
     if target is not None:todo.append(target)
  if document is not None:
   for row in document['contract']['adoptions']:
    if row['function']==f:budget.charge(work=1,edges=1,copied_bytes=64);todo.append(C.qid(row['callee_function']))
 return seen

def alpha(document,mapping):
 """Typed namespaces; QRef and ordinary SSA/literal indices are untouched."""
 d=deepcopy(document);c=d['contract']
 def m(ns,f,x):return mapping[ns,f,x]
 def within(f,w):
  if w['kind']=='scope':w['value']=m('scope_values',f,w['value'])
 for table in TABLES:
  for r in c[table]:
   f=r['function'];old=r['id'];r['id']=m(table,f,old)
   if table=='bindings':
    o=r['origin']
    for k in['binding','old_binding']:
     if k in o:o[k]=m('bindings',f,o[k])
   elif table=='scopes':
    if r['binding']is not None:r['binding']=m('bindings',f,r['binding'])
    r['enter_value']=m('scope_values',f,r['enter_value']);within(f,r['within'])
   elif table=='scope_values':
    o=r['origin'];k=o['kind']
    if k=='enter':o['scope']=m('scopes',f,o['scope']);o['phase']=m('phase_sites',f,o['phase'])
    elif k=='copy':o['source']=m('scope_values',f,o['source'])
    elif k=='select':
     for key in['if_true','if_false']:o[key]=m('scope_values',f,o[key])
    else:
     for i in o['incoming']:i['value']=m('scope_values',f,i['value'])
   elif table=='exits':
    r['scope_value']=m('scope_values',f,r['scope_value']);o=r['outcome']
    if 'retained_scope_value'in o:o['retained_scope_value']=m('scope_values',f,o['retained_scope_value'])
    if 'return'in o:o['return']=m('returns',f,o['return'])
   elif table=='ends':r['binding']=m('bindings',f,r['binding'])
   elif table=='returns':r['scope']=m('scopes',f,r['scope']);r['exit']=m('exits',f,r['exit'])
   elif table=='adoptions':
    r['callee_return']=m('returns',C.qid(r['callee_function']),r['callee_return']);v=r['receiver'];v['value']=m('scope_values',f,v['value'])
    if v['kind']=='create':v['scope']=m('scopes',f,v['scope'])
   elif table=='phase_sites':
    within(f,r['within']);e=r['event'];kind=e['kind']
    for k,ns in [('scope','scopes'),('scope_value','scope_values'),('binding','bindings'),('object_binding','bindings'),('adoption','adoptions'),('ticket','tickets'),('end','ends'),('exit','exits')]:
     if k in e and e[k]is not None:e[k]=m(ns,f,e[k])
    if kind=='scope_value':e['value']=m('scope_values',f,e['value'])
    if kind=='call':e['return_adoptions']=sorted(m('adoptions',f,a)for a in e['return_adoptions'])
 for o in d['proposed_operations']:
  f=o['function'];o['scope_value']=m('scope_values',f,o['scope_value']);o['adoption']=m('adoptions',f,o['adoption'])
 for table in TABLES:
  if table!='phase_sites':c[table].sort(key=lambda r:(r['function'],r['id']))
 # Cross-function placement of phases is not semantic; per-function order is.
 c['phase_sites'].sort(key=lambda r:r['function'])
 return d

def keys(d):
 out={}
 for table in TABLES:
  for r in d['contract'][table]:out[table,r['function'],r['id']]=None
 for r in d['contract']['phase_sites']:
  if r['event']['kind']=='call':
   k=('tickets',r['function'],r['event']['ticket']);C.need(k not in out,'ASC_CALL_TICKET_DUPLICATE');out[k]=None
 return out

def compare(a,ad,b,bd,fid,*,budget,_details=False):
 """Joint finite bijection, precharged candidate search; immutable originals.

 Worst O(product(n_namespace!)*(V+E)); O(V+E) mapping/capture. At most64 source
 nodes and8 per ambiguous partition; unsupported larger inputs explicitly refuse.
 """
 C.preflight(ad,budget);ad=deepcopy(ad);C.preflight(bd,budget);bd=deepcopy(bd)
 canonical=type(a)is C.RootContext and type(b)is C.RootContext
 revisions=None
 if canonical and type(a.sections)is dict and type(b.sections)is dict and type(a.sections.get(3))is dict and type(b.sections.get(3))is dict:
  revisions=(a.sections[3].get('payload_revision'),b.sections[3].get('payload_revision'))
 if revisions in ((2,3),(3,2)):
  from . import ContractToolError
  raise ContractToolError('unavailable','SCV_REVISION_PAIR_UNAVAILABLE')
 refined=revisions==(3,3)
 left_constraints=C.run(a,ad,budget=budget);right_constraints=C.run(b,bd,budget=budget)
 if refined:
  from . import comparison_values as V
  from factory_meter import copy_cost
  for owner in(a,b):
   copy_cost(owner.sections[3]['functions'],budget);copy_cost(owner.sections[2]['symbols'],budget)
   for fn in owner.sections[3]['functions']:
    for block in fn['blocks']:C.need(block['term']['op']!='tailcall','ASC_IDENTITY_TARGET_CLOSURE_PROFILE')
 def finish(value):
  astamp=C.RootContext.prepare_source_data(a,budget=budget);bstamp=C.RootContext.prepare_source_data(b,budget=budget)
  if refined:C.need(astamp is left_constraints.stamp and bstamp is right_constraints.stamp,'ASC_ORIGINAL_STAMP_CHANGED')
  return (value,left_constraints,right_constraints,tuple(sorted(af)))if _details else value
 af=closure(a,fid,budget,ad);bf=closure(b,fid,budget,bd);C.need(af==bf,'ASC_IDENTITY_ORDINARY_ID_PROFILE')
 for n in a.sections:
  if n!=3:
   if refined:
    av=V.root2_view(a.sections[n],budget=budget)if n==2 else a.sections[n];bv=V.root2_view(b.sections[n],budget=budget)if n==2 else b.sections[n]
    equal=V.same(av,bv,budget=budget)
   else:equal=a.sections[n]==b.sections[n]
   C.need(equal,'ASC_IDENTITY_SOURCE_CONTEXT_PROFILE')
 fa={f['id']:f for f in a.sections[3]['functions']};fb={f['id']:f for f in b.sections[3]['functions']}
 observer_relation=False
 if refined:
  from factory_meter import collection
  collection(budget,len(af),65)
  selected=sorted(af);left_functions=[fa[f]for f in selected];right_functions=[fb[f]for f in selected]
  observer_relation=V.has_observers(left_functions,budget=budget)or V.has_observers(right_functions,budget=budget)
  if not observer_relation and any(not V.same(fa[f],fb[f],budget=budget)for f in af):return finish(False)
 elif any(fa[f]!=fb[f]for f in af):return finish(False)
 def joint(source,functions,mapping):
  bodies=V.observer_functions(functions,mapping,budget=budget)
  budget.charge(work=2,edges=2,copied_bytes=256)
  return {'source':source,'functions':bodies}
 def projected(d):
  C.preflight(d,budget);budget.charge(work=256)
  out=deepcopy(d)
  for t in TABLES:out['contract'][t]=[r for r in out['contract'][t]if r['function']in af]
  out['proposed_operations']=[o for o in out['proposed_operations']if o['function']in af];return out
 left,right=projected(ad),projected(bd);lk,rk=keys(left),keys(right);C.need(len(lk)<=64 and len(rk)<=64,'ASC_IDENTITY_PROFILE_BOUND')
 partitions={};other={}
 def partition(d,k):
  ns,f,i=k
  if ns in['phase_sites','tickets']:return ns,f
  row=next(r for r in d['contract'][ns]if r['function']==f and r['id']==i)
  return ns,f,row['origin']['kind']if ns in['scope_values','bindings']else''
 for k in lk:partitions.setdefault(partition(left,k),[]).append(k)
 for k in rk:other.setdefault(partition(right,k),[]).append(k)
 if partitions.keys()!=other.keys()or any(len(v)!=len(other[k])for k,v in partitions.items()):return finish(False)
 fixed={};groups=[]
 for part,ls in partitions.items():
  rs=other[part]
  if part[0]in['phase_sites','tickets']:
   # keys retain authoritative per-function phase declaration order.
   fixed.update(zip(ls,[r[2]for r in rs]))
  else:
   C.need(len(ls)<=8,'ASC_IDENTITY_PROFILE_BOUND');groups.append((ls,rs))
 budget.charge(work=8*(len(lk)+len(rk)+1),copied_bytes=512*(len(lk)+len(rk)+1))
 C.preflight(right,budget)
 if refined:V.before_alpha(right,budget=budget)
 right_mapping={k:k[2]for k in rk}
 normalized=alpha(right,right_mapping)
 if observer_relation:normalized=joint(normalized,right_functions,right_mapping)
 target=V.encoded(normalized,budget=budget)if refined else raw(normalized);mapping=dict(fixed)
 def search(index):
  if index==len(groups):
   C.preflight(left,budget);budget.charge(work=32*(len(lk)+1),copied_bytes=16*len(target))
   if refined:V.before_alpha(left,budget=budget)
   candidate=alpha(left,mapping)
   if observer_relation:candidate=joint(candidate,left_functions,mapping)
   text=V.encoded(candidate,budget=budget)if refined else raw(candidate)
   if refined:budget.charge(work=4*(len(text)+len(target)+1))
   return text==target
  ls,rs=groups[index]
  budget.charge(work=len(rs)+1,copied_bytes=128*(len(rs)+1))
  for choice in permutations(rs):
   budget.charge(work=len(choice)+1,copied_bytes=128*(len(choice)+1));mapping.update((l,r[2])for l,r in zip(ls,choice))
   if search(index+1):return True
  return False
 result=search(0)
 # Metered ORIGINAL-owner rechecks occur after search, also on a definite mismatch.
 return finish(result)
