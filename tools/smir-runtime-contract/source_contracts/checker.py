"""Finite static source constraints over genuine original roots; no issuers."""
from pathlib import Path
from copy import deepcopy
from dataclasses import dataclass,field
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[3]
from . import ContractToolError
_semantic=ROOT/'tools/smir-format/execution'
def guard_imports():
 expected={'candidate':_semantic/'candidate/__init__.py','common':_semantic/'common.py','codec':ROOT/'tools/smir-format/codec.py'}
 for name in ['layout','nominal','construction','candidate_codec','contract_json','graph_identity','c_boundary','call_interfaces','site_config']:
  expected[name]=ROOT/'tools/smir-abi'/(name+'.py')
 for name in tuple(sys.modules):
  if name.startswith('candidate.'):
   relative=Path(*name.split('.'));path=_semantic/relative
   expected[name]=(path/'__init__.py')if path.is_dir()else path.with_suffix('.py')
 for name,path in expected.items():
  loaded=sys.modules.get(name)
  if loaded is not None and(type(getattr(loaded,'__file__',None))is not str or Path(loaded.__file__).resolve()!=path.resolve()):
   raise ContractToolError('input','SCV_IMPORT_CONTEXT',name)
guard_imports()
sys.path.insert(0,str(_semantic));sys.path.insert(0,str(ROOT/'tools/smir-format'))
from candidate.context import RootContext
from candidate.source_data_projection import source_api
from candidate.source_lifetimes import preflight,shape
SCHEMA=ROOT/'docs/specifications/smir/portable/schema/runtime/source_contracts.json'
SCHEMA_SHA='6cc14282b8f3f8c0113cb9e4d965b320cd4269d6a30c57cd8e88068e27de6654'
class ConstraintError(ValueError):
 def __init__(self,code):self.code=code;super().__init__(code)
def need(test,code):
 if not test:raise ConstraintError(code)
@dataclass(frozen=True)
class StaticConstraints:
 owner:object
 stamp:object
 checked_bindings:tuple
 checked_scope_values:tuple
 checked_exits:tuple
 deferred:tuple
 binding:str=field(default='unbound',init=False)
 source_fact_authority:bool=field(default=False,init=False)
 runtime_authority:bool=field(default=False,init=False)
 active_v3_verified:bool=field(default=False,init=False)
def qid(q):
 need(q['module']=={'kind':'self'},'ASC_ORIGINAL_NAMESPACE');return q['id']
def run(owner,document,*,budget):
 guard_imports()
 need(type(owner)is RootContext,'ASC_OWNER_CLASS');need(type(budget)is source_api().SourceQueryBudget,'ASC_BUDGET_CLASS')
 before=RootContext.prepare_source_data(owner,budget=budget)
 preflight(document,budget);size=SCHEMA.stat().st_size;need(0<size<=262144,'ASC_SCHEMA_BOUND');budget.charge(work=8*(size+1),copied_bytes=8*(size+1))
 with SCHEMA.open('rb')as f:raw=f.read(size+1)
 need(len(raw)==size and hashlib.sha256(raw).hexdigest()==SCHEMA_SHA,'ASC_SCHEMA_CHANGED');schema=json.loads(raw)
 preflight(document,budget);captured=deepcopy(document);shape(schema,captured,schema['$defs'],budget)
 if owner.sections[3]['payload_revision']==3:
  from candidate import root3_context as V3
  expected=V3.codec().raw_contract(owner.sections[3]['source_contract'],budget=budget)
  preflight(expected,budget)
  from .comparison_values import same
  need(same(captured['contract'],expected,budget=budget),'ASC_V3_EMBEDDED_CONTRACT_MISMATCH')
  need(not captured['proposed_operations'],'V3_OBSERVER_SEMANTICS_UNAVAILABLE')
 budget.charge(work=20,edges=10,copied_bytes=1024)
 for root in owner.sections.values():preflight(root,budget)
 roots=deepcopy(owner.sections)
 # This prototype supports a deliberately finite original-factory profile.
 # Charge the bounded verifier work BEFORE calling non-budget-taking factories;
 # this is not a complexity/admission claim for arbitrary original modules.
 nt=len(roots[1]['types']);ns=len(roots[10]['types']);nf=len(roots[3]['functions']);nb=sum(len(f['blocks'])for f in roots[3]['functions']);nv=sum(len(f['params'])+sum(len(b['phis'])+sum(1+len(o['results'])for o in b['ops'])for b in f['blocks'])for f in roots[3]['functions'])
 need(nt<=64 and ns<=16 and nf<=4 and nb<=64 and nv<=256,'ASC_ORIGINAL_FACTORY_PROFILE')
 need(all(t['kind']in['scalar','pointer','reference','function','void','record']for t in roots[10]['types']),'ASC_ORIGINAL_FACTORY_PROFILE')
 need(not roots[2]['manifest']['dependencies']and not roots[10]['bridges'],'ASC_ORIGINAL_FACTORY_PROFILE')
 need(len(roots[6]['imports'])<=8 and len(roots[10]['journals'])<=4,'ASC_ORIGINAL_FACTORY_PROFILE')
 for t in roots[10]['types']:
  if t['kind']=='record':
   ri=t['record_input'];need(ri is not None,'ASC_ORIGINAL_FACTORY_PROFILE');ri=ri['some']
   need(not ri['bases']and len(ri['fields'])<=8,'ASC_ORIGINAL_FACTORY_PROFILE')
   need(all(f['type']['module']=={'kind':'self'}and any(n['id']==f['type']['id']and n['kind']=='scalar'for n in roots[10]['types'])for f in ri['fields']),'ASC_ORIGINAL_FACTORY_PROFILE')
 for j in roots[10]['journals']:need(len(j['slots'])<=64 and all(a['count']<=1024 for a in j['slots']),'ASC_ORIGINAL_FACTORY_PROFILE')
 for i in roots[6]['imports']:need(i['kind']=='internal'and i['name']in['journal_begin','journal_advance','journal_publish_object'],'ASC_ORIGINAL_FACTORY_PROFILE')
 if roots[3]['payload_revision']==2:budget.charge(work=256*(ns**4+nt*nt+(nb+nv+nf)**2),copied_bytes=512*(nt+ns+nb+nv+nf))
 # Reserve original RootContext grammar loads before their bounded factory.
 for _name in ['runtime','abi']:
  _size=(ROOT/'docs/specifications/smir/portable/schema'/_name/'candidate.json').stat().st_size
  need(0<_size<=2**20,'ASC_SCHEMA_BOUND')
  budget.charge(work=64*(_size+1),edges=16*(_size+1),copied_bytes=128*(_size+1))
 actual=RootContext(roots,budget=budget)if roots[3]['payload_revision']==3 else RootContext(roots)
 actual.verify_abi()
 if roots[3]['payload_revision']==3:
  body=actual.verify_candidate_body(budget=budget)
  for observed in body.observers:
   if observed.result==2**32-1:raise ContractToolError('unavailable','SCVO_SOURCE_COORDINATE_PROFILE')
 else:actual.verify_execution()
 # Actual full original factories above. Fresh indexes below never trust editable
 # owner caches. Their proof objects are NOT rebranded as original-owner facts.
 c=captured['contract'];tables={}
 for name in['bindings','scopes','scope_values','exits','ends','returns','adoptions','phase_sites']:
  rows=c[name];budget.charge(work=len(rows),edges=len(rows),copied_bytes=192*len(rows));index={}
  for row in rows:
   k=row['function'],row['id'];need(k not in index,'ASC_DUPLICATE');index[k]=row
  if name!='phase_sites':need(list(index)==sorted(index),'ASC_TABLE_ORDER')
  tables[name]=index
 fns={f['id']:f for f in roots[3]['functions']};nom={n['id']:n for n in roots[10]['types']};plans={p['id']:p for p in roots[10]['signatures']};journals={p['id']:p for p in roots[10]['journals']};decls={};blocks={};pred={};dom={}
 deferred=set();checked=[]
 for fid,fn in fns.items():
  bs={b['id']:b for b in fn['blocks']};blocks[fid]=bs;ps={b:set()for b in bs}
  for b in bs.values():
   t=b['term'];targets=[]
   if t['op']=='jump':targets=[t['target']]
   elif t['op']=='cbranch':targets=[t['true'],t['false']]
   elif t['op'] in ['return','unreachable']:pass
   else:deferred.add('ASC_CFG_TERMINATOR_STATIC_SUBSET')
   for target in targets:ps[target].add(b['id'])
  pred[fid]=ps;ds={b:({b}if b==fn['entry']else set(bs))for b in bs}
  changed=True
  while changed:
   changed=False
   for b in bs:
    if b==fn['entry']:continue
    budget.charge(work=1+len(bs)*max(1,len(ps[b])),copied_bytes=64*len(bs))
    new={b}|(set.intersection(*(ds[p]for p in ps[b]))if ps[b]else set())
    if new!=ds[b]:ds[b]=new;changed=True
  dom[fid]=ds;defs={p['id']:(p['type'],fn['entry'],-4)for p in fn['params']}
  for b in bs.values():
   for phi in b['phis']:defs[phi['result']['id']]=(phi['result']['type'],b['id'],-1)
   for i,op in enumerate(b['ops']):
    for result in op['results']:defs[result['id']]=(result['type'],b['id'],2*i+1)
  decls[fid]=defs
 def get(table,fid,id):need((fid,id)in tables[table],'ASC_REFERENCE');return tables[table][fid,id]
 def function(fid):need(fid in fns,'ASC_FUNCTION');return fns[fid]
 def site(fid,s):
  fn=function(fid);need(s['block']in blocks[fid],'ASC_SITE_BLOCK');b=blocks[fid][s['block']];n=len(b['ops']);kind=s['kind']
  if kind in ['pre_op','normal_post']:need(s['index']<n,'ASC_SITE_INDEX');pos=2*s['index']+(1 if kind=='normal_post'else 0)
  else:pos=2*n+2
  if kind=='entry':need(b['id']==fn['entry'],'ASC_ENTRY_BLOCK');pos=-3
  if kind=='return_exit':need(b['term']['op']=='return','ASC_RETURN_SITE')
  if kind in['invoke_normal','invoke_unwind']:need(b['term']['op']=='invoke','ASC_INVOKE_SITE');deferred.add('ASC_EDGE_SSA_STATIC_SUBSET')
  if kind=='unwind_exit':deferred.add('ASC_UNWIND_SOURCE_PRODUCER')
  return b['id'],pos
 def vtype(fid,value,point=None,kind=None):
  need(value in decls[fid],'ASC_ORIGINAL_SSA');q,b,p=decls[fid][value];t=actual.types.get(q)
  if kind is not None:need(t['kind']==kind,'ASC_SSA_TYPE')
  if point is not None:need(b in dom[fid][point[0]]and(b!=point[0]or p<=point[1]),'ASC_SSA_DOMINANCE')
  return q
 def actual_op(fid,location):
  block=blocks[fid][location['block']]
  return block['ops'][location['index']]if location['kind']in['pre_op','normal_post']else block['term']
 def original_helper(fid,location,name,contract=None):
  op=actual_op(fid,location);need(op['op']=='call'and op['target']['kind']=='import','ASC_ORIGINAL_HELPER_CALL')
  imp=next((i for i in roots[6]['imports']if i['id']==qid(op['target']['import'])),None)
  need(imp is not None and imp['name']==name and(contract is None or imp['contract']==contract),'ASC_ORIGINAL_HELPER_CALL');return op
 def same_nominal(left,right):
  need(qid(left)in nom and qid(right)in nom,'ASC_NOMINAL')
  if roots[3]['payload_revision']==2:budget.charge(work=(ns+1)**4,edges=(ns+1)**2,copied_bytes=128*(ns+1)**2)
  return actual.abi_graph.compatible(left,right,ignore_top_cv=False)
 def same_subject(left,right):
  return same_nominal(left['root_nominal'],right['root_nominal'])and all(left[k]==right[k]for k in['root_view','required_leaf_view','edges'])
 def same_execution(left,right):
  if roots[3]['payload_revision']==2:budget.charge(work=(nt+1)**2,edges=2,copied_bytes=64)
  return actual.types.equal(left,right)
 def called_plan(fid,location,q,callee=None):
  n=qid(q);need(n in plans,'ASC_PLAN');op=actual_op(fid,location)
  need(op['op']in['call','invoke']and op['source_plan']=={'some':q},'ASC_RETURN_ORIGINAL_CALL')
  if callee is not None:need(op['target']['kind']=='direct'and op['target']['function']==callee,'ASC_ADOPTION_CALL_TARGET')
  need(same_execution(op['target']['signature'],plans[n]['execution']),'ASC_CALL_PLAN_EXECUTION')
  return plans[n]
 def plan(fid,q):
  n=qid(q);need(n in plans,'ASC_PLAN');need(function(fid)['abi_signature']=={'some':q},'ASC_FUNCTION_PLAN');return plans[n]
 for (fid,bid),b in tables['bindings'].items():
  function(fid);q=vtype(fid,b['value'],kind='data_ptr');pid=qid(b['static_pointer_type']);cid=qid(b['source_class']);need(pid in nom and cid in nom,'ASC_NOMINAL')
  p=nom[pid];need(p['kind']in['pointer','reference']and len(p['elements'])==1,'ASC_STATIC_POINTER');need(p['execution']is not None and same_execution(p['execution']['some'],q),'ASC_POINTER_EXECUTION');need(same_nominal(p['elements'][0],b['source_class']),'ASC_STATIC_POINTEE')
  subject=b['subject'];rid=qid(subject['root_nominal']);need(rid in nom,'ASC_ROOT_NOMINAL')
  current=nom[rid];current_ref=subject['root_nominal'];unknown=False;md_known=subject['root_view']=='complete';leaf_view=subject['root_view']
  for edge in subject['edges']:
   ek=edge['kind']
   if ek in ['base','member']:
    need(current['kind']=='record','ASC_PATH_KIND')
    ri=current.get('record_input')
    if ri is None:unknown=True;deferred.add('ASC_SOURCE_RECORD_INPUT_REQUIRED');break
    rows=ri['some']['bases'if ek=='base'else'fields'];i=edge['declaration_index'];need(i<len(rows),'ASC_PATH_DECLARATION');decl=rows[i]
    if ek=='base':
     need(decl['virtual']==edge['virtual'],'ASC_PATH_VIRTUAL');leaf_view='nonvirtual'
     if edge['virtual']and not md_known:unknown=True;deferred.add('ASC_NV_MOST_DERIVED_REQUIRED')
    else:leaf_view='complete'
    current_ref=decl['type'];need(qid(current_ref)in nom,'ASC_PATH_NOMINAL');current=nom[qid(current_ref)]
    if ek=='member'and current['kind']=='record'and not unknown:md_known=True
   else:
    need(current['kind']=='array'and current['extent']is not None and len(current['elements'])==1,'ASC_PATH_KIND');index=edge['index']
    if index['kind']=='constant':need(index['value']<current['extent']['some'],'ASC_PATH_INDEX')
    else:need(actual.types.get(vtype(fid,index['value'],kind='int'))['bits']<=64,'ASC_PATH_INDEX_TYPE');deferred.add('ASC_RUNTIME_SOURCE_INDEX_REQUIRED')
    current_ref=current['elements'][0];need(qid(current_ref)in nom,'ASC_PATH_NOMINAL');current=nom[qid(current_ref)];leaf_view='complete'
    if current['kind']=='record'and not unknown:md_known=True
  if not unknown:need(same_nominal(current_ref,b['source_class']),'ASC_SUBJECT_LEAF');need(leaf_view==subject['required_leaf_view'],'ASC_SUBJECT_VIEW')
  if subject['edges']:deferred.add('ASC_CANONICAL_PATH_RESOLVER_REQUIRED')
  origin=b['origin'];kind=origin['kind']
  if kind in['incoming_parameter','incoming_alias']:
   p=plan(fid,origin['plan']);i=origin['lowered_index'];need(i<len(p['lowered_params'])and i<len(function(fid)['params']),'ASC_FORMAL_INDEX');low=p['lowered_params'][i]
   need(function(fid)['params'][i]['id']==b['value'],'ASC_FORMAL_SSA');need(same_nominal(low['value_type'],b['static_pointer_type'])and ((low['mode']=='direct'and same_nominal(low['source_type'],b['static_pointer_type']))or(kind=='incoming_alias'and low['mode']=='sret'and low['role']=='sret'and same_nominal(low['source_type'],b['source_class']))),'ASC_FORMAL_SOURCE')
   if kind=='incoming_parameter':need(low['source_index']=={'some':origin['source_index']}and origin['source_index']<len(p['params'])and same_nominal(p['params'][origin['source_index']],b['static_pointer_type']),'ASC_SOURCE_INDEX')
  elif kind=='retained_alias':
   parent=get('bindings',fid,origin['binding']);need(origin['value']==parent['value']and parent['value']!=b['value'],'ASC_ALIAS_INPUT');need(same_nominal(parent['source_class'],b['source_class'])and same_subject(parent['subject'],subject),'ASC_ALIAS_SUBJECT')
   definition=next((phi for block in blocks[fid].values()for phi in block['phis']if phi['result']['id']==b['value']),None)
   if definition is None:deferred.add('ASC_RETAINED_ALIAS_OPERATION_SUBSET')
   else:need(all(i['value']==origin['value']for i in definition['incoming']),'ASC_ALIAS_PHI_LINEAGE')
  else:
   if 'binding'in origin:parent=get('bindings',fid,origin['binding']);need(origin['value']==parent['value']and origin['value']!=b['value'],'ASC_ALIAS_INPUT')
   if 'old_binding'in origin:get('bindings',fid,origin['old_binding']);vtype(fid,origin['value'])
   if 'site'in origin:site(fid,origin['site'])
   if 'call'in origin:
    site(fid,origin['call']);pid=qid(origin['plan']);need(pid in plans,'ASC_PLAN');p=plans[pid];op=actual_op(fid,origin['call'])
    need(op['op']in['call','invoke']and op['source_plan']=={'some':origin['plan']},'ASC_RETURN_ORIGINAL_CALL')
    if kind=='returned_result':
     need(origin['result_index']==0 and p['result']is not None,'ASC_LOGICAL_RESULT_INDEX')
     hidden=[(i,a)for i,a in enumerate(p['lowered_params'])if a['role']=='sret']
     if hidden:
      need(len(hidden)==1 and hidden[0][0]<len(op['operands'])and op['operands'][hidden[0][0]]==b['value']and p['result']is not None and same_nominal(p['result']['some'],b['source_class']),'ASC_LOGICAL_SRET_OBJECT')
     else:need(len(op['results'])==1 and op['results'][0]['id']==b['value']and p['result']is not None and same_nominal(p['result']['some'],b['static_pointer_type']),'ASC_LOGICAL_RESULT_SSA')
    if kind=='returned_parameter':
     i=origin['lowered_index'];n=origin['source_index'];need(i<len(p['lowered_params'])and i<len(op['operands'])and n<len(p['params']),'ASC_RETURN_PARAMETER_INDEX');low=p['lowered_params'][i]
     need(low['source_index']=={'some':n}and low['role']=='parameter'and low['mode']=='direct'and op['operands'][i]==b['value']and same_nominal(low['value_type'],b['static_pointer_type'])and same_nominal(p['params'][n],b['static_pointer_type']),'ASC_RETURN_PARAMETER_OBJECT')
   deferred.add('ASC_BINDING_'+kind.upper()+'_PRODUCER_REQUIRED')
  if b['access']!='ordinary':deferred.add('ASC_PHASE_ACCESS_ISSUER_REQUIRED')
  checked.append((fid,bid))
 # S definitions refer to actual original CFG and original enter events.
 points={};phases=tables['phase_sites'];order={k:i for i,k in enumerate(phases)}
 for key,s in tables['scopes'].items():
  fid,sid=key;function(fid);site(fid,s['enter']);need((s['program']is None)==(s['view']is None),'ASC_PROGRAM_VIEW_OPTIONS')
  need(s['binding']is not None,'ASC_SCOPE_BINDING');b=get('bindings',fid,s['binding'])
  if s['program']is None:need(s['subject']=='existing_object','ASC_SCOPE_NO_PROGRAM')
  else:need(qid(s['program'])in journals,'ASC_PROGRAM_REFERENCE');deferred.add('ASC_PROGRAM_SOURCE_COVERAGE_REQUIRED')
  if s['subject']=='physical':need(s['enter']['kind']=='entry'and s['within']['kind']=='incoming'and s['lifecycle']is not None,'ASC_PHYSICAL_ENTRY')
  if s['within']['kind']=='incoming':need(s['subject']=='physical','ASC_INCOMING_SUBJECT')
  if s['lifecycle']is not None:deferred.add('ASC_ORIGINAL_LIFECYCLE_PRODUCER_REQUIRED')
  e=get('scope_values',fid,s['enter_value']);need(e['origin']['kind']=='enter'and e['origin']['scope']==sid,'ASC_ENTER_VALUE')
 for key,v in tables['scope_values'].items():
  fid,vid=key;o=v['origin'];kind=o['kind'];function(fid)
  if kind=='enter':
   s=get('scopes',fid,o['scope']);p=get('phase_sites',fid,o['phase']);need(s['enter_value']==vid and p['site']==s['enter']and p['event'].get('scope')==o['scope'],'ASC_ENTER_PHASE');b,pos=site(fid,p['site']);points[key]=(b,pos,order[fid,o['phase']])
  elif kind=='phi':need(o['block']in blocks[fid],'ASC_SITE_BLOCK');need({i['predecessor']for i in o['incoming']}==pred[fid][o['block']]and len(o['incoming'])==len(pred[fid][o['block']]),'ASC_PHI_PREDECESSORS');points[key]=(o['block'],-1,-1)
  else:
   need(o['site']['kind']in['normal_post','pre_terminator'],'ASC_SCOPE_VALUE_SITE')
   b,pos=site(fid,o['site']);matches=[k for k,p in phases.items()if k[0]==fid and p['event']=={'kind':'scope_value','value':vid}and p['site']==o['site']];need(len(matches)==1,'ASC_SCOPE_VALUE_PHASE');points[key]=(b,pos,order[matches[0]])
 def use(fid,val,at):
  get('scope_values',fid,val);point=points[fid,val];need(point[0]in dom[fid][at[0]]and(point[0]!=at[0]or point[1:]<=at[1:]),'ASC_SCOPE_VALUE_DOMINANCE')
 inputs={};origins={k:set()for k in points};forward={k:[]for k in points};queue=[]
 for key,v in tables['scope_values'].items():
  fid,vid=key;o=v['origin'];at=points[key];kind=o['kind'];sources=[]
  if kind=='enter':queue.append((key,o['scope']))
  elif kind=='copy':sources=[o['source']];use(fid,o['source'],at)
  elif kind=='select':sources=[o['if_true'],o['if_false']];vtype(fid,o['condition'],at[:2],kind='int');need(actual.types.get(vtype(fid,o['condition']))['bits']==1,'ASC_SELECT_CONDITION');[use(fid,a,at)for a in sources]
  else:
   for i in o['incoming']:use(fid,i['value'],(i['predecessor'],2*len(blocks[fid][i['predecessor']]['ops'])+3,2**32));sources.append(i['value'])
  for x in sources:forward[fid,x].append(key)
 while queue:
  key,sid=queue.pop()
  if sid in origins[key]:continue
  budget.charge(work=1,edges=1,copied_bytes=128);origins[key].add(sid)
  for dependent in forward[key]:queue.append((dependent,sid))
 need(all(origins.values()),'ASC_SCOPE_VALUE_UNROOTED')
 # Guard lineage is a static compiler constraint, not a runtime Ref simulation.
 guards={}
 for key,slots in origins.items():
  selectors=[]
  for sid in slots:
   scope=get('scopes',key[0],sid);enter=get('scope_values',key[0],scope['enter_value'])
   selectors.append(get('phase_sites',key[0],enter['origin']['phase'])['selector'])
  need(all(x==selectors[0]for x in selectors),'ASC_SCOPE_VALUE_GUARD');guards[key]=selectors[0]
 for (fid,sid),scope in tables['scopes'].items():
  budget.charge(work=8,edges=1)
  entered=get('scope_values',fid,scope['enter_value'])
  defining=get('phase_sites',fid,entered['origin']['phase'])
  within=scope['within']
  if within['kind']=='scope':
   b,pos,phase_order=points[fid,scope['enter_value']]
   use(fid,within['value'],(b,pos,phase_order-1))
   parent_guard=guards[fid,within['value']]
   need(parent_guard['kind']=='always'or parent_guard==defining['selector'],'ASC_GUARDED_VALUE_SELECTOR')
  need(within==defining['within'],'ASC_SCOPE_ENTER_WITHIN')
 for fid in fns:need(sum(s['subject']=='physical'for (f,_),s in tables['scopes'].items()if f==fid)<=1,'E-SOURCE-PHYSICAL-ALIAS-REQUIRES-CLONE')
 for key,p in phases.items():
  fid,_=key;b,pos=site(fid,p['site']);at=(b,pos,order[key]);w=p['within'];e=p['event'];kind=e['kind'];selector=p['selector']
  if selector['kind']=='incoming_lifecycle':
   l=selector['lifecycle'];need(qid(l['source_class'])in nom and qid(l['nominal_function'])in nom and qid(l['plan'])in plans and qid(l['program'])in journals,'ASC_SELECTOR_ORIGINAL_REFERENCE')
   need(nom[qid(l['nominal_function'])]['kind']=='function','ASC_SELECTOR_FUNCTION');deferred.add('ASC_ORIGINAL_LIFECYCLE_PRODUCER_REQUIRED')
  used=[]
  if w['kind']=='scope':used.append(w['value'])
  if 'scope_value'in e:used.append(e['scope_value'])
  if kind=='scope_value':
   used.append(e['value']);need(guards[fid,e['value']]==selector,'ASC_SCOPE_DEFINITION_GUARD')
  if kind=='scope_exit':used.append(get('exits',fid,e['exit'])['scope_value'])
  for val in used:
   get('scope_values',fid,val);guard=guards[fid,val]
   need(guard['kind']=='always'or guard==selector,'ASC_GUARDED_VALUE_SELECTOR')
  if w['kind']=='scope':use(fid,w['value'],at)
  if w['kind']=='incoming':need(kind=='enter_incoming'and p['site']['kind']=='entry','ASC_WITHIN_INCOMING')
  locs={'enter_incoming':{'entry'},'enter_root':{'pre_op','pre_terminator'},'enter_child':{'pre_op','pre_terminator'},'enter_same_root':{'pre_op','pre_terminator'},'object_begin_root':{'normal_post'},'object_begin_child':{'normal_post'},'object_attach_incoming':{'entry'},'object_attach_returned':{'normal_post','invoke_normal'},'bind_journal':{'normal_post'},'activate':{'pre_op','pre_terminator'},'publish':{'normal_post'},'call':{'pre_op','pre_terminator'},'call_returned':{'normal_post','invoke_normal'},'call_failed':{'invoke_unwind','unwind_exit'},'child_commit':{'normal_post'},'scope_value':{'normal_post','pre_terminator'}}
  if kind in locs:need(p['site']['kind']in locs[kind],'ASC_PHASE_SITE')
  subjects={'enter_incoming':{'physical'},'enter_root':{'inline'},'enter_child':{'inline'},'enter_same_root':{'inline'},'object_begin_root':{'source_object'},'object_begin_child':{'source_object'},'object_attach_incoming':{'existing_object'},'object_attach_returned':{'existing_object'},'bind_journal':{'physical','inline'},'activate':{'physical','inline','source_object'},'publish':{'physical','inline','source_object'}}
  if kind in subjects:
   ids={e['scope']}if 'scope'in e else origins[fid,e['scope_value']]
   need(all(get('scopes',fid,x)['subject']in subjects[kind]for x in ids),'ASC_PHASE_SUBJECT')
  if kind=='call':
   op=actual_op(fid,p['site']);need(op['op']==('call'if p['site']['kind']=='pre_op'else'invoke'),'ASC_CALL_SITE')
   need(op['source_plan']=={'some':e['plan']},'ASC_CALL_SOURCE_PLAN')
   if e['object_binding']is not None:get('bindings',fid,e['object_binding'])
   ids=e['return_adoptions'];need(ids==sorted(set(ids)),'ASC_ADOPTION_CANONICAL_SET')
   if op['target']['kind']=='direct'and op['target']['function']['module']=={'kind':'self'}:
    need(op['target']['kind']=='direct'and op['target']['function']['module']=={'kind':'self'},'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS')
    callee=qid(op['target']['function']);need(callee in fns,'ASC_CALLEE_FUNCTION')
    returns=[x for (f,_),x in tables['returns'].items()if f==callee and x['disposition']=='retained_to_call']
    normal=[b for b in blocks[callee].values()if b['term']['op']=='return']
    need(len(normal)==1,'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS')
    candidates=[get('adoptions',fid,i)for i in ids]
    need(all(a['call']==p['site']and a['plan']==e['plan']and a['callee_function']==op['target']['function']for a in candidates),'ASC_ADOPTION_CALL_TARGET')
    need({a['callee_return']for a in candidates}=={r['id']for r in returns}and len(candidates)==len(returns),'ASC_ADOPTION_COMPLETE_SET')
    receivers=[(a['receiver']['scope'],a['receiver']['value'])for a in candidates if a['receiver']['kind']=='create'];need(len(receivers)==len(set(receivers)),'ASC_RECEIVER_RESERVATION_CONFLICT')
   else:need(False,'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS')
  if kind in['object_begin_root','object_begin_child']:
   op=original_helper(fid,p['site'],'journal_begin','construction')
   binding=next(i for i in roots[6]['imports']if i['id']==qid(op['target']['import']));need(binding['abi']=={'some':get('scopes',fid,e['scope'])['program']},'ASC_SCOPE_JOURNAL_PROGRAM')
   need(any(r['id']==e['journal']for r in op['results'])and op['operands'][0]==get('bindings',fid,e['binding'])['value'],'ASC_OBJECT_BEGIN_JOURNAL')
  if kind=='publish':
   op=original_helper(fid,p['site'],'journal_publish_object')
   need(op['operands']==[e['journal'],get('bindings',fid,e['binding'])['value']],'ASC_PUBLISH_JOURNAL')
  if kind=='object_attach_returned':
   scope=get('scopes',fid,e['scope']);need(scope['binding']==e['binding'],'ASC_ATTACH_BINDING')
   if e['adoption']is not None:
    adoption=get('adoptions',fid,e['adoption']);receiver=adoption['receiver']
    need(receiver['kind']=='create'and receiver['scope']==e['scope']and receiver['value']==scope['enter_value'],'ASC_ATTACH_RECEIVER')
    need(adoption['call']['block']==p['site']['block']and adoption['call'].get('index')==p['site'].get('index'),'ASC_ATTACH_CALL_SITE')
    calls=[x for (f,_),x in phases.items()if f==fid and x['site']==adoption['call']and x['event']['kind']=='call']
    need(len(calls)==1 and e['adoption']in calls[0]['event']['return_adoptions'],'ASC_ATTACH_SELECTED_ADOPTION')
   else:deferred.add('ASC_COMPLETE_RETURN_MATERIALIZATION_PROOF_REQUIRED')
  if kind=='call_returned':
   calls=[x for (f,_),x in phases.items()if f==fid and x['event']['kind']=='call'and x['event']['ticket']==e['ticket']]
   need(len(calls)==1,'ASC_RETURNED_CALL_TICKET');ids=calls[0]['event']['return_adoptions']
   following=[x for (f,_),x in list(phases.items())[order[key]+1:]if f==fid][:len(ids)]
   need(len(following)==len(ids)and all(x['site']==p['site']and x['event']['kind']=='object_attach_returned'for x in following)and {x['event']['adoption']for x in following}==set(ids),'ASC_ADOPTION_ATTACH_COMMIT_GROUP')
  if kind=='object_attach_incoming':
   s=get('scopes',fid,e['scope']);get('bindings',fid,e['binding']);need(s['subject']=='existing_object'and p['site']['kind']=='entry'and e['binding']==s['binding'],'ASC_ATTACH_INCOMING')
  elif kind=='scope_value':get('scope_values',fid,e['value'])
  elif kind=='scope_exit':x=get('exits',fid,e['exit']);need(x['site']==p['site'],'ASC_EXIT_PHASE')
  else:
   if 'scope_value'in e:use(fid,e['scope_value'],at)
   if 'journal'in e:vtype(fid,e['journal'],at[:2],kind='journal')
   if 'parent_journal'in e:vtype(fid,e['parent_journal'],at[:2],kind='journal')
   if 'binding'in e:get('bindings',fid,e['binding'])
   if 'scope'in e:get('scopes',fid,e['scope'])
   deferred.add('ASC_PHASE_'+kind.upper()+'_STATIC_SUBSET')
 exits=[]
 for (fid,eid),e in tables['exits'].items():
  b,pos=site(fid,e['site']);matches=[k for k,p in phases.items()if k[0]==fid and p['site']==e['site']and p['event']=={'kind':'scope_exit','exit':eid}];need(len(matches)==1,'ASC_EXIT_PHASE');use(fid,e['scope_value'],(b,pos,order[matches[0]]));kind=e['outcome']['kind'];mode='normal'if kind.startswith('normal')else'outward'if kind.startswith('outward')else'unwind'
  for sid in origins[fid,e['scope_value']]:
   s=get('scopes',fid,sid);physical=s['subject']=='physical';allowed={'return_exit'}if physical else{'pre_op','pre_terminator','normal_post','return_exit'}
   if mode=='unwind':allowed={'unwind_exit'}if physical else{'invoke_unwind','unwind_exit','pre_op','pre_terminator'}
   if mode=='outward':allowed={'unwind_exit'}
   need(e['site']['kind']in allowed,'ASC_EXIT_LOCATOR')
   if mode=='normal'and e['site']['kind']=='return_exit':need(kind!='normal_retained_scope','ASC_PHYSICAL_HOLDER')
  for field,typ in [('journal','journal'),('exception','exception')]:
   if field in e['outcome']:vtype(fid,e['outcome'][field],(b,pos),kind=typ)
  if kind=='normal_retained_call':
   budget.charge(work=8,edges=1)
   need(e['site']['kind']=='return_exit','ASC_RETURN_BOUNDARY')
   returned=get('returns',fid,e['outcome']['return'])
   need(returned['exit']==eid and returned['disposition']=='retained_to_call','ASC_RETURN_RETAINED_OUTCOME')
  if kind=='normal_retained_scope':use(fid,e['outcome']['retained_scope_value'],(b,pos,order[matches[0]]));need(e['scope_value']!=e['outcome']['retained_scope_value'],'ASC_RETAINED_SELF')
  if kind!='normal_no_journal':deferred.add('ASC_EXIT_'+kind.upper()+'_ACTUAL_OUTCOME_REQUIRED')
  exits.append((fid,eid))
 for name in['ends','returns','adoptions']:
  for (fid,rid),row in tables[name].items():
   function(fid)
   if 'site'in row:site(fid,row['site'])
   if 'call'in row:site(fid,row['call'])
   if name=='adoptions':
    p=called_plan(fid,row['call'],row['plan'],row['callee_function']);need(qid(row['callee_function'])in fns,'ASC_CALLEE_FUNCTION');recv=row['receiver'];get('scope_values',fid,recv['value'])
    if recv['kind']=='existing':b,pos=site(fid,row['call']);use(fid,recv['value'],(b,pos,-1))
    else:s=get('scopes',fid,recv['scope']);need(s['enter_value']==recv['value'],'ASC_RESERVED_RECEIVER_DEFINITION')
   if name=='ends':get('bindings',fid,row['binding'])
   if name=='returns':
    get('scopes',fid,row['scope']);exitrow=get('exits',fid,row['exit']);need(exitrow['site']['kind']=='return_exit','ASC_RETURN_BOUNDARY')
    slots=origins[fid,exitrow['scope_value']];need(len(slots)==1,'E-SOURCE-RETURN-SCOPE-AMBIGUOUS');need(slots=={row['scope']},'ASC_RETURN_SCOPE_EXIT')
    if row['disposition']=='retained_to_call':
     need(exitrow['outcome']['kind']=='normal_retained_call'and exitrow['outcome']['return']==rid,'ASC_RETURN_RETAINED_OUTCOME')
     p=plans[qid(function(fid)['abi_signature']['some'])];b=get('bindings',fid,get('scopes',fid,row['scope'])['binding']);origin=b['origin']
     same_sret=origin['kind']=='incoming_alias'and p['lowered_params'][origin['lowered_index']]['role']=='sret'
     need(not same_sret,'ASC_SRET_REQUIRES_COMPLETE_PUBLISH')
    else:need(exitrow['outcome']['kind']!='normal_retained_call','ASC_RETURN_RETAINED_OUTCOME')
   deferred.add('ASC_'+name.upper()+'_STATIC_SUBSET')
 for op in captured['proposed_operations']:
  fid=op['function'];site(fid,op['site']);get('scope_values',fid,op['scope_value']);get('adoptions',fid,op['adoption']);need(len(op['results'])==1 and actual.types.get(op['results'][0]['type'])['kind']=='journal','ASC_OBSERVER_RESULT');deferred.add('ASC_NEW_JOURNAL_OBSERVER_NOT_IMPLEMENTED')
 if tables['scopes']:deferred.add('ASC_FULL_SCOPE_PATH_COVERAGE_NOT_IMPLEMENTED')
 if roots[3]['payload_revision']==3:
  from .observer import check as check_observers
  if check_observers(actual,captured,budget=budget):deferred.add('ASC_OBSERVER_STATIC_SOURCE_PROFILE_ONLY')
 deferred.update(['ACTUAL_SOURCE_ALIAS_AND_SCOPE_ATTACHMENT_ISSUERS','ACTIVE_ROOT3_V3_ENCODING_AND_SEMANTIC_ADMISSION'])
 budget.charge(work=64+len(checked)+len(points)+len(exits),copied_bytes=512+128*(len(checked)+len(points)+len(exits)+len(deferred)))
 after=RootContext.prepare_source_data(owner,budget=budget);need(after is before,'ASC_ORIGINAL_STAMP_CHANGED')
 return StaticConstraints(owner,before,tuple(checked),tuple(sorted(points)),tuple(exits),tuple(sorted(deferred)))
