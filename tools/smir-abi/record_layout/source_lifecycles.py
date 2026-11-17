"""Strict flat original-v3 lifecycle associations with qualified logical costs.

Qualification covers this fixed SourceProgram/ABI/body association algorithm under
one canonical budget. It supplies no source/runtime/private/execution authority,
CPU/RSS bound or broader C++ source-body/CFG/EH/virtual-base proof.
"""
from dataclasses import dataclass,field
import hashlib,json
from pathlib import Path
from record_layout import source_programs as S
from record_layout import source_program_cost as P
PROFILE=P.PROFILE
from candidate.context import RootContext
ROOT=Path(__file__).resolve().parents[3]
PINS={'abi/source_programs.json':'a664b73c055a6d405cd468cff23f50b9dadb67a338bc1e765013a75731469030','runtime/source_contracts.json':'6cc14282b8f3f8c0113cb9e4d965b320cd4269d6a30c57cd8e88068e27de6654'}
LOCAL_SCHEMA_SHA256='8e10f3cc0db02c1dccb4f5d704b0d8ff5a77efc2770be266866c6fcdc9c1e933'
VARIANTS={'C1':('constructor','complete_constructor','complete'),'C2':('constructor','base_constructor','nonvirtual'),'D0':('destructor','deleting_destructor','complete'),'D1':('destructor','complete_destructor','complete'),'D2':('destructor','base_destructor','nonvirtual')}
class LifecycleError(ValueError):
 def __init__(self,code,detail=''):self.code=code;self.detail=detail;super().__init__(code+': '+detail)
def need(ok,code,detail=''):
 if not ok:raise LifecycleError(code,detail)
def u32(n):return type(n)is int and 0<=n<2**32-1

def schema(relative,budget):
 p=ROOT/'docs/specifications/smir/portable/schema'/relative
 return P.load_schema(p,PINS[relative],budget,PROFILE)

def table(rows,budget,key=lambda r:r['id']):
 need(type(rows)is list and len(rows)<=4096,'ABI_LC_TABLE');budget.charge(work=8*len(rows),edges=len(rows),copied_bytes=128*len(rows));out={}
 P.collection(budget,PROFILE,len(rows))
 for row in rows:
  P.row(budget,PROFILE,row,ops=21,native=0)
  P.row(budget,PROFILE,row,ops=21,native=0)
  k=key(row);need(k not in out,'ABI_LC_DUPLICATE');out[k]=row
 return out

def item(rows,key):need(key in rows,'ABI_LC_REFERENCE',repr(key));return rows[key]
def selfref(r,rows):
 need(r['module']=={'kind':'self'},'ABI_LC_DEP_UNAVAILABLE');return item(rows,r['id'])
def class_has_vbases(reference,nominals,budget):
 P.tick(budget,PROFILE,work=28,copy=64)
 pending=[reference];seen=set();virtual=False
 while pending:
  budget.charge(work=8,edges=1,copied_bytes=128);r=pending.pop();n=selfref(r,nominals)
  if n['id']in seen:continue
  seen.add(n['id']);need(n['kind']=='record' and n['record_input']is not None,'ABI_LC_CLASS_GRAPH_UNAVAILABLE');bases=n['record_input']['some']['bases'];budget.charge(work=4*len(bases),edges=len(bases),copied_bytes=128*len(bases))
  for base in bases:
   P.row(budget,PROFILE,base,ops=28,native=1)
   virtual=virtual or base['virtual'];pending.append(base['type'])
 return virtual

@dataclass(frozen=True)
class LifecycleAssociation:
 function:int;scope:int;method:int;program:int;variant:str;view:str;plan:int;execution:int;this_value:int;vtt_value:object
@dataclass(frozen=True)
class LifecycleAssociations:
 owner:object;stamp:object;context:int;associations:tuple;obligations:tuple
 binding:str=field(default='unbound',init=False)
 runtime_authority:bool=field(default=False,init=False)
 source_fact_authority:bool=field(default=False,init=False)
 executable:bool=field(default=False,init=False)
 active_v3_verified:bool=field(default=False,init=False)
 cost_profile_qualified:bool=field(default=True,init=False)

def verify_lifecycle_associations(owner,request,*,budget):
 S.ledger(budget);need(type(owner)is RootContext,'ABI_LC_ORIGINAL_CONTEXT')
 need(owner.sections[3]['payload_revision']==3,'ABI_LC_COST_PROFILE_UNAVAILABLE','original v3 required')
 if owner.sections[3]['payload_revision']==3:
  from candidate import root3_context as V3
  V3.owner_budget(owner,budget)
 data,_=S.capture(request,budget,cost_profile=PROFILE)
 need(type(data)is dict and set(data)=={'format','revision','context','source_programs','source_contract','links'}and data['format']=='abi-source-lifecycle-associations'and type(data['revision'])is int and data['revision']==1 and u32(data['context']),'ABI_LC_SHAPE')
 path=ROOT/'docs/specifications/smir/portable/schema/abi/source_lifecycles.json';size=path.stat().st_size;need(0<size<=1<<20,'ABI_LC_SCHEMA_BOUND');budget.charge(work=8*size,copied_bytes=8*size);local_raw,local=P.load_schema(path,LOCAL_SCHEMA_SHA256,budget,PROFILE)
 S.shape(local,data,local['$defs'],budget,cost_profile=PROFILE)
 raw,doc=schema('runtime/source_contracts.json',budget);S.shape(doc['$defs']['contract'],data['source_contract'],doc['$defs'],budget,cost_profile=PROFILE);abi_raw,_=schema('abi/source_programs.json',budget)
 need(type(data['links'])is list and len(data['links'])<=4096,'ABI_LC_TABLE')
 budget.charge(work=8*len(data['links']),copied_bytes=128*len(data['links']))
 for row in data['links']:need(type(row)is dict and set(row)=={'function','scope','method','program'}and all(u32(v)for v in row.values()),'ABI_LC_LINK_SHAPE')
 P.lifecycle_profile(data,budget,PROFILE)
 links=table(data['links'],budget,lambda r:(r['function'],r['scope']))
 stamp=RootContext.prepare_source_data(owner,budget=budget);revision=owner.sections[3]['payload_revision']
 if revision==3:
  from candidate import root3_context as V3
  from factory_meter import encoded_json,charge
  V3.owner_budget(owner,budget)
  embedded=V3.codec().raw_contract(owner.sections[3]['source_contract'],budget=budget)
  a=encoded_json(embedded,budget);b=encoded_json(data['source_contract'],budget)
  charge(budget,work=len(a)+len(b))
  need(a==b,'ABI_LC_V3_EMBEDDED_CONTRACT')
  RootContext.verify_abi(owner)
  checked=RootContext.verify_candidate_body(owner,budget=budget)
  need(type(checked)is V3.V3BodyChecks and checked.owner is owner and checked.stamp is stamp,'ABI_LC_ORIGINAL_V3_BODY')
  body=checked.verified
  a=encoded_json(body.functions_root,budget);b=encoded_json(owner.sections[3],budget)
  charge(budget,work=len(a)+len(b))
  need(a==b,'ABI_LC_FULL_V3_ROOT')
 else:
  raise LifecycleError('ABI_LC_COST_PROFILE_UNAVAILABLE','original v3 required')
 source=S.check_source_associations(data['source_programs'],owner,data['context'],budget=budget,cost_profile=PROFILE)
 need(source.stamp is stamp,'ABI_LC_ORIGINAL_STAMP')
 document=data['source_programs'];records=table(document['records'],budget);methods=table(document['methods'],budget);programs=table(document['programs'],budget);cleanups=table(document['cleanups'],budget)
 contract=data['source_contract'];scopes=table(contract['scopes'],budget,lambda r:(r['function'],r['id']));bindings=table(contract['bindings'],budget,lambda r:(r['function'],r['id']));values=table(contract['scope_values'],budget,lambda r:(r['function'],r['id']));phases=table(contract['phase_sites'],budget,lambda r:(r['function'],r['id']))
 P.collection(budget,PROFILE,len(scopes))
 selected={key:scope for key,scope in scopes.items()if scope['lifecycle']is not None};P.collection(budget,PROFILE,len(links));P.collection(budget,PROFILE,len(selected));need(set(links)==set(selected),'ABI_LC_EXHAUSTION')
 functions=table(body.functions_root['functions'],budget);nominals=table(owner.sections[10]['types'],budget);plans=table(owner.sections[10]['signatures'],budget);journals=table(owner.sections[10]['journals'],budget)
 phase_enters={}
 for key,phase in phases.items():
  P.row(budget,PROFILE,phase,ops=441,native=16)
  event=phase['event']
  if event['kind']=='enter_incoming':phase_enters.setdefault((key[0],event['scope']),[]).append(phase)
 out=[];physical_plans={}
 for key,scope in selected.items():
  P.row(budget,PROFILE,scope,ops=441,native=16)
  budget.charge(work=128,edges=32,copied_bytes=4096);link=links[key];lc=scope['lifecycle'];function=item(functions,key[0]);need(scope['subject']=='physical','ABI_LC_INLINE_IMPLEMENTATION_UNAVAILABLE');method=item(methods,link['method']);program=item(programs,link['program']);record=item(records,program['record']);cleanup=item(cleanups,program['cleanup'])
  need(program['method']==method['id']and method['record']==record['id'],'ABI_LC_METHOD_PROGRAM');need(record['source']['context']==data['context']and record['source']['nominal']==lc['source_class'],'ABI_LC_CLASS');need(method['signature']==lc['nominal_function'],'ABI_LC_PROTOTYPE')
  kind,variant,view=VARIANTS[lc['variant']];need(lc['kind']==method['kind']==kind and program['variant']==variant and lc['view']==cleanup['view']==view,'ABI_LC_VARIANT_VIEW')
  need(program['implementation']is not None,'ABI_LC_IMPLEMENTATION_UNAVAILABLE');impl=program['implementation'];plan=selfref(lc['plan'],plans)
  need(impl['function']=={'module':{'kind':'self'},'id':function['id']}and impl['call_signature']==lc['plan']and impl['execution']==plan['execution']==function['signature']and function['abi_signature']=={'some':lc['plan']},'ABI_LC_ENTRY_PLAN')
  old=physical_plans.setdefault(function['id'],lc['plan']);need(old==lc['plan'],'ABI_LC_SHARED_ENTRY_UNAVAILABLE')
  need(scope['program']==lc['program']and scope['view']==lc['view'],'ABI_LC_SCOPE_PROGRAM_VIEW')
  need(cleanup['journal_program']==lc['program'],'ABI_LC_CLEANUP');selfref(lc['program'],journals)
  expected_vtt=lc['variant']in['C2','D2']and class_has_vbases(lc['source_class'],nominals,budget)
  need(plan['vtt']==impl['uses_vtt']==expected_vtt,'ABI_LC_VTT_CLASS_VARIANT');need(plan['this_type']is not None,'ABI_LC_THIS_REQUIRED');this_type=selfref(plan['this_type']['some'],nominals);need(this_type['kind']=='pointer'and this_type['elements']==[lc['source_class']],'ABI_LC_THIS_CLASS')
  roles={}
  budget.charge(work=8*len(plan['lowered_params']),copied_bytes=128*len(plan['lowered_params']))
  for i,row in enumerate(plan['lowered_params']):
   P.row(budget,PROFILE,row,ops=441,native=16)
   if row['role']in['this','vtt']:need(row['role']not in roles,'ABI_LC_ROLE_DUPLICATE');roles[row['role']]=i
  need('this'in roles and('vtt'in roles)==expected_vtt,'ABI_LC_HIDDEN_ROLES');this_value=function['params'][roles['this']]['id'];vtt_value=function['params'][roles['vtt']]['id']if expected_vtt else None
  binding=item(bindings,(key[0],scope['binding']));need(binding['access']==('construction'if lc['kind']=='constructor'else'destruction'),'ABI_LC_THIS_ACCESS');need(binding['role']==('base'if lc['variant']in['C2','D2']else'complete'),'ABI_LC_THIS_ROLE');origin=binding['origin'];need(origin==dict(kind='incoming_alias',plan=lc['plan'],lowered_index=roles['this'])and binding['value']==this_value and binding['source_class']==lc['source_class']and binding['static_pointer_type']==plan['this_type']['some'],'ABI_LC_THIS_BINDING')
  subject=binding['subject'];need(subject==dict(root_nominal=lc['source_class'],root_view=view,required_leaf_view=view,edges=[]),'ABI_LC_THIS_SUBJECT')
  entries=phase_enters.get(key,());need(len(entries)==1,'ABI_LC_ENTRY_PHASE');phase=entries[0];site=dict(kind='entry',block=function['entry']);incoming=dict(kind='incoming',lifecycle=lc)
  need(phase['selector']['kind']!='always','ABI_LC_ENTRY_PROFILE_UNAVAILABLE')
  need(phase['selector']==dict(kind='incoming_lifecycle',lifecycle=lc),'ABI_LC_ENTRY_LIFECYCLE')
  need(scope['enter']==phase['site']==site and scope['within']==phase['within']==incoming,'ABI_LC_INCOMING_SELECTOR')
  need(phase['event']==dict(kind='enter_incoming',scope=scope['id'],binding=scope['binding'],vtt=vtt_value),'ABI_LC_INCOMING_OPERANDS');sv=item(values,(key[0],scope['enter_value']));need(sv['origin']==dict(kind='enter',scope=scope['id'],phase=phase['id']),'ABI_LC_S_ENTER')
  if lc['variant']=='D0':
   need(program['delegate']is not None,'ABI_LC_DELETING_DELEGATE');target=item(programs,program['delegate']['target']);need(target['variant']=='complete_destructor'and target['implementation']is not None,'ABI_LC_DELEGATE_IMPLEMENTATION_UNAVAILABLE')
  out.append(LifecycleAssociation(key[0],key[1],method['id'],program['id'],lc['variant'],view,plan['id'],plan['execution']['id'],this_value,vtt_value))
 P.collection(budget,PROFILE,len(out),128)
 budget.charge(work=8*len(out)*(len(out).bit_length()+1),copied_bytes=512*len(out))
 P.load_schema(path,LOCAL_SCHEMA_SHA256,budget,PROFILE)
 need(RootContext.prepare_source_data(owner,budget=budget)is stamp,'ABI_LC_SOURCE_CHANGED');current_raw=schema('runtime/source_contracts.json',budget)[0];current_abi=schema('abi/source_programs.json',budget)[0];budget.charge(work=len(current_raw)+len(raw)+len(current_abi)+len(abi_raw));need(current_raw==raw and current_abi==abi_raw,'ABI_LC_SCHEMA_CHANGED')
 obligations=('ABI_LC_BODY_SOURCE_LEGALITY_NOT_PROVED','ABI_LC_CFG_PUBLICATION_EH_NOT_PROVED','ABI_LC_INCOMING_TICKET_NOT_ISSUED','ABI_LC_SOURCE_SEMANTIC_ADMISSION_NOT_ISSUED','ABI_LC_VTT_CONTENTS_NOT_PROVED')
 return LifecycleAssociations(owner,stamp,data['context'],tuple(sorted(out,key=lambda r:(r.function,r.scope))),obligations)
