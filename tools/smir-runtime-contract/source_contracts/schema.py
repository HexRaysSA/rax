from pathlib import Path
import json,hashlib
ROOT=Path(__file__).resolve().parents[3]
TARGET=ROOT/'docs/specifications/smir/portable/schema/runtime/source_contracts.json'
D={}
def R(n):return {'$ref':'#/$defs/'+n}
def C(x):return {'const':x}
def E(*xs):return {'enum':list(xs)}
def V(t,n=4096):return {'type':'array','items':R(t)if isinstance(t,str)else t,'maxItems':n}
def N(t):return {'anyOf':[{'type':'null'},R(t)if isinstance(t,str)else t]}
def obj(**p):return {'type':'object','properties':p,'required':list(p),'additionalProperties':False}
def tagged(**arms):return {'anyOf':[obj(kind=C(k),**p)for k,p in arms.items()]}
u32={'type':'integer','minimum':0,'maximum':2**32-2};u64={'type':'integer','minimum':0,'maximum':2**64-1};boolean={'type':'boolean'}
D.update(u32=u32,u64=u64,view=E('complete','nonvirtual'))
D['qref']=obj(module=tagged(self={},dependency=dict(slot=u32)),id=u32)
D['decl']=obj(id=u32,type=R('qref'))
D['site']=tagged(entry=dict(block=u32),pre_op=dict(block=u32,index=u32),normal_post=dict(block=u32,index=u32),pre_terminator=dict(block=u32),invoke_normal=dict(block=u32),invoke_unwind=dict(block=u32),return_exit=dict(block=u32),unwind_exit=dict(block=u32,call_index=N(u32)))
D['index']=tagged(constant=dict(value=u64),ssa=dict(value=u32))
D['edge']=tagged(base=dict(declaration_index=u32,virtual=boolean),member=dict(declaration_index=u32),element=dict(index=R('index')))
D['subject']=obj(root_nominal=R('qref'),root_view=R('view'),required_leaf_view=R('view'),edges=V('edge',64))
D['origin']=tagged(created=dict(site=R('site')),incoming_parameter=dict(plan=R('qref'),source_index=u32,lowered_index=u32),incoming_alias=dict(plan=R('qref'),lowered_index=u32),returned_result=dict(call=R('site'),plan=R('qref'),result_index=u32),retained_alias=dict(binding=u32,value=u32),projected_alias=dict(binding=u32,value=u32,site=R('site')),transparent_replacement=dict(old_binding=u32,value=u32,site=R('site')),launder=dict(binding=u32,value=u32,site=R('site')))
D['binding']=obj(id=u32,function=u32,value=u32,source_class=R('qref'),static_pointer_type=R('qref'),access=E('ordinary','construction','destruction'),subject=R('subject'),role=E('complete','base','member','element'),origin=R('origin'))
D['lifecycle']=obj(source_class=R('qref'),nominal_function=R('qref'),plan=R('qref'),program=R('qref'),view=R('view'),kind=E('constructor','destructor'),variant=E('C1','C2','D0','D1','D2'))
D['within']=tagged(outside={},scope=dict(value=u32),incoming=dict(lifecycle=R('lifecycle')))
D['scope']=obj(id=u32,function=u32,enter=R('site'),enter_value=u32,subject=E('physical','inline','source_object','existing_object'),binding=N(u32),program=N('qref'),view=N('view'),within=R('within'),lifecycle=N('lifecycle'))
D['incoming']=obj(predecessor=u32,value=u32)
D['s_origin']=tagged(enter=dict(scope=u32,phase=u32),copy=dict(source=u32,site=R('site')),phi=dict(block=u32,incoming=V('incoming')),select=dict(site=R('site'),condition=u32,if_true=u32,if_false=u32))
D['s_value']=obj(id=u32,function=u32,origin=R('s_origin'))
D['outcome']=tagged(normal_no_journal={},normal_retained_scope=dict(journal=u32,retained_scope_value=u32),normal_retained_call={'journal':u32,'return':u32},unwind_no_journal=dict(exception=u32),unwind_with_journal=dict(journal=u32,exception=u32),outward_unwind_no_journal={},outward_unwind_with_journal=dict(journal=u32))
D['exit']=obj(id=u32,function=u32,scope_value=u32,site=R('site'),outcome=R('outcome'))
D['end_effect']=tagged(destructor_preentry=dict(call=R('site'),plan=R('qref')),trivial_end={},reuse_commit={},deallocation_commit={},cleanup_complete=dict(program=R('qref'),view=R('view')))
D['end']=obj(id=u32,function=u32,binding=u32,site=R('site'),reason=E('scope_end','reuse','storage_release'),stage=E('ordinary_end','destructive_retire','failed_construction_retire'),effect=R('end_effect'))
D['return']=obj(id=u32,function=u32,scope=u32,exit=u32,disposition=E('terminal','retained_to_call'))
D['receiver']=tagged(existing=dict(value=u32),create=dict(scope=u32,value=u32))
D['adoption']=obj(id=u32,function=u32,call=R('site'),plan=R('qref'),callee_function=R('qref'),callee_return=u32,receiver=R('receiver'))
D['parent']=tagged(none={},child=dict(journal=u32,slot=u32,element=R('index')),same_root=dict(journal=u32),incoming={})
p={k:dict(scope=u32,binding=u32,vtt=N(u32))for k in['enter_incoming','enter_root']};p.update(enter_child=dict(scope=u32,binding=u32,parent_journal=u32,slot=u32,element=R('index'),vtt=N(u32)),enter_same_root=dict(scope=u32,binding=u32,journal=u32,vtt=N(u32)),object_begin_root=dict(scope=u32,binding=u32,journal=u32),object_begin_child=dict(scope=u32,binding=u32,journal=u32,parent_journal=u32,slot=u32,element=R('index')),object_attach_incoming=dict(scope=u32,binding=u32),object_attach_returned=dict(scope=u32,binding=u32,adoption=u32),bind_journal=dict(scope_value=u32,journal=u32),activate=dict(scope_value=u32,journal=u32),publish=dict(scope_value=u32,journal=u32,binding=u32),call=dict(ticket=u32,plan=R('qref'),receiver=N(u32),parent=R('parent')),call_returned=dict(ticket=u32),call_failed=dict(ticket=u32,exception=N(u32)),child_commit=dict(scope_value=u32,journal=u32,slot=u32,element=R('index')),object_end=dict(end=u32),scope_exit=dict(exit=u32),scope_value=dict(value=u32))
p['call']=dict(ticket=u32,plan=R('qref'),object_binding=N(u32),parent=R('parent'),return_adoptions=V(u32))
p['object_attach_returned']['adoption']=N(u32)
D['origin']['anyOf'].append(obj(kind=C('returned_parameter'),call=R('site'),plan=R('qref'),source_index=u32,lowered_index=u32))
D['selector']=tagged(always={},incoming_lifecycle=dict(lifecycle=R('lifecycle')))
D['phase_event']=tagged(**p);D['phase']=obj(id=u32,function=u32,site=R('site'),selector=R('selector'),within=R('within'),event=R('phase_event'))
D['contract']=obj(revision=C(1),**{k:V(t)for k,t in [('bindings','binding'),('scopes','scope'),('scope_values','s_value'),('exits','exit'),('phase_sites','phase'),('ends','end'),('returns','return'),('adoptions','adoption')]})
D['observer']=obj(function=u32,site=R('site'),op=C('source_journal_observe'),results=V('decl',1),operands=V(u32,0),scope_value=u32,adoption=u32)
root=obj(format=C('draft-source-alias-compiler-constraints'),revision=C(4),draft_sha256=C('28db5402d408528b02aac917c53bf94f98ffe7d4b0fe49760dd3b0015cc1c029'),contract=R('contract'),proposed_operations=V('observer'))
D['diagnostic']={'type':'string','pattern':'^[A-Za-z0-9_:-]{1,128}$'}
D['digest']={'type':'string','pattern':'^[0-9a-f]{64}$'}
D['coordinate']=obj(schema_digest=R('digest'),roots=V(obj(section=E(*range(1,11)),digest=R('digest')),10))
D['checked_pair']=obj(function=u32,id=u32)
D['checked']=obj(bindings=V('checked_pair'),scope_values=V('checked_pair'),exits=V('checked_pair'))
D['budget']=obj(max_work=u64,max_edges=u64,max_copied_bytes=u64,max_depth={'type':'integer','minimum':1,'maximum':128})
flags=dict(format=C('smir-source-contracts-static-report'),revision=C(1),binding=C('unbound'),source_fact_authority=C(False),runtime_authority=C(False),active_v3_verified=C(False))
D['verify_report']=obj(**flags,status=C('conditional-static-constraints'),source=R('coordinate'),checked=R('checked'),deferred=V('diagnostic'))
D['comparison_report']=obj(**flags,status=C('static-comparison'),result=boolean,function=u32,functions=V(u32),left=obj(source=R('coordinate'),checked=R('checked')),right=obj(source=R('coordinate'),checked=R('checked')),deferred=V('diagnostic'))
D['error_report']=obj(**flags,status=C('error'),**{'class':E('input','semantic','unavailable','resource','internal')},code=R('diagnostic'),detail={'type':'string','maxLength':4096})
D['report']={'anyOf':[R('verify_report'),R('comparison_report'),R('error_report')]}
schema={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:rax:smir:runtime:source-contracts:reference:1','$comment':'Finite static source-contract reference tool. NOT active SMIR root3, runtime facts, ScopeRef or Journal authority.',**root,'$defs':D}
raw=(json.dumps(schema,indent=2)+'\n').encode()
def main():
 import sys
 if '--check'in sys.argv:
  if TARGET.read_bytes()!=raw:raise SystemExit('source-contract schema reproduction mismatch')
 else:TARGET.write_bytes(raw)
 print('source-contract schema',len(raw),'bytes',hashlib.sha256(raw).hexdigest())
if __name__=='__main__':main()
