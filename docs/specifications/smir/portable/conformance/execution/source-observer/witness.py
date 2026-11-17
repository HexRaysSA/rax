"""Actual observer typed-body/path witnesses; original source, no runtime issuer."""
from pathlib import Path
from copy import deepcopy
from dataclasses import FrozenInstanceError
import sys,json,hashlib
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6]
sys.path[:0]=[str(ROOT/p)for p in ('tools/smir-format','tools/smir-format/execution','tools/smir-runtime-contract','tools/smir-abi')]
from candidate.context import RootContext
from candidate import root3_context as D,source_observer as O
from candidate.source_data_projection import source_api
from candidate.type_system import Types,ref
from candidate.source_grounding import prove_paths,GroundingError


def need(value,message):
    if not value:raise AssertionError(message)


def budget():return source_api().SourceQueryBudget(max_work=10**24,max_edges=10**24,max_copied_bytes=10**24,max_depth=128)


def fixture():
    b=budget();o=RootContext.from_module((HERE/'inline-retained-observer.smo').read_bytes(),budget=b)
    return o,b,json.loads((HERE/'inline-retained-observer.source-contract.json').read_bytes())['contract']


def fresh(roots,b):
    raw=D.codec().encode_module(roots,budget=b)
    return RootContext.from_module(raw,budget=b)


def checked(o,b):o.verify_abi();return o.verify_candidate_body(budget=b)


def reject(callback,code):
    try:callback()
    except Exception as e:
        need(code in str(e),(code,type(e).__name__,str(e)));return
    raise AssertionError('accepted '+code)


def observer(o):return o.sections[3]['functions'][1]['blocks'][0]['ops'][1]


def run(case):
    if case=='fixture-integrity':
        for item in json.loads((HERE/'manifest.json').read_bytes())['files']:
            data=(HERE/item['path']).read_bytes();need(len(data)==item['bytes']and hashlib.sha256(data).hexdigest()==item['sha256'],'fixture drift')
    elif case=='original-body':
        o,b,c=fixture();stamp=o.prepare_source_data(budget=b);out=checked(o,b)
        need(out.owner is o and out.stamp is stamp and out.verified.functions_root==o.sections[3],'full original custody')
        need(len(out.observers)==1 and vars(out.observers[0])==dict(function=1,block=0,index=1,result=2,result_type=4000,scope_value=100,adoption=10),'exact actual coordinates')
        need(not out.executable and not out.semantic_admission and not out.active_v3_verified and o.execution_checked is None,'partial only')
        need({f['id']:prove_paths(f,c,b,source_observers=True)for f in o.sections[3]['functions']}=={0:1,1:1},'scope closure')
    elif case=='immutable-coordinates':
        o,b,c=fixture();out=checked(o,b)
        try:out.observers[0].scope_value=101
        except(FrozenInstanceError,AttributeError):pass
        else:raise AssertionError('mutable coordinates')
        need(type(out.observers)is tuple,'tuple')
    elif case=='same-numeric-namespaces':
        o,b,c=fixture();roots=deepcopy(o.sections);op=roots[3]['functions'][1]['blocks'][0]['ops'][1];op['results'][0]['id']=100
        roots[3]['source_contract']['exits'][1]['outcome']['journal']=100
        o=fresh(roots,b);out=checked(o,b);need(out.observers[0].result==out.observers[0].scope_value==100,'separate namespaces')
        c=D.codec().raw_contract(o.sections[3]['source_contract'],budget=b)
        need(prove_paths(o.sections[3]['functions'][1],c,b,source_observers=True)==1,'ordinary result did not overwrite S')
    elif case=='ordinary-ssa-ffffffff':
        o,b,c=fixture();roots=deepcopy(o.sections);roots[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id']=0xffffffff
        # Only typed-body domain positive: source terminal instead of an
        # unrepresentable raw-source Journal SSA. No source relation is claimed.
        roots[3]['source_contract']['exits'][1]['outcome']=dict(kind='normal_no_journal')
        roots[3]['source_contract']['returns'][1]['disposition']='terminal'
        o=fresh(roots,b);out=checked(o,b);need(out.observers[0].result==0xffffffff,'ordinary SSA sentinel narrowed')
    elif case=='physical-type-ffffffff':
        o,b,c=fixture();roots=deepcopy(o.sections)
        def refs(value):
            if type(value)is dict:
                if set(value)=={'module','id'}and value['module']=={'kind':'self'}and value['id']==4000:value['id']=0xffffffff
                else:
                    for child in value.values():refs(child)
            elif type(value)is list:
                for child in value:refs(child)
        refs(roots[1]);refs(roots[3]['functions'])
        for row in roots[10]['types']:
            if row['execution']is not None:refs(row['execution']['some'])
        for row in roots[6]['imports']:refs(row['types'])
        next(row for row in roots[1]['types']if row['id']==4000)['id']=0xffffffff;roots[1]['types'].sort(key=lambda x:x['id'])
        o=fresh(roots,b);out=checked(o,b);need(out.observers[0].result_type==0xffffffff,'physical type sentinel narrowed')
    elif case=='ordinary-block-ffffffff':
        o,b,c=fixture();roots=deepcopy(o.sections);function=deepcopy(roots[3]['functions'][0])
        function.update(id=2,entry=0xffffffff,abi_signature=None)
        function['blocks'][0].update(id=0xffffffff,ops=[])
        roots[3]['functions'].append(function)
        o=fresh(roots,b);out=checked(o,b)
        need(out.verified.functions_root['functions'][2]['entry']==0xffffffff,'ordinary block sentinel narrowed')
    elif case in('wrong-result-type','malformed-op','source-id-boundary','type-oracle-substitute'):
        o,b,c=fixture();op=deepcopy(observer(o));types=o.types
        if case=='wrong-result-type':op['results'][0]['type']=ref(1);reject(lambda:O.check(op,types,budget=b),'V3_OBSERVER_RESULT_TYPE')
        elif case=='malformed-op':
            for value in(None,[],dict(op='copy'),dict(op,operands=[0]),dict(op,results=[]),dict(op,extra=True)):
                reject(lambda value=value:O.check(value,types,budget=b),'V3_OBSERVER_')
        elif case=='source-id-boundary':
            for name in('scope_value','adoption'):
                for value in(True,0xffffffff,-1):
                    bad=deepcopy(op);bad[name]=value;reject(lambda:O.check(bad,types,budget=b),'V3_OBSERVER_SOURCE_ID')
        else:
            class Fake:
                def get(self,*args):raise AssertionError('caller oracle invoked')
            reject(lambda:O.check(op,Fake(),budget=b),'V3_OBSERVER_TYPE_CONTEXT')
    elif case=='duplicate-ssa':
        o,b,c=fixture();roots=deepcopy(o.sections);roots[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id']=1
        reject(lambda:fresh(roots,b),'V3_DUPLICATE')
    elif case in('ordinary-copy-use','ordinary-use-before-def'):
        o,b,c=fixture();roots=deepcopy(o.sections);ops=roots[3]['functions'][1]['blocks'][0]['ops'];copy=dict(op='copy',results=[dict(id=7,type=ref(4000))],operands=[2])
        ops.insert(1 if case=='ordinary-use-before-def'else 2,copy);o=fresh(roots,b)
        if case=='ordinary-use-before-def':reject(lambda:checked(o,b),'ssa_dominance')
        else:need(checked(o,b).observers[0].index==1,'ordinary copy')
    elif case in('scope-undefined-at-pre','scope-stale-at-pre','profile-mode'):
        o,b,c=fixture();f=o.sections[3]['functions'][1]
        if case=='profile-mode':
            reject(lambda:prove_paths(f,c,b),'CG_OBSERVER_PROFILE_UNAVAILABLE')
            reject(lambda:prove_paths(f,c,b,source_observers=1),'CG_OBSERVER_PROFILE')
            need(prove_paths(o.sections[3]['functions'][0],c,b)==1,'old no-observer default')
        elif case=='scope-undefined-at-pre':
            bad=deepcopy(f);bad['blocks'][0]['ops'][1]['scope_value']=999
            # Explicit malformed standalone helper boundary, not a public source-positive.
            reject(lambda:prove_paths(bad,c,b,source_observers=True),'CG_S_UNDEFINED')
        else:
            c=deepcopy(c);c['exits'].append(dict(id=1,function=1,scope_value=100,site=dict(kind='pre_op',block=0,index=1),outcome=dict(kind='normal_no_journal')))
            c['phase_sites'].append(dict(id=14,function=1,site=dict(kind='pre_op',block=0,index=1),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_exit',exit=1)))
            roots=deepcopy(o.sections);roots[3]['source_contract']=D.codec().wire_contract(c,budget=b)
            o=fresh(roots,b);checked(o,b)
            c=D.codec().raw_contract(o.sections[3]['source_contract'],budget=b)
            reject(lambda:prove_paths(o.sections[3]['functions'][1],c,b,source_observers=True),'CG_S_STALE')
    elif case=='changed-original-budget':
        o,b,c=fixture();o.verify_abi();reject(lambda:o.verify_candidate_body(budget=budget()),'V3_CONSTRUCTION_BUDGET')
    elif case=='editable-abi-flag':
        o,b,c=fixture();o.abi_checked=True;reject(lambda:o.verify_candidate_body(budget=b),'V3_GENUINE_ABI_REQUIRED')
    elif case=='collector-original-afterguard':
        o,b,c=fixture();o.verify_abi();actual=O.collect
        def changed(*args,**kw):
            value=actual(*args,**kw);o.sections[2]['manifest']['key']['abi_minor']+=1;return value
        with patch.object(O,'collect',changed):reject(lambda:o.verify_candidate_body(budget=b),'context_snapshot_changed')
    elif case=='predicate-quota-before-type':
        o,b,c=fixture();op=observer(o);calls=[];actual=Types.get
        def observed(self,*args,**kw):calls.append(1);return actual(self,*args,**kw)
        b.charge(work=b.max_work-b._used_work)
        with patch.object(Types,'get',observed):reject(lambda:O.check(op,o.types,budget=b),'SOURCE_DATA_RESOURCE')
        need(not calls,'type oracle entered before quota')
    elif case=='collector-quota-before-output':
        o,b,c=fixture();calls=[];actual=O.V3ObserverSite
        def observed(*args,**kw):calls.append(1);return actual(*args,**kw)
        b.charge(work=b.max_work-b._used_work)
        with patch.object(O,'V3ObserverSite',observed):reject(lambda:O.collect(o.sections[3],budget=b),'SOURCE_DATA_RESOURCE')
        need(not calls,'output allocated before quota')
    elif case=='legacy-machine-and-registry-refusal':
        o,b,c=fixture();out=checked(o,b)
        reject(o.verify_execution,'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
        reject(lambda:o.source_registry_context(budget=b),'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
        import candidate.machine as machine
        calls=[];actual=machine.Memory
        def observed(*args,**kw):calls.append(1);return actual(*args,**kw)
        with patch.object(machine,'Memory',observed):reject(lambda:machine.Machine(out.verified),'shape')
        need(not calls,'legacy Machine initialized memory for v3')
    elif case=='public-v2-rejects-observer':
        o,b,c=fixture();roots=deepcopy(o.sections);roots[3].pop('source_contract');roots[3]['payload_revision']=2
        from candidate.verify import verify
        reject(lambda:verify(roots[1],roots[3],roots[8]),'shape')
    else:raise ValueError('unknown observer case '+case)


if __name__=='__main__':
    selected=sys.argv[1];run(selected);print(json.dumps(dict(case=selected,passed=True,optimize=sys.flags.optimize,scope='actual typed body and finite path predicates; R pass2 separately qualified; no runtime/admission')))
