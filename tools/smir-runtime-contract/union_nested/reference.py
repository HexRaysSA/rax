"""Closed authored fixtures; observations run actual core-backed nested model."""
import json
from pathlib import Path
from union_prestore.bootstrap import initialize
initialize()
from .model import NestedWorld,Candidate,Index,SourceValue,Raw,Refusal,GuestFault,_api,arm,mask
ROOT=Path(__file__).resolve().parents[3]
FOLDER=ROOT/'docs/specifications/smir/portable/conformance/runtime/union-nested-reference'

def observe(name):
    b=_api().SourceQueryBudget(max_work=10**7,max_edges=10**6,max_copied_bytes=10**7,max_depth=64)
    w=NestedWorld(budget=b);r=w.register(logical_index=(1<<40)-1 if name=='huge-symbolic' else 0,bound=1<<40 if name=='huge-symbolic' else 1,budget=b)
    def path(inner='left',outer='aggregate'):
        q=w._lookup(w.windows,r)
        return (Candidate('outer',outer,Index(q.logical_index,128,False,q.bound)),)+((Candidate('inner',inner,Index(0)),) if inner else ())
    def assign(inner='left',outer='aggregate',byte=0,n=42):
        p=w.preflight(r,path(inner,outer),SourceValue(Raw.integer(8,n)),byte=byte,budget=b)
        t=w.commit(p,budget=b);w.execute_store(t,budget=b);w.complete(t,budget=b)
    if name in ['both-births','huge-symbolic']:
        assign();s=w._state(r)
        if name=='huge-symbolic':return dict(objects=len(w.machine.memory.objects),physical_bytes=sum(o['size']for o in w.machine.memory.objects.values()),logical_index=w._lookup(w.windows,r).logical_index)
        return dict(generations=[arm(s,'aggregate').generation,s.container_generation,arm(s,'left',True).generation],stores=len(w.machine.memory.effects),cursor=w.cursor,physical=w.machine.memory.raw_load(w.pointer(r),1).bits)
    if name=='same-parent-switch-child':
        assign();w.store_value(r,8,SourceValue(Raw.integer(8,17)),budget=b);assign(inner='right',n=43);s=w._state(r)
        return dict(parent=arm(s,'aggregate').generation,child=arm(s,'right',True).generation,sibling=w.load(r,8,1,budget=b).raw.bits,sibling_init=w.load(r,8,1,budget=b).indeterminate,old_child_live=arm(s,'left',True).live)
    if name=='parent-replacement':
        assign(byte=1,n=17);assign(outer='alternate',inner=None);s=w._state(r)
        return dict(container_live=s.container_live,child_live=arm(s,'left',True).live,physical=w.machine.memory.raw_load(w.pointer(r,1),1).bits,source_init=w.load(r,1,1,budget=b).indeterminate)
    if name=='readonly-inner':
        w.machine.memory.objects[w.pointer(r).origin]['mutable']=False
        try:w.preflight(r,path(),SourceValue(Raw.integer(8,42)),budget=b)
        except GuestFault as e:return dict(error=e.code,cursor=w.cursor,effects=len(w.machine.memory.effects),live=sum(a.live for a in w._state(r).outer))
    if name in ('index128-alias','unknown-phase'):
        cs=path();inner=Candidate('inner','left',Index(1<<64,128,False,1)) if name=='index128-alias' else Candidate('inner','left',Index(0),phase='unknown')
        try:w.preflight(r,(cs[0],inner),SourceValue(Raw.integer(8,42)),budget=b)
        except Refusal as e:return dict(error=e.code,kind=e.kind,cursor=w.cursor,effects=len(w.machine.memory.effects),live=sum(a.live for a in w._state(r).outer))
    if name=='first-parent-birth-stale':
        h=w.prospective(r,inner='left',budget=b);assign(inner=None,byte=8);assign(outer='alternate',inner=None);assign()
        try:w.resolve(h)
        except Refusal as e:return dict(error=e.code,parent_generation=arm(w._state(r),'aggregate').generation)
    if name=='physical-origin-copy':
        assign();other=w.register(budget=b)
        op=(Candidate('outer','aggregate',Index(0)),Candidate('inner','left',Index(0)))
        p=w.preflight(other,op,SourceValue(Raw.integer(8,42)),budget=b);t=w.commit(p,budget=b);w.execute_store(t,budget=b);w.complete(t,budget=b)
        raw=Raw.pointer(w.pointer(r));w.machine.memory.raw_store(w.pointer(r),raw);w.copy(other,0,r,0,8,budget=b)
        observed=w.load(other,0,8,budget=b)
        return dict(physical_origins=len(w.machine.memory.raw_load(w.pointer(other),8).origins),observed_origin_bits=sum(s.length for s in observed.raw.origins),source_init=observed.indeterminate)
    raise ValueError('unsupported fixture scenario or missing expected rejection')

def check(document=None):
    import schema
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('duplicate fixture key')
            out[k]=v
        return out
    def noninteger(value):raise ValueError('noninteger fixture value')
    d=json.loads((FOLDER/'cases.json').read_bytes(),object_pairs_hook=unique,parse_float=noninteger,parse_constant=noninteger) if document is None else document
    rule=json.loads((ROOT/'docs/specifications/smir/portable/schema/runtime/union_nested_reference.schema.json').read_bytes())
    schema.audit_schema(rule);schema._validate(d,rule,rule,'$')
    if set(d)!={'format','binding','source_fact_authority','runtime_authority','semantic_admission','cost_profile_qualified','cases','tests'}:raise ValueError('fixture fields')
    if d['format']!='nested-union-prestore-reference' or d['binding']!='unbound' or any(d[n]is not False for n in ['source_fact_authority','runtime_authority','semantic_admission','cost_profile_qualified']):raise ValueError('fixture authority')
    seen=set()
    for row in d['cases']:
        if type(row)is not dict or set(row)!={'scenario','expected'} or row['scenario']in seen:raise ValueError('fixture row')
        seen.add(row['scenario'])
        if json.dumps(observe(row['scenario']),sort_keys=True,allow_nan=False)!=json.dumps(row['expected'],sort_keys=True,allow_nan=False):raise ValueError('observation mismatch: '+row['scenario'])
    return len(seen)


def main(argv=None):
    import argparse,fnmatch,sys,unittest
    from . import fixtures
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--selftest',action='store_true');p.add_argument('--name-pattern',action='append',default=[]);a=p.parse_args(argv)
    if not(a.check or a.selftest):p.error('choose --check or --selftest')
    if len(a.name_pattern)>32 or any(len(x)>128 for x in a.name_pattern)or a.name_pattern and not a.selftest:p.error('bounded name patterns require --selftest')
    cases=tests=0;ok=True
    if a.check:fixtures.check();cases=check()
    if a.selftest:
        loader=unittest.TestLoader();loader.testNamePatterns=a.name_pattern or None
        result=unittest.TextTestRunner(verbosity=2).run(loader.loadTestsFromName('union_nested.test_reference'))
        tests=result.testsRun;ok=result.wasSuccessful()
    report=dict(format='nested-union-reference-report',binding='unbound',source_fact_authority=False,runtime_authority=False,semantic_admission=False,cost_profile_qualified=False,
        status='pass'if ok else'fail',cases=cases,tests=tests,optimize=sys.flags.optimize,dont_write_bytecode=sys.dont_write_bytecode,pycache_prefix=sys.pycache_prefix)
    if a.selftest and not tests:report['status']='no-tests-matched'
    import schema
    rule=json.loads((ROOT/'docs/specifications/smir/portable/schema/runtime/union_nested_reference.schema.json').read_bytes());schema.audit_schema(rule);schema._validate(report,rule['$defs']['report'],rule,'$')
    print(json.dumps(report,sort_keys=True));return 0 if ok else 1
if __name__=='__main__':raise SystemExit(main())
