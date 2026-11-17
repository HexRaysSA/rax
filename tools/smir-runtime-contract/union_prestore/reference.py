"""Run finite unbound reference observations; never admit executable source SMIR."""
import argparse,json,sys,unittest
from .bootstrap import initialize

def _api():
    initialize()
    from .model import World,SourceValue,_api,mask
    from candidate.raw import Raw
    from candidate.type_system import ref
    from candidate.memory import GuestFault
    return World,SourceValue,_api,mask,Raw,ref,GuestFault

def _budget(api):
    return api().SourceQueryBudget(max_work=10**7,max_edges=10**6,max_copied_bytes=10**7,max_depth=64)

def _assignment(w,arm,offset,value,api):
    b=_budget(api);p=w.preflight(arm,offset,value,budget=b);t=w.commit(p,budget=b)
    w.execute_store(t,budget=b);w.complete(t,budget=b)

def _failure(action):
    from candidate.memory import GuestFault
    try:action()
    except GuestFault as error:return error.code,error.language_ub
    except ValueError as error:return str(error),False
    raise ValueError('UNION_REFERENCE_EXPECTED_REJECTION')

def observe(scenario):
    World,SourceValue,api,mask,Raw,ref,GuestFault=_api()
    w=World();value=lambda n:SourceValue(Raw.integer(8,n))
    if scenario=='initialized-store':
        _assignment(w,'a',0,value(42),api)
        return dict(physical=w.machine.memory.raw_load(w.base,1).bits,source_init=w.load(w.base,1).indeterminate,stores=len(w.machine.memory.effects),generation=w.cells['a'].generation,cursor=w.cursor)
    if scenario=='sticky-freeze-store':
        w.machine.memory.raw_store(w.base,Raw.integer(8,0x91));v=w.load(w.base,1).freeze()
        w.init[w.base.origin]=0;w.store(w.base,v)
        error,_=_failure(lambda:v.numeric(types=w.machine.types,reference=ref(1)))
        return dict(physical=w.machine.memory.raw_load(w.base,1).bits,source_init=w.load(w.base,1).indeterminate,numeric_error=error)
    if scenario in ('same-live-arm','replace-arm','reactivate-ended-arm'):
        _assignment(w,'a',1,value(17),api)
        if scenario=='reactivate-ended-arm':w.end('a')
        arm='b' if scenario=='replace-arm' else 'a'
        _assignment(w,arm,0,value(19),api)
        result=dict(generation=w.cells[arm].generation,physical_sibling=w.machine.memory.raw_load(w.pointer(1),1).bits,sibling_init=w.load(w.pointer(1),1).indeterminate)
        if scenario=='same-live-arm':result['stores']=len(w.machine.memory.effects)
        if scenario=='replace-arm':result['old_live']=w.cells['a'].live
        return result
    if scenario=='first-birth-stale':
        h=w.prospective('a');_assignment(w,'a',0,value(1),api);w.end('a');_assignment(w,'a',0,value(2),api)
        error,_=_failure(lambda:w.resolve(h));return dict(error=error)
    if scenario=='physical-origin-copy':
        w=World(16);w.machine.memory.raw_store(w.base,Raw.pointer(w.base));w.copy(w.pointer(8),w.base,8)
        return dict(physical_origins=len(w.machine.memory.raw_load(w.pointer(8),8).origins),observed_origins=len(w.load(w.pointer(8),8).raw.origins),source_init=w.load(w.pointer(8),8).indeterminate)
    if scenario=='overlap-snapshot':
        for i in range(8):w.machine.memory.raw_store(w.pointer(i),Raw.integer(8,i+1))
        w.init[w.base.origin]=0x00ff0000ff00ff00;w.copy(w.pointer(2),w.base,6,overlap=True)
        return dict(physical=[w.machine.memory.raw_load(w.pointer(i),1).bits for i in range(8)],source_init=w.init[w.base.origin])
    if scenario=='untracked-allocation':
        extra=w.machine.memory.allocate(1,1);error,_=_failure(lambda:w.load(extra,1))
        return dict(error=error,effects=len(w.machine.memory.effects),tracked=extra.origin in w.init)
    if scenario=='range-numeric-conversion':
        p=w.machine.memory.offset(w.base,0,False,False,False,inrange={'lower':0,'upper':8})
        v=SourceValue(Raw.pointer(p).slice(0,8),0)
        error,ub=_failure(lambda:v.numeric(types=w.machine.types,reference=ref(1)))
        return dict(error=error,language_ub=ub)
    if scenario=='ordinary-origin-conversion':
        raw=Raw.pointer(w.base);v=SourceValue(raw,0).numeric(types=w.machine.types,reference=ref(3))
        return dict(value=v.data,raw_origins=len(raw.origins))
    if scenario=='core-poison-undef':
        p=SourceValue(Raw.integer(8,0xa5,poison=1),0).numeric(types=w.machine.types,reference=ref(1))
        u=SourceValue(Raw.integer(8,0xa5,undef=0xf0),0).numeric(types=w.machine.types,reference=ref(1))
        return dict(poison_state=p.state,undef_state=u.state,undef_value=u.data)
    if scenario=='readonly-preflight':
        w.machine.memory.objects[w.base.origin]['mutable']=False
        error,_=_failure(lambda:w.preflight('a',0,value(42),budget=_budget(api)))
        return dict(error=error,cells=len(w.cells),cursor=w.cursor,effects=len(w.machine.memory.effects))
    if scenario=='post-store-resume':
        b=_budget(api);p=w.preflight('a',0,value(42),budget=b);t=w.commit(p,budget=b);w.execute_store(t,budget=b)
        w.park(t,budget=b);w.resume(t,budget=b)
        error,_=_failure(lambda:w.execute_store(t,budget=b));w.complete(t,budget=b)
        return dict(error=error,physical=w.machine.memory.raw_load(w.base,1).bits,stores=len(w.machine.memory.effects),cursor=w.cursor)
    raise ValueError('UNION_REFERENCE_SCENARIO')

def validate(document):
    initialize()
    import schema
    from pathlib import Path
    if Path(schema.__file__).resolve()!=Path(__file__).resolve().parents[1]/'schema.py':
        raise RuntimeError('UNION_REFERENCE_SCHEMA_NAMESPACE')
    schema.validate(document,'union_prestore_reference')
    names=[row['scenario'] for row in document['cases']]
    if len(names)!=len(set(names)):raise ValueError('UNION_REFERENCE_DUPLICATE_SCENARIO')

def run_cases(document):
    validate(document)
    count=0
    for row in document['cases']:
        observed=observe(row['scenario'])
        if observed!=row['expected']:raise ValueError('UNION_REFERENCE_OBSERVATION_MISMATCH: '+row['scenario'])
        count+=1
    return count

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='read-only schema, product and actual observation check')
    parser.add_argument('--selftest',action='store_true',help='run the finite independent reference tests')
    args=parser.parse_args(argv)
    if not(args.check or args.selftest):parser.error('choose --check or --selftest')
    initialize();cases=0;tests=0;success=True
    if args.check:
        from . import fixtures
        fixtures.check();cases=run_cases(json.loads((fixtures.FOLDER/'cases.json').read_bytes()))
    if args.selftest:
        suite=unittest.defaultTestLoader.loadTestsFromName('union_prestore.test_reference')
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        tests=result.testsRun;success=result.wasSuccessful()
    report=dict(format='union-prestore-reference-report',revision=1,binding='unbound',
        source_fact_authority=False,runtime_authority=False,semantic_admission=False,
        cost_profile_qualified=False,status='pass' if success else 'fail',cases=cases,tests=tests,
        optimize=sys.flags.optimize,dont_write_bytecode=sys.dont_write_bytecode,pycache_prefix=sys.pycache_prefix,
        scope='quiescent-single-tracked-union-reference')
    import schema
    rule=json.loads((schema.SCHEMAS/'union_prestore_reference.schema.json').read_bytes())
    schema.audit_schema(rule);schema._validate(report,rule['$defs']['report'],rule,'$')
    print(json.dumps(report,sort_keys=True))
    return 0 if success else 1
if __name__=='__main__':raise SystemExit(main())
