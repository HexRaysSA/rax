"""Authored legal inline-retained source observer recipe; no frontend/runtime proof."""
from copy import deepcopy
from .test_factory import pointer_factory
from candidate.context import RootContext
from candidate import root3_context as D

def blueprint():
    old,carrier=pointer_factory();roots=deepcopy(old.sections);doc=deepcopy(carrier);c=doc['contract']
    scope=next(s for s in c['scopes']if s['function']==0);scope['subject']='inline';scope['enter']=dict(kind='pre_op',block=0,index=0)
    phase=next(p for p in c['phase_sites']if p['function']==0 and p['id']==0);phase['site']=deepcopy(scope['enter']);phase['event']=dict(kind='enter_root',scope=0,binding=0,vtt=None)
    bind=dict(id=1,function=0,site=dict(kind='normal_post',block=0,index=0),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='bind_journal',scope_value=100,journal=20))
    c['phase_sites'].insert(1,bind)
    caller=roots[3]['functions'][1];caller['blocks'][0]['ops'].append(dict(op='source_journal_observe',results=[dict(id=2,type=dict(module=dict(kind='self'),id=4000))],operands=[],scope_value=100,adoption=10))
    c['exits'].append(dict(id=0,function=1,scope_value=100,site=dict(kind='return_exit',block=0),outcome=dict(kind='normal_retained_call',journal=2,**{'return':0})))
    c['returns'].append(dict(id=0,function=1,scope=0,exit=0,disposition='retained_to_call'))
    c['phase_sites'].append(dict(id=13,function=1,site=dict(kind='return_exit',block=0),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_exit',exit=0)))
    return roots,doc

def owner(roots, document, budget):
    roots=deepcopy(roots)
    roots[3].update(payload_revision=3,source_contract=D.codec().wire_contract(document['contract'],budget=budget))
    return RootContext.from_module(D.codec().encode_module(roots,budget=budget),budget=budget)


def products():
    """Reference SEM's exact binary; never duplicate/regenerate another owner."""
    from pathlib import Path
    import ast,hashlib,json
    root=Path(__file__).resolve().parents[3]
    sem='docs/specifications/smir/portable/conformance/execution/source-observer/'
    inputs=[sem+'inline-retained-observer.smo',sem+'inline-retained-observer.source-contract.json',
        'docs/specifications/smir/portable/schema/runtime/source_contracts.json',
        'docs/specifications/smir/portable/schema/runtime/source_carrier_records.json',
        'tools/smir-runtime-contract/source_contracts/'+ 'observer_fixtures.py',
        *['tools/smir-runtime-contract/source_contracts/'+n for n in ['checker.py','identity.py','comparison_values.py','observer.py','test_observer.py']],
        *['tools/smir-format/execution/candidate/'+n for n in ['context.py','root3_context.py','verify.py','source_observer.py','source_grounding.py']]]
    methods=[]
    for cls in ast.parse((root/'tools/smir-runtime-contract/source_contracts/test_observer.py').read_bytes()).body:
        if isinstance(cls,ast.ClassDef):
            methods.extend('source_contracts.test_observer.'+cls.name+'.'+fn.name for fn in cls.body if isinstance(fn,ast.FunctionDef)and fn.name.startswith('test_'))
    document=dict(format='static-source-journal-observer-fixtures',revision=1,
        binding='unbound',source_fact_authority=False,runtime_authority=False,executable=False,
        reference_fixture=sem+'inline-retained-observer.smo',
        tests=[dict(test=name,expected_test_pass=True)for name in methods],
        limits='Conditional static source graph/body constraints only; negative tests assert actual refusals, not accepted semantics. No Journal/runtime/registry/source semantic admission.')
    provenance=dict(format='static-source-journal-observer-provenance',revision=1,
        source_origin='New authored legal inline-retained callee/caller recipe; same exact binary owned by SEM, not compiler/frontend or native guest output.',
        input_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest()for n in inputs},
        reference_smo_bytes=(root/inputs[0]).stat().st_size,
        source_fact_authority=False,runtime_authority=False,executable=False,
        interpretation='Input identity and authored expectations only; actual normal/O/current source qualification receipts live outside this fixture corpus.')
    return {n:(json.dumps(value,indent=2)+'\n').encode()for n,value in [('cases.json',document),('provenance.json',provenance)]}


def main():
    import argparse
    from pathlib import Path
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    root=Path(__file__).resolve().parents[3];folder=root/'docs/specifications/smir/portable/conformance/runtime/source-observer'
    for name,raw in products().items():
        target=folder/name
        if args.check:
            if not target.is_file()or target.read_bytes()!=raw:raise SystemExit('observer fixture drift: '+name)
        else:folder.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    print('observer reference2products; no binary written;', 'nonwriting reproduction passed'if args.check else'owned metadata written')

if __name__=='__main__':main()
