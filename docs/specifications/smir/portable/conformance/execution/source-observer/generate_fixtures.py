"""Author only this package's fixture; nonwriting exact --check reproduction."""
from pathlib import Path
from copy import deepcopy
import sys,json,hashlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6]
sys.path[:0]=[str(ROOT/p)for p in ('tools/smir-format','tools/smir-format/execution')]
from codec import CandidateCodec
from candidate.context import RootContext
from candidate import root3_context as D
from candidate.source_data_projection import source_api


def encoded(document):return(json.dumps(document,indent=2)+'\n').encode('utf8')


def emit():
    folder=ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts'
    inputs=[folder/'pointer-partial-factory-and-caller.smo',folder/'pointer-partial-return-adoption.source-contract.json']
    schemas={name:json.loads((ROOT/'docs/specifications/smir/portable/schema'/name/'candidate.json').read_bytes())for name in('abi','execution','runtime')}
    roots=CandidateCodec(schemas).decode(inputs[0].read_bytes()).roots
    doc=json.loads(inputs[1].read_bytes());c=doc['contract']
    scope=next(row for row in c['scopes']if row['function']==0)
    scope.update(subject='inline',enter=dict(kind='pre_op',block=0,index=0))
    phase=next(row for row in c['phase_sites']if row['function']==0 and row['id']==0)
    phase.update(site=deepcopy(scope['enter']),event=dict(kind='enter_root',scope=0,binding=0,vtt=None))
    c['phase_sites'].insert(1,dict(id=1,function=0,site=dict(kind='normal_post',block=0,index=0),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='bind_journal',scope_value=100,journal=20)))
    roots[3]['functions'][1]['blocks'][0]['ops'].append(dict(op='source_journal_observe',results=[dict(id=2,type=dict(module=dict(kind='self'),id=4000))],operands=[],scope_value=100,adoption=10))
    c['exits'].append(dict(id=0,function=1,scope_value=100,site=dict(kind='return_exit',block=0),outcome=dict(kind='normal_retained_call',journal=2,**{'return':0})))
    c['returns'].append(dict(id=0,function=1,scope=0,exit=0,disposition='retained_to_call'))
    c['phase_sites'].append(dict(id=13,function=1,site=dict(kind='return_exit',block=0),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_exit',exit=0)))
    b=source_api().SourceQueryBudget(max_work=10**24,max_edges=10**24,max_copied_bytes=10**24,max_depth=128)
    roots[3].update(payload_revision=3,source_contract=D.codec().wire_contract(c,budget=b))
    raw=D.codec().encode_module(roots,budget=b);owner=RootContext.from_module(raw,budget=b)
    owner.verify_abi();body=owner.verify_candidate_body(budget=b)
    if len(body.observers)!=1 or body.semantic_admission:raise AssertionError('fixture actual typed body')
    outputs={'inline-retained-observer.smo':raw,'inline-retained-observer.source-contract.json':encoded(doc),'inline-retained-observer.source.json':encoded(dict(sections={str(k):v for k,v in owner.sections.items()}))}
    outputs['manifest.json']=encoded(dict(format='source-observer-static-fixtures',revision=1,
        scope='Source-authored legal inline partial factory/caller. Real typed body/source constraints, no runtime/source operation issuer.',
        files=[dict(path=name,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))for name,data in sorted(outputs.items())],
        provenance=dict(author_role='RUNTIME+SEMANTICS',baseline_inputs=[dict(project_path=str(p.relative_to(ROOT)),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in inputs],ordinary_fn_return='pointer only; logical retained Journal uses original source metadata, not physical Fn return slot')))
    return outputs


if __name__=='__main__':
    if sys.argv[1:]not in([],['--check']):raise SystemExit('usage: generate_fixtures.py [--check]')
    outputs=emit();check='--check'in sys.argv
    for name,data in outputs.items():
        p=HERE/name
        if check:
            if not p.is_file()or p.read_bytes()!=data:raise SystemExit('fixture mismatch: '+name)
        else:p.write_bytes(data)
    print(json.dumps(dict(files=len(outputs),octets=sum(map(len,outputs.values())),checked=check)))
