"""Independent local capture predicates for the accepted S004/INT028 static join.

The provider is absent. No provider formals/body or full-reference admission is
invented. The oracle checks only actual local types, unique supplied formal IDs,
exact journal-program association, and the fixed invoke PRE frontier. All Rust
objects still pass through the actual complete phase factories.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[4]
SPEC=ROOT/'docs/specifications/smir/portable'
sys.path.insert(0,str(ROOT/'tools/smir-format'))
from codec import CandidateCodec
from oracle_sources import input_roots, input_sources, interpreter_identity
sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
from candidate.context import RootContext
from candidate.type_system import key
CODEC=CandidateCodec({o:json.loads((SPEC/f'schema/{o}/candidate.json').read_text()) for o in ['execution','runtime','abi']})
SOURCE=Path(__file__).with_name('phase-cases.json')
BASE=CODEC.decode(bytes.fromhex(next(c for c in json.loads(SOURCE.read_text())['cases']
    if c['name']=='static_external_recipe_obligation')['encoded_hex'])).roots
BASE[1]['types'].append(dict(id=700,kind='journal'))
CASES=[]
def ref(identifier):return dict(module=dict(kind='self'),id=identifier)
def capture(parameter,typ,source):return dict(parameter=parameter,type=ref(typ),source=source)
def oracle(roots):
    context=RootContext(roots)
    context.verify_abi()  # Real local source ABI/journal; not a provider certificate.
    function=roots[3]['functions'][1]
    assert function['id']==1 and len(function['blocks'])==3
    entry=function['blocks'][0]
    assert entry['id']==0 and entry['ops']==[] and entry['term']['op']=='invoke'
    term=entry['term']
    value_types={p['id']:p['type'] for p in function['params']}
    value_types.update({p['id']:p['type'] for p in term['normal']['results']})
    value_types[term['unwind']['exception']['id']]=term['unwind']['exception']['type']
    pre_values={p['id'] for p in function['params']}
    action=roots[8]['functions'][0]['actions'][0]
    seen=set()
    for item in action['captures']:
        if item['parameter'] in seen:return 'cleanup_capture_bijection'
        seen.add(item['parameter'])
        source=item['source'];typ=context.types.get(item['type'])['kind']
        if source['kind']=='value':
            if source['value'] not in value_types:return 'ssa_reference'
            if not context.types.equal(value_types[source['value']],item['type']):return 'cleanup_capture_value_type'
        elif source['kind']=='exception':
            if typ!='exception':return 'cleanup_capture_exception'
        elif source['kind']=='journal':
            if typ!='journal' or source['program']!=action['program']:return 'cleanup_capture_journal'
    # Type checks precede dominance, matching the explicit two-stage contract.
    if any(c['source']['kind']=='value' and c['source']['value'] not in pre_values for c in action['captures']):
        return 'ssa_dominance'
    context.assert_snapshot()
    return 'ok'
def add(name,captures):
    roots=deepcopy(BASE);roots[8]['functions'][0]['actions'][0]['captures']=captures
    encoded=CODEC.encode(roots)
    CASES.append(dict(name=name,expected=oracle(roots),sha256=hashlib.sha256(encoded).hexdigest(),encoded_hex=encoded.hex()))

def generate():
    value=capture(10,7,dict(kind='value',value=0))
    exception=capture(11,7,dict(kind='exception'))
    journal=capture(12,700,dict(kind='journal',program=ref(0)))
    for name,c in [('value_pre_parameter',value),('injected_exception',exception),('injected_exact_journal',journal)]:add(name,[c])
    add('three_distinct_capture_sources',[value,exception,journal])
    add('reject_missing_ssa_value',[capture(10,7,dict(kind='value',value=999))])
    add('reject_value_type',[capture(10,17,dict(kind='value',value=0))])
    add('reject_normal_result_at_invoke_PRE',[capture(10,17,dict(kind='value',value=1))])
    add('reject_unwind_exception_at_invoke_PRE',[capture(10,7,dict(kind='value',value=2))])
    add('reject_injected_exception_type',[capture(11,17,dict(kind='exception'))])
    add('reject_injected_journal_type',[capture(12,17,dict(kind='journal',program=ref(0)))])
    add('reject_injected_journal_program',[capture(12,700,dict(kind='journal',program=ref(999)))])
    add('reject_duplicate_supplied_formal',[value,value])
    sources={Path(m.__file__).resolve() for m in list(sys.modules.values()) if getattr(m,'__file__',None) and Path(m.__file__).resolve().is_relative_to(ROOT)}
    sources.update([SOURCE,Path(__file__).resolve()])
    output=Path(__file__).with_name('capture-cases.json')
    output.write_text(json.dumps(dict(scope='Accepted S004/INT028 conditional static proof plus independent actual-local-type/fixed-invoke-PRE capture oracle. Provider formals/body/instance and full reference admission unavailable; exact future SEM/R obligations retained.',sources=input_sources(ROOT,sources),oracle_input_roots=input_roots(),oracle_interpreter=interpreter_identity(),cases=CASES),separators=(',',':'))+'\n')
    print(len(CASES),'cases',sum(c['expected']=='ok' for c in CASES),'positive',sum(c['expected']!='ok' for c in CASES),'negative')
if __name__=='__main__':generate()
