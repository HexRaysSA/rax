"""Independent-codec bindings from unchanged SEM full-root state-helper cases."""
from fixture_provenance import provenance, write_bytes, write_text
from pathlib import Path
from copy import deepcopy
import hashlib,json,sys
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from fixtures import prepare_declared_abi2_source, CandidateCodec,SCHEMAS,ROOT

def main():
    codec=CandidateCodec(SCHEMAS)
    source=HERE.parent/'execution/core-cases.json'
    cases={}
    for case in json.loads(source.read_text())['cases']:
        if case['oracle_scope']!='abi-and-execution' or case['expected']!='ok':continue
        roots=codec.decode(bytes.fromhex(case['encoded_hex'])).roots
        if not roots[6]['imports']:continue
        name=case['name'];cases[name]=roots
        for suffix,field,value in [('bad-catalog','catalog','00'*32),('bad-version','version',0),
                                   ('bad-contract','contract','unknown')]:
            changed=deepcopy(roots);changed[6]['imports'][0][field]=value
            # Remove private wrapper bodies: the bad import remains present but
            # is not called. Every static import must still be checked.
            changed[3]['functions']=changed[3]['functions'][:1]
            cases[name+'-'+suffix]=changed
        changed=deepcopy(roots)
        target=changed[6]['imports'][0]['signature']['id']
        signature=next(t for t in changed[1]['types'] if t['id']==target)
        attrs=next((key for key in ('param_noundef','result_noundef') if signature[key]),None)
        if attrs is not None:
            signature[attrs][0]=not signature[attrs][0]
            changed[3]['functions']=changed[3]['functions'][:1]
            cases[name+'-bad-noundef']=changed
        changed=deepcopy(roots)
        changed[6]['imports'][0]['options']['predicate']='oeq'
        changed[3]['functions']=changed[3]['functions'][:1]
        cases[name+'-unused-fp-option']=changed
    folder=HERE/'state-helper-fixtures';folder.mkdir(exist_ok=True);manifest={}
    for name,roots in cases.items():
        prepare_declared_abi2_source(roots)
        data=codec.encode(roots);codec.decode(data);write_bytes(folder/(name+'.smo'), data)
        source_records=any(t['kind']=='record' for t in roots[10]['types'])
        expected='ok' if '-' not in name else 'semantic'
        manifest[name]={'expected_class':expected, 'evidence_limit':'ABI039/R009 canonical state proof qualification; actual full factory and phase predicates' if source_records else 'real full factory or semantic rejection', 'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
                        'accept': expected=='ok'}
    write_text(folder/'manifest.json', json.dumps({'scope':'Real full factory after ABI039/R009 canonical source qualification; no helper execution',
        'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'provenance':provenance(__file__, ['crates/smir-portable/tests/metadata/fixtures.py', str(source.relative_to(ROOT))], manifest),'cases':manifest},indent=2)+'\n')
    print('state-helper fixtures',len(manifest),'positive',sum(c['accept'] for c in manifest.values()))
if __name__=='__main__':main()
