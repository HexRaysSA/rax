"""Complete frozen portable-service catalog signatures, independent Python codec.

No service executes; explicit reference grants are separate from file requests.
"""
from fixture_provenance import provenance, write_bytes, write_text
from pathlib import Path
from copy import deepcopy
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from profile_fixtures import complete
from fixtures import prepare_declared_abi2_source, CandidateCodec,SCHEMAS,SPEC,ref,some

def main():
    catalog_path=SPEC/'schema/runtime/services-v1.json'
    catalog=json.loads(catalog_path.read_text());codec=CandidateCodec(SCHEMAS)
    cases={}
    for spec in catalog['records']:
        roots=complete('portable-identity')
        by_bits={t['bits']:t['id'] for t in roots[1]['types'] if t['kind']=='int'}
        data=next(t['id'] for t in roots[1]['types'] if t['kind']=='data_ptr' and t['space']=='guest_data')
        fresh=max(t['id'] for t in roots[1]['types'])+1
        roots[1]['types'].append({'id':fresh,'kind':'code_ptr','signature':ref(12)})
        def formal(template):
            if template[0] in 'iu' and template[1:].isdigit():return ref(by_bits[int(template[1:])])
            if template=='data_ptr':return ref(data)
            if template=='code_ptr':return ref(fresh)
            raise RuntimeError(template)
        signature=fresh+1
        roots[1]['types'].append({'id':signature,'kind':'function',
            'params':[formal(v['type']) for v in spec['params']],
            'results':[formal(v['type']) for v in spec['results']],
            'param_noundef':[v['noundef'] for v in spec['params']],
            'result_noundef':[v['noundef'] for v in spec['results']], 'variadic':False,'cc':'portable'})
        descriptor=None
        if spec['descriptor_namespace']=='signature':descriptor=some(ref(0))
        if spec['descriptor_namespace']=='nominal':descriptor=some(ref(1))
        roots[6]['imports']=[{'id':0,'kind':'service','namespace':spec['namespace'],'name':spec['name'],
            'version':1,'catalog':'7cbbc87ceb70207fbc59dfe3fa3882d8ea50c8c9d1cf39c585d3b1c8780c15d6',
            'signature':ref(signature),'abi':None,'capability':spec['capability'],'descriptor':descriptor}]
        roots[9]['capabilities']=[spec['capability']]
        cases[spec['name']]=roots
    folder=HERE/'service-fixtures';folder.mkdir(exist_ok=True);manifest={}
    for name,roots in cases.items():
        prepare_declared_abi2_source(roots)
        data=codec.encode(roots);codec.decode(data);write_bytes(folder/(name+'.smo'), data)
        manifest[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
            'capability':roots[6]['imports'][0]['capability']}
    write_text(folder/'manifest.json', json.dumps({'scope':'59 complete static service signature witnesses; no grants/service execution',
        'catalog_sha256':hashlib.sha256(catalog_path.read_bytes()).hexdigest(),'provenance':provenance(__file__, ['crates/smir-portable/tests/metadata/fixtures.py', 'crates/smir-portable/tests/metadata/profile_fixtures.py', 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json', 'docs/specifications/smir/portable/schema/runtime/services-v1.json'], manifest),'cases':manifest},indent=2)+'\n')
    print('service full-root signature witnesses',len(manifest))
if __name__=='__main__':main()
