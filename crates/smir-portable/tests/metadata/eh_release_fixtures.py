#!/usr/bin/env python3
"""Released EH_RELEASE_STATIC_01 static fixtures; no live Ex creation/execution."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
from fixture_provenance import provenance,write_bytes,write_text
from fixtures import CandidateCodec,SCHEMAS,ROOT

ORIGINAL='6caf25c3cb971915edae82da2c7f61a8627397974a9a35243090d80f94e73e0c'


def main():
    here=Path(__file__).resolve().parent;folder=here/'eh-release-fixtures';folder.mkdir(exist_ok=True)
    source=here.parent/'execution/core-cases.json';document=json.loads(source.read_text())
    case=next(c for c in document['cases'] if c['name']=='reject_catch_end_wrong_helper')
    original=bytes.fromhex(case['encoded_hex'])
    # Current independently authored SEM source; ORIGINAL pins the archived
    # historical negative and is never decoded as a current object.
    current_source_sha256=hashlib.sha256(original).hexdigest()
    codec=CandidateCodec(SCHEMAS);base=codec.decode(original).roots
    function=next(f for f in base[3]['functions'] if f['id']==1)
    operation=function['blocks'][0]['ops'][0]
    operation['op']='call';operation['target']=operation.pop('helper');operation['unwind']='propagate';operation['source_plan']=None
    cases={}
    def add(name,roots,expected,code=None,raw=None):
        data=raw if raw is not None else codec.encode(roots);codec.decode(data)
        write_bytes(folder/(name+'.smo'),data)
        cases[name]={'expected_class':expected,'expected_code':code,
            'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    add('ordinary-call-ex-parameter',base,'ok')
    unused=deepcopy(base);unused[3]['functions']=unused[3]['functions'][:1]
    unused[8]['functions']=[f for f in unused[8]['functions'] if f['function']==0]
    add('unused-valid-import',unused,'ok')
    add('original-wrong-catch-helper',None,'semantic','catch_helper',original)
    for name,kind,code in [
        ('signature',0,'RT_HELPER_TYPE'),('noundef',1,'RT_HELPER_NOUNDEF'),
        ('fp-option',2,'RT_HELPER_UNUSED_FP'),('alignment',3,'RT_HELPER_ALIGNMENT'),
        ('unused-abi',4,'RT_HELPER_UNUSED_ABI'),('unused-target',5,'RT_HELPER_UNUSED_TARGET'),
        ('extra-type',6,'RT_HELPER_TYPE_ARITY')]:
        roots=deepcopy(unused);imp=roots[6]['imports'][0]
        signature=next(t for t in roots[1]['types'] if t['id']==imp['signature']['id'])
        if kind==0:signature['params'][0]=next({'module':{'kind':'self'},'id':t['id']}
            for t in roots[1]['types'] if t['kind']=='data_ptr')
        elif kind==1:signature['param_noundef'][0]=True
        elif kind==2:imp['options']['predicate']='oeq'
        elif kind==3:imp['options']['alignment']=0
        elif kind==4:imp['abi']={'some':{'module':{'kind':'self'},'id':1}}
        elif kind==5:imp['options']['target']={'some':{'module':{'kind':'self'},'id':0}}
        else:imp['types']=[{'module':{'kind':'self'},'id':1}]
        add('unused-bad-'+name,roots,'semantic',code)
    roots=deepcopy(unused);imp=roots[6]['imports'][0];imp['name']='eh_retain'
    signature=next(t for t in roots[1]['types'] if t['id']==imp['signature']['id'])
    signature['results']=[deepcopy(signature['params'][0])];signature['result_noundef']=[False]
    add('other-valid-eh-retain',roots,'unavailable-evidence','P2_METADATA_PROFILE_UNAUDITED')
    inputs=['crates/smir-portable/tests/metadata/fixtures.py',str(source.relative_to(ROOT))]
    write_text(folder/'manifest.json',json.dumps({'scope':__doc__,
        'original_sem_negative_sha256':ORIGINAL,'current_sem_negative_sha256':current_source_sha256,'provenance':provenance(__file__,inputs,cases),'cases':cases},indent=2)+'\n')
    print('EH release static witnesses',len(cases),'2positive/8semantic/1unknown')

if __name__=='__main__':main()
