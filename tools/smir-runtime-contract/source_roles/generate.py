#!/usr/bin/env python3
"""Generate actual declared-source INT032 full-root witnesses, never execution."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
SPEC = ROOT/'docs/specifications/smir/portable'
OUTPUT = SPEC/'conformance/runtime/candidate/source-roles/atomic-flag.json'
sys.path.insert(0,str(ROOT/'tools/smir-runtime-contract'))
from generate_service_type_fixtures import complete_identity, prepare_abi2_nonrecord_source, ref
sys.path.insert(0,str(ROOT/'tools/smir-format'))
from codec import CandidateCodec
sys.path.insert(0,str(ROOT/'tools/smir-abi'))
from candidate_fixtures import build


def document():
    baseline=complete_identity()
    source,_=build()
    flag=next(t for t in source['types'] if t['kind']=='atomic_flag')
    flag_layout=next(l for l in source['layouts'] if l['id']==flag['layout']['some'])
    paths=[SPEC/'schema'/name/'candidate.json' for name in ('execution','runtime','abi')]
    codec=CandidateCodec({name:json.loads(path.read_text()) for name,path in zip(('execution','runtime','abi'),paths)})
    catalog_path=SPEC/'schema/runtime/helpers-v1.json';catalog=json.loads(catalog_path.read_text())
    digest=hashlib.sha256(b'SMIR-HELPERS-V1\0'+json.dumps(catalog,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    defaults={'alignment':1,'scope':'process','order':'relaxed','failure_order':'none','weak':False,
        'comparison':'none','mask':'','rounding':'none','exceptions':'none','predicate':'none','target':None,'flags':[]}
    cases=[]
    for name in ('atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear'):
        row=next(r for r in catalog['records'] if r['name']==name)
        for kind in ('int32','unsigned_char_1B','actual_atomic_flag_1B'):
            roots=deepcopy(baseline);selected=1
            if kind!='int32':
                nominal_id=max(t['id'] for t in roots[10]['types'])+1
                layout_id=max(l['id'] for l in roots[10]['layouts'])+1
                if kind=='actual_atomic_flag_1B':
                    nominal=deepcopy(flag);layout=deepcopy(flag_layout)
                    execution=next(t['id'] for t in roots[1]['types'] if t['kind']=='raw' and t['bits']==8)
                else:
                    nominal=deepcopy(roots[10]['types'][0]);layout=deepcopy(roots[10]['layouts'][0])
                    execution=next(t['id'] for t in roots[1]['types'] if t['kind']=='int' and t['bits']==8)
                    nominal.update(bits=8,signed=False);nominal['identity']['entity']='unsigned char'
                nominal.update(id=nominal_id,domain=roots[10]['domains'][0]['id'],
                    execution={'some':ref(execution)},layout={'some':layout_id})
                layout.update(id=layout_id,type=ref(nominal_id),size=1,align=1,data_size=1,nonvirtual_size=1,nonvirtual_align=1)
                roots[10]['types'].append(nominal);roots[10]['layouts'].append(layout);selected=nominal_id
            nextid=max(t['id'] for t in roots[1]['types'])+1
            roots[1]['types'].append({'id':nextid,'kind':'int','bits':1})
            integer32=next(t['id'] for t in roots[1]['types'] if t['kind']=='int' and t['bits']==32)
            pointer=next(t['id'] for t in roots[1]['types'] if t['kind']=='data_ptr')
            ids={'i1':nextid,'u32':integer32,'data_ptr':pointer}
            signature={'id':nextid+1,'kind':'function','variadic':False,'cc':'portable'}
            for side,attributes in [('params','param_noundef'),('results','result_noundef')]:
                signature[side]=[ref(ids[f['type']]) for f in row[side]]
                signature[attributes]=[f['noundef'] for f in row[side]]
            roots[1]['types'].append(signature)
            roots[6]['imports']=[{'id':0,'kind':'internal','namespace':row['namespace'],'name':name,
                'version':1,'catalog':digest,'signature':ref(signature['id']),'abi':{'some':ref(selected)},
                'types':[],'contract':'default','options':deepcopy(defaults)}]
            prepare_abi2_nonrecord_source(roots)
            data=codec.encode(roots);decoded=codec.decode(data)
            cases.append({'name':name+'-'+kind,'source_role_accept':kind=='actual_atomic_flag_1B',
                'source_kind':kind,'sha256':hashlib.sha256(data).hexdigest(),
                'content_identity':decoded.content_digest,'encoded_hex':data.hex()})
    inputs=[ROOT/'tools/smir-runtime-contract/generate_service_type_fixtures.py',ROOT/'tools/smir-format/codec.py',
        SPEC/'conformance/execution/candidate/portable-identity.json',catalog_path,*paths,
        *[ROOT/'tools/smir-abi'/name for name in ('candidate_fixtures.py','nominal.py','layout.py','graph_identity.py','site_config.py')]]
    return {'interface':'INT032/ABI030REV6; localR008REV2model not shared wiring',
        'scope':'Nine complete source objects; actual ABI/execution admission followed by local role predicate; helper imports unused; no execution or factory proof.',
        'provenance':{'generator':str(Path(__file__).relative_to(ROOT)),
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'input_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs)},
            'encoded_object_bytes':sum(len(bytes.fromhex(c['encoded_hex'])) for c in cases),
            'size_justification':'Three helpers times int32, same-size unsignedchar and actual atomicflag isolate nominal purpose from physical bytecount. Full ten-root records permit independent real ABI/type checks.',
            'check_command':'python3 -B tools/smir-runtime-contract/source_roles/generate.py --check'},'cases':cases}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    data=(json.dumps(document(),indent=2)+'\n').encode()
    if args.check:
        if OUTPUT.read_bytes()!=data:raise SystemExit('stale INT032 source-role corpus')
    else:
        OUTPUT.parent.mkdir(exist_ok=True,parents=True);OUTPUT.write_bytes(data)
    print(('checked' if args.check else 'generated')+' source-role flags9 bytes='+str(len(data)))

if __name__=='__main__':main()
