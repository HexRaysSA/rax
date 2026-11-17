#!/usr/bin/env python3
"""Actual ABI039 state bindings with explicitly excluded R005 data symbols."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from fixture_provenance import provenance, write_bytes, write_text
from profile_fixtures import complete
from fixtures import CandidateCodec, SCHEMAS, SPEC, ROOT, ref, some

ABI=ROOT/'tools/smir-abi';sys.path.insert(0,str(ABI))
MODULE='rax_abi_builtin_builder_for_runtime_profile'
spec=importlib.util.spec_from_file_location(MODULE,ABI/'source_roles/builder.py')
builder=importlib.util.module_from_spec(spec);sys.modules[MODULE]=builder;spec.loader.exec_module(builder)
from nominal import NominalGraph


def source_document():
    roots=complete('portable-identity')
    source_next=max([t['id'] for t in roots[10]['types']]+[l['id'] for l in roots[10]['layouts']])+1
    execution_next=max(t['id'] for t in roots[1]['types'])+1
    source_ids={name:source_next+i for i,name in enumerate(('uint32','uint64','va_state','jmp_state','va_list','jmp_buf'))}
    execution_ids={name:execution_next+i for i,name in enumerate(('uint32','uint64','raw8','state_bytes','list_wrapper'))}
    fragments=builder.build_builtin_states(source_ids=source_ids,execution_ids=execution_ids,
        domain_id=roots[10]['domains'][0]['id'])
    if {t['id'] for t in roots[10]['types']} & {t['id'] for t in fragments['types']}:
        raise RuntimeError('source type collision')
    if {l['id'] for l in roots[10]['layouts']} & {l['id'] for l in fragments['layouts']}:
        raise RuntimeError('source layout collision')
    roots[10]['types']+=fragments['types'];roots[10]['layouts']+=fragments['layouts']
    roots[1]['types']+=fragments['execution_graph']
    graph=NominalGraph(roots[10],'runtime-canonical-state-producer')
    for item in roots[10]['types']:
        item['identity']['definition']=graph.fingerprint(ref(item['id'])) if 'complete' in item['flags'] else '00'*32
    memory=max(l['id'] for l in roots[1]['memory_layouts'])+1
    roots[1]['memory_layouts'] += [
        {'id':memory,'type':ref(execution_ids['raw8']),'size':1,'alignment':1,'access_bytes':1,
         'fields':[],'element':None,'stride':0},
        {'id':memory+1,'type':ref(execution_ids['state_bytes']),'size':32,'alignment':8,'access_bytes':32,
         'fields':[],'element':some(ref(memory)),'stride':8}]
    return roots,fragments,execution_ids,memory+1


def main():
    here=Path(__file__).resolve().parent;folder=here/'canonical-profile-fixtures';folder.mkdir(exist_ok=True)
    codec=CandidateCodec(SCHEMAS);manifest={}
    base,names,execution,memory=source_document()
    for name in ('va_state','jmp_state','va_list','jmp_buf'):
        roots=deepcopy(base);nominal=names[name]
        roots[10]['storage_bindings']=[{'id':i,'nominal':nominal,'execution_layout':ref(memory),'kind':kind,
            'view_offset_bits':0,'view_width_bits':256,'required_alignment':8,'access_bytes':32,
            'fragments':[{'source_path':[],'source_offset_bits':0,'execution_offset_bits':0,'width_bits':256,
                          'role':'object_representation' if kind=='allocation' else 'value'}]}
            for i,kind in enumerate(('allocation','object_bytes'))]
        roots[4]['segments']=[{'id':0,'layout':some(ref(memory)),'nominal':some(nominal),'abi_binding':some(ref(0)),
            'alignment':8,'mutable':False,'initial':'00'*32,'poison':'00'*32,'undef':'00'*32,
            'zero_fill':0,'zero_shadow':'defined'}]
        roots[2]['symbols'].append({'id':1,'namespace':'profile','name':name,'kind':'data',
            'source_linkage':'c','binding':'strong','visibility':'default','execution':ref(execution['state_bytes']),
            'nominal':some(nominal),'abi_signature':None,'definition':some({'kind':'data','segment':0}),
            'size':some(32),'alignment':8,'comdat':None,'fallback':None})
        data=codec.encode(roots);codec.decode(data);write_bytes(folder/(name+'.smo'),data)
        manifest[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'source_nominal':nominal['id'],'allocation_binding':0,'object_bytes_binding':1,
            'abi_expected':'ok','metadata_expected':'unavailable-evidence',
            'reason':'R005 finite symbols remain Int32/Pointer4B/8B; ABI039 binding proof is not R005 symbol qualification'}
    inputs=['crates/smir-portable/tests/metadata/fixtures.py','crates/smir-portable/tests/metadata/profile_fixtures.py',
        'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json',
        'tools/smir-abi/source_roles/builder.py']
    write_text(folder/'manifest.json',json.dumps({'scope':__doc__,'provenance':provenance(__file__,inputs,manifest),
        'cases':manifest},indent=2)+'\n')
    print('canonical ABI binding / excluded R005 symbol controls',len(manifest))

if __name__=='__main__':main()
