"""Explicit revision2/3 structural payload/module API. Never executable."""
from copy import deepcopy
from dataclasses import dataclass,field
from types import MappingProxyType
import hashlib,re
from .bindings import check_budget,envelope
from .errors import CarrierError,need
from .ordered import OrderedCodec,Limits
from .source_records import raw_contract,wire_contract
from .references import validate_references
def decode_root3(payload,*,budget):
    check_budget(budget);need(type(payload)is bytes and len(payload)>=4,'V3_REVISION_TRUNCATED')
    budget.charge(work=4,copied_bytes=4);revision=int.from_bytes(payload[:4],'little');need(revision in(2,3),'V3_REVISION')
    codec=OrderedCodec(budget);name='execution_functions'if revision==2 else'execution_functions_v3'
    root=codec.decode(name,payload)
    if revision==3:raw_contract(root['source_contract'],budget=budget)
    validate_references(root,budget=budget)
    return root

def encode_root3(root,*,budget):
    check_budget(budget);need(type(root)is dict and type(root.get('payload_revision'))is int,'V3_REVISION');revision=root['payload_revision'];need(revision in(2,3),'V3_REVISION')
    if revision==3:raw_contract(root['source_contract'],budget=budget)
    return OrderedCodec(budget).encode('execution_functions'if revision==2 else'execution_functions_v3',root)

@dataclass(frozen=True)
class StructuralModule:
    roots:dict
    envelope:dict
    digest:str
    binding:str=field(default='unbound',init=False)
    executable:bool=field(default=False,init=False)
    semantic_admission:bool=field(default=False,init=False)
    active_v3_verified:bool=field(default=False,init=False)

ROOT_NAMES=MappingProxyType(dict(envelope.CandidateCodec.ROOTS))
REVISIONS=MappingProxyType(dict(envelope.CandidateCodec.PAYLOAD_REVISIONS))

def module_digest(payloads):
    need(len(payloads[2])>=36,'V3_MANIFEST')
    normalized=payloads[2][:4]+bytes(32)+payloads[2][36:]
    digest=hashlib.sha256(b'SMIR0.2\0'+(2).to_bytes(4,'little'))
    for identifier in ROOT_NAMES:
        raw=normalized if identifier==2 else payloads[identifier]
        digest.update(identifier.to_bytes(2,'little'));digest.update(len(raw).to_bytes(8,'little'));digest.update(raw)
    return digest.hexdigest()

def encode_module(roots,*,budget,kind=1,entry=0xffffffff,metadata=()):
    check_budget(budget);need(type(roots)is dict and len(roots)==10 and set(roots)==set(ROOT_NAMES),'V3_ROOTS')
    need(type(metadata)in(list,tuple)and len(metadata)<=1014,'V3_METADATA')
    budget.charge(work=8*(len(metadata)+1)*(len(metadata)+1).bit_length(),edges=len(metadata),copied_bytes=256*(len(metadata)+1))
    clean_metadata=[]
    for row in metadata:
        need(type(row)is dict and len(row)==3 and set(row)=={'kind','required','hex'},'V3_METADATA')
        need(type(row['kind'])is int and 0x8000<=row['kind']<=0xffff and row['required']is False and type(row['hex'])is str,'V3_METADATA')
        length=len(row['hex']);need(length%2==0 and length//2<=16*1024*1024,'V3_RESOURCE')
        budget.charge(work=8*(length+1),copied_bytes=128)
        need(re.fullmatch('(?:[0-9a-f]{2})*',row['hex'],re.ASCII)is not None,'V3_HEX');clean_metadata.append(dict(row))
    clean_metadata.sort(key=lambda r:r['kind'])
    need(all(clean_metadata[i-1]['kind']<clean_metadata[i]['kind']for i in range(1,len(clean_metadata))),'V3_METADATA')
    codec=OrderedCodec(budget);payloads={};total=0
    for identifier,name in ROOT_NAMES.items():
        if identifier==3:payloads[identifier]=encode_root3(roots[identifier],budget=budget)
        else:
            need(roots[identifier]['payload_revision']==REVISIONS[identifier],'V3_REVISION')
            payloads[identifier]=codec.encode(name,roots[identifier])
        total+=len(payloads[identifier]);need(total<=16*1024*1024,'V3_RESOURCE')
    cursor=48+24*(10+len(clean_metadata))
    for length in [len(p)for p in payloads.values()]+[len(r['hex'])//2 for r in clean_metadata]:cursor=(cursor+7)//8*8+length
    need(cursor<=16*1024*1024,'V3_RESOURCE');budget.charge(work=16*(cursor+1),copied_bytes=32*(cursor+1))
    budget.charge(work=8*sum(map(len,payloads.values())),copied_bytes=8*sum(map(len,payloads.values())))
    digest=module_digest(payloads);symbols=deepcopy(roots[2]);symbols['manifest']['identity']=digest;payloads[2]=codec.encode(ROOT_NAMES[2],symbols)
    sections=[dict(kind=i,required=True,hex=p.hex())for i,p in payloads.items()]
    sections.extend(clean_metadata)
    return envelope.encode_candidate(dict(kind=kind,entry=entry,sections=sections))

def decode_module(raw,*,budget):
    check_budget(budget);need(type(raw)is bytes and len(raw)<=16*1024*1024,'V3_RESOURCE')
    budget.charge(work=16*(len(raw)+1),edges=len(raw)+1,copied_bytes=32*(len(raw)+1));frame=envelope.decode_candidate(raw,max_bytes=16*1024*1024)
    roots={};payloads={};codec=OrderedCodec(budget)
    for section in frame['sections']:
        identifier=section['kind']
        if identifier not in ROOT_NAMES:continue
        payload=bytes.fromhex(section['hex']);payloads[identifier]=payload
        if identifier==3:roots[identifier]=decode_root3(payload,budget=budget)
        else:
            need(len(payload)>=4 and int.from_bytes(payload[:4],'little')==REVISIONS[identifier],'V3_REVISION');roots[identifier]=codec.decode(ROOT_NAMES[identifier],payload)
    need(set(roots)==set(ROOT_NAMES),'V3_ROOTS');digest=module_digest(payloads);need(roots[2]['manifest']['identity']==digest,'V3_IDENTITY')
    validate_references(roots[3],budget=budget,roots=roots)
    return StructuralModule(roots,frame,digest)
