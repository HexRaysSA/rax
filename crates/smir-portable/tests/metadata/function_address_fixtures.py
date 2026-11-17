#!/usr/bin/env python3
"""Current static CodeAddress witnesses; encoded records confer no runtime rights."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from fixture_provenance import provenance, write_bytes, write_text
from fixtures import CandidateCodec, SCHEMAS, ref, some, prepare_declared_abi2_source
from profile_fixtures import complete


def base():
    roots = complete('portable-identity')
    roots[1]['types'].append({'id': 900, 'kind': 'code_address'})
    return roots


def address_symbol(roots):
    symbol = deepcopy(roots[2]['symbols'][0])
    symbol.update(id=90, namespace='address', name='unresolved', kind='function_address',
                  execution=ref(900), abi_signature=None, definition=None)
    roots[2]['symbols'].append(symbol)
    return symbol


def stored_address(tls=False):
    roots = complete('storage-tls-wrapper')
    roots[1]['types'].append({'id': 900, 'kind': 'code_address'})
    roots[5]['relocations'] = [{'source_kind': 'data', 'source': 1, 'offset': 0,
        'width': 8, 'integer_bits': 0, 'kind': 'code_address', 'target': ref(0),
        'addend': 0, 'derivation': [], 'check_base': False, 'flags': [], 'inrange': None}]
    if tls:
        segment = deepcopy(roots[4]['segments'][1]); segment['id'] = 1
        roots[7]['segments'].append({'storage': segment, 'initializers': [],
            'destructors': [], 'initialization': 'static'})
        symbol = deepcopy(roots[2]['symbols'][2])
        symbol.update(id=4, kind='tls', name='tls_pointer', definition=some({'kind':'tls','segment':1}))
        roots[2]['symbols'].append(symbol)
        roots[5]['relocations'][0]['source_kind'] = 'tls'
    return roots


def build():
    cases = {}
    def add(name, roots, result='static', code=None):
        cases[name] = (roots, result, code)
    roots = base()
    roots[3]['functions'][0]['blocks'][0]['ops'].append({'op':'constant',
        'results':[{'id':90,'type':ref(900)}], 'operands':[], 'literal':{'kind':'zero'}})
    add('null-code-address', roots)
    add('self-function-address', stored_address())
    roots = complete('service-wrapper'); roots[9]['capabilities'] = ['memory']
    roots[1]['types'].append({'id':900,'kind':'code_address'})
    symbol = deepcopy(roots[2]['symbols'][0]); imported = roots[6]['imports'][0]
    symbol.update(id=90, namespace='address', name='service', kind='import', source_linkage='none',
        nominal=None, abi_signature=None, execution=deepcopy(imported['signature']),
        definition=some({'kind':'import','import':imported['id']}))
    roots[2]['symbols'].append(symbol)
    add('self-import-address', roots, 'unavailable')
    roots = base(); address_symbol(roots)
    add('address-only-declaration', roots)
    roots = deepcopy(roots); roots[2]['manifest']['foreign_isa']='x86_64'
    roots[2]['symbols'][-1]['definition']=some({'kind':'native','image':'aa'*32,
        'domain':0,'offset':0,'size':1})
    add('native-address-conditional', roots, 'semantic', 'RT_NATIVE_PROCESS_ISA')
    roots = base()
    roots[2]['manifest']['dependencies']=[{'slot':7,'key':{'namespace':'address','name':'provider',
        'abi_major':1,'abi_minor':0},'minimum_minor':0,'maximum_minor':None,
        'site':roots[2]['manifest']['site'],'declarations':[{'id':99,'kind':'symbol',
        'symbol_kind':'function_address','source_linkage':'cpp','namespace':'address','name':'entry',
        'execution':some(ref(900)),'nominal':some(ref(12)),'abi_signature':None,'weak':False}]}]
    add('dependency-address-expectation', roots, 'unavailable')
    weak = base(); address_symbol(weak)['binding']='weak'
    add('weak-address-conditional', weak, 'unavailable')
    add('data-address-relocation', stored_address())
    add('tls-address-relocation', stored_address(True), 'unavailable')
    for name, field, value, code in [
        ('wrong-address-execution','execution',ref(12),'RT_SYMBOL_SIGNATURE'),
        ('wrong-source-nominal','nominal',some(ref(1)),'RT_SOURCE_FUNCTION_NOMINAL'),
        ('address-plan-present','abi_signature',some(ref(0)),'RT_FUNCTION_ADDRESS_SHAPE'),
        ('address-size-present','size',some(1),'RT_FUNCTION_ADDRESS_SHAPE'),
        ('address-alias-definition','definition',some({'kind':'alias','target':ref(0)}),'RT_FUNCTION_ADDRESS_DEFINITION'),
        ('address-tls-definition','definition',some({'kind':'tls','segment':0}),'RT_FUNCTION_ADDRESS_DEFINITION'),
        ('address-common-binding','binding','common','RT_FUNCTION_ADDRESS_SHAPE')]:
        roots=base(); address_symbol(roots)[field]=value; add(name,roots,'semantic',code)
    roots=deepcopy(cases['dependency-address-expectation'][0])
    roots[2]['manifest']['dependencies'][0]['declarations'][0]['symbol_kind']='data'
    add('dependency-data-collision',roots,'semantic','RT_SOURCE_FUNCTION_NOMINAL')
    roots=deepcopy(cases['dependency-address-expectation'][0])
    declaration=roots[2]['manifest']['dependencies'][0]['declarations'][0]
    declaration.update(symbol_kind='function',execution=some(ref(12)))
    add('call-expectation-weakened',roots,'semantic','RT_SOURCE_PLAN_PRESENCE')
    for name,field,value,code in [
        ('relocation-width','width',4,'RT_CODE_RELOCATION'),
        ('relocation-integer-bits','integer_bits',64,'RT_RELOCATION_INTEGER_WIDTH'),
        ('relocation-addend','addend',1,'RT_CODE_RELOCATION'),
        ('relocation-flags','flags',['nuw'],'RT_PATCH_UNUSED_POINTER_OPTIONS'),
        ('relocation-target-data','target',ref(1),'RT_RELOCATION_DOMAIN')]:
        roots=stored_address(); roots[5]['relocations'][0][field]=value
        add(name,roots,'semantic',code)
    for name,offset in [('relocation-overlap',0),('relocation-partial',1)]:
        roots=stored_address(); duplicate=deepcopy(roots[5]['relocations'][0]);duplicate['offset']=offset
        if offset:
            # A wider untyped segment isolates overlap from bounds checking.
            segment=roots[4]['segments'][1];segment.update(layout=None,nominal=None,abi_binding=None,
                initial='00'*16,poison='00'*16,undef='00'*16)
            roots[2]['symbols']=roots[2]['symbols'][:2]
        roots[5]['relocations'].append(duplicate);add(name,roots,'semantic','RT_RELOCATION_OVERLAP')
    roots=stored_address()
    # A valid no-argument constant initializer returning the actual storage-array
    # layout value isolates overlap from signature validation.
    roots[1]['types'].append({'id':901,'kind':'function','params':[],
        'results':[ref(305)],'param_noundef':[],'result_noundef':[False],
        'variadic':False,'cc':'portable'})
    roots[3]['functions'].append({'id':91,'signature':ref(901),'abi_signature':None,
        'params':[],'entry':0,'escape':'propagate','no_return':False,
        'blocks':[{'id':0,'phis':[],'ops':[{'op':'constant','results':[{'id':0,'type':ref(305)}],
            'operands':[],'literal':{'kind':'zero'}}], 'term':{'op':'return','values':[0]}}]})
    roots[5]['constant_initializers']=[{'id':0,'source_kind':'data','source':1,'offset':0,
        'layout':ref(8),'function':ref(91),'association':None}]
    add('relocation-constant-overlap',roots,'semantic','RT_INITIALIZER_OVERLAP')
    for name,field,value in [('ordinary-plan-this','this_type',some(ref(1))),
                             ('ordinary-plan-vtt','vtt',True),
                             ('plan-execution-mismatch','execution',ref(13))]:
        roots=base(); roots[10]['signatures'][0][field]=value
        add(name,roots,'semantic',None)
    return cases


def main():
    folder=Path(__file__).resolve().parent/'function-address-fixtures';folder.mkdir(exist_ok=True)
    codec=CandidateCodec(SCHEMAS);cases={}
    for name,(roots,result,code) in build().items():
        prepare_declared_abi2_source(roots)
        data=codec.encode(roots);decoded=codec.decode(data)
        write_bytes(folder/(name+'.smo'),data)
        cases[name]={'expected':result,'code':code,'bytes':len(data),
            'sha256':hashlib.sha256(data).hexdigest(),'content_identity':decoded.content_digest}
    inputs=['crates/smir-portable/tests/metadata/fixtures.py',
        'crates/smir-portable/tests/metadata/profile_fixtures.py',
        *['docs/specifications/smir/portable/conformance/execution/candidate/'+n+'.json'
          for n in ('portable-identity','storage-tls-wrapper','service-wrapper')]]
    write_text(folder/'manifest.json',json.dumps({'scope':__doc__,
        'provenance':provenance(__file__,inputs,cases),'cases':cases},indent=2)+'\n')
    print('function address static witnesses',len(cases))


if __name__=='__main__': main()
