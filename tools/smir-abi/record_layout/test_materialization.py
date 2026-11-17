"""Genuine prepared SourceData probes, isolated from historical candidate.py.

Each test invokes a fresh execution-package worker. No module eviction, fake
LocalSourceData, substituted successful factory or private runtime facts.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[3]
CASES=('scalar','phase_independent','record','bool','bitint','pointer_null','data_leaf','code_leaf',
       'wrong_target','missing_target','wrong_namespace','wrong_width','overlap','placeholder',
       'originless','reference_null','constant','bad_constant','partial','integer_precision',
       'huge_tail','alignment','missing_source','wrong_budget','wrong_stamp','graph_mismatch',
       'graph_indexes','family','dependency_type','dependency_source','mutation','quota','expectations',
       'poison_outside','undef_outside','mutable','undef_tail','fake_callback','strict_expectation',
       'bool_bitfield','partial_then_malformed','constant_then_malformed','image_bound','zero_size','field_alias','nullptr_type',
       'constant_derived_indexes','integer_bitfield_scope','integer_float_bits','comparator_bound')


def worker(name):
    from copy import deepcopy
    import importlib.util
    from unittest.mock import patch
    abi=ROOT/'tools/smir-abi';sys.path.insert(0,str(abi))
    from record_layout import materialization as M
    from function_address.fixtures import source_only,ordinary,seal,source,layout
    from nominal import NominalGraph,ref,some
    spec=importlib.util.spec_from_file_location('_materialization_abi_contract',abi/'candidate.py')
    contract=importlib.util.module_from_spec(spec);sys.modules[spec.name]=contract;spec.loader.exec_module(contract)
    sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
    from candidate.context import RootContext
    from candidate.source_data_projection import source_api

    def need(value,detail):
        if not value:raise AssertionError(detail)

    def reject(code,call):
        try:call()
        except Exception as error:
            actual=getattr(error,'code',str(error));need(actual==code,(code,type(error).__name__,actual));return
        raise AssertionError('unexpected success '+code)

    def budget():
        return source_api().SourceQueryBudget(max_work=10**10,max_edges=10**9,
            max_copied_bytes=10**9,max_depth=128)

    def roots(raw=b'\x2a\0\0\0',zero=0,align=8,complete=False):
        r=ordinary(complete_record=True) if complete else source_only();size=len(raw)+zero
        r[1]['types'].append(dict(id=330,kind='array',element=ref(9),count=size))
        r[4]['segments'].append(dict(id=331,layout=None,nominal=None,abi_binding=None,alignment=align,
            mutable=False,initial=raw.hex(),poison='00'*len(raw),undef='00'*len(raw),zero_fill=zero,zero_shadow='defined'))
        r[2]['symbols'].append(dict(id=330,namespace='example',name='materialization',kind='data',source_linkage='none',
            binding='global',visibility='default',execution=ref(330),nominal=None,abi_signature=None,
            definition=some(dict(kind='data',segment=331)),size=some(size),alignment=align,comdat=None,fallback=None))
        return seal(r)

    def unavailable(reference):raise ValueError('native evidence unavailable')

    def prepared(r,verify=True):
        seal(r);owner=RootContext(r)
        if verify:owner.verify_abi()
        key=owner.sections[2]['manifest']['key'];family=key['namespace'],key['name'],key['abi_major']
        module=family[0]+':'+family[1]+':'+str(family[2]);b=budget();stamp=owner.prepare_source_data(budget=b)
        c=contract.Context(module,owner.abi_execution,owner.symbol,owner.metadata,{}, {},unavailable,unavailable,
            {module:family},owner.memory_layout,source_data=owner.source_data,source_stamp=stamp,source_budget=b)
        graph=owner.abi_graph if verify else NominalGraph(owner.sections[10],module,families={module:family})
        return owner,graph,c,b

    def read(r,typ=1,offset=0,verify=True):
        owner,g,c,b=prepared(r,verify);return M.read_materialization(g,c,ref(typ),ref(330),offset,budget=b)

    def scalar(r,identifier,entity,bits,size,align,kind='scalar'):
        r[1]['types'].append(dict(id=identifier+1000,kind='int',bits=bits))
        r[10]['types'].append(source(identifier,kind,bits=bits,execution=identifier+1000,layout_id=identifier,
            representation='value',flags=['complete','trivial_copy','trivial_destroy'],entity=entity))
        r[10]['layouts'].append(layout(identifier,size,align))

    def leaf(r,kind='data_address',target=330,at=0,width=8,precision=0):
        row=dict(source_kind='data',source=331,offset=at,width=width,integer_bits=precision,kind=kind,
            target=ref(target),addend=0,derivation=[],check_base=False,flags=[],inrange=None)
        r[5]['relocations'].append(row);return row

    def constant(r,bad=False):
        r[1]['types'].append(dict(id=1800,kind='function',cc='portable',variadic=False,params=[],
            results=[ref(17)],param_noundef=[],result_noundef=[bad]))
        r[3]['functions'].append(dict(id=1800,signature=ref(1800),abi_signature=None,params=[],entry=0,
            escape='propagate',no_return=False,blocks=[dict(id=0,phis=[],ops=[dict(op='constant',
            results=[dict(id=0,type=ref(17))],operands=[],literal=dict(kind='bits',value='00000000'))],
            term=dict(op='return',values=[0]))]))
        r[5]['constant_initializers'].append(dict(id=0,source_kind='data',source=331,offset=0,
            layout=ref(0),function=ref(1800),association=None))

    if name in ('scalar','phase_independent'):
        owner,g,c,b=prepared(roots(),name!='phase_independent');image=M.read_materialization(g,c,ref(1),ref(330),budget=b)
        need(image.pre_relocation_bytes==bytes.fromhex('2a000000') and image.value_mask==b'\xff'*4,'bytes/mask')
        need(image.symbol==('self',330) and image.storage==('self',331) and image.stamp is c.source_stamp,'original identities')
        need(image.state=='ready' and image.production_admitted is False,'source data only')
        if name=='phase_independent':need(owner.abi_checked is False,'ABI prerequisite cycle')
    elif name=='record':
        image=read(roots(complete=True),100);need(image.value_mask==b'\xff'*4,'selected POD layout')
    elif name=='bool':
        r=roots(b'\x02');scalar(r,700,'bool',1,1,1);reject('ABI_MAT_BOOL_REPRESENTATION',lambda:read(r,700))
    elif name=='bitint':
        r=roots(b'\xff'*16);scalar(r,700,'bitint',65,16,8,'bitint');image=read(r,700)
        need(image.pre_relocation_bytes==b'\xff'*16 and image.value_mask==b'\xff'*8+b'\1'+bytes(7),'padding')
    elif name=='pointer_null':need(read(roots(bytes(8)),102).state=='ready','null representation')
    elif name in ('data_leaf','code_leaf'):
        r=roots(bytes(8));code=name=='code_leaf';row=leaf(r,'code_address' if code else 'data_address',0 if code else 330)
        owner,g,c,b=prepared(r);image=M.check_materialization(g,c,ref(104 if code else 102),ref(330),bytes(8),(row,),budget=b)
        need(image.state=='deferred' and image.declared_leaves[0].source==('self',331) and
             image.production_admitted is False,'symbolic original leaf only')
    elif name in ('wrong_target','missing_target','wrong_namespace'):
        r=roots(bytes(8));leaf(r,'code_address',330 if name=='wrong_target' else 12 if name=='wrong_namespace' else 999)
        reject('ABI_MAT_PATCH_TARGET',lambda:read(r,104))
    elif name=='wrong_width':
        r=roots(bytes(8));leaf(r,'code_address',0,width=4);reject('ABI_MAT_CODE_RELOCATION',lambda:read(r,104))
    elif name=='overlap':
        r=roots(bytes(8));leaf(r);leaf(r);reject('ABI_MAT_PATCH_OVERLAP',lambda:read(r,102))
    elif name=='placeholder':
        r=roots(b'\1'+bytes(7));leaf(r);reject('ABI_MAT_PATCH_PLACEHOLDER',lambda:read(r,102))
    elif name=='originless':reject('ABI_MAT_POINTER_ORIGIN_UNAVAILABLE',lambda:read(roots(b'\1'+bytes(7)),102))
    elif name=='reference_null':
        r=roots(bytes(8));r[10]['types'].append(source(700,'reference',elements=[100],bits=64,execution=1002,
            layout_id=700,representation='value',flags=['complete','trivial_copy','trivial_destroy','lvalue_ref']))
        r[10]['layouts'].append(layout(700,8,8));reject('ABI_MAT_NULL_REFERENCE',lambda:read(r,700))
    elif name in ('constant','bad_constant'):
        r=roots(bytes(8));constant(r,name=='bad_constant')
        reject('RT_INITIALIZER_SIGNATURE' if name=='bad_constant' else 'ABI_MAT_CONSTANT_CONTENT_UNAVAILABLE',lambda:read(r))
    elif name=='partial':
        r=roots(bytes(16));leaf(r);reject('ABI_MAT_PARTIAL_PATCH_UNAVAILABLE',lambda:read(r,1,4))
    elif name=='integer_precision':
        r=roots(bytes(2));scalar(r,700,'bitint',9,2,2,'bitint');leaf(r,'data_integer',330,width=2,precision=9)
        image=read(r,700);need(image.state=='deferred' and image.value_mask==b'\xff\1','value bits vs storage')
    elif name=='huge_tail':need(read(roots(bytes(8),1<<40),102,1<<40).pre_relocation_bytes==bytes(8),'bounded zero tail')
    elif name=='alignment':reject('ABI_MAT_ALIGNMENT',lambda:read(roots(bytes(12)),102,4))
    elif name in ('missing_source','wrong_budget','wrong_stamp'):
        owner,g,c,b=prepared(roots());args=dict(graph=g,context=c,nominal=ref(1),symbol=ref(330),budget=b)
        if name=='missing_source':c.source_data=None;code='ABI_MAT_SOURCE_UNAVAILABLE'
        elif name=='wrong_budget':args['budget']=budget();code='SOURCE_DATA_CONTEXT'
        else:
            other,_,_,_=prepared(roots());c.source_data=other.source_data;code='SOURCE_DATA_CONTEXT'
        reject(code,lambda:M.read_materialization(**args))
    elif name=='graph_mismatch':
        owner,g,c,b=prepared(roots());raw=deepcopy(g.modules[g.module_id]);raw['layouts'][0]['size']=8
        fake=NominalGraph(raw,g.module_id,families=g.families)
        reject('ABI_MAT_GRAPH_CONTEXT',lambda:M.read_materialization(fake,c,ref(1),ref(330),budget=b))
    elif name=='graph_indexes':
        owner,g,c,b=prepared(roots());g.tables[g.module_id]={};g.layouts[g.module_id]={}
        need(M.read_materialization(g,c,ref(1),ref(330),budget=b).size==4,'untrusted derived indexes')
    elif name=='family':
        owner,g,c,b=prepared(roots());g.families[g.module_id]=('wrong','owner',1)
        reject('ABI_MAT_GRAPH_OWNER',lambda:M.read_materialization(g,c,ref(1),ref(330),budget=b))
    elif name in ('dependency_type','dependency_source'):
        r=roots();source_dep=name=='dependency_source'
        declaration=dict(id=999,kind='symbol' if source_dep else 'nominal',symbol_kind='data' if source_dep else 'none',
            source_linkage='none',namespace='example',name='expected',execution=some(ref(330)) if source_dep else None,
            nominal=None if source_dep else some(ref(1)),abi_signature=None,weak=False)
        r[2]['manifest']['dependencies']=[dict(slot=7,key=dict(namespace='example',name='provider',abi_major=1,abi_minor=0),
            minimum_minor=0,maximum_minor=None,site=r[10]['identity'],declarations=[declaration])]
        owner,g,c,b=prepared(r)
        if source_dep:reject('ABI_MAT_DEPENDENCY_UNAVAILABLE',lambda:M.read_materialization(g,c,ref(1),ref(999,7),budget=b))
        else:
            image=M.read_materialization(g,c,ref(999,7),ref(330),budget=b)
            need(image.nominal==('dependency',7,999),'original consumer expectation')
    elif name=='mutation':
        owner,g,c,b=prepared(roots());original=M._mask
        def mutate(*args):
            result=original(*args);owner.sections[4]['segments'][0]['initial']='00000000';return result
        with patch.object(M,'_mask',side_effect=mutate):
            reject('context_snapshot_changed',lambda:M.read_materialization(g,c,ref(1),ref(330),budget=b))
    elif name=='quota':
        owner,g,c,b=prepared(roots());b.work(b.max_work-b._used_work)
        reject('SOURCE_DATA_RESOURCE',lambda:M.read_materialization(g,c,ref(1),ref(330),budget=b))
    elif name=='expectations':
        owner,g,c,b=prepared(roots());M.check_materialization(g,c,ref(1),ref(330),b'\x2a\0\0\0',budget=b)
        reject('ABI_MAT_BYTES_MISMATCH',lambda:M.check_materialization(g,c,ref(1),ref(330),bytes(4),budget=b))
    elif name in ('poison_outside','undef_outside','mutable','undef_tail'):
        r=roots(bytes(8));segment=r[4]['segments'][0]
        if name=='mutable':segment['mutable']=True
        elif name=='undef_tail':
            r=roots(bytes(4),4);r[4]['segments'][0]['zero_shadow']='undef'
        else:segment['poison' if name=='poison_outside' else 'undef']='00'*7+'01'
        reject('RT_METADATA_INITIALIZED_READONLY',lambda:read(r))
    elif name=='fake_callback':
        owner,g,c,b=prepared(roots())
        def fake(*args,**kwargs):raise AssertionError('untrusted callback invoked')
        c.source_data=fake
        reject('SOURCE_DATA_CONTEXT',lambda:M.read_materialization(g,c,ref(1),ref(330),budget=b))
    elif name=='strict_expectation':
        r=roots(bytes(8));row=leaf(r,'code_address',0);owner,g,c,b=prepared(r)
        for field in ('id','addend'):
            expected=deepcopy(row)
            if field=='id':expected['target']['id']=False
            else:expected['addend']=False
            reject('ABI_MAT_RELOCATION_MISMATCH',lambda:M.check_materialization(
                g,c,ref(104),ref(330),bytes(8),(expected,),budget=b))
    elif name in ('bool_bitfield','integer_bitfield_scope'):
        r=roots(b'\x0f\0\0\0' if name=='bool_bitfield' else bytes(4));scalar(r,700,'bool',1,1,1)
        fields=[dict(name=some(n),type=ref(t),bit_width=some(w),explicit_align=None,
            no_unique_address=False,anonymous=False,access='public') for n,t,w in [('a',700,1),('b',1,3)]]
        t=source(710,'record',execution=1710,layout_id=710,representation='storage',
            flags=['complete','trivial_copy','trivial_destroy'],entity='example.Bits')
        t['record_input']=some(dict(revision=1,kind='struct',explicit_align=None,pod03=True,trivial=True,
            standard_layout=True,polymorphic=False,dynamic=False,empty=False,fields=fields,bases=[]))
        r[10]['types'].append(t);r[1]['types'].append(dict(id=1710,kind='raw',bits=32))
        r[10]['layouts'].append(layout(710,4,4,[dict(declaration_index=i,name=n,type=ref(t),offset_bits=o,
            width_bits=w,flags=['bitfield']) for i,(n,t,o,w) in enumerate([('a',700,0,1),('b',1,1,3)])]))
        if name=='bool_bitfield':need(read(r,710).value_mask==b'\x0f\0\0\0','neighbor bits are not bool padding')
        else:
            leaf(r,'data_integer',330,width=1,precision=1)
            reject('ABI_MAT_BITFIELD_RELOCATION_UNAVAILABLE',lambda:read(r,710))
    elif name in ('partial_then_malformed','constant_then_malformed'):
        r=roots(bytes(24));offset=4 if name=='partial_then_malformed' else 0
        if offset:leaf(r,at=0)
        else:constant(r)
        leaf(r,'code_address',330,at=8)
        r[10]['types'].append(source(700,'array',elements=[1],extent=4,execution=1700,
            layout_id=700,representation='value',flags=['complete','trivial_copy','trivial_destroy']))
        r[1]['types'].append(dict(id=1700,kind='array',element=ref(17),count=4))
        r[10]['layouts'].append(layout(700,16,4))
        reject('ABI_MAT_PATCH_TARGET',lambda:read(r,700,offset))
    elif name in ('image_bound','zero_size'):
        r=roots(bytes(4),2<<20);count=0 if name=='zero_size' else (1<<18)+1
        r[10]['types'].append(source(700,'array',elements=[1],extent=count,execution=1700,
            layout_id=700,representation='value',flags=['complete','trivial_copy','trivial_destroy']))
        r[1]['types'].append(dict(id=1700,kind='array',element=ref(17),count=count))
        r[10]['layouts'].append(layout(700,count*4,4))
        reject('ABI_CC_ARRAY_COUNT' if count==0 else 'SOURCE_DATA_RESOURCE',lambda:read(r,700))
        if count==0:reject('ABI_CC_ARRAY_COUNT',lambda:read(r,700,verify=False))
    elif name=='field_alias':
        r=roots(complete=True)
        t=deepcopy(next(t for t in r[10]['types'] if t['id']==1));t.update(id=701,layout=some(701))
        l=deepcopy(next(l for l in r[10]['layouts'] if l['id']==1));l.update(id=701,type=ref(701))
        r[10]['types'].append(t);r[10]['layouts'].append(l)
        next(l for l in r[10]['layouts'] if l['id']==100)['fields'][0]['type']=ref(701)
        need(read(r,100).value_mask==b'\xff'*4,'actual distinct compatible field source nodes')
    elif name=='comparator_bound':
        r=roots();t=deepcopy(next(t for t in r[10]['types'] if t['id']==1))
        t.update(id=701,layout=some(701));r[10]['types'].append(t)
        l=deepcopy(next(l for l in r[10]['layouts'] if l['id']==1));l.update(id=701,type=ref(701))
        r[10]['layouts'].append(l)
        t=deepcopy(t);t.update(id=702,layout=some(702),qualifiers=['const']);r[10]['types'].append(t)
        l=deepcopy(l);l.update(id=702,type=ref(702));r[10]['layouts'].append(l)
        owner,g,c,b=prepared(r)
        calls=[];original=NominalGraph.compatible
        def observed(*args,**kwargs):
            calls.append(1);return original(*args,**kwargs)
        with patch.object(NominalGraph,'compatible',observed):
            bound=M._bound_graph(g,c,owner,c.source_stamp,b)
        need(bound.compatible(ref(1),ref(1)) and not calls,'actual-node reflexivity')
        need(bound.compatible(ref(1),ref(701)) and len(calls)==1,'real structural comparator')
        need(not bound.compatible(ref(1),ref(702)) and len(calls)==2,'real source mismatch')
        b.work(b.max_work-b._used_work-32)
        reject('SOURCE_DATA_RESOURCE',lambda:bound.compatible(ref(1),ref(701)))
        need(len(calls)==2,'quota refusal must precede original comparator')
    elif name=='nullptr_type':
        def value(raw):
            r=roots(raw);r[1]['types'].append(dict(id=1700,kind='data_ptr',space='guest_data'))
            r[10]['types'].append(source(700,'scalar',bits=64,execution=1700,layout_id=700,
                representation='value',flags=['complete','trivial_copy','trivial_destroy'],entity='nullptr_t'))
            r[10]['layouts'].append(layout(700,8,8));return r
        need(read(value(bytes(8)),700).state=='ready','nullptr_t null representation')
        reject('ABI_MAT_NULLPTR_REPRESENTATION',lambda:read(value(b'\1'+bytes(7)),700))
    elif name=='constant_derived_indexes':
        from types import SimpleNamespace
        r=roots(bytes(8));constant(r,True);owner,g,c,b=prepared(r)
        def forged(*args):raise AssertionError('caller-derived constant resolver used')
        owner.function=forged;owner.types=SimpleNamespace(get=forged,equal=forged)
        owner.layouts=SimpleNamespace(get=forged)
        reject('RT_INITIALIZER_SIGNATURE',lambda:M.read_materialization(g,c,ref(1),ref(330),budget=b))
    elif name=='integer_float_bits':
        r=roots(bytes(4));r[1]['types'].append(dict(id=1700,kind='float',format='binary32'))
        r[10]['types'].append(source(700,'scalar',bits=32,execution=1700,layout_id=700,
            representation='value',flags=['complete','trivial_copy','trivial_destroy'],entity='float'))
        r[10]['layouts'].append(layout(700,4,4));leaf(r,'data_integer',330,width=4,precision=32)
        need(read(r,700).state=='deferred','integer leaf retains raw float bits without FP execution')
    else:raise AssertionError(name)
    print(json.dumps(dict(case=name,passed=True)))


class MaterializationTests(unittest.TestCase):pass


def make_test(name):
    def test(self):
        argv=[sys.executable,'-B',str(Path(__file__).resolve()),'--case',name]
        if not __debug__:argv.insert(2,'-O')
        result=subprocess.run(argv,cwd=ROOT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        report=json.loads(result.stdout);self.assertEqual(report['case'],name);self.assertIs(report['passed'],True)
    return test

for _name in CASES:setattr(MaterializationTests,'test_'+_name,make_test(_name))

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--case':worker(sys.argv[2])
    else:unittest.main()
