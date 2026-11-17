"""Independent authored ABI source-program contracts; no runtime issuer mocks."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from . import source_programs as S

ROOT = Path(__file__).resolve().parents[3]


def budget(**changes):
    policy = dict(max_work=10**9, max_edges=10**7, max_copied_bytes=10**9, max_depth=128)
    policy.update(changes); return S._api().SourceQueryBudget(**policy)


def q(identifier, slot=None):
    return dict(module=dict(kind='self') if slot is None else dict(kind='dependency', slot=slot), id=identifier)


def source(identifier, context=0):
    return dict(context=context, nominal=q(identifier))


def traits(**changes):
    t = dict(aggregate=True, abstract=False, final=False, destructor_user_provided=False,
        destructor_trivial=True, destructor_deleted=False, constructors_complete=True,
        pending_default=False, trivial_default=False, nontrivial_default=False,
        pending_copy=False, trivial_copy=False, copy_deleted=False, pending_move=False,
        trivial_move=False, move_deleted=False, implicit_lifetime=True)
    t.update(changes); return t


def record(identifier, name, size=4, nv=4, align=4, **changes):
    r = dict(id=identifier, source=source(100+identifier), name=name, record_kind='struct',
        complete_size=size, nonvirtual_size=nv, alignment=align, nonvirtual_alignment=align,
        traits=traits(), slots=[])
    r.update(changes); return r


def method(identifier, owner, kind='constructor', **changes):
    m = dict(id=identifier, record=owner, declaration_index=identifier, name='A::A' if kind=='constructor' else 'A::~A',
        kind=kind, signature=q(500+identifier), parameters=[], trivial=False, deleted=False,
        eligible=True, user_provided=True, has_definition=True, noexcept=False)
    m.update(changes); return m


def slot(identifier, kind='member', index=0, nominal=1, child=None, offset=0, width=32, destructor=None, **changes):
    row = dict(id=identifier, kind=kind, declaration_index=index, name='value' if kind=='member' else None,
        paths=[[dict(kind='member' if kind=='member' else 'base', declaration_index=index, virtual=kind=='virtual_base')]],
        source=source(nominal), element_kind='record' if child is not None else 'scalar', element_record=child,
        array_extents=[], offset_bits=offset, width_bits=width, alignment=4,
        destruction='none' if destructor is None else 'complete' if kind=='member' else 'base', destructor=destructor)
    row.update(changes); return row


def cleanup(identifier, owner, slots=(), view='complete', destructor=None):
    return dict(id=identifier, record=owner, view=view, journal_program=q(700+identifier),
        signature=q(201), slots=list(slots), destructor=destructor)


def program(identifier, owner=0, variant='aggregate_init', cleanup_id=0, method_id=None, steps=(), **changes):
    p = dict(id=identifier, record=owner, variant=variant, method=method_id, cleanup=cleanup_id,
        implementation=None, delegate=None, union_selection=None, steps=list(steps))
    p.update(changes); return p


def document():
    return dict(format='draft-abi-source-programs', revision=2, binding='unbound', runtime_authority=False,
        source_fact_authority=False, trait_oracle=dict(llvm_revision='36763294ef639d8a6a4379d81da653dda1c20686',
        sema_sha256='c4e6787950457657419ae2bcc030a9b817e000f298cec82dddd216490a7ac452'),
        contexts=[dict(id=0, family=dict(namespace='example', name='source', abi_major=1), abi_site='00'*32,
                      abi_root='00'*32, module_root='00'*32)],
        records=[record(0,'A',slots=[slot(0)])], methods=[], cleanups=[cleanup(0,0,[0])],
        programs=[program(0,steps=[0])], array_progress=[], implicit_selections=[], ast_bindings=[])


def classes():
    d=document(); nonimplicit=traits(aggregate=False, destructor_user_provided=True,
        destructor_trivial=False, implicit_lifetime=False)
    d['records']=[record(0,'A',16,12,8,traits=deepcopy(nonimplicit),slots=[
        slot(0,'virtual_base',0,101,1,96,32,20),slot(1,index=0),
        slot(2,index=1,nominal=102,child=2,offset=32,destructor=22,name='member'),
        slot(3,'nonvirtual_base',1,103,3,64,32)]),
        record(1,'V',traits=deepcopy(nonimplicit)),record(2,'M',traits=deepcopy(nonimplicit)),record(3,'N')]
    d['methods']=[method(0,0),method(1,0,parameters=[source(1)]),method(2,0,'destructor'),
                  method(20,1,'destructor',name='V::~V'),method(22,2,'destructor',name='M::~M')]
    d['cleanups']=[cleanup(0,0,[0,3,1,2],destructor=2),cleanup(1,0,[3,1,2],'nonvirtual',2)]
    d['programs']=[program(0,variant='complete_constructor',method_id=0,steps=[0,3,1,2]),
        program(1,variant='base_constructor',cleanup_id=1,method_id=0,steps=[3,1,2]),
        program(2,variant='complete_destructor',method_id=2,steps=[2,1,3,0]),
        program(3,variant='base_destructor',cleanup_id=1,method_id=2,steps=[2,1,3]),
        program(4,variant='complete_constructor',method_id=1,delegate=dict(target=0,owner_relation='distinct_program',
            cell_map=[dict(child=i,parent=i) for i in (0,3,1,2)])),
        program(5,variant='deleting_destructor',method_id=2,delegate=dict(target=2,owner_relation='distinct_program',
            cell_map=[dict(child=i,parent=i) for i in (0,3,1,2)]))]
    return d


class SourcePrograms(unittest.TestCase):
    def rejected(self,code,document,kind='semantic',policy=None):
        with self.assertRaises(S._api().SourceDataError) as caught:
            S.verify(document,budget=policy or budget())
        self.assertEqual((caught.exception.code,caught.exception.kind),(code,kind))

    def test_actual_budget_and_unbound_frozen_result(self):
        result=S.verify(document(),budget=budget());self.assertEqual(result.coverage,((0,(0,)),))
        self.assertFalse(result.runtime_authority);self.assertFalse(result.source_fact_authority)
        with self.assertRaises(AttributeError):result.binding='bound'
        with self.assertRaises(TypeError):S.SourceProgramObligations('x',(),(),(),(),runtime_authority=True)

    def test_local_revision_migration_has_no_unit_fallback(self):
        d=document();self.assertEqual(d['revision'],2)
        old=deepcopy(d);old['revision']=1;old['contexts'][0]['unit']=old['contexts'][0].pop('abi_site')
        self.rejected('ABI_SP_SHAPE',old)
        old=deepcopy(d);old['contexts'][0]['unit']=old['contexts'][0].pop('abi_site')
        self.rejected('ABI_SP_SHAPE',old)

    def test_complete_nonvirtual_and_distinct_programs(self):
        result=S.verify(classes(),budget=budget());self.assertEqual(dict(result.coverage),{0:(0,3,1,2),1:(3,1,2)})
        self.assertEqual(len([x for x in result.obligations if x[0]=='actual_source_body_frontiers_per_program_view']),6)

    def test_same_offset_distinct_source_cells(self):
        d=document();d['records'][0]['slots'].append(slot(1,index=1,name='other'));d['cleanups'][0]['slots']=[0,1];d['programs'][0]['steps']=[0,1]
        self.assertEqual(dict(S.verify(d,budget=budget()).coverage)[0],(0,1))

    def test_symbolic_array_progress(self):
        d=document();r=d['records'][0];r.update(complete_size=1<<40,nonvirtual_size=1<<40)
        r['slots'][0].update(array_extents=[1<<38],width_bits=1<<43)
        d['array_progress']=[dict(program=0,slot=0,phase='construction',completed=(1<<38)-1,pending=(1<<38)-1)]
        result=S.verify(d,budget=budget(max_work=1000000));self.assertEqual(result.array_progress[0][2],1<<38)
        self.assertEqual(len(result.array_progress),1)

    def test_implicit_array_does_not_create_ineligible_element(self):
        d=document();bad=record(1,'M',traits=traits(aggregate=False,destructor_user_provided=True,
            destructor_trivial=False,implicit_lifetime=False))
        d['records'].append(bad);d['methods'].append(method(1,1,'destructor',name='M::~M'))
        d['records'][0].update(complete_size=8,nonvirtual_size=8)
        d['records'][0]['slots']=[slot(0,nominal=800,child=1,array_extents=[2],width=64,destructor=1)]
        d['programs'][0]['variant']='implicit_lifetime'
        patterns=S.verify(d,budget=budget()).implicit_patterns
        self.assertEqual([(p[3],p[4]) for p in patterns],[('record',0),('array',None)])

    def test_implicit_noneligible_member_absent(self):
        d=classes();d['records'][0]['traits']=traits();d['records'][0]['slots']=[d['records'][0]['slots'][2]]
        d['methods']=[m for m in d['methods'] if m['record']!=0];d['cleanups']=[cleanup(0,0,[2])]
        d['programs']=[program(0,variant='implicit_lifetime',steps=[2])]
        self.assertEqual(len(S.verify(d,budget=budget()).implicit_patterns),1)

    def test_pending_constructor_trait_branches(self):
        for branch in ('default','copy','move'):
            with self.subTest(branch=branch):
                d=document();t=traits(aggregate=False);t['pending_'+branch]=True;t['trivial_'+branch]=True
                d['records'][0]['traits']=t;d['programs'][0]['variant']='implicit_lifetime'
                self.assertTrue(S.verify(d,budget=budget()).implicit_patterns)

    def test_trivial_source_constructor_without_function(self):
        d=document();d['methods']=[method(0,0,trivial=True,user_provided=False,has_definition=False)]
        d['programs'][0].update(variant='trivial_init',method=0)
        self.assertEqual(len(S.verify(d,budget=budget()).coverage),1)

    def test_union_explicit_uniform_pattern(self):
        d=document();d['records'][0]['record_kind']='union';d['cleanups'][0]['slots']=[]
        d['programs'][0].update(variant='implicit_lifetime',steps=[0],union_selection=0)
        d['implicit_selections']=[dict(program=0,path=[],selected_member=0,scope='uniform_source_pattern')]
        self.assertEqual([p[3] for p in S.verify(d,budget=budget()).implicit_patterns],['record','scalar'])
        d['implicit_selections'][0]['selected_member']=None
        d['programs'][0].update(steps=[],union_selection=None)
        self.assertEqual(len(S.verify(d,budget=budget()).implicit_patterns),1)

    def test_missing_union_selection_unavailable(self):
        d=document();d['records'][0]['record_kind']='union';d['cleanups'][0]['slots']=[]
        d['programs'][0].update(variant='implicit_lifetime',steps=[])
        self.rejected('ABI_SP_UNION_SELECTION_UNAVAILABLE',d,'unavailable')

    def test_malformed_precedes_missing_union_selection(self):
        d=document();d['records'][0]['record_kind']='union';d['cleanups'][0]['slots']=[]
        d['programs'][0].update(variant='implicit_lifetime',steps=[])
        d['array_progress']=[dict(program=99,slot=0,phase='construction',completed=0,pending=None)]
        self.rejected('ABI_SP_PROGRAM_REFERENCE',d)

    def test_zero_nonvirtual_explicit_unavailable(self):
        d=document();d['records'][0].update(nonvirtual_size=0,slots=[]);d['cleanups']=[cleanup(0,0,[],view='nonvirtual')]
        d['methods']=[method(0,0)];d['programs']=[program(0,variant='base_constructor',method_id=0)]
        self.rejected('ABI_CC_CPP_ZERO_NV_VIEW',d,'unavailable')

    def test_cumulative_quota_and_depth(self):
        b=budget(max_work=0);self.rejected('SOURCE_DATA_RESOURCE',document(),'resource',b)
        self.rejected('SOURCE_DATA_RESOURCE',document(),'resource',budget(max_depth=2))
        b=budget();S.verify(document(),budget=b);used=b._used_work;S.verify(document(),budget=b)
        self.assertGreater(b._used_work,used)

    def test_array_progress_phase_boundaries(self):
        for phase,completed,pending,valid in [('construction',0,0,True),('construction',3,None,True),
                ('construction',3,3,False),('cleanup',3,2,True),('cleanup',2,1,True),
                ('cleanup',0,None,True),('cleanup',0,0,False),('cleanup',2,2,False)]:
            d=document();d['records'][0].update(complete_size=12,nonvirtual_size=12)
            d['records'][0]['slots'][0].update(array_extents=[3],width_bits=96)
            d['array_progress']=[dict(program=0,slot=0,phase=phase,completed=completed,pending=pending)]
            with self.subTest(phase=phase,completed=completed,pending=pending):
                if valid:self.assertEqual(len(S.verify(d,budget=budget()).array_progress),1)
                else:self.rejected('ABI_SP_ARRAY_PROGRESS',d)

    def test_nontrivial_missing_definition_unavailable(self):
        d=classes();d['methods'][0]['has_definition']=False
        self.rejected('ABI_SP_METHOD_DEFINITION_UNAVAILABLE',d,'unavailable')

    def test_portable_explicit_alignment_boundary(self):
        d=document();d['records'][0].update(complete_size=65536,nonvirtual_size=65536,
            alignment=65536,nonvirtual_alignment=65536)
        self.assertEqual(len(S.verify(d,budget=budget()).coverage),1)
        d['records'][0].update(complete_size=131072,nonvirtual_size=131072,
            alignment=131072,nonvirtual_alignment=131072)
        self.rejected('ABI_SP_ALIGNMENT',d)

    def test_portable_symbolic_object_extent_boundary(self):
        for extent in (1<<49,(1<<61)-4):
            d=document();d['records'][0].update(complete_size=extent,nonvirtual_size=extent)
            with self.subTest(extent=extent):
                self.assertEqual(len(S.verify(d,budget=budget(max_work=1000000,max_copied_bytes=1000000)).coverage),1)
        d['records'][0].update(complete_size=1<<61,nonvirtual_size=1<<61)
        self.rejected('ABI_SP_GEOMETRY',d)
        d=document();d['records'][0]['slots'][0].update(offset_bits=(1<<64)-1,width_bits=32)
        self.rejected('ABI_SP_GEOMETRY',d)

    def test_noncanonical_ledger_rejected(self):
        self.rejected('ABI_SP_BUDGET',document(),policy=object())


NEGATIVES={
 'bool_id':('ABI_SP_SHAPE',lambda d:d['records'][0].update(id=True)),
 'unknown_field':('ABI_SP_SHAPE',lambda d:d['records'][0].update(unrecognized=0)),
 'authority':('ABI_SP_SHAPE',lambda d:d.update(runtime_authority=True)),
 'reserved_id':('ABI_SP_SHAPE',lambda d:d['programs'][0].update(id=0xffffffff)),
 'wrong_context':('ABI_SP_SOURCE_CONTEXT',lambda d:d['records'][0]['source'].update(context=1)),
 'duplicate_record':('ABI_SP_DUPLICATE_ID',lambda d:d['records'].append(deepcopy(d['records'][0]))),
 'negative_id':('ABI_SP_SHAPE',lambda d:d['programs'][0].update(id=-1)),
 'float_geometry':('ABI_SP_SHAPE',lambda d:d['records'][0].update(complete_size=4.0)),
 'wrong_geometry':('ABI_SP_GEOMETRY',lambda d:d['records'][0]['slots'][0].update(offset_bits=32)),
 'alignment':('ABI_SP_ALIGNMENT',lambda d:d['records'][0].update(alignment=3)),
 'array_zero':('ABI_SP_SHAPE',lambda d:d['records'][0]['slots'][0].update(array_extents=[0])),
 'array_overflow':('ABI_SP_ARRAY_OVERFLOW',lambda d:d['records'][0]['slots'][0].update(array_extents=[1<<63,3])),
 'array_width':('ABI_SP_ARRAY_GEOMETRY',lambda d:d['records'][0]['slots'][0].update(array_extents=[3])),
 'implicit_lie':('ABI_SP_IMPLICIT_TRAIT',lambda d:d['records'][0]['traits'].update(implicit_lifetime=False)),
 'incomplete_constructors':('ABI_SP_SHAPE',lambda d:d['records'][0]['traits'].update(constructors_complete=False)),
 'step_order':('ABI_SP_STEP_ORDER',lambda d:d['programs'][0].update(steps=[])),
 'coverage':('ABI_SP_COVERAGE',lambda d:d['cleanups'][0].update(slots=[])),
 'source_path':('ABI_SP_SOURCE_PATH',lambda d:d['records'][0]['slots'][0].update(paths=[])),
 'wrong_path':('ABI_SP_SOURCE_PATH',lambda d:d['records'][0]['slots'][0]['paths'][0][0].update(declaration_index=7)),
 'wrong_element_kind':('ABI_SP_ELEMENT_KIND',lambda d:d['records'][0]['slots'][0].update(element_kind='record')),
 'constructorless':('ABI_SP_CONSTRUCTORLESS',lambda d:d['programs'][0].update(method=33)),
 'union_selection':('ABI_SP_UNION_SELECTION',lambda d:d['programs'][0].update(union_selection=0)),
 'progress_nonarray':('ABI_SP_PROGRESS_ARRAY',lambda d:d['array_progress'].append(dict(program=0,slot=0,phase='construction',completed=0,pending=None))),
 'wrong_owner_relation':('ABI_SP_SHAPE',lambda d:d['programs'][0].update(delegate=dict(target=0,owner_relation='same_journal',cell_map=[]))),
 'wrong_implementation':('ABI_SP_IMPLEMENTATION',lambda d:d['programs'][0].update(implementation=dict(function=q(0),call_signature=q(0),execution=q(0),uses_vtt=False))),
}


def negative_test(code,mutation):
    def run(self):
        d=document();mutation(d);self.rejected(code,d)
    return run

for name,(code,mutation) in NEGATIVES.items():
    setattr(SourcePrograms,'test_reject_'+name,negative_test(code,mutation))


class DelegationRejections(unittest.TestCase):
    def test_wrong_variant_map_and_canonical_identity(self):
        cases=[]
        d=classes();d['programs'][4]['delegate']['target']=1;cases.append(('ABI_SP_DELEGATION_VARIANT',d))
        d=classes();d['programs'][4]['delegate']['cell_map'][0]['parent']=1;cases.append(('ABI_SP_DELEGATION_COVERAGE',d))
        d=classes();d['cleanups'][1]['journal_program']=q(700);cases.append(('ABI_SP_JOURNAL_PROGRAM_ALIAS',d))
        d=classes();d['cleanups'].append(deepcopy(d['cleanups'][0]));d['cleanups'][-1]['id']=2;cases.append(('ABI_SP_CANONICAL_CLEANUP',d))
        d=classes();d['programs'][0].update(steps=[],delegate=dict(target=4,owner_relation='distinct_program',cell_map=[dict(child=i,parent=i) for i in (0,3,1,2)]));cases.append(('ABI_SP_DELEGATION_CYCLE',d))
        for code,d in cases:
            with self.subTest(code=code),self.assertRaises(S._api().SourceDataError) as caught:S.verify(d,budget=budget())
            self.assertEqual(caught.exception.code,code)


ROOT_CASES=('original','wrong_identity','wrong_method','wrong_journal','wrong_journal_signature','dep_journal','mutated_source','wrong_ledger','fake_owner','source_only_method','physical','physical_abi_verified','physical_entry_association','physical_wrong_execution','physical_wrong_vtt','physical_wrong_body_plan','prototype_arity','shared_ledger','wrong_manifest_site')


def root_worker(case):
    if case not in ROOT_CASES:raise ValueError('unknown original-association test case: '+case)
    sys.path.insert(0,str(ROOT/'tools/smir-abi'))
    from function_address.fixtures import ordinary,seal,source as nominal
    sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
    from candidate.context import RootContext
    roots=ordinary(complete_record=True)
    roots[10]['journals'].append(dict(id=700,signature=201,params=[],slots=[],normal_order=[],exception_order=[]))
    if case=='wrong_journal_signature':
        plan=deepcopy(next(p for p in roots[10]['signatures'] if p['id']==201));plan['id']=202
        roots[10]['signatures'].append(plan)
    d=document();d['records'][0]['name']='example.R'
    if case in ('wrong_method','source_only_method','physical','physical_abi_verified','physical_entry_association','physical_wrong_execution','physical_wrong_vtt','physical_wrong_body_plan','prototype_arity'):
        roots[10]['types'].append(nominal(1500,'void'))
        roots[10]['types'].append(nominal(1501,'function',elements=[1500],extent=0,flags=['complete']))
        actual=next(t for t in roots[10]['types'] if t['id']==100)
        actual['methods']=[dict(name='example.R::R',signature=q(1501),virtual=False,slot=None,noexcept=False)]
        d['methods']=[method(0,0,name='example.R::R',declaration_index=0,signature=q(1501),trivial=True,user_provided=False,has_definition=False)]
        d['programs'][0].update(variant='trivial_init',method=0)
        if case.startswith('physical'):
            from function_address.fixtures import layout
            roots[10]['types'].append(nominal(1510,'pointer',elements=[100],bits=64,execution=1002,
                layout_id=1510,representation='value',flags=['complete','trivial_copy','trivial_destroy']))
            roots[10]['layouts'].append(layout(1510,8,8))
            roots[1]['types'].append(dict(id=1800,kind='function',cc='portable',variadic=False,
                params=[q(1002)],results=[],param_noundef=[True],result_noundef=[]))
            roots[3]['functions'].append(dict(id=1800,signature=q(1800),abi_signature={'some':q(202)},
                params=[dict(id=0,type=q(1002))],entry=0,escape='propagate',no_return=False,
                blocks=[dict(id=0,phis=[],ops=[],term=dict(op='return',values=[]))]))
            roots[10]['signatures'].append(dict(id=202,function_type=q(1501),params=[],result=None,
                this_type={'some':q(1510)},vtt=False,variadic=False,noexcept=False,
                lowered_params=[dict(source_index=None,role='this',source_type=q(1510),value_type=q(1510),
                    mode='direct',align=8,bytes=8,noundef=True,copy=None,move=None,destroy=None)],
                lowered_results=[],varargs=None,return_noundef=True,execution=q(1800)))
            d['methods'][0]['has_definition']=True
            d['programs'][0]['implementation']=dict(function=q(1800),call_signature=q(202),execution=q(1800),uses_vtt=False)
            if case=='physical_wrong_execution':d['programs'][0]['implementation']['execution']=q(1000)
            if case=='physical_wrong_vtt':d['programs'][0]['implementation']['uses_vtt']=True
            if case=='physical_wrong_body_plan':roots[3]['functions'][-1]['abi_signature']=None
        if case=='prototype_arity':next(t for t in roots[10]['types'] if t['id']==1501)['elements']=[]
    seal(roots)
    if case=='wrong_manifest_site':roots[2]['manifest']['site']='00'*32
    owner=RootContext(roots)
    if case in ('physical_abi_verified','physical_entry_association'):owner.verify_abi()
    if case=='physical_entry_association':
        verified=owner.verify_execution()
        body=next(f for f in verified.functions_root['functions'] if f['id']==1800)
        if body['abi_signature']!={'some':q(202)}:raise AssertionError('physical entry association lost')
    b=budget();stamp=owner.prepare_source_data(budget=b)
    key=roots[2]['manifest']['key'];d['contexts'][0].update(family={n:key[n] for n in ('namespace','name','abi_major')},abi_site=roots[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
    if case=='shared_ledger':
        first=S.check_source_associations(d,owner,0,budget=b)
        from record_layout.materialization import _context
        for same_content in (True,False):
            second_roots=deepcopy(roots)
            if not same_content:second_roots[2]['manifest']['key']['name']='other_owner'
            second=RootContext(second_roots);second_stamp=second.prepare_source_data(budget=b)
            second_doc=deepcopy(d);second_doc['contexts'][0].update(
                family={k:second_roots[2]['manifest']['key'][k] for k in ('namespace','name','abi_major')},
                abi_root=dict(second_stamp.root_digests)[10].hex(),module_root=dict(second_stamp.root_digests)[2].hex())
            observed=S.check_source_associations(second_doc,second,0,budget=b)
            if first.stamp is not stamp or observed.stamp is not second_stamp or stamp is second_stamp or stamp.context_anchor is second_stamp.context_anchor:
                raise AssertionError('source owners merged by ABI-site/shared ledger')
            if d['contexts'][0]['abi_site']!=second_doc['contexts'][0]['abi_site']:
                raise AssertionError('expected same pinned ABI site')
            if same_content and dict(stamp.root_digests)!=dict(second_stamp.root_digests):
                raise AssertionError('expected byte-identical roots with separate original owners')
            second.verify_abi()
            contract=sys.modules['rax_abi_candidate_contract'];family=second_roots[2]['manifest']['key']
            module=family['namespace']+':'+family['name']+':'+str(family['abi_major'])
            def unavailable(reference):raise ValueError('native evidence unavailable')
            context=contract.Context(module,second.abi_execution,second.symbol,second.metadata,{}, {},
                unavailable,unavailable,{module:(family['namespace'],family['name'],family['abi_major'])},
                second.memory_layout,source_data=second.source_data,source_stamp=second_stamp,source_budget=b)
            if _context(context,b)[2] is not second:raise AssertionError('original owner association lost')
            context.source_stamp=stamp
            try:_context(context,b)
            except S._api().SourceDataError as error:
                if error.code!='SOURCE_DATA_CONTEXT':raise
            else:raise AssertionError('cross-owner original stamp accepted')
        print(json.dumps(dict(case=case,passed=True)));return
    if case=='wrong_identity':d['contexts'][0]['abi_site']='00'*32
    if case=='wrong_method':d['methods'][0]['signature']=q(103)
    if case=='wrong_journal':d['cleanups'][0]['journal_program']=q(999)
    if case=='wrong_journal_signature':d['cleanups'][0]['signature']=q(202)
    if case=='dep_journal':d['cleanups'][0]['journal_program']=q(700,7)
    if case=='mutated_source':owner.sections[10]['identity']='00'*32
    if case=='wrong_ledger':b=budget()
    if case=='fake_owner':owner=object()
    expected=dict(wrong_identity='ABI_SP_ORIGINAL_SITE',wrong_method='ABI_SP_ORIGINAL_METHOD',wrong_journal='ABI_SP_ORIGINAL_REFERENCE',wrong_journal_signature='ABI_SP_ORIGINAL_JOURNAL_SIGNATURE',dep_journal='ABI_SP_DEP_JOURNAL_UNAVAILABLE',mutated_source='context_snapshot_changed',wrong_ledger='SOURCE_DATA_CONTEXT',fake_owner='ABI_SP_ORIGINAL_CONTEXT',physical_wrong_execution='ABI_SP_ORIGINAL_IMPLEMENTATION',physical_wrong_vtt='ABI_SP_ORIGINAL_IMPLEMENTATION',physical_wrong_body_plan='ABI_SP_ORIGINAL_IMPLEMENTATION',prototype_arity='ABI_SP_ORIGINAL_SIGNATURE',wrong_manifest_site='ABI_SP_ORIGINAL_SITE')
    try:
        result=S.check_source_associations(d,owner,0,budget=b)
    except Exception as error:
        if case not in expected or getattr(error,'code',str(error))!=expected[case]:raise
    else:
        if case in expected:raise AssertionError('expected rejection '+case)
        if result.runtime_authority or result.source_fact_authority or result.stamp is not stamp or owner.abi_checked != (case in ('physical_abi_verified','physical_entry_association')):raise AssertionError('wrong authority/source phase')
        if not any(x[0]=='original_journal_program_call_signature' for x in result.checks):raise AssertionError('missing original program check')
    print(json.dumps(dict(case=case,passed=True)))


class OriginalAssociations(unittest.TestCase):pass


def root_test(case):
    def run(self):
        argv=[sys.executable,'-B','-m','record_layout.test_source_programs','--case',case]
        if not __debug__:argv.insert(2,'-O')
        result=subprocess.run(argv,cwd=ROOT/'tools/smir-abi',env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertTrue(json.loads(result.stdout)['passed'])
    return run

for case in ROOT_CASES:setattr(OriginalAssociations,'test_'+case,root_test(case))



class ActualAstComparison(unittest.TestCase):
    def fixture(self):
        directory=ROOT/'docs/specifications/smir/portable/conformance/abi/source-programs'
        return (json.loads((directory/'delegating.json').read_text()),json.loads((directory/'delegating-ast.json').read_text()))

    def test_actual_six_compiler_programs(self):
        d,a=self.fixture();result=S.compare_ast(d,a,budget=budget())
        self.assertEqual(len(d['ast_bindings'][0]['programs']),6)
        self.assertFalse(result.runtime_authority);self.assertFalse(result.source_fact_authority)
        self.assertFalse(any(x[0].startswith('ast_unmatched_') for x in result.obligations))
        self.assertTrue(any(x[0]=='ast_parameter_original_nominal_binding' for x in result.obligations))

    def test_partial_mapping_records_unmatched(self):
        d,a=self.fixture();d['ast_bindings'][0]['programs'].pop()
        result=S.compare_ast(d,a,budget=budget())
        self.assertIn(('ast_unmatched_descriptor_program',5),result.obligations)
        self.assertIn(('ast_unmatched_oracle_program',5),result.obligations)

    def test_empty_mapping_is_not_comparison(self):
        d,a=self.fixture();d['ast_bindings']=[]
        with self.assertRaises(S._api().SourceDataError) as caught:S.compare_ast(d,a,budget=budget())
        self.assertEqual(caught.exception.code,'ABI_SP_AST_EMPTY_COMPARISON')

    def test_original_name_and_schedule_mismatch(self):
        for mutate,code in [(lambda a:a['methods'][0].update(name='Other::Other'),'ABI_SP_AST_METHOD'),
            (lambda a:a['programs'][0]['steps'][0].update(declaration_index=99),'ABI_SP_AST_STEPS'),
            (lambda a:a['programs'][2]['delegate'].update(target_method=2),'ABI_SP_AST_ORACLE')]:
            d,a=self.fixture();mutate(a)
            with self.subTest(code=code),self.assertRaises(S._api().SourceDataError) as caught:S.compare_ast(d,a,budget=budget())
            self.assertEqual(caught.exception.code,code)

    def test_malformed_unmapped_oracle_rejects(self):
        mutations=[lambda a:a['programs'][0].update(cleanup='body_then_reverse_covered'),
                   lambda a:a['methods'][0].update(has_definition=False),
                   lambda a:a['programs'][0]['steps'][0].update(order=8),
                   lambda a:a.update(runtime_authority=True)]
        for mutation in mutations:
            d,a=self.fixture();d['ast_bindings'][0]['programs']=[p for p in d['ast_bindings'][0]['programs'] if p['program']!=0]
            mutation(a)
            with self.assertRaises(S._api().SourceDataError):S.compare_ast(d,a,budget=budget())


DEFERRED_CASES=('valid','missing_path','missing_path_bad_method','missing_path_bad_journal',
    'missing_path_bad_implementation','missing_path_bad_field','dep_journal','dep_journal_bad_signature',
    'unselected_gap','selected_method_gap','zero_nv','zero_nv_bad_method','alternative_path_bad',
    'old_refusal_order','shared_ledger','wrong_ledger','fake_owner','mutated_source','afterguard_resource',
    'afterguard_mutation','constructor_invariants','beforeguard_resource')


def deferred_worker(case):
    sys.path.insert(0,str(ROOT/'tools/smir-abi'))
    from function_address.fixtures import ordinary,seal,source as nominal,layout
    sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
    from candidate.context import RootContext
    roots=ordinary(complete_record=True)
    roots[10]['journals'].append(dict(id=700,signature=201,params=[],slots=[],normal_order=[],exception_order=[]))
    roots[10]['types'].extend([nominal(1500,'void'),nominal(1501,'function',elements=[1500],extent=0,flags=['complete'])])
    actual=next(t for t in roots[10]['types'] if t['id']==100)
    actual['methods']=[dict(name='example.R::R',signature=q(1501),virtual=False,slot=None,noexcept=False)]
    d=document();d['records'][0]['name']='example.R'
    d['methods']=[method(0,0,name='example.R::R',declaration_index=0,signature=q(1501),trivial=True,user_provided=False,has_definition=False)]
    d['programs'][0].update(variant='trivial_init',method=0)
    expected=None
    if case.startswith('missing_path') or case=='old_refusal_order':actual['record_input']=None
    if case.endswith('bad_method') or case=='old_refusal_order':d['methods'][0]['signature']=q(103);expected='ABI_SP_ORIGINAL_METHOD'
    if case=='missing_path_bad_journal':
        plan=deepcopy(next(p for p in roots[10]['signatures'] if p['id']==201));plan['id']=202;roots[10]['signatures'].append(plan)
        d['cleanups'][0]['signature']=q(202);expected='ABI_SP_ORIGINAL_JOURNAL_SIGNATURE'
    if case=='missing_path_bad_implementation':
        d['methods'][0]['has_definition']=True
        d['programs'][0]['implementation']=dict(function=q(0),call_signature=q(201),execution=q(1001),uses_vtt=False)
        expected='ABI_SP_ORIGINAL_IMPLEMENTATION'
    if case=='missing_path_bad_field':d['records'][0]['slots'][0]['name']='wrong';expected='ABI_SP_ORIGINAL_SLOT'
    if case.startswith('dep_journal'):
        d['cleanups'][0]['journal_program']=q(700,7)
        if case.endswith('bad_signature'):d['cleanups'][0]['signature']=q(999);expected='ABI_SP_ORIGINAL_REFERENCE'
    if case in ('selected_method_gap','unselected_gap'):
        if case=='selected_method_gap':
            d['methods'][0].update(trivial=False,user_provided=True)
            d['programs'][0]['variant']='complete_constructor'
        else:
            context=deepcopy(d['contexts'][0]);context['id']=1;d['contexts'].append(context)
            d['records'].append(record(1,'Other',source=source(100,1)))
            d['methods'].append(method(1,1,has_definition=False))
            d['cleanups'].append(cleanup(1,1))
            d['programs'].append(program(1,1,'complete_constructor',1,1))
    if case.startswith('zero_nv'):
        d['records'][0].update(nonvirtual_size=0,slots=[])
        d['cleanups'][0].update(view='nonvirtual',slots=[])
        d['programs'][0].update(variant='base_constructor',steps=[])
        next(l for l in roots[10]['layouts'] if l['id']==100)['nonvirtual_size']=0
    if case=='alternative_path_bad':
        roots[10]['types'].append(nominal(1600,'record',entity='Child',layout_id=1600,execution=1010,representation='storage',flags=['complete','trivial_copy','trivial_destroy']))
        roots[10]['layouts'].append(layout(1600,4,4));actual['record_input']['some']['fields'][0]['type']=q(1600)
        d['records'][0]['slots'][0]['paths']=[[dict(kind='member',declaration_index=i,virtual=False) for i in route] for route in ((0,0),(99,0))]
        expected='ABI_SP_ORIGINAL_PATH'
    seal(roots);owner=RootContext(roots);b=budget();stamp=owner.prepare_source_data(budget=b)
    key=roots[2]['manifest']['key'];d['contexts'][0].update(family={n:key[n] for n in ('namespace','name','abi_major')},abi_site=roots[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
    if case=='old_refusal_order':
        try:S.check_source_associations(d,owner,0,budget=b)
        except S._api().SourceDataError as e:
            if (e.kind,e.code)!=('unavailable','ABI_SP_SOURCE_PATH_UNAVAILABLE'):raise
        else:raise AssertionError('old unavailable precedence changed')
    if case=='wrong_ledger':b=budget();expected='SOURCE_DATA_CONTEXT'
    if case=='fake_owner':owner=object();expected='ABI_SP_ORIGINAL_CONTEXT'
    if case=='mutated_source':owner.sections[10]['identity']='00'*32;expected='context_snapshot_changed'
    if case in ('afterguard_resource','afterguard_mutation'):
        from unittest.mock import patch
        original=RootContext.prepare_source_data;observed=[]
        def measured(current,*,budget):
            observed.append(budget._used_work)
            return original(current,budget=budget)
        with patch.object(RootContext,'prepare_source_data',measured):
            S.check_source_associations_deferred(d,owner,0,budget=b)
        if len(observed)!=2:raise AssertionError('missing real before/afterguard')
        after_work=b._used_work-observed[-1];limited=budget(max_work=observed[-1]+max(1,after_work//2))
        owner=RootContext(deepcopy(roots));stamp=owner.prepare_source_data(budget=limited);calls=[]
        def guarded(current,*,budget):
            calls.append(budget._used_work)
            if len(calls)==2 and case=='afterguard_mutation':current.sections[10]['identity']='00'*32
            return original(current,budget=budget)
        selected=limited
        if case=='afterguard_mutation':
            owner=RootContext(deepcopy(roots));selected=budget();owner.prepare_source_data(budget=selected)
        try:
            with patch.object(RootContext,'prepare_source_data',guarded):
                S.check_source_associations_deferred(d,owner,0,budget=selected)
        except Exception as e:
            if len(calls)!=2:raise AssertionError('guard observer did not reach the actual afterguard')
            if case=='afterguard_resource':
                if getattr(e,'kind',None)!='resource':raise
            elif getattr(e,'code',str(e))!='context_snapshot_changed':raise
        else:raise AssertionError('original afterguard failed to refuse')
        print(json.dumps(dict(case=case,passed=True)));return
    if case=='beforeguard_resource':
        for dimension in ('max_work','max_edges','max_copied_bytes'):
            fresh=budget(**{dimension:0});original=RootContext(deepcopy(roots))
            try:S.check_source_associations_deferred(d,original,0,budget=fresh)
            except S._api().SourceDataError as e:
                if e.kind!='resource':raise
            else:raise AssertionError('zero quota returned an original source association')
        print(json.dumps(dict(case=case,passed=True)));return
    try:result=S.check_source_associations_deferred(d,owner,0,budget=b)
    except Exception as e:
        if expected is None or getattr(e,'code',str(e))!=expected:raise
    else:
        if expected is not None:raise AssertionError('expected semantic rejection '+expected)
        if result.owner is not owner or result.stamp is not stamp or result.runtime_authority or result.source_fact_authority or result.binding!='unbound':raise AssertionError('wrong original association/authority')
        if case in ('missing_path','dep_journal','selected_method_gap','zero_nv'):
            codes=dict(missing_path='ABI_SP_SOURCE_PATH_UNAVAILABLE',dep_journal='ABI_SP_DEP_JOURNAL_UNAVAILABLE',selected_method_gap='ABI_SP_METHOD_DEFINITION_UNAVAILABLE',zero_nv='ABI_CC_CPP_ZERO_NV_VIEW')
            if len(result.deferred)!=1 or result.deferred[0].code!=codes[case]:raise AssertionError(result.deferred)
            if case=='missing_path' and (result.deferred[0].path,result.deferred[0].edge_index)!=((0,0),0):raise AssertionError('wrong source path coordinate')
            if case=='dep_journal' and any(t[0]=='original_journal_program_call_signature' for t in result.checks):raise AssertionError('unavailable Journal marked checked')
        elif result.deferred:raise AssertionError(result.deferred)
        if case=='unselected_gap':
            if len(result.unselected_deferred)!=1 or result.unselected_deferred[0].context_id!=1:raise AssertionError('wrong selected scope')
            if any(t[1]==1 for t in result.checks):raise AssertionError('unselected source claimed checked')
        if case=='constructor_invariants':
            args=(result.descriptor,owner,stamp,0,(),(),(),())
            for flag,value in [('binding','bound'),('runtime_authority',True),('source_fact_authority',True)]:
                try:S.DeferredOriginalSourceAssociations(*args,**{flag:value})
                except TypeError:pass
                else:raise AssertionError('caller-set authority tag accepted')
            try:result.binding='bound'
            except AttributeError:pass
            else:raise AssertionError('mutable original association')
        if case=='shared_ledger':
            other=RootContext(deepcopy(roots));second=S.check_source_associations_deferred(d,other,0,budget=b)
            if second.owner is not other or second.stamp is stamp or second.stamp.context_anchor is stamp.context_anchor:raise AssertionError('same-byte owners merged')
            if RootContext.prepare_source_data(other,budget=b) is not second.stamp:raise AssertionError('lost original callback')
            owner.verify_abi();other.verify_abi()
            from record_layout.materialization import _context
            contract=sys.modules['rax_abi_candidate_contract'];family=roots[2]['manifest']['key'];module=family['namespace']+':'+family['name']+':'+str(family['abi_major'])
            def unavailable(reference):raise ValueError('native evidence unavailable')
            ctx=contract.Context(module,other.abi_execution,other.symbol,other.metadata,{}, {},unavailable,unavailable,{module:(family['namespace'],family['name'],family['abi_major'])},other.memory_layout,source_data=other.source_data,source_stamp=stamp,source_budget=b)
            try:_context(ctx,b)
            except S._api().SourceDataError as e:
                if e.code!='SOURCE_DATA_CONTEXT':raise
            else:raise AssertionError('cross-owner original stamp reused')
    print(json.dumps(dict(case=case,passed=True)))


class DeferredAssociations(unittest.TestCase):pass


def deferred_test(case):
    def run(self):
        argv=[sys.executable,'-B','-m','record_layout.test_source_programs','--deferred-case',case]
        result=subprocess.run(argv,cwd=ROOT/'tools/smir-abi',env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertTrue(json.loads(result.stdout)['passed'])
    return run


for case in DEFERRED_CASES:setattr(DeferredAssociations,'test_'+case,deferred_test(case))


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--deferred-case':
        deferred_worker(sys.argv[2])
    elif len(sys.argv)==3 and sys.argv[1]=='--case':
        root_worker(sys.argv[2])
    else:unittest.main()
