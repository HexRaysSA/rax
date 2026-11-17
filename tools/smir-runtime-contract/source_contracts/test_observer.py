"""Actual original-v3 source verifier against the composed draft kernel."""
from .observer_fixtures import blueprint,owner
from .test_v3_identity import budget
from . import checker as C
from . import compare
from copy import deepcopy
import unittest
from source_contracts import verify,ContractToolError
from candidate.source_grounding import prove_paths


class ActualObserverSource(unittest.TestCase):
    def verify(self,roots,doc):
        B=budget();original=owner(roots,doc,B);return verify(original,doc,budget=B)
    def reject(self,roots,doc,code=None):
        with self.assertRaises(Exception)as caught:self.verify(roots,doc)
        if code is not None:self.assertEqual(getattr(caught.exception,'code',None),code)
        return caught.exception
    def test_real_body_and_public_source_keep_original_owner_stamp_false_flags(self):
        roots,doc=blueprint();B=budget();original=owner(roots,doc,B);stamp=original.prepare_source_data(budget=B);original.verify_abi();body=original.verify_candidate_body(budget=B)
        self.assertIs(body.owner,original);self.assertIs(body.stamp,stamp);self.assertEqual(len(body.observers),1)
        result=verify(original,doc,budget=B);self.assertIs(result.owner,original);self.assertIs(result.stamp,stamp)
        self.assertFalse(result.source_fact_authority);self.assertFalse(result.runtime_authority);self.assertFalse(result.active_v3_verified)
        self.assertIn('ASC_OBSERVER_STATIC_SOURCE_PROFILE_ONLY',result.deferred)
        self.assertEqual(roots[3]['functions'][0]['blocks'][0]['term']['values'],[0]);self.assertEqual(roots[3]['functions'][1]['blocks'][0]['term']['values'],[1])
        for method in (original.verify_execution,lambda:original.source_registry_context(budget=B)):
            with self.assertRaises(Exception):method()
    def test_source_scope_id_is_not_ordinary_ssa(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'][1]['scope_value']=2
        self.reject(roots,doc,'V3_REFERENCE')
    def test_wrong_adoption(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'][1]['adoption']=11
        self.reject(roots,doc,'V3_REFERENCE')
    def test_pre_call_observer_cannot_use_future_return_receiver(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'].reverse();self.reject(roots,doc)
    def test_typed_nonjournal_result_rejected_by_real_body(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['type']['id']=1
        self.reject(roots,doc)
    def test_duplicate_ordinary_ssa_rejected_by_real_body(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id']=1
        self.reject(roots,doc)
    def test_missing_actual_callee_binding(self):
        roots,doc=blueprint();doc['contract']['phase_sites']=[p for p in doc['contract']['phase_sites']if not(p['function']==0 and p['event']['kind']=='bind_journal')]
        self.reject(roots,doc,'SCVO_PHASE_COUNT_PROFILE')
    def test_wrong_callee_binding_value(self):
        roots,doc=blueprint();next(p for p in doc['contract']['phase_sites']if p['function']==0 and p['event']['kind']=='bind_journal')['event']['journal']=0
        self.reject(roots,doc)
    def test_extra_well_typed_journal_does_not_supply_original_association(self):
        roots,doc=blueprint();begin=deepcopy(roots[3]['functions'][0]['blocks'][0]['ops'][0]);begin['results'][0]['id']=21;roots[3]['functions'][0]['blocks'][0]['ops'].append(begin)
        self.reject(roots,doc,'SCVO_CALLEE_OPERATIONS_PROFILE')
    def test_wrong_actual_program(self):
        roots,doc=blueprint();other=deepcopy(roots[10]['journals'][0]);other['id']=1;roots[10]['journals'].append(other);next(s for s in doc['contract']['scopes']if s['function']==1)['program']['id']=1
        self.reject(roots,doc,'ASC_OBSERVER_PROGRAM')
    def test_wrong_view(self):
        roots,doc=blueprint();next(s for s in doc['contract']['scopes']if s['function']==1)['view']='nonvirtual'
        self.reject(roots,doc,'ASC_OBSERVER_VIEW')
    def test_existing_object_caller_rebinding_is_not_an_observer_phase(self):
        roots,doc=blueprint();doc['contract']['phase_sites'].insert(-1,dict(id=14,function=1,site=dict(kind='normal_post',block=0,index=1),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='bind_journal',scope_value=100,journal=2)))
        self.reject(roots,doc,'ASC_PHASE_SUBJECT')
    def test_source_object_double_bind_not_new_inline_positive(self):
        roots,doc=blueprint();s=next(s for s in doc['contract']['scopes']if s['function']==0);s['subject']='source_object';s['enter']=dict(kind='normal_post',block=0,index=0);p=next(p for p in doc['contract']['phase_sites']if p['function']==0 and p['id']==0);p['site']=deepcopy(s['enter']);p['event']=dict(kind='object_begin_root',scope=0,binding=0,journal=20)
        self.reject(roots,doc,'ASC_PHASE_SUBJECT')
    def test_missing_caller_scope_exit_cannot_disappear(self):
        roots,doc=blueprint();doc['contract']['exits']=[r for r in doc['contract']['exits']if r['function']!=1];doc['contract']['returns']=[r for r in doc['contract']['returns']if r['function']!=1];doc['contract']['phase_sites']=[r for r in doc['contract']['phase_sites']if not(r['function']==1 and r['event']['kind']=='scope_exit')]
        self.reject(roots,doc)
    def test_swapped_original_budget_and_changed_embedded_contract_refuse(self):
        roots,doc=blueprint();B=budget();original=owner(roots,doc,B)
        with self.assertRaises(Exception):verify(original,doc,budget=budget())
        changed=deepcopy(doc);changed['contract']['phase_sites']=[]
        with self.assertRaises(Exception):verify(original,changed,budget=B)
    def test_pure_path_observer_default_explicitly_unavailable(self):
        roots,doc=blueprint();B=budget();original=owner(roots,doc,B)
        with self.assertRaises(Exception)as e:prove_paths(original.sections[3]['functions'][1],doc['contract'],B)
        self.assertEqual(e.exception.code,'CG_OBSERVER_PROFILE_UNAVAILABLE')
        self.assertEqual(prove_paths(original.sections[3]['functions'][1],doc['contract'],B,source_observers=True),1)
    def test_real_path_checker_uses_actual_observer_pre_not_newest_scope(self):
        roots,doc=blueprint();doc['contract']['exits'].append(dict(id=1,function=1,scope_value=100,site=dict(kind='normal_post',block=0,index=0),outcome=dict(kind='normal_no_journal')));doc['contract']['exits'].sort(key=lambda r:(r['function'],r['id']));extra=dict(id=14,function=1,site=dict(kind='normal_post',block=0,index=0),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_exit',exit=1));doc['contract']['phase_sites'].insert(-1,extra);B=budget();original=owner(roots,doc,B);original.verify_abi();original.verify_candidate_body(budget=B)
        with self.assertRaises(Exception)as e:prove_paths(original.sections[3]['functions'][1],doc['contract'],B,source_observers=True)
        self.assertEqual(e.exception.code,'CG_S_STALE')
    def test_ordinary_prelude_is_explicit_initial_profile_unavailable(self):
        roots,doc=blueprint();block=roots[3]['functions'][1]['blocks'][0];block['ops'].insert(0,dict(op='constant',results=[dict(id=30,type=dict(module=dict(kind='self'),id=1))],operands=[],literal=dict(kind='bits',value='00000000')))
        for p in doc['contract']['phase_sites']:
            if p['function']==1 and p['site']['kind']in('pre_op','normal_post'):p['site']['index']=1
        next(r for r in doc['contract']['scopes']if r['function']==1)['enter']['index']=1;doc['contract']['adoptions'][0]['call']['index']=1;next(r for r in doc['contract']['bindings']if r['function']==1)['origin']['call']['index']=1
        self.reject(roots,doc,'SCVO_NORMAL_LAST_OPERATION_PROFILE')
    def test_unrepresentable_complete_source_link_rejects_before_body(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id']=2**32-1
        # Original complete graph still refers to J2. The real local-reference
        # guard rejects before body/source querying; no removed graph or fake
        # context is used to force the later source-profile diagnostic.
        self.reject(roots,doc,'V3_REFERENCE')
    def test_current_reference_products_and_real_sem_fixture(self):
        from . import observer_fixtures as F
        from pathlib import Path
        import json
        folder=C.ROOT/'docs/specifications/smir/portable/conformance/runtime/source-observer';before={n:(folder/n).read_bytes()for n in F.products()}
        self.assertEqual(before,F.products());self.assertEqual(before,{n:(folder/n).read_bytes()for n in before})
        sem=C.ROOT/'docs/specifications/smir/portable/conformance/execution/source-observer';B=budget();original=C.RootContext.from_module((sem/'inline-retained-observer.smo').read_bytes(),budget=B);document=json.loads((sem/'inline-retained-observer.source-contract.json').read_bytes());result=verify(original,document,budget=B)
        self.assertIs(result.owner,original);self.assertFalse(result.runtime_authority);self.assertIn('ASC_OBSERVER_STATIC_SOURCE_PROFILE_ONLY',result.deferred)
    def test_phi_scope_is_not_a_reserved_receiver_enter(self):
        roots,doc=blueprint();doc['contract']['scope_values'].append(dict(id=101,function=1,origin=dict(kind='phi',block=0,incoming=[])));roots[3]['functions'][1]['blocks'][0]['ops'][1]['scope_value']=101;self.reject(roots,doc)

    def test_future_source_copy_is_not_live_at_observer_pre(self):
        roots,doc=blueprint();doc['contract']['scope_values'].append(dict(id=101,function=1,origin=dict(kind='copy',site=dict(kind='normal_post',block=0,index=1),source=100)));roots[3]['functions'][1]['blocks'][0]['ops'][1]['scope_value']=101
        doc['contract']['phase_sites'].insert(-1,dict(id=14,function=1,site=dict(kind='normal_post',block=0,index=1),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_value',value=101)))
        self.reject(roots,doc)
        B=budget();original=owner(roots,doc,B);original.verify_abi();original.verify_candidate_body(budget=B)
        with self.assertRaises(Exception)as e:prove_paths(original.sections[3]['functions'][1],doc['contract'],B,source_observers=True)
        self.assertEqual(e.exception.code,'CG_S_UNDEFINED')
    def test_two_actual_callee_returns_are_explicitly_ambiguous(self):
        roots,doc=blueprint();roots[1]['types'].append(dict(kind='int',id=5100,bits=1));callee=roots[3]['functions'][0];block=callee['blocks'][0];block['ops'].append(dict(op='constant',results=[dict(id=30,type=dict(module=dict(kind='self'),id=5100))],operands=[],literal=dict(kind='bits',value='01')));block['term']=dict(op='cbranch',condition=30,**{'true':1,'false':2});callee['blocks'].extend([dict(id=i,phis=[],ops=[],term=dict(op='return',values=[0]))for i in(1,2)])
        next(r for r in doc['contract']['exits']if r['function']==0)['site']['block']=1;next(r for r in doc['contract']['phase_sites']if r['function']==0 and r['event']['kind']=='scope_exit')['site']['block']=1
        doc['contract']['exits'].append(dict(id=1,function=0,scope_value=100,site=dict(kind='return_exit',block=2),outcome=dict(kind='normal_retained_call',journal=20,**{'return':1})));doc['contract']['exits'].sort(key=lambda r:(r['function'],r['id']));doc['contract']['returns'].append(dict(id=1,function=0,scope=0,exit=1,disposition='retained_to_call'));doc['contract']['returns'].sort(key=lambda r:(r['function'],r['id']));doc['contract']['phase_sites'].append(dict(id=3,function=0,site=dict(kind='return_exit',block=2),selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_exit',exit=1)))
        B=budget();original=owner(roots,doc,B);original.verify_abi();original.verify_candidate_body(budget=B)
        self.reject(roots,doc,'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS')



def rename_receiver(roots,doc):
    roots,doc=deepcopy(roots),deepcopy(doc);c=doc['contract']
    next(r for r in c['scope_values']if r['function']==1)['id']=700
    next(r for r in c['scopes']if r['function']==1)['enter_value']=700
    next(r for r in c['exits']if r['function']==1)['scope_value']=700
    adoption=c['adoptions'][0];adoption['id']=17;adoption['receiver']['value']=700
    for p in c['phase_sites']:
        if p['function']!=1:continue
        if p['within']['kind']=='scope':p['within']['value']=700
        if p['event']['kind']=='call':p['event']['return_adoptions']=[17]
        if p['event']['kind']=='object_attach_returned':p['event']['adoption']=17
    op=roots[3]['functions'][1]['blocks'][0]['ops'][1];op['scope_value']=700;op['adoption']=17
    return roots,doc


class JointActualAlpha(unittest.TestCase):
    def test_actual_joint_private_source_ids_true_complete_stamps_retained(self):
        roots,doc=blueprint();other,odoc=rename_receiver(roots,doc);B=budget();a=owner(roots,doc,B);b=owner(other,odoc,B);astamp=a.prepare_source_data(budget=B);bstamp=b.prepare_source_data(budget=B)
        self.assertNotEqual(dict(astamp.root_digests)[3],dict(bstamp.root_digests)[3]);out=compare(a,doc,b,odoc,1,budget=B)
        self.assertTrue(out.result);self.assertIs(out.left.owner,a);self.assertIs(out.right.owner,b);self.assertIs(out.left.stamp,astamp);self.assertIs(out.right.stamp,bstamp);self.assertFalse(out.active_v3_verified);self.assertFalse(out.runtime_authority)
        self.assertEqual(a.sections[3]['functions'][1]['blocks'][0]['ops'][1]['scope_value'],100);self.assertEqual(b.sections[3]['functions'][1]['blocks'][0]['ops'][1]['scope_value'],700)
    def test_ordinary_journal_ssa_is_not_private_alpha(self):
        roots,doc=blueprint();other,odoc=deepcopy(roots),deepcopy(doc);other[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id']=3;next(r for r in odoc['contract']['exits']if r['function']==1)['outcome']['journal']=3
        B=budget();a=owner(roots,doc,B);b=owner(other,odoc,B);verify(a,doc,budget=B);verify(b,odoc,budget=B);self.assertFalse(compare(a,doc,b,odoc,1,budget=B).result)
    def test_valid_ordinary_return_difference_remains_false(self):
        roots,doc=blueprint();other=deepcopy(roots);other[3]['functions'][1]['blocks'][0]['term']['values']=[0];B=budget();a=owner(roots,doc,B);b=owner(other,doc,B);verify(a,doc,budget=B);verify(b,doc,budget=B);self.assertFalse(compare(a,doc,b,doc,1,budget=B).result)
    def test_equal_integer_source_scope_and_ordinary_journal_ids_stay_distinct(self):
        roots,doc=blueprint();roots[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id']=100;next(r for r in doc['contract']['exits']if r['function']==1)['outcome']['journal']=100
        other,odoc=rename_receiver(roots,doc);self.assertEqual(other[3]['functions'][1]['blocks'][0]['ops'][1]['results'][0]['id'],100);self.assertEqual(next(r for r in odoc['contract']['exits']if r['function']==1)['outcome']['journal'],100)
        B=budget();a=owner(roots,doc,B);b=owner(other,odoc,B);self.assertTrue(compare(a,doc,b,odoc,1,budget=B).result)
    def test_valid_unreachable_body_difference_is_outside_observer_closure(self):
        roots,doc=blueprint();extra=deepcopy(roots[3]['functions'][0]);extra['id']=2;extra['blocks'][0]['ops']=[];roots[3]['functions'].append(extra);other=deepcopy(roots);other[3]['functions'][2]['blocks'][0]['ops']=[dict(op='constant',results=[dict(id=30,type=dict(module=dict(kind='self'),id=1))],operands=[],literal=dict(kind='bits',value='01000000'))]
        B=budget();a=owner(roots,doc,B);b=owner(other,doc,B);verify(a,doc,budget=B);verify(b,doc,budget=B);self.assertTrue(compare(a,doc,b,doc,1,budget=B).result);self.assertFalse(compare(a,doc,b,doc,2,budget=B).result)

if __name__=='__main__':unittest.main(verbosity=2)
