from pathlib import Path
import sys,json,unittest,os
from copy import deepcopy
ROOT=Path(__file__).resolve().parents[7]
for p in ('tools/smir-format/execution','tools/smir-abi','tools/smir-runtime-contract','tools/smir-format'):
    sys.path.append(str(ROOT/p))
from candidate.context import RootContext
from candidate import source_join_paths as P
from source_contracts.test_factory import factory,pointer_factory
from test_candidate_source_join_paths import simple,budget
from candidate.source_grounding import ground,prove_paths,GroundingError

def fixture(pointer=False):
    owner,carrier=pointer_factory() if pointer else factory()
    b=budget();stamp=owner.prepare_source_data(budget=b)
    join,abi,_,_=simple()
    family={n:owner.sections[2]['manifest']['key'][n] for n in ('namespace','name','abi_major')}
    abi['contexts'][0].update(family=deepcopy(family),abi_site=owner.sections[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
    join['contexts'][0].update(family=deepcopy(family),abi_site=owner.sections[10]['identity'],schema_digest=stamp.schema_digest.hex(),roots=[dict(section=n,digest=h.hex()) for n,h in stamp.root_digests])
    q=lambda n:dict(module=dict(kind='self'),id=n)
    abi['cleanups'][0].update(journal_program=q(0),signature=q(0))
    abi['programs']=[]
    join['programs'][0].update(original_journal=q(0),cleanup_signature=q(0))
    request=dict(format='draft-carrier-static-grounding',revision=1,carrier=carrier,source_join=join,abi_programs=abi,
      bindings=[dict(function=r['function'],binding=r['id'],root_binding=r['id'],program='cleanup',cell='root')for r in carrier['contract']['bindings']],
      scopes=[dict(function=r['function'],scope=r['id'],program='cleanup',journal_cells=[dict(slot=0,cell='root')])for r in carrier['contract']['scopes']],lifecycles=[])
    return owner,request,b

class GroundingTests(unittest.TestCase):
    def test_actual_published_sret_canonical_and_closed_scope(self):
        o,d,b=fixture();before=deepcopy((o.sections,d));r=ground(o,d,budget=b)
        self.assertIs(r.owner,o);self.assertIs(r.stamp,o.prepare_source_data(budget=b));self.assertEqual(r.path_functions,((0,1),));self.assertFalse(r.runtime_authority);self.assertFalse(r.source_fact_authority);self.assertEqual(before,(o.sections,d))
    def test_actual_pointer_factory_caller_scope_leak(self):
        o,d,b=fixture(True)
        with self.assertRaisesRegex(GroundingError,'CG_SCOPE_RETURN_LEAK'):ground(o,d,budget=b)
    def test_root_journal_slot_is_not_cleanup_field_zero(self):
        o,d,b=fixture();d['scopes'][0]['journal_cells'][0]['cell']='value'
        with self.assertRaisesRegex(GroundingError,'CG_JOURNAL_ROOT_ANCHOR'):ground(o,d,budget=b)
    def test_binding_root_cannot_be_field_at_same_address(self):
        o,d,b=fixture();d['bindings'][0]['cell']='value'
        with self.assertRaisesRegex(GroundingError,'CG_CELL_SUBJECT'):ground(o,d,budget=b)
    def test_original_context_digest_refuses(self):
        o,d,b=fixture();d['source_join']['contexts'][0]['roots'][0]['digest']='00'*32
        with self.assertRaisesRegex(P.JoinError,'SJX_SOURCE_COORDINATES'):ground(o,d,budget=b)
    def test_same_original_owner_requires_same_ledger(self):
        o,d,b=fixture()
        with self.assertRaises(Exception)as c:ground(o,d,budget=budget())
        self.assertEqual(c.exception.code,'SOURCE_DATA_CONTEXT')
    def test_zero_quota_refuses(self):
        o,d,b=fixture()
        with self.assertRaises(Exception):ground(o,d,budget=budget(max_work=0))

class CompletenessTests(unittest.TestCase):
    def test_deleting_scope_metadata_cannot_prove_scope_free_factory(self):
        o,d,b=fixture();c=d['carrier']['contract']
        for name in ('scopes','scope_values','phase_sites','exits','returns'):c[name]=[]
        d['scopes']=[]
        with self.assertRaisesRegex(GroundingError,'CG_HELPER_SCOPE_COVERAGE'):ground(o,d,budget=b)
    def test_boolean_link_id_is_not_integer_id(self):
        o,d,b=fixture();d['bindings'][0]['root_binding']=False
        with self.assertRaisesRegex(GroundingError,'CG_LINK_ID'):ground(o,d,budget=b)
    def test_scope_table_must_be_exhausted(self):
        o,d,b=fixture();d['scopes']=[]
        with self.assertRaisesRegex(GroundingError,'CG_EXHAUSTION'):ground(o,d,budget=b)
    def test_upstream_gaps_and_false_authority_survive(self):
        from dataclasses import FrozenInstanceError
        o,d,b=fixture();r=ground(o,d,budget=b)
        self.assertIn('ASC_FULL_SCOPE_PATH_COVERAGE_NOT_IMPLEMENTED',r.deferred)
        self.assertIn('CG_NORMAL_CFG_ONLY',r.deferred)
        with self.assertRaises(FrozenInstanceError):r.runtime_authority=True
        with self.assertRaises(TypeError):type(r)(o,r.stamp,(),(),(),(),runtime_authority=True)

class ActualCFGTests(unittest.TestCase):
    def test_both_actual_branch_returns_closed(self):
        from reference_cfg import diamond
        o,d,b=diamond();r=ground(o,d,budget=b);self.assertEqual(r.path_functions,((0,3),))
    def test_one_branch_missing_exit_rejects(self):
        from reference_cfg import diamond
        o,d,b=diamond(True)
        with self.assertRaisesRegex(GroundingError,'CG_SCOPE_RETURN_LEAK'):ground(o,d,budget=b)
    def test_parallel_shadow_phi_actual_predecessors(self):
        from reference_cfg import merged_phi
        o,d,b=merged_phi();r=ground(o,d,budget=b);self.assertEqual(r.path_functions,((0,5),))
    def test_closed_reentering_actual_loop_converges(self):
        from reference_cfg import looping
        o,d,b=looping();r=ground(o,d,budget=b);self.assertLessEqual(r.path_functions[0][1],8)
    def test_actual_loop_live_reentry_rejects(self):
        from reference_cfg import looping
        o,d,b=looping(True)
        with self.assertRaisesRegex(GroundingError,'CG_SCOPE_REENTER_LIVE'):ground(o,d,budget=b)
    def test_saved_scope_alias_after_close_is_stale(self):
        o,d,b=fixture();c=d['carrier']['contract'];site=dict(kind='normal_post',block=0,index=7)
        c['scope_values'].append(dict(id=101,function=0,origin=dict(kind='copy',source=100,site=site)))
        c['phase_sites'].insert(2,dict(id=3,function=0,site=site,selector=dict(kind='always'),within=dict(kind='scope',value=100),event=dict(kind='scope_value',value=101)))
        c['phase_sites'].append(dict(id=4,function=0,site=dict(kind='return_exit',block=0),selector=dict(kind='always'),within=dict(kind='scope',value=101),event=dict(kind='scope_value',value=101)))
        # R requires one defining scope_value phase; use a supported event that USES saved S.
        c['phase_sites'][-1]['event']=dict(kind='scope_exit',exit=1)
        c['exits'].append(dict(id=1,function=0,scope_value=101,site=dict(kind='return_exit',block=0),outcome=dict(kind='normal_no_journal')))
        with self.assertRaisesRegex(GroundingError,'CG_S_STALE'):ground(o,d,budget=b)
    def test_unbound_report_cannot_replace_raw_carrier(self):
        o,d,b=fixture();d['carrier']=dict(binding='unbound',source_fact_authority=False)
        with self.assertRaises(Exception):ground(o,d,budget=b)

if __name__=='__main__':unittest.main(verbosity=2)
