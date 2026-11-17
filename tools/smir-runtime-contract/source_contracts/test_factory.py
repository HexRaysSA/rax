from pathlib import Path
from copy import deepcopy
import json,unittest
from . import checker as C
from .test_checker import budget,ref,scoped
from codec import CandidateCodec
O=Path(__file__).resolve().parent;W=C.ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts'
SCHEMAS={n:json.loads((C.ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in['abi','execution','runtime']}
def factory(published=True):
 name='sret-published-factory'if published else'sret-source-factory';o=C.RootContext(CandidateCodec(SCHEMAS).decode((W/(name+'.smo')).read_bytes()).roots);n='published-sret-terminal'if published else'partial-sret-retention-reject';d=json.loads((W/(n+'.source-contract.json')).read_bytes());return o,d
class FactoryContracts(unittest.TestCase):
 def test_real_published_sret_source_object_at_physical_return(self):
  o,d=factory();out=C.run(o,d,budget=budget());self.assertIn('ASC_FULL_SCOPE_PATH_COVERAGE_NOT_IMPLEMENTED',out.deferred);self.assertFalse(out.source_fact_authority)
 def test_actual_partial_same_sret_result_cannot_retain_into_complete_result(self):
  o,d=factory(False)
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_SRET_REQUIRES_COMPLETE_PUBLISH')
 def test_real_object_begin_call_and_journal_identity_required(self):
  o,d=factory();d['contract']['phase_sites'][0]['site']['index']=3;d['contract']['scopes'][0]['enter']['index']=3
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_ORIGINAL_HELPER_CALL')
 def test_publish_must_follow_actual_publish_helper(self):
  o,d=factory();d['contract']['phase_sites'][1]['site']['index']=6
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_ORIGINAL_HELPER_CALL')
 def test_nonphysical_subject_still_requires_call_holder_at_physical_return(self):
  o,d=factory();d['contract']['exits'][0]['outcome']=dict(kind='normal_retained_scope',journal=20,retained_scope_value=100)
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_PHYSICAL_HOLDER')
 def test_selector_is_required_not_inferred_from_within(self):
  o,d=factory();del d['contract']['phase_sites'][0]['selector']
  with self.assertRaises(Exception):C.run(o,d,budget=budget())
 def test_selector_original_entities_are_not_invented(self):
  o,d=factory();d['contract']['phase_sites'][0]['selector']=dict(kind='incoming_lifecycle',lifecycle=dict(source_class=ref(100),nominal_function=ref(12),plan=ref(0),program=ref(999),view='complete',kind='constructor',variant='C1'))
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_SELECTOR_ORIGINAL_REFERENCE')
def pointer_factory():
 o=C.RootContext(CandidateCodec(SCHEMAS).decode((W/'pointer-partial-factory-and-caller.smo').read_bytes()).roots);d=json.loads((W/'pointer-partial-return-adoption.source-contract.json').read_bytes());return o,d
class ActualCallerContracts(unittest.TestCase):
 def test_genuine_pointer_return_factory_and_static_self_adoption(self):
  o,d=pointer_factory();out=C.run(o,d,budget=budget());self.assertFalse(out.runtime_authority);self.assertIn('ASC_ADOPTIONS_STATIC_SUBSET',out.deferred)
 def test_source_binding_namespace_cannot_name_adoption_id(self):
  o,d=pointer_factory();d['contract']['phase_sites'][2]['event']['object_binding']=10
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_REFERENCE')
 def test_missing_reserved_candidate_rejects(self):
  o,d=pointer_factory();d['contract']['phase_sites'][2]['event']['return_adoptions']=[999]
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_REFERENCE')
 def test_canonical_adoption_set_has_no_duplicate(self):
  o,d=pointer_factory();d['contract']['phase_sites'][2]['event']['return_adoptions']=[10,10]
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_ADOPTION_CANONICAL_SET')
 def test_attach_actual_selected_adoption_required(self):
  o,d=pointer_factory();d['contract']['phase_sites'][4]['event']['adoption']=999
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_ADOPTION_ATTACH_COMMIT_GROUP')
 def test_no_post_consumer_interleaves_atomic_attach_group(self):
  o,d=pointer_factory();d['contract']['phase_sites'][3:5]=reversed(d['contract']['phase_sites'][3:5])
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_ADOPTION_ATTACH_COMMIT_GROUP')
 def test_result_index_is_logical_not_physical_pointer_width(self):
  o,d=pointer_factory();d['contract']['bindings'][1]['origin']['result_index']=1
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_LOGICAL_RESULT_INDEX')
 def test_returned_object_must_use_actual_call_result_ssa(self):
  o,d=pointer_factory();d['contract']['bindings'][1]['value']=0
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_LOGICAL_RESULT_SSA')
if __name__=='__main__':unittest.main(verbosity=2)
