"""Actual original-v3 static comparison; all inspection authority remains false."""
from copy import deepcopy
import unittest
from . import checker as C
from .test_factory import factory
from . import compare
from . import comparison_values as V
from candidate.context import RootContext
from candidate import root3_context as D
from candidate.source_data_projection import source_api

def budget(**changes):
 d=dict(max_work=10**24,max_edges=10**24,max_copied_bytes=10**24,max_depth=128);d.update(changes);return source_api().SourceQueryBudget(**d)
def roots_and_doc():
 old,doc=factory();return deepcopy(old.sections),deepcopy(doc)
def owner(roots,doc,B,*,minor=0):
 roots=deepcopy(roots);roots[2]['manifest']['key']['abi_minor']+=minor
 roots[3].update(payload_revision=3,source_contract=D.codec().wire_contract(doc['contract'],budget=B))
 raw=D.codec().encode_module(roots,budget=B);decoded=D.codec().decode_module(raw,budget=B)
 return RootContext.from_module(raw,budget=B),decoded.digest,raw

def alpha(doc):
 d=deepcopy(doc);d['contract']['bindings'][0]['id']=7
 for s in d['contract']['scopes']:
  if s['binding']==0:s['binding']=7
 for p in d['contract']['phase_sites']:
  if p['event'].get('binding')==0:p['event']['binding']=7
 return d
class ActualV3Comparison(unittest.TestCase):
 def test_genuine_full_embedded_alpha_original_stamps(self):
  roots,doc=roots_and_doc();other=alpha(doc);B=budget();a,adigest,araw=owner(roots,doc,B);b,bdigest,braw=owner(roots,other,B)
  astamp=a.prepare_source_data(budget=B);bstamp=b.prepare_source_data(budget=B);self.assertNotEqual(adigest,bdigest);self.assertNotEqual(dict(astamp.root_digests)[3],dict(bstamp.root_digests)[3])
  out=compare(a,doc,b,other,0,budget=B);self.assertTrue(out.result);self.assertIs(out.left.owner,a);self.assertIs(out.right.owner,b);self.assertIs(out.left.stamp,astamp);self.assertIs(out.right.stamp,bstamp);self.assertFalse(out.active_v3_verified);self.assertFalse(out.runtime_authority)
  self.assertEqual(a.sections[3]['payload_revision'],3);self.assertEqual(b.sections[3]['payload_revision'],3);self.assertIs(a.prepare_source_data(budget=B),astamp);self.assertIs(b.prepare_source_data(budget=B),bstamp)
 def test_changed_other_manifest_rejects_after_both_real_source_checks(self):
  roots,doc=roots_and_doc();B=budget();a,_,_=owner(roots,doc,B);b,_,_=owner(roots,doc,B,minor=1)
  ca=C.run(a,doc,budget=B);cb=C.run(b,doc,budget=B);self.assertIs(ca.owner,a);self.assertIs(cb.owner,b)
  with self.assertRaises(C.ConstraintError)as e:compare(a,doc,b,doc,0,budget=B)
  self.assertEqual(e.exception.code,'ASC_IDENTITY_SOURCE_CONTEXT_PROFILE')
 def test_replacement_embedded_contract_rejects(self):
  roots,doc=roots_and_doc();B=budget();a,_,_=owner(roots,doc,B)
  with self.assertRaises(C.ConstraintError)as e:C.run(a,alpha(doc),budget=B)
  self.assertEqual(e.exception.code,'ASC_V3_EMBEDDED_CONTRACT_MISMATCH')
 def test_swapped_original_budget_rejects(self):
  roots,doc=roots_and_doc();B=budget();a,_,_=owner(roots,doc,B)
  with self.assertRaises(Exception):C.run(a,doc,budget=budget())
 def test_mixed_revision_explicit_unavailable(self):
  roots,doc=roots_and_doc();B=budget();a,_,_=owner(roots,doc,B);b,_=factory()
  with self.assertRaises(Exception)as e:compare(a,doc,b,doc,0,budget=B)
  self.assertEqual(getattr(e.exception,'code',None),'SCV_REVISION_PAIR_UNAVAILABLE')
 def test_changed_reachable_body_is_valid_but_not_equal(self):
  roots,doc=roots_and_doc();changed=deepcopy(roots);changed[3]['functions'][0]['blocks'][0]['ops'][4]['literal']['value']='2b000000';B=budget();a,_,_=owner(roots,doc,B);b,_,_=owner(changed,doc,B)
  C.run(a,doc,budget=B);C.run(b,doc,budget=B)
  self.assertFalse(compare(a,doc,b,doc,0,budget=B).result)
 def test_unreachable_valid_body_difference_is_outside_selected_function(self):
  roots,doc=roots_and_doc();extra=deepcopy(roots[3]['functions'][0]);extra['id']=1;roots[3]['functions'].append(extra);changed=deepcopy(roots);changed[3]['functions'][1]['blocks'][0]['ops'][4]['literal']['value']='2b000000';B=budget();a,_,_=owner(roots,doc,B);b,_,_=owner(changed,doc,B)
  C.run(a,doc,budget=B);C.run(b,doc,budget=B)
  self.assertTrue(compare(a,doc,b,doc,0,budget=B).result)
  self.assertFalse(compare(a,doc,b,doc,1,budget=B).result)
 def test_mutated_original_source_cannot_reuse_stamp(self):
  roots,doc=roots_and_doc();B=budget();a,_,_=owner(roots,doc,B);b,_,_=owner(roots,doc,B);a.prepare_source_data(budget=B);a.sections[3]['source_contract']['revision']=2
  with self.assertRaises(Exception):compare(a,doc,b,doc,0,budget=B)
 def test_observer_operation_descriptor_is_not_a_body_fact(self):
  roots,doc=roots_and_doc();B=budget();a,_,_=owner(roots,doc,B);bad=deepcopy(doc)
  bad['proposed_operations']=[dict(function=0,site=dict(kind='entry',block=0),op='source_journal_observe',results=[],operands=[],scope_value=0,adoption=0)]
  with self.assertRaises(C.ConstraintError)as e:C.run(a,bad,budget=B)
  self.assertEqual(e.exception.code,'V3_OBSERVER_SEMANTICS_UNAVAILABLE')
 def test_valid_retained_data_difference_is_not_ignored(self):
  roots,doc=roots_and_doc();roots[4]['segments']=[dict(id=0,layout=None,nominal=None,abi_binding=None,alignment=1,mutable=True,initial='00'*2048,poison='00'*2048,undef='00'*2048,zero_fill=0,zero_shadow='defined')]
  changed=deepcopy(roots);changed[4]['segments'][0]['initial']='00'*2047+'01';B=budget();a,_,_=owner(roots,doc,B);b,_,_=owner(changed,doc,B)
  C.run(a,doc,budget=B);C.run(b,doc,budget=B)
  with self.assertRaises(C.ConstraintError)as e:compare(a,doc,b,doc,0,budget=B)
  self.assertEqual(e.exception.code,'ASC_IDENTITY_SOURCE_CONTEXT_PROFILE')
 def test_original_v2_alpha_unchanged(self):
  a,doc=factory();b,_=factory();out=compare(a,doc,b,alpha(doc),0,budget=budget());self.assertTrue(out.result);self.assertFalse(out.active_v3_verified)
class PlainValueMeter(unittest.TestCase):
 def test_both_dict_key_types_before_membership(self):
  class Key:
   def __hash__(self):return hash('x')
   def __eq__(self,other):raise RuntimeError('custom equality invoked')
  right={Key():1}
  with self.assertRaises(C.ConstraintError)as e:V.same({'x':1},right,budget=budget())
  self.assertEqual(e.exception.code,'SCV_VALUE_PROFILE')
 def test_exact_one_less_all_dimensions_no_partial_comparison(self):
  value={'a':['some string',42,True,None,{'b':'z'*2048}]};B=budget();self.assertTrue(V.same(value,deepcopy(value),budget=B))
  exact=dict(max_work=B._used_work,max_edges=B._used_edges,max_copied_bytes=B._used_copied_bytes);self.assertTrue(V.same(value,deepcopy(value),budget=budget(**exact)))
  with self.assertRaises(source_api().SourceDataError):V.same(value,deepcopy(value),budget=budget(max_work=0))
  for key,used in [('max_work',B._used_work),('max_edges',B._used_edges),('max_copied_bytes',B._used_copied_bytes)]:
   with self.assertRaises(source_api().SourceDataError):V.same(value,deepcopy(value),budget=budget(**{key:used-1}))
 def test_plain_mismatch_and_cycle_profile(self):
  self.assertFalse(V.same({'a':[1]},{'a':[2]},budget=budget()));self.assertFalse(V.same(1,True,budget=budget()));a=[];a.append(a)
  with self.assertRaises(C.ConstraintError):V.same(a,a,budget=budget())
if __name__=='__main__':unittest.main(verbosity=2)
