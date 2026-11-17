from copy import deepcopy
import unittest
from . import identity as I
from . import checker as C
from .test_checker import owner,scoped,base,budget
from .test_factory import pointer_factory

def renamed(d):
 ks=I.keys(d);mapping={k:1000+19*i for i,k in enumerate(reversed(list(ks)))}
 return I.alpha(d,mapping)
class ActualGraphIdentity(unittest.TestCase):
 def test_original_ordinary_body_and_complete_private_alpha_bijection(self):
  d=scoped();self.assertTrue(I.compare(owner(),d,owner(),renamed(d),0,budget=budget()))
 def test_same_actual_body_different_source_exit_is_not_equal(self):
  d=scoped();e=deepcopy(d);e['contract']['exits'][0]['site']=dict(kind='return_exit',block=3);e['contract']['phase_sites'][-1]['site']=deepcopy(e['contract']['exits'][0]['site'])
  self.assertFalse(I.compare(owner(),d,owner(),e,0,budget=budget()))
 def test_one_nonempty_source_contract_cannot_equal_empty(self):
  self.assertFalse(I.compare(owner(),base(),owner(),scoped(),0,budget=budget()))
 def test_actual_caller_callee_return_adoption_closure_alpha(self):
  a,d=pointer_factory();b,e=pointer_factory();self.assertTrue(I.compare(a,d,b,renamed(e),1,budget=budget()))
 def test_canonical_candidate_set_alpha_reversal_mathematical_unit_only(self):
  # Typed rewrite algebra only; no original factory or admission claimed here.
  _,d=pointer_factory();d=deepcopy(d);ad=deepcopy(d['contract']['adoptions'][0]);ad['id']=11;d['contract']['adoptions'].append(ad);d['contract']['phase_sites'][2]['event']['return_adoptions']=[10,11]
  mapping={k:k[2]for k in I.keys(d)};mapping['adoptions',1,10]=51;mapping['adoptions',1,11]=50
  out=I.alpha(d,mapping);self.assertEqual(out['contract']['phase_sites'][2]['event']['return_adoptions'],[50,51]);self.assertEqual([a['id']for a in out['contract']['adoptions']],[50,51])
 def test_actual_comparison_resource_has_no_partial_equal(self):
  d=scoped();ledger=budget();self.assertTrue(I.compare(owner(),d,owner(),renamed(d),0,budget=ledger));used=ledger._used_work
  with self.assertRaises(Exception)as e:I.compare(owner(),d,owner(),renamed(d),0,budget=budget(max_work=used-1))
  self.assertIn('RESOURCE',getattr(e.exception,'code',str(e.exception)))
if __name__=='__main__':unittest.main(verbosity=2)
