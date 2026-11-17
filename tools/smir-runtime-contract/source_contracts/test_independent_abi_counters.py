from pathlib import Path
import json,unittest
from . import checker as C,identity as I
from .test_factory import SCHEMAS
from .test_checker import budget
from codec import CandidateCodec
O=C.ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts';codec=CandidateCodec(SCHEMAS)
def read(n,doc=None):
 o=C.RootContext(codec.decode((O/(n+'.smo')).read_bytes()).roots);o.verify_abi();o.verify_execution();return o,json.loads((O/(n+'.source-contract.json'if doc is None else doc)).read_bytes())
class ActualIndependentAbiCounterRegressions(unittest.TestCase):
 def test_baseline_and_equivalent_execution_alias(self):
  for n in['baseline','equivalent-execution-dataptr-id']:
   o,d=read(n);r=C.run(o,d,budget=budget());self.assertFalse(r.runtime_authority)
 def test_generic_caller_uses_actual_callee_plan(self):
  o,d=read('generic-caller-own-abi-none');self.assertIsNone(o.sections[3]['functions'][1]['abi_signature']);r=C.run(o,d,budget=budget());self.assertFalse(r.source_fact_authority)
 def test_missing_all_adoptions_does_not_skip_required_set(self):
  o,d=read('missing-all-adoptions')
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_ADOPTION_COMPLETE_SET')
 def test_return_scope_must_equal_exit_scope(self):
  o,d=read('return-scope-not-exit-scope')
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_RETURN_SCOPE_EXIT')
 def test_exact_journal_program_cannot_be_shape_clone(self):
  o,d=read('scope-program-differs-actual-journal-begin')
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_SCOPE_JOURNAL_PROGRAM')
 def test_actual_original_address_target_source_closure_not_omitted(self):
  a,d=read('address-only-source-closure','address-only-source-closure-left.json');b,e=read('address-only-source-closure','address-only-source-closure-right.json');ledger=budget();self.assertFalse(I.compare(a,d,b,e,0,budget=ledger));self.assertEqual(I.closure(a,0,ledger,d),{0,1})
if __name__=='__main__':unittest.main(verbosity=2)
