from pathlib import Path
from copy import deepcopy
import json,unittest
from . import checker as C
from .test_factory import SCHEMAS
from .test_checker import budget,ref
from codec import CandidateCodec
O=C.ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts';codec=CandidateCodec(SCHEMAS)
def read(n):
 o=C.RootContext(codec.decode((O/(n+'.smo')).read_bytes()).roots);o.verify_abi();o.verify_execution();return o,json.loads((O/(n+'.source-contract.json')).read_bytes())
class ActualNominalAliasRegressions(unittest.TestCase):
 def test_source_class_canonical_alias(self):
  o,d=read('source-class-compatible-alias');self.assertTrue(o.abi_graph.compatible(ref(100),ref(1100),ignore_top_cv=False));self.assertFalse(C.run(o,d,budget=budget()).runtime_authority)
 def test_subject_root_canonical_alias(self):
  o,d=read('subject-root-compatible-alias');self.assertFalse(C.run(o,d,budget=budget()).source_fact_authority)
 def test_formal_static_pointer_canonical_alias(self):
  o,d=read('formal-static-pointer-compatible-alias');self.assertFalse(C.run(o,d,budget=budget()).active_v3_verified)
 def test_returned_static_pointer_canonical_alias(self):
  o,d=read('returned-static-pointer-compatible-alias');self.assertFalse(C.run(o,d,budget=budget()).runtime_authority)
 def test_nominal_alias_cannot_change_pointer_reference_category(self):
  o,d=read('formal-static-pointer-compatible-alias');d['contract']['bindings'][0]['static_pointer_type']=ref(100)
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_STATIC_POINTER')
 def test_top_cv_is_not_dropped(self):
  o,d=read('negative-top-cv');self.assertTrue(o.abi_graph.compatible(ref(100),ref(1100),ignore_top_cv=True));self.assertFalse(o.abi_graph.compatible(ref(100),ref(1100),ignore_top_cv=False))
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_STATIC_POINTEE')
 def test_pointer_reference_category_preserved_after_actual_abi(self):
  o,d=read('negative-reference-category');self.assertFalse(o.abi_graph.compatible(ref(500),ref(1500),ignore_top_cv=False))
  with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
  self.assertEqual(e.exception.code,'ASC_FORMAL_SOURCE')
 def test_definition_digest_tamper_fails_original_abi(self):
  o=C.RootContext(codec.decode((O/'negative-definition-digest.smo').read_bytes()).roots)
  with self.assertRaises(Exception)as e:o.verify_abi()
  self.assertEqual(getattr(e.exception,'code',str(e.exception)),'ABI_CC_DEFINITION_HASH')
 def test_different_class_and_wrong_namespace_rejected(self):
  for name,code in [('negative-different-class','ASC_STATIC_POINTEE'),('negative-wrong-namespace','ASC_ORIGINAL_NAMESPACE')]:
   o,d=read(name)
   with self.assertRaises(C.ConstraintError)as e:C.run(o,d,budget=budget())
   self.assertEqual(e.exception.code,code)
if __name__=='__main__':unittest.main(verbosity=2)
