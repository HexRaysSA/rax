from pathlib import Path
from copy import deepcopy
import sys,json,hashlib,unittest
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'tools/smir-format/execution'),str(ROOT/'tools/smir-abi'),str(ROOT/'tools/smir-runtime-contract'),str(ROOT/'tools/smir-format')]
from candidate.context import RootContext
from candidate import root3_context as D
from .lifecycle_fixtures import fixture,budget
from .source_lifecycles import verify_lifecycle_associations as verify,LifecycleError

def original(variant='C1',mutate=None,mutate_roots=None):
 old,req,_=fixture(variant);roots=deepcopy(old.sections);b=budget(max_work=10**15,max_edges=10**12,max_copied_bytes=10**15)
 if mutate is not None:mutate(req)
 if mutate_roots is not None:mutate_roots(roots)
 roots[3].update(payload_revision=3,source_contract=D.codec().wire_contract(req['source_contract'],budget=b))
 raw=D.codec().encode_module(roots,budget=b);roots=D.codec().decode_module(raw,budget=b).roots
 owner=RootContext(roots,budget=b);stamp=RootContext.prepare_source_data(owner,budget=b);key=roots[2]['manifest']['key'];req['source_programs']['contexts'][0].update(family={n:key[n]for n in['namespace','name','abi_major']},abi_site=roots[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
 return owner,req,b,raw

class ActualV3(unittest.TestCase):
 def test_persisted_positive_and_rejection_fixtures(self):
  from dataclasses import asdict
  files=sorted((ROOT/'docs/specifications/smir/portable/conformance/abi/source-lifecycles').glob('*.json'))
  self.assertEqual(len(files),10)
  for path in files:
   with self.subTest(fixture=path.name):
    data=json.loads(path.read_text());b=budget(max_work=10**24,max_edges=10**24,max_copied_bytes=10**24)
    roots={int(k):v for k,v in data['sections'].items()};raw=D.codec().encode_module(roots,budget=b);roots=D.codec().decode_module(raw,budget=b).roots;owner=RootContext(roots,budget=b)
    if 'error'in data['expected']:
     with self.assertRaisesRegex(ValueError,data['expected']['error']):verify(owner,data['request'],budget=b)
    else:self.assertEqual([asdict(a)for a in verify(owner,data['request'],budget=b).associations],data['expected']['associations'])
 def test_five_original_full_v3_variants(self):
  for variant in ['C1','C2','D0','D1','D2']:
   with self.subTest(variant=variant):
    owner,d,b,raw=original(variant);stamp=owner.prepare_source_data(budget=b);r=verify(owner,d,budget=b)
    self.assertIs(r.owner,owner);self.assertIs(r.stamp,stamp);self.assertEqual(owner.sections[3]['payload_revision'],3);self.assertEqual(r.associations[0].variant,variant);self.assertFalse(r.source_fact_authority);self.assertFalse(r.runtime_authority);self.assertTrue(r.cost_profile_qualified);self.assertNotIn('ABI_LC_UNMETERED_FACTORY_PROFILE_NOT_QUALIFIED',r.obligations);self.assertFalse(r.executable);self.assertFalse(r.active_v3_verified);self.assertIsNone(owner.execution_checked)
 def test_actual_embedded_access_rejected_after_real_body(self):
  owner,d,b,_=original(mutate=lambda q:q['source_contract']['bindings'][0].__setitem__('access','destruction'))
  with self.assertRaises(LifecycleError)as e:verify(owner,d,budget=b)
  self.assertEqual(e.exception.code,'ABI_LC_THIS_ACCESS');self.assertTrue(owner.abi_checked);self.assertIsNone(owner.execution_checked)
 def test_actual_embedded_role_rejected(self):
  owner,d,b,_=original('C2',mutate=lambda q:q['source_contract']['bindings'][0].__setitem__('role','complete'))
  with self.assertRaises(LifecycleError)as e:verify(owner,d,budget=b)
  self.assertEqual(e.exception.code,'ABI_LC_THIS_ROLE')
 def test_actual_embedded_this_ssa_rejected(self):
  owner,d,b,_=original(mutate=lambda q:q['source_contract']['bindings'][0].__setitem__('value',1),mutate_roots=lambda roots:next(f for f in roots[3]['functions']if f['id']==1800)['blocks'][0]['ops'].append(dict(op='constant',results=[dict(id=1,type={'module':{'kind':'self'},'id':1002})],operands=[],literal=dict(kind='zero'))))
  with self.assertRaises(LifecycleError)as e:verify(owner,d,budget=b)
  self.assertEqual(e.exception.code,'ABI_LC_THIS_BINDING')
 def test_actual_embedded_always_explicit_profile_unavailable(self):
  owner,d,b,_=original(mutate=lambda q:q['source_contract']['phase_sites'][0].__setitem__('selector',{'kind':'always'}))
  with self.assertRaises(LifecycleError)as e:verify(owner,d,budget=b)
  self.assertEqual(e.exception.code,'ABI_LC_ENTRY_PROFILE_UNAVAILABLE')
 def test_replacement_external_contract_rejected(self):
  owner,d,b,_=original();d['source_contract']['phase_sites']=[]
  with self.assertRaises(LifecycleError)as e:verify(owner,d,budget=b)
  self.assertEqual(e.exception.code,'ABI_LC_V3_EMBEDDED_CONTRACT')
 def test_wrong_original_ledger_rejected(self):
  owner,d,b,_=original()
  with self.assertRaises(Exception):verify(owner,d,budget=budget())
 def test_source_mutation_rejected(self):
  owner,d,b,_=original();owner.sections[3]['source_contract']['revision']=2
  with self.assertRaises(Exception):verify(owner,d,budget=b)
if __name__=='__main__':unittest.main(verbosity=2)
