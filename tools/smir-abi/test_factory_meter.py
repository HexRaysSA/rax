"""Finite ABI logical-meter witnesses; no runtime execution or admission."""
import sys,unittest,importlib.util,json,hashlib
from pathlib import Path
from copy import deepcopy
R=Path(__file__).resolve().parents[2];D=Path(__file__).resolve().parent
sys.path[:0]=[str(R/'tools/smir-format/execution'),str(R/'tools/smir-abi')]
from record_layout.test_source_programs import budget,q
from function_address.fixtures import ordinary,source,layout,seal
from nominal import NominalGraph as Original
from nominal import NominalGraph
from graph_identity import canonical_quotient as original_q
from graph_identity import canonical_quotient
from record_layout.materialization import _api

def stats(b):return dict(work=b._used_work,edges=b._used_edges,copied_bytes=b._used_copied_bytes)
def quota(s,delta=0):return budget(max_work=s['work']+delta,max_edges=s['edges'],max_copied_bytes=s['copied_bytes'])
def calls(fn):
 hits={}
 def trace(frame,event,arg):
  if event=='call':
   key=frame.f_code.co_filename+':'+frame.f_code.co_name;hits[key]=hits.get(key,0)+1
 sys.setprofile(trace)
 try:fn()
 finally:sys.setprofile(None)
 return hits

class KernelTests(unittest.TestCase):
 def test_quotients(self):
  cases=[({0:{'s':'int'}},{0:[]},0),({0:{'s':'p'},1:{'s':'p'}},{0:[1],1:[0]},0),({7:{'s':'f'},1:{'s':'i'},2:{'s':'i'}},{7:[1,2],1:[],2:[]},7),({0:{'s':'a'},1:{'s':'a'},2:{'s':'b'}},{0:[1],1:[2],2:[2]},0),({0:{'x':'\u0000\u00df\U0001f600'},1:{'x':'long'*256}},{0:[1],1:[]},0)]
  for labels,edges,root in cases:
   with self.subTest(root=root,labels=len(labels)):
    f=json.loads((R/'docs/specifications/smir/portable/conformance/abi/factory-meter/quotients.json').read_text());static=next(x for x in f['cases']if x['labels']=={str(a):v for a,v in labels.items()})
    expected=static['expected_ascii'].encode('ascii');self.assertEqual(canonical_quotient(labels,edges,root),expected)
    b=budget();self.assertEqual(canonical_quotient(labels,edges,root,budget=b),expected);s=stats(b)
    self.assertEqual(canonical_quotient(labels,edges,root,budget=quota(s)),expected)
    with self.assertRaises(_api().SourceDataError) as e:canonical_quotient(labels,edges,root,budget=quota(s,-1))
    self.assertEqual(e.exception.code,'SOURCE_DATA_RESOURCE')
 def test_nominal_all_genuine_fixture_types(self):
  roots=ordinary(complete_record=True);old=Original(roots[10],'a');none=NominalGraph(roots[10],'a');b=budget();new=NominalGraph(roots[10],'a',budget=b)
  for t in roots[10]['types']:
   r=q(t['id']);self.assertEqual(new.fingerprint(r),old.fingerprint(r));self.assertEqual(none.fingerprint(r),old.fingerprint(r))
   self.assertEqual(new.compatible(r,r),old.compatible(r,r))
   if t['kind']in('scalar','pointer','reference','record') and t['layout'] is not None:self.assertEqual(new.value_mask(r),old.value_mask(r))
  self.assertGreater(b._used_work,0)
 def test_compatible_negative(self):
  roots=ordinary(complete_record=True);old=Original(roots[10],'a');new=NominalGraph(roots[10],'a',budget=budget())
  for a in roots[10]['types']:
   for b in roots[10]['types']:self.assertEqual(new.compatible(q(a['id']),q(b['id'])),old.compatible(q(a['id']),q(b['id'])))
 def test_nominal_deepcopy_retains_ledger(self):
  roots=ordinary(complete_record=True);b=budget();g=NominalGraph(roots[10],'a',budget=b);h=deepcopy(g)
  self.assertIs(h.budget,b);self.assertIsNot(h.modules,g.modules);self.assertEqual(h.fingerprint(q(100)),g.fingerprint(q(100)))
 def test_zero_before_json_serializer(self):
  b=budget(max_work=0);seen={}
  def run():
   with self.assertRaises(_api().SourceDataError):canonical_quotient({0:{'x':'a'*4096}},{0:[]},0,budget=b)
  seen=calls(run);self.assertEqual(sum(v for k,v in seen.items()if '/json/'in k),0)
 def test_huge_mask_geometry_rejected_before_shift(self):
  roots=ordinary(complete_record=True);g=NominalGraph(roots[10],'a',budget=budget());g.layouts['a'][100]['fields'][0]['offset_bits']=1<<50
  with self.assertRaisesRegex(Exception,'ABI_FACTORY_COST_UNAVAILABLE'):g.value_mask(q(100))
 def test_exact_constructor_quota(self):
  roots=ordinary(complete_record=True);b=budget();NominalGraph(roots[10],'a',budget=b);s=stats(b)
  NominalGraph(roots[10],'a',budget=quota(s))
  with self.assertRaises(_api().SourceDataError):NominalGraph(roots[10],'a',budget=quota(s,-1))
 def test_wrong_budget_class(self):
  with self.assertRaisesRegex(ValueError,'ABI_FACTORY_BUDGET_CLASS'):NominalGraph(ordinary()[10],'a',budget=object())

class ShapeTests(unittest.TestCase):
 def test_actual_shapes_all_records(self):
  from execution_shapes import ExecutionShapes as Old
  from execution_shapes import ExecutionShapes as New
  records=ordinary(complete_record=True)[1]['types'];old=Old(records);none=New(records);b=budget();new=New(records,budget=b)
  for item in records:
   r=q(item['id']);self.assertEqual(new.describe(r),old.describe(r));self.assertEqual(none.describe(r),old.describe(r))
  for a in records:
   for c in records:self.assertEqual(new.equal(q(a['id']),q(c['id'])),old.equal(q(a['id']),q(c['id'])))
  before=stats(b);new.digest(q(records[0]['id']));self.assertGreater(b._used_work,before['work'])
 def test_actual_function_code_cycle(self):
  from execution_shapes import ExecutionShapes as Old
  from execution_shapes import ExecutionShapes as New
  records=[dict(id=0,kind='function',cc='portable',variadic=False,params=[q(1)],results=[],param_noundef=[True],result_noundef=[]),dict(id=1,kind='code_ptr',signature=q(0))]
  self.assertEqual(New(records,budget=budget()).describe(q(0)),Old(records).describe(q(0)))
 def test_shape_deepcopy_same_budget(self):
  from execution_shapes import ExecutionShapes
  b=budget();g=ExecutionShapes(ordinary()[1]['types'],budget=b);g.digest(q(1));h=deepcopy(g)
  self.assertIs(h.budget,b);self.assertEqual(g.describe(q(1)),h.describe(q(1)))
 def test_shape_zero_before_serializer(self):
  from execution_shapes import ExecutionShapes
  records=ordinary()[1]['types'];probe=budget();ExecutionShapes(records,budget=probe);b=budget(max_work=probe._used_work);g=ExecutionShapes(records,budget=b)
  def run():
   with self.assertRaises(_api().SourceDataError):g.digest(q(1))
  seen=calls(run);self.assertEqual(sum(v for k,v in seen.items()if '/json/'in k),0)
 def test_shape_exact_one_less(self):
  from execution_shapes import ExecutionShapes
  records=ordinary()[1]['types']
  def run(b):return ExecutionShapes(records,budget=b).digest(q(1))
  b=budget();expected=run(b);s=stats(b);self.assertEqual(run(quota(s)),expected)
  with self.assertRaises(_api().SourceDataError):run(quota(s,-1))


from candidate.context import RootContext
_spec=importlib.util.spec_from_file_location('abi_factory_meter_test_candidate',R/'tools/smir-abi/candidate.py')
C=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=C;_spec.loader.exec_module(C)
def roots():return {int(k):v for k,v in json.loads((R/'docs/specifications/smir/portable/conformance/runtime/source-contracts/sret-published-factory.json').read_text())['sections'].items()}
def context(owner,b=None):
 key=owner.sections[2]['manifest']['key'];name=key['namespace']+':'+key['name']+':'+str(key['abi_major'])
 return C.Context(name,owner.abi_execution,owner.symbol,owner.metadata,{}, {},owner.native_type if hasattr(owner,'native_type')else lambda ref: {},lambda ref:{},{name:('family',)},owner.memory_layout,nominal_expectations={name:{}},factory_budget=b)
def original_module():
 spec=importlib.util.spec_from_file_location('abi_factory_original_for_test',R/'tools/smir-abi/candidate.py');m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
class ActualShellTests(unittest.TestCase):
 def test_legacy_wrong_metadata_callback_diagnostic(self):
  o=RootContext(roots());c=context(o);c.metadata(q(0)) if False else None
  # Actual Context wrapper must retain its ABI error for a wrong callback type.
  c=C.Context('a',o.abi_execution,o.symbol,lambda ref:None,{}, {},lambda ref:{},lambda ref:{},{},o.memory_layout)
  with self.assertRaisesRegex(Exception,'ABI_CC_METADATA_EVIDENCE'):c.metadata(q(0))
 def test_genuine_array_backed_record_storage(self):
  d=roots();storage=next(x for x in d[1]['types']if x['id']==1010);storage.clear();storage.update(id=1010,kind='array',count=4,element=q(991));d[1]['types'].append(dict(id=991,kind='raw',bits=8));d[1]['types'].sort(key=lambda x:x['id']);d[1]['memory_layouts'].append(dict(id=4991,type=q(991),size=1,alignment=1,access_bytes=1,fields=[],element=None,stride=0));d[1]['memory_layouts'].sort(key=lambda x:x['id']);memory=next(x for x in d[1]['memory_layouts']if x['id']==5010);memory.update(element={'some':q(4991)},stride=8);o=RootContext(d);expected=o.verify_abi();b=budget();seen=[]
  def trace(frame,event,arg):
   if event=='call'and frame.f_code.co_name=='__init__'and frame.f_code.co_filename.endswith('/execution_shapes.py'):seen.append(frame.f_locals.get('budget'))
  sys.setprofile(trace)
  try:actual=C.verify(o.abi,context(o,b))
  finally:sys.setprofile(None)
  self.assertEqual(actual,expected);self.assertTrue(seen);self.assertTrue(all(x is b for x in seen))
 def test_genuine_published_abi_original_and_metered(self):
  o=RootContext(roots());expected=o.verify_abi();o.verify_execution();b=budget();out=C.verify(o.abi,context(o,b));self.assertEqual(out,expected);self.assertFalse(out['admitted_for_execution']);self.assertGreater(b._used_work,0)
 def test_legacy_none_original_complete_fixture(self):
  o=RootContext(ordinary(complete_record=True));expected=o.verify_abi();self.assertEqual(C.verify(o.abi,context(o)),expected)
 def test_actual_shell_exact_and_one_less(self):
  o=RootContext(roots())
  def run(b):return C.verify(o.abi,context(o,b))
  b=budget();expected=run(b);s=stats(b);self.assertEqual(run(quota(s)),expected)
  with self.assertRaises(_api().SourceDataError):run(quota(s,-1))
 def test_zero_before_any_abi_factory(self):
  o=RootContext(roots());c=context(o,budget())
  c.factory_budget=budget(max_work=0)
  def run():
   with self.assertRaises(_api().SourceDataError):C.verify(o.abi,c)
  seen=calls(run)
  self.assertEqual(sum(v for k,v in seen.items()if k.endswith(':__init__')and ('nominal' in k or 'checked'in k)),0)
 def test_unsupported_nominal_array_before_graph(self):
  o=RootContext(ordinary());c=context(o,budget())
  def run():
   with self.assertRaisesRegex(Exception,'ABI_FACTORY_COST_UNAVAILABLE'):C.verify(o.abi,c)
  seen=calls(run);self.assertEqual(sum(v for k,v in seen.items()if 'nominal' in k and k.endswith(':__init__')),0)
 def test_actual_semantic_wrong_definition_rejected(self):
  o=RootContext(roots());d=json.loads(json.dumps(o.abi));d['types'][0]['identity']['definition']='0'*64
  with self.assertRaisesRegex(Exception,'ABI_CC_DEFINITION_HASH'):C.verify(d,context(o,budget()))

if __name__=='__main__':unittest.main(verbosity=2)
