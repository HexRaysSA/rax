"""Original source, geometry, view, context and resource witnesses; no runtime facts."""
from pathlib import Path
from copy import deepcopy
import json,sys,unittest,hashlib
ROOT=Path(__file__).resolve().parents[3]
FIXTURE=ROOT/'docs/specifications/smir/portable/conformance/abi/source-paths'

def setup_originals():
 global P,env,RootContext,codec,seal,ref,records,original
 sys.path.insert(0,str(ROOT/'tools/smir-format/execution'));sys.path.insert(0,str(ROOT/'tools/smir-format'))
 from . import source_paths as P
 from candidate.context import RootContext
 from codec import CandidateCodec
 from function_address.fixtures import source,layout,seal
 from nominal import ref
 env={'nominal':source,'layout':layout}
 schemas={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes()) for n in ('abi','execution','runtime')}
 codec=CandidateCodec(schemas);records=json.loads((FIXTURE/'records.json').read_bytes())
 original=codec.decode((FIXTURE/'source.smo').read_bytes()).roots

def budget(**kw):
 policy=dict(max_work=10**15,max_edges=10**10,max_copied_bytes=10**12,max_depth=128);policy.update(kw);return P._api().SourceQueryBudget(**policy)
def owner(roots=None):return RootContext(codec.decode(codec.encode(seal(deepcopy(original if roots is None else roots)))).roots)
def member(i):return dict(kind='member',declaration_index=i)
def base(i,virtual=False):return dict(kind='base',declaration_index=i,virtual=virtual)
def element(first,count=1):return dict(kind='element',selection=dict(first=first,count=count))
def document(root='D',routes=None,leaf='V',view='complete',label='cell'):
 return dict(format='original-source-paths',revision=1,binding='unbound',runtime_authority=False,source_fact_authority=False,
  root=ref(records[root] if type(root)is str else root),view=view,selectors=[dict(label=label,declared_leaf=ref(records[leaf] if type(leaf)is str else leaf),routes=routes or [[base(0),base(0,True)]])])

class CanonicalSourcePaths(unittest.TestCase):
 def rejected(self,code,doc,raw=None,policy=None,kind='semantic'):
  with self.assertRaises(P._api().SourceDataError) as caught:P.resolve_source_paths(owner(raw),doc,budget=policy or budget())
  self.assertEqual((caught.exception.code,caught.exception.kind),(code,kind))
 def test_exact_closed_schema(self):
  mutations=[lambda d:d.update(revision=True),lambda d:d.update(extra=1),lambda d:d.update(binding='bound'),lambda d:d.update(runtime_authority=True),lambda d:d['selectors'][0].update(routes=[]),lambda d:d['selectors'][0]['routes'][0][0].update(declaration_index=True),lambda d:d['root'].update(id=0xffffffff),lambda d:d['root'].update(module=dict(kind='dependency',slot=True))]
  for change in mutations:
   d=document();change(d)
   with self.subTest(document=d):self.rejected('ABI_PATH_SHAPE',d)
 def test_original_root_stamp_and_noauthority(self):
  o=owner();b=budget();p=P.resolve_source_paths(o,document(),budget=b)
  self.assertIs(p.owner,o);self.assertIs(p.stamp,o.prepare_source_data(budget=b));self.assertFalse(p.runtime_authority);self.assertFalse(p.source_fact_authority);self.assertEqual(p.patterns[0].offset_constant_bits,256)
  with self.assertRaises(AttributeError):p.binding='bound'
  for flag,val in [('binding','bound'),('runtime_authority',True),('source_fact_authority',True)]:
   with self.assertRaises(TypeError):P.OriginalSourcePaths(o,p.stamp,(),(),'complete',(),(),(),**{flag:val})
 def test_compiled_diamond_and_member_alternatives(self):
  b0=[base(0),base(0,True)];b1=[base(1),base(0,True)]
  for root,prefix in [('D',[]),('Box',[member(0)])]:
   result=P.resolve_source_paths(owner(),document(root,[prefix+b0,prefix+b1]),budget=budget());self.assertEqual(len(result.patterns),1);self.assertFalse(result.deferred)
 def test_distinct_nonvirtual_and_equaloffset_cells(self):
  cases=[('NVD',[base(0),base(0)],[base(1),base(0)],'V'),('Box',[member(0)],[member(1)],'D'),('EmptyBases',[base(0)],[base(1)],None),('Choice',[member(0)],[member(1)],None)]
  for root,a,z,leaf in cases:
   left=document(root,[a],leaf or ('B1' if root=='EmptyBases' else 'V'));right=document(root,[z],leaf or ('B2' if root=='EmptyBases' else 10002));r=P.compare_source_paths(owner(),left,'cell',right,'cell',budget=budget());self.assertEqual(r.relation,'disjoint')
 def test_array_symbolic_overlap_and_disjoint(self):
  tail=[base(0),base(0,True)]
  def d(first,count):return document('Box',[[member(2),element(first,count),element(0,3)]+tail])
  for a,z,want in [((0,2),(1,1),'overlap'),((0,1),(1,1),'disjoint'),((1,1),(1,1),'equal')]:
   with self.subTest(a=a,z=z):self.assertEqual(P.compare_source_paths(owner(),d(*a),'cell',d(*z),'cell',budget=budget()).relation,want)
 def test_multidimensional_alternatives(self):
  p=[member(2),element(0,2),element(0,3)];d=document('Box',[p+[base(0),base(0,True)],p+[base(1),base(0,True)]])
  r=P.resolve_source_paths(owner(),d,budget=budget());self.assertEqual([(x.extent,x.count) for x in r.patterns[0].axes],[(2,2),(3,3)]);self.assertEqual(r.patterns[0].offset_coefficients_bits,(960,320))
 def test_root_views_retained(self):
  a=document('D',[[]],'D');z=deepcopy(a);z['view']='nonvirtual';r=P.compare_source_paths(owner(),a,'cell',z,'cell',budget=budget());self.assertEqual(r.relation,'equal');self.assertFalse(r.same_coverage_view);self.assertNotEqual(r.left.width_bits,r.right.width_bits)
 def test_unknown_nvroot_has_no_geometry(self):
  d=document(view='nonvirtual');r=P.resolve_source_paths(owner(),d,budget=budget());self.assertFalse(r.patterns);self.assertEqual([x.code for x in r.deferred],['ABI_PATH_NV_MOST_DERIVED_UNAVAILABLE'])
  with self.assertRaises(P._api().SourceDataError) as caught:P.compare_source_paths(owner(),d,'cell',document(),'cell',budget=budget())
  self.assertEqual(caught.exception.kind,'unavailable')
 def test_known_nvmember_class_reset(self):
  d=document('Box',[[member(0),base(0),base(0,True)]],view='nonvirtual');r=P.resolve_source_paths(owner(),d,budget=budget());self.assertEqual(len(r.patterns),1);self.assertEqual(r.patterns[0].root_view,'nonvirtual');self.assertTrue(r.patterns[0].most_derived_skeleton)
 def test_deferred_nv_then_known_bad_index(self):self.rejected('ABI_PATH_DECLARATION_INDEX',document(routes=[[base(0),base(0,True),member(99)]],leaf=10002,view='nonvirtual'))
 def test_deferred_nv_then_bad_alternative(self):self.rejected('ABI_PATH_DECLARATION_INDEX',document(routes=[[base(0),base(0,True)],[base(99)]],view='nonvirtual'))
 def test_duplicate_and_distinct_alternatives(self):
  self.rejected('ABI_PATH_ROUTE_DUPLICATE',document(routes=[[base(0),base(0,True)],[base(0),base(0,True)]]))
  self.rejected('ABI_PATH_ALTERNATIVE_CELL',document('NVD',[[base(0),base(0)],[base(1),base(0)]]))
 def test_bad_source_indices_virtual_flags_and_leaf(self):
  for d,c in [(document(routes=[[base(99)]]),'ABI_PATH_DECLARATION_INDEX'),(document(routes=[[base(0),base(0,False)]]),'ABI_PATH_BASE_DECLARATION'),(document(leaf='E'),'ABI_PATH_DECLARED_LEAF')]:self.rejected(c,d)
 def test_bad_array_bound_and_count(self):
  self.rejected('ABI_PATH_ARRAY_BOUNDS',document('Box',[[member(2),element(2),element(0)]],'D'))
  self.rejected('ABI_PATH_SHAPE',document('Box',[[member(2),element(0,0),element(0)]],'D'))
  self.rejected('ABI_PATH_ARRAY_BOUNDS',document('Box',[[member(2),element(2**64-1,2),element(0)]],'D'))
 def test_bad_field_base_and_primitive_geometry(self):
  mutations=[('Box','ABI_PATH_FIELD_GEOMETRY',lambda r:next(l for l in r[10]['layouts'] if l['id']==records['Box'])['fields'][0].update(offset_bits=8)),('D','ABI_PATH_BASE_GEOMETRY',lambda r:next(l for l in r[10]['layouts'] if l['id']==records['D'])['bases'][-1].update(offset=40)),('D','ABI_PATH_SCALAR_SIGNEDNESS',lambda r:next(t for t in r[10]['types'] if t['id']==10002).update(signed=False))]
  for root,code,mutate in mutations:
   raw=deepcopy(original);mutate(raw);d=document(root,[[member(0)]+([base(0),base(0,True)] if root=='Box' else [])],leaf='V' if root=='Box' else 10002);self.rejected(code,d,raw)
 def test_missing_input_does_not_hide_later_selector(self):
  raw=deepcopy(original);next(t for t in raw[10]['types'] if t['id']==records['V'])['record_input']=None
  d=document();second=deepcopy(d['selectors'][0]);second.update(label='later',routes=[[base(77)]]);d['selectors'].append(second);self.rejected('ABI_PATH_DECLARATION_INDEX',d,raw)
 def test_samebyte_contexts_and_budget_identity(self):
  a,z=owner(),owner();b=budget();pa=P.resolve_source_paths(a,document(),budget=b);pz=P.resolve_source_paths(z,document(),budget=b);self.assertIsNot(pa.stamp,pz.stamp);self.assertIsNot(pa.stamp.context_anchor,pz.stamp.context_anchor)
  with self.assertRaises(P._api().SourceDataError) as caught:P.resolve_source_paths(a,document(),budget=budget())
  self.assertEqual(caught.exception.code,'SOURCE_DATA_CONTEXT')
 def test_source_mutation_and_canonical_zero_quotas(self):
  o=owner();b=budget();P.resolve_source_paths(o,document(),budget=b);o.sections[10]['identity']='00'*32
  with self.assertRaises(Exception) as caught:P.resolve_source_paths(o,document(),budget=b)
  self.assertEqual(getattr(caught.exception,'code',None),'context_snapshot_changed')
  for dimension in ('max_work','max_edges','max_copied_bytes'):
   self.rejected('SOURCE_DATA_RESOURCE',document(),policy=budget(**{dimension:0}),kind='resource')
 def test_cycles_depth_and_noncanonical_budget(self):
  d=document();d['selectors'].append(d);self.rejected('ABI_PATH_CYCLE',d)
  self.rejected('SOURCE_DATA_RESOURCE',document(),policy=budget(max_depth=2),kind='resource')
  with self.assertRaises(P._api().SourceDataError):P.resolve_source_paths(owner(),document(),budget=object())


 def test_symbolic_huge_array_no_extent_walk(self):
  raw=deepcopy(original);n=1<<40
  raw[10]['types'].append(env['nominal'](50000,'array',elements=[records['D']],extent=n,layout_id=50000,execution=60000,representation='value',flags=['complete']))
  raw[10]['layouts'].append(env['layout'](50000,40*n,8));raw[1]['types'].append(dict(id=60000,kind='array',element=ref(20005),count=n))
  d=document(50000,[[element(0,n),base(0),base(0,True)]],'V');r=P.resolve_source_paths(owner(raw),d,budget=budget())
  self.assertEqual(len(r.patterns),1);self.assertEqual(r.patterns[0].axes[0].count,n);self.assertEqual(r.patterns[0].offset_coefficients_bits,(320,))
 def test_class_alias_conflict_and_equivalent(self):
  for bad in (False,True):
   raw=deepcopy(original);alias=deepcopy(next(t for t in raw[10]['types'] if t['id']==records['V']));alias['id']=45000
   if bad:alias['record_input']['some']['fields'][0]['name']={'some':'conflict'}
   raw[10]['types'].append(alias)
   if bad:self.rejected('ABI_PATH_CLASS_CONFLICT',document(),raw)
   else:self.assertEqual(len(P.resolve_source_paths(owner(raw),document(),budget=budget()).patterns),1)
 def test_real_afterguard_quota_and_mutation(self):
  from unittest.mock import patch
  original_prepare=RootContext.prepare_source_data;o=owner();b=budget();seen=[]
  def measured(current,*,budget):seen.append(budget._used_work);return original_prepare(current,budget=budget)
  with patch.object(RootContext,'prepare_source_data',measured):P.resolve_source_paths(o,document(),budget=b)
  self.assertEqual(len(seen),2)
  for mutate in (False,True):
   o=owner();limited=budget() if mutate else budget(max_work=seen[-1]+1);calls=[]
   def observe(current,*,budget):
    calls.append(budget._used_work)
    if len(calls)==2 and mutate:current.sections[10]['identity']='00'*32
    return original_prepare(current,budget=budget)
   with self.assertRaises(Exception) as caught,patch.object(RootContext,'prepare_source_data',observe):P.resolve_source_paths(o,document(),budget=limited)
   self.assertEqual(len(calls),2)
   if mutate:self.assertEqual(getattr(caught.exception,'code',None),'context_snapshot_changed')
   else:self.assertEqual(caught.exception.kind,'resource')
 def test_coverage_real_program_and_later_mismatch(self):
  from record_layout.test_source_programs import document as source_document
  raw=deepcopy(original);keep=lambda row:row['id']<10000 or row['id'] in (10001,10002)
  raw[10]['types']=[x for x in raw[10]['types'] if keep(x)];raw[10]['layouts']=[x for x in raw[10]['layouts'] if keep(x)]
  raw[10]['journals'].append(dict(id=700,signature=201,params=[],slots=[],normal_order=[],exception_order=[]))
  o=owner(raw);b=budget();stamp=o.prepare_source_data(budget=b);o.verify_abi()
  d=source_document();d['records'][0].update(name='V',source=dict(context=0,nominal=ref(10001)));d['records'][0]['slots'][0]['source']['nominal']=ref(10002)
  key=o.sections[2]['manifest']['key'];d['contexts'][0].update(family={k:key[k] for k in ('namespace','name','abi_major')},abi_site=o.sections[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
  paths=document('V',[[member(0)]],10002);r=P.check_source_coverage(d,paths,o,0,0,budget=b);self.assertEqual(r.memberships,(('cell','member',0),));self.assertIs(r.stamp,stamp)
  duplicate=deepcopy(paths);second=deepcopy(duplicate['selectors'][0]);second['label']='other';duplicate['selectors'].append(second)
  with self.assertRaises(P._api().SourceDataError) as caught:P.check_source_coverage(d,duplicate,o,0,0,budget=b)
  self.assertEqual(caught.exception.code,'ABI_PATH_COVERAGE_DUPLICATE')
  wrong=deepcopy(paths);wrong['view']='nonvirtual'
  with self.assertRaises(P._api().SourceDataError) as caught:P.check_source_coverage(d,wrong,o,0,0,budget=b)
  self.assertEqual(caught.exception.code,'ABI_PATH_COVERAGE_VIEW')

 def test_private_tuuid_same_owner_distinct_cells(self):
  from nominal import unit_identity,some
  raw=deepcopy(original);first=next(t for t in raw[10]['types'] if t['id']==records['V']);key=raw[2]['manifest']['key']
  first['identity'].update(linkage='internal',unit=some(unit_identity(key['namespace'],key['name'],key['abi_major'],'unitA')))
  second=deepcopy(first);second['id']=45000;second['layout']=some(45000);second['identity']['unit']=some(unit_identity(key['namespace'],key['name'],key['abi_major'],'unitB'));raw[10]['types'].append(second)
  shape=deepcopy(next(l for l in raw[10]['layouts'] if l['id']==records['V']));shape.update(id=45000,type=ref(45000));raw[10]['layouts'].append(shape)
  a=document('V',[[]],'V');z=document(45000,[[]],45000);r=P.compare_source_paths(owner(raw),a,'cell',z,'cell',budget=budget());self.assertEqual(r.relation,'disjoint')
 def test_layout_source_backreference(self):
  raw=deepcopy(original);next(l for l in raw[10]['layouts'] if l['id']==records['V'])['type']=ref(records['E'])
  self.rejected('ABI_PATH_LAYOUT_BINDING',document(),raw)
 def test_missing_original_namespace_rejects(self):
  d=document();d['root']['module']=dict(kind='dependency',slot=999);self.rejected('ABI_PATH_ORIGINAL_REFERENCE',d)
 def test_actual_whole_abi_virtual_target_guard_is_preserved(self):
  o=owner()
  with self.assertRaises(Exception) as caught:o.verify_abi()
  self.assertEqual(str(caught.exception),'ABI_CC_VBASE_TARGET_METADATA_UNAVAILABLE')

class OriginalSourcePathHarness(unittest.TestCase):pass

def delegated_test(name):
 def run(self):
  import subprocess,os
  command=[sys.executable,'-B','-m','record_layout.test_source_paths','--case',name]
  result=subprocess.run(command,cwd=ROOT/'tools/smir-abi',env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertIn('Ran 1 test',result.stderr)
 return run

for name in vars(CanonicalSourcePaths):
 if name.startswith('test_'):setattr(OriginalSourcePathHarness,name,delegated_test(name))

def load_tests(loader,tests,pattern):
 return loader.loadTestsFromTestCase(OriginalSourcePathHarness)

if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--case':
  setup_originals();result=unittest.TextTestRunner(verbosity=2).run(CanonicalSourcePaths(sys.argv[2]));raise SystemExit(not result.wasSuccessful())
 else:unittest.main()

