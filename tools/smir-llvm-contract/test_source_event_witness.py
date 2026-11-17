from pathlib import Path
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json,os,sys,tempfile,unittest,subprocess
from unittest.mock import patch
import source_event_witness as W
HERE=Path(__file__).resolve().parent
FIXTURES=W.PROJECT/'docs/specifications/smir/portable/conformance/llvm/source-events'
class SourceEvents(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.output=Path(tempfile.mkdtemp(prefix='source-event-tests-',dir=os.environ.get('CEW_TEST_DIR',tempfile.gettempdir())));cls.budget_api=W.R.apis()[4];oracle=os.environ.get('CEW_ORACLE');llvm=os.environ.get('LLVM_REFERENCE_CHECKOUT');
  if oracle:cls.oracle=Path(oracle)
  elif llvm:
   from build_source_event_witness import build
   cls.oracle=build(Path(llvm),cls.output/'native-build')
  else:raise ValueError('actual CEW_ORACLE or pinned LLVM_REFERENCE_CHECKOUT required; no skip/fallback')
  cls.main=W.observe(FIXTURES/'control.cpp',cls.oracle,budget=cls.budget()).report();cls.schema=json.loads(W.SCHEMA.read_text())
 @classmethod
 def budget(cls,**changes):
  x=dict(max_work=10**18,max_edges=10**12,max_copied_bytes=10**18,max_depth=128);x.update(changes);return cls.budget_api.SourceQueryBudget(**x)
 def observe(self,name):return W.observe(FIXTURES/name,self.oracle,budget=self.budget()).report()
 def case(self,text):
  p=self.output/('case'+str(len(list(self.output.glob('case*'))))+'.cpp');p.write_text(text);return p
 def function(self,report,name):
  d={x['id']:x for x in report['raw']['declarations']};return next(f for f in report['raw']['functions']if d[f['declaration']]['qualified_name']==name)
 def test_actual_control_and_original_coordinates(self):
  r=self.main;self.assertEqual(len(r['raw']['functions']),5);self.assertEqual(r['raw']['llvm_pin'],W.PIN);self.assertEqual(r['source_sha256'],W.digest((FIXTURES/'control.cpp').read_bytes()));self.assertEqual((r['binding'],r['runtime_authority'],r['source_fact_authority'],r['executable']),('unbound',False,False,False));self.assertEqual(r['schema_sha256'],W.SCHEMA_SHA)
 def test_actual_branch_temporary_constructor_and_returns(self):
  f=self.function(self.main,'branch');k=[e['kind']for b in f['blocks']for e in b['elements']];self.assertIn('constructor',k);self.assertIn('temporary_dtor',k);self.assertIn('automatic_object_dtor',k);self.assertTrue(any(len(b['successors'])==2 for b in f['blocks']));self.assertEqual(sum(n['stmt_class']=='ReturnStmt'for n in f['nodes']),2)
 def test_actual_aggregate_return_observations(self):
  f=self.function(self.main,'aggregate_return');self.assertTrue(any(n['stmt_class']=='InitListExpr'for n in f['nodes']));self.assertEqual(sum(n['stmt_class']=='ReturnStmt'for n in f['nodes']),2)
 def test_actual_exception_cfg_gap_is_preserved(self):
  f=self.function(self.main,'exception_cleanup');nodes={n['id']:n for n in f['nodes']};blocks={b['id']:b for b in f['blocks']};throw=[b['id']for b in blocks.values()if any(e['statement']is not None and nodes[e['statement']['some']]['stmt_class']=='CXXThrowExpr'for e in b['elements'])];catch={b['id']for b in blocks.values()if b['label']is not None and nodes[b['label']['some']]['stmt_class']=='CXXCatchStmt'};self.assertTrue(throw and catch)
  todo=[(x,False)for x in throw];seen=set();gap=False
  while todo:
   bid,dtor=todo.pop()
   if (bid,dtor)in seen:continue
   seen.add((bid,dtor));b=blocks[bid];dtor=dtor or any(e['kind']=='automatic_object_dtor'for e in b['elements'])
   if bid in catch and not dtor:gap=True
   todo.extend((e['reachable']['some'],dtor)for e in b['successors']if e['reachable']is not None)
  self.assertTrue(gap);self.assertTrue(any(e['kind']=='automatic_object_dtor'for b in blocks.values()for e in b['elements']));self.assertTrue(any('EH/lifetime' in x for x in self.main['obligations']))
 def test_actual_catch_variable_and_record_parent(self):
  raw=self.main['raw'];decls={d['id']:d for d in raw['declarations']};f=self.function(self.main,'exception_cleanup');catch=next(n for n in f['nodes']if n['stmt_class']=='CXXCatchStmt');self.assertEqual(len(catch['declarations']),1);self.assertEqual(decls[catch['declarations'][0]]['decl_kind'],'Var');ctor=self.function(self.main,'Item::Item');parent=decls[decls[ctor['declaration']]['semantic_parent']['some']];self.assertEqual(parent['decl_kind'],'CXXRecord')
 def test_canonical_forward_overload_and_shadow_identity(self):
  r=self.observe('identity.cpp');decls=r['raw']['declarations'];same=[d for d in decls if d['decl_kind']=='Function'and d['qualified_name']=='same'];self.assertEqual(len(same),2);self.assertNotEqual(same[0]['id'],same[1]['id']);self.assertTrue(all(d['canonical_offset']!=d['definition_offset']for d in same));a=[d for d in decls if d['decl_kind']=='Var'and d['qualified_name'].split('::')[-1]=='a'];self.assertEqual(len(a),2);self.assertNotEqual(a[0]['id'],a[1]['id']);self.assertNotEqual(a[0]['canonical_offset'],a[1]['canonical_offset'])
 def test_real_reference_temporary_and_loop_regions(self):
  r=self.observe('temporary.cpp');f=self.function(r,'reference_temporary');self.assertTrue(any(n['extending_decl']is not None and n['bound_to_lvalue_reference']for n in f['nodes']));loop=self.function(r,'loops');self.assertIn('ForStmt',[x['stmt_class']for x in loop['regions']]);self.assertTrue(any(n['stmt_class']=='BreakStmt'for n in loop['nodes']))
 def test_I_C27_array_trait_not_element_lifetime(self):
  r=self.observe('traits.cpp');values=[t['value']for t in r['raw']['traits_inspection']if t['trait']=='__builtin_is_implicit_lifetime'];self.assertEqual(values,[True,False,True,True,False]);self.assertFalse(r['source_fact_authority']);self.assertTrue(any('I-C27' in s for s in r['obligations']))
 def test_empty_translation_unit_boundary(self):
  p=self.case('');r=W.observe(p,self.oracle,budget=self.budget()).report();self.assertEqual(r['raw']['functions'],[]);self.assertEqual(r['raw']['declarations'],[])
 def test_true_frozen_constructor_false_flags(self):
  result=W.observe(FIXTURES/'control.cpp',self.oracle,budget=self.budget())
  with self.assertRaises(FrozenInstanceError):result.runtime_authority=True
  with self.assertRaises(TypeError):result.data['runtime_authority']=True
  with self.assertRaises(TypeError):W.EventWitness(result.data,runtime_authority=True)
  altered=result.report();altered['raw']['functions'].clear();self.assertTrue(result.report()['raw']['functions'])
 def test_actual_compiler_rejection_and_unsupported_profiles(self):
  bad=self.case('int bad( { invalid;')
  with self.assertRaises(W.EventError)as e:W.observe(bad,self.oracle,budget=self.budget())
  self.assertEqual(e.exception.kind,'input')
  for text in ['template<class T> T f(T x){return x;}','#define N 1\nint f(){return N;}','int f(){auto x=[](){return 1;};return x();}','struct X { virtual ~X(){} };','int *f(){return new int(1);}']:
   with self.subTest(text=text),self.assertRaises(W.EventError)as e:W.observe(self.case(text),self.oracle,budget=self.budget())
   self.assertEqual(e.exception.kind,'unavailable')
 def test_actual_source_afterguard_mutation(self):
  p=self.case('int value(){return 1;}');original=W.run_native
  def actual_then_mutate(*args,**kwargs):
   result=original(*args,**kwargs);p.write_text(p.read_text()+'\n');return result
  with patch.object(W,'run_native',actual_then_mutate),self.assertRaisesRegex(W.EventError,'source afterguard'):W.observe(p,self.oracle,budget=self.budget())
 def test_wrong_schema_and_native_input_guard(self):
  p=self.output/'schema.json';p.write_bytes(W.SCHEMA.read_bytes()+b' ')
  with patch.object(W,'SCHEMA',p),self.assertRaisesRegex(W.EventError,'schema pin'):W.observe(FIXTURES/'control.cpp',self.oracle,budget=self.budget())
  folder=self.output/'bad-native';folder.mkdir();binary=folder/'source-event-oracle';binary.write_bytes(self.oracle.read_bytes());binary.chmod(0o755);receipt=json.loads((self.oracle.parent/'build-receipt.json').read_text());receipt['input_hashes'][str(HERE/'source_event_witness.cpp')]='0'*64;(folder/'build-receipt.json').write_text(json.dumps(receipt))
  with self.assertRaisesRegex(W.EventError,'native build input changed'):W.observe(FIXTURES/'control.cpp',binary,budget=self.budget())
 def test_actual_normal_and_O_cli_identical(self):
  budget=self.output/'budget.json';budget.write_text(json.dumps(dict(max_work=10**18,max_edges=10**12,max_copied_bytes=10**18,max_depth=128)));outputs=[]
  for flags in [[],['-O']]:
   p=subprocess.run([sys.executable,'-B',*flags,str(HERE/'source_event_witness.py'),'observe','--oracle',str(self.oracle),'--source',str(FIXTURES/'control.cpp'),'--budget',str(budget)],capture_output=True,timeout=60);self.assertEqual(p.returncode,0,p.stderr.decode());outputs.append(p.stdout)
  self.assertEqual(outputs[0],outputs[1]);self.assertEqual(json.loads(outputs[0])['raw']['source_sha256'],self.main['source_sha256'])
 def test_forward_variable_definition_is_actual_later_decl(self):
  source=(FIXTURES/'forward-global.cpp').read_bytes();r=self.observe('forward-global.cpp');rows=[d for d in r['raw']['declarations']if d['qualified_name']=='global'];self.assertEqual(len(rows),1);self.assertEqual(rows[0]['canonical_offset'],{'some':source.index(b'global')});self.assertEqual(rows[0]['definition_offset'],{'some':source.index(b'global',source.index(b'global')+1)})
 def test_actual_base_and_member_cleanup_declarations(self):
  r=self.observe('subobjects.cpp');f=self.function(r,'Derived::~Derived');kinds=[e['kind']for b in f['blocks']for e in b['elements']];self.assertIn('base_dtor',kinds);self.assertIn('member_dtor',kinds)
 def test_actual_parallel_and_discarded_edges(self):
  r=self.observe('edges.cpp');f=self.function(r,'parallel_edges');self.assertTrue(any(len(b['successors'])>=2 for b in f['blocks']));self.assertEqual(r['raw']['source_filesystem'],'main-buffer-only-in-memory');self.assertIn('-fno-trigraphs',r['raw']['options'])
 def test_digraph_splice_and_header_mutation_reject(self):
  header=self.output/'outside.hpp';header.write_text('struct Outside { int member; };')
  for prefix in ['%:','%'+'\\'+'\n'+':','%'+'\\'+' \t'+'\n'+':','??=']:
   for contents in ['struct Outside { int member; };','struct Outside { long changed; };']:
    header.write_text(contents);source=prefix+'include '+json.dumps(str(header))+'\nint f(Outside x){return 1;}\n'
    with self.subTest(prefix=prefix),self.assertRaises(W.EventError)as e:W.observe(self.case(source),self.oracle,budget=self.budget())
    self.assertEqual(e.exception.kind,'unavailable')
class BuilderSupport:
 def setUp(self):
  self.output=Path(tempfile.mkdtemp(prefix='source-event-builder-guards-',dir=os.environ.get('CEW_TEST_DIR',tempfile.gettempdir())));self.fake_project=self.output/'fake-project';self.fake_project.mkdir();self.fake_llvm=self.output/'fake-llvm';self.fake_llvm.mkdir();self.bin=self.output/'bin';self.bin.mkdir()

 def git(self,value):
  p=self.bin/'git';p.write_text('#!'+sys.executable+'\nprint('+repr(value)+')\n');p.chmod(0o755)

 def call(self,llvm,output,flags=()):
  env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],CEW_REFERENCE_PROJECT=str(self.fake_project));return subprocess.run([sys.executable,'-B',*flags,str(HERE/'build_source_event_witness.py'),'--llvm',str(llvm),'--output',str(output)],capture_output=True,text=True,env=env,timeout=60)


class BuilderPureGuards(BuilderSupport,unittest.TestCase):
 def test_output_inside_fake_source_trees_normal_and_O(self):
  for flags in [[],['-O']]:
   for tree in [self.fake_llvm,self.fake_project]:
    out=tree/('forbidden-'+str(len(flags)));p=self.call(self.fake_llvm,out,flags);self.assertNotEqual(p.returncode,0);self.assertIn('CEW_BUILD_OUTPUT',p.stderr);self.assertFalse(out.exists())

 def test_wrong_pin_rejects_before_any_output_normal_and_O(self):
  self.git('wrong-pin')
  for flags in [[],['-O']]:
   out=self.output/('wrong-pin-'+str(len(flags)));p=self.call(self.fake_llvm,out,flags);self.assertIn('CEW_BUILD_PIN',p.stderr);self.assertFalse(out.exists())

 def test_wrong_compiler_rejects_before_any_output_normal_and_O(self):
  self.git(W.PIN);cc=self.fake_llvm/'build/bin/clang++';cc.parent.mkdir(parents=True);cc.write_text('not a pinned compiler')
  for flags in [[],['-O']]:
   out=self.output/('wrong-compiler-'+str(len(flags)));p=self.call(self.fake_llvm,out,flags);self.assertIn('CEW_BUILD_COMPILER',p.stderr);self.assertFalse(out.exists())


class BuilderNativeGuards(BuilderSupport,unittest.TestCase):
 def test_no_static_libraries_rejects_before_output_normal_and_O(self):
  self.git(W.PIN);receipt=json.loads((Path(os.environ['CEW_ORACLE']).parent/'build-receipt.json').read_text());cc=self.fake_llvm/'build/bin/clang++';cc.parent.mkdir(parents=True);cc.symlink_to(receipt['compiler']['path'])
  for flags in [[],['-O']]:
   out=self.output/('no-libraries-'+str(len(flags)));p=self.call(self.fake_llvm,out,flags);self.assertIn('CEW_BUILD_LIBRARIES',p.stderr);self.assertFalse(out.exists())

 def test_bad_compiler_version_rejects_without_output(self):
  import build_source_event_witness as B
  receipt=json.loads((Path(os.environ['CEW_ORACLE']).parent/'build-receipt.json').read_text());cc=self.fake_llvm/'build/bin/clang++';cc.parent.mkdir(parents=True);cc.symlink_to(receipt['compiler']['path']);out=self.output/'bad-version'
  def actual_negative_command(args):
   if str(args[0])=='git':return B.PIN
   if '--version'in args:return 'wrong version'
   raise AssertionError('unexpected command in negative preflight')
  with patch.object(B,'check',actual_negative_command),self.assertRaisesRegex(B.BuildError,'CEW_BUILD_COMPILER'):B.build(self.fake_llvm,out)
  self.assertFalse(out.exists())

 def test_actual_compile_then_copied_source_drift_rejects(self):
  import build_source_event_witness as B
  receipt=json.loads((Path(os.environ['CEW_ORACLE']).parent/'build-receipt.json').read_text());llvm=Path(receipt['compiler']['path']).parents[2];copy=self.output/'native-source';copy.mkdir();cpp=copy/'source_event_witness.cpp';cpp.write_bytes((HERE/'source_event_witness.cpp').read_bytes());out=self.output/'actual-build-drift';original=subprocess.run;mutated=[]
  def actual_compile_then_mutate(argv,*a,**kw):
   result=original(argv,*a,**kw)
   if str(cpp)in [str(x)for x in argv]and '-o'in argv:
    self.assertEqual(result.returncode,0,result.stderr);cpp.write_bytes(cpp.read_bytes()+b'\n');mutated.append(True)
   return result
  with patch.object(B,'HERE',copy),patch.object(B.subprocess,'run',actual_compile_then_mutate),self.assertRaisesRegex(B.BuildError,'CEW_BUILD_DRIFT'):B.build(llvm,out)
  self.assertEqual(mutated,[True]);record=json.loads((out/'build-receipt.json').read_text());self.assertEqual(record['exit'],0);self.assertIn(str(cpp.resolve()),record['drift'])



class SourceEventPureSchema(unittest.TestCase):
 """Frozen genuine fixture/actual schema and graph checks, no native tool needed."""
 @classmethod
 def setUpClass(cls):
  cls.output=Path(tempfile.mkdtemp(prefix='source-event-pure-',dir=os.environ.get('CEW_TEST_DIR',tempfile.gettempdir())));cls.oracle=Path('/nonexistent-source-event-oracle');cls.budget_api=W.R.apis()[4];cls.main=json.loads((FIXTURES/'native-control-r6.reference.json').read_text());cls.schema=json.loads(W.SCHEMA.read_text())
 @classmethod
 def budget(cls,**changes):
  x=dict(max_work=10**18,max_edges=10**12,max_copied_bytes=10**18,max_depth=128);x.update(changes);return cls.budget_api.SourceQueryBudget(**x)
 def test_closed_schema_bool_ids_and_flags(self):
  for key,value in [('id',True),('extra',True)]:
   raw=deepcopy(self.main['raw']);raw['functions'][0]['nodes'][0][key]=value
   with self.assertRaises(W.R.ProjectionError):W.R.shape(self.schema['$defs']['raw'],raw,self.schema['$defs'],self.budget())
  r=deepcopy(self.main);r['runtime_authority']=True
  with self.assertRaises(W.R.ProjectionError):W.R.shape(self.schema['$defs']['report'],r,self.schema['$defs'],self.budget())

 def test_semantic_bad_cfg_and_declaration_reference(self):
  for field in ['CFG','DECL']:
   raw=deepcopy(self.main['raw'])
   if field=='CFG':raw['functions'][0]['entry']=99999
   else:raw['functions'][0]['declaration']=99999
   with self.assertRaisesRegex(W.EventError,'CEW_GRAPH'):W.raw_semantics(raw,(FIXTURES/'control.cpp').read_bytes(),self.budget())

 def test_direct_graph_wrong_callee_and_nonreciprocal_edge(self):
  for label in ['callee','edge']:
   raw=deepcopy(self.main['raw'])
   if label=='callee':
    target=next(d['id']for d in raw['declarations']if d['decl_kind']=='ParmVar');node=next(n for f in raw['functions']for n in f['nodes']if n['direct_callee']is not None);node['direct_callee']={'some':target}
   else:
    f=raw['functions'][0];block=next(b for b in f['blocks']if any(e['reachable']is not None for e in b['successors']));edge=next(e for e in block['successors']if e['reachable']is not None);edge['reachable']={'some':block['id']}
   with self.subTest(label=label),self.assertRaisesRegex(W.EventError,'CEW_GRAPH'):W.raw_semantics(raw,(FIXTURES/'control.cpp').read_bytes(),self.budget())

 def test_budget_bootstrap_growth_closed_counts_and_depth(self):
  path=self.output/'bootstrap.json';path.write_text('{}');original=Path.stat;changed=[False]
  def grow(p,*a,**kw):
   info=original(p,*a,**kw)
   if p==path and not changed[0]:changed[0]=True;path.write_bytes(b'['*8192)
   return info
  with patch.object(Path,'stat',grow),self.assertRaisesRegex(W.EventError,'growth/size'):W.load_budget(path)
  for data in [b'['*20+b'0'+b']'*20,b'{"max_work":0,"max_work":1}',json.dumps(dict(max_work=True,max_edges=1,max_copied_bytes=1,max_depth=1)).encode(),json.dumps(dict(max_work=1<<64,max_edges=1,max_copied_bytes=1,max_depth=1)).encode()]:
   path.write_bytes(data)
   with self.assertRaises(W.EventError):W.load_budget(path)

 def test_budget_zero_prevents_native_process(self):
  seen=[]
  def audit(event,args):
   if event=='subprocess.Popen':seen.append(args)
  sys.addaudithook(audit);before=len(seen)
  with self.assertRaises(Exception)as e:W.observe(FIXTURES/'control.cpp',self.oracle,budget=self.budget(max_work=0))
  self.assertIn('RESOURCE',getattr(e.exception,'code',str(e.exception)));self.assertEqual(len(seen),before)


if __name__=='__main__':unittest.main(verbosity=2)
