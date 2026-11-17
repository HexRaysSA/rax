from pathlib import Path
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json,unittest
from . import checker as C
from codec import CandidateCodec
R=C.ROOT;O=C.ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts'
SCHEMAS={n:json.loads((R/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in['abi','execution','runtime']}
def owner():return C.RootContext(CandidateCodec(SCHEMAS).decode((O/'original-pointer.smo').read_bytes()).roots)
def budget(**changes):
 p=dict(max_work=10**8,max_edges=10**7,max_copied_bytes=10**8,max_depth=128);p.update(changes);return C.source_api().SourceQueryBudget(**p)
def ref(n):return dict(module=dict(kind='self'),id=n)
def base():
 b=dict(id=0,function=0,value=0,source_class=ref(1),static_pointer_type=ref(500),access='ordinary',subject=dict(root_nominal=ref(1),root_view='complete',required_leaf_view='complete',edges=[]),role='complete',origin=dict(kind='incoming_parameter',plan=ref(0),source_index=0,lowered_index=0))
 return dict(format='draft-source-alias-compiler-constraints',revision=4,draft_sha256='28db5402d408528b02aac917c53bf94f98ffe7d4b0fe49760dd3b0015cc1c029',contract=dict(revision=1,bindings=[b],scopes=[],scope_values=[],exits=[],phase_sites=[],ends=[],returns=[],adoptions=[]),proposed_operations=[])
def scoped():
 d=base();c=d['contract'];entry=dict(kind='entry',block=0);pre=dict(kind='pre_terminator',block=0);out=dict(kind='pre_terminator',block=3);outside=dict(kind='outside')
 c['scopes']=[dict(id=0,function=0,enter=entry,enter_value=0,subject='existing_object',binding=0,program=None,view=None,within=outside,lifecycle=None)]
 c['scope_values']=[dict(id=0,function=0,origin=dict(kind='enter',scope=0,phase=100)),dict(id=1,function=0,origin=dict(kind='copy',source=0,site=pre)),dict(id=2,function=0,origin=dict(kind='select',site=pre,condition=10,if_true=0,if_false=1)),dict(id=3,function=0,origin=dict(kind='phi',block=3,incoming=[dict(predecessor=1,value=2),dict(predecessor=2,value=0)]))]
 c['exits']=[dict(id=0,function=0,scope_value=3,site=out,outcome=dict(kind='normal_no_journal'))]
 c['phase_sites']=[dict(id=100,function=0,site=entry,within=outside,event=dict(kind='object_attach_incoming',scope=0,binding=0)),dict(id=17,function=0,site=pre,within=outside,event=dict(kind='scope_value',value=1)),dict(id=4,function=0,site=pre,within=outside,event=dict(kind='scope_value',value=2)),dict(id=1,function=0,site=out,within=dict(kind='scope',value=3),event=dict(kind='scope_exit',exit=0))]
 for p in c['phase_sites']:p['selector']=dict(kind='always')
 return d
def matrix():
 rows={}
 def put(n,d,code=None):rows[n]=dict(document=d,expected='constraints'if code is None else'reject',code=code)
 put('original_pointer_formal',base());put('original_cfg_shadow_phi_select',scoped())
 d=base();b=deepcopy(d['contract']['bindings'][0]);b.update(id=1,value=2,origin=dict(kind='retained_alias',binding=0,value=0));d['contract']['bindings'].append(b);put('original_pointer_phi_transport',d)
 edits=[('wrong_original_function',lambda d:d['contract']['bindings'][0].update(function=999),'ASC_FUNCTION'),('wrong_original_ssa',lambda d:d['contract']['bindings'][0].update(value=999),'ASC_ORIGINAL_SSA'),('wrong_static_pointer_kind',lambda d:d['contract']['bindings'][0].update(static_pointer_type=ref(1)),'ASC_STATIC_POINTER'),('wrong_static_pointee',lambda d:d['contract']['bindings'][0].update(source_class=ref(500)),'ASC_STATIC_POINTEE'),('wrong_original_plan',lambda d:d['contract']['bindings'][0]['origin'].update(plan=ref(999)),'ASC_PLAN'),('wrong_lowered_index',lambda d:d['contract']['bindings'][0]['origin'].update(lowered_index=1),'ASC_FORMAL_INDEX'),('wrong_source_index',lambda d:d['contract']['bindings'][0]['origin'].update(source_index=1),'ASC_SOURCE_INDEX'),('wrong_source_root',lambda d:d['contract']['bindings'][0]['subject'].update(root_nominal=ref(500)),'ASC_SUBJECT_LEAF'),('view_conversion',lambda d:d['contract']['bindings'][0]['subject'].update(required_leaf_view='nonvirtual'),'ASC_SUBJECT_VIEW'),('scalar_fake_member',lambda d:d['contract']['bindings'][0]['subject'].update(edges=[dict(kind='member',declaration_index=0)]),'ASC_PATH_KIND')]
 for name,change,code in edits:d=base();change(d);put(name,d,code)
 d=base();d['contract']['bindings'].append(deepcopy(d['contract']['bindings'][0]));put('duplicate_binding',d,'ASC_DUPLICATE')
 d=scoped();d['contract']['scope_values'][3]['origin']['incoming'].pop();put('wrong_real_cfg_phi_predecessors',d,'ASC_PHI_PREDECESSORS')
 d=scoped();d['contract']['scope_values'][2]['origin']['condition']=0;put('non_integer_select_condition',d,'ASC_SSA_TYPE')
 d=scoped();d['contract']['phase_sites'][1:3]=reversed(d['contract']['phase_sites'][1:3]);put('authoritative_vector_order',d,'ASC_SCOPE_VALUE_DOMINANCE')
 d=scoped();d['contract']['phase_sites'][0]['event']['kind']='enter_root';d['contract']['phase_sites'][0]['event']['vtt']=None;put('wrong_enter_source_subject',d,'ASC_PHASE_SITE')
 d=scoped();d['contract']['exits'][0]['site']=dict(kind='return_exit',block=3);d['contract']['phase_sites'][-1]['site']=deepcopy(d['contract']['exits'][0]['site']);put('ordinary_nonphysical_scope_at_physical_return',d)
 d=base();d['contract']['bindings'][0]['origin']=dict(kind='created',site=dict(kind='normal_post',block=0,index=0));bad=deepcopy(d['contract']['bindings'][0]);bad.update(id=1,value=999);d['contract']['bindings'].append(bad);put('known_later_error_before_missing_creator',d,'ASC_ORIGINAL_SSA')
 d=scoped();d['contract']['scope_values'][1]['origin']['source']=999;put('missing_shadow_reference',d,'ASC_REFERENCE')
 return rows
class CompilerConstraintsTests(unittest.TestCase):
 def test_authored_matrix_against_original_factories(self):
  for name,row in matrix().items():
   with self.subTest(case=name):
    if row['expected']=='constraints':
     out=C.run(owner(),row['document'],budget=budget());self.assertFalse(out.runtime_authority);self.assertFalse(out.source_fact_authority);self.assertFalse(out.active_v3_verified);self.assertIn('ACTIVE_ROOT3_V3_ENCODING_AND_SEMANTIC_ADMISSION',out.deferred)
    else:
     with self.assertRaises(C.ConstraintError)as e:C.run(owner(),row['document'],budget=budget())
     self.assertEqual(e.exception.code,row['code'])
 def test_original_wire_type_abi_cfg_factories(self):
  o=owner();o.verify_abi();o.verify_execution();self.assertEqual(len(o.sections),10)
 def test_fresh_actual_owners_shared_ledger(self):
  a,b=owner(),owner();ledger=budget();x=C.run(a,base(),budget=ledger);y=C.run(b,base(),budget=ledger);self.assertIs(x.owner,a);self.assertIs(y.owner,b);self.assertIsNot(x.stamp.context_anchor,y.stamp.context_anchor)
 def test_false_authority_constructor_invariants(self):
  x=C.run(owner(),base(),budget=budget())
  with self.assertRaises(FrozenInstanceError):x.runtime_authority=True
  with self.assertRaises(TypeError):C.StaticConstraints(None,None,(),(),(),(),runtime_authority=True)
 def test_zero_canonical_quotas_no_input_mutation(self):
  for key in ['max_work','max_edges','max_copied_bytes']:
   d=scoped();before=deepcopy(d)
   with self.assertRaises(Exception)as e:C.run(owner(),d,budget=budget(**{key:0}))
   self.assertIn('RESOURCE',getattr(e.exception,'code',str(e.exception)));self.assertEqual(d,before)
 def test_one_work_less_than_actual_completion_refuses(self):
  ledger=budget();C.run(owner(),scoped(),budget=ledger);used=ledger._used_work;d=scoped();before=deepcopy(d)
  with self.assertRaises(Exception)as e:C.run(owner(),d,budget=budget(max_work=used-1))
  self.assertIn('RESOURCE',getattr(e.exception,'code',str(e.exception)));self.assertEqual(d,before)
 def test_closed_schema_and_cycle_rejections(self):
  d=base();d['unknown']=1
  with self.assertRaises(Exception):C.run(owner(),d,budget=budget())
  d=base();d['contract']['bindings'].append(d)
  with self.assertRaises(Exception):C.run(owner(),d,budget=budget())
 def test_actual_original_mutation_guard(self):
  from unittest.mock import patch
  o=owner();original=C.RootContext.verify_execution
  def observe(ctx):
   result=original(ctx);o.sections[2]['symbols'][0]['name']+='-changed';return result
  with patch.object(C.RootContext,'verify_execution',observe):
   with self.assertRaises(C.source_api().SourceDataError)as e:C.run(o,base(),budget=budget())
  self.assertEqual(e.exception.code,'context_snapshot_changed')
 def test_original_cached_index_poison_is_not_evidence(self):
  o=owner();o.nominals.clear();o.signatures.clear();out=C.run(o,base(),budget=budget());self.assertEqual(out.checked_bindings,((0,0),))
 def test_pinned_schema_replacement_refuses(self):
  import tempfile
  from unittest.mock import patch
  with tempfile.TemporaryDirectory()as temporary:
   p=Path(temporary)/'changed.json';p.write_bytes(C.SCHEMA.read_bytes()+b' ')
   with patch.object(C,'SCHEMA',p):
    with self.assertRaises(C.ConstraintError)as e:C.run(owner(),base(),budget=budget())
   self.assertEqual(e.exception.code,'ASC_SCHEMA_CHANGED')
if __name__=='__main__':unittest.main(verbosity=2)
