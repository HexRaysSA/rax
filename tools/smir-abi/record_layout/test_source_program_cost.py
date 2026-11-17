"""Actual original B quotas, no fake factories or positive callbacks."""
from pathlib import Path
import sys,unittest,json
from copy import deepcopy
from . import test_source_lifecycles as V
from record_layout import source_programs as S,source_program_cost as P
from record_layout.test_source_programs import document,budget
from .source_lifecycles import verify_lifecycle_associations as verify
from candidate.context import RootContext
from candidate import root3_context as D

def used(b):return dict(work=b._used_work,edges=b._used_edges,copied_bytes=b._used_copied_bytes)
def policy(x):return budget(max_work=x['work'],max_edges=x['edges'],max_copied_bytes=x['copied_bytes'])
def original(max_work=10**24,variant='C1'):
 old,req,_=V.fixture(variant);roots=deepcopy(old.sections);b=budget(max_work=max_work,max_edges=10**24,max_copied_bytes=10**24)
 roots[3].update(payload_revision=3,source_contract=D.codec().wire_contract(req['source_contract'],budget=b));raw=D.codec().encode_module(roots,budget=b);roots=D.codec().decode_module(raw,budget=b).roots;o=RootContext(roots,budget=b);stamp=o.prepare_source_data(budget=b);key=roots[2]['manifest']['key'];req['source_programs']['contexts'][0].update(family={n:key[n]for n in['namespace','name','abi_major']},abi_site=roots[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex());return o,req,b

def observe(fn):
 hits=[]
 def trace(frame,event,arg):
  if event=='call':
   name=frame.f_code.co_name;file=frame.f_code.co_filename
   if file.endswith('/record_layout/source_programs.py')and name=='__init__':hits.append((name,frame.f_locals['budget']._used_work))
 sys.setprofile(trace)
 try:value=fn()
 finally:sys.setprofile(None)
 return value,hits
class ActualCost(unittest.TestCase):
 def test_strict_v2_rejects_before_factories(self):
  o,d,b=V.fixture();hits=[]
  def trace(frame,event,arg):
   if event=='call'and frame.f_code.co_name in ['verify_abi','verify_execution','verify_candidate_body']:hits.append(frame.f_code.co_name)
  sys.setprofile(trace)
  try:
   with self.assertRaisesRegex(ValueError,'ABI_LC_COST_PROFILE_UNAVAILABLE'):verify(o,d,budget=b)
  finally:sys.setprofile(None)
  self.assertEqual(hits,[])
 def test_base_walk_zero_budget_precedes_initial_payload(self):
  from .source_lifecycles import class_has_vbases
  hits=[]
  def trace(frame,event,arg):
   if event=='call'and frame.f_code.co_name=='selfref'and frame.f_code.co_filename.endswith('source_lifecycles.py'):hits.append('selfref')
  sys.setprofile(trace)
  try:
   with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):class_has_vbases({}, {},budget(max_copied_bytes=0))
  finally:sys.setprofile(None)
  self.assertEqual(hits,[])
 def test_closed_profile_and_budget_reject_before_callbacks(self):
  calls=[]
  class Forged:
   def __eq__(self,other):calls.append('eq');raise AssertionError('caller equality')
   def __ne__(self,other):calls.append('ne');raise AssertionError('caller inequality')
  for value in [Forged(),17,True,[],{}]:
   with self.subTest(profile_type=type(value).__name__):
    with self.assertRaisesRegex(ValueError,'ABI_SP_COST_PROFILE_UNAVAILABLE'):P.active(value,budget())
  for b in [None,Forged()]:
   with self.subTest(budget_type=type(b).__name__):
    with self.assertRaisesRegex(ValueError,'ABI_SP_BUDGET|ABI_FACTORY_BUDGET_CLASS'):S.Checker(document(),b,cost_profile=P.PROFILE)
  self.assertEqual(calls,[])
  self.assertFalse(P.active(None,Forged()))
  self.assertEqual(calls,[])
 def test_profile_keys_before_any_json_delegate(self):
  for key in ['x'*257,1]:
   with self.subTest(key_type=type(key).__name__):
    hits=[]
    def trace(frame,event,arg):
     if event=='call'and '/json/'in frame.f_code.co_filename:hits.append(frame.f_code.co_name)
    sys.setprofile(trace)
    try:
     with self.assertRaisesRegex(ValueError,'ABI_SP_COST_PROFILE_UNAVAILABLE: key'):S.capture({key:0},budget(),cost_profile=P.PROFILE)
    finally:sys.setprofile(None)
    self.assertEqual(hits,[])
  b=budget(max_work=10**24,max_edges=10**24,max_copied_bytes=10**24)
  self.assertEqual(S.capture({'x'*256:0},b,cost_profile=P.PROFILE)[0],{'x'*256:0})
 def test_actual_foreign_prototype_separate_stage_charge(self):
  o,d,b=original();hits=[]
  def trace(frame,event,arg):
   if event=='call'and frame.f_code.co_name=='row'and frame.f_code.co_filename.endswith('/source_program_cost.py'):
    v=frame.f_locals.get('value')
    if type(v)is dict and v.get('kind')=='function'and 'elements'in v:hits.append((v['id'],frame.f_locals['b'] is b))
  sys.setprofile(trace)
  try:S.check_source_associations(d['source_programs'],o,0,budget=b,cost_profile=P.PROFILE)
  finally:sys.setprofile(None)
  self.assertTrue(hits);self.assertTrue(all(same for _,same in hits))
 def test_capture_exact_and_each_one_less(self):
  d=document();b=budget(max_work=10**24,max_edges=10**24,max_copied_bytes=10**24);expected=S.capture(d,b,cost_profile=P.PROFILE);n=used(b)
  self.assertEqual(S.capture(d,policy(n),cost_profile=P.PROFILE),expected)
  for dim in n:
   q=dict(n);q[dim]-=1
   with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):S.capture(d,policy(q),cost_profile=P.PROFILE)
 def test_zero_capture_precedes_json(self):
  hits=[]
  def trace(frame,event,arg):
   if event=='call'and '/json/'in frame.f_code.co_filename:hits.append(frame.f_code.co_name)
  sys.setprofile(trace)
  try:
   with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):S.capture(document(),budget(max_work=0),cost_profile=P.PROFILE)
  finally:sys.setprofile(None)
  self.assertEqual(hits,[])
 def test_real_whole_lifecycle_exact_and_one_less(self):
  for variant in ['C1','C2','D0','D1','D2']:
   with self.subTest(variant=variant):
    o,d,b=original(variant=variant);r=verify(o,d,budget=b);limit=b._used_work
    o,d,b=original(limit,variant);again=verify(o,d,budget=b);self.assertEqual(again.associations,r.associations)
    o,d,b=original(limit-1,variant)
    with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):verify(o,d,budget=b)
 def test_before_real_sourceprogram_factory_entry(self):
  o,d,b=original();_,hits=observe(lambda:verify(o,d,budget=b));self.assertEqual(len(hits),1);limit=hits[0][1]-1
  o,d,b=original(limit)
  def fail():
   with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):verify(o,d,budget=b)
  _,hits=observe(fail);self.assertEqual(hits,[])
 def test_quota_before_actual_abi_and_body_factories(self):
  for target in ['verify_abi','verify_candidate_body']:
   with self.subTest(target=target):
    o,d,b=original();hits=[]
    def trace(frame,event,arg):
     if event=='call'and frame.f_code.co_name==target and frame.f_locals.get('self')is o:hits.append(b._used_work)
    sys.setprofile(trace)
    try:verify(o,d,budget=b)
    finally:sys.setprofile(None)
    self.assertEqual(len(hits),1);o,d,b=original(hits[0]-1);hits=[]
    sys.setprofile(trace)
    try:
     with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):verify(o,d,budget=b)
    finally:sys.setprofile(None)
    self.assertEqual(hits,[])
 def test_profile_excludes_array_before_real_checker(self):
  o,d,b=original();d['source_programs']['records'][0]['slots'][0]['array_extents']=[2]
  def fail():
   with self.assertRaisesRegex(Exception,'ABI_SP_COST_PROFILE_UNAVAILABLE'):verify(o,d,budget=b)
  _,hits=observe(fail);self.assertEqual(hits,[])
 def test_profile_rejects_unknown_schema_pattern_before_regex(self):
  schema=dict(type='string',pattern='(a+)+$',minLength=0,maxLength=256)
  with self.assertRaisesRegex(Exception,'ABI_SP_COST_PROFILE_UNAVAILABLE'):S.shape(schema,'a'*128,{},budget(),cost_profile=P.PROFILE)
 def test_input_depth_refuses_before_json(self):
  x=0
  for _ in range(65):x=[x]
  with self.assertRaisesRegex(Exception,'ABI_SP_COST_PROFILE_UNAVAILABLE'):S.capture(x,budget(),cost_profile=P.PROFILE)
class Boundaries(unittest.TestCase):
 def test_excluded_shapes_precede_all_real_factories(self):
  mutations={
   'record_size':lambda d:d['source_programs']['records'][0].__setitem__('complete_size',4097),
   'union':lambda d:d['source_programs']['records'][0].__setitem__('record_kind','union'),
   'base':lambda d:d['source_programs']['records'][0]['slots'][0].__setitem__('kind','nonvirtual_base'),
   'width':lambda d:d['source_programs']['records'][0]['slots'][0].__setitem__('width_bits',32769),
   'slots':lambda d:d['source_programs']['records'][0].__setitem__('slots',d['source_programs']['records'][0]['slots']*9),
   'methods':lambda d:d['source_programs'].__setitem__('methods',d['source_programs']['methods']*9),
   'parameters':lambda d:d['source_programs']['methods'][0].__setitem__('parameters',[{'context':0,'nominal':{'module':{'kind':'self'},'id':1}}]*17),
   'steps':lambda d:d['source_programs']['programs'][0].__setitem__('steps',[1]*9),
   'links':lambda d:d.__setitem__('links',d['links']*5),
  }
  for name,mutate in mutations.items():
   with self.subTest(case=name):
    o,d,b=original();mutate(d);hits=[]
    def trace(frame,event,arg):
     if event=='call'and(frame.f_code.co_name in ['verify_abi','verify_candidate_body']or(frame.f_code.co_name=='__init__'and frame.f_code.co_filename.endswith('/record_layout/source_programs.py'))):hits.append(frame.f_code.co_name)
    sys.setprofile(trace)
    try:
     with self.assertRaisesRegex(ValueError,'ABI_(SP|LC)_COST_PROFILE_UNAVAILABLE'):verify(o,d,budget=b)
    finally:sys.setprofile(None)
    self.assertEqual(hits,[])
if __name__=='__main__':unittest.main(verbosity=2)

