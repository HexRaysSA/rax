"""Original exact site dispatch; no new source-category issuer or runtime."""
import unittest,sys,hashlib,json
from pathlib import Path
from copy import deepcopy
import site_config as S
from record_layout.test_source_programs import budget
R=Path(__file__).resolve().parents[2]
class Sites(unittest.TestCase):
 def root(self,n):return dict(site=S.site_record(platform_source_abi_revision=n),identity=S.identity(platform_source_abi_revision=n))
 def test_known_original_both(self):
  self.assertEqual(S.identity(),'a8a121228724a418689aa46a1287d3de566bb8a66fdf722749a4ef00927e9c71')
  self.assertEqual(S.identity(platform_source_abi_revision=2),'5d720afc00ef5c4db7d4ff018155be283f7ae39260119c5024e6a17e9acf1de3')
  for n in [1,2]:self.assertEqual(S.original_profile(self.root(n)),n)
 def test_noarg_legacy_exact(self):
  p=R/'docs/specifications/smir/portable/conformance/abi/source-bytes/legacy-site-api.json';golden=json.loads(p.read_text())
  def digest(value):return hashlib.sha256(value).hexdigest()
  for name in ['config','site_record']:
   self.assertEqual(digest(json.dumps(getattr(S,name)(),sort_keys=True,separators=(',',':')).encode()),golden[name+'_canonical_sha256'])
  self.assertEqual(digest(S.header().encode()),golden['header_utf8_sha256']);self.assertEqual(S.identity(),golden['identity'])
 def test_selectors_closed_no_callbacks(self):
  hits=[]
  class Bad:
   def __eq__(self,x):hits.append(x);raise AssertionError('caller eq')
   def __ne__(self,x):hits.append(x);raise AssertionError('caller ne')
  for x in [True,False,0,3,'2',Bad()]:
   for f in [S.config,S.site_record,S.identity]:
    with self.assertRaisesRegex(ValueError,'ABI_CC_SITE_REVISION'):f(platform_source_abi_revision=x)
  self.assertEqual(hits,[])
 def test_wrong_identity_duplicate_unknown_wrongstate(self):
  for case in ['identity','duplicate','unknown','wrongstate','missing']:
   r=self.root(2)
   if case=='identity':r['identity']=S.identity()
   elif case=='duplicate':r['site']['options'].append(dict(name='RAX_PORTABLE_SOURCE_ABI_REVISION',state='contract',value='2'))
   else:
    q=next(x for x in r['site']['options']if x['name']=='RAX_PORTABLE_SOURCE_ABI_REVISION')
    if case=='unknown':q['value']='3'
    elif case=='wrongstate':q['state']='cmake'
    else:r['site']['options'].remove(q)
   with self.assertRaisesRegex(ValueError,'ABI_CC_SITE'):S.original_profile(r)
 def test_nonplain_fields_no_callbacks_or_json(self):
  hits=[]
  class Bad:
   def __eq__(self,x):hits.append('eq');raise AssertionError('caller eq')
   def __hash__(self):hits.append('hash');raise AssertionError('caller hash')
  for target in ['identity','rowvalue','rowname','rowstate','library']:
   r=self.root(2)
   if target=='identity':r['identity']=Bad()
   elif target=='library':r['site']['libcxx_abi']=True
   else:r['site']['options'][0][{'rowvalue':'value','rowname':'name','rowstate':'state'}[target]]=Bad()
   with self.assertRaisesRegex(ValueError,'ABI_CC_SITE'):S.original_profile(r)
  self.assertEqual(hits,[])
 def test_zero_budget_before_json(self):
  hits=[]
  def trace(frame,event,arg):
   if event=='call'and '/json/'in frame.f_code.co_filename:hits.append(1)
  r=self.root(2);sys.setprofile(trace)
  try:
   with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):S.original_profile(r,budget=budget(max_work=0))
  finally:sys.setprofile(None)
  self.assertEqual(hits,[])
 def test_actual_budget_exact_and_each_one_less(self):
  r=self.root(2);b=budget(max_work=10**20,max_edges=10**20,max_copied_bytes=10**20);self.assertEqual(S.original_profile(r,budget=b),2)
  limits=dict(max_work=b._used_work,max_edges=b._used_edges,max_copied_bytes=b._used_copied_bytes);self.assertEqual(S.original_profile(r,budget=budget(**limits)),2)
  for key in limits:
   q=dict(limits);q[key]-=1
   with self.assertRaisesRegex(Exception,'SOURCE_DATA_RESOURCE'):S.original_profile(r,budget=budget(**q))
if __name__=='__main__':unittest.main(verbosity=2)
