from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
import hashlib,json,subprocess,tempfile,unittest
from . import codec as V
from .errors import CarrierError
from .source_records import source_schema
from .bindings import PROJECT,C,source_api
from .comparison import OriginalV2Comparison,compare_against_original_v2
from .fixtures import F,budget,examples,products,representative
from source_contracts.test_factory import factory,pointer_factory,W
from source_contracts.test_checker import owner,scoped
HERE=Path(__file__).resolve().parent
class CodecTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='source-carrier-',dir=__import__('os').environ.get('SMIR_SOURCE_CARRIER_TMPDIR'));cls.addClassCleanup(cls.tmp.cleanup);cls.scratch=Path(cls.tmp.name);cls.cpp_calls=0
 def cpp(self,kind,raw,accept=True):
  p=self.scratch/'payload.bin';p.write_bytes(raw)
  r=subprocess.run([__import__('os').environ['SMIR_SOURCE_CARRIER_ORACLE'],kind,str(p)],capture_output=True,text=True)
  type(self).cpp_calls+=1
  self.assertEqual(r.returncode,0 if accept else 2,(kind,r.stdout,r.stderr))
  return json.loads(r.stdout)if accept else r.stdout.strip()
 def rejects(self,raw,code=None,cpp=True):
  with self.assertRaises(CarrierError)as e:V.decode_root3(raw,budget=budget())
  if code:self.assertEqual(e.exception.code,code)
  if cpp:self.cpp('root3',raw,False)
 def root(self,name='published-sret'):
  return json.loads((F/(name+'.wire.json')).read_bytes())
 def wire(self,root):return V.OrderedCodec(budget()).encode('execution_functions_v3',root)
 def test_01_reproducible_exact_fixture_products(self):
  out=products();self.assertEqual(set(out),{p.name for p in F.iterdir()if p.is_file()and p.name not in ('README.md','provenance.json')})
  for n,b in out.items():self.assertEqual((F/n).read_bytes(),b,n)
 def test_02_all_actual_module_and_cpp_payload_roundtrips(self):
  for name,o,d in examples():
   raw=(F/(name+'.v3.smo')).read_bytes();m=V.decode_module(raw,budget=budget());root=self.root(name)
   self.assertEqual(m.roots[3],root);self.assertEqual(V.encode_module(m.roots,budget=budget()),raw)
   payload=(F/(name+'.root3.bin')).read_bytes();self.assertEqual(V.encode_root3(root,budget=budget()),payload);self.assertEqual(self.cpp('root3',payload),root)
   self.assertFalse(m.executable);self.assertFalse(m.semantic_admission);self.assertFalse(m.active_v3_verified);self.assertEqual(m.binding,'unbound')
 def test_03_old_actual_v2_full_bytes_and_cpp_payload(self):
  expected={'published-sret':'sret-published-factory','retained-pointer':'pointer-partial-factory-and-caller','scoped-phi':'original-pointer','explicit-empty':'original-pointer'}
  for name,o,d in examples():
   raw=(W/(expected[name]+'.smo')).read_bytes();self.assertEqual((F/(name+'.v2.smo')).read_bytes(),raw)
   m=V.decode_module(raw,budget=budget());self.assertEqual(V.encode_module(m.roots,budget=budget()),raw)
   payload=V.encode_root3(m.roots[3],budget=budget());self.assertEqual(self.cpp('root3',payload),m.roots[3])
 def test_04_grammar_every_record_every_variant_independent_cpp(self):
  rows=json.loads((F/'grammar-cases.json').read_bytes());seen=set();codec=V.OrderedCodec(budget())
  for row in rows:
   raw=bytes.fromhex(row['hex']);self.assertEqual(codec.decode(row['kind'],raw),row['value']);self.assertEqual(codec.encode(row['kind'],row['value']),raw);self.assertEqual(self.cpp(row['kind'],raw),row['value']);seen.add((row['kind'],row['variant']))
  expected={(n,t)for n,r in codec.records.items()for t in(r['variants']if'discriminator'in r else [''])}
  self.assertEqual(seen,expected)
 def test_05_every_truncated_prefix_empty_payload(self):
  raw=(F/'empty.root3.bin').read_bytes()
  for i in range(len(raw)):self.rejects(raw[:i])
 def test_06_wrong_revisions_no_trial(self):
  raw=(F/'empty.root3.bin').read_bytes()
  for rev in [0,1,4,0xffffffff]:self.rejects(rev.to_bytes(4,'little')+raw[4:],'V3_REVISION')
  self.rejects((2).to_bytes(4,'little')+raw[4:],'V3_TRAILING')
  self.rejects((3).to_bytes(4,'little')+bytes(4),'V3_TRUNCATED')
 def test_07_trailing_bytes_complete_consumption(self):self.rejects((F/'empty.root3.bin').read_bytes()+b'\0','V3_TRAILING')
 def test_08_counts_before_allocation_python_cpp(self):
  raw=(F/'empty.root3.bin').read_bytes()
  for count in [4097,0xffffffff]:self.rejects(raw[:12]+count.to_bytes(4,'little')+raw[16:],'V3_COUNT')
 def test_09_unknown_union_tag_closed(self):
  for kind in ['operation_v3','sc_site','sc_binding_origin']:
   codec=V.OrderedCodec(budget())
   if kind not in codec.records:continue
   with self.assertRaises(CarrierError):codec.decode(kind,b'\x03zzz')
   self.cpp(kind,b'\x03zzz',False)
 def test_10_invalid_primitive_tags_utf8_tokens(self):
  for kind,raw in [('bool',b'\x02'),('opt:u32',b'\x02'),('token',b'\x02C1'),('utf8',b'\x01\0\0\0\xff')]:
   with self.assertRaises(CarrierError):V.OrderedCodec(budget()).decode(kind,raw)
   self.cpp(kind,raw,False)
 def test_11_source_id_excludes_no_entry(self):
  c=V.OrderedCodec(budget());value=representative(c,'sc_binding');raw=c.encode('sc_binding',value)
  raw=(0xffffffff).to_bytes(4,'little')+raw[4:]
  with self.assertRaises(CarrierError):c.decode('sc_binding',raw)
  self.cpp('sc_binding',raw,False)
 def test_12_lifecycle_uppercase_exact_enum_utf8(self):
  c=V.OrderedCodec(budget());k=next(n for n,r in c.records.items()if'fields'in r and ['variant','utf8']in r['fields']);v=representative(c,k)
  for variant in ['C1','C2','D0','D1','D2']:
   v['variant']=variant;raw=c.encode(k,v);self.assertEqual(c.decode(k,raw),v);self.assertEqual(self.cpp(k,raw),v)
  bad=raw[:-1]+b'9'
  with self.assertRaises(CarrierError):c.decode(k,bad)
  self.cpp(k,bad,False)
 def test_13_lookup_order_duplicates_unknown_function(self):
  root=self.root('retained-pointer');rows=root['source_contract']['bindings']
  mutations=[lambda r:r['source_contract']['bindings'].reverse(),lambda r:r['source_contract']['bindings'].append(deepcopy(rows[-1])),lambda r:r['source_contract']['bindings'][0].update(function=999)]
  for edit in mutations:
   r=deepcopy(root);edit(r);self.rejects(self.wire(r),cpp=False)
 def test_14_unknown_ssa_and_source_reference(self):
  for edit in [lambda r:r['source_contract']['bindings'][0].update(value=999),lambda r:r['source_contract']['exits'][0].update(scope_value=999),lambda r:r['source_contract']['phase_sites'][0]['event'].update(binding=999)]:
   r=self.root();edit(r);self.rejects(self.wire(r),'V3_REFERENCE',cpp=False)
 def test_15_phase_order_authoritative_not_id_sorted(self):
  r=self.root('scoped-phi');ids=[p['id']for p in r['source_contract']['phase_sites']];self.assertNotEqual(ids,sorted(ids));self.assertEqual(V.decode_root3(self.wire(r),budget=budget()),r)
 def test_16_full_module_qrefs_refuse_unknown_original_entities(self):
  raw=(F/'published-sret.v3.smo').read_bytes();m=V.decode_module(raw,budget=budget());r=deepcopy(m.roots);r[3]['source_contract']['bindings'][0]['source_class']['id']=999999
  bad=V.encode_module(r,budget=budget())
  with self.assertRaises(CarrierError)as e:V.decode_module(bad,budget=budget())
  self.assertEqual(e.exception.code,'V3_REFERENCE')
 def test_17_observer_shape_references_and_unsupported_relation(self):
  raw=(F/'observer-structural-only.v3.smo').read_bytes();m=V.decode_module(raw,budget=budget());self.assertFalse(m.active_v3_verified)
  with self.assertRaises(CarrierError)as e:compare_against_original_v2(raw,pointer_factory()[0],budget=budget())
  self.assertEqual(e.exception.code,'V3_OBSERVER_SEMANTICS_UNAVAILABLE')
  for field,val in [('scope_value',999),('adoption',999)]:
   root=deepcopy(m.roots[3]);root['functions'][1]['blocks'][0]['ops'][-1][field]=val;self.rejects(self.wire(root),'V3_REFERENCE',cpp=False)
  root=deepcopy(m.roots[3]);root['functions'][1]['blocks'][0]['ops'][-1]['results']=[]
  with self.assertRaises(CarrierError):self.wire(root)
 def test_18_observer_requires_actual_journal_type(self):
  m=V.decode_module((F/'observer-structural-only.v3.smo').read_bytes(),budget=budget());r=deepcopy(m.roots)
  t=next(x['id']for x in r[1]['types']if x['kind']=='int');r[3]['functions'][1]['blocks'][0]['ops'][-1]['results'][0]['type']['id']=t
  with self.assertRaises(CarrierError)as e:V.decode_module(V.encode_module(r,budget=budget()),budget=budget())
  self.assertEqual(e.exception.code,'V3_OBSERVER_TYPE')
 def test_19_digest_tamper_refuses(self):
  raw=(F/'published-sret.v3.smo').read_bytes();frame=V.envelope.decode_candidate(raw);section=next(s for s in frame['sections']if s['kind']==2);b=bytearray.fromhex(section['hex']);b[4]^=1;section['hex']=b.hex()
  with self.assertRaises(CarrierError)as e:V.decode_module(V.envelope.encode_candidate(frame),budget=budget())
  self.assertEqual(e.exception.code,'V3_IDENTITY')
 def test_20_genuine_original_v2_owner_only(self):
  for name,o,d in examples():
   raw=(F/(name+'.v3.smo')).read_bytes();b=budget();stamp=o.prepare_source_data(budget=b);result=compare_against_original_v2(raw,o,budget=b)
   self.assertIs(result.original_v2_owner,o);self.assertIs(result.original_v2_stamp,stamp);self.assertIsNone(result.original_v3_source_stamp);self.assertFalse(result.executable);self.assertFalse(result.active_v3_verified);self.assertIn('ORIGINAL_V3_SOURCE_CONTEXT_UNAVAILABLE',result.deferred)
 def test_21_authority_cannot_be_set_by_constructor_or_assignment(self):
  with self.assertRaises(TypeError):V.StructuralModule({}, {}, '',executable=True)
  x=V.decode_module((F/'published-sret.v3.smo').read_bytes(),budget=budget())
  with self.assertRaises(FrozenInstanceError):x.executable=True
  with self.assertRaises(TypeError):OriginalV2Comparison(None,None,'',None,(),active_v3_verified=True)
 def test_22_raw_wire_nullable_bijection_and_closed_fields(self):
  for name,o,d in examples():
   self.assertEqual(V.raw_contract(V.wire_contract(d['contract'],budget=budget()),budget=budget()),d['contract'])
  d=factory()[1]['contract'];d['scopes'][0]['program']={'some':d['scopes'][0]['program']}
  with self.assertRaises(CarrierError):V.wire_contract(d,budget=budget())
  r=self.root();r['source_contract']['extra']=0
  with self.assertRaises(CarrierError):V.encode_root3(r,budget=budget())
 def test_23_zero_budgets_and_exact_one_less(self):
  raw=(F/'published-sret.root3.bin').read_bytes()
  for key in ['max_work','max_edges','max_copied_bytes']:
   with self.assertRaises(C.source_api().SourceDataError):V.decode_root3(raw,budget=budget(**{key:0}))
  b=budget();V.decode_root3(raw,budget=b)
  for key,used in [('max_work',b._used_work),('max_edges',b._used_edges),('max_copied_bytes',b._used_copied_bytes)]:
   with self.assertRaises(C.source_api().SourceDataError):V.decode_root3(raw,budget=budget(**{key:used-1}))
 def test_24_limits_and_budget_identity(self):
  with self.assertRaises(CarrierError):V.decode_root3((F/'empty.root3.bin').read_bytes(),budget=object())
  with self.assertRaises(CarrierError):V.OrderedCodec(budget(),V.Limits(max_depth=129))
  with self.assertRaises(CarrierError):V.OrderedCodec(budget(),V.Limits(max_bytes=1)).decode('u32',bytes(4))
 def test_25_schema_source_read_is_pinned_and_metered(self):
  # Pinned schema must be validated through the real bounded source loader.
  source=PROJECT/'docs/specifications/smir/portable/schema/runtime/source_contracts.json'
  b=budget();expected=source_schema(b)
  self.assertEqual(expected['$id'],'urn:rax:smir:runtime:source-contracts:reference:1')
  self.assertGreater(b._used_work,source.stat().st_size)
 def test_26_unverified_source_context_is_not_candidate_context(self):
  raw=(F/'published-sret.v3.smo').read_bytes()
  schemas={n:json.loads((PROJECT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in ('execution','runtime','abi')}
  with self.assertRaises(Exception):V.envelope.CandidateCodec(schemas).decode(raw)
  self.assertFalse(V.decode_module(raw,budget=budget()).semantic_admission)
 def test_27_vector_item_reserved_id_and_count_boundaries(self):
  codec=V.OrderedCodec(budget());name='sc_phase_event';tag='call';v=representative(codec,name,tag=tag);v['return_adoptions']=[0xfffffffe]
  raw=codec.encode(name,v);self.assertEqual(codec.decode(name,raw),v);self.assertEqual(self.cpp(name,raw),v)
  bad=raw[:-4]+(0xffffffff).to_bytes(4,'little')
  with self.assertRaises(CarrierError):codec.decode(name,bad)
  self.cpp(name,bad,False)
  v['return_adoptions']=[0xffffffff]
  with self.assertRaises(CarrierError):codec.encode(name,v)
  v['return_adoptions']=[0]*4096;raw=codec.encode(name,v);self.assertEqual(len(codec.decode(name,raw)['return_adoptions']),4096);self.cpp(name,raw)
  v['return_adoptions'].append(0)
  with self.assertRaises(CarrierError):codec.encode(name,v)
 def test_28_optional_scalar_same_path_constraints(self):
  codec=V.OrderedCodec(budget());name='sc_scope';v=representative(codec,name,nonnull=True);v['binding']={'some':0xfffffffe}
  raw=codec.encode(name,v);self.assertEqual(codec.decode(name,raw),v);self.assertEqual(self.cpp(name,raw),v)
  v['binding']={'some':0xffffffff}
  with self.assertRaises(CarrierError):codec.encode(name,v)
 def test_29_observer_source_id_reserved_boundaries(self):
  c=V.OrderedCodec(budget());v=representative(c,'operation_v3',tag='source_journal_observe')
  for name in ['scope_value','adoption']:
   x=deepcopy(v);x[name]=0xfffffffe;raw=c.encode('operation_v3',x);self.cpp('operation_v3',raw)
   x[name]=0xffffffff
   with self.assertRaises(CarrierError):c.encode('operation_v3',x)
   index=-8 if name=='scope_value'else -4;bad=bytearray(raw);bad[index:index+4 if index+4 else None]=(0xffffffff).to_bytes(4,'little')
   with self.assertRaises(CarrierError):c.decode('operation_v3',bytes(bad))
   self.cpp('operation_v3',bytes(bad),False)
 def test_30_allocation_limits_before_hex_scan_and_conversion(self):
  from unittest.mock import patch
  c=V.OrderedCodec(budget(),V.Limits(max_bytes=8));text='ff'*9;original=V.re.fullmatch;seen=[]
  def observe(pattern,value,*args,**kw):
   if value==text:seen.append(pattern)
   return original(pattern,value,*args,**kw)
  with patch.object(V.re,'fullmatch',observe):
   with self.assertRaises(CarrierError)as e:c.encode('hex',text)
  self.assertEqual(e.exception.code,'V3_RESOURCE');self.assertEqual(seen,[])
  for text in ['a'*9,'é'*5,'\ud800']:
   c=V.OrderedCodec(budget(),V.Limits(max_string=8))
   with self.assertRaises(CarrierError):c.encode('utf8',text)
 def test_31_metadata_is_bounded_and_never_consumes_arbitrary_iterator(self):
  o=factory()[0]
  def hostile():
   raise RuntimeError('iterator consumed')
   yield {}
  for metadata in [hostile(),[None]*1015]:
   with self.assertRaises(CarrierError)as e:V.encode_module(o.sections,budget=budget(),metadata=metadata)
   self.assertEqual(e.exception.code,'V3_METADATA')
  for row in [dict(kind=0x8000,required=False,hex='zz'),dict(kind=True,required=False,hex=''),dict(kind=0x8000,required=True,hex=''),dict(kind=0x8000,required=False,hex='',extra=0)]:
   with self.assertRaises(CarrierError):V.encode_module(o.sections,budget=budget(),metadata=[row])
 def test_32_optional_metadata_roundtrip_outside_content_digest(self):
  r=V.decode_module((F/'published-sret.v3.smo').read_bytes(),budget=budget());metadata=[dict(kind=0x8000,required=False,hex='aabb')]
  raw=V.encode_module(r.roots,budget=budget(),metadata=metadata);m=V.decode_module(raw,budget=budget());self.assertEqual(m.digest,r.digest)
  self.assertEqual(raw,V.encode_module(m.roots,budget=budget(),metadata=metadata));self.assertFalse(m.executable)
 def test_33_dependency_observer_kind_explicitly_unavailable(self):
  m=V.decode_module((F/'observer-structural-only.v3.smo').read_bytes(),budget=budget());r=deepcopy(m.roots);c=V.OrderedCodec(budget())
  dep=representative(c,'dependency');dep['slot']=7;decl=representative(c,'external_declaration');decl.update(id=900,kind='type',symbol_kind='none',source_linkage='none',namespace='',name='Journal');dep['declarations']=[decl];r[2]['manifest']['dependencies']=[dep]
  r[3]['functions'][1]['blocks'][0]['ops'][-1]['results'][0]['type']=dict(module=dict(kind='dependency',slot=7),id=900)
  with self.assertRaises(CarrierError)as e:V.decode_module(V.encode_module(r,budget=budget()),budget=budget())
  self.assertEqual(e.exception.code,'V3_OBSERVER_EXTERNAL_TYPE_UNAVAILABLE')
 def test_34_structural_import_preserves_actual_execution_codec_and_path(self):
  import importlib.util,sys
  beforepath=list(sys.path);oldcodec=sys.modules.get('codec');name='source_carrier._isolation_codec'
  execution=PROJECT/'tools/smir-format/execution/codec.py';spec=importlib.util.spec_from_file_location('codec',execution);actual=importlib.util.module_from_spec(spec)
  try:
   sys.modules['codec']=actual;spec.loader.exec_module(actual)
   spec=importlib.util.spec_from_file_location(name,V.__file__);fresh=importlib.util.module_from_spec(spec);sys.modules[name]=fresh;spec.loader.exec_module(fresh)
   self.assertIs(sys.modules['codec'],actual);self.assertEqual(sys.path,beforepath);self.assertIs(__import__('source_carrier.bindings',fromlist=['source_api']).source_api(),source_api())
   self.assertNotIn('source_contracts',vars(fresh))
  finally:
   sys.modules.pop(name,None)
   if oldcodec is None:sys.modules.pop('codec',None)
   else:sys.modules['codec']=oldcodec
   sys.path[:]=beforepath
if __name__=='__main__':unittest.main(verbosity=2)
