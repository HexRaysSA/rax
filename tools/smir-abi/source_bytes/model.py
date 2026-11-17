"""Static declared projection checks; no category/ABI/runtime issuer."""
from pathlib import Path
from dataclasses import dataclass,field
import json,hashlib
import factory_meter as M
from record_layout import source_programs as S
from record_layout.materialization import _api
from nominal import NominalGraph
from site_config import original_profile
ROOT=Path(__file__).resolve().parents[3]
SCHEMA=ROOT/'docs/specifications/smir/portable/schema/abi/source_byte_projection.json'
BUILTINS={'char':('char',True),'signed char':('signed_char',True),
          'unsigned char':('unsigned_char',False),'char8_t':('char8_t',False)}

def fail(code,detail='',kind='semantic'):
 raise _api().SourceDataError(kind,code,detail)
def need(ok,code):
 if not ok:fail(code)
def self_id(ref):
 if ref['module']!={'kind':'self'}:
  fail('ABI_BYTE_EXTERNAL_CATEGORY_EVIDENCE_UNAVAILABLE',kind='unavailable')
 return ref['id']

@dataclass(frozen=True,slots=True)
class StaticSourceByteProjection:
 owner:object;stamp:object;document_digest:str;categories:tuple
 binding:str=field(default='unbound',init=False)
 source_fact_authority:bool=field(default=False,init=False)
 semantic_admission:bool=field(default=False,init=False)
 runtime_authority:bool=field(default=False,init=False)
 original_category_evidence_required:bool=field(default=True,init=False)

def verify_projection_descriptor(document,owner,*,budget):
 from candidate.context import RootContext
 S.ledger(budget);need(type(owner)is RootContext,'ABI_BYTE_ORIGINAL_OWNER')
 # Actual source capture is phase-independent: it does not request ABI2 facts.
 stamp=RootContext.prepare_source_data(owner,budget=budget)
 try:
  return _verify(document,owner,stamp,budget)
 finally:
  need(RootContext.prepare_source_data(owner,budget=budget)is stamp,'ABI_BYTE_SOURCE_CHANGED')

def _verify(document,owner,stamp,budget):
 data,digest=S.capture(document,budget)
 size=SCHEMA.stat().st_size;budget.charge(work=8*size,copied_bytes=8*size)
 schema=json.loads(SCHEMA.read_text());S.shape(schema,data,schema['$defs'],budget)
 # This standalone descriptor has exactly one context: local binder zero is the
 # exact RootContext argument. It is not a registry/global/context-table index.
 need(data['context']==0,'ABI_BYTE_LOCAL_CONTEXT')
 roots=dict(stamp.root_digests)
 need(data['module_root']==roots[2].hex()and data['abi_root']==roots[10].hex(),'ABI_BYTE_SOURCE_ROOTS')
 need(original_profile(owner.sections[10],budget=budget)==2,'ABI_BYTE_EPOCH')
 graph=NominalGraph(owner.sections[10],'original',budget=budget)
 M.collection(budget,len(data['types']),8);rows={}
 for row in data['types']:
  M.row(row,budget);key=self_id(row['nominal']);need(key not in rows,'ABI_BYTE_DUPLICATE');rows[key]=row
 # Reserve selected tuples and final output tuple before their allocations.
 M.collection(budget,len(data['types']),8,copied_per_row=256)
 selected=[]
 for node in owner.sections[10]['types']:
  M.row(node,budget);key=node['id'];identity=node['identity'];name=identity['entity'];row=rows.get(key)
  if node['kind']=='scalar'and name in BUILTINS:
   category,signed=BUILTINS[name]
   need(identity['linkage']=='builtin'and identity['language']in('c23','cpp23'),'ABI_BYTE_BUILTIN_IDENTITY')
   need(name!='char8_t'or identity['language']=='cpp23','ABI_BYTE_C23_ALIAS_CANONICAL')
   need(row is not None and row['category']==category and row['declaration']is None,'ABI_BYTE_CATEGORY_TABLE')
   need(node['bits']==8 and node['signed']is signed,'ABI_BYTE_SCALAR')
  elif row is not None:
   # Structural std_byte assertion only. Actual pinned original canonical FIRST
   # and definition/source declaration membership still requires the real issuer.
   need(row['category']=='std_byte'and node['kind']=='enum'and identity['language']=='cpp23'and identity['library']is not None,'ABI_BYTE_STD_BYTE_DECLARATION')
   M.collection(budget,len(node['flags']),16)
   need('scoped'in node['flags']and'fixed_base'in node['flags']and not node['enumerators']and len(node['elements'])==1,'ABI_BYTE_STD_BYTE_SHAPE')
   base=graph.resolve(node['elements'][0])[1];M.row(base,budget)
   need(base['kind']=='scalar'and base['identity']['entity']=='unsigned char'and base['bits']==8 and not base['signed'],'ABI_BYTE_STD_BYTE_BASE')
   need(row['declaration']==row['nominal'],'ABI_BYTE_STD_BYTE_DECLARATION')
  else:
   # Non-byte numeric scalar/enums cannot hide a Raw execution projection.
   if node['kind']in('scalar','bitint','enum')and node['execution']is not None:
    shape=owner.abi_execution(node['execution']['some']);M.row(shape,budget)
    need(shape['kind']!='raw','ABI_BYTE_NUMERIC_RAW_PROJECTION')
   continue
  need(node['execution']is not None and row['execution']==node['execution']['some'],'ABI_BYTE_EXECUTION')
  shape=owner.abi_execution(row['execution']);M.row(shape,budget)
  need(shape['kind']=='raw'and shape.get('bits')==8,'ABI_BYTE_RAW8')
  layout=graph.layout(row['nominal']);M.row(layout,budget)
  need(layout['size']==layout['align']==layout['data_size']==layout['nonvirtual_size']==layout['nonvirtual_align']==1,'ABI_BYTE_LAYOUT')
  selected.append((key,row['category']))
 M.collection(budget,len(selected),8)
 need(len(selected)==len(rows),'ABI_BYTE_CATEGORY_TABLE')
 return StaticSourceByteProjection(owner,stamp,digest,tuple(selected))
