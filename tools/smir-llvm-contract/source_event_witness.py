"""Actual pinned Clang AST/CFG observations; no lifetime/ABI authority."""
from pathlib import Path
from dataclasses import dataclass,field
import hashlib,json,os,re,selectors,subprocess,sys,tempfile,time
from collections import Counter
HERE=Path(__file__).resolve().parent
PROJECT=Path(os.environ.get('CEW_REFERENCE_PROJECT',str(HERE.parents[1]))) # Explicit DRAFT override; installed path is default.
sys.path.insert(0,str(PROJECT/'tools/smir-llvm-contract'))
import source_projection as R
HERE=Path(__file__).resolve().parent
SCHEMA=PROJECT/'docs/specifications/smir/portable/llvm/source-event-witness.schema.json'
SCHEMA_SHA='7d79af45d3205cfd2467999fe4f87d43a1f55218c0bdbca3c15f8ab20fab4296'
PIN='36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER='192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'
MAX_OUTPUT=64<<20
class EventError(ValueError):
 def __init__(self,code,detail='',kind='input'):self.code=code;self.detail=detail;self.kind=kind;super().__init__(code+': '+detail)
def need(test,code,detail='',kind='input'):
 if not test:raise EventError(code,detail,kind)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def digest(x):return hashlib.sha256(x).hexdigest()
def read(path,limit,budget):
 p=Path(path);n=p.stat().st_size;need(0<=n<=limit,'CEW_RESOURCE','input size','resource');budget.charge(work=4*n+1,copied_bytes=4*n+1)
 with p.open('rb') as f:raw=f.read(n+1)
 need(len(raw)==n,'CEW_PROVENANCE','input changed while reading');return raw
def file_hash(path,budget):
 p=Path(path);n=p.stat().st_size;need(0<=n<=1<<31,'CEW_RESOURCE','native input size','resource');budget.charge(work=2*n+1,copied_bytes=n+1);h=hashlib.sha256()
 with p.open('rb') as f:
  total=0
  for part in iter(lambda:f.read(1<<20),b''):total+=len(part);need(total<=n,'CEW_PROVENANCE','native input grew');h.update(part)
 need(total==n,'CEW_PROVENANCE','native input shrank');return h.hexdigest()
def load_json(raw):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'CEW_INPUT','duplicate JSON key');d[k]=v
  return d
 try:return json.loads(raw,object_pairs_hook=pairs)
 except (ValueError,UnicodeError) as e:
  if isinstance(e,EventError):raise
  raise EventError('CEW_INPUT','invalid JSON/UTF8') from e
def schema(budget):
 raw=read(SCHEMA,1<<20,budget);need(digest(raw)==SCHEMA_SHA,'CEW_PROVENANCE','schema pin');return load_json(raw),raw
def native_identity(oracle,budget):
 p=Path(oracle).resolve();receipt=p.parent/'build-receipt.json';raw=read(receipt,4<<20,budget);d=load_json(raw);need(type(d.get('exit'))is int and d['exit']==0 and d.get('llvm_pin')==PIN,'CEW_PROVENANCE','actual native build receipt')
 need(type(d)is dict and set(d)=={'format','llvm_pin','compiler','command','exit','input_hashes','drift','scope','binary'} and d['format']=='draft-source-event-native-build','CEW_PROVENANCE','closed native receipt');need(type(d['compiler'])is dict and set(d['compiler'])=={'path','sha256','version'} and type(d['compiler']['path'])is str and type(d['compiler']['version'])is str and PIN in d['compiler']['version'],'CEW_PROVENANCE','compiler record');need(d['compiler']['sha256']==COMPILER,'CEW_PROVENANCE','compiler pin');need(type(d['binary'])is dict and set(d['binary'])=={'path','sha256'} and type(d['binary']['sha256'])is str and re.fullmatch('[0-9a-f]{64}',d['binary']['sha256']),'CEW_PROVENANCE','binary record');need(type(d['command'])is list and 0<len(d['command'])<=4096 and all(type(x)is str and len(x)<=4096 for x in d['command']) and d['drift']==[] and type(d['scope'])is str,'CEW_PROVENANCE','build fields');inputs=d.get('input_hashes');need(type(inputs)is dict and 0<len(inputs)<=8192,'CEW_PROVENANCE','native inputs');paths=set()
 for name,h in inputs.items():
  need(type(name)is str and type(h)is str and re.fullmatch('[0-9a-f]{64}',h) and Path(name).is_absolute(),'CEW_PROVENANCE','native input record');resolved=str(Path(name).resolve());need(resolved not in paths,'CEW_PROVENANCE','duplicate native input path');paths.add(resolved);need(file_hash(name,budget)==h,'CEW_PROVENANCE','native build input changed')
 cpp_inputs=[h for name,h in inputs.items() if Path(name).name=='source_event_witness.cpp'];need(len(cpp_inputs)==1 and cpp_inputs[0]==file_hash(HERE/'source_event_witness.cpp',budget),'CEW_PROVENANCE','actual source input identity');need(str(Path(d['compiler']['path']).resolve()) in paths and file_hash(d['compiler']['path'],budget)==COMPILER,'CEW_PROVENANCE','actual compiler input');binary=file_hash(p,budget);need(binary==d.get('binary',{}).get('sha256'),'CEW_PROVENANCE','oracle binary');return d,raw,binary,digest(canonical(inputs))
def run_native(oracle,source,budget):
 budget.charge(work=1,edges=1,copied_bytes=256);p=subprocess.Popen([str(oracle),str(source)],stdout=subprocess.PIPE,stderr=subprocess.PIPE);sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ,'stdout');sel.register(p.stderr,selectors.EVENT_READ,'stderr');data={'stdout':bytearray(),'stderr':bytearray()};start=time.monotonic()
 try:
  while sel.get_map():
   need(time.monotonic()-start<=30,'CEW_RESOURCE','native timeout','resource')
   for key,_ in sel.select(0.1):
    budget.charge(work=65536,copied_bytes=65536);part=os.read(key.fileobj.fileno(),65536)
    if not part:sel.unregister(key.fileobj);continue
    need(sum(len(v) for v in data.values())+len(part)<=MAX_OUTPUT,'CEW_RESOURCE','native output','resource');data[key.data].extend(part)
  code=p.wait(timeout=1)
 finally:
  sel.close()
  if p.poll() is None:p.kill();p.wait()
  p.stdout.close();p.stderr.close()
 if code:
  detail=data['stderr'].decode('utf8','replace')[:4096];kind='resource' if code==4 else 'unavailable' if code==3 else 'input' if code==2 else 'internal';raise EventError('CEW_NATIVE_REJECTED',detail,kind)
 budget.charge(work=8*len(data['stdout']),copied_bytes=8*len(data['stdout']));return R.capture(load_json(data['stdout']),budget)
def unwrap(x):return None if x is None else x['some']
def table(rows,budget):
 budget.charge(work=len(rows),edges=len(rows),copied_bytes=128*len(rows));need([x['id'] for x in rows]==list(range(len(rows))),'CEW_GRAPH','noncanonical local IDs');return {x['id']:x for x in rows}
def raw_semantics(raw,source,budget):
 need(raw['source_sha256']==digest(source) and PIN in raw['library_version'],'CEW_PROVENANCE','source/library identity');decls=table(raw['declarations'],budget);total=0
 def ref(q,t):
  if q is not None:need(q['some'] in t,'CEW_GRAPH','reference namespace')
 def offsets(span):
  for q in span.values():
   if q is not None:need(q['some']<=len(source),'CEW_GRAPH','source offset')
 for d in decls.values():
  offsets({k:d[k] for k in ['canonical_offset','definition_offset']})
  for k in ['semantic_parent','canonical_lexical_parent','definition_lexical_parent']:ref(d[k],decls)
 seen_functions=set()
 for f in raw['functions']:
  budget.charge(work=32,edges=8,copied_bytes=1024);need(f['declaration'] in decls and f['declaration'] not in seen_functions,'CEW_GRAPH','function declaration');seen_functions.add(f['declaration']);need(decls[f['declaration']]['decl_kind'] in ['Function','CXXMethod','CXXConstructor','CXXDestructor','CXXConversion'],'CEW_GRAPH','function kind');nodes=table(f['nodes'],budget);regions=table(f['regions'],budget);blocks={x['id']:x for x in f['blocks']};need(len(blocks)==len(f['blocks']) and f['entry'] in blocks and f['exit'] in blocks,'CEW_GRAPH','CFG role IDs');need(f['body'] in nodes,'CEW_GRAPH','body ID');total+=len(nodes);need(total<=32768,'CEW_RESOURCE','node bound','resource')
  for p in f['parameters']:need(p in decls and decls[p]['decl_kind']=='ParmVar','CEW_GRAPH','parameter declaration')
  for n in nodes.values():
   budget.charge(work=24+len(n['children'])+len(n['declarations']),edges=16+len(n['children']),copied_bytes=64);offsets(n['range']);ref(n['region'],regions)
   for c in n['children']:need(c in nodes,'CEW_GRAPH','AST child')
   for d in n['declarations']:need(d in decls,'CEW_GRAPH','AST declaration')
   for k in ['referenced_decl','direct_callee','constructor','temporary_destructor','extending_decl','return_nrvo_candidate']:ref(n[k],decls)
   for k,kind in [('constructor','CXXConstructor'),('temporary_destructor','CXXDestructor')]:
    if n[k] is not None:need(decls[n[k]['some']]['decl_kind']==kind,'CEW_GRAPH','typed declaration edge')
   need((n['type_spelling_inspection']is None)==(n['value_category']is None),'CEW_GRAPH','expression inspection pair')
   functions={'Function','CXXMethod','CXXConstructor','CXXDestructor','CXXConversion'}
   if n['direct_callee']is not None:need(decls[n['direct_callee']['some']]['decl_kind']in functions and (n['stmt_class'].endswith('CallExpr')or n['stmt_class']=='UserDefinedLiteral'),'CEW_GRAPH','typed direct callee')
   if n['referenced_decl']is not None:need(n['stmt_class']in ['DeclRefExpr','MemberExpr'] and decls[n['referenced_decl']['some']]['type_spelling_inspection']is not None,'CEW_GRAPH','typed value reference')
   constructor=n['stmt_class']in ['CXXConstructExpr','CXXTemporaryObjectExpr'];need(constructor==(n['constructor']is not None)==(n['is_elidable']is not None),'CEW_GRAPH','constructor property applicability')
   need((n['temporary_destructor']is not None)==(n['stmt_class']=='CXXBindTemporaryExpr'),'CEW_GRAPH','temporary destructor applicability')
   need((n['bound_to_lvalue_reference']is not None)==(n['stmt_class']=='MaterializeTemporaryExpr'),'CEW_GRAPH','materialization applicability')
   if n['extending_decl']is not None:need(n['stmt_class']=='MaterializeTemporaryExpr','CEW_GRAPH','extending declaration applicability')
   if n['return_nrvo_candidate']is not None:need(n['stmt_class']=='ReturnStmt'and decls[n['return_nrvo_candidate']['some']]['decl_kind']=='Var','CEW_GRAPH','NRVO observation applicability')

  for region in regions.values():
   budget.charge(work=8,edges=2,copied_bytes=32);need(region['stmt'] in nodes and nodes[region['stmt']]['region']=={'some':region['id']},'CEW_GRAPH','AST region association');ref(region['parent'],regions);need(region['parent'] is None or region['parent']['some']<region['id'],'CEW_GRAPH','region parent');offsets(region['range'])
  seeds={f['body']}
  for b in blocks.values():
   budget.charge(work=16+len(b['elements'])+len(b['successors'])+len(b['predecessors']),edges=4+len(b['successors'])+len(b['predecessors']),copied_bytes=128);need([e['index'] for e in b['elements']]==list(range(len(b['elements']))),'CEW_GRAPH','element order')
   for k in ['terminator','condition','label','loop_target']:ref(b[k],nodes);seeds.update([] if b[k]is None else [b[k]['some']])
   for e in b['successors']+b['predecessors']:ref(e['reachable'],blocks);ref(e['possibly_unreachable'],blocks)
   for e in b['elements']:
    budget.charge(work=16+len(e['expiring_temporaries']),edges=8+len(e['expiring_temporaries']),copied_bytes=64)
    for k in ['statement','trigger']:ref(e[k],nodes);seeds.update([] if e[k]is None else [e[k]['some']])
    for k in ['declaration','destructor']:ref(e[k],decls)
    for n in e['expiring_temporaries']:need(n in nodes,'CEW_GRAPH','temporary node');seeds.add(n)
    is_dtor=e['kind'] in ['automatic_object_dtor','temporary_dtor','base_dtor','member_dtor'];need(is_dtor==(e['destructor']is not None)==(e['destructor_noreturn_inspection']is not None),'CEW_GRAPH','destructor property kind')
    if is_dtor:need(decls[e['destructor']['some']]['decl_kind']=='CXXDestructor','CEW_GRAPH','destructor declaration')
    need((e['construction_context']is not None)==(e['kind'] in ['constructor','record_typed_call']),'CEW_GRAPH','construction context kind')
    statement_kinds={'statement','constructor','record_typed_call','initializer','temporary_dtor','loop_exit_marker','full_expr_cleanup'}
    trigger_kinds={'scope_begin','scope_end','lifetime_ends_marker','automatic_object_dtor'}
    need((e['statement']is not None)==(e['kind']in statement_kinds),'CEW_GRAPH','element statement applicability')
    need((e['trigger']is not None)==(e['kind']in trigger_kinds),'CEW_GRAPH','element trigger applicability')
    if e['expiring_temporaries']:need(e['kind']=='full_expr_cleanup','CEW_GRAPH','expiring temporary applicability')
    for n in e['expiring_temporaries']:need(nodes[n]['stmt_class']=='MaterializeTemporaryExpr','CEW_GRAPH','expiring temporary node kind')
    if e['kind']=='constructor':need(nodes[e['statement']['some']]['constructor']is not None,'CEW_GRAPH','CFG constructor statement kind')
    if e['kind']=='temporary_dtor':need(nodes[e['statement']['some']]['stmt_class']=='CXXBindTemporaryExpr','CEW_GRAPH','CFG temporary destructor statement kind')
    if e['kind']in trigger_kinds:need(e['declaration']is not None and decls[e['declaration']['some']]['decl_kind']in ['Var','ParmVar','Decomposition'],'CEW_GRAPH','scope marker variable')
  # Exact pinned CFGBlock::addSuccessor semantics, preserving parallel edges.
  expected={bid:Counter()for bid in blocks}
  for bid,b in blocks.items():
   for edge in b['successors']:
    r,u=unwrap(edge['reachable']),unwrap(edge['possibly_unreachable'])
    need(r is None or u is None or r!=u,'CEW_GRAPH','noncanonical alternate edge')
    if r is not None:expected[r][(bid,None)]+=1
    if u is not None:expected[u][(None,bid)]+=1
  for bid,b in blocks.items():
   actual=Counter((unwrap(e['reachable']),unwrap(e['possibly_unreachable']))for e in b['predecessors'])
   need(actual==expected[bid],'CEW_GRAPH','CFG predecessor successor reciprocity')

  # Reachability here is AST representation closure, never dynamic lifetime reachability.
  visited=set();active=set()
  def visit(n,depth):
   budget.charge(work=1,edges=1);need(depth<=128,'CEW_RESOURCE','AST graph depth','resource');need(n not in active,'CEW_GRAPH','cyclic AST graph')
   if n in visited:return
   active.add(n)
   for c in nodes[n]['children']:visit(c,depth+1)
   active.remove(n);visited.add(n)
  for seed in sorted(seeds):visit(seed,0)
  need(len(visited)==len(nodes),'CEW_GRAPH','unaccounted AST node')
 for t in raw['traits_inspection']:budget.work(4);offsets(t['range'])
@dataclass(frozen=True)
class EventWitness:
 data:object
 binding:str=field(default='unbound',init=False)
 runtime_authority:bool=field(default=False,init=False)
 source_fact_authority:bool=field(default=False,init=False)
 executable:bool=field(default=False,init=False)
 def report(self):
  value=R.thaw(self.data);value.update(binding=self.binding,runtime_authority=False,source_fact_authority=False,executable=False);return value
def observe(source,oracle,*,budget):
 need(type(budget)is R.apis()[4].SourceQueryBudget,'CEW_INPUT','canonical budget class');doc,schema_raw=schema(budget);raw_source=read(source,1<<20,budget);need(b'\0' not in raw_source,'CEW_INPUT','NUL source');build,receipt_raw,binary,inputs=native_identity(oracle,budget)
 parent=os.environ.get('CEW_SCRATCH');
 with tempfile.TemporaryDirectory(prefix='source-event-',dir=parent) as tmp:
  copy=Path(tmp)/'input.cpp';budget.charge(work=len(raw_source),copied_bytes=len(raw_source));copy.write_bytes(raw_source);raw=run_native(oracle,copy,budget)
 R.shape(doc['$defs']['raw'],raw,doc['$defs'],budget);raw_semantics(raw,raw_source,budget)
 config=dict(target=raw['target'],source_filesystem=raw['source_filesystem'],options=raw['options'],cfg_options=raw['cfg_options'],char_bits=8,pointer_bits=64,long_bits=64,little_endian=True)
 out=dict(format='clang-source-events-reference',revision=1,binding='unbound',runtime_authority=False,source_fact_authority=False,executable=False,source_sha256=digest(raw_source),config_sha256=digest(canonical(config)),compiler_sha256=COMPILER,oracle_sha256=binary,build_input_identity=inputs,schema_sha256=SCHEMA_SHA,raw=raw,obligations=['AST regions are syntactic containment, not complete C++ lexical/name-lookup or lifetime scopes.','CFG scope/lifetime/destructor elements are compiler observations, not full cleanup/lifetime/source-object proofs.','Observed throwing paths may lack automatic destructors; no EH/lifetime completeness claimed.','Type spellings and traits never substitute for canonical declaration identity or I-C27 subobject-creation evidence.','No portable ABI plan, emitter, private S/J/alias/access/union state or runtime/guest execution is established.','Translation-unit/global initialization and compiler-emitted ABI variants are not analyzed as function bodies.'])
 R.shape(doc['$defs']['report'],out,doc['$defs'],budget);need(read(source,1<<20,budget)==raw_source,'CEW_PROVENANCE','source afterguard');need(read(SCHEMA,1<<20,budget)==schema_raw,'CEW_PROVENANCE','schema afterguard');after,after_raw,after_binary,after_inputs=native_identity(oracle,budget);need(after_raw==receipt_raw and after_binary==binary and after_inputs==inputs,'CEW_PROVENANCE','native afterguard');return EventWitness(R.freeze(out))
def load_budget(path):
 path=Path(path);size=path.stat().st_size;need(size<=4096,'CEW_INPUT','budget bootstrap size')
 with path.open('rb') as stream:raw=stream.read(4097)
 need(len(raw)<=4096 and len(raw)==size,'CEW_INPUT','budget bootstrap growth/size')
 depth=0;quoted=False;escaped=False
 for c in raw.decode('utf8','strict'):
  if quoted:
   if escaped:escaped=False
   elif c=='\\':escaped=True
   elif c=='"':quoted=False
  elif c=='"':quoted=True
  elif c in '{[':depth+=1;need(depth<=8,'CEW_INPUT','budget bootstrap depth')
  elif c in '}]':depth-=1;need(depth>=0,'CEW_INPUT','budget bootstrap depth')
 d=load_json(raw);need(type(d)is dict and set(d)=={'max_work','max_edges','max_copied_bytes','max_depth'},'CEW_INPUT','budget fields')
 need(all(type(d[k])is int and 0<=d[k]<=(1<<64)-1 for k in ['max_work','max_edges','max_copied_bytes']) and type(d['max_depth'])is int and 1<=d['max_depth']<=128,'CEW_INPUT','budget counts')
 return R.apis()[4].SourceQueryBudget(**d)
def main():
 import argparse
 p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
 build=sub.add_parser('build');build.add_argument('--llvm',type=Path,required=True);build.add_argument('--output',type=Path,required=True)
 obs=sub.add_parser('observe');obs.add_argument('--oracle',type=Path,required=True);obs.add_argument('--source',type=Path,required=True);obs.add_argument('--budget',type=Path,required=True);a=p.parse_args()
 if a.command=='build':
  from build_source_event_witness import build
  build(a.llvm,a.output);return
 print(json.dumps(observe(a.source,a.oracle,budget=load_budget(a.budget)).report(),sort_keys=True,indent=2))
if __name__=='__main__':main()
