"""R041 actual SEM evaluation plus independent whole-stage publication oracle."""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import ast
from pathlib import Path
import subprocess
import sys
import unittest

from test_candidate_contract import HERE, ref

# Run in an isolated process: execution's canonical candidate/common names must
# not replace a package already used by another owner's independent tests.
SCRIPT=r'''
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.raw import Raw
from candidate.initializers import evaluate_initializer
from candidate.type_system import ref
from test_candidate import constant, decl, operation
from test_candidate_initializers import initializer_roots
from test_candidate_storage_join import reference_image
from candidate.bindings import runtime_package_module
R=runtime_package_module('initialization');L=runtime_package_module('linking')
Reject=runtime_package_module('errors').Reject

def reserve_actual(context,memory=None):
    def forbidden(*args):raise AssertionError('restricted initializer invoked source helper')
    machine=Machine(context.execution_checked,imports={('self',0):forbidden})
    if memory is not None:machine.memory=memory
    storage={}
    for kind,records in [('data',context.sections[4]['segments']),
                         ('tls',[v['storage'] for v in context.sections[7]['segments']])]:
        for segment in records:
            raw=bytes.fromhex(segment['initial'])+bytes(segment['zero_fill'])
            pointer=machine.memory.allocate(len(raw),segment['alignment'])
            machine.memory.raw_store(pointer,Raw.integer(8*len(raw),int.from_bytes(raw,'little')))
            machine.memory.objects[pointer.origin]['mutable']=segment['mutable']
            storage[kind,segment['id']]=pointer
    for key,symbol in context.symbols.items():
        definition=symbol['definition']['some']
        if definition['kind'] in {'data','tls'}:machine.symbols[key]=storage[definition['kind'],definition['segment']]
    return machine

def fixture(ops=None,result_type=5,layout=9,source_kind='data',offset=0,edit=None):
    roots=initializer_roots(ops,result_type,layout)
    storage={'id':9,'layout':None,'nominal':None,'abi_binding':None,'alignment':1,'mutable':False,
             'initial':'a5'*24,'poison':'00'*24,'undef':'00'*24,'zero_fill':0,'zero_shadow':'defined'}
    if source_kind=='data':roots[4]['segments'].append(storage)
    else:roots[7]['segments'].append({'storage':storage,'initializers':[],'destructors':[],'initialization':'static'})
    roots[5]['relocations']=[]
    roots[5]['constant_initializers']=[{'id':0,'source_kind':source_kind,'source':9,'offset':offset,
        'layout':ref(layout),'function':ref(7),'association':None}]
    if edit is not None:edit(roots)
    c=RootContext(roots);c.verify_abi();c.verify_execution();m=reserve_actual(c)
    rc=L.Context(site=c.abi['identity'],execution=c.execution,nominal=c.nominal,function=c.function,
        symbol=c.runtime_symbol,execution_equal=c.types.equal,nominal_compatible=c.abi_graph.boundary_compatible,
        storage_layout=c.memory_layout,symbol_body=None,symbol_identity=None,abi_entity=c.abi_entity,
        target_entity=c.target_entity,nominal_layout=c.abi_graph.layout,signature_compatible=c.abi_graph.signature_compatible,grants=frozenset({'memory'}))
    L.validate({i:c.sections[i] for i in L.ROOTS},rc)
    def body(reference):
        symbol=c.runtime_symbol(reference);definition=symbol['definition']['some']
        storage=next(v for v in c.sections[4]['segments'] if v['id']==definition['segment'])
        return bytes.fromhex(storage['initial'])
    rc.symbol_body=body
    image={'bytes':bytearray(b'\xa5'*24),'poison':bytearray(24),'undef':bytearray(24),'origins':[],
           'mutable':False,'sealed':False}
    selected=runtime_package_module('selection').select_definitions(
        {'a'*64:{i:c.sections[i] for i in L.ROOTS}},{'a'*64:rc},['a'*64],
        lambda a,x,b,y:c.types.equal(x,y),
        lambda a,x,b,y:c.abi_graph.boundary_compatible(x,y),
        signature_compatible=lambda a,x,b,y:c.abi_graph.signature_compatible(x,y))
    modules={'a'*64:{'context':c,'generation':1,'pins':1,'phase':'admitted'}}
    threads=[None] if source_kind=='data' else [11,12]
    store=R.Store({('a'*64,source_kind,9,t):image for t in threads},modules,
                  {('a'*64,t):m for t in threads},selected)
    return c,m,rc,store

def prepare(store,rc,evaluator=evaluate_initializer):
    return store.prepare(['a'*64],{'a'*64:rc},evaluator,lambda *a:None)

c,m,rc,store=fixture(offset=1)
before=deepcopy(store.images);t=prepare(store,rc)
assert store.images==before and not store.exposed and not store.exposed_code
store.commit(t);out=store.images['a'*64,'data',9,None]
expected=m.symbols[('self',2)].address-m.symbols[('self',1)].address
assert int.from_bytes(out['bytes'][1:9],'little')==expected
assert out['bytes'][:1]==b'\xa5' and out['bytes'][9:]==b'\xa5'*15 and out['sealed']
assert store.exposed=={(m.symbols[('self',i)].origin,m.symbols[('self',i)].generation) for i in [1,2]}
assert not m.memory.exposed and not m.exposed_code
try:store.commit(t);raise AssertionError('replayed transaction')
except Reject as e:assert e.code=='RT_INITIALIZER_AUTHORITY'

# Failed later initializer cannot publish an earlier patch or exposure.
c,m,rc,store=fixture();before=deepcopy(store.images)
def fails(*a,**k):
    evaluate_initializer(*a,**k)
    raise RuntimeError('independent evaluator fault')
try:prepare(store,rc,fails);raise AssertionError('fault accepted')
except RuntimeError:pass
assert store.images==before and not store.exposed
fresh=prepare(store,rc)
try:store.commit(replace(fresh));raise AssertionError('forged transaction')
except Reject as e:assert e.code=='RT_INITIALIZER_AUTHORITY'
store.modules['a'*64]['generation']=2
try:store.commit(fresh);raise AssertionError('stale transaction')
except Reject as e:assert e.code=='RT_INITIALIZER_STALE'
assert store.images==before

# Non-byte integer patches significant access bytes only, preserving tail bytes.
c,m,rc,store=fixture([operation('constant',[decl(0,10)],literal={'kind':'poison'})],10,2)
store.commit(prepare(store,rc));out=store.images['a'*64,'data',9,None]
assert out['poison'][:9]==b'\xff'*8+b'\x01' and out['poison'][9:]==bytes(15)
assert out['bytes'][9:]==b'\xa5'*15

# Actual source code tokens expose CODE only. PtrToAddr never exposes either.
for conversion in ['ptrtoaddr','ptrtoint']:
    ops=[operation('address_of',[decl(0,600)],symbol=ref(0)),operation(conversion,[decl(1,5)],[0])]
    # Add actual code pointer type before executable admission.
    roots=initializer_roots(ops,extra_types=[{'id':600,'kind':'code_ptr','signature':ref(12)}])
    # Reuse fixture creation with its type extension via a narrow builder patch.
    import test_candidate_initializers as fixtures
    original=initializer_roots
    def with_types(*args,**kwargs):return roots
    globals()['initializer_roots']=with_types
    try:c,m,rc,store=fixture()
    finally:globals()['initializer_roots']=original
    p=m.register_function(ref(0),ref(0),ref(12))
    store.commit(prepare(store,rc))
    assert store.exposed_code==({p.address} if conversion=='ptrtoint' else set()) and not store.exposed

# Per-TID static TLS patches are separate; data initializer cannot capture TLS.
c,m,rc,store=fixture([constant(0,5,'2300000000000000')],source_kind='tls')
store.commit(prepare(store,rc))
assert [int.from_bytes(store.images['a'*64,'tls',9,t]['bytes'][:8],'little') for t in [11,12]]==[35,35]
c,m,rc,store=fixture([operation('address_of',[decl(0,4)],symbol=ref(3)),
                      operation('ptrtoint',[decl(1,5)],[0])])
try:prepare(store,rc);raise AssertionError('ambient TLS accepted')
except Reject as e:assert e.code=='RT_INITIALIZER_AMBIENT_TLS'

# Quota checks also cover no-evaluation and discarded-only storage.
c,m,rc,store=fixture()
try:R.Store(store.images,store.modules,store.machines,store.selection,max_bytes=23);raise AssertionError('quota')
except Reject as e:assert e.code=='RT_INITIALIZER_RESOURCE'
try:store.prepare(['a'*64],{'a'*64:rc},evaluate_initializer,lambda *a:None,max_bytes=23);raise AssertionError('quota')
except Reject as e:assert e.code=='RT_INITIALIZER_RESOURCE'
# A code_integer leaf exposes the actual issued token to a later pure inttoptr.
def code_leaf(roots):
    roots[1]['types'].append({'id':600,'kind':'code_ptr','signature':ref(12)})
    roots[1]['types'].sort(key=lambda x:x['id'])
    roots[1]['memory_layouts'].append({'id':10,'type':ref(600),'size':8,'access_bytes':8,'alignment':8,
                                     'fields':[],'element':None,'stride':0})
    roots[5]['relocations']=[{'source_kind':'data','source':9,'offset':0,'width':8,'integer_bits':64,
        'kind':'function_integer','target':ref(0),'addend':0,'derivation':[],'check_base':False,
        'flags':[],'inrange':None}]
ops=[constant(0,5,'0200000000000000'),operation('inttoptr',[decl(1,600)],[0])]
c,m,rc,store=fixture(ops,600,10,offset=8,edit=code_leaf)
p=m.register_function(ref(0),ref(0),ref(12));assert p.address==2
resolve=lambda *a:{'kind':'function','live':True,'owner':'a'*64,'generation':1,'value':p.address,
                   'object':p.origin,'object_generation':p.generation,'portable':True}
store.commit(store.prepare(['a'*64],{'a'*64:rc},evaluate_initializer,resolve))
image=store.images['a'*64,'data',9,None]
assert store.exposed_code=={p.address} and not store.exposed
assert all(o['domain']=='code' and o['object']=={'some':p.origin} for o in image['origins'])
assert len(image['origins'])==8 and all(o['offset']>=64 for o in image['origins'])
assert not m.exposed_code

# The adapter must not clone actual reserved backing before S074 budget checks.
c,m,rc,store=fixture()
class CopyBomb(dict):
    def __deepcopy__(self,memo):raise AssertionError('backing cloned before quota')
first=next(iter(m.memory.objects));m.memory.objects[first]=CopyBomb(m.memory.objects[first])
m.memory.objects[first]['size']=2**40
try:prepare(store,rc);raise AssertionError('oversized memory')
except Reject as e:assert e.code=='RT_INITIALIZER_RESOURCE'

# Actual two-module selection: discard CE AND leaf-only relocation before effect.
def grouped(name,with_ce):
    def edit(roots):
        roots[2]['manifest']['key']['name']=name
        roots[1]['types'].append({'id':700,'kind':'array','element':ref(9),'count':24})
        roots[2]['symbols'].append({'id':99,'namespace':'example','name':'static_group','kind':'data',
            'source_linkage':'none','binding':'weak','visibility':'default','execution':ref(700),
            'nominal':None,'abi_signature':None,'definition':{'some':{'kind':'data','segment':9}},
            'size':{'some':24},'alignment':1,'comdat':{'some':0},'fallback':None})
        roots[2]['comdats']=[{'id':0,'namespace':'example','name':'static_group',
            'selection':'any','key_symbol':99,'members':[99]}]
        if with_ce:roots[5]['constant_initializers'][0]['association']={'some':ref(99)}
        else:
            roots[5]['constant_initializers']=[]
            roots[5]['relocations']=[{'source_kind':'data','source':9,'offset':0,'width':8,'integer_bits':64,
                'kind':'data_integer','target':ref(1),'addend':0,'derivation':[],'check_base':False,'flags':[],
                'inrange':None}]
    return edit
for with_ce in [True,False]:
    a,ma,ra,sa=fixture(edit=grouped('first',with_ce));b,mb,rb,sb=fixture(edit=grouped('second',with_ce))
    ids=['a'*64,'b'*64];contexts=dict(zip(ids,[a,b]));runtime_contexts=dict(zip(ids,[ra,rb]))
    for c,r in [(a,ra),(b,rb)]:
        def body(ref,c=c):
            symbol=c.runtime_symbol(ref);storage=c.sections[4]['segments'][-1]
            assert symbol['definition']['some']['segment']==storage['id']
            return bytes.fromhex(storage['initial'])
        r.symbol_body=body
    modules={i:{n:c.sections[n] for n in L.ROOTS} for i,c in contexts.items()}
    graph=type(a.abi_graph)(a.abi,ids[0],{i:c.abi for i,c in contexts.items()},
        families={i:L.family(c.sections[2]['manifest']['key']) for i,c in contexts.items()})
    plan=runtime_package_module('selection').select_definitions(modules,runtime_contexts,ids,
        lambda x,p,y,q:contexts[x].types.digest(p)==contexts[y].types.digest(q),
        lambda x,p,y,q:graph.boundary_compatible(p,q,x,y),
        data_compatible=lambda x,p,y,q:graph.data_boundary_compatible(p,q,x,y),
        signature_compatible=lambda x,p,y,q:graph.signature_compatible(p,q,x,y))
    assert plan.symbols[ids[1],99]==(ids[0],99)
    images=deepcopy(sa.images)
    # A retained private source forces processing of the loser module while its
    # discarded segment9 has NO reservation and must never be looked up.
    images[ids[1],'data',0,None]={'bytes':bytearray([7,0,0,0]),'poison':bytearray(4),'undef':bytearray(4),
                                'origins':[],'sealed':False,'mutable':True}
    facts={i:{'context':c,'generation':1,'pins':1,'phase':'admitted'} for i,c in contexts.items()}
    st=R.Store(images,facts,{(ids[0],None):ma,(ids[1],None):mb},plan)
    calls=[]
    def evaluate(c,*args,**kwargs):
        assert c is a
        calls.append(c)
        return evaluate_initializer(c,*args,**kwargs)
    def resolve(owner,thread,ref):
        assert owner==ids[0]
        p=ma.symbols[('self',ref['id'])];obj=ma.memory.objects[p.origin]
        return {'kind':'data','live':True,'owner':owner,'generation':1,'value':p.address,
                'object':p.origin,'object_generation':p.generation,'object_base':obj['address'],
                'object_size':obj['size'],'restriction':None}
    st.commit(st.prepare(ids,runtime_contexts,evaluate,resolve))
    assert len(calls)==(1 if with_ce else 0)
    assert (ids[1],'data',9,None) not in st.images
    # Prior published winner stays OUTSIDE the new-only admission Store.
    old_images=deepcopy(sa.images)
    new_image=deepcopy(images[ids[1],'data',0,None])
    new_store=R.Store({(ids[1],'data',0,None):new_image},{ids[1]:facts[ids[1]]},
                      {(ids[1],None):mb},plan)
    def forbidden(*args,**kwargs):raise AssertionError('discarded source evaluated or resolved')
    new_store.commit(new_store.prepare([ids[1]],{ids[1]:rb},forbidden,forbidden))
    assert not new_store.exposed and not new_store.exposed_code and sa.images==old_images


# A new-only transaction may bind an actual prior selected weak provider.
def weak_source(roots):
    for symbol in roots[2]['symbols']:
        symbol['binding']='weak' if symbol['id']==1 else 'local'
    roots[5]['constant_initializers'][0]['offset']=8
    roots[5]['relocations']=[{'source_kind':'data','source':9,'offset':0,'width':8,'integer_bits':64,
        'kind':'data_integer','target':ref(1),'addend':0,'derivation':[],'check_base':False,'flags':[],
        'inrange':None}]
a,ma,ra,sa=fixture(edit=weak_source);b,mb,rb,sb=fixture(edit=weak_source)
mb=reserve_actual(b,memory=ma.memory)
ids=['a'*64,'b'*64];contexts=dict(zip(ids,[a,b]));runtime_contexts=dict(zip(ids,[ra,rb]))
graph=type(a.abi_graph)(a.abi,ids[0],{i:c.abi for i,c in contexts.items()},
    families={i:L.family(c.sections[2]['manifest']['key']) for i,c in contexts.items()})
plan=runtime_package_module('selection').select_definitions(
    {i:{n:c.sections[n] for n in L.ROOTS} for i,c in contexts.items()},runtime_contexts,ids,
    lambda x,p,y,q:contexts[x].types.digest(p)==contexts[y].types.digest(q),
    lambda x,p,y,q:graph.boundary_compatible(p,q,x,y),
    data_compatible=lambda x,p,y,q:graph.data_boundary_compatible(p,q,x,y),
    signature_compatible=lambda x,p,y,q:graph.signature_compatible(p,q,x,y))
assert plan.symbols[ids[1],1]==(ids[0],1)
mb.symbols[('self',1)]=ma.symbols[('self',1)]  # Actual selected reservation, not local loser.
old=ma.symbols[('self',1)];old_object=ma.memory.objects[old.origin]
resolve=lambda *args:{'kind':'data','live':True,'owner':ids[0],'generation':7,'value':old.address,
    'object':old.origin,'object_generation':old.generation,'object_base':old_object['address'],
    'object_size':old_object['size'],'restriction':None}
images={(ids[1],'data',9,None):next(iter(sb.images.values()))}
facts={ids[1]:{'context':b,'generation':5,'pins':1,'phase':'admitted'}}
cap=object();leases={cap:{'module':ids[0],'generation':7,'live':True,'kind':'object'}}
providers={ids[0]:{'context':a,'generation':7,'pins':1,'phase':'published',
                   'held_lease':cap,'lease_table':leases}}
store=R.Store(images,facts,{(ids[1],None):mb},plan,retained_modules=providers)
before=deepcopy(ma.memory.objects)
ticket=store.prepare([ids[1]],{ids[1]:rb},evaluate_initializer,resolve)
store.commit(ticket)
assert int.from_bytes(store.images[ids[1],'data',9,None]['bytes'][:8],'little')==old.address
assert (old.origin,old.generation) in store.exposed and ma.memory.objects==before and not ma.memory.exposed
store=R.Store(images,facts,{(ids[1],None):mb},plan,retained_modules=providers)
ticket=store.prepare([ids[1]],{ids[1]:rb},evaluate_initializer,resolve)
providers[ids[0]]['pins']=0
try:store.commit(ticket);raise AssertionError('stale retained provider')
except Reject as e:assert e.code=='RT_INITIALIZER_PROVIDER'
assert store.images==images and not store.exposed
providers[ids[0]]['pins']=1;providers[ids[0]]['phase']='closing'
ticket=store.prepare([ids[1]],{ids[1]:rb},evaluate_initializer,resolve)
leases[cap]['live']=False
try:store.commit(ticket);raise AssertionError('released retained lease')
except Reject as e:assert e.code=='RT_INITIALIZER_PROVIDER_LEASE'
assert store.images==images and not store.exposed

# Actual ABI+SEM roots must reject independently selected physical alias chains.
for depth in [1,2]:
    def aliases(roots,depth=depth):
        grouped('aliases',True)(roots)
        for index in range(depth):
            identity=100+index
            roots[2]['symbols'].append({'id':identity,'namespace':'example','name':'alias'+str(index),
                'kind':'data','source_linkage':'none','binding':'weak','visibility':'default',
                'execution':ref(700),'nominal':None,'abi_signature':None,
                'definition':{'some':{'kind':'alias','target':ref(99+index)}},'size':{'some':24},
                'alignment':1,'comdat':{'some':index+1},'fallback':None})
            roots[2]['comdats'].append({'id':index+1,'namespace':'example','name':'alias_group'+str(index),
                'selection':'any','key_symbol':identity,'members':[identity]})
    try:fixture(edit=aliases);raise AssertionError('independent physical alias owner accepted')
    except Reject as e:assert e.code=='RT_INITIALIZER_SHARED_SELECTION'

# Fixed absence proofs also depend on the exact accepted selection/binding plan.
from test_candidate_weak_initializers import weak_modules
for kind in ['data','function']:
    consumer,reservations=weak_modules(kind)
    cap=reservations.reserve_weak(consumer,ref(901,0))
    reservations.selection.owners=frozenset({'tampered'})
    try:reservations.verify_weak(cap,consumer,ref(901,0));raise AssertionError('changed selection')
    except Reject as e:assert e.code=='RT_WEAK_SELECTION'

print('actual_S074_R041: packed-byte-patch, multibase, rollback, forged/stale, i65, CODE, TLS2, ambientTLS, quotas PASS')
'''


class InitializationTests(unittest.TestCase):
    def test_actual_semantics_whole_staging_and_rejections(self):
        # Test invariants remain active while the actual reference modules run
        # under -O; the tested implementation must not rely on Python assert.
        class ExplicitChecks(ast.NodeTransformer):
            def visit_Assert(self,node):
                return ast.If(test=ast.UnaryOp(op=ast.Not(),operand=node.test),body=[ast.Raise(
                    exc=ast.Call(func=ast.Name(id='AssertionError',ctx=ast.Load()),
                                 args=[node.msg or ast.Constant(value=f'invariant line {node.lineno}')],keywords=[]),
                    cause=None)],orelse=[])
        source=ast.unparse(ast.fix_missing_locations(ExplicitChecks().visit(ast.parse(SCRIPT))))
        result=subprocess.run([sys.executable,*([] if __debug__ else ['-O']),'-B','-c',source],
                              cwd=HERE.parents[1]/'tools/smir-format/execution',
                              text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('quotas PASS',result.stdout)


if __name__=='__main__':unittest.main()
