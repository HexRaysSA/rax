"""Boundary, negative and cross-owner witnesses for current candidate contracts."""
import copy
from pathlib import Path
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

from test_candidate_contract import HERE, ref, roots
from runtime_candidate import admission, comdat, fenv, flow, identity, journals, live, native, powi, services
from runtime_candidate.errors import Reject, some
from runtime_candidate.helpers import DEFAULT_OPTIONS, digest, instantiate
from runtime_candidate.wire import SCHEMA, decode, encode

ROOT=HERE.parents[1]
EXEC=ROOT/'tools/smir-format/execution'
# unittest discovery imports the local candidate package even when it contains no
# tests. Runtime uses runtime_candidate; reserve candidate for the execution
# owner's absolute imports before loading the independent actual-root witness.
for name,module in list(sys.modules.items()):
    location=getattr(module,'__file__',None)
    if (name=='candidate' or name.startswith('candidate.')) and location and HERE/'candidate' in Path(location).parents:
        del sys.modules[name]
# A nested source-role suite can prepend SEM before discovery returns here.
# Keep this suite's test-module namespace first; load SEM's package explicitly.
sys.path[:] = [str(HERE),str(EXEC)] + [entry for entry in sys.path
    if entry not in (str(HERE),str(EXEC))]
if 'candidate' not in sys.modules:
    specification=importlib.util.spec_from_file_location('candidate',EXEC/'candidate/__init__.py',
        submodule_search_locations=[str(EXEC/'candidate')])
    semantic_package=importlib.util.module_from_spec(specification)
    sys.modules['candidate']=semantic_package;specification.loader.exec_module(semantic_package)
from candidate.type_system import Types
from candidate.verify import verify
from candidate.live import Registry as ValueRegistry, validate as value_validate


def scalar(reference,value,width=32):
    return {'type':reference,'payload':{'kind':'scalar','bits':value.to_bytes((width+7)//8,'little').hex()}}


def execution_example():
    types={'payload_revision':2,'types':[
        {'id':0,'kind':'int','bits':32},
        {'id':1,'kind':'function','params':[ref(0)],'results':[ref(0)],
         'param_noundef':[False],'result_noundef':[False],'variadic':False,'cc':'portable'}],
        'memory_layouts':[]}
    function={'id':0,'signature':ref(1),'abi_signature':None,'params':[{'id':10,'type':ref(0)}],
              'entry':5,'escape':'propagate','no_return':False,'blocks':[
        {'id':5,'phis':[],'ops':[
            {'op':'constant','results':[{'id':11,'type':ref(0)}],'operands':[],
             'literal':{'kind':'bits','value':'01000000'}},
            {'op':'i_add','results':[{'id':12,'type':ref(0)}],'operands':[10,11],'flags':[]},
            {'op':'constant','results':[{'id':13,'type':ref(0)}],'operands':[],
             'literal':{'kind':'bits','value':'ffffffff'}}],
         'term':{'op':'return','values':[12]}}]}
    verified=verify(types,{'payload_revision':2,'functions':[function]},
                    {'payload_revision':1,'functions':[]})
    return verified,function


def live_example():
    verified,_=execution_example()
    image='a'*64
    frame={'activation':3,'module':image,'generation':1,'binding_generation':1,'function':0,
           'position':{'block':5,'operation':0,'predecessor':None},'status':'suspended',
           'locals':[{'id':10,'value':scalar(ref(0),3)}],'allocations':[],
           'normal':None,'unwind':None,'ticket':None,'journals':[],'bridge':None,
           'exception':None,'progress':None,'unwind_state':None}
    document={'payload_revision':2,'thread':{'payload_revision':1,'process':1,'thread':2,
        'worker':None,'epoch':7,'memory_generation':1,'journal_sequence':0,'errno':-1,
        'fenv':{'rounding':'nearest_even','flags':32,'traps':0},'diagnostic_policy':31,'frames':[frame]},
        'journals':[],'lifetimes':[],'partial_objects':[],'bridges':[],'nonlocals':[],'unwinds':[]}
    def values(module,value,thread,activation):
        return value_validate(value,verified.types,ValueRegistry(),thread,activation)
    def absent(*args):raise Reject('TEST_UNEXPECTED_METADATA')
    registry=live.Registry(1,2,7,1,{image:{'generation':1,'binding_generation':1,'pins':1,'verified':verified}},
        {},{},{},values,absent,absent,{},{},{},{})
    return document,registry


class ClosureTests(unittest.TestCase):
    def error(self,code,function,*args,**kwargs):
        with self.assertRaises(Reject) as caught:function(*args,**kwargs)
        self.assertEqual(caught.exception.code,code)

    def test_fenv_256_words_and_mode_current_flags(self):
        state=fenv.Fenv(diagnostic_mask=31)
        for rounding in [0,0x400,0x800,0xc00]:
            for flags in range(64):
                state.set_word(rounding|flags)
                self.assertEqual(state.word(),rounding|flags)
                state.set_word(0,True)
                self.assertEqual(state.environment.flags,flags)
                self.assertEqual(state.environment.rounding,0)
        for code,rounding in [(0,0xc00),(1,0),(2,0x800),(3,0x400)]:
            state.set_rounding_code(code)
            self.assertEqual((state.rounding_code(),state.environment.rounding),(code,rounding))
        before=state.getenv()
        self.error('RT_FENV_WORD',state.set_word,1<<63)
        self.error('RT_FENV_AMBIENT_ROUNDING',state.set_rounding_code,4)
        self.assertEqual(state.getenv(),before)
        self.assertEqual(state.diagnostic_mask,31)

    def test_powi_full_width_selected_steps_only(self):
        calls=[]
        def multiply(a,b):calls.append(('mul',a,b));return a*b,2
        def divide(a,b):calls.append(('div',a,b));return a//b,1
        self.assertEqual(powi.evaluate(9,0,64,one=1,multiply=multiply,divide=divide),(1,0))
        self.assertFalse(calls)
        self.assertEqual(powi.evaluate(2,1,64,one=1,multiply=multiply,divide=divide),(2,2))
        self.assertEqual(calls,[('mul',1,2)])
        calls.clear()
        self.assertEqual(powi.evaluate(1,2**32,64,one=1,multiply=multiply,divide=divide),(1,2))
        self.assertEqual(len(calls),33)  #32requiredsquares+onechosenproduct, noti32truncation.
        calls.clear()
        self.assertEqual(powi.evaluate(1,-2**63,64,one=1,multiply=multiply,divide=divide),(1,3))
        self.assertEqual(calls[-1][0],'div')

    def test_actual_type_vector_helper_shape_and_c_api_scalar_rule(self):
        definitions=[{'kind':'float','id':0,'format':'binary32'},
            {'kind':'vector','id':1,'count':2,'element':ref(0)},
            {'kind':'int','id':2,'bits':32},
            {'kind':'vector','id':3,'count':2,'element':ref(2)},
            {'kind':'vector','id':4,'count':3,'element':ref(2)},
            {'kind':'function','id':5,'params':[ref(1),ref(3)],'results':[ref(1)],
             'param_noundef':[False,False],'result_noundef':[False],'variadic':False,'cc':'portable'}]
        types=Types({'payload_revision':2,'types':definitions,'memory_layouts':[]})
        record={'kind':'internal','id':0,'namespace':'smir.internal.v1','name':'fp_ldexp','version':1,
            'catalog':digest(),'signature':ref(5),'abi':None,'types':[ref(1),ref(3)],'contract':'constrained',
            'options':{**DEFAULT_OPTIONS,'rounding':'dynamic','exceptions':'strict'}}
        instantiate(record,types.resolve)
        bad=copy.deepcopy(record);bad['types'][1]=ref(4)
        self.error('RT_HELPER_VECTOR_SHAPE',instantiate,bad,types.resolve)
        bad=copy.deepcopy(record);bad['contract']='c_fenv'
        self.error('RT_HELPER_C_LIBM_SCALAR',instantiate,bad,types.resolve)

    def test_source_unit_identity_paths_and_artifacts_separate(self):
        a=identity.source_unit('example','lib','source/unit.cc',1)
        self.assertEqual(a,identity.source_unit('example','lib','source/unit.cc',1))
        self.assertNotEqual(a,identity.source_unit('example','lib','source/./unit.cc',1))
        for path in ['/tmp/unit.cc','C:\\unit.cc','\\\\server\\share']:
            self.error('RT_UNIT_ABSOLUTE',identity.source_unit,'example','lib',path,1)

    def test_parallel_domain_admission_one_constructor_winner(self):
        for first,second in [('x86_64','aarch64'),('aarch64','x86_64')]:
            state=admission.ProcessAdmission('linux')
            barrier=threading.Barrier(2)
            effects=[];errors=[]
            def run(isa):
                plan={'personality':'linux','foreign_isa':isa,'order':[isa],'components':[[isa]]}
                barrier.wait()
                try:state.commit(plan,0,effects.append)
                except Reject as error:errors.append(error.code)
            workers=[threading.Thread(target=run,args=(isa,)) for isa in [first,second]]
            for worker in workers:worker.start()
            for worker in workers:worker.join(5);self.assertFalse(worker.is_alive())
            self.assertEqual(len(effects),1)
            self.assertEqual(errors,['RT_PROCESS_ISA'])
            self.assertEqual(state.foreign_isa,effects[0])

    def test_failure_keeps_foreign_isa_pinned(self):
        state=admission.ProcessAdmission('linux')
        plan={'personality':'linux','foreign_isa':'x86_64','order':['a'],'components':[['a']]}
        with self.assertRaises(RuntimeError):
            state.commit(plan,0,lambda module:(_ for _ in ()).throw(RuntimeError('constructor')))
        self.assertEqual(state.foreign_isa,'x86_64')
        self.assertEqual(state.modules,{'a':'failed_pinned'})

    def test_live_ssa_actual_verified_function_and_private_handoff(self):
        document,registry=live_example()
        live.validate(document,registry)
        ticket=live.Handoff(document,registry)
        self.error('RT_HANDOFF_SOURCE_NOT_PARKED',live.Handoff,document,registry)
        changed=copy.deepcopy(document);changed['thread']['frames'][0]['locals'][0]['value']=scalar(ref(0),99)
        self.error('RT_HANDOFF_CHANGED_IMAGE',ticket.resume,changed,registry,4)
        resumed=ticket.resume(document,registry,4)
        self.assertEqual((resumed['thread']['epoch'],resumed['thread']['worker']),(8,some(4)))
        live.validate(resumed,registry)
        self.error('RT_HANDOFF_REPLAY',ticket.resume,document,registry,5)

    def test_live_missing_dead_future_values_and_generation_reject(self):
        document,registry=live_example()
        bad=copy.deepcopy(document);bad['thread']['frames'][0]['locals']=[]
        self.error('RT_FRAME_LIVE_SET',live.validate,bad,registry)
        bad=copy.deepcopy(document);bad['thread']['frames'][0]['locals'].append({'id':13,'value':scalar(ref(0),0)})
        self.error('RT_FRAME_LIVE_SET',live.validate,bad,registry)
        bad=copy.deepcopy(document);bad['thread']['frames'][0]['generation']=2
        self.error('RT_FRAME_GENERATION',live.validate,bad,registry)
        verified,function=execution_example()
        analysis=flow.Flow(function)
        self.assertEqual([set(analysis.frontier({'block':5,'operation':i,'predecessor':None})) for i in range(4)],
                         [{10},{10,11},{12},{12}])

    def test_error_conversions_are_explicit_and_unknown_retained(self):
        self.assertEqual(services.from_personality('darwin',35)['status'],11)
        self.assertEqual(services.from_personality('darwin',11)['status'],35)
        self.assertEqual(services.to_personality('darwin',11),35)
        value=services.from_personality('win32',0x7fffffff)
        self.assertEqual(value,{'status':5,'cause':{'domain':'win32','raw':0x7fffffff}})
        self.error('RT_ERROR_STATUS',services.to_personality,'linux',999999)

    def test_service_guards_zero_length_paths_and_progress(self):
        handles={1:{'kind':'file','live':True}}
        checks=[]
        guard=lambda *span:checks.append(span)
        request=services.request('file.write',[1,0,0],capabilities={'file'},handles=handles,guard=guard)
        self.assertEqual(checks,[])
        self.assertEqual(services.result(request,0,0),(0,0))
        services.request('file.open',[4096,3,1,0],capabilities={'file'},handles={},guard=guard,inputs={0:b'abc'})
        self.error('RT_SERVICE_UTF8',services.request,'file.open',[4096,1,1,0],
                   capabilities={'file'},handles={},guard=guard,inputs={0:b'\xff'})
        request=services.request('file.read',[1,4096,100000],capabilities={'file'},handles=handles,guard=guard)
        self.assertEqual(request['spans'],[(4096,65536,'out')])
        self.error('RT_SERVICE_PROGRESS',services.result,request,0,65537)
        self.error('RT_SERVICE_ERROR_VALUE',services.result,request,5,1)
        self.error('RT_SERVICE_CAPABILITY',services.request,'file.read',[1,4096,1],
                   capabilities=set(),handles=handles,guard=guard)

    def test_canonical_metadata_structures_and_reserved_bytes(self):
        self.assertEqual(services.structure('time16',struct.pack('<qII',-1,999999999,0))['seconds'],-1)
        self.error('RT_SERVICE_NANOSECONDS',services.structure,'time16',struct.pack('<qII',0,1000000000,0))
        self.error('RT_SERVICE_RESERVED',services.structure,'time16',struct.pack('<qII',0,0,1))
        self.assertEqual(services.structure('dir_entry',struct.pack('<IIII',1,1,3,0)+b'abc')['name'],'abc')
        self.error('RT_SERVICE_DIRENT',services.structure,'dir_entry',struct.pack('<IIII',1,1,4,0)+b'abc')
        for item in services.catalog()['structures'].values():
            self.assertEqual(struct.calcsize(item['format']),item['size'])


if __name__=='__main__':unittest.main()
