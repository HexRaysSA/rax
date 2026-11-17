"""Adversarial protocols, actual-root shapes, and independent ABI crosschecks."""
import copy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import struct
import sys
import threading
import unittest

from test_candidate_contract import HERE, ref, roots
from test_candidate_closure import execution_example, live_example, Types
from runtime_candidate import comdat, exceptions, host, lifetimes, linking, live, native, requirements, selection, startup, tls
from runtime_candidate.errors import Reject, some
from runtime_candidate.wire import decode, encode


class ProtocolTests(unittest.TestCase):
    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(Reject) as caught:function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def group(self, ordinal, members, policy='any'):
        return {'key':'g','selection':policy,'key_symbol':'a','members':members,'input_ordinal':ordinal}

    def member(self, name, body=b'x', abi='a'*64):
        return {'symbol':name,'abi':abi,'kind':'function','extent':len(body),'body':body,'extent_policy':'fixed'}

    def test_comdat_unequal_whole_members_and_union_abi(self):
        a=self.member('a');b=self.member('b');c=self.member('c')
        for policy in ['any','largest','samesize']:
            self.assertEqual(comdat.select([self.group(0,[a,b],policy),self.group(1,[a,c],policy)]),[0])
        self.error('RT_COMDAT_EXACTMATCH',comdat.select,[self.group(0,[a,b],'exactmatch'),self.group(1,[a,c],'exactmatch')])
        # Third group's member must compare with SECOND group's first occurrence.
        self.error('RT_COMDAT_ABI',comdat.select,[self.group(0,[a]),self.group(1,[a,b]),
            self.group(2,[a,{**b,'abi':'b'*64}])])

    def test_all_comdat_selection_kinds_and_stable_ties(self):
        a,b=self.member('a'),self.member('a',b'xx')
        for policy,expected in [('any',[2]),('largest',[5]),('nodeduplicate',[2,5])]:
            self.assertEqual(comdat.select([self.group(5,[b],policy),self.group(2,[a],policy)]),expected)
        self.error('RT_COMDAT_SAMESIZE',comdat.select,[self.group(0,[a],'samesize'),self.group(1,[b],'samesize')])
        self.error('RT_COMDAT_DUPLICATE',comdat.select,[self.group(0,[a],'noduplicates'),self.group(1,[a],'noduplicates')])
        self.assertEqual(comdat.select([self.group(0,[a],'any'),self.group(1,[b],'largest')]),[1])

    def selection_inputs(self, member_count=(2,1)):
        modules={};contexts={}
        for index, count in enumerate(member_count):
            artifact=str(index+1)*64
            root=roots()
            root[2]['manifest']['identity']=artifact
            root[2]['symbols']=[]
            for identity in range(count):
                root[2]['symbols'].append({'id':identity,'namespace':'test','name':chr(97+identity),
                    'kind':'function','source_linkage':'none','binding':'weak','visibility':'default',
                    'execution':ref(1),'nominal':None,'abi_signature':None,'definition':some({'kind':'function','target':ref(identity+10)}),
                    'size':None,'alignment':1,'comdat':some(0),'fallback':None})
            root[2]['comdats']=[{'id':0,'namespace':'test','name':'g','selection':'any','key_symbol':0,
                                  'members':list(range(count))}]
            modules[artifact]=root
            class Context:
                def symbol_body(self, reference):return bytes([reference['id']+1])
            contexts[artifact]=Context()
        return modules,contexts,list(modules)

    def test_actual_root_selection_function_redirect_and_missing_member(self):
        modules,contexts,order=self.selection_inputs((1,2))
        plan=selection.select_definitions(modules,contexts,order,lambda *a:True,lambda *a:True)
        self.assertEqual(plan.symbol(order[1],0),(order[0],0))
        self.assertEqual(plan.function(order[1],10),(order[0],10))
        self.error('RT_SELECTION_DISCARDED_MEMBER',plan.symbol,order[1],1)
        self.error('RT_SELECTION_DISCARDED_FUNCTION',plan.function,order[1],11)
        self.assertEqual(len(plan.kept_groups),1)

    def test_selection_rejects_actual_graph_mismatch_and_live_replacement(self):
        modules,contexts,order=self.selection_inputs((1,1))
        self.error('RT_SELECTION_EXECUTION',selection.select_definitions,modules,contexts,order,
                   lambda *a:False,lambda *a:True)
        for module in modules.values():module[2]['comdats'][0]['selection']='largest'
        # Existing last module cannot be replaced by first input, including tie.
        scope=('public','test','g')
        self.error('RT_COMDAT_LIVE_REPLACEMENT',selection.select_definitions,modules,contexts,order,
                   lambda *a:True,lambda *a:True,prior={scope:(order[1],0)})

    def test_selection_shared_function_conflict(self):
        modules,contexts,order=self.selection_inputs((2,1))
        a=modules[order[0]][2]
        a['symbols'][1]['definition']['some']['target']=ref(10)
        a['symbols'][1]['comdat']=None
        a['comdats'][0]['members']=[0]
        self.error('RT_COMDAT_SHARED_FUNCTION',selection.select_definitions,modules,contexts,order,
                   lambda *a:True,lambda *a:True)

    def test_requirement_exact_versions_registration_not_file_grants(self):
        registry=requirements.Registry({('runtime','portable',1),('feature','threads',1)})
        entries=[{'kind':'feature','name':'threads','version':1},{'kind':'runtime','name':'portable','version':1}]
        requirements.validate(entries,registry.supports)
        self.error('RT_REQUIREMENT_UNSUPPORTED',requirements.validate,[{**entries[0],'version':2}],registry.supports)
        self.error('RT_REQUIREMENT_UNREGISTERED',requirements.validate,entries,None)
        self.error('RT_REQUIREMENT_ORDER',requirements.validate,list(reversed(entries)),registry.supports)
        self.error('RT_REQUIREMENT_KIND',requirements.validate,[{**entries[0],'kind':'wildcard'}],registry.supports)

    def host_call(self):
        value={'payload':{'kind':'raw','bits':'ff01','poison':'0100','undef':'0200','origins':[]}}
        return host.Call([value],[{'kind':'raw','bits':9,'noundef':False}],[{'kind':'int','bits':9}])

    def test_host_scalar_private_results_pending_and_once(self):
        call=self.host_call()
        self.assertEqual(call.arguments,(b'\xfc\x01',))
        self.error('RT_HOST_CALL_STATE',call.result_bits,0,b'\x01\x00')
        call.enter(lambda *args:None)
        self.error('RT_HOST_RETURN_TYPES',call.returned,[host.ResultValue(call,0,b'\xff\xff')])
        self.error('RT_HOST_RETURN_PACKET',call.complete,host.ReturnPacket(call,()))
        result=call.result_bits(0,b'\x01\x00');packet=call.returned([result])
        call.complete(packet)
        self.assertEqual(call.publish(),(b'\x01\x00',))
        self.error('RT_HOST_COMMIT',call.publish)
        self.error('RT_HOST_REPLAY',call.complete,packet)

    def test_host_callback_exception_contained_and_abandoned_no_publication(self):
        call=self.host_call()
        def failure(*args):raise RuntimeError('host failure')
        call.enter(failure)
        self.assertEqual(call.state,'failed')
        call=self.host_call();call.enter(lambda *args:None)
        packet=call.returned([call.result_bits(0,b'\x00\x00')]);call.abandon();call.complete(packet)
        self.assertEqual(call.state,'abandoned_done')
        self.error('RT_HOST_COMMIT',call.publish)
        fresh=self.host_call();fresh.abandon()
        self.error('RT_HOST_REPLAY',fresh.enter,lambda *a:None)

    def test_startup_utf8_arrays_null_termination_and_onepast(self):
        image=startup.build('program',['a',''],[{'name':'X','value':'\u03bb'}])
        objects={o['object']:o for o in image['objects']}
        self.assertEqual(image['argc'],3)
        argv=objects[image['argv']]
        self.assertEqual(argv['alignment'],8)
        self.assertEqual(bytes.fromhex(argv['bytes'])[-8:],bytes(8))
        self.assertEqual(len(argv['origins']),3)
        self.assertTrue(all(origin['range'] is None for origin in argv['origins']))
        self.assertTrue(all(o['poison']==o['undef']=='00'*o['size'] for o in objects.values()))
        self.error('RT_STARTUP_UTF8',startup.build,'p',['\ud800'],[])
        self.error('RT_STARTUP_ENVIRONMENT',startup.build,'p',[],[{'name':'A=B','value':''}])
        self.error('RT_STARTUP_RESOURCE',startup.build,'p',[],[],base=2**64-2)
        self.assertEqual(startup.exit_status(-1,'windows'),2**32-1)
        self.assertEqual(startup.exit_status(-1,'linux'),255)

    def native_context(self, isa='x86_64'):
        sizes=[128,256,16,112,32] if isa=='x86_64' else [256,512,16,0,16]
        context={'isa':isa,'profile':isa+'_v1',**{k:bytes(n).hex() for k,n in
            zip(['integer','vector','control','x87','tls'],sizes)},'code_object':1,'code_generation':2,
            'pc':4096,'stack_object':2,'stack_generation':3,'unwind_row':0,'opaque_extension':''}
        integer=bytearray.fromhex(context['integer'])
        struct.pack_into('<Q',integer,32 if isa=='x86_64' else 248,8192)
        context['integer']=integer.hex()
        objects={1:{'live':True,'kind':'native_code','generation':2,'address':4096,'size':16},
                 2:{'live':True,'kind':'stack','generation':3,'address':8192,'size':4096}}
        options={'isa':isa,'objects':objects,'thread_tls':context['tls'],'unwind_rows':{
            (1,2,0):{'lower':4096,'upper':4112,'profile':isa+'_v1'}}}
        return context,options

    def test_native_context_both_profiles_extensions_generation_and_x87(self):
        for isa in ['x86_64','aarch64']:
            context,options=self.native_context(isa);native.validate(context,**options)
            bad={**context,'opaque_extension':'00'}
            self.error('RT_NATIVE_EXTENSION',native.validate,bad,**options)
            self.error('RT_NATIVE_CODE_LEASE',native.validate,{**context,'code_generation':1},**options)
        context,_=self.native_context()
        x87=bytearray(112)
        for i in range(8):x87[i*10:(i+1)*10]=bytes([i])*10
        struct.pack_into('<H',x87,82,5<<11);context['x87']=x87.hex()
        self.assertEqual(native.x87_logical(context,0),bytes([5])*10)
        self.assertEqual(native.x87_logical(context,7),bytes([4])*10)
        self.assertEqual(native.mmx(context,0),bytes(8))

    def exception_registry(self):
        objects={1:{'live':True,'generation':1,'address':4096,'size':16,'alignment':16},
                 2:{'live':True,'generation':1,'address':8192,'size':32,'alignment':8}}
        registry=exceptions.Registry(1,objects,lambda code:code in {'default','custom'},
            lambda payload,cert:cert==('T',1),'default')
        facade=registry.allocate(7,object_id=1,nominal='T',destructor='T::~T',proxy_object=2)
        return registry,facade

    def test_exception_construction_failure_never_complete_destructor(self):
        registry,facade=self.exception_registry()
        self.error('RT_EH_THROW_STATE',registry.raise_initial,facade,7)
        self.assertIsNone(registry.release(facade,7))
        self.assertEqual(next(iter(registry.payloads.values()))['destructor_entries'],0)
        self.error('RT_EH_STALE_FACADE',registry.object_address,facade,7)

    def test_exception_owner_cross_thread_fresh_facade_and_last_destructor_once(self):
        registry,facade=self.exception_registry()
        registry.complete_construction(facade,7,('T',1));registry.raise_initial(facade,7)
        pointer=registry.object_address(facade,7)
        adjusted=replace(pointer,address=pointer.address+8)
        registry.select_catch(facade,7,adjusted)
        self.assertEqual(registry.catch_object(facade,7),adjusted)
        self.assertEqual(registry.uncaught(7),1)  # getter has no begin transition
        registry.begin_catch(facade,7);owner=registry.current_owner(7)
        self.assertIsNone(registry.end_catch(facade,7))
        fresh=registry.owner_rethrow(owner,9)
        self.assertNotEqual(fresh,facade)
        self.error('RT_EH_FACADE_OWNER',registry.object_address,fresh,7)
        forged=exceptions.Facade(fresh.process,fresh.identity,7)
        self.error('RT_EH_STALE_FACADE',registry.object_address,forged,7)
        registry.select_catch(fresh,9,pointer);registry.begin_catch(fresh,9)
        registry.end_catch(fresh,9)
        cleanup=registry.owner_release(owner)
        calls=[];registry.run_cleanup(cleanup,calls.append)
        self.assertEqual(calls,['T::~T'])
        self.error('RT_EH_CLEANUP_REPLAY',registry.run_cleanup,cleanup,calls.append)
        self.error('RT_EH_OWNER_POINTER',registry.owner_retain,owner)

    def test_exception_proxy_not_payload_interior_or_copied_header_authority(self):
        registry,facade=self.exception_registry()
        pointer=registry.object_address(facade,7)
        self.error('RT_EH_OWNER_POINTER',registry.owner_retain,pointer)
        registry.complete_construction(facade,7,('T',1));registry.raise_initial(facade,7)
        registry.select_catch(facade,7,pointer);registry.begin_catch(facade,7)
        owner=registry.current_owner(7)
        for bad in [replace(owner,address=owner.address+1),replace(owner,generation=2),replace(owner,object=3)]:
            self.error('RT_EH_OWNER_POINTER',registry.owner_retain,bad)
        self.assertEqual(len(registry.proxies[2]['header']),32)

    def test_termination_implicit_causing_catch_handler_capture_and_uncaught(self):
        registry,facade=self.exception_registry()
        registry.complete_construction(facade,7,('T',1));registry.raise_initial(facade,7)
        registry.set_terminate('custom')
        observed=[]
        registry.terminate(7,lambda handler:observed.append((handler,registry.uncaught(7),registry.current_owner(7))),cause=facade)
        self.assertEqual(observed[0][:2],('default',0))
        self.assertIsNotNone(observed[0][2]);self.assertTrue(registry.aborted)
        self.error('RT_EH_RECURSIVE_TERMINATE',registry.terminate,7,lambda handler:None)

    def test_exception_self_assignment_recapture_and_handler_swap_profiles(self):
        registry,facade=self.exception_registry()
        registry.complete_construction(facade,7,('T',1));registry.raise_initial(facade,7)
        pointer=registry.object_address(facade,7)
        registry.select_catch(facade,7,pointer);registry.begin_catch(facade,7)
        owner=registry.current_owner(7)
        value=exceptions.OwnerValue(registry,owner)
        self.assertIsNone(value.copy_from(value));self.assertEqual(value.pointer,owner)
        self.assertIsNone(value.move_from(value));self.assertEqual(value.pointer,owner)
        self.assertIsNone(value.release())  # catch still retains payload/proxy
        self.assertEqual(registry.current_owner(7),owner)  # stable proxy across 0 owner refs
        value.pointer=owner
        registry.set_terminate('custom')
        bare=registry.rethrow_current(7,lambda *a:None)
        dependent=registry.owner_rethrow(owner,9)
        self.assertEqual(registry.facades[bare.identity]['handler'],'default')
        self.assertEqual(registry.facades[dependent.identity]['handler'],'custom')
        observed=[]
        registry.terminate(7,observed.append)
        self.assertEqual(observed,['default'])  # explicit terminate selects active caught snapshot

    def test_bare_rethrow_without_catch_terminates_current_handler(self):
        registry,_=self.exception_registry();registry.set_terminate('custom');observed=[]
        self.assertIsNone(registry.rethrow_current(8,observed.append))
        self.assertEqual(observed,['custom']);self.assertTrue(registry.aborted)

    def test_live_snapshot_cannot_mint_lifetime_certificate(self):
        document,registry=live_example()
        document['lifetimes']=[{'id':1,'revision':1,'module':'a'*64,'module_generation':1,'object':1,
            'object_generation':1,'address':4096,'program':ref(0),'counts':[],'captures':[],'subobjects':[],
            'phase':'alive','claim':None,'owner':None,'leases':[]}]
        self.error('RT_LIFETIME_SNAPSHOT_AUTHORITY',live.validate,document,registry)

    def test_tls_preissued_raw_pure_wrap_and_guard_abort_retry(self):
        registry=tls.Registry()
        registry.reserve(1,'a',0,{'id':1,'generation':2,'address':4096,'size':8,'live':True})
        pointer=registry.address_raw(1,'a',0,2**64-4096)
        self.assertEqual(pointer.bits,0)
        self.assertEqual((pointer.object,pointer.generation,pointer.lower,pointer.upper),(1,2,4096,4104))
        self.assertEqual(registry.guards[1,'a',0]['state'],'uninitialized')
        self.assertTrue(registry.acquire(1,'a',0,7))
        self.error('RT_TLS_RECURSIVE_INITIALIZATION',registry.acquire,1,'a',0,7)
        registry.release(1,'a',0,7,abort=True)
        self.assertTrue(registry.acquire(1,'a',0,8));registry.release(1,'a',0,8)
        self.assertFalse(registry.acquire(1,'a',0,9))

    def test_relaxed_source_fence_has_no_sc_event_and_unused_helper_options_reject(self):
        from runtime_candidate.atomic import Atomics
        from runtime_candidate.helpers import DEFAULT_OPTIONS, helper, verify_options
        model=Atomics();model.fence(0);self.assertEqual(model.events,[])
        model.fence(1);self.assertEqual(len(model.events),1)
        record={'name':'fenv_get','contract':'default','options':{**DEFAULT_OPTIONS,'scope':'system'}}
        self.error('RT_HELPER_UNUSED_SCOPE',verify_options,record,helper('fenv_get'))
        record['options']={**DEFAULT_OPTIONS,'alignment':8}
        self.error('RT_HELPER_UNUSED_MEMORY_OPTIONS',verify_options,record,helper('fenv_get'))


if __name__=='__main__':unittest.main()
