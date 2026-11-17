"""Fresh destructor seeds, nested clocks, source nonlocal exits and embedding."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest

from test_candidate_contract import HERE, ref
from test_candidate_closure import live_example
from runtime_candidate import embedding, journals, lifetimes, nonlocal_exit
from runtime_candidate.errors import Reject, some


ARTIFACT='a'*64


def slot(identity=0, child=None):
    return {'id':identity,'type':ref(0),'offset':0,'extent':8,'align':8,'parent':None,
        'role':'root','count':1,'stride':8,'count_source':None,'constructor':None,
        'destructor':some(0),'destructor_kind':'leaf','covers':[],'owner':0,
        'dependencies':[],'child_program':None if child is None else some(ref(child))}


def owner(instance,thread=7):
    return {'thread':thread,'activation':instance+100,'generation':1,'instance':instance}


def program(identity=0, child=None):
    return {'id':identity,'signature':0,'params':[],'slots':[slot(child=child)],
            'normal_order':[0],'exception_order':[0]}


def document(identity, program_id, phases, sequences, *, thread=2, parent=None, seed=None):
    entries=[];ordinal=1 if seed is not None else 0
    for phase,ticket in phases:
        if phase=='construct_commit':ordinal+=1
        entries.append({'instance':identity,'transition':identity,'thread':thread,'activation':identity+100,
            'generation':1,'slot':0,'element':0,'ticket':ticket,'phase':phase,'ordinal':ordinal,
            'owner':0,'exception_lease':None})
    return {'id':identity,'module':ARTIFACT,'module_generation':1,'object':1,'object_generation':1,
        'object_address':4096,'program':ref(program_id),'seed':seed,'state':{
            'revision':1,'instance':identity,'program':ref(program_id),'parent_instance':parent,
            'transition':identity,'thread':thread,'activation':identity+100,'generation':1,
            'stage':'destroyed' if phases and phases[-1][0]=='destroy_commit' else 'alive',
            'next_ordinal':ordinal,'exception_lease':None,'entries':entries},'event_sequences':sequences,
        'captures':[],'counts':[{'slot':0,'count':1}],'leases':[1]}


class LifetimeTests(unittest.TestCase):
    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(Reject) as caught:function(*args, **kwargs)
        self.assertEqual(caught.exception.code,code)

    def setup(self, definitions):
        objects={1:{'generation':1,'address':4096,'size':16,'live':True}}
        resolve=lambda module,reference:((module,reference['id']),definitions[reference['id']])
        kwargs={'thread':2,'highwater':100,'modules':{ARTIFACT:{'generation':1}},'objects':objects,'handles':{},
            'program':resolve,'nominal':lambda *a:None,'value_check':lambda *a:None,'type_equal':lambda *a:True}
        return objects,resolve,kwargs

    def test_constructor_replay_agrees_with_independent_abi_reference(self):
        definition=program();objects,resolve,kwargs=self.setup({0:definition})
        source='''import json,sys\nfrom construction import ConstructionJournal\np=json.load(sys.stdin)\nj=ConstructionJournal(p,transition=1,thread=2,activation=101,generation=1,instance=1)\nj.begin(0,0,9,j.identity);j.commit(0,0,9,j.identity);j.finish_construction()\nprint(json.dumps(j.entries))\n'''
        result=subprocess.run([sys.executable,'-B','-c',source],input=json.dumps(definition),text=True,
            capture_output=True,cwd=HERE.parents[1]/'tools/smir-abi',check=True)
        doc=document(1,0,[('construct_begin',9),('construct_commit',9)],[1,2])
        self.assertEqual(json.loads(result.stdout),doc['state']['entries'])
        state=journals.validate([doc],**kwargs)[1]
        self.assertEqual(state['cells'][0,0]['phase'],'alive')

    def test_fresh_other_thread_destruction_no_constructor_replay(self):
        definition=program();objects,resolve,kwargs=self.setup({0:definition})
        ctor=document(1,0,[('construct_begin',9),('construct_commit',9)],[1,2])
        state=journals.validate([ctor],**kwargs)[1]
        registry=lifetimes.Registry(objects,resolve,{1:{'live':True}})
        cert=registry.publish(state,{(0,0):{'lifetime':1,'child':None}})
        registry.claim(cert['id'],cert['revision'],owner(8))
        self.error('RT_LIFETIME_CLAIM',registry.claim,cert['id'],cert['revision'],owner(9))
        dtor=document(8,0,[('destroy_begin',12),('destroy_commit',12)],[1,2],thread=7,
                      seed=some({'kind':'object','certificate':cert['id'],'revision':cert['revision']}))
        dtor_state=journals.validate([dtor],**{**kwargs,'thread':7,'lifetimes':registry.snapshots()})[8]
        self.assertTrue(all(e['phase'].startswith('destroy_') for e in dtor['state']['entries']))
        self.assertEqual(registry.finish(dtor_state)['phase'],'dead')
        self.error('RT_LIFETIME_STALE',registry.claim,cert['id'],cert['revision'],owner(10))

    def test_nested_parent_ticket_order_global_clock_and_seeded_children(self):
        objects,resolve,kwargs=self.setup({0:program(0,1),1:program(1)})
        parent=document(1,0,[('construct_begin',1),('construct_commit',1)],[1,4])
        child=document(2,1,[('construct_begin',2),('construct_commit',2)],[2,3],
                       parent=some({'journal':1,'slot':0,'element':0}))
        states=journals.validate([parent,child],**kwargs)
        registry=lifetimes.Registry(objects,resolve,{1:{'live':True}})
        child_cert=registry.publish(states[2],{(0,0):{'lifetime':2,'child':None}})
        outer=registry.publish(states[1],{(0,0):{'lifetime':1,'child':some(child_cert['id'])}})
        registry.claim(outer['id'],1,owner(8));registry.claim(child_cert['id'],2,owner(9),parent_owner=owner(8))
        parent_dtor=document(8,0,[('destroy_begin',3),('destroy_commit',3)],[1,4],thread=7,
            seed=some({'kind':'object','certificate':outer['id'],'revision':1}))
        child_dtor=document(9,1,[('destroy_begin',4),('destroy_commit',4)],[2,3],thread=7,
            parent=some({'journal':8,'slot':0,'element':0}),seed=some({'kind':'object','certificate':child_cert['id'],'revision':2}))
        result=journals.validate([parent_dtor,child_dtor],**{**kwargs,'thread':7,'lifetimes':registry.snapshots()})
        registry.finish(result[9]);registry.finish(result[8])
        self.assertTrue(all(c['phase']=='dead' for c in registry.items.values()))

    def test_ended_member_not_revived_and_transparent_alias_conditions(self):
        objects,resolve,kwargs=self.setup({0:program()})
        ctor=document(1,0,[('construct_begin',1),('construct_commit',1)],[1,2])
        state=journals.validate([ctor],**kwargs)[1]
        registry=lifetimes.Registry(objects,resolve,{1:{'live':True}})
        cert=registry.publish(state,{})
        self.error('RT_LIFETIME_DEAD_REQUIRED_CHILD',registry.claim,cert['id'],1,owner(8))
        # A separate object instance exercises placement alias forwarding.
        ctor=document(2,0,[('construct_begin',1),('construct_commit',1)],[3,4])
        state=journals.validate([ctor],**kwargs)[2]
        other=lifetimes.Registry(objects,resolve,{1:{'live':True}})
        cert=other.publish(state,{(0,0):{'lifetime':1,'child':None}})
        self.error('RT_LIFETIME_NOT_TRANSPARENT',other.replace,cert['id'],1,0,0,2,transparent=True,
                   same_type=True,overlapping=True,parents_eligible=True)
        replaced=other.replace(cert['id'],1,0,0,2,transparent=True,same_type=True,
                               overlapping=False,parents_eligible=True)
        self.assertEqual(other.forward,{1:2})
        self.assertEqual(replaced['subobjects'][0]['ordinal'],1)

    def test_cookie32_no_memory_rollback_reusable_and_wrong_thread(self):
        doc,_=live_example();registry=nonlocal_exit.Registry(1)
        cookie=registry.capture(doc,activation=3,continuation={'block':5,'operation':1,'predecessor':None},
                                result=11,sequence=0,signal_mask=bytes(128))
        self.assertEqual(len(cookie),32)
        changed=copy.deepcopy(doc);changed['thread']['errno']=7;changed['thread']['fenv']['flags']=1
        result=registry.restore(cookie,changed,0,active_nontrivial=lambda *a:False,objects={},current_signal_mask=b'x'*128)
        self.assertEqual(result['value'],1)
        self.assertEqual(result['state']['thread']['errno'],7)
        self.assertEqual(result['state']['thread']['fenv']['flags'],1)
        self.assertEqual(result['signal_mask'],bytes(128))
        self.assertEqual(registry.restore(cookie,changed,-4,active_nontrivial=lambda *a:False,
            objects={},current_signal_mask=None)['value'],-4)
        bad=copy.deepcopy(doc);bad['thread']['thread']=9
        self.error('RT_JMP_WRONG_THREAD',registry.restore,cookie,bad,1,
                   active_nontrivial=lambda *a:False,objects={},current_signal_mask=None)
        self.error('RT_JMP_NONTRIVIAL_CLEANUP',registry.restore,cookie,doc,1,
                   active_nontrivial=lambda *a:True,objects={},current_signal_mask=None)
        registry.invalidate_activation(2,3)
        self.error('RT_JMP_STALE',registry.restore,cookie,doc,1,
                   active_nontrivial=lambda *a:False,objects={},current_signal_mask=None)

    def test_embedding_first_start_once_two_threads_and_callback_reentry(self):
        process=embedding.Process(1);barrier=threading.Barrier(2);entries=[];threads=[];errors=[]
        def run():
            barrier.wait()
            try:threads.append(process.start(entries.append))
            except Exception as error:errors.append(error)
        workers=[threading.Thread(target=run) for _ in range(2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join(2);self.assertFalse(worker.is_alive())
        self.assertEqual(errors,[]);self.assertEqual(len(entries),1);self.assertEqual(len(set(threads)),2)
        with embedding.host_callback(1):
            self.error('RT_CAPI_REENTRY_EDEADLK',process.start,entries.append)
            self.error('RT_CAPI_REENTRY_EDEADLK',process.join)
        self.assertTrue(all(t['errno']==0 and t['flags']==0 for t in process.threads.values()))

    def test_embedding_owner_cleanup_before_public_exit_nonblocking_release(self):
        process=embedding.Process(1);thread=process.start(lambda t:None);events=[]
        destructor=lambda:events.append(('destructor',process.state))
        process.retain_owner(8,destructor)
        process.finish_thread(thread,lambda t:events.append(('tls',t)))
        self.assertEqual(process.join(),'closing')
        self.error('RT_CAPI_FINALIZE_EBUSY',process.finalize)
        with embedding.host_callback(1):process.release_owner(8)
        self.assertEqual(events,[('tls',thread)])
        self.assertTrue(process.drive_cleanup());self.assertEqual(process.state,'exited')
        self.assertEqual(events[-1],('destructor','closing'))
        self.assertEqual(process.exit_publications,1)
        self.error('RT_CAPI_POSTEXIT_CLEANUP',process.drive_cleanup)
        process.finalize()


if __name__=='__main__':unittest.main()
