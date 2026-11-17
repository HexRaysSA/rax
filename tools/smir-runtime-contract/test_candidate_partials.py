"""R042 source coroutine partial-object protocol, no native coroutine execution."""
from copy import deepcopy
from dataclasses import dataclass, replace
import unittest

from test_candidate_contract import ref
import test_candidate_lifetime as lifetime_fixtures
from test_candidate_lifetime import ARTIFACT, document, owner, program, slot
from runtime_candidate import journals, lifetimes, partials
from runtime_candidate.errors import Reject, some
from runtime_candidate.wire import decode, encode


@dataclass(frozen=True)
class Pointer:
    address:int=4096
    origin:int=1
    generation:int=1
    domain:str='data'


class PartialTests(unittest.TestCase):
    def error(self,code,fn,*args,**kwargs):
        with self.assertRaises(Reject) as caught:fn(*args,**kwargs)
        self.assertEqual(caught.exception.code,code)

    def setup(self):
        parent=program(0);parent['slots']=[slot(0,1),slot(1,1)]
        parent['slots'][1]['offset']=8;parent['normal_order']=[1,0];parent['exception_order']=[1,0]
        objects,resolve,kwargs=lifetime_fixtures.LifetimeTests().setup({0:parent,1:program(1)})
        objects[1]['size']=32
        lives=lifetimes.Registry(objects,resolve,{1:{'live':True}})
        builders=partials.Registry(lives,lambda _:None,lambda *a:None,lambda *a:None,
                                  modules={ARTIFACT:{'generation':1,'pins':1}},
                                  exception_check=lambda value,thread:self.assertEqual((value,thread),(9,7)))
        def child(identity,address,thread,sequence):
            d=document(identity,1,[('construct_begin',identity),('construct_commit',identity)],
                       [sequence,sequence+1],thread=thread)
            d['object_address']=address
            state=journals.validate([d],**{**kwargs,'thread':thread,'highwater':1000})[identity]
            return lives.publish(state,{(0,0):{'lifetime':identity,'child':None}})
        def begin(o):return builders.begin(ARTIFACT,ref(0),Pointer(),o,[],
            [{'slot':0,'count':1},{'slot':1,'count':1}],[1])
        return builders,lives,kwargs,child,begin

    def test_two_resume_threads_completion_order_not_event_clock_and_parent_publish(self):
        builders,lives,kwargs,child,begin=self.setup();a,b=owner(10,2),owner(20,7)
        first=child(1,4096,2,500);j=begin(a)
        builders.adopt_child(j,a,0,0,first['id'],1)
        detached=builders.detach(j,a)
        self.error('RT_PARTIAL_JOURNAL',builders.detach,j,a)
        self.error('RT_LIFETIME_STALE',lives.claim,first['id'],first['revision'],owner(99))
        # Handle publication/await_suspend is now legal: no old usable journal.
        j=begin(b);second=child(2,4104,7,1)
        builders.adopt_child(j,b,1,0,second['id'],2)
        checkpoint=builders.snapshot(j,b,transition=8)
        self.assertEqual(checkpoint['state']['next_ordinal'],2)
        self.assertEqual(checkpoint['event_sequences'],[])
        state=journals.validate([checkpoint],**{**kwargs,'thread':7,'partials':builders.snapshots()})[20]
        self.assertEqual([state['cells'][i,0]['ordinal'] for i in [0,1]],[1,2])
        cert=builders.publish(j,b)
        self.assertEqual([e['ordinal'] for e in cert['subobjects']],[1,2])
        self.assertTrue(all(e['owner']['some']['kind']=='object' for i,e in lives.items.items() if i!=cert['id']))
        self.assertEqual(decode('runtime_object_lifetime',encode('runtime_object_lifetime',cert)),cert)
        self.assertEqual(detached['completed'][0]['ordinal'],1)

    def test_partial_cancel_and_failed_second_constructor_never_parent_destructor(self):
        for exception in [None,9]:
            with self.subTest(exception=exception):
                builders,lives,_,child,begin=self.setup();a,b=owner(10,2),owner(20,7)
                first=child(1,4096,2,500);j=begin(a);builders.adopt_child(j,a,0,0,first['id'],1)
                builders.detach(j,a)
                cleanup=builders.claim_partial(Pointer(),b,exception)
                self.assertEqual([e['slot'] for e in builders.cleanup_order(cleanup,b)],[0])
                self.error('RT_PARTIAL_CLEANUP',builders.finish_cleanup,cleanup,b)
                builders.end_child(cleanup,b,0,0)
                final=builders.finish_cleanup(cleanup,b)
                self.assertEqual(final['phase'],'dead');self.assertEqual(len(lives.items),1)
                self.assertEqual(lives.items[first['id']]['phase'],'dead')

    def test_no_detach_during_effect_or_claim_by_stale_wrong_owner(self):
        builders,_,_,_,begin=self.setup();a=owner(10,2);j=begin(a)
        builders.begin_effect(j,a,88)
        self.error('RT_PARTIAL_EFFECT',builders.detach,j,a)
        self.error('RT_PARTIAL_OWNER',builders.detach,j,owner(10,7))
        self.error('RT_PARTIAL_JOURNAL',builders.detach,replace(j),a)
        builders.end_effect(j,a,88);builders.detach(j,a)
        fresh=begin(owner(20,2));self.assertIsNot(fresh,j)
        self.error('RT_PARTIAL_BUSY',begin,owner(21,7))

    def test_duplicate_wrong_address_and_ended_child_not_revived(self):
        builders,lives,_,child,begin=self.setup();a=owner(10,2);j=begin(a)
        wrong=child(1,4104,2,500)
        self.error('RT_PARTIAL_CHILD',builders.adopt_child,j,a,0,0,wrong['id'],1)
        builders.adopt_child(j,a,1,0,wrong['id'],1)
        self.error('RT_PARTIAL_SLOT',builders.adopt_child,j,a,1,0,wrong['id'],1)
        builders.end_child(j,a,1,0,explicit=True)
        snapshot=builders.detach(j,a)
        self.assertEqual(len(snapshot['completed']),1);self.assertEqual(snapshot['current'],[])
        cleanup=builders.claim_partial(Pointer(),owner(20,7))
        self.assertEqual(builders.cleanup_order(cleanup,owner(20,7)),[])
        builders.finish_cleanup(cleanup,owner(20,7))
        self.assertEqual(lives.items[wrong['id']]['phase'],'dead')

    def test_ordinal_overflow_rejects_before_mutation_and_seed_owner_exact(self):
        builders,_,kwargs,child,begin=self.setup();a=owner(10,2);j=begin(a)
        first=child(1,4096,2,500);builders.adopt_child(j,a,0,0,first['id'],1)
        builders.items[1]['completed'][0]['ordinal']=2**64-1
        second=child(2,4104,2,502);before=builders.snapshots()
        self.error('RT_PARTIAL_RESOURCE',builders.adopt_child,j,a,1,0,second['id'],2)
        self.assertEqual(builders.snapshots(),before)
        checkpoint=builders.snapshot(j,a,transition=8)
        checkpoint['state']['generation']=99
        self.error('RT_LIFETIME_SEED',journals.validate,[checkpoint],**{**kwargs,'partials':builders.snapshots()})

    def test_owned_second_constructor_failure_consumes_old_journal_only_after_frontier_check(self):
        builders,lives,_,child,begin=self.setup();a=owner(10,7);j=begin(a)
        first=child(1,4096,7,500);builders.adopt_child(j,a,0,0,first['id'],1)
        builders.begin_effect(j,a,77)
        fresh={**a,'instance':20}
        before=builders.snapshots()
        self.error('RT_PARTIAL_FAILED_FRONTIER',builders.claim_partial,Pointer(),fresh,9,
                   failed_journal=j,previous_owner=a,failed_ticket=77)
        self.assertEqual(builders.snapshots(),before)
        def check(owner,ticket,exception):
            if ticket!=77:raise Reject('TEST_BAD_FRONTIER')
        builders.failure_check=check
        self.error('RT_PARTIAL_FAILED_FRONTIER',builders.claim_partial,Pointer(),fresh,9,
                   failed_journal=j,previous_owner=a,failed_ticket=78)
        cleanup=builders.claim_partial(Pointer(),fresh,9,failed_journal=j,previous_owner=a,failed_ticket=77)
        self.error('RT_PARTIAL_JOURNAL',builders.detach,j,a)
        self.assertEqual([e['slot'] for e in builders.cleanup_order(cleanup,fresh)],[0])
        builders.end_child(cleanup,fresh,0,0);builders.finish_cleanup(cleanup,fresh)
        self.assertEqual(len(lives.items),1)

    def test_explicit_source_destruction_and_replacement_follow_current_owner_graph(self):
        builders,lives,kwargs,child,begin=self.setup();a=owner(10,2);j=begin(a)
        first=child(1,4096,2,500);builders.adopt_child(j,a,0,0,first['id'],1);builders.detach(j,a)
        claimed=lives.claim_source(ARTIFACT,ref(1),Pointer(),owner(30,7))
        self.assertEqual(builders.snapshots()[1]['current'],[])
        dtor=document(30,1,[('destroy_begin',90),('destroy_commit',90)],[1,2],thread=7,
            seed=some({'kind':'object','certificate':claimed['id'],'revision':claimed['revision']}))
        state=journals.validate([dtor],**{**kwargs,'thread':7,'lifetimes':lives.snapshots()})[30]
        lives.finish(state)
        replacement=child(2,4096,7,3)
        lives.replace_source(first['id'],replacement['id'])
        builder=builders.snapshots()[1]
        self.assertEqual(builder['completed'][0]['child'],some(first['id']))
        self.assertEqual(builder['current'][0]['child'],some(replacement['id']))
        self.assertEqual(builder['current'][0]['ordinal'],1)
        self.assertEqual(lives.forward,{})  # Nontransparent old aliases stay old.
        cleanup=builders.claim_partial(Pointer(),owner(40,7))
        self.assertEqual(builders.cleanup_order(cleanup,owner(40,7))[0]['child'],some(replacement['id']))

    def test_scalar_leaf_completion_requires_actual_replay_and_survives_partial_cleanup(self):
        builders,lives,kwargs,_,begin=self.setup()
        definition=lives.program(ARTIFACT,ref(0))[1]
        definition['slots'][0]['child_program']=None
        a=owner(10,2);j=begin(a);checkpoint=builders.snapshot(j,a,transition=10)
        for phase,ticket,ordinal,sequence in [('construct_begin',8,0,500),('construct_commit',8,1,501)]:
            checkpoint['state']['entries'].append({'instance':10,'transition':10,'thread':2,'activation':110,
                'generation':1,'slot':0,'element':0,'ticket':ticket,'phase':phase,'ordinal':ordinal,'owner':0,
                'exception_lease':None})
            checkpoint['event_sequences'].append(sequence)
        checkpoint['state']['next_ordinal']=1
        state=journals.validate([checkpoint],**{**kwargs,'highwater':501,'partials':builders.snapshots()})[10]
        builders.commit_replayed_leaf(j,a,0,0,7,state)
        builders.detach(j,a)
        cleanup=builders.claim_partial(Pointer(),owner(20,7))
        self.assertEqual(builders.cleanup_order(cleanup,owner(20,7))[0]['child'],None)
        builders.end_child(cleanup,owner(20,7),0,0);builders.finish_cleanup(cleanup,owner(20,7))


if __name__=='__main__':unittest.main()
