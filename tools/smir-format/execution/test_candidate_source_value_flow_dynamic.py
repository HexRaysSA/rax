"""Actual completed-core events; public MODEL masks never grant SOURCE admission."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from candidate import pure
from candidate.machine import Machine
from candidate.raw import Raw
from candidate.type_system import ref
from candidate.values import Value
from source_value_flow.dynamic import UnboundFlowRuntime,Limits,Event,Birth,Reservation,EntryReservation
from source_value_flow.fixtures import document,context,codec,encoded,RAW,INT8,BOOL,INT64,FN,NOMINAL
from test_candidate import block,constant,decl,operation
from test_candidate_source_value_flow import budget
from candidate.source_data_projection import source_api


class DynamicFlowTests(unittest.TestCase):
    def setup_machine(self,profile='loop',*,roots=None,assertion=None,masks=None,limits=None,ledger=None):
        if roots is None:roots,assertion=document(profile)
        owner=context(codec().encode(roots));owner.verify_abi();machine=Machine(owner.verify_execution())
        if masks is None:
            masks=tuple((d['id'],(1<<machine.types.width(d['type']))-1)for d in machine.functions[1]['params'])
        ledger=ledger if ledger is not None else budget()
        runtime=UnboundFlowRuntime(owner,encoded(assertion),parameter_masks=masks,
                                   limits=limits or Limits(),budget=ledger)
        machine.attach_unbound_value_flow(runtime,budget=ledger)
        return owner,machine,runtime,ledger

    def loop(self,*,condition=1,state='concrete',iterations=2,masks=(0,255),same=False,raw=None,limits=None):
        roots,assertion=document('loop')
        if same:
            roots[3]['functions'][-1]['blocks'][1]['ops'][1]['operands'][1]=10
            next(row for row in assertion['flows']if row['kind']=='select')['true_value']=10
        owner,machine,flow,ledger=self.setup_machine(roots=roots,assertion=assertion,
            masks=((0,masks[0]),(1,masks[1]),(2,2**64-1),(3,1)),limits=limits)
        a=Value(ref(RAW),'concrete',raw if raw is not None else Raw.pointer(machine.memory.allocate(1,1)).slice(56,8))
        b=a if same else Value(ref(RAW),'concrete',Raw.pointer(machine.memory.allocate(1,1)).slice(56,8))
        machine.start(1,[a,b,Value(ref(INT64),'concrete',iterations),Value(ref(BOOL),state,condition if state=='concrete'else None)])
        return owner,machine,flow,ledger,a,b

    def until(self,machine,predicate):
        for _ in range(100):
            if predicate(machine.stack[-1]):return machine.stack[-1]
            result=machine.run(fuel=1)
            self.assertEqual(result['kind'],'resource',result)
        self.fail('actual core frontier did not arrive')

    def error(self,code,call):
        with self.assertRaises(source_api().SourceDataError)as caught:call()
        self.assertEqual(caught.exception.code,code)
        return caught.exception

    def test_actual_loop_parallel_phi_snapshots_and_nonwrapping_births(self):
        _,machine,flow,_,a,b=self.loop()
        frame=self.until(machine,lambda f:f.block==1 and f.position==-1)
        machine.run(fuel=1)
        first=(flow.birth(frame,10),flow.birth(frame,11));first_serial=flow.counts()['serials'][0]
        self.assertIs(frame.values[10],a);self.assertIs(frame.values[11],b)
        self.until(machine,lambda f:f.block==1 and f.position==-1)
        flow.request_park_after_next_completion('phi_batch');before=(frame.values[10],frame.values[11])
        stopped=machine.run(fuel=1);event=stopped['event'];self.assertEqual(stopped['reason'],'unbound_flow_parked')
        row=flow._events[event]
        self.assertEqual(row['inputs'][:2],(first[1],first[0]))
        self.assertIs(row['outputs'][0],before[1]);self.assertIs(row['outputs'][1],before[0])
        self.assertIs(frame.values[10],before[0]);self.assertEqual(flow.birth(frame,10),first[0])
        flow.resume_completed(event,budget=flow.budget);machine.run(fuel=0)
        second=(flow.birth(frame,10),flow.birth(frame,11))
        self.assertNotEqual(first,second)
        self.assertEqual(tuple(flow.describe_birth(x)['mask']for x in second),(255,0))
        self.assertGreater(flow.describe_birth(second[0])['serial'],first_serial)
        self.assertIs(frame.values[10],before[1]);self.assertIs(frame.values[11],before[0])
        self.assertEqual(machine.run()['kind'],'return')

    def test_actual_selection_operand_indices_survive_identical_value_aliases(self):
        for condition,index,mask in [(1,1,0),(0,2,255)]:
            with self.subTest(condition=condition):
                _,machine,flow,_,a,b=self.loop(condition=condition,same=True)
                self.assertIs(a,b)
                frame=self.until(machine,lambda f:f.block==1 and f.position==1)
                flow.request_park_after_next_completion('select');stopped=machine.run(fuel=1)
                event=stopped['event'];row=flow._events[event]
                self.assertEqual(flow.describe_event(event)['selected_index'],index)
                self.assertIs(row['outputs'][0],a)
                self.assertEqual(row['selection'][3],row['inputs'][index])
                flow.resume_completed(event,budget=flow.budget);machine.run(fuel=0)
                self.assertEqual(flow.describe_birth(flow.birth(frame,14))['mask'],mask)

    def test_undef_condition_materialized_once_across_pause_and_repeated_dispatch(self):
        _,machine,flow,_,_,_=self.loop(state='undef')
        frame=self.until(machine,lambda f:f.block==1 and f.position==1)
        original=pure.materialize;calls=[]
        def observe(types,value):calls.append(value);return original(types,value)
        flow.request_park_after_next_completion('select')
        with patch.object(pure,'materialize',observe):
            stopped=machine.run(fuel=1);event=stopped['event'];steps=machine.steps;counts=flow.counts()
            self.assertEqual(machine.run(fuel=0)['event'],event)
            self.assertEqual(machine.run(fuel=10)['event'],event)
            self.assertEqual(flow.counts(),counts)
            flow.resume_completed(event,budget=flow.budget)
            self.assertEqual(machine.run(fuel=0)['reason'],'fuel')
        self.assertEqual(len(calls),1);self.assertIs(calls[0],frame.values[3])
        self.assertEqual(machine.steps,steps);self.assertEqual(flow.selection_uses,1)
        self.assertEqual(flow.describe_event(event)['stage'],'published')
        self.error('UNBOUND_FLOW_RESUME',lambda:flow.resume_completed(event,budget=flow.budget))

    def test_poison_select_refuses_before_materialization_step_reservation_or_publication(self):
        _,machine,flow,_,_,_=self.loop(state='poison')
        frame=self.until(machine,lambda f:f.block==1 and f.position==1)
        prior=(machine.steps,frame.position,dict(frame.values),flow.counts(),len(flow._reservations))
        original=pure.materialize;calls=[]
        def observe(types,value):calls.append(value);return original(types,value)
        with patch.object(pure,'materialize',observe):
            for _ in range(2):
                error=self.error('UNBOUND_FLOW_MODEL_STATE_UNAVAILABLE',lambda:machine.run(fuel=1))
                self.assertEqual(error.kind,'unavailable')
        self.assertEqual(calls,[])
        self.assertEqual((machine.steps,frame.position,dict(frame.values),flow.counts(),len(flow._reservations)),prior)

    def test_actual_freeze_changes_raw_masks_but_preserves_public_model_mask(self):
        for raw in [Raw(8,1,poison=1),Raw(8,1,undef=1)]:
            with self.subTest(raw=raw):
                _,machine,flow,_,_,_=self.loop(raw=raw,iterations=1)
                frame=self.until(machine,lambda f:f.block==1 and f.position==4)
                old=frame.values[14];self.assertTrue(old.data.poison or old.data.undef)
                flow.request_park_after_next_completion('freeze');stopped=machine.run(fuel=1);event=stopped['event']
                result=flow._events[event]['outputs'][0];self.assertIsNot(result,old)
                self.assertEqual((result.data.poison,result.data.undef),(0,0))
                before=flow.counts();steps=machine.steps
                flow.resume_completed(event,budget=flow.budget);machine.run(fuel=0)
                self.assertIs(frame.values[17],result)
                self.assertEqual(flow.describe_birth(flow.birth(frame,17))['mask'],0)
                self.assertEqual(machine.steps,steps);self.assertEqual(flow.computations,before['computations'])

    def test_zero_parameter_and_zero_phi_batches_emit_events_without_serials(self):
        _,machine,flow,_=self.setup_machine('literal',limits=Limits(max_serial=1))
        machine.start(1,[]);self.assertEqual(flow.counts()['births'],0)
        self.assertIsNone(flow._published[0]['first_serial'])
        flow.request_park_after_next_completion('phi_batch');event=machine.run(fuel=1)['event']
        self.assertEqual(flow.describe_event(event)['capacity'],dict(values_in=0,births_in=0,values_out=0,births_out=0,events=1))
        self.assertIsNone(flow.describe_event(event)['first_output_serial'])
        flow.resume_completed(event,budget=flow.budget);machine.run(fuel=0)
        self.assertEqual(flow.counts()['serials'],(0,))
        self.assertEqual(machine.run()['kind'],'return');self.assertEqual(flow.counts()['serials'],(1,))

    def test_empty_phi_at_serial_limit_then_positive_birth_refuses_before_compute(self):
        roots,assertion=document('chain',1)
        _,machine,flow,_=self.setup_machine(roots=roots,assertion=assertion,limits=Limits(max_serial=1))
        machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))])
        machine.run(fuel=1);self.assertEqual(flow.counts()['serials'],(1,));self.assertEqual(flow.counts()['published'],2)
        prior=(machine.steps,flow.counts(),dict(machine.stack[-1].values))
        self.error('UNBOUND_FLOW_SERIAL',lambda:machine.run(fuel=1))
        self.assertEqual((machine.steps,flow.counts(),dict(machine.stack[-1].values)),prior)

    def test_parameter_coordinates_use_actual_ssa_identifier_not_argument_ordinal(self):
        _,machine,flow,_=self.setup_machine('max-id')
        machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))]);frame=machine.stack[-1]
        self.assertEqual(flow.describe_birth(flow.birth(frame,4294967293))['coordinate'],{'parameter':4294967293})
        machine.run();self.assertEqual(flow.counts()['serials'],(2,))

    def test_entry_exact_same_budget_and_one_less_precede_activation(self):
        roots,assertion=document('chain',1)
        _,machine,flow,ledger=self.setup_machine(roots=roots,assertion=assertion)
        machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))])
        exact=dict(max_work=ledger._used_work,max_edges=ledger._used_edges,max_copied_bytes=ledger._used_copied_bytes,max_depth=128)
        for dimension in [None,'max_work','max_edges','max_copied_bytes']:
            values=dict(exact)
            if dimension:values[dimension]-=1
            _,machine,flow,_=self.setup_machine(roots=deepcopy(roots),assertion=deepcopy(assertion),ledger=source_api().SourceQueryBudget(**values))
            if dimension:
                self.error('SOURCE_DATA_RESOURCE',lambda:machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))]))
                self.assertEqual((machine.activation,machine.stack,flow.counts()['births'],flow.counts()['events']),(0,[],0,0))
            else:
                machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))]);self.assertEqual(machine.activation,1)

    def test_whole_phi_capacity_preflight_preserves_original_frontier(self):
        _,machine,flow,_,_,_=self.loop(limits=Limits(max_births=9))
        frame=self.until(machine,lambda f:f.block==1 and f.position==-1)
        prior=(machine.steps,frame.position,dict(frame.values),flow.counts())
        self.error('UNBOUND_FLOW_CAPACITY',lambda:machine.run(fuel=1))
        self.assertEqual((machine.steps,frame.position,dict(frame.values),flow.counts()),prior)

    def test_event_capacity_before_compute_and_before_frame_activation(self):
        _,machine,flow,_=self.setup_machine('literal',limits=Limits(max_events=1))
        machine.start(1,[]);prior=(machine.steps,flow.counts())
        self.error('UNBOUND_FLOW_CAPACITY',lambda:machine.run(fuel=1))
        self.assertEqual((machine.steps,flow.counts()),prior)
        _,machine,flow,_=self.setup_machine('literal');machine.activation=2**64-1
        self.error('UNBOUND_FLOW_ACTIVATION',lambda:machine.start(1,[]))
        self.assertEqual((machine.activation,machine.stack,flow.counts()['events']),(2**64-1,[],0))

    def numeric(self,mask):
        roots,assertion=document('chain',1)
        fn=roots[3]['functions'][-1]
        fn['blocks']=[block(0,[operation('bitcast',[decl(1,INT8)],[0]),constant(2,INT8,'00'),
            operation('i_sub',[decl(3,INT8)],[1,2],flags=[]),operation('freeze',[decl(4,INT8)],[3]),
            operation('icmp',[decl(5,BOOL)],[1,1],predicate='eq'),operation('bitcast',[decl(7,RAW)],[4])],
            dict(op='return',values=[7]))]
        assertion['flows']=[];assertion['nominals']=[dict(value=i,nominal=ref(NOMINAL))for i in (0,7)]
        assertion['seeds']=[dict(value=0,kind='parameter'),dict(value=7,kind='numeric_to_byte')]
        _,machine,flow,_=self.setup_machine(roots=roots,assertion=assertion,masks=((0,mask),))
        machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))]);return machine,flow

    def test_numeric_arithmetic_freeze_and_self_comparison_cannot_launder_masks(self):
        for mask in (0,127):
            with self.subTest(mask=mask):
                machine,flow=self.numeric(mask);frame=self.until(machine,lambda f:f.position==5)
                self.assertEqual(flow.describe_birth(flow.birth(frame,1))['mask'],mask)
                for identifier in (3,4,5):self.assertEqual(flow.describe_birth(flow.birth(frame,identifier))['mask'],0)
                prior=(machine.steps,flow.counts(),dict(frame.values))
                self.error('UNBOUND_FLOW_MODEL_STATE_UNAVAILABLE',lambda:machine.run(fuel=1))
                self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),prior)

    def test_full_model_numeric_seed_actual_conversion_and_park_has_no_origins(self):
        machine,flow=self.numeric(255);flow.request_park_after_next_completion('numeric_to_byte')
        stopped=machine.run();event=stopped['event'];frame=machine.stack[-1]
        self.assertEqual(flow.describe_event(event)['kind'],'numeric_to_byte')
        self.assertNotIn(7,frame.values);actual=flow._events[event]['outputs'][0]
        self.assertEqual((actual.data.bits,actual.data.origins),(42,()))
        steps=machine.steps;flow.resume_completed(event,budget=flow.budget);machine.run(fuel=0)
        self.assertIs(frame.values[7],actual);self.assertEqual(machine.steps,steps)
        self.assertEqual(flow.describe_birth(flow.birth(frame,7))['mask'],255)
        self.assertEqual(machine.run()['kind'],'return')

    def test_all_supported_completion_classes_publish_retained_event_once(self):
        for kind in ('ordinary','noop','phi_batch','select','freeze','literal'):
            with self.subTest(kind=kind):
                _,machine,flow,_,_,_=self.loop(iterations=1)
                flow.request_park_after_next_completion(kind);stopped=machine.run();event=stopped['event']
                frame=machine.stack[-1];prior=(machine.steps,flow.counts()['computations'],flow.counts()['births'])
                self.assertEqual(flow.describe_event(event)['kind'],kind)
                self.assertEqual(flow.describe_event(event)['stage'],'parked')
                flow.resume_completed(event,budget=flow.budget);machine.run(fuel=0)
                self.assertEqual((machine.steps,flow.counts()['computations']),prior[:2])
                self.assertEqual(flow.counts()['births']-prior[2],flow.describe_event(event)['outputs'])
                self.assertEqual(flow.describe_event(event)['stage'],'published')
                self.assertEqual(machine.run()['kind'],'return')

    def test_forged_foreign_duplicate_and_wrong_budget_references_reject(self):
        for cls in (Event,Birth,Reservation,EntryReservation):
            with self.assertRaises(TypeError):cls()
        _,machine,flow,_,_,_=self.loop();flow.request_park_after_next_completion('select')
        event=machine.run()['event']
        self.error('UNBOUND_FLOW_EVENT_REFERENCE',lambda:flow.resume_completed(object(),budget=flow.budget))
        self.error('UNBOUND_FLOW_BUDGET',lambda:flow.resume_completed(event,budget=budget()))
        _,other,foreign,_,_,_=self.loop();foreign.request_park_after_next_completion('select')
        foreign_event=other.run()['event']
        self.error('UNBOUND_FLOW_EVENT_REFERENCE',lambda:flow.resume_completed(foreign_event,budget=flow.budget))
        flow.resume_completed(event,budget=flow.budget)
        self.error('UNBOUND_FLOW_RESUME',lambda:flow.resume_completed(event,budget=flow.budget))

    def test_frontier_activation_values_map_and_epoch_reject_stale_resume(self):
        for change in ('frontier','activation','values','epoch'):
            with self.subTest(change=change):
                _,machine,flow,_,_,_=self.loop();flow.request_park_after_next_completion('select')
                event=machine.run()['event'];frame=machine.stack[-1];before=flow.counts()['births']
                if change=='frontier':frame.position+=1
                elif change=='activation':frame.activation+=1
                elif change=='values':frame.values=dict(frame.values)
                else:flow.expire()
                self.error('UNBOUND_FLOW_EVENT_REFERENCE',lambda:flow.resume_completed(event,budget=flow.budget))
                self.assertEqual(flow.counts()['births'],before)

    def test_snapshot_change_blocks_preflight_and_retained_completion_publication(self):
        owner,machine,flow,_,_,_=self.loop();flow.request_park_after_next_completion('select')
        event=machine.run()['event'];frame=machine.stack[-1];old=dict(frame.values);before=flow.counts()
        owner.sections[3]['functions'][-1]['no_return']=True
        flow.resume_completed(event,budget=flow.budget)
        with self.assertRaises(Exception):machine.run(fuel=0)
        self.assertEqual(frame.values,old);self.assertEqual(flow.counts(),before)

    def test_actual_events_do_not_advertise_source_language_or_runtime_permission(self):
        _,machine,flow,_,_,_=self.loop();self.assertEqual(machine.run()['kind'],'return')
        for name in ('source_facts_issued','source_admission_passed','runtime_permission'):
            self.assertIs(flow.counts()[name],False)
        self.assertFalse(flow.observation['private_core_events_issued'])
        self.assertGreater(flow.counts()['events'],0)

    def test_dispatch_is_exclusive_and_configuration_cannot_be_reassigned(self):
        _,machine,flow,_,_,_=self.loop()
        prior=(machine.steps,flow.counts())
        self.assertTrue(flow._dispatch_lock.acquire(blocking=False))
        try:
            from common import Reject
            with self.assertRaises(Reject):machine.run(fuel=1)
        finally:flow._dispatch_lock.release()
        self.assertEqual((machine.steps,flow.counts()),prior)
        for name,value in [('budget',budget()),('limits',Limits(max_serial=1))]:
            with self.assertRaises(AttributeError):setattr(flow,name,value)
        self.assertEqual(machine.run()['kind'],'return')

    def test_same_full_model_mask_does_not_admit_actual_undefined_numeric_seed(self):
        roots,assertion=document('chain',1)
        roots[3]['functions'][-1]['blocks']=[block(0,[operation('bitcast',[decl(1,INT8)],[0]),
            operation('bitcast',[decl(7,RAW)],[1])],dict(op='return',values=[7]))]
        assertion['flows']=[];assertion['nominals']=[dict(value=i,nominal=ref(NOMINAL))for i in (0,7)]
        assertion['seeds']=[dict(value=0,kind='parameter'),dict(value=7,kind='numeric_to_byte')]
        _,machine,flow,_=self.setup_machine(roots=roots,assertion=assertion,masks=((0,255),))
        machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42,poison=1))])
        frame=self.until(machine,lambda f:f.position==1)
        prior=(machine.steps,flow.counts(),dict(frame.values))
        self.error('UNBOUND_FLOW_MODEL_STATE_UNAVAILABLE',lambda:machine.run(fuel=1))
        self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),prior)

    def test_unsupported_actual_body_and_forged_parameter_coordinates_refuse_before_start(self):
        roots,assertion=document('chain',1)
        roots[3]['functions'][-1]['blocks'][0]['ops'][0]=operation('i_add',[decl(1,INT8)],[0,0],flags=[])
        # Build a valid scalar Int8 body outside the finite supported whitelist.
        signature=next(t for t in roots[1]['types']if t['id']==FN)
        signature['params']=[ref(INT8)];signature['results']=[ref(INT8)]
        roots[3]['functions'][-1]['params']=[decl(0,INT8)]
        assertion.update(flows=[],nominals=[],seeds=[])
        self.error('UNBOUND_FLOW_BODY_UNAVAILABLE',lambda:self.setup_machine(roots=roots,assertion=assertion))
        self.error('UNBOUND_FLOW_PARAMETER_MASK',lambda:self.setup_machine('max-id',masks=((0,255),)))
        self.error('UNBOUND_FLOW_PARAMETER_MASK',lambda:self.setup_machine('max-id',masks=((4294967293,256),)))

    def test_deterministic_actual_loop_grid_preserves_selected_origins_and_birth_counts(self):
        import random
        rng=random.Random(0x5A17)
        for case in range(32):
            iterations=rng.randrange(1,6);condition=rng.randrange(2);left=rng.randrange(256);right=rng.randrange(256)
            with self.subTest(case=case,iterations=iterations,condition=condition):
                _,machine,flow,_,a,b=self.loop(iterations=iterations,condition=condition,masks=(left,right))
                frame=machine.stack[-1]
                result=machine.run();self.assertEqual(result['kind'],'return')
                x,y=(a,b)if iterations%2 else(b,a)
                mx,my=(left,right)if iterations%2 else(right,left)
                selected,mask=(x,mx)if condition else(y,my)
                self.assertEqual(result['values'][0].data,selected.data)
                self.assertEqual(flow.describe_birth(flow.birth(frame,17))['mask'],mask)
                self.assertEqual(flow.selection_uses,iterations)
                serials=[birth['serial']for birth in flow._births.values()]
                self.assertEqual(serials,list(range(1,len(serials)+1)))
                self.assertEqual(len(serials),7+8*iterations)

    def test_actual_machine_body_mutation_cannot_execute_under_original_assertion(self):
        _,machine,flow,_,_,_=self.loop()
        frame=self.until(machine,lambda f:f.block==1 and f.position==1)
        frame.function['blocks'][1]['ops'][1]['operands'][1]=11
        prior=(machine.steps,flow.counts(),dict(frame.values))
        self.error('UNBOUND_FLOW_ORIGINAL',lambda:machine.run(fuel=1))
        self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),prior)

    def test_operation_one_less_each_budget_axis_keeps_same_resource_and_no_compute(self):
        roots,assertion=document('chain',1)
        _,machine,flow,ledger=self.setup_machine(roots=roots,assertion=assertion)
        machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))]);machine.run(fuel=2)
        measured=dict(max_work=ledger._used_work,max_edges=ledger._used_edges,
                      max_copied_bytes=ledger._used_copied_bytes,max_depth=128)
        for dimension in ('max_work','max_edges','max_copied_bytes'):
            with self.subTest(dimension=dimension):
                limits=dict(measured);limits[dimension]-=1
                _,machine,flow,ledger=self.setup_machine(roots=deepcopy(roots),assertion=deepcopy(assertion),
                    ledger=source_api().SourceQueryBudget(**limits))
                machine.start(1,[Value(ref(RAW),'concrete',Raw(8,42))]);machine.run(fuel=1)
                prior=(machine.steps,flow.counts(),dict(machine.stack[-1].values))
                charge=source_api().SourceQueryBudget.charge;errors=[]
                def observe(actual,**amounts):
                    try:return charge(actual,**amounts)
                    except source_api().SourceDataError as error:errors.append(error);raise
                with patch.object(source_api().SourceQueryBudget,'charge',observe):
                    error=self.error('SOURCE_DATA_RESOURCE',lambda:machine.run(fuel=1))
                self.assertEqual(len(errors),1);self.assertIs(error,errors[0])
                self.assertEqual((machine.steps,flow.counts(),dict(machine.stack[-1].values)),prior)

    def test_actual_completed_result_retained_when_event_bookkeeping_fails_before_event_exists(self):
        for kind in ('select','phi_batch','freeze'):
            with self.subTest(kind=kind):
                _,machine,flow,_,_,_=self.loop()
                if kind=='select':self.until(machine,lambda f:f.block==1 and f.position==1)
                elif kind=='freeze':self.until(machine,lambda f:f.block==1 and f.position==4)
                else:self.until(machine,lambda f:f.block==1 and f.position==-1)
                frame=machine.stack[-1];before=flow.counts();old=dict(frame.values)
                original=UnboundFlowRuntime._new_event;injected=MemoryError('injected after actual core completion')
                def fail_once(actual,*args,**kwargs):raise injected
                with patch.object(UnboundFlowRuntime,'_new_event',fail_once):
                    with self.assertRaises(MemoryError)as caught:machine.run(fuel=1)
                self.assertIs(caught.exception,injected)
                retained=machine._flow_actual_outputs;self.assertIsNotNone(retained)
                self.assertIsNone(machine._flow_event);self.assertEqual(frame.values,old)
                steps=machine.steps;computed=flow.computations;selected=flow.selection_uses
                self.assertEqual(computed,before['computations']+1)
                actual_pure=pure.execute;actual_materialize=pure.materialize;calls=[]
                def observe(*args,**kwargs):calls.append('execute');return actual_pure(*args,**kwargs)
                def materialize(*args,**kwargs):calls.append('materialize');return actual_materialize(*args,**kwargs)
                with patch.object(pure,'execute',observe),patch.object(pure,'materialize',materialize):
                    self.assertEqual(machine.run(fuel=0)['reason'],'fuel')
                self.assertEqual(calls,[]);self.assertIsNone(machine._flow_actual_outputs)
                self.assertEqual((machine.steps,flow.computations,flow.selection_uses),(steps,computed,selected))
                self.assertEqual(flow.counts()['events'],before['events']+1)
                self.assertEqual(machine.run()['kind'],'return')

    def test_failure_after_actual_select_choice_is_sticky_original_exception(self):
        from candidate import machine as machine_module
        _,machine,flow,_,_,_=self.loop(state='undef')
        frame=self.until(machine,lambda f:f.block==1 and f.position==1)
        original=machine_module.Machine._note_unbound_selection;materialize=pure.materialize
        injected=MemoryError('after actual select recording, before result collection');calls=[]
        def observed(types,value):calls.append('materialize');return materialize(types,value)
        def fail_after_note(actual,*args,**kwargs):
            original(actual,*args,**kwargs);raise injected
        before=(flow.counts()['events'],flow.counts()['births'],dict(frame.values))
        with patch.object(pure,'materialize',observed):
            with patch.object(machine_module.Machine,'_note_unbound_selection',fail_after_note):
                with self.assertRaises(MemoryError)as caught:machine.run(fuel=1)
            self.assertIs(caught.exception,injected);self.assertEqual(calls,['materialize'])
            self.assertIs(machine._flow_terminal_error,injected)
            self.assertIsNone(machine._flow_actual_outputs)
            after=(machine.steps,flow.counts(),dict(frame.values))
            for fuel in (0,1,100):
                with self.assertRaises(MemoryError)as repeated:machine.run(fuel=fuel)
                self.assertIs(repeated.exception,injected)
                self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),after)
        self.assertEqual(calls,['materialize']);self.assertEqual(flow.selection_uses,1)
        self.assertEqual((flow.counts()['events'],flow.counts()['births'],dict(frame.values)),before)

    def test_failure_inside_actual_phi_selection_is_sticky_without_reselection(self):
        import builtins
        from candidate import machine as machine_module
        for fail_ordinal in (1,2,3):
            with self.subTest(fail_ordinal=fail_ordinal):
                _,machine,flow,_,_,_=self.loop()
                frame=self.until(machine,lambda f:f.block==1 and f.position==-1)
                injected=MemoryError('after actual incoming selection');selected=[]
                def choose(iterator,*default):
                    value=builtins.next(iterator,*default)
                    if machine._flow_computing and type(value)is int:
                        selected.append(value)
                        if len(selected)==fail_ordinal:raise injected
                    return value
                before=(flow.counts()['events'],flow.counts()['births'],dict(frame.values))
                with patch.object(machine_module,'next',choose,create=True):
                    with self.assertRaises(MemoryError)as caught:machine.run(fuel=1)
                    self.assertIs(caught.exception,injected)
                    self.assertEqual(len(selected),fail_ordinal)
                    after=(machine.steps,flow.counts(),dict(frame.values))
                    for fuel in (0,1,100):
                        with self.assertRaises(MemoryError)as repeated:machine.run(fuel=fuel)
                        self.assertIs(repeated.exception,injected)
                        self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),after)
                    self.assertEqual(len(selected),fail_ordinal)
                self.assertIs(machine._flow_terminal_error,injected)
                self.assertEqual((flow.counts()['events'],flow.counts()['births'],dict(frame.values)),before)

    def test_failure_after_actual_freeze_before_result_collection_is_sticky(self):
        _,machine,flow,_,_,_=self.loop(raw=Raw(8,1,poison=1))
        frame=self.until(machine,lambda f:f.block==1 and f.position==4)
        actual_freeze=pure.freeze;outputs=[];injected=MemoryError('after actual freeze result')
        def freeze_then_fail(types,value):
            output=actual_freeze(types,value);outputs.append(output);raise injected
        before=(flow.counts()['events'],flow.counts()['births'],dict(frame.values))
        with patch.object(pure,'freeze',freeze_then_fail):
            with self.assertRaises(MemoryError)as caught:machine.run(fuel=1)
            self.assertIs(caught.exception,injected);self.assertEqual(len(outputs),1)
            self.assertEqual((outputs[0].data.poison,outputs[0].data.undef),(0,0))
            after=(machine.steps,flow.counts(),dict(frame.values))
            for fuel in (0,1,100):
                with self.assertRaises(MemoryError)as repeated:machine.run(fuel=fuel)
                self.assertIs(repeated.exception,injected)
                self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),after)
            self.assertEqual(len(outputs),1)
        self.assertIs(machine._flow_terminal_error,injected)
        self.assertEqual((flow.counts()['events'],flow.counts()['births'],dict(frame.values)),before)

    def test_failure_after_actual_control_transfer_is_sticky_without_next_dispatch(self):
        from candidate import machine as machine_module
        _,machine,flow,_,_,_=self.loop()
        frame=self.until(machine,lambda f:f.block==1 and f.position==5)
        branch=machine_module.Machine.branch;edges=[];injected=MemoryError('after actual branch')
        def branch_then_fail(actual,actual_frame,target):
            branch(actual,actual_frame,target);edges.append(target);raise injected
        with patch.object(machine_module.Machine,'branch',branch_then_fail):
            with self.assertRaises(MemoryError)as caught:machine.run(fuel=1)
            self.assertIs(caught.exception,injected);self.assertEqual(edges,[1])
            after=(machine.steps,flow.counts(),frame.block,frame.position,dict(frame.values))
            for fuel in (0,1,100):
                with self.assertRaises(MemoryError)as repeated:machine.run(fuel=fuel)
                self.assertIs(repeated.exception,injected)
                self.assertEqual((machine.steps,flow.counts(),frame.block,frame.position,dict(frame.values)),after)
            self.assertEqual(edges,[1])
        self.assertIs(machine._flow_terminal_error,injected)

    def test_inplace_current_value_replacement_cannot_reuse_old_birth(self):
        for frontier in ('select','phi_batch','freeze'):
            with self.subTest(frontier=frontier):
                _,machine,flow,_,_,_=self.loop()
                if frontier=='select':frame=self.until(machine,lambda f:f.block==1 and f.position==1)
                elif frontier=='freeze':frame=self.until(machine,lambda f:f.block==1 and f.position==4)
                else:frame=self.until(machine,lambda f:f.block==1 and f.position==-1)
                identifier=11 if frontier=='select' else 14 if frontier=='freeze' else 0
                replacement=Value(ref(RAW),'concrete',Raw.pointer(machine.memory.allocate(1,1)).slice(56,8))
                old=frame.values[identifier];self.assertEqual(old.data.bits,replacement.data.bits)
                self.assertIsNot(old,replacement);frame.values[identifier]=replacement
                before=(machine.steps,flow.counts(),dict(frame.values))
                for _ in range(2):self.error('UNBOUND_FLOW_VALUE_BIRTH',lambda:machine.run(fuel=1))
                self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),before)
                self.assertEqual(flow.selection_uses,0 if frontier!='freeze' else 1)

    def test_paused_completion_rejects_inplace_input_replacement_before_resume(self):
        _,machine,flow,_,_,_=self.loop();flow.request_park_after_next_completion('select')
        event=machine.run()['event'];frame=machine.stack[-1]
        frame.values[11]=Value(ref(RAW),'concrete',Raw.pointer(machine.memory.allocate(1,1)).slice(56,8))
        before=(machine.steps,flow.counts(),dict(frame.values),flow.describe_event(event)['stage'])
        self.error('UNBOUND_FLOW_VALUE_BIRTH',lambda:flow.resume_completed(event,budget=flow.budget))
        self.assertEqual((machine.steps,flow.counts(),dict(frame.values),flow.describe_event(event)['stage']),before)

    def test_actual_phi_snapshot_value_must_match_selected_birth_even_after_map_restore(self):
        from candidate import machine as machine_module
        _,machine,flow,_,_,_=self.loop()
        frame=self.until(machine,lambda f:f.block==1 and f.position==-1)
        actual_finish=UnboundFlowRuntime._finish
        replacement=Value(ref(RAW),'concrete',Raw.pointer(machine.memory.allocate(1,1)).slice(56,8))
        before=(flow.counts()['events'],flow.counts()['births'],dict(frame.values))
        def change_snapshot(actual,reservation,inputs,outputs,predecessor,**kwargs):
            # Actual original phi selection ran; fault model corrupts only its retained snapshot.
            altered=(replacement,)+tuple(outputs)[1:]
            return actual_finish(actual,reservation,inputs,altered,predecessor,**kwargs)
        with patch.object(UnboundFlowRuntime,'_finish',change_snapshot):
            self.error('UNBOUND_FLOW_VALUE_BIRTH',lambda:machine.run(fuel=1))
        self.assertEqual((flow.counts()['events'],flow.counts()['births'],dict(frame.values)),before)
        self.assertIsNotNone(machine._flow_actual_outputs)

    def test_inplace_numeric_input_replacement_cannot_reuse_initialized_birth(self):
        from candidate.values import from_raw
        machine,flow=self.numeric(255);frame=self.until(machine,lambda f:f.position==5)
        pointer=machine.memory.allocate(1,1);machine.memory.raw_store(pointer,Raw(8,42))
        replacement=from_raw(machine.types,ref(INT8),machine.memory.raw_load(pointer,1))
        self.assertEqual(replacement.data,frame.values[4].data)
        self.assertIsNot(replacement,frame.values[4]);frame.values[4]=replacement
        before=(machine.steps,flow.counts(),dict(frame.values))
        self.error('UNBOUND_FLOW_VALUE_BIRTH',lambda:machine.run(fuel=1))
        self.assertEqual((machine.steps,flow.counts(),dict(frame.values)),before)

    def test_unattached_original_core_execution_remains_available(self):
        roots,_=document('literal');owner=context(codec().encode(roots));owner.verify_abi()
        machine=Machine(owner.verify_execution());machine.start(1,[])
        self.assertIsNone(machine._unbound_flow)
        result=machine.run();self.assertEqual(result['kind'],'return');self.assertEqual(result['values'][0].data.bits,42)

if __name__=='__main__':unittest.main()
