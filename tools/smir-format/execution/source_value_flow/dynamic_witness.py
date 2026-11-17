"""Reproducible actual-core completed-event witnesses, explicitly UNBOUND."""
import argparse
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve()
sys.path.insert(0,str(HERE.parents[1]))
from candidate.machine import Machine
from candidate.raw import Raw
from candidate.type_system import ref
from candidate.values import Value
from candidate.source_data_projection import source_api
from source_value_flow.dynamic import UnboundFlowRuntime,Limits
from source_value_flow.fixtures import document,context,codec,encoded,RAW,INT64,BOOL

FIXTURE=HERE.with_name('dynamic-model-cases.json')


def witness(condition,state,raw_state):
    roots,assertion=document('loop');owner=context(codec().encode(roots));owner.verify_abi()
    machine=Machine(owner.verify_execution())
    budget=source_api().SourceQueryBudget(max_work=10**15,max_edges=10**15,max_copied_bytes=10**15,max_depth=128)
    flow=UnboundFlowRuntime(owner,encoded(assertion),parameter_masks=((0,0),(1,255),(2,2**64-1),(3,1)),limits=Limits(),budget=budget)
    machine.attach_unbound_value_flow(flow,budget=budget)
    a=Raw.pointer(machine.memory.allocate(1,1)).slice(56,8)
    b=Raw.pointer(machine.memory.allocate(1,1)).slice(56,8)
    samebits=a.bits==b.bits;different=a.origins[0].pointer.origin!=b.origins[0].pointer.origin
    if raw_state=='poison':a=Raw(8,1,poison=1)
    elif raw_state=='undef':a=Raw(8,1,undef=1)
    machine.start(1,[Value(ref(RAW),'concrete',a),Value(ref(RAW),'concrete',b),
        Value(ref(INT64),'concrete',2),Value(ref(BOOL),state,condition if state=='concrete'else None)])
    frame=machine.stack[-1];flow.request_park_after_next_completion('select')
    stopped=machine.run();event=stopped['event'];before=flow.describe_event(event);steps=machine.steps
    counts_before=flow.counts();flow.resume_completed(event,budget=budget);fuel=machine.run(fuel=0)
    after=flow.describe_event(event);first_mask=flow.describe_birth(flow.birth(frame,14))['mask']
    resumed=dict(no_extra_steps=machine.steps==steps,no_recomputation=flow.computations==counts_before['computations'],
                 same_retained_event=after['stage']=='published',fuel=fuel['reason'],mask=first_mask)
    result=machine.run()
    return dict(condition=condition,condition_state=state,input_raw_state=raw_state,
        actual_same_bits=samebits,actual_distinct_allocation_origins=different,
        parked=before,resumed=resumed,outcome=result['kind'],final=flow.counts(),
        final_mask=flow.describe_birth(flow.birth(frame,17))['mask'])


def corpus():
    rows=[witness(1,'concrete','defined'),witness(0,'concrete','defined'),witness(0,'undef','defined'),
          witness(1,'concrete','poison'),witness(1,'concrete','undef')]
    return dict(format='unbound-actual-core-event-model-witnesses',revision=1,cases=rows,
        source_facts_issued=False,source_category_proved=False,source_body_equivalence=False,
        source_admission_passed=False,runtime_permission=False,full_factory_cost_qualified=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    if args.check and args.write:parser.error('choose one output mode')
    data=(json.dumps(corpus(),sort_keys=True,indent=2)+'\n').encode()
    if args.check:
        if FIXTURE.read_bytes()!=data:raise SystemExit('dynamic witness fixture changed')
        print(json.dumps(dict(checked=True,cases=5,source_admission_passed=False)))
    elif args.write:FIXTURE.write_bytes(data)
    else:sys.stdout.buffer.write(data)

if __name__=='__main__':main()
