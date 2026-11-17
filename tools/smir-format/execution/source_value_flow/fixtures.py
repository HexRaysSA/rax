"""Actual core modules and public assertions, never private source facts/events."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from candidate.context import RootContext
from candidate.function_address_contract import source_roots
from candidate.machine import Machine
from candidate.type_system import ref
from candidate.values import Value
from candidate.raw import Raw
from test_candidate import block, constant, decl, operation

ROOT = Path(__file__).resolve().parents[4]
FOLDER = ROOT/'docs/specifications/smir/portable/conformance/execution/source-value-flow'
RAW, INT8, BOOL, INT64, FN, NOMINAL = 2300, 2301, 2302, 2303, 2304, 2300


def document(profile='loop', count=4):
    roots = source_roots()
    params = [RAW, RAW, INT64, BOOL] if profile == 'loop' else [RAW] if profile in {'chain', 'max-id'} else []
    results = [RAW, RAW] if profile == 'loop' else [RAW]
    roots[1]['types'] += [dict(id=RAW, kind='raw', bits=8), dict(id=INT8, kind='int', bits=8),
        dict(id=BOOL, kind='int', bits=1), dict(id=INT64, kind='int', bits=64),
        dict(id=FN, kind='function', params=[ref(t) for t in params], results=[ref(t) for t in results],
             param_noundef=[False]*len(params), result_noundef=[False]*len(results),
             cc='portable', variadic=False)]
    roots[1]['memory_layouts'].append(dict(id=RAW, type=ref(RAW), size=1, access_bytes=1,
        alignment=1, fields=[], element=None, stride=0))
    nominal = dict(id=NOMINAL, domain=0,
        identity=dict(language='cpp23', linkage='builtin', entity='unsigned char',
                      definition='0'*64, library=None, unit=None),
        kind='scalar', qualifiers=[], bits=8, signed=False, elements=[], extent=None,
        representation='value', execution={'some':ref(RAW)}, layout={'some':NOMINAL},
        flags=['complete','trivial_copy','trivial_destroy'], methods=[], enumerators=[], record_input=None)
    roots[10]['types'].append(nominal)
    roots[10]['layouts'].append(dict(id=NOMINAL, type=ref(NOMINAL), size=1, align=1,
        data_size=1, nonvirtual_size=1, nonvirtual_align=1, fields=[], bases=[], vptrs=[]))
    sys.path.insert(0,str(ROOT/'tools/smir-abi'))
    try:
        import nominal as actual_nominal
        if Path(actual_nominal.__file__).resolve() != ROOT/'tools/smir-abi/nominal.py':
            raise RuntimeError('nominal module identity')
        nominal['identity']['definition'] = actual_nominal.NominalGraph(roots[10],'flow-assertion').fingerprint(ref(NOMINAL))
    finally:
        sys.path.pop(0)
    flows, seeds = [], []
    if profile == 'loop':
        def phi(identifier, typ, a, b):
            return dict(result=decl(identifier,typ),incoming=[dict(predecessor=0,value=a),dict(predecessor=1,value=b)])
        first = block(0,[constant(4,INT64,'0100000000000000'),constant(5,INT64,'0000000000000000'),
                         constant(50,RAW,'00')],dict(op='jump',target=1))
        phis = [phi(10,RAW,0,11),phi(11,RAW,1,10),phi(12,INT64,2,15)]
        middle = block(1,[operation('copy',[decl(13,RAW)],[10]),
            operation('select',[decl(14,RAW)],[3,13,11]),
            operation('i_sub',[decl(15,INT64)],[12,4],flags=[]),
            operation('icmp',[decl(16,BOOL)],[15,5],predicate='eq'),
            operation('freeze',[decl(17,RAW)],[14])],
            dict(op='cbranch',condition=16,true=2,false=1),phis)
        blocks=[first,middle,block(2,[],dict(op='return',values=[17,11]))]
        for item in phis[:2]:
            flows.append(dict(kind='phi',block=1,result=item['result']['id'],nominal=ref(NOMINAL),incoming=deepcopy(item['incoming'])))
        flows += [dict(kind='noop',block=1,operation=0,input=10,result=13,input_nominal=ref(NOMINAL),result_nominal=ref(NOMINAL)),
            dict(kind='select',block=1,operation=1,condition=3,true_value=13,false_value=11,result=14,nominal=ref(NOMINAL)),
            dict(kind='freeze',block=1,operation=4,input=14,result=17,nominal=ref(NOMINAL))]
        values=[0,1,10,11,13,14,17,50];seeds=[dict(value=i,kind='parameter')for i in (0,1)]+[dict(value=50,kind='literal')]
    elif profile in {'chain','max-id'}:
        start = 4294967293 if profile == 'max-id' else 0
        count = 1 if profile == 'max-id' else count
        ops=[]
        for i in range(count):
            output=start+i+1
            ops.append(operation('copy',[decl(output,RAW)],[output-1]))
            flows.append(dict(kind='noop',block=0,operation=i,input=output-1,result=output,
                              input_nominal=ref(NOMINAL),result_nominal=ref(NOMINAL)))
        blocks=[block(0,ops,dict(op='return',values=[start+count]))]
        values=list(range(start,start+count+1));seeds=[dict(value=start,kind='parameter')]
    else:
        ops=[constant(0,RAW,'2a')]
        seeds=[dict(value=0,kind='literal')];values=[0]
        if profile == 'seeds':
            ops += [constant(1,INT8,'07'),operation('bitcast',[decl(2,RAW)],[1]),
                    operation('bitcast',[decl(3,RAW)],[0]),operation('freeze',[decl(4,RAW)],[3])]
            values += [2,3,4];seeds.append(dict(value=2,kind='numeric_to_byte'))
            flows += [dict(kind='noop',block=0,operation=3,input=0,result=3,input_nominal=ref(NOMINAL),result_nominal=ref(NOMINAL)),
                      dict(kind='freeze',block=0,operation=4,input=3,result=4,nominal=ref(NOMINAL))]
        elif profile != 'literal':
            raise ValueError('profile')
        blocks=[block(0,ops,dict(op='return',values=[values[-1]]))]
    fn=dict(id=1,signature=ref(FN),abi_signature=None,params=[decl(i,t)for i,t in enumerate(params)],
            entry=0,escape='propagate',no_return=False,blocks=blocks)
    if profile=='max-id':fn['params'][0]['id']=4294967293
    roots[3]['functions'].append(fn)
    roots[1]['types'].sort(key=lambda r:r['id']);roots[1]['memory_layouts'].sort(key=lambda r:r['id'])
    roots[10]['types'].sort(key=lambda r:r['id']);roots[10]['layouts'].sort(key=lambda r:r['id'])
    assertion=dict(format='source-value-flow-assertion',revision=1,function=ref(1),
                   flows=flows,nominals=[dict(value=i,nominal=ref(NOMINAL))for i in values],seeds=seeds)
    return roots,assertion


def codec():
    name='_rax_source_value_flow_codec'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'tools/smir-format/codec.py')
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    schemas={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in ('execution','abi','runtime')}
    return sys.modules[name].CandidateCodec(schemas)


def context(wire):
    return RootContext(codec().decode(wire).roots)


def encoded(assertion):
    return (json.dumps(assertion,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')


def core_witness(wire, iterations=2, condition=1, state='concrete'):
    """Observe actual generic Machine values/PC; do not issue private events."""
    owner=context(wire);owner.verify_abi();admitted=owner.verify_execution();machine=Machine(admitted)
    p=machine.memory.allocate(1,1);q=machine.memory.allocate(1,1)
    a=Value(ref(RAW),'concrete',Raw.pointer(p).slice(56,8))
    b=Value(ref(RAW),'concrete',Raw.pointer(q).slice(56,8))
    cond=Value(ref(BOOL),state,condition if state=='concrete' else None)
    machine.start(1,[a,b,Value(ref(INT64),'concrete',iterations),cond])
    batches=[];selections=[];freezes=[]
    for _ in range(1000):
        frame=machine.stack[-1];before_steps=machine.steps
        batch=(frame.values.get(10),frame.values.get(11)) if frame.block==1 and frame.position==-1 else None
        selected=(frame.values[13],frame.values[11]) if frame.block==1 and frame.position==1 else None
        freeze_input=frame.values[14] if frame.block==1 and frame.position==4 else None
        outcome=machine.run(fuel=1)
        if batch is not None:
            batches.append(dict(predecessor=frame.predecessor,ordinal=len(batches)+1,
                swaps_previous=(frame.values[10] is batch[1] and frame.values[11] is batch[0])if batch[0]is not None else None))
        if selected is not None:
            output=frame.values[14]
            selections.append(dict(steps=machine.steps-before_steps,state=output.state,
                selected='true'if output is selected[0]else'false'if output is selected[1]else None,
                equal_input_bits=selected[0].data.bits==selected[1].data.bits,
                distinct_input_origins=selected[0].data.origins[0].pointer.origin!=selected[1].data.origins[0].pointer.origin))
        if freeze_input is not None:
            output=frame.values[17]
            freezes.append(dict(input_state=freeze_input.state,output_state=output.state,
                actual_output_defined=output.data.poison==0 and output.data.undef==0))
        if outcome['kind']!='resource':break
    else:raise RuntimeError('core step bound')
    owner.assert_snapshot()
    return dict(outcome=outcome['kind'],batches=batches,selections=selections,freezes=freezes,
                source_facts_issued=False,private_core_events_issued=False,source_admission_passed=False)
