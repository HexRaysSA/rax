#!/usr/bin/env python3
"""LLVM051 bounded grammar/source-fact and actual pinned retention witnesses."""
import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import bindings
import life_markers as life
from canonical import require

ROOT=Path(__file__).resolve().parents[2]
FIXTURES=ROOT/'docs/specifications/smir/portable/conformance/llvm'
UID='1'*64
PREFIX='__smir_life_v1.'+UID+'.7.'
ANCHOR='__smir_life_program_fixture'


def context(formal_count=1):
    sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
    from test_candidate_storage_join import storage_wrapper
    from candidate.context import RootContext
    from candidate.type_system import ref
    roots=storage_wrapper()
    formals=[dict(id=19,type=ref(1))]+([dict(id=3,type=ref(4))] if formal_count==2 else [])
    roots[10]['journals']=[dict(id=0,signature=0,params=formals,slots=[dict(
        id=0,type=ref(1),offset=0,extent=4,align=4,parent=None,role='root',count=1,stride=4,
        count_source=None,constructor=None,destructor=None,destructor_kind='none',covers=[],owner=0,
        dependencies=[],child_program=None)],normal_order=[0],exception_order=[0])]
    c=RootContext(roots);c.verify_abi();c.verify_execution()
    return c,ref


def document(formal_count=1):
    c,ref=context(formal_count);contexts={UID:c}
    object_value,capture_value=object(),object()
    def descriptor(ordinal,kind,execution,nominal,storage):
        return dict(revision=1,unit=UID,ordinal=ordinal,kind=kind,execution=ref(execution),
                    nominal=None if nominal is None else {'some':ref(nominal)},
                    storage_binding=None if storage is None else {'some':ref(storage)},code_signature=None)
    obj=descriptor(0,'object',4,1,1);cap=descriptor(1,'capture',1,1,None)
    facts=life.SourceFacts(contexts,{object_value:obj,capture_value:cap})
    object_fact,capture_fact=facts.bind(object_value,obj),facts.bind(capture_value,cap)
    second_value=object();second_descriptor=descriptor(2,'capture',4,4,None)
    if formal_count==2:
        facts.source[second_value]=[second_descriptor]
        second_fact=facts.bind(second_value,second_descriptor)
    anchor=dict(anchor=ANCHOR,unit=UID,program=ref(0),bytes=life.program_bytes(c,ref(0)).hex(),retained=True)
    notes=[]
    for phase in ('object.begin','construct.begin','construct.commit','suspend.prepare','resume','publish','object.destroy','object.done'):
        captured=phase in life.CAPTURED
        notes.append(dict(callee=PREFIX+phase,anchor=ANCHOR,site=7,phase=phase,
            attachment=[1,ANCHOR,7,phase],transports=[['direct']] if captured else [],
            prototype=dict(return_='unused'),direct=True,escaped=False,slot=0,element=0,
            capture_types=[ref(1)] if captured else [],
            operand_values=[object_value,capture_value] if captured else [object_value],
            value_facts=[object_fact,capture_fact] if captured else [object_fact]))
        notes[-1]['prototype']={'return':'void','cc':'c','params':['ptr','i32','i64']+(['i32'] if captured else []),
                               'variadic':False,'param_attributes':[[]]*(4 if captured else 3),'attributes':['nounwind']}
        if captured and formal_count==2:
            notes[-1]['transports'].append(['direct']);notes[-1]['capture_types'].append(ref(4))
            notes[-1]['operand_values'].append(second_value);notes[-1]['value_facts'].append(second_fact)
            notes[-1]['prototype']['params'].append('ptr');notes[-1]['prototype']['param_attributes'].append([])
    return dict(revision=1,programs=[anchor],notes=notes),contexts,facts


def clone_document(doc):
    # LLVM Value/fact object identities must be retained; no deepcopy capability.
    result=copy.deepcopy({k:v for k,v in doc.items() if k!='notes'})
    result['notes']=[]
    for n in doc['notes']:
        item=copy.deepcopy({k:v for k,v in n.items() if k not in {'operand_values','value_facts'}})
        item.update(operand_values=list(n['operand_values']),value_facts=list(n['value_facts']))
        result['notes'].append(item)
    return result


def pure_witness():
    doc,contexts,facts=document();life.validate(doc,contexts,facts=facts)
    from candidate.type_system import Types,ref
    cases=[]
    changes=[('attachment',lambda d:d['notes'][0].update(attachment=None)),
        ('tampered_program',lambda d:d['programs'][0].update(bytes=d['programs'][0]['bytes']+'00')),
        ('unknown_phase',lambda d:d['notes'][0].update(phase='guess')),
        ('memory_none',lambda d:d['notes'][0]['prototype']['attributes'].append('readnone')),
        ('noundef_capture',lambda d:d['notes'][0]['prototype']['param_attributes'][-1].append('noundef')),
        ('indirect',lambda d:d['notes'][0].update(direct=False)),
        ('wrong_value',lambda d:d['notes'][0]['operand_values'].__setitem__(1,object())),
        ('forged_fact',lambda d:d['notes'][0]['value_facts'].__setitem__(1,object())),
        ('unretained_anchor',lambda d:d['programs'][0].update(retained=False)),
        ('unavailable_destroy_capture',lambda d:d['notes'][-2]['prototype']['params'].append('i32'))]
    for name,change in changes:
        bad=clone_document(doc);change(bad)
        try:life.validate(bad,contexts,facts=facts)
        except (ValueError,TypeError,KeyError) as error:cases.append(dict(case=name,rejected=str(error)))
        else:raise AssertionError('Accepted invalid lifetime note: '+name)
    try:life.validate(doc,contexts,facts=facts,final=True)
    except ValueError:pass
    else:raise AssertionError('Residual notes accepted for emission')
    life.validate(dict(revision=1,programs=[],notes=[]),contexts,facts=facts,final=True)
    external,contexts2,facts2=document(2)
    life.validate(external,contexts2,facts=facts2)
    require(len(external['notes'][-2]['prototype']['params'])==3,'EXTERNAL_DESTROY_CAPTURE_GUESS')
    old=doc['notes'][0]['value_facts'][1];old_value=doc['notes'][0]['operand_values'][1];new_value=object()
    mapped=facts.remap(old,new_value,{old_value:new_value})
    facts.verify(mapped,new_value)
    try:facts.remap(old,object(),{})
    except ValueError:pass
    else:raise AssertionError('Name/equality guessed a missing LLVM value map')
    # Separate source views share one ptr Value without mutually compatible T.
    shared=object();desc0=copy.deepcopy(facts.issued[doc['notes'][0]['value_facts'][0]][1])
    desc1=copy.deepcopy(desc0);desc1.update(ordinal=99,nominal={'some':ref(4)},storage_binding={'some':ref(3)})
    facts.source[shared]=[desc0,desc1]
    view0,view1=facts.bind(shared,desc0),facts.bind(shared,desc1)
    merged=object();newfacts=facts.rauw(shared,merged)
    require(len(newfacts)==2 and {facts.verify(f,merged)['ordinal'] for f in newfacts}=={0,99},'SHARED_SOURCE_VIEWS')
    try:facts.deleted(merged,surviving_note_use=True)
    except ValueError:pass
    else:raise AssertionError('Deleted a value still used by a note')
    facts.deleted(merged,surviving_note_use=False)
    # Recursive copyable snapshots, including empty arrays: no native fenv type.
    c=contexts[UID]
    from candidate.type_system import Types,ref
    types=Types(dict(payload_revision=2,memory_layouts=[],types=[dict(id=0,kind='fenv'),
        dict(id=1,kind='int',bits=32),dict(id=2,kind='struct',fields=[ref(0),ref(1)]),
        dict(id=3,kind='array',element=ref(0),count=2),dict(id=4,kind='array',element=ref(0),count=0)]))
    require(life.llvm_type(types,ref(2))=='{ [32 x i8], i32 }','NESTED_FENV')
    require(life.llvm_type(types,ref(3))=='[2 x [32 x i8]]','NESTED_FENV')
    require(life.llvm_type(types,ref(4))=='[0 x i8]','EMPTY_FENV')
    # Freeze every allowed capture ONCE; same defined snapshot is saved/resumed.
    from candidate.values import Value,freeze
    from candidate.fenv import pack,unpack
    for state in ('undef','poison'):
        frozen=freeze(types,Value(ref(0),state))
        require(unpack(pack(frozen.data))==frozen.data,'FENV_CAPTURE_STABILITY')
        integer=freeze(types,Value(ref(1),state));require(integer.state=='concrete' and integer.data==0,'CAPTURE_STABILITY')
    return dict(positive_notes=len(doc['notes']),rejections=cases,recursive_fenv=3,remap_positive=True,
                remap_negative=True,two_view_same_value=True,external_destroy_formals=2,stable_capture_cases=4,
                builder_stability=builder_stability())


def builder_stability():
    """Actual decoded RootContext, live values and R Builder across two TIDs."""
    from candidate.bindings import runtime_package_module
    from candidate.context import RootContext
    from candidate.live import Registry as LiveRegistry,validate as live_validate
    from candidate.type_system import ref
    from candidate.values import Value,Pointer,freeze
    from test_candidate_journal_factory import capture_factory
    from test_candidate_storage_join import reference_image
    schema={owner:json.loads((ROOT/'docs/specifications/smir/portable/schema'/owner/'candidate.json').read_text())
            for owner in ('execution','runtime','abi')}
    decoded=runtime_package_module('wire').PRIMITIVES.CandidateCodec(schema).decode(
        runtime_package_module('wire').PRIMITIVES.CandidateCodec(schema).encode(capture_factory()))
    context=RootContext(decoded.roots);context.verify_abi();context.verify_execution()
    machine=reference_image(context);source=machine.symbols['self',1];module=decoded.content_digest
    def setup():
        objects={1:dict(address=source.address,size=4,generation=source.generation,live=True)}
        def program(owner,r):
            require(owner==module,'CAPTURE_OWNER');return (owner,r['id']),context.abi_entity('journal',r)
        lives=runtime_package_module('lifetimes').Registry(objects,program,{1:{'live':True}})
        def nominal(owner,r):require(owner==module,'CAPTURE_OWNER');return context.nominal(r)
        def check(owner,value,activation):
            require(owner==module,'CAPTURE_OWNER')
            return live_validate(value,context.types,LiveRegistry(),11 if activation==101 else 12,activation)
        return runtime_package_module('partials').Registry(lives,lambda owner:context.types,nominal,check,
            modules={module:dict(generation=1,pins=1)})
    pointer=Pointer(source.address,1,source.generation)
    old=dict(thread=11,activation=101,generation=1,instance=7)
    new=dict(thread=12,activation=201,generation=1,instance=8)
    counts=[dict(slot=0,count=1)];rows=[]
    for state in ('undef','poison'):
        integer=freeze(context.types,Value(ref(17),state));ptr=freeze(context.types,Value(ref(4),state))
        require(integer.state==ptr.state=='concrete' and ptr.data.origin is None and ptr.data.address==0,'CAPTURE_FREEZE')
        stable=[dict(parameter=0,value=dict(type=ref(17),payload=dict(kind='scalar',bits=integer.data.to_bytes(4,'little').hex()))),
            dict(parameter=1,value=dict(type=ref(4),payload=dict(kind='pointer',address=0,object=None,generation=0,domain='data',range=None,binding_permit=None)))]
        builders=setup();j=builders.begin(module,ref(0),pointer,old,stable,counts,[1]);builders.detach(j,old)
        fresh=builders.begin(module,ref(0),pointer,new,copy.deepcopy(stable),counts,[1])
        require(builders.snapshot(fresh,new,transition=2)['captures']==stable,'CAPTURE_RESUME_EQUALITY')
        unstable=[dict(parameter=i,value=dict(type=ref(17 if i==0 else 4),payload=dict(kind=state))) for i in (0,1)]
        unprotected=setup();j=unprotected.begin(module,ref(0),pointer,old,unstable,counts,[1]);unprotected.detach(j,old)
        try:unprotected.begin(module,ref(0),pointer,new,stable,counts,[1])
        except ValueError as error:require('RT_PARTIAL_BUSY' in str(error),'CAPTURE_COUNTER')
        else:raise AssertionError('Expected saved unknown capture to differ without stabilization')
        rows.append(dict(source_state=state,stable_resume=True,without_freeze_rejects=True))
    return rows


def command(argv):
    process=subprocess.run([str(v) for v in argv],capture_output=True,text=True)
    if process.returncode:raise AssertionError(f'{argv!r}\n{process.stderr}')
    return process.stdout


def decorate(text,program_hex,fact_descriptors):
    """Fixture-only metadata/source-fact producer, not a general LLVM emitter."""
    begin=next(line for line in text.splitlines() if 'call void @'+PREFIX+'object.begin' in line)
    args=re.search(r'\((.*)\)',begin).group(1).replace('noundef ','')
    parts=args.split(', ');obj=parts[0].removeprefix('ptr ');captured=parts[-1].removeprefix('i32 ')
    # Markers are private logical calls, so remove source C++ ABI attributes.
    lines=[];in_function=False;injected=False;stored=False
    for line in text.splitlines():
        if line.startswith('define '):in_function='@_Z15marked_lifetimei(' in line
        if PREFIX in line and ('call void @' in line):line=line.replace('noundef ','')
        if 'call void @'+PREFIX+'object.begin' in line:
            lines.append(f'  %smir.life.stable = freeze i32 {captured}')
            line=line.replace('i32 '+captured+')','i32 %smir.life.stable)')
        if in_function and not injected and '@llvm.coro.save' in line and any(PREFIX+'object.begin' in x for x in lines):
            lines.append(line)
            lines.append(f'  call void @{PREFIX}suspend.prepare(ptr {obj}, i32 0, i64 0)')
            injected=True;continue
        if in_function and injected and not stored and re.search(r'store i32 .*ptr '+re.escape(obj)+r'[, ]',line):
            lines.append(f'  call void @{PREFIX}resume(ptr {obj}, i32 0, i64 0, i32 %smir.life.stable)')
            lines.append(f'  call void @{PREFIX}construct.begin(ptr {obj}, i32 0, i64 0)')
            stored=True
        if line.startswith('declare void @'+PREFIX):continue
        lines.append(line)
    require(injected and stored,'LIFETIME_FIXTURE_INSERTION')
    metadata_ids=[int(x) for x in re.findall(r'^!(\d+)\s*=',text,re.M)]
    base=max(metadata_ids,default=0)+100
    phases=['object.begin','construct.begin','construct.commit','suspend.prepare','resume','publish']
    # Keep program/source fact anchors through actual optimizers and Split.
    blob=''.join('\\'+program_hex[i:i+2] for i in range(0,len(program_hex),2))
    lines.append(f'@{ANCHOR} = private constant [{len(program_hex)//2} x i8] c"{blob}", align 1')
    fact_hex=[]
    for suffix,descriptor in zip(('object','capture'),fact_descriptors):
        payload=json.dumps(descriptor,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode().hex()
        fact_hex.append((suffix,payload))
        escaped=''.join('\\'+payload[i:i+2] for i in range(0,len(payload),2))
        lines.append(f'@__smir_life_fact_{suffix} = private constant [{len(payload)//2} x i8] c"{escaped}", align 1')
    lines.append(f'@llvm.compiler.used = appending global [3 x ptr] [ptr @{ANCHOR}, ptr @__smir_life_fact_object, ptr @__smir_life_fact_capture], section "llvm.metadata"')
    for phase in phases:
        params='ptr, i32, i64'+(', i32' if phase in life.CAPTURED else '')
        lines.append(f'declare void @{PREFIX}{phase}({params}) nounwind')
    lines.append(f'!smir.life.programs = !{{!{base}}}')
    lines.append(f'!{base} = !{{i32 1, ptr @{ANCHOR}, !"{UID}", i32 0}}')
    for index,phase in enumerate(phases,1):
        lines.append(f'!{base+index} = !{{i32 1, ptr @{ANCHOR}, i32 7, !"{phase}"}}')
    lines.append(f'!{base+20} = !{{}}')
    lines.append(f'!{base+21} = !{{!{base+22}}}')
    lines.append(f'!{base+22} = !{{!"direct"}}')
    result=[]
    for line in lines:
        if 'call void @'+PREFIX in line:
            phase=next(p for p in phases if '@'+PREFIX+p+'(' in line)
            descriptor=base+1+phases.index(phase)
            callargs=line.split('@'+PREFIX+phase+'(',1)[1].split(')',1)[0].split(', ')
            bundle='ptr @__smir_life_fact_object, '+callargs[0]
            if phase in life.CAPTURED:bundle+=', ptr @__smir_life_fact_capture, '+callargs[3]
            line+=' [ "smir.life.values"('+bundle+') ]'
            line+=f', !smir.life !{descriptor}, !smir.life.transports !{base+21 if phase in life.CAPTURED else base+20}'
        result.append(line)
    return '\n'.join(result)+'\n'


def llvm_string(payload):
    result=bytearray();index=0
    while index<len(payload):
        if payload[index]=='\\':result.append(int(payload[index+1:index+3],16));index+=3
        else:result.append(ord(payload[index]));index+=1
    return result


def inspect(text,program_hex,fact_descriptors):
    match=re.search(r'@'+ANCHOR+r' = private (?:unnamed_addr )?constant \[\d+ x i8\] c"([^\n]*)", align 1',text)
    require(match is not None and bytes(llvm_string(match.group(1))).hex()==program_hex,'E-LIFE-ANCHOR-BYTES')
    require(re.search(r'@llvm.compiler.used = .*@'+ANCHOR,text) is not None,'E-LIFE-ANCHOR-RETENTION')
    for suffix,expected in zip(('object','capture'),fact_descriptors):
        fact=re.search(r'@__smir_life_fact_'+suffix+r' = private (?:unnamed_addr )?constant \[\d+ x i8\] c"([^\n]*)", align 1',text)
        require(fact is not None and json.loads(llvm_string(fact.group(1)))==expected,'E-LIFE-SOURCE-FACT')
    nodes={int(n):body for n,body in re.findall(r'^!(\d+) = !\{(.*)\}$',text,re.M)}
    phases=[]
    for line in text.splitlines():
        if 'call void @'+PREFIX not in line:continue
        phase=line.split('@'+PREFIX,1)[1].split('(',1)[0]
        node=re.search(r'!smir.life !(\d+)',line)
        require(node is not None,'E-LIFE-ATTACHMENT')
        require(nodes[int(node.group(1))]==f'i32 1, ptr @{ANCHOR}, i32 7, !"{phase}"','E-LIFE-ATTACHMENT')
        require('!smir.life.transports !' in line,'E-LIFE-TRANSPORT')
        arguments=line.split('@'+PREFIX+phase+'(',1)[1].split(')',1)[0].split(', ')
        bundle=re.search(r'"smir.life.values"\(([^)]*)\)',line)
        require(bundle is not None,'E-LIFE-SOURCE-VALUE')
        actual=bundle.group(1).split(', ')
        def value_operand(argument):
            parts=argument.split();require(parts[0] in {'ptr','i32','i64'},'E-LIFE-PROTOTYPE')
            # Canonical printed fixture operands: compare actual type/value,
            # separately admitting only optimizer-added value promises.
            require(set(parts[1:-1])<={'nonnull','noundef'},'E-LIFE-PARAM-ATTRIBUTES')
            return parts[0]+' '+parts[-1]
        expected=['ptr @__smir_life_fact_object',value_operand(arguments[0])]
        if phase in life.CAPTURED:expected+=['ptr @__smir_life_fact_capture',value_operand(arguments[3])]
        require(actual==expected,'E-LIFE-SOURCE-VALUE')
        phases.append(phase)
    expected={'object.begin','construct.begin','construct.commit','suspend.prepare','resume','publish'}
    require(set(phases)==expected,'E-LIFE-RETAINED-PHASES')
    attributes={int(i):set(a.split()) for i,a in re.findall(r'^attributes #(\d+) = \{ (.*?) \}$',text,re.M)}
    for phase in expected:
        declaration=re.search(r'^declare void @'+re.escape(PREFIX+phase)+r'\(([^)]*)\)[^\n]*#(\d+)',text,re.M)
        require(declaration is not None,'E-LIFE-PROTOTYPE')
        params=['ptr','i32','i64']+(['i32'] if phase in life.CAPTURED else [])
        require(declaration.group(1).split(', ')==params,'E-LIFE-PROTOTYPE')
        require('nounwind' in attributes[int(declaration.group(2))] and
                attributes[int(declaration.group(2))]<=life.ALLOWED_ATTRIBUTES,'E-LIFE-ATTRIBUTES')
    split=re.search(r'^define .*@_Z15marked_lifetimei\.resume\(',text,re.M) is not None
    return dict(call_count=len(phases),phases=sorted(set(phases)),split=split,
                exact_source_operand_pairs=True,actual_fact_blobs=True)


def live_witness(clang,output):
    output.mkdir(parents=True,exist_ok=True)
    doc,_,facts=document();program_hex=doc['programs'][0]['bytes']
    fact_descriptors=[facts.issued[f][1] for f in doc['notes'][0]['value_facts']]
    original=command([clang,'-target','x86_64-unknown-linux-gnu','-std=c++23','-O2','-fcoro-aligned-allocation',
        '-Xclang','-disable-llvm-passes','-S','-emit-llvm',FIXTURES/'lifetime-markers.cpp','-o','-'])
    source=decorate(original,program_hex,fact_descriptors);path=output/'before.ll';path.write_text(source)
    results=[]
    for mode,options in [('O0',['-O0']),('O2',['-O2']),('full',['-O2','-flto=full']),('thin',['-O2','-flto=thin'])]:
        text=command([clang,'-target','x86_64-unknown-linux-gnu','-x','ir',*options,'-S','-emit-llvm',path,'-o','-'])
        (output/(mode+'.ll')).write_text(text);results.append(dict(mode=mode,**inspect(text,program_hex,fact_descriptors)))
    return results


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--clang',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=dict(pure=pure_witness())
    if args.clang:result['live']=live_witness(args.clang,args.output)
    print(json.dumps(result))
