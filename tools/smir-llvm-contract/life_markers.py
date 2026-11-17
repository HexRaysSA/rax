"""LLVM051 exact private note grammar; actual source graphs, no runtime authority."""
import re
import json
from pathlib import Path
import bindings
from canonical import require

CONTRACT=json.loads((Path(__file__).resolve().parents[2]/
    'docs/specifications/smir/portable/llvm/lifetime-marker-contract.json').read_text())
PHASES=set(CONTRACT['phases'])
SLOT_PHASES={'construct.begin','construct.commit','adopt','slot.destroy.begin','slot.destroy.commit'}
FORBIDDEN={'readnone','readonly','argmemonly','speculatable','nosync','willreturn','noreturn'}
ALLOWED_ATTRIBUTES={'nounwind','nocallback','noinline'}
CAPTURED={p for p,d in CONTRACT['phases'].items() if d['prototype']=='captured'}


def transport_tree(types, reference):
    typ=types.get(reference);kind=typ['kind']
    if kind=='fenv':return ['fenv_bytes32']
    if kind=='struct':return ['struct',*[transport_tree(types,r) for r in typ['fields']]]
    if kind in {'array','vector'}:
        if typ['count']==0:return ['empty_array']
        return [kind,typ['count'],transport_tree(types,typ['element'])]
    return ['direct']


def llvm_type(types, reference, transport=None):
    """Logical private-call transport; no source/native ABI coercion."""
    typ=types.get(reference);kind=typ['kind']
    expected=transport_tree(types,reference)
    require(transport is None or transport==expected,'E-LIFE-TRANSPORT')
    if kind=='fenv':
        return '[32 x i8]'
    if kind in {'int','raw'}:return ('i' if kind=='int' else 'b')+str(typ['bits'])
    if kind=='float':
        return {'binary16':'half','bfloat16':'bfloat','binary32':'float','binary64':'double','binary128':'fp128'}[typ['format']]
    if kind in {'data_ptr','code_ptr'}:return 'ptr'
    if kind in {'array','vector'}:
        if typ['count']==0:return '[0 x i8]'
        element_kind=types.get(typ['element'])['kind']
        native_vector=kind=='vector' and element_kind in {'int','float','data_ptr','code_ptr'}
        brackets=('<','>') if native_vector else ('[',']')
        return brackets[0]+str(typ['count'])+' x '+llvm_type(types,typ['element'])+brackets[1]
    if kind=='struct':return '{ '+', '.join(llvm_type(types,r) for r in typ['fields'])+' }'
    raise ValueError('E-LIFE-CAPTURE-TYPE')


def program_bytes(context, reference):
    from candidate.context import records
    from candidate.wire import encode
    return encode('cleanup_program',context.abi_entity('journal',reference),records=records())


def validate(document, contexts, *, facts=None, final=False):
    """Validate decoded LLVM-note projection against ACTUAL admitted contexts.

    Projection includes real decl/call metadata and bytes, not an authority token.
    Actual LLVM source-value typing/CFG effect correspondence remains a compiler
    proof obligation; this reference proves grammar/source graph/type retention.
    O(records+blob bytes+type/graph work), bounded notes<=65536/programs<=4096.
    """
    from candidate.context import RootContext
    require(type(document) is dict and set(document)=={'revision','programs','notes'},'E-LIFE-SHAPE')
    require(document['revision']==1,'E-LIFE-REVISION')
    require(type(document['programs']) is list and type(document['notes']) is list,'E-LIFE-SHAPE')
    require(len(document['programs'])<=4096 and len(document['notes'])<=65536,'E-LIFE-RESOURCE')
    require(not final or not document['notes'] and not document['programs'],'E-LIFE-RESIDUAL')
    programs={}
    for anchor in document['programs']:
        require(set(anchor)=={'anchor','unit','program','bytes','retained'},'E-LIFE-ANCHOR')
        require(re.fullmatch('[0-9a-f]{64}',anchor['unit']) is not None,'E-LIFE-SOURCE')
        context=contexts.get(anchor['unit'])
        require(isinstance(context,RootContext) and context.abi_checked and context.execution_checked is not None,'E-LIFE-SOURCE')
        context.assert_snapshot()
        require(anchor['program']['module']=={'kind':'self'},'E-LIFE-PROGRAM')
        require(type(anchor['bytes']) is str and len(anchor['bytes'])<=2**21 and
                re.fullmatch('(?:[0-9a-f]{2})*',anchor['bytes']) is not None,'E-LIFE-ANCHOR')
        require(bytes.fromhex(anchor['bytes'])==program_bytes(context,anchor['program']),'E-LIFE-ANCHOR-BYTES')
        require(anchor['retained'] is True,'E-LIFE-ANCHOR-RETENTION')
        prior=programs.get(anchor['anchor'])
        require(prior is None or prior==anchor,'E-LIFE-ANCHOR-CONFLICT')
        programs[anchor['anchor']]=anchor
    plans=[]
    for note in document['notes']:
        require(set(note)=={'callee','anchor','site','phase','attachment','transports','prototype',
                           'direct','escaped','slot','element','capture_types','operand_values','value_facts'},'E-LIFE-NOTE')
        require(note['anchor'] in programs,'E-LIFE-ANCHOR')
        anchor=programs[note['anchor']];context=contexts[anchor['unit']]
        require(type(note['site']) is int and 0<=note['site']<2**32 and note['phase'] in PHASES,'E-LIFE-SITE')
        name=f"__smir_life_v1.{anchor['unit']}.{note['site']}.{note['phase']}"
        require(note['callee']==name and note['direct'] is True and note['escaped'] is False,'E-LIFE-CALLEE')
        attachment=note['attachment']
        require(type(attachment) is list and len(attachment)==4 and type(attachment[0]) is int
                and attachment==[1,note['anchor'],note['site'],note['phase']],'E-LIFE-ATTACHMENT')
        program=context.abi_entity('journal',anchor['program'])
        formals=program['params'] if note['phase'] in CAPTURED else []
        require(len(formals)<=65536,'E-LIFE-RESOURCE')
        require(type(note['transports']) is list and len(note['transports'])==len(formals)
                and len(note['capture_types'])==len(formals),'E-LIFE-TRANSPORT')
        capture_params=[]
        for formal,actual,transport in zip(formals,note['capture_types'],note['transports']):
            source=context.nominal(formal['type']);execution=source['execution']
            require(execution is not None and context.types.equal(execution['some'],actual),'E-LIFE-CAPTURE-SOURCE')
            require(not context.types.contains_value_kind(actual,{'exception','journal','stack_mark','va_list'}),'E-LIFE-CAPTURE-TYPE')
            capture_params.append(llvm_type(context.types,actual,transport))
        params=['ptr','i32','i64']+(['ptr'] if note['phase']=='adopt' else [])+capture_params
        if note['phase']=='fail':params.append('target("smir.exception")')
        require(isinstance(facts,SourceFacts),'E-LIFE-SOURCE-VALUE')
        values=note['operand_values'];proofs=note['value_facts']
        require(type(values) is list and type(proofs) is list and len(values)==len(proofs)==1+len(formals)+
                int(note['phase'] in {'adopt','fail'}),'E-LIFE-SOURCE-VALUE')
        descriptors=[facts.verify(fact,value) for fact,value in zip(proofs,values)]
        require(descriptors[0]['unit']==anchor['unit'] and descriptors[0]['kind']=='object', 'E-LIFE-OBJECT-SOURCE')
        start=2 if note['phase']=='adopt' else 1
        for descriptor,formal in zip(descriptors[start:start+len(formals)],formals):
            require(descriptor['unit']==anchor['unit'] and descriptor['nominal'] is not None
                    and context.abi_graph.fingerprint(descriptor['nominal']['some'])==
                        context.abi_graph.fingerprint(formal['type']),'E-LIFE-CAPTURE-SOURCE')
        if note['phase']=='fail':require(descriptors[-1]['kind']=='unwind','E-LIFE-UNWIND-SOURCE')
        prototype=note['prototype']
        require(set(prototype)=={'return','cc','params','variadic','param_attributes','attributes'},'E-LIFE-PROTOTYPE')
        require(prototype['return']=='void' and prototype['cc']=='c' and prototype['params']==params
                and prototype['variadic'] is False,'E-LIFE-PROTOTYPE')
        require(prototype['param_attributes']==[[] for _ in params],'E-LIFE-PARAM-ATTRIBUTES')
        attrs=prototype['attributes']
        require(type(attrs) is list and len(attrs)==len(set(attrs)) and 'nounwind' in attrs
                and set(attrs)<=ALLOWED_ATTRIBUTES,'E-LIFE-ATTRIBUTES')
        require(type(note['slot']) is int and 0<=note['slot']<2**32 and
                type(note['element']) is int and 0<=note['element']<2**64,'E-LIFE-SLOT')
        if note['phase'] in SLOT_PHASES:
            require(note['slot'] in {s['id'] for s in program['slots']},'E-LIFE-SLOT')
        else:require(note['slot']==note['element']==0,'E-LIFE-UNUSED-SLOT')
        plans.append({'site':note['site'],'phase':note['phase'],'program':anchor['program']})
    for context in contexts.values():context.assert_snapshot()
    return plans


class SourceFacts:
    """Bounded PRIVATE typed-source ledger model, not file/AST authority.

    admitted_values is supplied by independently checked frontend typed AST/IR
    lowering, keyed actual LLVMValue object. Production producer/transform proof
    is not implemented here. Model verifies graph relations and issued membership.
    """
    def __init__(self,contexts,admitted_values):
        self.contexts=contexts
        self.source={v:list(d) if type(d) is list else [d] for v,d in admitted_values.items()}
        self.issued={};self.identities={}

    def bind(self,value,descriptor):
        from copy import deepcopy
        require(value in self.source and descriptor in self.source[value],'E-LIFE-SOURCE-VALUE')
        require(set(descriptor)=={'revision','unit','ordinal','kind','execution','nominal','storage_binding','code_signature'},
                'E-LIFE-SOURCE-FACT')
        require(type(descriptor['revision']) is int and descriptor['revision']==1 and
                type(descriptor['ordinal']) is int and 0<=descriptor['ordinal']<2**32,'E-LIFE-SOURCE-FACT')
        context=self.contexts[descriptor['unit']];context.assert_snapshot()
        identity=descriptor['unit'],descriptor['ordinal']
        require(identity not in self.identities or self.identities[identity]==descriptor,'E-LIFE-FACT-CONFLICT')
        typ=context.types.get(descriptor['execution']);kind=descriptor['kind']
        if kind=='object':
            require(typ['kind']=='data_ptr' and descriptor['nominal'] is not None and
                    descriptor['storage_binding'] is not None and descriptor['code_signature'] is None,'E-LIFE-OBJECT-SOURCE')
            binding=context.abi_entity('storage_binding',descriptor['storage_binding']['some'])
            require(context.abi_graph.fingerprint(binding['nominal'])==
                    context.abi_graph.fingerprint(descriptor['nominal']['some']),'E-LIFE-OBJECT-SOURCE')
        elif kind=='unwind':
            require(typ['kind']=='exception' and descriptor['nominal'] is None and descriptor['storage_binding'] is None
                    and descriptor['code_signature'] is None,'E-LIFE-UNWIND-SOURCE')
        else:
            require(kind in {'capture','code'} and descriptor['nominal'] is not None,'E-LIFE-CAPTURE-SOURCE')
            nominal=context.nominal(descriptor['nominal']['some'])
            require(nominal['execution'] is not None and context.types.equal(nominal['execution']['some'],descriptor['execution']),
                    'E-LIFE-CAPTURE-SOURCE')
            if typ['kind']=='code_ptr':
                require(kind=='code' and descriptor['code_signature'] is not None and
                        context.types.equal(typ['signature'],descriptor['code_signature']['some']),'E-LIFE-CODE-SOURCE')
            else:require(descriptor['code_signature'] is None,'E-LIFE-CODE-SOURCE')
        self.identities[identity]=deepcopy(descriptor)
        token=object();self.issued[token]=(value,deepcopy(descriptor));return token

    def verify(self,fact,value):
        require(fact in self.issued and self.issued[fact][0] is value,'E-LIFE-SOURCE-VALUE')
        descriptor=self.issued[fact][1];self.contexts[descriptor['unit']].assert_snapshot()
        return descriptor

    def remap(self,fact,new_value,value_map):
        require(fact in self.issued and value_map.get(self.issued[fact][0]) is new_value,'E-LIFE-REMAP')
        descriptor=self.issued[fact][1]
        if descriptor not in self.source.setdefault(new_value,[]):self.source[new_value].append(descriptor)
        return self.bind(new_value,descriptor)

    def rauw(self,old,new):
        # CallbackVH path: old/new are actual Value objects, not guessed equality.
        mapped=[]
        for fact,(value,_) in list(self.issued.items()):
            if value is old:
                mapped.append(self.remap(fact,new,{old:new}))
                del self.issued[fact]
        self.source.pop(old,None)
        require(mapped,'E-LIFE-REMAP')
        return mapped

    def deleted(self,value,*,surviving_note_use):
        require(not surviving_note_use,'E-LIFE-FACT-LOST')
        self.issued={f:entry for f,entry in self.issued.items() if entry[0] is not value}
        self.source.pop(value,None)
