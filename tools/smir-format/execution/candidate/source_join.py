"""Original-source requirement joins; all results UNBOUND, never private facts."""
from dataclasses import dataclass, field
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys

from candidate.source_data_projection import source_api
from candidate.source_lifetimes import shape, ContractError

ROOT=Path(__file__).resolve().parents[4]
SCHEMA=ROOT/'docs/specifications/smir/portable/schema/execution/source_join.json'
SCHEMA_SHA256='70b58e08cbdc76ce4463aa88b9a8cdc9ceff635d20fbf3f019159b7827551f24'

class JoinError(ValueError):
    def __init__(self,code,detail='',kind='semantic'):
        self.code,self.detail,self.kind=code,detail,kind
        super().__init__(code+(': '+detail if detail else ''))

def need(value,code,detail=''):
    if not value:raise JoinError(code,detail)

@dataclass(frozen=True)
class OriginalOwnerInput:
    context:str
    owner:object

@dataclass(frozen=True)
class OriginalContextBinding:
    context:str
    owner:object
    stamp:object

@dataclass(frozen=True)
class JoinedStaticSourceRequirements:
    document_digest:str
    abi_descriptor_digest:str
    bindings:tuple
    programs:tuple
    cells:tuple
    unselected_deferred:tuple
    obligations:tuple
    binding:str=field(default='unbound',init=False)
    runtime_authority:bool=field(default=False,init=False)
    source_fact_authority:bool=field(default=False,init=False)

def abi_api():
    directory=ROOT/'tools/smir-abi';package='rax_abi_record_layout'
    if package not in sys.modules:
        spec=importlib.util.spec_from_file_location(package,directory/'record_layout/__init__.py',submodule_search_locations=[str(directory/'record_layout')])
        module=importlib.util.module_from_spec(spec);sys.modules[package]=module;spec.loader.exec_module(module)
    need(Path(sys.modules[package].__file__).resolve()==(directory/'record_layout/__init__.py').resolve(),'SJ_ABI_MODULE')
    previous=list(sys.path)
    try:
        sys.path.insert(0,str(directory));module=importlib.import_module(package+'.source_programs')
    finally:sys.path[:]=previous
    need(Path(module.__file__).resolve()==(directory/'record_layout/source_programs.py').resolve(),'SJ_ABI_MODULE')
    return module

def capture(value,budget):
    nodes=0;size=0;active=set()
    def visit(x,depth):
        nonlocal nodes,size
        budget.charge(work=2,edges=1,copied_bytes=64);nodes+=1;size+=64
        if nodes>200000 or size>8*1024*1024 or depth>min(64,budget.max_depth):raise JoinError('SJ_RESOURCE',kind='resource')
        if type(x) is str:
            need(len(x)<=4096,'SJ_STRING_LIMIT');budget.charge(work=len(x),copied_bytes=12*len(x));size+=12*len(x)
            if size>8*1024*1024:raise JoinError('SJ_RESOURCE',kind='resource')
            return x
        if type(x) is int:
            need(x.bit_length()<=64,'SJ_INTEGER_RANGE');return x
        if x is None or type(x) is bool:return x
        need(type(x) in (dict,list),'SJ_SHAPE');need(id(x) not in active,'SJ_CYCLE')
        active.add(id(x));budget.charge(work=len(x),edges=len(x),copied_bytes=16*len(x))
        try:
            if type(x) is list:return [visit(y,depth+1) for y in x]
            need(all(type(k) is str for k in x),'SJ_SHAPE')
            return {visit(k,depth+1):visit(y,depth+1) for k,y in x.items()}
        finally:active.remove(id(x))
    result=visit(value,0);return result,size+16*nodes

def digest(value,bound,budget):
    budget.charge(work=4*bound,copied_bytes=2*bound)
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')).hexdigest()

def index(rows,budget,key='id'):
    budget.charge(work=len(rows),edges=len(rows),copied_bytes=128*len(rows));result={}
    for row in rows:
        identity=getattr(row,key) if not isinstance(row,dict) else row[key]
        need(identity not in result,'SJ_DUPLICATE');result[identity]=row
    return result

def get(table,key):
    need(key in table,'SJ_REFERENCE',str(key));return table[key]


def original_base_geometry(owner,record,slot,budget):
    roots=owner.sections;types=index(roots[10]['types'],budget);layouts=index(roots[10]['layouts'],budget)
    def nominal(reference):
        if reference['module']['kind']=='dependency':
            dependencies=index(roots[2]['manifest']['dependencies'],budget,'slot')
            declarations=index(get(dependencies,reference['module']['slot'])['declarations'],budget)
            declaration=get(declarations,reference['id'])
            need(declaration['kind']=='nominal' and declaration['nominal'] is not None,'SJ_ORIGINAL_REFERENCE')
            reference=declaration['nominal']['some']
        need(reference['module']=={'kind':'self'},'SJ_ORIGINAL_REFERENCE')
        return get(types,reference['id'])
    parent=nominal(record['source']['nominal']);layout=get(layouts,parent['layout']['some'])
    budget.charge(work=len(layout['bases']),copied_bytes=64*len(layout['bases']))
    bases=[x for x in layout['bases'] if not x['virtual'] and x['declaration_index']=={'some':slot['declaration_index']}]
    need(len(bases)==1,'SJ_ORIGINAL_BASE_LAYOUT');base=bases[0];leaf=nominal(slot['source']['nominal']);actual=nominal(base['type'])
    need(actual['kind']==leaf['kind']=='record' and actual['domain']==leaf['domain'],'SJ_ORIGINAL_BASE_TYPE')
    identity=lambda x:{k:v for k,v in x['identity'].items() if k!='definition'}
    need(identity(actual)==identity(leaf),'SJ_ORIGINAL_BASE_TYPE')
    child=get(layouts,leaf['layout']['some'])
    need((slot['offset_bits'],slot['width_bits'],slot['alignment'])==(8*base['offset'],8*child['nonvirtual_size'],child['nonvirtual_align']),'SJ_ORIGINAL_BASE_LAYOUT')
    return actual['identity']==leaf['identity'] and actual['qualifiers']==leaf['qualifiers']


def verify(document,abi_document,*,original_owners,budget,expected_bindings=None):
    from candidate.context import RootContext
    need(type(budget) is source_api().SourceQueryBudget,'SJ_BUDGET_IDENTITY')
    need(type(original_owners) is tuple and len(original_owners)<=256 and all(type(x) is OriginalOwnerInput for x in original_owners),'SJ_OWNER_INPUT')
    data,bound=capture(document,budget);abi,abi_bound=capture(abi_document,budget)
    length=SCHEMA.stat().st_size;need(length<=256*1024,'SJ_SCHEMA_LIMIT')
    budget.charge(work=8*length,copied_bytes=8*length)
    with SCHEMA.open('rb') as f:raw=f.read(length+1)
    need(len(raw)==length,'SJ_SCHEMA_CHANGED');need(hashlib.sha256(raw).hexdigest()==SCHEMA_SHA256,'SJ_SCHEMA_IDENTITY');schema=json.loads(raw)
    try:shape(schema,data,schema['$defs'],budget)
    except ContractError as e:raise JoinError('SJ_RESOURCE' if e.code=='SL_RESOURCE' else 'SJ_SHAPE',e.detail,kind='resource' if e.code=='SL_RESOURCE' else 'semantic') from e
    contexts=index(data['contexts'],budget);owners=index(original_owners,budget,'context')
    need(set(contexts)==set(owners),'SJ_OWNER_INPUT')
    need(len({x['abi_context'] for x in contexts.values()})==len(contexts),'SJ_CONTEXT_DUPLICATE')
    programs=index(data['programs'],budget);cell_rows=index(data['cells'],budget)
    need(bool(contexts),'SJ_CONTEXT_REQUIRED')
    api=abi_api();first_label=next(iter(contexts));first=contexts[first_label]
    first_report=api.check_source_associations_deferred(abi,owners[first_label].owner,first['abi_context'],budget=budget)
    abi_contexts=index(abi['contexts'],budget);records=index(abi['records'],budget);cleanups=index(abi['cleanups'],budget)
    reports={};bindings=[];deferred=[];unselected=[]
    for label,context in contexts.items():
        owner=owners[label].owner
        need(type(owner) is RootContext,'SJ_OWNER_INPUT')
        report=first_report if label==first_label else api.check_source_associations_deferred(abi,owner,context['abi_context'],budget=budget)
        stamp=report.stamp;declared=get(abi_contexts,context['abi_context'])
        budget.charge(work=len(stamp.root_digests),copied_bytes=128*len(stamp.root_digests))
        actual_roots=[dict(section=n,digest=h.hex()) for n,h in stamp.root_digests]
        need(context['roots']==actual_roots,'SJ_ROOT_DIGESTS')
        need(context['schema_digest']==stamp.schema_digest.hex(),'SJ_SOURCE_SCHEMA')
        need(context['family']==declared['family'] and context['abi_site']==declared['abi_site'],'SJ_CONTEXT_IDENTITY')
        reports[label]=report;bindings.append(OriginalContextBinding(label,owner,stamp))
        deferred.extend(report.deferred);unselected.extend(report.unselected_deferred)
    if expected_bindings is not None:
        need(type(expected_bindings) is tuple and len(expected_bindings)<=256 and all(type(x) is OriginalContextBinding for x in expected_bindings),'SJ_PRIOR_BINDING')
        prior=index(expected_bindings,budget,'context');need(set(prior)==set(contexts),'SJ_PRIOR_BINDING')
        for binding in bindings:
            old=prior[binding.context]
            need(old.owner is binding.owner and old.stamp is binding.stamp,'SJ_PRIOR_BINDING')
    checked_programs=[];coverage={};selected_records={};keys=set();direct_slots={}
    for label,p in programs.items():
        context=get(contexts,p['context']);cleanup=get(cleanups,p['abi_cleanup']);record=get(records,cleanup['record'])
        need(record['source']['context']==context['abi_context'],'SJ_PROGRAM_CONTEXT')
        need(p['original_journal']==cleanup['journal_program'] and p['cleanup_signature']==cleanup['signature'],'SJ_PROGRAM_REFERENCE')
        need(p['source_class']==record['source']['nominal'] and p['view']==cleanup['view'],'SJ_PROGRAM_VIEW')
        budget.charge(work=64,copied_bytes=256)
        key=(id(owners[p['context']].owner),json.dumps(p['original_journal'],sort_keys=True),p['view'])
        need(key not in keys,'SJ_PROGRAM_DUPLICATE');keys.add(key)
        coverage[label]=set();direct_slots[label]=set();selected_records[label]=record;checked_programs.append(label)
    checked_cells=[];unsupported=[];selectors=set()
    for label,cell in cell_rows.items():
        p=get(programs,cell['program']);record=selected_records[p['id']];selector=cell['selector']
        need(selector['record']==record['id'],'SJ_CELL_RECORD')
        budget.charge(work=128,copied_bytes=2048)
        if selector['kind']=='root':selector_key=(p['id'],'root',selector['record'])
        else:
            budget.charge(work=32*len(selector['steps']),copied_bytes=512*len(selector['steps']))
            selector_key=(p['id'],'path',selector['record'],tuple((x['slot'],None if x['indices'] is None else tuple(x['indices'])) for x in selector['steps']))
        need(selector_key not in selectors,'SJ_CELL_DUPLICATE');selectors.add(selector_key)
        if selector['kind']=='root':
            need(cell['declared_nominal']==record['source']['nominal'],'SJ_CELL_NOMINAL')
            unsupported.append(('root',label));continue
        steps=selector['steps'];need(bool(steps),'SJ_PATH_EMPTY');slot=None
        budget.charge(work=len(steps),edges=len(steps),copied_bytes=128*len(steps))
        for i,step in enumerate(steps):
            slots=index(record['slots'],budget);slot=get(slots,step['slot'])
            indices=step['indices'];extents=slot['array_extents']
            if indices is not None:
                need(bool(extents) and len(indices)==len(extents) and all(n<e for n,e in zip(indices,extents)),'SJ_ARRAY_INDICES')
            if i+1<len(steps):
                need(slot['element_record'] is not None and (not extents or indices is not None),'SJ_PATH_DESCENT')
                record=get(records,slot['element_record'])
        need(cell['declared_nominal']==slot['source']['nominal'],'SJ_CELL_NOMINAL')
        first_slot=steps[0]['slot']
        coverage[p['id']].add(first_slot)
        paths=slot['paths'];budget.work(sum(len(x) for x in paths)+len(paths))
        direct=(len(steps)==1 and steps[0]['indices'] is None and not slot['array_extents'] and
                slot['kind'] in {'member','nonvirtual_base'} and len(paths)==1 and len(paths[0])==1 and not paths[0][0]['virtual'])
        if direct:
            if slot['kind']=='nonvirtual_base' and not original_base_geometry(owners[p['context']].owner,selected_records[p['id']],slot,budget):unsupported.append(('base_type_compatibility',label))
            need(first_slot not in direct_slots[p['id']],'SJ_COVERAGE_DUPLICATE');direct_slots[p['id']].add(first_slot)
            expected=selector['expected_layout'];need(expected is not None,'SJ_LAYOUT_REQUIRED')
            need(expected=={k:slot[k] for k in ('offset_bits','width_bits','alignment')},'SJ_CELL_LAYOUT')
            checked_cells.append(label)
        else:
            need(selector['expected_layout'] is None,'SJ_UNSUPPORTED_LAYOUT')
            unsupported.append(('selector',label))
    for label,p in programs.items():
        required=get(cleanups,p['abi_cleanup'])['slots'];budget.work(len(required))
        need(coverage[label]==set(required),'SJ_COVERAGE_EXHAUSTION')
    for binding in bindings:
        need(RootContext.prepare_source_data(binding.owner,budget=budget) is binding.stamp,'SJ_SOURCE_CONTEXT')
    budget.charge(work=4*length,copied_bytes=2*length)
    with SCHEMA.open('rb') as f:after=f.read(length+1)
    need(hashlib.sha256(after).digest()==hashlib.sha256(raw).digest(),'SJ_SCHEMA_CHANGED')
    if deferred or unsupported:
        raise JoinError('SJ_SOURCE_EVIDENCE_UNAVAILABLE',repr(tuple((x.code,x.context_id) for x in deferred)+tuple(unsupported)),kind='unavailable')
    doc_digest=digest(data,bound,budget);abi_digest=digest(abi,abi_bound,budget)
    need(all(report.descriptor.document_digest==abi_digest for report in reports.values()),'SJ_ABI_DESCRIPTOR_CHANGED')
    budget.charge(work=len(bindings)+len(checked_cells)+len(checked_programs)+len(unselected),copied_bytes=256*(len(bindings)+len(checked_cells)+len(checked_programs)+len(unselected)))
    return JoinedStaticSourceRequirements(doc_digest,abi_digest,tuple(bindings),tuple(checked_programs),tuple(checked_cells),
        tuple((x.code,x.context_id,x.subject_kind,x.subject_id,x.path,x.edge_index) for x in unselected),
        ('Raw original source joins only; genuine complete Type/ABI/Metadata/Program/source facts still required.',
         'No source alias/generation/schedule/carrier, private fact or execution authority is issued.',
         'Unselected source contexts and extended canonical source truth remain unresolved.'))
