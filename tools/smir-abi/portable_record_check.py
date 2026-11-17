"""Independent finite formula/graph checks; no source/admission authority."""
from pathlib import Path
import sys,json
from portable_record_paths import foundation
ROOT=foundation()
sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
sys.path.insert(1,str(ROOT/'tools/smir-abi'))
from candidate.type_system import Types
from candidate.wire import encode,decode
from layout import SCALARS
from contract_json import verify as verify_schema
from nominal import NominalGraph,ref,classify
from record_layout.checked import CheckedRecords

class CheckError(ValueError): pass

def need(ok,code):
    if not ok: raise CheckError(code)

def check(product):
    verify_schema(product,json.loads(Path(__file__).with_name("portable_record_projection.schema.json").read_text()))
    need(product['binding']=='unbound' and all(product[k] is False for k in
         ('source_fact_authority','semantic_admission','runtime_authority','library_membership_authority')),
         'TYPE_AUTHORITY')
    root=product['execution_root']
    need(decode('execution_types',encode('execution_types',root))==root,'EXECUTION_WIRE')
    types=Types(root)
    ns={t['id']:t for t in product['abi_fragment']['types']}
    ls={t['id']:t for t in product['abi_fragment']['layouts']}
    xs={t['id']:t for t in root['types']}
    rel=product['emitted_type_relation']
    need({r['nominal']['id'] for r in rel}==set(ns) and len(rel)==len(ns),'EXHAUSTIVE_NOMINAL_RELATION')
    need({r['ast_type'] for r in rel}==set(ns),'EXHAUSTIVE_AST_RELATION')
    for r in rel:
        n=ns[r['ast_type']]
        expected_execution=None if n['execution'] is None else n['execution']['some']
        expected_layout=None if n['layout'] is None else n['layout']['some']
        matching=[p['id'] for p in product['abi_fragment']['signatures'] if p['function_type']==ref(n['id'])]
        need(r['nominal']==ref(n['id']) and r['execution']==expected_execution and
             r['layout']==expected_layout and r['call_plan']==(matching[0] if len(matching)==1 else None),
             'EXACT_EMITTED_RELATION_JOIN')
    origins={r['nominal']['id']:r['origins'] for r in rel}
    aux=product['auxiliary_execution_relation']
    accounted={r['execution']['id'] for r in rel if r['execution'] is not None}|{a['execution']['id'] for a in aux}
    need(accounted==set(xs),'EXHAUSTIVE_EXECUTION_RELATION')
    need(len(aux)==sum(n['kind']=='vector' for n in ns.values()) and {a['vector_ast_type'] for a in aux}=={i for i,n in ns.items() if n['kind']=='vector'},'EXHAUSTIVE_VECTOR_RELATION')
    for a in aux:
        n=ns[a['vector_ast_type']]
        need(a['reason']=='numeric_vector_lane' and n['elements']==[ref(a['element_ast_type'])] and
             xs[n['execution']['some']['id']]['element']==a['execution'],'VECTOR_RELATION_JOIN')
    def eid(i):
        q=ns[i]['execution']
        return None if q is None else q['some']['id']
    graph=NominalGraph(dict(identity=product['abi_identity'],types=list(ns.values()),layouts=list(ls.values()),domains=[dict(id=0,abi_identity=product['abi_identity'])]),'independent')
    record_model=CheckedRecords(graph)
    sizes={}
    def geometry(i):
        if i in sizes:return sizes[i]
        n=ns[i];k=n['kind'];e=n['elements']
        if k in ('void','function'): result=None
        elif k=='scalar': result=SCALARS[n['identity']['entity']]
        elif k=='pointer': result=(8,8)
        elif k=='record':
            computed=record_model.verify(ref(i))
            result=(computed.size,computed.align)
        elif k=='bitint':
            q=(n['bits']+7)//8
            a=min(8,1<<(q-1).bit_length())
            result=((q+a-1)//a*a,a)
        elif k=='enum':
            result=geometry(e[0]['id'])
            if 'fixed_base' not in n['flags']:
                vals=[int.from_bytes(bytes.fromhex(v['value']),'little',signed=n['signed']) for v in n['enumerators']]
                expected=next((name for name,bits,signed in [('int',32,True),('unsigned int',32,False),
                    ('long',64,True),('unsigned long',64,False)] if all(
                        (-(1<<(bits-1)) if signed else 0)<=v<(1<<(bits-int(signed))) for v in vals)),None)
                need(expected is not None and ns[e[0]['id']]['identity']['entity']==expected,'ENUM_SIGNED_FIRST')
        elif k=='array':
            s,a=geometry(e[0]['id']); result=(s*n['extent']['some'],a)
        elif k=='vector':
            s,a=geometry(e[0]['id']); total=s*n['extent']['some']
            need(total<=64 and total&(total-1)==0,'VECTOR_POWER_TWO')
            result=(total,total)
        else:raise CheckError('UNSUPPORTED_NOMINAL')
        sizes[i]=result
        if result is None:need(n['layout'] is None,'NONOBJECT_LAYOUT')
        else:
            l=ls[n['layout']['some']]
            need((l['size'],l['align'])==result,'INDEPENDENT_LAYOUT_'+str(i))
            need(l['type']==ref(i) and l['data_size']==l['nonvirtual_size']==result[0] and
                 l['nonvirtual_align']==result[1] and (k=='record' or not l['fields']) and not l['bases'] and not l['vptrs'],
                 'FINITE_LAYOUT_FIELDS')
        return result
    byte={'char','signed char','unsigned char','char8_t'}
    for i,n in ns.items():
        geometry(i)
        x=xs.get(eid(i)); kind=n['kind']
        if kind=='void':need(x is None,'VOID_EXECUTION')
        elif kind=='scalar':
            name=n['identity']['entity']
            expected='raw' if name in byte else 'float' if name in ('float','double','long double') else 'int'
            need(x['kind']==expected,'SCALAR_EXECUTION')
            if expected!='float':need(x['bits']==n['bits'],'SCALAR_PRECISION')
            if name=='bool':need(n['bits']==1,'BOOL_PRECISION')
        elif kind in ('bitint','enum'):need(x['kind']=='int' and x['bits']==n['bits'],'NUMERIC_EXECUTION')
        elif kind=='record':need(x['kind']=='raw' and x['bits']==ls[n['layout']['some']]['size']*8 and n['representation']=='storage','RECORD_STORAGE_EXECUTION')
        elif kind=='pointer':need(x['kind']==('code_address' if 'code'in n['flags'] else 'data_ptr'),'POINTER_EXECUTION')
        elif kind in ('array','vector'):
            child=ns[n['elements'][0]['id']]; childx=xs[x['element']['id']]
            need(x['kind']==kind and x['count']==n['extent']['some'],'AGGREGATE_EXECUTION')
            if kind=='vector':
                need(childx['kind'] in ('int','float') and childx['kind']!='raw','NUMERIC_VECTOR_LANE')
                if childx['kind']=='int':need(childx['bits']==child['bits'],'VECTOR_PRECISION')
            else:need(x['element']==ref(eid(child['id'])),'ARRAY_ELEMENT')
    plans=product['abi_fragment']['signatures']
    need({r['call_plan'] for r in rel if r['call_plan'] is not None}=={p['id'] for p in plans},'EXHAUSTIVE_PLAN_RELATION')
    need({p['function_type']['id'] for p in plans}=={i for i,n in ns.items() if n['kind']=='function'},'EXHAUSTIVE_PLANS')
    wanted_derivations=[]
    for p in plans:
        n=ns[p['function_type']['id']]; f=xs[p['execution']['id']]
        need(p['this_type'] is None and p['vtt'] is False and p['variadic'] is False and p['varargs'] is None and
             p['noexcept']==('noexcept' in n['flags']) and p['execution']==ref(eid(n['id'])),'FINITE_ORDINARY_PLAN')
        params=n['elements'][:-1]; result=n['elements'][-1]['id']
        need(p['params']==params,'PLAN_SOURCE_ARITY')
        wanted,results=classify(graph,p)
        need(len(wanted)==len(p['lowered_params']) and results==p['lowered_results'],'PLAN_CLASSIFICATION')
        attrs=[]
        for expected,a in zip(wanted,p['lowered_params']):
            source=ns[a['source_type']['id']]
            byte_value=source['kind']=='scalar' and source['identity']['entity'] in byte
            expected['noundef']=False if expected['mode']=='direct' and byte_value else True
            need(all(a[k]==v for k,v in expected.items()),'CLASSIFIED_PARAMETER')
            need(a['copy'] is a['move'] is a['destroy'] is None,'ORDINARY_C_LIFECYCLE')
            if a['mode']!='direct':
                pointer=ns[a['value_type']['id']]
                need(source['kind']=='record' and pointer['kind']=='pointer' and pointer['elements']==[a['source_type']],'AGGREGATE_POINTER')
                need('abi_lowering' in origins[pointer['id']],'DERIVATION_ORIGIN_JOIN')
                wanted_derivations.append(dict(function=p['function_type'],role=a['role'],source_index=a['source_index'],source_type=a['source_type'],pointer_type=a['value_type']))
            else:need(a['value_type']==a['source_type'],'DIRECT_VALUE_TYPE')
            attrs.append(expected['noundef'])
        ret=ns[result];void=ret['kind']=='void';aggregate=ret['kind']=='record'
        wantret=ret['kind']!='scalar' or ret['identity']['entity'] not in byte
        need(p['return_noundef'] is wantret and p['result']==(None if void else {'some':ref(result)}),'PLAN_RESULT')
        need(f['param_noundef']==attrs and f['result_noundef']==([] if void or aggregate else [wantret]) and
             f['params']==[ref(eid(a['value_type']['id'])) for a in p['lowered_params']] and
             f['results']==[ref(eid(x['id'])) for x in results] and f['cc']=='portable' and f['variadic'] is False,'EXECUTION_PLAN_JOIN')
    need(product['abi_derivations']==wanted_derivations,'EXHAUSTIVE_ABI_DERIVATIONS')
    observations=product['record_observations']
    need(len(observations)==sum(n['kind']=='record' for n in ns.values()) and
         {o['nominal']['id'] for o in observations}=={i for i,n in ns.items() if n['kind']=='record'},'RECORD_OBSERVATION_COVERAGE')
    for o in observations:
        l=ls[o['nominal']['id']]
        need((o['ast_size'],o['ast_align'],o['policy_data_size'])==(l['size'],l['align'],l['data_size']) and
             o['ast_data_size']==l['size'],'C_AST_GEOMETRY')
    for r in rel:
        need(r['origins'] in (['source'],['abi_lowering'],['source','abi_lowering']),'TYPE_ORIGINS')
        if 'abi_lowering' in r['origins']:
            n=ns[r['nominal']['id']]
            need(n['kind']=='pointer' and ns[n['elements'][0]['id']]['kind']=='record','DERIVED_RECORD_POINTER')
    graph=NominalGraph(dict(identity=product['abi_identity'],types=list(ns.values()),layouts=list(ls.values()),domains=[dict(id=0,abi_identity=product['abi_identity'])]),'independent')
    for i,n in ns.items():need(n['identity']['definition']==graph.fingerprint(ref(i)),'NOMINAL_FINGERPRINT')
    need(all(d['type_id'] in ns for d in product['declarations']),'DECLARATION_RELATION')
    return dict(types=len(ns),layouts=len(ls),plans=len(plans),execution_types=len(xs),declarations=len(product['declarations']))
