"""Independent finite formula/graph checks; no source/admission authority."""
from pathlib import Path
import sys,json
from portable_type_paths import foundation
ROOT=foundation()
sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
sys.path.insert(1,str(ROOT/'tools/smir-abi'))
from candidate.type_system import Types
from candidate.wire import encode,decode
from layout import SCALARS
from contract_json import verify as verify_schema
from nominal import NominalGraph,ref

class CheckError(ValueError): pass

def need(ok,code):
    if not ok: raise CheckError(code)

def check(product):
    verify_schema(product,json.loads(Path(__file__).with_name("portable_type_projection.schema.json").read_text()))
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
    aux=product['auxiliary_execution_relation']
    accounted={r['execution']['id'] for r in rel if r['execution'] is not None}|{a['execution']['id'] for a in aux}
    need(accounted==set(xs),'EXHAUSTIVE_EXECUTION_RELATION')
    need({a['vector_ast_type'] for a in aux}=={i for i,n in ns.items() if n['kind']=='vector'},'EXHAUSTIVE_VECTOR_RELATION')
    for a in aux:
        n=ns[a['vector_ast_type']]
        need(a['reason']=='numeric_vector_lane' and n['elements']==[ref(a['element_ast_type'])] and
             xs[n['execution']['some']['id']]['element']==a['execution'],'VECTOR_RELATION_JOIN')
    def eid(i):
        q=ns[i]['execution']
        return None if q is None else q['some']['id']
    sizes={}
    def geometry(i):
        if i in sizes:return sizes[i]
        n=ns[i];k=n['kind'];e=n['elements']
        if k in ('void','function'): result=None
        elif k=='scalar': result=SCALARS[n['identity']['entity']]
        elif k=='pointer': result=(8,8)
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
                 l['nonvirtual_align']==result[1] and not l['fields'] and not l['bases'] and not l['vptrs'],
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
    for p in plans:
        n=ns[p['function_type']['id']]; f=xs[p['execution']['id']]
        need(p['this_type'] is None and p['vtt'] is False and p['variadic'] is False and p['varargs'] is None and
             p['noexcept']==('noexcept' in n['flags']) and p['execution']==ref(eid(n['id'])),'FINITE_ORDINARY_PLAN')
        params=n['elements'][:-1]; result=n['elements'][-1]['id']
        need(p['params']==params and len(p['lowered_params'])==len(params),'PLAN_ARITY')
        attrs=[]
        for j,(q,a) in enumerate(zip(params,p['lowered_params'])):
            t=ns[q['id']];want=t['kind']!='scalar' or t['identity']['entity'] not in byte
            need(a['source_index']=={'some':j} and a['source_type']==a['value_type']==q and
                 a['role']=='parameter' and a['mode']=='direct' and (a['bytes'],a['align'])==geometry(q['id']) and
                 a['noundef'] is want and a['copy'] is a['move'] is a['destroy'] is None,'DIRECT_PLAN_PARAMETER')
            attrs.append(want)
        ret=ns[result];void=ret['kind']=='void'
        wantret=ret['kind']!='scalar' or ret['identity']['entity'] not in byte
        need(p['return_noundef'] is wantret and p['result']==(None if void else {'some':ref(result)}) and
             p['lowered_results']==([] if void else [ref(result)]),'DIRECT_PLAN_RESULT')
        need(f['param_noundef']==attrs and f['result_noundef']==([] if void else [wantret]) and
             f['params']==[ref(eid(q['id'])) for q in params] and f['results']==([] if void else [ref(eid(result))]) and
             f['cc']=='portable' and f['variadic'] is False,'EXECUTION_PLAN_JOIN')
    graph=NominalGraph(dict(types=list(ns.values()),layouts=list(ls.values()),domains=[dict(id=0,abi_identity=product['abi_identity'])]),'independent')
    for i,n in ns.items():need(n['identity']['definition']==graph.fingerprint(ref(i)),'NOMINAL_FINGERPRINT')
    need(all(d['type_id'] in ns for d in product['declarations']),'DECLARATION_RELATION')
    return dict(types=len(ns),layouts=len(ls),plans=len(plans),execution_types=len(xs),declarations=len(product['declarations']))
