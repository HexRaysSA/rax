"""Actual quotient algorithm + explicit per-operation logical charges.

Optional None preserves legacy computation. Counts cover declared logical row/
comparison-byte/copy units, not CPython instructions, RSS or host timing.
"""
import json

def charge(budget,work=0,edges=0,copied_bytes=0):
    if budget is not None:budget.charge(work=work,edges=edges,copied_bytes=copied_bytes)

def json_bound(value,budget):
    """Metered plain JSON tree bound before json allocation; no user callbacks."""
    charge(budget,work=1,copied_bytes=64);pending=[(value,0)];bound=0;sort_work=0;nodes=0
    while pending:
        charge(budget,work=1);v,depth=pending.pop();nodes+=1
        if depth>budget.max_depth:raise ValueError('ABI_FACTORY_JSON_DEPTH')
        if nodes>200000:raise ValueError('ABI_FACTORY_JSON_BOUND')
        if type(v)is dict:
            charge(budget,work=len(v),edges=2*len(v),copied_bytes=128*len(v))
            if not all(type(k)is str for k in v):raise ValueError('ABI_FACTORY_JSON_KEY')
            longest=max((len(k)for k in v),default=0);sort_work+=(len(v)+1)**2*(longest+1)
            bound+=2+2*len(v);pending.extend((x,depth+1)for x in v.keys());pending.extend((x,depth+1)for x in v.values())
        elif type(v)in(list,tuple):
            charge(budget,work=len(v),edges=len(v),copied_bytes=64*len(v));bound+=2+len(v);pending.extend((x,depth+1)for x in v)
        elif type(v)is str:
            charge(budget,work=len(v));bound+=12*len(v)+2
        elif type(v)is int:
            if v.bit_length()>64:raise ValueError('ABI_FACTORY_JSON_INTEGER_PROFILE')
            bound+=24
        elif v is None or type(v)is bool:bound+=5
        else:raise ValueError('ABI_FACTORY_JSON_TYPE')
    return bound,sort_work

def encoded_json(value,budget):
    if budget is None:return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'))
    bound,sort_work=json_bound(value,budget);charge(budget,work=bound+sort_work,copied_bytes=bound)
    out=json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'))
    if len(out)>bound:raise RuntimeError('ABI_FACTORY_JSON_COST_MODEL')
    return out

def collection(budget,count,comparison_width=1,copied_per_row=128):
    # Source-level conservative comparison model for one native collection pass.
    # This is intentionally quadratic: no adversarial hash O(1) assumption.
    charge(budget,work=(count+1)**2*(comparison_width+1),edges=count,copied_bytes=copied_per_row*(count+1))


def encoded_bytes(value,budget):
    text=encoded_json(value,budget)
    charge(budget,work=len(text),copied_bytes=len(text))
    return text.encode('ascii')

def check_budget(budget):
    if budget is not None:
        from record_layout.materialization import _api
        if type(budget) is not _api().SourceQueryBudget:raise ValueError('ABI_FACTORY_BUDGET_CLASS')

def copy_cost(value,budget):
    if budget is not None:
        bound,sorting=json_bound(value,budget);charge(budget,work=bound+sorting,copied_bytes=bound)

class ModelBudgetAdapter:
    def __init__(self,budget):check_budget(budget);self.budget=budget
    def work(self,n=1):charge(self.budget,work=n)
    def reserve(self,n):charge(self.budget,copied_bytes=n)
    def __deepcopy__(self,memo):return self


def row(value,budget):
    """Plain descriptor copy/scan cost, each actual row before consumption."""
    copy_cost(value,budget)

def flat_profile(document,budget):
    if budget is None:return
    copy_cost(document,budget)
    from layout import require
    require(len(document['types'])<=16 and len(document['layouts'])<=16 and len(document['signatures'])<=8,'ABI_FACTORY_COST_UNAVAILABLE')
    require(all(not document[k]for k in ('recipes','personalities','unwind','catches','bridges')),'ABI_FACTORY_COST_UNAVAILABLE')
    require(len(document['domains'])==1 and all(d['isa']==d['abi']==d['personality']=='portable'for d in document['domains']),'ABI_FACTORY_COST_UNAVAILABLE')
    items={t['id']:t for t in document['types']}
    for t in document['types']:
        charge(budget,work=1)
        require(t['kind']in('void','scalar','pointer','reference','function','record') and 0<=t['bits']<=128,'ABI_FACTORY_COST_UNAVAILABLE')
        require(len(t['elements'])<=17 and len(t['methods'])<=8 and not any(m['virtual']for m in t['methods']),'ABI_FACTORY_COST_UNAVAILABLE')
        require(t['identity']['entity']not in('rax.va_state','rax.jmp_state'),'ABI_FACTORY_COST_UNAVAILABLE')
        source=None if t['record_input']is None else t['record_input']['some']
        if source is not None:
            require(not source['bases'] and not source['dynamic'] and not source['polymorphic'] and len(source['fields'])<=8,'ABI_FACTORY_COST_UNAVAILABLE')
            require(source['explicit_align']is None or 0<source['explicit_align']['some']<=4096,'ABI_FACTORY_COST_UNAVAILABLE')
            for f in source['fields']:
                charge(budget,work=1)
                require(f['type']['module']['kind']=='self'and f['type']['id']in items and items[f['type']['id']]['kind']=='scalar'and not f['anonymous'],'ABI_FACTORY_COST_UNAVAILABLE')
                require(f['bit_width']is None or 0<=f['bit_width']['some']<=128,'ABI_FACTORY_COST_UNAVAILABLE')
                require(f['explicit_align']is None or 0<f['explicit_align']['some']<=4096,'ABI_FACTORY_COST_UNAVAILABLE')
    for l in document['layouts']:
        charge(budget,work=1)
        require(all(0<=l[k]<=4096 for k in('size','align','data_size','nonvirtual_size','nonvirtual_align'))and not l['bases']and not l['vptrs']and len(l['fields'])<=8,'ABI_FACTORY_COST_UNAVAILABLE')
        for f in l['fields']:
            charge(budget,work=1)
            require(0<=f['offset_bits']<=32768 and 0<=f['width_bits']<=32768 and f['offset_bits']+f['width_bits']<=l['size']*8,'ABI_FACTORY_COST_UNAVAILABLE')
    for plan in document['signatures']:
        charge(budget,work=1)
        require(len(plan['params'])<=16 and len(plan['lowered_params'])<=16 and len(plan['lowered_results'])<=8 and not plan['variadic']and plan['varargs']is None,'ABI_FACTORY_COST_UNAVAILABLE')
    require(len(document['journals'])<=4,'ABI_FACTORY_COST_UNAVAILABLE')
    for program in document['journals']:journal_cost(program,budget)
    require(len(document['storage_bindings'])<=64,'ABI_FACTORY_COST_UNAVAILABLE')

def journal_cost(program,budget):
    if budget is None:return
    from layout import require
    copy_cost(program,budget)
    slots=program['slots'];require(len(slots)<=64 and len(program['params'])<=16,'ABI_FACTORY_COST_UNAVAILABLE')
    for slot in slots:
        charge(budget,work=1)
        require(slot['parent']is None and slot['count_source']is None and slot['child_program']is None and not slot['covers']and not slot['dependencies'],'ABI_FACTORY_COST_UNAVAILABLE')
        require(all(0<=slot[k]<=4096 for k in('offset','extent','stride','align'))and 0<=slot['count']<=1024 and slot['count']*slot['stride']<=4096,'ABI_FACTORY_COST_UNAVAILABLE')
    collection(budget,len(slots))
    charge(budget,work=4*(len(slots)+1),edges=4*len(slots),copied_bytes=256*(len(slots)+1))
    for name in('normal_order','exception_order'):
        collection(budget,len(program[name]));collection(budget,len(program[name]))

def binding_cost(binding,graph,budget):
    if budget is None:return
    from layout import require
    copy_cost(binding,budget)
    l=graph.layout(binding['nominal']);size=l['size']
    require(0<=size<=4096 and 0<=binding['view_offset_bits']<=32768 and 0<=binding['view_width_bits']<=32768 and 0<=binding['access_bytes']<=4096 and len(binding['fragments'])<=64,'ABI_FACTORY_COST_UNAVAILABLE')
    for f in binding['fragments']:
        charge(budget,work=1)
        require(len(f['source_path'])<=16 and all(0<=f[k]<=32768 for k in('source_offset_bits','execution_offset_bits','width_bits')),'ABI_FACTORY_COST_UNAVAILABLE')
        current=binding['nominal']
        for name in f['source_path']:
            selected=graph.layout(current);collection(budget,len(selected['fields']),len(name)+1)
            matches=[field for field in selected['fields']if field['name']==name]
            require(len(matches)==1,'ABI_CC_STORAGE_SOURCE_PATH');current=matches[0]['type']
    charge(budget,work=8*(len(binding['fragments'])+4)*(size*8+1),copied_bytes=8*(len(binding['fragments'])+4)*(size+32))

def model_row(model_budget,value):
    if type(model_budget)is ModelBudgetAdapter:
        b=model_budget.budget
        bound,sorting=json_bound(value,b)
        charge(b,work=bound+sorting,copied_bytes=bound)
        # Each direct vector in this flat source/selected descriptor is consumed
        # by native field/flag/name collections in the real checked adapter.
        for child in value.values():
            charge(b,work=1)
            if type(child)is list:collection(b,len(child),bound)
            elif type(child)is dict and set(child)=={'some'} and type(child['some'])is dict:
                for nested in child['some'].values():
                    charge(b,work=1)
                    if type(nested)is list:collection(b,len(nested),bound)
