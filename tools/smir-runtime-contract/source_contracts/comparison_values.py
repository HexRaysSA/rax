"""Metered original-v3 plain-value comparison; no admission certificate."""
from . import checker as C

def same(left,right,*,budget):
    C.need(type(budget)is C.source_api().SourceQueryBudget,'ASC_BUDGET_CLASS')
    budget.charge(work=1,edges=1,copied_bytes=64);pending=[(left,right,0)];nodes=0
    while pending:
        budget.charge(work=4,edges=1,copied_bytes=64);a,b,depth=pending.pop();nodes+=1
        C.need(depth<=64 and nodes<=16384,'SCV_VALUE_PROFILE')
        if type(a)is not type(b):return False
        t=type(a)
        if t is dict:
            if len(a)!=len(b):return False
            maximum=0
            for source in(a,b):
                for key in source:
                    C.need(type(key)is str,'SCV_VALUE_PROFILE');budget.charge(work=4*(len(key)+1));maximum=max(maximum,len(key))
            n=len(a);budget.charge(work=8*(n+1)**2*(maximum+1),edges=n,copied_bytes=128*(n+1))
            for key in a:
                if key not in b:return False
                pending.append((a[key],b[key],depth+1))
        elif t is list:
            if len(a)!=len(b):return False
            n=len(a);budget.charge(work=4*(n+1),edges=n,copied_bytes=128*(n+1))
            for i in range(n-1,-1,-1):pending.append((a[i],b[i],depth+1))
        elif t in(str,bytes):
            budget.charge(work=4*(len(a)+len(b)+1))
            if a!=b:return False
        elif t is int:
            budget.charge(work=4+(a.bit_length()+b.bit_length()+7)//8)
            if a!=b:return False
        elif t is bool:
            if a is not b:return False
        elif a is not None:C.need(False,'SCV_VALUE_PROFILE')
    return True

def root2_view(root,*,budget):
    C.need(type(root)is dict and type(root.get('manifest'))is dict,'SCV_VALUE_PROFILE')
    n=len(root)+len(root['manifest']);budget.charge(work=8*(n+1),edges=n,copied_bytes=256*(n+1))
    out=dict(root);out['manifest']=dict(root['manifest']);out['manifest'].pop('identity');return out

def before_alpha(document,*,budget):
    from factory_meter import json_bound,collection
    bound,_=json_bound(document,budget)
    budget.charge(work=16*(bound+1),copied_bytes=8*(bound+1))
    for rows in document['contract'].values():
        if type(rows)is list:collection(budget,len(rows),65)

def encoded(document,*,budget):
    from factory_meter import encoded_json
    return encoded_json(document,budget)

def has_observers(functions, *, budget):
    from factory_meter import collection
    collection(budget,len(functions),65)
    for fn in functions:
        collection(budget,len(fn['blocks']),65)
        for block in fn['blocks']:
            collection(budget,len(block['ops']),65)
            if any(op['op']=='source_journal_observe'for op in block['ops']):return True
    return False


def observer_functions(functions, mapping, *, budget):
    """Copy complete real bodies, jointly rename only the two private fields."""
    from copy import deepcopy
    from factory_meter import copy_cost,collection
    copy_cost(functions,budget)
    out=deepcopy(functions)
    collection(budget,len(out),65)
    for fn in out:
        collection(budget,len(fn['blocks']),65)
        for block in fn['blocks']:
            collection(budget,len(block['ops']),65)
            for op in block['ops']:
                if op['op']=='source_journal_observe':
                    budget.charge(work=16*(len(mapping)+1)*66,copied_bytes=256)
                    for field,namespace in(('scope_value','scope_values'),('adoption','adoptions')):
                        key=(namespace,fn['id'],op[field])
                        C.need(key in mapping,'ASC_OBSERVER_ALPHA_NAMESPACE')
                        op[field]=mapping[key]
    return out
