"""Actual quotient algorithm with optional canonical logical meter."""
from factory_meter import *
def canonical_quotient(labels,edges,root,*,budget=None):
    b=budget;check_budget(b);n=len(labels);collection(b,n);encoded={key:encoded_json(label,b)for key,label in labels.items()}
    longest=max((len(v)for v in encoded.values()),default=0)
    collection(b,n,longest);names={label:index for index,label in enumerate(sorted(set(encoded.values())))}
    collection(b,n);colors={key:names[label]for key,label in encoded.items()}
    rounds=0
    while True:
        rounds+=1
        if budget is not None and rounds>n:raise RuntimeError('ABI_FACTORY_REFINEMENT_ROUND_BOUND')
        collection(b,n)
        edge_count=0;maximum=0
        for key in labels:
            charge(b,work=n+1);degree=len(edges[key]);edge_count+=degree;maximum=max(maximum,degree)
        charge(b,work=edge_count,edges=edge_count,copied_bytes=64*edge_count)
        signatures={key:(encoded[key],tuple(colors[child]for child in edges[key]))for key in labels}
        collection(b,n,longest+maximum)
        names={signature:index for index,signature in enumerate(sorted(set(signatures.values())))}
        collection(b,n,longest+maximum);updated={key:names[value]for key,value in signatures.items()}
        collection(b,n);collection(b,n);stable=len(set(updated.values()))==len(set(colors.values()));colors=updated
        if stable:break
    collection(b,n);representatives={}
    for key in labels:representatives.setdefault(colors[key],key)
    charge(b,work=n+1,copied_bytes=128*(n+1));order=[colors[root]];indices={colors[root]:0};records=[]
    for color in order:
        charge(b,work=2*(n+1));key=representatives[color];degree=len(edges[key]);charge(b,work=4*(n+1)*(degree+1),edges=degree,copied_bytes=128*(degree+1));children=[]
        for child in edges[key]:
            target=colors[child]
            if target not in indices:indices[target]=len(order);order.append(target)
            children.append(indices[target])
        records.append({'label':labels[key],'children':children})
    return encoded_bytes(records,b)
