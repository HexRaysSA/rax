"""Typed portable module lookup against actual selected definitions, R021/R034.

Trusted issue callback pins process/module/code/object generation and returns an
actual issued pointer value. This resolver cannot manufacture pointer authority.
"""
from .errors import option, require
from .linking import self_ref


def resolve(modules, contexts, plan, artifact, namespace, name, *, requester, descriptor,
            function, signature_compatible, nominal_compatible, issue, data_compatible=None,
            address_compatible=None):
    require(artifact in modules and artifact in contexts and requester in contexts, 'RT_LOOKUP_MODULE')
    candidates=[]
    table={s['id']:s for s in modules[artifact][2]['symbols']}
    for exported in modules[artifact][2]['manifest']['exports']:
        if (exported['namespace'],exported['name'])!=(namespace,name):continue
        if function and exported['kind']=='function':candidates.append(('function',exported['target']['id']))
        elif exported['kind']=='symbol':
            symbol=table[exported['target']['id']]
            if (function and symbol['kind'] in {'function','import'}) or (not function and symbol['kind'] in {'data','tls'}):
                candidates.append(('symbol',symbol['id']))
    require(len(candidates)==1,'RT_LOOKUP_NOT_FOUND' if not candidates else 'RT_LOOKUP_AMBIGUOUS')
    kind,identity=candidates[0]
    if kind=='function':
        target=plan.functions.get((artifact,identity),(artifact,identity))
        require(target is not None,'RT_SELECTION_DISCARDED_FUNCTION')
        owner,identity=target;context=contexts[owner]
        body=context.function({'module':{'kind':'self'},'id':identity})
        actual=option(body['abi_signature'])
        require(actual is not None and self_ref(actual),'RT_LOOKUP_SOURCE_PLAN')
        require(signature_compatible(requester,descriptor,owner,actual),'RT_LOOKUP_SIGNATURE')
        return issue(owner,'function',identity,actual)
    owner,identity=plan.symbol(artifact,identity)
    symbol=next(s for s in modules[owner][2]['symbols'] if s['id']==identity)
    definition=option(symbol['definition'])
    require(definition is not None and definition['kind']!='native','RT_NATIVE_PORTABLE_TOKEN')
    if function:
        actual=option(symbol['abi_signature'])
        require(actual is not None and self_ref(actual),'RT_LOOKUP_SOURCE_PLAN')
        require(signature_compatible(requester,descriptor,owner,actual),'RT_LOOKUP_SIGNATURE')
        return issue(owner,'symbol',identity,actual)
    actual=option(symbol['nominal'])
    require(actual is not None,'RT_LOOKUP_SOURCE_TYPE')
    requested=contexts[requester].nominal(descriptor)
    compare=nominal_compatible
    if symbol['source_linkage']=='c':
        require(data_compatible is not None,'RT_LOOKUP_C_DATA_COMPARATOR')
        compare=data_compatible
    elif 'complete' not in requested['flags']:
        require(address_compatible is not None,'RT_LOOKUP_ADDRESS_COMPARATOR')
        compare=address_compatible
    require(compare(requester,descriptor,owner,actual),'RT_LOOKUP_NOMINAL')
    return issue(owner,symbol['kind'],identity,actual)
