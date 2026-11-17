"""Build genuine published-sret CFG diamonds, retain raw roots for real factories."""
from copy import deepcopy
from reference_grounding import fixture,RootContext,ground
from function_address.fixtures import seal

def diamond(missing=False):
    owner,request,budget=fixture()
    roots=deepcopy(owner.sections);f=roots[3]['functions'][0];block=f['blocks'][0]
    boolean=max(t['id'] for t in roots[1]['types'])+1
    roots[1]['types'].append(dict(id=boolean,kind='int',bits=1))
    q=lambda n:dict(module=dict(kind='self'),id=n)
    block['ops'].append(dict(op='icmp',predicate='eq',results=[dict(id=30,type=q(boolean))],operands=[21,21]))
    block['term']=dict(op='cbranch',condition=30,true=1,false=2)
    f['blocks'] += [dict(id=i,phis=[],ops=[],term=dict(op='return',values=[]))for i in (1,2)]
    c=request['carrier']['contract'];exit=c['exits'][0];exit['site']['block']=1;c['phase_sites'][2]['site']['block']=1
    if not missing:
        second=deepcopy(exit);second['id']=1;second['site']['block']=2;c['exits'].append(second)
        phase=deepcopy(c['phase_sites'][2]);phase['id']=3;phase['site']['block']=2;phase['event']['exit']=1;c['phase_sites'].append(phase)
        returned=deepcopy(c['returns'][0]);returned.update(id=1,exit=1);c['returns'].append(returned)
    seal(roots);owner=RootContext(roots);stamp=owner.prepare_source_data(budget=budget)
    ctx=request['source_join']['contexts'][0];ctx['roots']=[dict(section=n,digest=h.hex())for n,h in stamp.root_digests]
    for ctx in request['abi_programs']['contexts']:
        ctx['abi_root']=dict(stamp.root_digests)[10].hex();ctx['module_root']=dict(stamp.root_digests)[2].hex()
    return owner,request,budget

if __name__=='__main__':
    o,d,b=diamond();print(ground(o,d,budget=b))

def refreshed(roots,request,budget):
    seal(roots);owner=RootContext(roots);stamp=owner.prepare_source_data(budget=budget)
    request['source_join']['contexts'][0]['roots']=[dict(section=n,digest=h.hex())for n,h in stamp.root_digests]
    request['source_join']['contexts'][0]['schema_digest']=stamp.schema_digest.hex()
    for context in request['abi_programs']['contexts']:
        context['abi_root']=dict(stamp.root_digests)[10].hex();context['module_root']=dict(stamp.root_digests)[2].hex()
    return owner,request,budget

def merged_phi():
    owner,request,budget=diamond()
    roots=deepcopy(owner.sections);f=roots[3]['functions'][0]
    for block in f['blocks'][1:]:block['term']=dict(op='jump',target=3)
    f['blocks'].append(dict(id=3,phis=[],ops=[],term=dict(op='return',values=[])))
    c=request['carrier']['contract'];c['exits']=c['exits'][:1];c['returns']=c['returns'][:1];c['phase_sites']=c['phase_sites'][:3]
    c['exits'][0]['site']['block']=3;c['exits'][0]['scope_value']=101;c['phase_sites'][2]['site']['block']=3;c['phase_sites'][2]['within']['value']=101
    c['scope_values'].append(dict(id=101,function=0,origin=dict(kind='phi',block=3,incoming=[dict(predecessor=i,value=100)for i in (1,2)])))
    return refreshed(roots,request,budget)

def looping(missing_close=False):
    owner,request,budget=diamond()
    roots=deepcopy(owner.sections);f=roots[3]['functions'][0];body=f['blocks'][0];body['id']=1;body['term'].update(true=1,false=2)
    f['blocks']=[dict(id=0,phis=[],ops=[],term=dict(op='jump',target=1)),body,dict(id=2,phis=[],ops=[],term=dict(op='return',values=[]))]
    c=request['carrier']['contract'];c['exits']=c['exits'][:1];c['returns']=[];c['phase_sites']=c['phase_sites'][:3]
    c['scopes'][0]['enter']['block']=1
    for phase in c['phase_sites'][:2]:phase['site']['block']=1
    site=dict(kind='pre_terminator',block=1);c['exits'][0]['site']=deepcopy(site);c['phase_sites'][2]['site']=deepcopy(site)
    if missing_close:
        c['exits']=[];c['phase_sites']=c['phase_sites'][:2]
    return refreshed(roots,request,budget)
