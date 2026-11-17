"""Exact explicit nullable-carrier/wire-option bijection."""
import hashlib,json
from .bindings import PROJECT,check_budget
from .errors import need
def source_schema(budget):
    path=PROJECT/'docs/specifications/smir/portable/schema/runtime/source_contracts.json'
    size=path.stat().st_size;need(size<=2**20,'V3_SOURCE_SCHEMA_BOUND')
    budget.charge(work=8*(size+1),edges=size+1,copied_bytes=16*(size+1))
    with path.open('rb')as stream:raw=stream.read(size+1)
    need(len(raw)==size and hashlib.sha256(raw).hexdigest()=='6cc14282b8f3f8c0113cb9e4d965b320cd4269d6a30c57cd8e88068e27de6654','V3_SOURCE_SCHEMA_IDENTITY')
    return json.loads(raw)

def adapt(rule,value,budget,*,raw_schema,to_wire,depth=0):
    while '$ref'in rule:rule=raw_schema['$defs'][rule['$ref'].split('/')[-1]]
    budget.charge(work=2,edges=1,copied_bytes=64);need(depth<=min(64,budget.max_depth),'V3_RESOURCE')
    if 'anyOf'in rule:
        arms=rule['anyOf'];nonnull=[x for x in arms if x.get('type')!='null']
        if len(arms)==2 and len(nonnull)==1:
            if value is None:return None
            if to_wire:return {'some':adapt(nonnull[0],value,budget,raw_schema=raw_schema,to_wire=True,depth=depth+1)}
            need(type(value)is dict and set(value)=={'some'},'V3_OPTION')
            return adapt(nonnull[0],value['some'],budget,raw_schema=raw_schema,to_wire=False,depth=depth+1)
        need(type(value)is dict and type(value.get('kind'))is str,'V3_TAG')
        selected=[a for a in arms if a['properties']['kind']['const']==value['kind']];need(len(selected)==1,'V3_TAG')
        return adapt(selected[0],value,budget,raw_schema=raw_schema,to_wire=to_wire,depth=depth+1)
    kind=rule.get('type')
    if kind=='object':
        need(type(value)is dict and len(value)==len(rule['required'])and set(value)==set(rule['required']),'V3_FIELDS')
        return {name:adapt(child,value[name],budget,raw_schema=raw_schema,to_wire=to_wire,depth=depth+1)for name,child in rule['properties'].items()}
    if kind=='array':
        need(type(value)is list and len(value)<=rule['maxItems'],'V3_COUNT')
        budget.charge(work=len(value),edges=len(value),copied_bytes=8*len(value))
        return [adapt(rule['items'],x,budget,raw_schema=raw_schema,to_wire=to_wire,depth=depth+1)for x in value]
    if 'const'in rule:need(type(value)is type(rule['const'])and value==rule['const'],'V3_CONSTANT')
    if 'enum'in rule:need(any(type(value)is type(x)and value==x for x in rule['enum']),'V3_ENUM')
    if kind=='integer':need(type(value)is int and rule['minimum']<=value<=rule['maximum'],'V3_INTEGER')
    if kind=='boolean':need(type(value)is bool,'V3_TYPE')
    return value

def wire_contract(raw,*,budget):
    check_budget(budget)
    raw_schema=source_schema(budget)
    return adapt(raw_schema['$defs']['contract'],raw,budget,raw_schema=raw_schema,to_wire=True)
def raw_contract(wire,*,budget):
    check_budget(budget)
    raw_schema=source_schema(budget)
    return adapt(raw_schema['$defs']['contract'],wire,budget,raw_schema=raw_schema,to_wire=False)
