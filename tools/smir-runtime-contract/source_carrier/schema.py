"""Reproduce the allocated experimental structural carrier record document."""
from pathlib import Path
from copy import deepcopy
import hashlib,json,re
PROJECT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SOURCE=PROJECT/'docs/specifications/smir/portable/schema/runtime/source_contracts.json'
RAW=json.loads(SOURCE.read_bytes())
BASE={}
for name in ('execution','runtime','abi'):
    document=json.loads((PROJECT/'docs/specifications/smir/portable/schema'/name/'candidate.json').read_bytes())
    for key,value in document['records'].items():
        if key in BASE and BASE[key]!=value:raise ValueError('conflicting existing record '+key)
        BASE[key]=value
RECORDS=deepcopy(BASE);CAPS={};SCALAR_RULES={};SOURCE_RULES={}
def deref(rule):
    while '$ref'in rule:rule=RAW['$defs'][rule['$ref'].split('/')[-1]]
    return rule

def kind(rule,name):
    if '$ref'in rule:
        label=rule['$ref'].split('/')[-1]
        return kind(deref(rule),'sc_'+label)
    rule=deref(rule)
    if 'anyOf'in rule:
        arms=rule['anyOf'];nonnull=[x for x in arms if x.get('type')!='null']
        if len(arms)==2 and len(nonnull)==1:return 'opt:'+kind(nonnull[0],name+'_some')
        if name not in RECORDS:
            RECORDS[name]={'discriminator':'kind','variants':{}}
            SOURCE_RULES[name]=rule
            for arm in arms:
                tag=arm['properties']['kind']['const']
                RECORDS[name]['variants'][tag]=fields(arm,name+'.'+tag,skip='kind')
        return name
    value_type=rule.get('type')
    if value_type=='object':
        if name not in RECORDS:
            RECORDS[name]={'fields':[]};SOURCE_RULES[name]=rule
            RECORDS[name]['fields']=fields(rule,name)
        return name
    if value_type=='array':return 'vec:'+kind(rule['items'],name+'_item')
    if value_type=='integer'or type(rule.get('const'))is int:
        return 'u64'if rule.get('maximum',0)>2**32-1 else'u32'
    if value_type=='boolean':return 'bool'
    values=rule.get('enum',[rule.get('const')])
    if values and all(type(x)is str for x in values):
        return 'token'if all(re.fullmatch('[a-z][a-z0-9_]{0,62}',x)for x in values)else'utf8'
    raise ValueError(('unrepresented source rule',name,rule))

def constraints(rule,path):
    rule=deref(rule)
    if 'anyOf'in rule:
        nonnull=[r for r in rule['anyOf']if r.get('type')!='null']
        if len(rule['anyOf'])==2 and len(nonnull)==1:constraints(nonnull[0],path)
    elif rule.get('type')=='array':
        CAPS[path]=dict(maximum=rule['maxItems'],minimum=rule.get('minItems',0))
        constraints(rule['items'],path+'[]')
    elif rule.get('type')in('integer','boolean','string')or'const'in rule or'enum'in rule:
        SCALAR_RULES[path]=rule

def fields(rule,name,skip=None):
    if set(rule['properties'])!=set(rule['required'])or rule['additionalProperties']is not False:raise ValueError('open source rule')
    output=[]
    for field,child in rule['properties'].items():
        if field==skip:continue
        resolved=deref(child);path=name+'.'+field
        output.append([field,kind(child,name+'_'+field)])
        if resolved.get('type')=='array':CAPS[path]=dict(maximum=resolved['maxItems'],minimum=resolved.get('minItems',0))
        SCALAR_RULES[path]=resolved
        constraints(child,path)
    return output

CONTRACT=kind(RAW['$defs']['contract'],'sc_contract')
RECORDS['operation_v3']=deepcopy(BASE['operation'])
RECORDS['operation_v3']['variants']['source_journal_observe']=[['results','vec:decl'],['operands','vec:u32'],['scope_value','u32'],['adoption','u32']]
CAPS['operation_v3.source_journal_observe.results']=dict(minimum=1,maximum=1)
CAPS['operation_v3.source_journal_observe.operands']=dict(minimum=0,maximum=0)
for name in ('scope_value','adoption'):SCALAR_RULES['operation_v3.source_journal_observe.'+name]=dict(type='integer',minimum=0,maximum=2**32-2)
RECORDS['block_v3']=deepcopy(BASE['block'])
RECORDS['block_v3']['fields']=[[n,'vec:operation_v3'if n=='ops'else k]for n,k in RECORDS['block_v3']['fields']]
RECORDS['function_v3']=deepcopy(BASE['function'])
RECORDS['function_v3']['fields']=[[n,'vec:block_v3'if n=='blocks'else k]for n,k in RECORDS['function_v3']['fields']]
RECORDS['execution_functions_v3']={'fields':[['payload_revision','u32'],['functions','vec:function_v3'],['source_contract',CONTRACT]]}
DOCUMENT=dict(format='portable-source-carrier-records',revision=2,proposed_payload_revision=3,registry_status='assigned-experimental-reference',records=RECORDS,field_caps=CAPS,source_scalar_rules=SCALAR_RULES,source_schema_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),notes=['Wire options are canonical null/{some:value}; explicit bijection adapts the current raw conditional carrier direct options.','Union discriminants are existing token strings, no numeric opcode/tag assigned. Lifecycle C1/C2/D0/D1/D2 scalar uses utf8 because existing token is lowercase-only.','Root3v2 grammar unchanged; v3 adds source_contract last and a symbolic observer operation; structural decode grants no admission.'])
def main():
    import sys
    raw=(json.dumps(DOCUMENT,indent=2)+'\n').encode();target=PROJECT/'docs/specifications/smir/portable/schema/runtime/source_carrier_records.json'
    if '--check'in sys.argv:
        if target.read_bytes()!=raw:raise SystemExit('grammar drift')
    else:target.write_bytes(raw)
    print(len(RECORDS),'records',len(CAPS),'fieldcaps',hashlib.sha256(raw).hexdigest())
if __name__=='__main__':main()
