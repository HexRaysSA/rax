"""Regenerate ABI-owned source fixtures after explicit ABI3 migration release.

Known record declarations come from the source-authored builder. No unknown AST
input is inferred from selected field offsets or old envelope bytes.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from candidate_fixtures import build, seal
from c_interop_fixtures import build_pair

ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'docs/specifications/smir/portable/conformance/abi/candidate'


def generate():
    doc,evidence=build()
    c,cpp,interop,ids=build_pair()
    values={'complete':doc,'evidence':evidence,'c-provider':c,'cpp-consumer':cpp,
            'c-interop-evidence':interop,'c-interop-ids':ids}
    # Preserve historical origin and the precise old CFI counter's non-record
    # declarations; source inputs for the only two known records are authored in
    # candidate_fixtures, with checked same child source identities.
    path=OUT/'reject-portable-native-cfi.json'
    counter=json.loads(path.read_text())
    declarations={t['identity']['entity']:t for t in doc['types'] if t['kind']=='record' and t['domain']==0}
    for typ in counter['abi']['types']:
        typ['record_input']=None
        if typ['kind']=='record':
            source=declarations[typ['identity']['entity']]
            for field in source['record_input']['some']['fields']:
                identifier=field['type']['id']
                expected=next(t for t in doc['types'] if t['id']==identifier)['identity']['entity']
                actual=next(t for t in counter['abi']['types'] if t['id']==identifier)['identity']['entity']
                if actual!=expected:raise ValueError('CFI_SOURCE_DECLARATION_MISMATCH')
            typ['record_input']=deepcopy(source['record_input'])
    # These exact source plans are authored by build(), not invented by a wire
    # decoder or inferred from the optional Function.execution association.
    plans={plan['id']:plan for plan in doc['signatures']}
    for plan in counter['abi']['signatures']:
        if plan['id']==500:
            # Exact fixture-authored logical personality interface; its actual
            # execution graph separately contains this closed Fn500 record.
            if plan['function_type']!={'module':{'kind':'self'},'id':500}:
                raise ValueError('CFI_PERSONALITY_SOURCE_PLAN')
            plan['execution']={'module':{'kind':'self'},'id':500}
            continue
        source=plans[plan['id']]
        if plan['function_type']!=source['function_type']:
            raise ValueError('CFI_SOURCE_PLAN_MISMATCH')
        plan['execution']=deepcopy(source['execution'])
    for typ in counter['abi']['types']:
        if typ['kind']=='function':
            source=next((item for item in doc['types'] if item['id']==typ['id']),None)
            if source is None:
                # The explicitly authored logical personality prototype is not
                # an ordinary callable default. Its source interface remains.
                if typ['id']!=500:raise ValueError('CFI_UNKNOWN_SOURCE_PROTOTYPE')
                typ.update(execution=None,representation='none')
            else:
                typ['execution']=deepcopy(source['execution'])
                typ['representation']=source['representation']
    counter['abi']['payload_revision']=3
    for layout in counter['abi']['layouts']:
        for index,field in enumerate(layout['fields']):field['declaration_index']=index
        if layout['bases'] or layout['vptrs']:raise ValueError('CFI_UNEXPECTED_SOURCE_HIERARCHY')
    seal(counter['abi'])
    counter['abi3_migration']={'source':'source-authored candidate_fixtures.build known declarations and plans',
                              'historical_origin_retained':True,'payload_revision':3}
    values['reject-portable-native-cfi']=counter
    for name,value in values.items():
        (OUT/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
    return {name:hashlib.sha256((OUT/(name+'.json')).read_bytes()).hexdigest() for name in values}


if __name__=='__main__':print(json.dumps(generate(),indent=2))
