#!/usr/bin/env python3
"""Candidate record and local semantic fixtures; never executable admission."""
from collections import Counter
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
if 'runtime_candidate' not in sys.modules:
    spec=importlib.util.spec_from_file_location('runtime_candidate',HERE/'candidate/__init__.py',
                                               submodule_search_locations=[str(HERE/'candidate')])
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
from runtime_candidate import comdat, fenv, linking, relocations, requirements, services, startup
from runtime_candidate.errors import Reject, require
from runtime_candidate.wire import decode, encode

CORPUS=HERE.parents[1]/'docs/specifications/smir/portable/conformance/runtime/candidate'


def verify(case):
    surface,doc=case['surface'],case['document']
    if surface=='wire':
        if 'encoded' in doc:return decode(doc['record'],bytes.fromhex(doc['encoded']))
        return decode(doc['record'],encode(doc['record'],doc['value']))
    if surface=='runtime_roots':
        def absent(*args):raise Reject('FIXTURE_UNEXPECTED_METADATA')
        context=linking.Context(doc['site'],*[absent]*9,grants=frozenset(doc['grants']))
        return linking.validate({int(k):v for k,v in doc['roots'].items()},context)
    if surface=='fenv':
        state=fenv.Fenv();state.set_word(doc['word']);return state.word()
    if surface=='relocation_step':return relocations.validate_step(doc)
    if surface=='requirements':
        registry=requirements.Registry(tuple(tuple(v) for v in doc['registered']))
        return requirements.validate(doc['requirements'],registry.supports)
    if surface=='startup':return startup.build(doc['name'],doc['arguments'],doc['environment'],base=doc['base'])
    if surface=='errno':
        return (services.to_personality(doc['domain'],doc['status']) if 'status' in doc else
                services.from_personality(doc['domain'],doc['native']))
    if surface=='structure':return services.structure(doc['name'],bytes.fromhex(doc['bytes']))
    if surface=='comdat':
        groups=[]
        for group in doc:
            groups.append({**group,'members':[{**m,'body':bytes.fromhex(m['body'])} for m in group['members']]})
        return comdat.select(groups)
    raise Reject('FIXTURE_SURFACE',surface)


def check():
    counts=Counter()
    paths=sorted(CORPUS.glob('*.json'))
    require(paths,'FIXTURE_EMPTY')
    for path in paths:
        case=json.loads(path.read_text())
        try:verify(case)
        except Reject as error:
            require(not case['accept'],'FIXTURE_UNEXPECTED_REJECTION',f'{path.name}: {error}')
            require(error.code==case['code'],'FIXTURE_DIAGNOSTIC',f'{path.name}: {error.code} != {case["code"]}')
            counts[case['surface'],'reject']+=1
        else:
            require(case['accept'],'FIXTURE_UNEXPECTED_ACCEPTANCE',path.name)
            counts[case['surface'],'accept']+=1
    return counts


if __name__=='__main__':
    counts=check()
    print(json.dumps({'cases':sum(counts.values()),'accept':sum(v for (s,k),v in counts.items() if k=='accept'),
                      'reject':sum(v for (s,k),v in counts.items() if k=='reject'),
                      'by_surface':{f'{s}/{k}':v for (s,k),v in sorted(counts.items())},
                      'scope':'ordered records and local semantic protocols, not ten-root executable admission'},indent=2))
