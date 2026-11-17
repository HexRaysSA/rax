#!/usr/bin/env python3
"""Independent ordinary C23/C++23 scalar source objects and static oracles.

No production issuer, execution permit or runtime entry is synthesized here.
Case generation costs O(total serialized bytes), excluding genuine validators'
bounded graph/fingerprint costs. Source records never derive from host C types.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import metadata_manifest_cases as original

ROOT = original.ROOT
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/ordinary-scalar'
SEED = ROOT / 'docs/specifications/smir/portable/conformance/llvm/generic-functions/seed.source.json'
ref, some = original.ref, original.some
SCALARS = (
    ('signed char', 8, True), ('unsigned char', 8, False),
    ('short', 16, True), ('unsigned short', 16, False),
    ('int', 32, True), ('unsigned int', 32, False),
    ('long', 64, True), ('unsigned long', 64, False),
    ('long long', 64, True), ('unsigned long long', 64, False))
EXECUTION = {8: 2, 16: 600, 32: 17, 64: 18}


def seal(roots):
    # Use only the genuine canonical fingerprint algorithm, not its case builder.
    program = ('import json,sys;sys.path.insert(0,sys.argv[1]);'
               'from candidate_fixtures import seal;print(json.dumps(seal(json.load(sys.stdin))))')
    result = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT / 'tools/smir-abi')],
        input=json.dumps(roots[10]), text=True, capture_output=True, check=True)
    roots[10] = json.loads(result.stdout)
    return roots


def source(params=(4,), result=4, *, language='cpp23', linkage='cpp', default=True):
    roots = {int(k): v for k, v in json.loads(SEED.read_text())['sections'].items()}
    roots[2]['manifest']['identity'] = '00' * 32
    # Independently restrict the actual execution graph to the needed integers
    # and a structural I32 alias; no inherited pointer/code-pointer default.
    roots[1]['types'] = [dict(kind='int', id=i, bits=b) for i, b in
                         ((1, 32), (2, 8), (17, 32), (18, 64), (600, 16))]
    physical_params = [EXECUTION[SCALARS[i][1]] for i in params]
    physical_results = [] if result is None else [EXECUTION[SCALARS[result][1]]]
    roots[1]['types'].append(dict(kind='function', id=300, params=[ref(t) for t in physical_params],
        results=[ref(t) for t in physical_results], cc='portable', variadic=False,
        param_noundef=[True] * len(params), result_noundef=[True] * len(physical_results)))
    roots[1]['types'].sort(key=lambda t: t['id'])
    roots[1]['memory_layouts'] = [dict(id=i, type=ref(EXECUTION[b]), size=b // 8,
        alignment=b // 8, access_bytes=b // 8, fields=[], element=None, stride=0)
        for i, b in enumerate((8, 16, 32, 64))]
    template = copy.deepcopy(roots[10]['types'][0])
    nominals, layouts = [], []
    for i, (entity, bits, signed) in enumerate(SCALARS):
        nominal = copy.deepcopy(template)
        nominal.update(id=i + 1, bits=bits, signed=signed, execution=some(EXECUTION[bits]),
                       layout={'some': i + 1})
        nominal['identity'].update(language=language, entity=entity)
        nominals.append(nominal)
        layouts.append(dict(id=i + 1, type=ref(i + 1), size=bits // 8, align=bits // 8,
            data_size=bits // 8, nonvirtual_size=bits // 8, nonvirtual_align=bits // 8,
            fields=[], bases=[], vptrs=[]))
    void = copy.deepcopy(template)
    void.update(id=20, kind='void', bits=0, signed=False, execution=None, layout=None,
                representation='none')
    void['identity'].update(language=language, entity='void')
    function = copy.deepcopy(roots[10]['types'][1])
    function.update(id=100, elements=[ref(i + 1) for i in params] + [ref(20 if result is None else result + 1)],
        extent={'some': len(params)}, execution=some(300) if default else None,
        representation='signature' if default else 'none',
        flags=['c_linkage', 'complete'] if linkage == 'c' else ['complete'])
    function['identity'].update(language=language)
    roots[10].update(types=nominals + [void, function], layouts=layouts)
    plan = roots[10]['signatures'][0]
    plan.update(function_type=ref(100), params=[ref(i + 1) for i in params],
        result=None if result is None else some(result + 1),
        lowered_params=[dict(source_index={'some': n}, role='parameter',
            source_type=ref(i + 1), value_type=ref(i + 1), mode='direct',
            align=SCALARS[i][1] // 8, bytes=SCALARS[i][1] // 8, noundef=True,
            copy=None, move=None, destroy=None) for n, i in enumerate(params)],
        lowered_results=[] if result is None else [ref(result + 1)], execution=ref(300))
    body = copy.deepcopy(roots[3]['functions'][0])
    body.update(signature=ref(300), abi_signature=some(0),
        params=[dict(id=n, type=ref(t)) for n, t in enumerate(physical_params)])
    ops, returned = [], []
    if result is not None:
        matches = [n for n, t in enumerate(physical_params) if t == physical_results[0]]
        if matches:
            returned = [matches[0]]
        else:
            ops = [dict(op='constant', results=[dict(id=len(params), type=ref(physical_results[0]))],
                        operands=[], literal=dict(kind='bits', value='00' * (SCALARS[result][1] // 8)))]
            returned = [len(params)]
    body['blocks'] = [dict(id=0, phis=[], ops=ops, term=dict(op='return', values=returned))]
    roots[3]['functions'] = [body]
    roots[2]['symbols'][0].update(execution=ref(300), source_linkage=linkage,
                                 nominal=some(100), abi_signature=some(0))
    return roots


def nominal(roots, identifier):
    return next(t for t in roots[10]['types'] if t['id'] == identifier)


def fullfn(roots):
    return next(t for t in roots[1]['types'] if t['id'] == 300)


def cases():
    result = {}
    def add(name, params=(4,), returned=4, mutate=lambda r: None, **kwargs):
        roots = source(params, returned, **kwargs)
        mutate(roots)
        result[name] = seal(roots)
    for language, linkage in (('c23', 'c'), ('cpp23', 'cpp')):
        for i, (entity, _, _) in enumerate(SCALARS):
            add(linkage + '-' + entity.replace(' ', '-'), (i,), i, language=language, linkage=linkage)
    add('zero-void', (), None)
    add('zero-unsigned-long-long', (), 9)
    add('mixed-void', (0, 3, 4, 7, 8), None)
    add('mixed-signed-return', (1, 2, 6, 9), 6)
    add('mixed-unsigned-return', (0, 3, 6, 9), 9)
    add('no-source-default', (6,), 6, default=False)
    add('structural-execution-alias', mutate=lambda r: r[2]['symbols'][0].update(execution=ref(301)))
    alias = result.pop('structural-execution-alias')
    typ = copy.deepcopy(fullfn(alias)); typ.update(id=301, params=[ref(1)], results=[ref(1)])
    alias[1]['types'].append(typ); alias[1]['types'].sort(key=lambda t: t['id'])
    result['structural-execution-alias'] = alias
    def second_plan(r):
        f = copy.deepcopy(nominal(r, 100)); f.update(id=101, elements=[ref(1), ref(1)],
            extent={'some': 1}, execution=some(301))
        r[10]['types'].append(f)
        p = copy.deepcopy(r[10]['signatures'][0]); p.update(id=1, function_type=ref(101),
            params=[ref(1)], result=some(1), lowered_results=[ref(1)], execution=ref(301),
            lowered_params=[dict(source_index={'some': 0}, role='parameter',
                source_type=ref(1), value_type=ref(1), mode='direct', align=1, bytes=1,
                noundef=True, copy=None, move=None, destroy=None)])
        r[10]['signatures'].append(p)
        typ = copy.deepcopy(fullfn(r)); typ.update(id=301, params=[ref(2)], results=[ref(2)],
                                                 param_noundef=[True], result_noundef=[True])
        r[1]['types'].append(typ); r[1]['types'].sort(key=lambda t: t['id'])
        body = copy.deepcopy(r[3]['functions'][0]); body.update(id=1, signature=ref(301),
            abi_signature=some(1), params=[dict(id=0, type=ref(2))])
        body['blocks'] = [dict(id=0, phis=[], ops=[], term=dict(op='return', values=[0]))]
        r[3]['functions'].append(body)
        symbol = copy.deepcopy(r[2]['symbols'][0]); symbol.update(id=7, name='second_source_function',
            execution=ref(301), nominal=some(101), abi_signature=some(1))
        symbol['definition']['some']['target'] = ref(1)
        r[2]['symbols'].append(symbol)
    add('multiple-source-plans', (8, 9), 9, mutate=second_plan)
    add('reject-builtin-signedness', (0,), 0, mutate=lambda r: nominal(r, 1).update(signed=False))
    add('reject-builtin-precision', (6,), 6, mutate=lambda r: nominal(r, 7).update(bits=32))
    add('reject-layout-size', (6,), 6, mutate=lambda r: r[10]['layouts'][6].update(size=4))
    add('reject-source-index', (0, 9), 9, mutate=lambda r: r[10]['signatures'][0]['lowered_params'][0].update(source_index={'some': 1}))
    add('reject-lowered-width', (0,), 0, mutate=lambda r: r[10]['signatures'][0]['lowered_params'][0].update(value_type=ref(5)))
    add('reject-plan-execution', (6,), 6, mutate=lambda r: r[10]['signatures'][0].update(execution=ref(17)))
    add('reject-default-execution', (6,), 6, mutate=lambda r: nominal(r, 100).update(execution=some(17)))
    add('reject-source-linkage', (6,), 6, mutate=lambda r: r[2]['symbols'][0].update(source_linkage='c'))
    add('reject-param-noundef', (6,), 6, mutate=lambda r: fullfn(r).update(param_noundef=[False]))
    add('reject-result-noundef', (6,), 6, mutate=lambda r: fullfn(r).update(result_noundef=[False]))
    add('reject-return-arity', (6,), None, mutate=lambda r: r[3]['functions'][0]['blocks'][0]['term'].update(values=[0]))
    def wrong_identity(r):
        f = copy.deepcopy(nominal(r, 100)); f.update(id=101, elements=[ref(9), ref(9)], execution=None, representation='none')
        r[10]['types'].append(f)
        r[2]['symbols'][0].update(nominal=some(101))
    add('reject-same-width-source-identity', (6,), 6, mutate=wrong_identity)
    add('some-void-control', (), None, mutate=lambda r: r[10]['signatures'][0].update(result=some(20)))
    def plain_char(r):
        nominal(r, 1)['identity']['entity'] = 'char'
    add('plain-char-control', (0,), 0, mutate=plain_char)
    add('hidden-control', (6,), 6, mutate=lambda r: r[2]['symbols'][0].update(visibility='hidden'))
    return result


def observe(payload, *, optimized=False):
    process = subprocess.run([sys.executable, '-B'] + (['-O'] if optimized else []) +
        [str(Path(__file__).resolve()), 'oracle'], input=payload, capture_output=True, check=True)
    return json.loads(process.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('generate', 'oracle'))
    args = parser.parse_args()
    if args.command == 'oracle':
        try:
            report = original.python_oracle(sys.stdin.buffer.read())
        except Exception as error:
            report = dict(status='rejected', code=getattr(error, 'code', str(error).split(':', 1)[0]),
                          exception=type(error).__name__, detail=str(error))
        report['interpreter_optimization'] = sys.flags.optimize
        print(json.dumps(report, sort_keys=True))
        return
    FIXTURES.mkdir(exist_ok=True)
    codec = original.load_codec()
    manifest = []
    for name, roots in cases().items():
        payload = codec.encode(roots)
        (FIXTURES / (name + '.smo')).write_bytes(payload)
        manifest.append(dict(name=name, sha256=hashlib.sha256(payload).hexdigest(), python=observe(payload)))
    (FIXTURES / 'observed-python.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(cases=len(manifest), directory=str(FIXTURES))))


if __name__ == '__main__':
    main()
