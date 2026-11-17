#!/usr/bin/env python3
"""Independent generic-Fn source cases and an executable integer witness.

Static acceptance never supplies an opaque CLI input or execution authority.
Generation is O(total source-case bytes), with the owner validators' separate
bounded graph costs. Space is O(total generated source-case bytes).
"""
import argparse
import copy
import json
import subprocess
import sys
from pathlib import Path

import metadata_manifest_cases as original

ROOT = original.ROOT
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/generic-functions'
ref, some = original.ref, original.some


def source(params, results, returned=None):
    roots = {int(k): v for k, v in json.loads((FIXTURES / 'seed.source.json').read_text())['sections'].items()}
    roots[2]['manifest']['identity'] = '00' * 32
    roots[1]['types'].extend([
        dict(kind='function', id=300, params=[ref(t) for t in params], results=[ref(t) for t in results],
             variadic=False, cc='portable', param_noundef=[True] * len(params), result_noundef=[True] * len(results)),
        dict(kind='int', id=310, bits=1), dict(kind='int', id=311, bits=9),
        dict(kind='array', id=312, element=ref(17), count=3),
        dict(kind='vector', id=313, element=ref(17), count=4)])
    roots[1]['types'].sort(key=lambda t: t['id'])
    function = copy.deepcopy(roots[3]['functions'][0])
    function.update(signature=ref(300), abi_signature=None,
                    params=[dict(id=i, type=ref(t)) for i, t in enumerate(params)])
    function['blocks'] = [dict(id=0, phis=[], ops=[], term=dict(op='return', values=
        list(range(len(results))) if returned is None else returned))]
    roots[3]['functions'] = [function]
    roots[2]['symbols'][0].update(execution=ref(300), source_linkage='none', nominal=None, abi_signature=None)
    return roots


def fn(roots, identifier=300):
    return next(t for t in roots[1]['types'] if t['id'] == identifier)


def body_variant(roots, params, results, returned=None, *, noundef=True):
    typ = copy.deepcopy(fn(roots)); typ.update(id=301, params=[ref(t) for t in params],
        results=[ref(t) for t in results], param_noundef=[noundef] * len(params), result_noundef=[noundef] * len(results))
    roots[1]['types'].append(typ); roots[1]['types'].sort(key=lambda t: t['id'])
    body = roots[3]['functions'][0]
    body.update(signature=ref(301), params=[dict(id=i, type=ref(t)) for i, t in enumerate(params)])
    body['blocks'][0]['term']['values'] = list(range(len(results))) if returned is None else returned


def alias(roots, *, mismatch=False):
    typ = copy.deepcopy(fn(roots)); typ.update(id=301)
    if mismatch:
        typ.update(params=[ref(18)], results=[ref(18)])
    else:
        typ.update(params=[ref(1)], results=[ref(16)])
    roots[1]['types'].append(typ); roots[1]['types'].sort(key=lambda t: t['id'])
    symbol = copy.deepcopy(roots[2]['symbols'][0]); symbol.update(id=7, name='independent_alias', execution=ref(301))
    symbol['definition'] = {'some': dict(kind='alias', target=ref(0))}
    roots[2]['symbols'].append(symbol)


def dependency_execution(roots):
    roots[2]['manifest']['dependencies'] = [dict(slot=5,
        key=dict(namespace='independent', name='generic_provider', abi_major=1, abi_minor=0),
        minimum_minor=0, maximum_minor=None, site=roots[10]['identity'], declarations=[dict(
            id=11, kind='type', symbol_kind='none', source_linkage='none', namespace='independent',
            name='signature', execution=some(300), nominal=None, abi_signature=None, weak=False)])]
    roots[2]['symbols'][0]['execution'] = {'module': {'kind': 'dependency', 'slot': 5}, 'id': 11}


def cpp64(roots):
    scalar = next(t for t in roots[10]['types'] if t['id'] == 1)
    scalar['identity']['entity'] = 'long'
    scalar.update(bits=64, execution=some(18))
    layout = roots[10]['layouts'][0]
    layout.update(size=8, align=8, data_size=8, nonvirtual_size=8, nonvirtual_align=8)
    next(t for t in roots[10]['types'] if t['id'] == 12)['execution'] = some(300)
    plan = roots[10]['signatures'][0]
    # Lowered value/result references are nominal, unlike execution FullFn.
    plan.update(execution=ref(300))
    plan['lowered_params'][0].update(align=8, bytes=8)
    roots[1]['memory_layouts'].append(dict(id=5, type=ref(18), size=8, alignment=8,
        access_bytes=8, fields=[], element=None, stride=0))
    roots[2]['symbols'][0].update(source_linkage='cpp', nominal=some(12), abi_signature=some(0))
    roots[3]['functions'][0]['abi_signature'] = some(0)
    command = ('import sys,json;sys.path.insert(0,sys.argv[1]);'
               'from candidate_fixtures import seal;print(json.dumps(seal(json.load(sys.stdin))))')
    result = subprocess.run([sys.executable, '-B', '-c', command, str(ROOT / 'tools/smir-abi')],
        input=json.dumps(roots[10]), text=True, capture_output=True, check=True)
    roots[10] = json.loads(result.stdout)


def executable_witness():
    """Independently authored (sum, square(sum)) with an actual internal call."""
    roots = source([18, 18], [18, 18])
    typ = copy.deepcopy(fn(roots)); typ.update(id=301, params=[ref(18)], results=[ref(18)],
        param_noundef=[True], result_noundef=[True])
    roots[1]['types'].append(typ); roots[1]['types'].sort(key=lambda t: t['id'])
    roots[3]['functions'][0]['blocks'][0].update(ops=[
        dict(op='i_add', results=[dict(id=2, type=ref(18))], operands=[0, 1], flags=[]),
        dict(op='call', results=[dict(id=3, type=ref(18))], operands=[2],
             target=dict(kind='direct', function=ref(1), signature=ref(301)), unwind='propagate', source_plan=None)],
        term=dict(op='return', values=[2, 3]))
    child = copy.deepcopy(roots[3]['functions'][0]); child.update(id=1, signature=ref(301), params=[dict(id=0, type=ref(18))])
    child['blocks'] = [dict(id=0, phis=[], ops=[dict(op='i_mul', results=[dict(id=1, type=ref(18))],
        operands=[0, 0], flags=[])], term=dict(op='return', values=[1]))]
    roots[3]['functions'].append(child)
    return roots


def cases():
    result = {}
    def add(name, params=(17,), results=(17,), mutate=lambda r: None, returned=None):
        roots = source(params, results, returned); mutate(roots); result[name] = roots
    add('void', (), ())
    add('mixed-three-params', (310, 18, 900), ())
    add('mixed-multi-results', (17, 18), (17, 18))
    for name, typ in [('int1', 310), ('int9', 311), ('int64', 18), ('int65', 10),
                      ('raw256', 8), ('code-address', 900), ('data-pointer', 19),
                      ('code-pointer', 901), ('struct', 200), ('array', 312), ('vector', 313)]:
        add(name, (typ,), (typ,))
    add('structural-alias', mutate=alias)
    add('undefined-generic', (18,), (18,), lambda r: r[2]['symbols'][0].update(definition=None))
    add('dependency-int32-preserved', mutate=dependency_execution)
    add('dependency-int64-control', (18,), (18,), dependency_execution)
    add('hidden-control', (18,), (18,), lambda r: r[2]['symbols'][0].update(visibility='hidden'))
    add('weak-control', (18,), (18,), lambda r: r[2]['symbols'][0].update(binding='weak'))
    add('cpp64-control', (18,), (18,), cpp64)
    add('variadic-control', mutate=lambda r: fn(r).update(variadic=True))
    add('reject-not-function', mutate=lambda r: r[2]['symbols'][0].update(execution=ref(18)))
    add('reject-body-width', mutate=lambda r: body_variant(r, [18], [18]))
    add('reject-body-param-arity', mutate=lambda r: body_variant(r, [17, 17], [17]))
    add('reject-body-result-arity', mutate=lambda r: body_variant(r, [17], [17, 17], [0, 0]))
    add('reject-body-noundef', mutate=lambda r: body_variant(r, [17], [17], noundef=False))
    add('reject-param-noundef-arity', mutate=lambda r: fn(r).update(param_noundef=[]))
    add('reject-body-params', mutate=lambda r: r[3]['functions'][0].update(params=[]))
    add('reject-body-param-type', mutate=lambda r: r[3]['functions'][0]['params'][0].update(type=ref(18)))
    add('reject-return-arity', returned=[])
    add('reject-forged-code-address-return', (900, 18), (900,), returned=[1])
    add('reject-alias-shape', mutate=lambda r: alias(r, mismatch=True))
    add('reject-nonportable-cc', mutate=lambda r: fn(r).update(cc='unassigned_native'))
    result['wide-internal-call'] = executable_witness()
    return result


def observe(payload, *, optimized=False):
    command = [sys.executable, '-B'] + (['-O'] if optimized else []) + [str(Path(__file__).resolve()), 'oracle']
    process = subprocess.run(command, input=payload, capture_output=True, check=True)
    return json.loads(process.stdout)


def refusal_probe(name, arguments):
    """Observe negative-only actual Machine methods; never replace issuers."""
    original.load_codec()
    codec = sys.modules['llvm_metadata_wire']
    sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
    from candidate.machine import Machine
    saved = {key: getattr(Machine, key) for key in ('__init__', 'start', 'run')}
    calls = dict.fromkeys(saved, 0)
    for key, method in saved.items():
        def observed(self, *args, _key=key, _method=method, **kwargs):
            calls[_key] += 1
            return _method(self, *args, **kwargs)
        setattr(Machine, key, observed)
    try:
        codec.run_reference((FIXTURES / (name + '.smo')).read_bytes(), entry_function=0,
            argument_bits=arguments, policy=json.loads((FIXTURES / 'policy.json').read_text()))
        result = dict(status='unexpected-return')
    except Exception as error:
        result = dict(status='rejected', code=getattr(error, 'code', str(error).split(':', 1)[0]),
                      exception=type(error).__name__)
    finally:
        for key, method in saved.items():
            setattr(Machine, key, method)
    result.update(calls=calls, restored=all(getattr(Machine, k) is v for k, v in saved.items()),
                  interpreter_optimization=sys.flags.optimize)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['generate', 'oracle', 'refusal-probe'])
    args = parser.parse_args()
    if args.command == 'refusal-probe':
        request = json.load(sys.stdin)
        print(json.dumps(refusal_probe(request['case'], request['arguments']), sort_keys=True))
        return
    if args.command == 'oracle':
        try:
            report = original.python_oracle(sys.stdin.buffer.read())
        except Exception as error:
            report = dict(status='rejected', code=getattr(error, 'code', str(error).split(':', 1)[0]),
                          detail=str(error), exception=type(error).__name__)
        report['interpreter_optimization'] = sys.flags.optimize
        print(json.dumps(report, sort_keys=True))
        return
    import hashlib
    codec = original.load_codec(); observations = []
    for name, roots in cases().items():
        payload = codec.encode(roots); (FIXTURES / (name + '.smo')).write_bytes(payload)
        observations.append(dict(name=name, sha256=hashlib.sha256(payload).hexdigest(), python=observe(payload)))
    (FIXTURES / 'observed-python.json').write_text(json.dumps(observations, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(cases=len(observations), fixtures=str(FIXTURES))))


if __name__ == '__main__':
    main()
