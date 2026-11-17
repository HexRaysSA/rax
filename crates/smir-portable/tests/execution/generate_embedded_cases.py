"""Embed local execution fixtures beside an actual scalar source ABI definition.

The original local corpus is unchanged. This generator derives fresh whole-root
reference results; neither a callback nor a producer-supplied fact admits input.
Only independently declared, disjoint source function/type IDs are introduced.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec, reference_report
from oracle_sources import input_roots, input_sources, interpreter_identity
CODEC = CandidateCodec({owner: json.loads((SPEC / f'schema/{owner}/candidate.json').read_text())
                        for owner in ['execution', 'runtime', 'abi']})
SOURCE = Path(__file__).with_name('core-cases.json')
BASE_SOURCE = SPEC / 'conformance/execution/candidate/portable-identity.json'
BASE = {int(k): v for k, v in json.loads(BASE_SOURCE.read_text())['sections'].items()}


def ref(identifier):
    return dict(module=dict(kind='self'), id=identifier)


def embedded(local):
    roots = deepcopy(BASE)
    # These two type definitions and this actual body fully implement the
    # separately retained int(int) source plan. Other bodies retain their IDs.
    scalar, signature, source_function = 10000, 10001, 10000
    assert all(t['id'] not in {scalar, signature} for t in local[1]['types'])
    assert all(f['id'] != source_function for f in local[3]['functions'])
    roots[1] = deepcopy(local[1])
    roots[1]['types'] += [dict(id=scalar, kind='int', bits=32),
        dict(id=signature, kind='function', params=[ref(scalar)], results=[ref(scalar)],
             param_noundef=[True], result_noundef=[True], variadic=False, cc='portable')]
    roots[1]['types'].sort(key=lambda t: t['id'])
    source = deepcopy(BASE[3]['functions'][0])
    source.update(id=source_function, signature=ref(signature))
    source['params'][0]['type'] = ref(scalar)
    roots[3] = deepcopy(local[3])
    roots[3]['functions'].append(source)
    roots[3]['functions'].sort(key=lambda f: f['id'])
    roots[8] = deepcopy(local[8])
    roots[10]['types'][0]['execution'] = dict(some=ref(scalar))
    roots[10]['types'][1]['execution'] = dict(some=ref(signature))
    roots[10]['signatures'][0]['execution'] = ref(signature)
    roots[2]['symbols'][0]['execution'] = ref(signature)
    roots[2]['symbols'][0]['definition']['some']['target'] = ref(source_function)
    for n, name, field in [(5, 'relocations', 'constant_initializers'), (7, 'segments', None),
                           (9, 'capabilities', 'requirements')]:
        roots[n] = dict(payload_revision=2 if n == 5 else 1, **{name: []})
        if field:
            roots[n][field] = []
    roots[9]['limits'] = []
    return roots


def generate():
    cases = []
    for case in json.loads(SOURCE.read_text())['cases']:
        if case['oracle_scope'] != 'execution-local':
            continue
        roots = embedded(CODEC.decode(bytes.fromhex(case['encoded_hex'])).roots)
        encoded = CODEC.encode(roots)
        try:
            reference_report(encoded)
            reference = 'ok'
        except ValueError as error:
            reference = getattr(error, 'code', str(error).split(':', 1)[0])
        cases.append(dict(name=case['name'], expected=reference,
            original_local_result=case['expected'], sha256=hashlib.sha256(encoded).hexdigest(),
            encoded_hex=encoded.hex()))
    sources = {Path(module.__file__).resolve() for module in list(sys.modules.values())
               if getattr(module, '__file__', None) and Path(module.__file__).resolve().is_relative_to(ROOT)}
    sources.update([SOURCE, BASE_SOURCE, Path(__file__).resolve()])
    document = dict(scope='Full ten-root independent reference after embedding local bodies beside a genuine disjoint scalar source ABI function; original local corpus unchanged. No guest execution.',
        sources=input_sources(ROOT, sources), oracle_input_roots=input_roots(), oracle_interpreter=interpreter_identity(), cases=cases)
    output = Path(__file__).with_name('embedded-cases.json')
    output.write_text(json.dumps(document, separators=(',', ':')) + '\n')
    differences = [(c['name'], c['original_local_result'], c['expected']) for c in cases if c['expected'] != c['original_local_result']]
    print('cases', len(cases), 'positive', sum(c['expected'] == 'ok' for c in cases),
          'negative', sum(c['expected'] != 'ok' for c in cases), 'bytes', output.stat().st_size)
    print('local versus whole-root reference differences:', differences)


if __name__ == '__main__':
    generate()
