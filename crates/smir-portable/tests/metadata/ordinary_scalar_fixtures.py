"""Source-authored ordinary scalar ABI/metadata full-object witnesses.

Independent from the ABI worker generator; no current object, provider or permit.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from fixture_provenance import provenance, write_bytes, write_text
from manifest_symbol_fixtures import base, dependency, declaration
from fixtures import CandidateCodec, SCHEMAS, ref, some, prepare_declared_abi2_source

HERE = Path(__file__).resolve().parent
SCALARS = [('signed char', 8, True), ('unsigned char', 8, False), ('short', 16, True),
           ('unsigned short', 16, False), ('int', 32, True), ('unsigned int', 32, False),
           ('long', 64, True), ('unsigned long', 64, False), ('long long', 64, True),
           ('unsigned long long', 64, False)]
SOURCE = {name: 201 + i for i, (name, _, _) in enumerate(SCALARS)}
EXECUTION = {name: 1000 + i for i, (name, _, _) in enumerate(SCALARS)}


def ordinary(params=('long',), result='long', *, c=False, result_noundef=True):
    roots = base(); prototype = deepcopy(roots[10]['types'][0])
    layout = deepcopy(roots[10]['layouts'][0])
    for name, bits, signed in SCALARS:
        identifier = SOURCE[name]; physical = EXECUTION[name]; size = bits // 8
        roots[1]['types'].append(dict(id=physical, kind='int', bits=bits))
        source = deepcopy(prototype); source.update(id=identifier, bits=bits, signed=signed,
            execution=some(ref(physical)), layout=some(identifier)); source['identity']['entity'] = name
        roots[10]['types'].append(source)
        geometry = deepcopy(layout); geometry.update(id=identifier, type=ref(identifier))
        for key in ['size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align']: geometry[key] = size
        roots[10]['layouts'].append(geometry)
    void = deepcopy(prototype); void.update(id=220, kind='void', bits=0, signed=False,
        representation='none', execution=None, layout=None, flags=[]); void['identity']['entity'] = 'void'
    roots[10]['types'].append(void)
    result_ids = [] if result is None else [EXECUTION[result]]
    roots[1]['types'].append(dict(id=2000, kind='function', cc='portable', variadic=False,
        params=[ref(EXECUTION[x]) for x in params], results=[ref(x) for x in result_ids],
        param_noundef=[True] * len(params), result_noundef=[result_noundef] * len(result_ids)))
    nominal = roots[10]['types'][1]
    nominal.update(elements=[ref(SOURCE[x]) for x in params] + [ref(220 if result is None else SOURCE[result])],
                   extent=some(len(params)), execution=some(ref(2000)),
                   flags=['c_linkage', 'complete'] if c else ['complete'])
    nominal['identity']['language'] = 'c23' if c else 'cpp23'
    plan = roots[10]['signatures'][0]; template = deepcopy(plan['lowered_params'][0])
    plan.update(params=[ref(SOURCE[x]) for x in params], result=None if result is None else some(ref(SOURCE[result])),
        execution=ref(2000), lowered_results=[] if result is None else [ref(SOURCE[result])],
        return_noundef=result_noundef if result is not None else False, lowered_params=[])
    for i, name in enumerate(params):
        lowered = deepcopy(template); size = next(bits // 8 for n, bits, _ in SCALARS if n == name)
        lowered.update(source_index=some(i), source_type=ref(SOURCE[name]), value_type=ref(SOURCE[name]), align=size, bytes=size)
        plan['lowered_params'].append(lowered)
    function = roots[3]['functions'][0]
    function.update(signature=ref(2000), params=[dict(id=i, type=ref(EXECUTION[x])) for i, x in enumerate(params)])
    block = function['blocks'][0]; block['ops'] = []
    if result is None: returned = []
    elif result in params: returned = [list(params).index(result)]
    else:
        output = len(params); size = next(bits // 8 for n, bits, _ in SCALARS if n == result)
        block['ops'] = [dict(op='constant', results=[dict(id=output, type=ref(EXECUTION[result]))],
            operands=[], literal=dict(kind='bits', value=(42).to_bytes(size, 'little').hex()))]
        returned = [output]
    block['term'] = dict(op='return', values=returned)
    roots[2]['symbols'][0].update(execution=ref(2000), source_linkage='c' if c else 'cpp')
    return roots


def build():
    cases = {}
    def add(name, roots, expected='static', code=None): cases[name] = (roots, expected, code)
    for name, _, _ in SCALARS:
        for c in [False, True]: add(('c-' if c else 'cpp-') + name.replace(' ', '-'), ordinary([name], name, c=c))
    for c in [False, True]:
        add(('c-' if c else 'cpp-') + 'void-zero', ordinary([], None, c=c))
        add(('c-' if c else 'cpp-') + 'void-mixed', ordinary(['signed char', 'unsigned long', 'long long'], None, c=c))
        add(('c-' if c else 'cpp-') + 'mixed-return', ordinary(['signed char', 'unsigned long', 'long long'], 'unsigned long', c=c))
        add(('c-' if c else 'cpp-') + 'zero-arg-return', ordinary([], 'unsigned long long', c=c))
    roots = ordinary(); roots[10]['types'][1].update(execution=None, representation='none'); add('no-source-default-inferred', roots)
    add('exact-return-noundef-false', ordinary(result_noundef=False))
    roots = ordinary(); full = deepcopy(roots[1]['types'][-1]); full['id'] = 2001; roots[1]['types'].append(full)
    roots[2]['symbols'][0]['execution'] = ref(2001); add('structural-physical-alias', roots)
    roots = ordinary(); roots[2]['symbols'][0]['definition'] = None; add('undefined-retains-source-obligations', roots)
    roots = ordinary(); dependency(roots, [declaration('function', execution=some(ref(2000)))])
    add('original-dependency-source-expectation', roots)
    roots = ordinary(); nominal = deepcopy(roots[10]['types'][1]); nominal['id'] = 3000
    roots[10]['types'].append(nominal); plan = deepcopy(roots[10]['signatures'][0]); plan.update(id=1, function_type=ref(3000))
    roots[10]['signatures'].append(plan); body = deepcopy(roots[3]['functions'][0]); body.update(id=1, abi_signature=some(ref(1)))
    roots[3]['functions'].append(body); symbol = deepcopy(roots[2]['symbols'][0]); symbol.update(id=1, name='second_source',
        nominal=some(ref(3000)), abi_signature=some(ref(1)), definition=some(dict(kind='function', target=ref(1))))
    roots[2]['symbols'].append(symbol); add('multiple-original-source-plans', roots)
    roots = ordinary(); alias = deepcopy(roots[2]['symbols'][0]); alias.update(id=1, name='source_alias', definition=some(dict(kind='alias', target=ref(0))))
    roots[2]['symbols'].append(alias); add('original-source-alias', roots)
    for name, key, value, code in [('source-index', 'source_index', some(7), 'ABI_CC_CALL_PARAMETER'),
         ('lowered-bytes', 'bytes', 4, 'ABI_CC_CALL_PARAMETER'), ('lowered-align', 'align', 4, 'ABI_CC_CALL_PARAMETER'),
         ('parameter-noundef', 'noundef', False, 'ABI_CC_CALL_PARAMETER')]:
        roots = ordinary(); roots[10]['signatures'][0]['lowered_params'][0][key] = value
        add('reject-' + name, roots, 'semantic', code)
    for name, key, value, code in [('source-sign', 'signed', False, 'ABI_CC_SCALAR_SIGNEDNESS'),
         ('source-precision', 'bits', 32, 'ABI_CC_SCALAR_PRECISION')]:
        roots = ordinary(); next(t for t in roots[10]['types'] if t['id'] == SOURCE['long'])[key] = value
        if name == 'source-precision':
            next(t for t in roots[10]['types'] if t['id'] == SOURCE['long'])['execution'] = some(ref(EXECUTION['int']))
        add('reject-' + name, roots, 'semantic', code)
    roots = ordinary(); next(l for l in roots[10]['layouts'] if l['id'] == SOURCE['long'])['size'] = 16
    add('reject-source-layout', roots, 'semantic', 'ABI_CC_LAYOUT_POLICY')
    roots = ordinary(); wrong = deepcopy(roots[10]['types'][1]); wrong.update(id=3000, execution=None, representation='none',
        elements=[ref(SOURCE['long long']), ref(SOURCE['long long'])]); roots[10]['types'].append(wrong)
    roots[2]['symbols'][0]['nominal'] = some(ref(3000)); add('reject-same-width-source-long-long', roots, 'semantic', 'RT_SOURCE_PLAN_NOMINAL')
    roots = ordinary(); roots[2]['symbols'][0]['source_linkage'] = 'c'
    add('reject-source-c-linkage', roots, 'semantic', 'RT_SYMBOL_SOURCE_LINKAGE')
    roots = ordinary(); roots[3]['functions'][0]['blocks'][0]['term']['values'] = []
    add('reject-body-return-arity', roots, 'semantic', 'return_signature')
    roots = ordinary(); roots[3]['functions'][0]['params'][0]['type'] = ref(1)
    add('reject-body-parameter-type', roots, 'semantic', 'parameter_signature')
    roots = ordinary(); full = deepcopy(roots[1]['types'][-1]); full.update(id=2001, param_noundef=[False]); roots[1]['types'].append(full)
    roots[2]['symbols'][0]['execution'] = ref(2001); add('reject-body-noundef', roots, 'semantic', 'RT_DEFINITION_SIGNATURE')
    roots = ordinary(); roots[10]['signatures'][0]['execution'] = ref(12)
    add('reject-explicit-plan-fullfn', roots, 'semantic', 'ABI_CC_LOWERED_SIGNATURE')
    for name, key, value in [('hidden', 'visibility', 'hidden'), ('weak', 'binding', 'weak'), ('alignment', 'alignment', 2)]:
        roots = ordinary(); roots[2]['symbols'][0][key] = value
        add('retained-' + name, roots, 'unavailable', 'P2_METADATA_PROFILE_UNAUDITED')
    roots = ordinary([], None); roots[10]['signatures'][0]['result'] = some(ref(220))
    add('retained-some-void', roots, 'unavailable', 'P2_ABI_VERIFIER_INCOMPLETE')
    roots = ordinary(['signed char'], 'signed char'); next(t for t in roots[10]['types'] if t['id'] == SOURCE['signed char'])['identity']['entity'] = 'char'
    add('retained-plain-char', roots, 'unavailable', 'P2_ABI_VERIFIER_INCOMPLETE')
    return cases


def main():
    folder = HERE / 'ordinary-scalar-fixtures'
    if '--check' not in __import__('sys').argv: folder.mkdir(exist_ok=True)
    codec = CandidateCodec(SCHEMAS); manifest = {}
    for name, (roots, expected, code) in build().items():
        prepare_declared_abi2_source(roots); data = codec.encode(roots)
        write_bytes(folder / (name + '.smo'), data)
        manifest[name] = dict(expected=expected, code=code, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
            content_identity=codec.decode(data).content_digest)
    inputs = ['crates/smir-portable/tests/metadata/manifest_symbol_fixtures.py',
        'crates/smir-portable/tests/metadata/fixtures.py', 'crates/smir-portable/tests/metadata/profile_fixtures.py',
        'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json']
    write_text(folder / 'manifest.json', json.dumps(dict(scope=__doc__, provenance=provenance(__file__, inputs, manifest), cases=manifest), indent=2) + '\n')
    print('ordinary scalar complete original objects', len(manifest))


if __name__ == '__main__': main()
