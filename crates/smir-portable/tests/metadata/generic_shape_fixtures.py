"""Independent original generic Fn shapes through complete static factories.

These source-authored ten-root objects supply no source ABI or runtime authority.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from fixture_provenance import provenance, write_bytes, write_text
from manifest_symbol_fixtures import base, dependency, declaration
from fixtures import CandidateCodec, SCHEMAS, ref, some, prepare_declared_abi2_source

HERE = Path(__file__).resolve().parent


def generic(params, results, returns):
    roots = base()
    roots[1]['types'].extend([
        dict(id=900, kind='code_address'),
        dict(id=901, kind='code_ptr', signature=ref(12)),
        dict(id=902, kind='array', element=ref(1), count=3),
        dict(id=903, kind='vector', element=ref(1), count=4),
        dict(id=904, kind='int', bits=1),
        dict(id=905, kind='int', bits=9),
        dict(id=1001, kind='function', params=[ref(t) for t in params],
             results=[ref(t) for t in results], param_noundef=[True] * len(params),
             result_noundef=[True] * len(results), cc='portable', variadic=False)])
    function = roots[3]['functions'][0]
    function.update(signature=ref(1001), abi_signature=None,
                    params=[dict(id=i, type=ref(t)) for i, t in enumerate(params)])
    function['blocks'][0].update(phis=[], ops=[], term=dict(op='return', values=returns))
    roots[2]['symbols'][0].update(execution=ref(1001), source_linkage='none',
                                  nominal=None, abi_signature=None)
    return roots


def signature(roots):
    return next(t for t in roots[1]['types'] if t['id'] == 1001)


def distinct_signature(roots, **changes):
    value = dict(deepcopy(signature(roots)), id=1002, **changes)
    roots[1]['types'].append(value)
    return value


def build():
    cases = {}
    def add(name, roots, expected='static', code=None):
        cases[name] = (roots, expected, code)
    add('void', generic([], [], []))
    add('multiarg', generic([1, 5, 3], [], []))
    add('multiresult', generic([1, 5], [1, 5], [0, 1]))
    for name, kind in [('int1', 904), ('int9', 905), ('int64', 5), ('int65', 10),
                       ('code-address', 900), ('data-pointer', 4), ('raw256', 8),
                       ('code-pointer', 901), ('array', 902), ('vector', 903), ('struct', 200)]:
        add(name + '-identity', generic([kind], [kind], [0]))
    roots = generic([5], [5], [0]); distinct_signature(roots)
    roots[2]['symbols'][0]['execution'] = ref(1002)
    add('structural-equality-not-type-id', roots)
    roots = generic([5], [5], [0]); roots[2]['symbols'][0]['definition'] = None
    add('undefined-original-requirement', roots)
    roots = generic([5], [5], [0]); alias = deepcopy(roots[2]['symbols'][0])
    alias.update(id=1, name='generic_alias', definition=some(dict(kind='alias', target=ref(0))))
    roots[2]['symbols'].append(alias); add('original-generic-alias', roots)
    roots = generic([5], [5], [0]); function = deepcopy(roots[3]['functions'][0]); function['id'] = 1
    roots[3]['functions'].append(function); symbol = deepcopy(roots[2]['symbols'][0])
    symbol.update(id=1, name='second_generic', definition=some(dict(kind='function', target=ref(1))))
    roots[2]['symbols'].append(symbol); add('two-generic-bodies', roots)
    # Original dependency declaration is an expectation, not a selected provider.
    roots = generic([5], [5], [0]); dependency(roots, [declaration('function',
        execution=some(ref(1001)), source_linkage='none', nominal=None, abi_signature=None)])
    add('original-generic-declaration-expectation', roots)
    for name, kind, expected, code in [('int32', 1, 'static', None),
                                       ('int64', 5, 'unavailable', 'P2_METADATA_PROFILE_UNAUDITED')]:
        roots = generic([kind], [kind], [0])
        dependency(roots, [declaration('type', execution=some(ref(1001)))])
        roots[2]['symbols'][0]['execution'] = dict(module=dict(kind='dependency', slot=7), id=40)
        add('retained-nonself-generic-' + name, roots, expected, code)
    for name, changes in [('parameter-type', dict(params=[ref(1)])),
                           ('result-type', dict(results=[ref(1)])),
                           ('noundef', dict(param_noundef=[False])),
                           ('result-noundef', dict(result_noundef=[False])),
                           ('arity', dict(params=[ref(5), ref(5)], param_noundef=[True, True]))]:
        roots = generic([5], [5], [0]); distinct_signature(roots, **changes)
        roots[2]['symbols'][0]['execution'] = ref(1002)
        add('reject-body-' + name, roots, 'semantic', 'RT_DEFINITION_SIGNATURE')
    roots = generic([5], [5], [0]); roots[2]['symbols'][0]['execution'] = ref(5)
    add('reject-symbol-not-function', roots, 'semantic', 'RT_SYMBOL_SIGNATURE')
    roots = generic([5], [5], [0]); signature(roots)['param_noundef'] = []
    add('reject-noundef-arity', roots, 'semantic', 'type_signature')
    roots = generic([5], [5], [0]); signature(roots)['variadic'] = True
    add('reject-variadic', roots, 'semantic', 'calling_convention')
    roots = generic([5], [5], [0]); roots[3]['functions'][0]['params'][0]['type'] = ref(1)
    add('reject-ssa-param-type', roots, 'semantic', 'parameter_signature')
    roots = generic([5], [5], [0]); roots[3]['functions'][0]['params'] = []
    add('reject-ssa-param-arity', roots, 'semantic', 'parameter_signature')
    roots = generic([5], [5], [0]); roots[3]['functions'][0]['blocks'][0]['term']['values'] = []
    add('reject-return-arity', roots, 'semantic', 'return_signature')
    roots = generic([900], [5], [0])
    add('reject-code-address-returned-as-int', roots, 'semantic', 'return_signature')
    roots = generic([5], [5], [99])
    add('reject-undefined-return-ssa', roots, 'semantic', 'ssa_reference')
    roots = generic([5], [5], [0]); distinct_signature(roots, results=[ref(1)])
    alias = deepcopy(roots[2]['symbols'][0]); alias.update(id=1, name='wrong_alias',
        execution=ref(1002), definition=some(dict(kind='alias', target=ref(0))))
    roots[2]['symbols'].append(alias); add('reject-alias-result-shape', roots, 'semantic', 'RT_DEFINITION_SIGNATURE')
    for name, field, value in [('hidden', 'visibility', 'hidden'), ('weak', 'binding', 'weak'),
                                ('alignment', 'alignment', 2), ('size', 'size', some(8))]:
        roots = generic([5], [5], [0]); roots[2]['symbols'][0][field] = value
        add('retained-' + name, roots, 'unavailable', 'P2_METADATA_PROFILE_UNAUDITED')
    add('ordinary-source-unchanged', base())
    roots = base(); roots[10]['types'][1]['flags'].append('c_linkage')
    roots[10]['types'][1]['flags'].sort(); roots[2]['symbols'][0]['source_linkage'] = 'c'
    add('retained-c-source-abi-limit', roots, 'unavailable', 'P2_ABI_VERIFIER_INCOMPLETE')
    roots = generic([5], [5], [0]); roots[2]['symbols'][0]['source_linkage'] = 'cpp'
    add('reject-pretend-source-linkage', roots, 'semantic', 'RT_SOURCE_LINKAGE_WITHOUT_NOMINAL')
    return cases


def main():
    folder = HERE / 'generic-shape-fixtures'
    if '--check' not in __import__('sys').argv:
        folder.mkdir(exist_ok=True)
    codec = CandidateCodec(SCHEMAS); manifest = {}
    for name, (roots, expected, code) in build().items():
        prepare_declared_abi2_source(roots)
        data = codec.encode(roots)
        write_bytes(folder / (name + '.smo'), data)
        manifest[name] = dict(expected=expected, code=code, bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(), content_identity=codec.decode(data).content_digest)
    inputs = ['crates/smir-portable/tests/metadata/manifest_symbol_fixtures.py',
        'crates/smir-portable/tests/metadata/fixtures.py',
        'crates/smir-portable/tests/metadata/profile_fixtures.py',
        'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json']
    document = dict(scope=__doc__, provenance=provenance(__file__, inputs, manifest), cases=manifest)
    write_text(folder / 'manifest.json', json.dumps(document, indent=2) + '\n')
    print('generic-shape complete original objects', len(manifest))


if __name__ == '__main__':
    main()
