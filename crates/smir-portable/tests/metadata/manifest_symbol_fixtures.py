"""Independent whole-object manifest/symbol contracts, no runtime authority."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from fixture_provenance import provenance, write_bytes, write_text
from fixtures import CandidateCodec, SCHEMAS, ref, some, prepare_declared_abi2_source
from profile_fixtures import complete

HERE = Path(__file__).resolve().parent


def base():
    return complete('portable-identity')


def exported(kind, target=0, **changes):
    value = dict(id=0, kind=kind, namespace='manifest', name='public',
                 source_linkage='none', target=ref(target), execution=None,
                 nominal=None, abi_signature=None)
    if kind in ('function', 'symbol'):
        value.update(source_linkage='cpp', execution=some(ref(12)),
                     nominal=some(ref(12)), abi_signature=some(ref(0)))
    elif kind == 'type':
        value.update(execution=some(ref(target)))
    elif kind == 'nominal':
        value.update(execution=some(ref(1)), nominal=some(ref(target)))
    value.update(changes)
    return value


def declaration(kind, identifier=40, **changes):
    value = dict(id=identifier, kind=kind, symbol_kind='none', source_linkage='none',
                 namespace='provider', name=kind, execution=None, nominal=None,
                 abi_signature=None, weak=False)
    if kind == 'type':
        value['execution'] = some(ref(1))
    elif kind == 'nominal':
        value['nominal'] = some(ref(12))
    elif kind in ('function', 'symbol'):
        value.update(source_linkage='cpp', execution=some(ref(12)),
                     nominal=some(ref(12)), abi_signature=some(ref(0)))
        if kind == 'symbol':
            value['symbol_kind'] = 'function'
    value.update(changes)
    return value


def dependency(roots, declarations):
    roots[2]['manifest']['dependencies'] = [dict(slot=7,
        key=dict(namespace='provider', name='original', abi_major=1, abi_minor=2),
        minimum_minor=1, maximum_minor=some(3), site=roots[10]['identity'],
        declarations=declarations)]


def build():
    cases = {}
    def add(name, roots, expected='static', code=None):
        cases[name] = (roots, expected, code)
    for personality in ('linux', 'darwin', 'windows'):
        for count in (0, 1, 3):
            roots = base(); roots[2]['manifest']['personality'] = personality
            template = roots[2]['symbols'][0]
            roots[2]['symbols'] = [dict(deepcopy(template), id=i, name='function_' + str(i))
                                  for i in range(count)]
            add(personality + '-symbols-' + str(count), roots)
    roots = base(); body = deepcopy(roots[3]['functions'][0]); body['id'] = 1
    roots[3]['functions'].append(body)
    roots[2]['symbols'].append(dict(deepcopy(roots[2]['symbols'][0]), id=1, name='second',
                                    definition=some(dict(kind='function', target=ref(1)))))
    add('two-distinct-bodies', roots)
    roots = base(); roots[3]['functions'][0]['abi_signature'] = None
    roots[2]['symbols'][0].update(source_linkage='none', nominal=None, abi_signature=None)
    add('generic-source-function', roots)
    roots = base(); roots[2]['symbols'][0]['definition'] = None
    add('undefined-ordinary-retains-obligation', roots)
    roots = base(); roots[2]['symbols'].append(dict(deepcopy(roots[2]['symbols'][0]),
        id=1, name='alias', definition=some(dict(kind='alias', target=ref(0)))))
    add('local-function-alias', roots)
    roots = base(); roots[10]['types'][1]['flags'].append('c_linkage')
    roots[10]['types'][1]['flags'].sort(); roots[2]['symbols'][0]['source_linkage'] = 'c'
    add('c-source-abi-unavailable', roots, 'unavailable', 'P2_ABI_VERIFIER_INCOMPLETE')
    roots = base(); roots[2]['symbols'][0]['visibility'] = 'hidden'
    add('hidden-control', roots, 'unavailable', 'P2_METADATA_PROFILE_UNAUDITED')
    roots = base(); roots[2]['symbols'][0]['binding'] = 'weak'
    add('weak-control', roots, 'unavailable', 'P2_METADATA_PROFILE_UNAUDITED')
    for kind, target in [('function', 0), ('symbol', 0), ('type', 1), ('nominal', 1)]:
        roots = base(); roots[2]['manifest']['exports'] = [exported(kind, target)]
        add('export-' + kind, roots)
    roots = base(); roots[2]['symbols'] = []
    roots[2]['manifest']['exports'] = [exported('function')]
    add('direct-export-without-symbol', roots)
    for kind in ('type', 'nominal', 'function', 'symbol', 'recipe'):
        roots = base(); dependency(roots, [declaration(kind)])
        add('original-declaration-' + kind, roots)
    roots = base(); roots[1]['types'].append(dict(id=900, kind='code_address'))
    dependency(roots, [declaration('symbol', symbol_kind='function_address',
        execution=some(ref(900)), abi_signature=None)])
    add('original-declaration-function-address', roots)
    roots = base(); dependency(roots, [declaration('nominal')])
    roots[2]['symbols'][0]['nominal'] = some(dict(module=dict(kind='dependency', slot=7), id=40))
    add('function-original-dependency-nominal', roots)
    for field, value, code in [
        ('source_linkage', 'c', 'RT_EXPORT_SOURCE_LINKAGE'),
        ('nominal', some(ref(1)), 'RT_EXPORT_NOMINAL'),
        ('abi_signature', None, 'RT_EXPORT_SOURCE_PLAN')]:
        roots = base(); roots[2]['manifest']['exports'] = [exported('function', **{field:value})]
        add('reject-export-' + field, roots, 'semantic', code)
    roots = base(); roots[1]['types'].append(dict(id=300, kind='function', params=[ref(17)],
        results=[ref(5)], variadic=False, cc='portable', param_noundef=[True], result_noundef=[True]))
    roots[2]['manifest']['exports'] = [exported('function', execution=some(ref(300)))]
    add('reject-export-execution', roots, 'semantic', 'RT_EXPORT_EXECUTION')
    for field, value, code in [
        ('nominal', some(ref(1)), 'RT_SOURCE_FUNCTION_NOMINAL'),
        ('abi_signature', None, 'RT_SOURCE_PLAN_PRESENCE'),
        ('source_linkage', 'c', 'RT_SYMBOL_SOURCE_LINKAGE'),
        ('execution', ref(5), 'RT_SYMBOL_SIGNATURE')]:
        roots = base(); roots[2]['symbols'][0][field] = value
        add('reject-symbol-' + field, roots, 'semantic', code)
    roots = base(); roots[3]['functions'][0]['abi_signature'] = None
    add('reject-body-source-presence', roots, 'semantic', 'RT_FUNCTION_SOURCE_PRESENCE')
    for field, value, code in [('weak', True, 'RT_WEAK_DECLARATION_KIND'),
        ('source_linkage', 'cpp', 'RT_SOURCE_LINKAGE'),
        ('symbol_kind', 'function', 'RT_DECLARATION_SYMBOL_KIND')]:
        roots = base(); dependency(roots, [declaration('type', **{field:value})])
        add('reject-type-declaration-' + field, roots, 'semantic', code)
    roots = base(); dependency(roots, [declaration('function', abi_signature=None)])
    add('reject-declaration-missing-plan', roots, 'semantic', 'RT_SOURCE_PLAN_PRESENCE')
    roots = base(); dependency(roots, [declaration('function', execution=some(ref(1)))])
    add('probe-declaration-function-scalar', roots, 'semantic', 'RT_DECLARATION_FUNCTION_TYPE')
    roots = base(); roots[1]['types'].append(dict(id=300, kind='function', params=[ref(17)],
        results=[ref(5)], variadic=False, cc='portable', param_noundef=[True], result_noundef=[True]))
    dependency(roots, [declaration('function', execution=some(ref(300)))])
    add('probe-declaration-function-plan-shape', roots, 'semantic', 'RT_DECLARATION_SOURCE_PLAN_EXECUTION')
    roots = base(); dependency(roots, [declaration('function', source_linkage='none',
        nominal=None, abi_signature=None)])
    add('generic-declaration-still-explicit-function', roots)
    roots = base(); dependency(roots, [declaration('function', execution=None)])
    add('reject-declaration-missing-execution', roots, 'semantic', 'RT_DECLARATION_FUNCTION_TYPE')
    for name, execution in [('missing', None), ('scalar', some(ref(1)))]:
        roots = base(); dependency(roots, [declaration('function', execution=execution,
            source_linkage='none', nominal=None, abi_signature=None)])
        add('reject-generic-declaration-' + name, roots, 'semantic', 'RT_DECLARATION_FUNCTION_TYPE')
    roots = base(); alias = deepcopy(next(t for t in roots[1]['types'] if t['id'] == 12))
    alias.update(id=300, params=[ref(1)], results=[ref(1)])
    roots[1]['types'].append(alias)
    dependency(roots, [declaration('function', execution=some(ref(300)))])
    add('declaration-structurally-equal-distinct-function', roots)
    for name, changes in [('noundef', dict(param_noundef=[False])),
                          ('arity', dict(params=[ref(17), ref(17)], param_noundef=[True, True]))]:
        roots = base(); signature = deepcopy(next(t for t in roots[1]['types'] if t['id'] == 12))
        signature.update(id=300, **changes); roots[1]['types'].append(signature)
        dependency(roots, [declaration('function', execution=some(ref(300)))])
        add('reject-declaration-plan-' + name, roots, 'semantic', 'RT_DECLARATION_SOURCE_PLAN_EXECUTION')
    for kind in ('function', 'import'):
        roots = base(); signature = deepcopy(next(t for t in roots[1]['types'] if t['id'] == 12))
        signature.update(id=300, results=[ref(5)]); roots[1]['types'].append(signature)
        dependency(roots, [declaration('symbol', symbol_kind=kind, execution=some(ref(300)))])
        add('reject-declaration-' + kind + '-symbol-plan', roots, 'semantic',
            'RT_DECLARATION_SOURCE_PLAN_EXECUTION')
    return cases


def main():
    folder = HERE / 'manifest-symbol-fixtures'; folder.mkdir(exist_ok=True)
    codec = CandidateCodec(SCHEMAS); manifest = {}
    for name, (roots, expected, code) in build().items():
        prepare_declared_abi2_source(roots)
        data = codec.encode(roots)
        write_bytes(folder / (name + '.smo'), data)
        manifest[name] = dict(expected=expected, code=code, bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(), content_identity=codec.decode(data).content_digest)
    inputs = ['crates/smir-portable/tests/metadata/fixtures.py',
        'crates/smir-portable/tests/metadata/profile_fixtures.py',
        'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json']
    document = dict(scope=__doc__, provenance=provenance(__file__, inputs, manifest), cases=manifest)
    write_text(folder / 'manifest.json', json.dumps(document, indent=2) + '\n')
    print('manifest-symbol whole objects', len(manifest))


if __name__ == '__main__':
    main()
