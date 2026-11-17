#!/usr/bin/env python3
"""Independent ABI3/V3 metadata cases; never creates admission authority.

The seed contains source records, not decoder defaults or another role's cases.
Each oracle runs in its own process to preserve canonical package identities.
Generation and verification are linear in total serialized case size, apart
from the genuine owner validators' documented graph bounds.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/metadata-manifest'
DEFAULT_RUST = Path('/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target/debug/smir-inspect')


def load_codec():
    spec = importlib.util.spec_from_file_location('llvm_metadata_wire', ROOT / 'tools/smir-format/codec.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    schemas = {name: json.loads((ROOT / 'docs/specifications/smir/portable/schema' / name / 'candidate.json').read_text())
               for name in ('execution', 'runtime', 'abi')}
    return module.CandidateCodec(schemas)


def ref(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


def some(identifier):
    return {'some': ref(identifier)}


def export(kind, target, execution, nominal, plan=None, linkage='none'):
    return dict(id=0, kind=kind, namespace='independent', name='exported',
                target=ref(target), execution=None if execution is None else some(execution),
                nominal=None if nominal is None else some(nominal),
                abi_signature=None if plan is None else some(plan), source_linkage=linkage)


def declaration(kind, execution, nominal, plan=None, linkage='none', symbol_kind='none'):
    return dict(id=11, kind=kind, namespace='independent', name='needed',
                execution=None if execution is None else some(execution),
                nominal=None if nominal is None else some(nominal),
                abi_signature=None if plan is None else some(plan), source_linkage=linkage,
                symbol_kind=symbol_kind, weak=False)


def cases():
    seed = json.loads((FIXTURES / 'seed.source.json').read_text())
    base = {int(k): v for k, v in seed['sections'].items()}
    base[3]['functions'] = base[3]['functions'][:1]
    base[2]['manifest']['identity'] = '00' * 32  # Recomputed by real wire codec.
    result = {}

    def add(name, mutate=lambda roots: None):
        roots = copy.deepcopy(base)
        mutate(roots)
        result[name] = roots

    def symbol_count(roots):
        body = copy.deepcopy(roots[3]['functions'][0])
        body['id'] = 3
        roots[3]['functions'].append(body)
        for identifier, body_id in ((7, 3), (9, 0)):
            symbol = copy.deepcopy(roots[2]['symbols'][0])
            symbol.update(id=identifier, name='independent_' + str(identifier))
            symbol['definition']['some']['target'] = ref(body_id)
            roots[2]['symbols'].append(symbol)

    def generic(roots):
        roots[3]['functions'][0]['abi_signature'] = None
        roots[2]['symbols'][0].update(source_linkage='none', nominal=None, abi_signature=None)

    def c_linkage(roots):
        nominal = next(t for t in roots[10]['types'] if t['id'] == 12)
        nominal['flags'] = ['c_linkage', 'complete']
        # Genuine ABI fingerprint algorithm, isolated from execution's package.
        program = ('import json,sys;sys.path.insert(0,sys.argv[1]);'
                   'from candidate_fixtures import seal;'
                   'print(json.dumps(seal(json.load(sys.stdin))))')
        output = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT / 'tools/smir-abi')],
                                input=json.dumps(roots[10]), text=True, capture_output=True, check=True)
        roots[10] = json.loads(output.stdout)
        roots[2]['symbols'][0]['source_linkage'] = 'c'

    for personality in ('linux', 'darwin', 'windows'):
        add('personality-' + personality, lambda r, p=personality: r[2]['manifest'].update(personality=p))
    add('zero-function-symbols', lambda r: r[2].update(symbols=[]))
    add('multiple-symbols-shared-body', symbol_count)
    add('generic-function', generic)
    add('c-function', c_linkage)
    add('hidden-control', lambda r: r[2]['symbols'][0].update(visibility='hidden'))
    exports = {'function': export('function', 0, 12, 12, 0, 'cpp'),
               'symbol': export('symbol', 0, 12, 12, 0, 'cpp'),
               'type': export('type', 17, 17, 1),
               'nominal': export('nominal', 1, 1, 1)}
    for kind, value in exports.items():
        add('export-' + kind, lambda r, v=value: r[2]['manifest'].update(exports=[copy.deepcopy(v)]))
    declarations = {'type': declaration('type', 17, 1),
                    'function': declaration('function', 12, 12, 0, 'cpp'),
                    'symbol': declaration('symbol', 12, 12, 0, 'cpp', 'function'),
                    'function-address': declaration('symbol', 900, 12, None, 'cpp', 'function_address'),
                    'nominal': declaration('nominal', None, 1)}

    def dependency(roots, decl):
        roots[2]['manifest']['dependencies'] = [dict(slot=5,
            key=dict(namespace='independent', name='provider', abi_major=1, abi_minor=0),
            minimum_minor=0, maximum_minor={'some': 9}, site=roots[10]['identity'], declarations=[copy.deepcopy(decl)])]

    for kind, value in declarations.items():
        add('declaration-' + kind, lambda r, d=value: dependency(r, d))

    def export_bad(name, kind, field, value):
        def mutate(r):
            item = copy.deepcopy(exports[kind])
            item[field] = value
            r[2]['manifest']['exports'] = [item]
        add(name, mutate)

    export_bad('reject-export-function-target-namespace', 'function', 'target', ref(12))
    add('reject-export-recipe-namespace', lambda r: r[2]['manifest'].update(
        exports=[export('recipe', 0, None, None)]))
    export_bad('reject-export-function-execution', 'function', 'execution', some(17))
    export_bad('reject-export-function-nominal', 'function', 'nominal', some(1))
    export_bad('reject-export-function-plan-missing', 'function', 'abi_signature', None)
    export_bad('reject-export-function-linkage', 'function', 'source_linkage', 'c')
    export_bad('reject-export-type-nominal-binding', 'type', 'nominal', some(12))
    export_bad('reject-export-type-execution-missing', 'type', 'execution', None)
    export_bad('reject-export-dependency-target', 'function', 'target',
               {'module': {'kind': 'dependency', 'slot': 5}, 'id': 11})

    def decl_bad(name, kind, field, value):
        def mutate(r):
            item = copy.deepcopy(declarations[kind])
            item[field] = value
            dependency(r, item)
        add(name, mutate)

    decl_bad('reject-declaration-type-symbol-kind', 'type', 'symbol_kind', 'function')
    decl_bad('reject-declaration-type-weak', 'type', 'weak', True)
    decl_bad('reject-declaration-type-linkage', 'type', 'source_linkage', 'cpp')
    decl_bad('reject-declaration-function-plan-missing', 'function', 'abi_signature', None)
    decl_bad('reject-declaration-symbol-execution', 'symbol', 'execution', some(17))
    decl_bad('reject-declaration-address-execution', 'function-address', 'execution', some(12))
    decl_bad('reject-declaration-address-plan', 'function-address', 'abi_signature', some(0))
    add('reject-symbol-linkage', lambda r: r[2]['symbols'][0].update(source_linkage='c'))
    add('reject-symbol-body-namespace', lambda r: r[2]['symbols'][0]['definition']['some'].update(target=ref(12)))
    add('reject-manifest-site', lambda r: r[2]['manifest'].update(site='ff' * 32))

    def declaration_shape(roots, symbol_kind='none', equivalent=False):
        execution = copy.deepcopy(next(t for t in roots[1]['types'] if t['id'] == 12))
        execution.update(id=300, params=[ref(1 if equivalent else 18)],
                         results=[ref(1 if equivalent else 17)])
        roots[1]['types'].append(execution)
        roots[1]['types'].sort(key=lambda t: t['id'])
        dependency(roots, declaration('function' if symbol_kind == 'none' else 'symbol',
            300, 12, 0, 'cpp', symbol_kind))

    # Original consumer claims: structural aliases remain valid; source-plan
    # transport contradictions must reject even when no instruction uses them.
    add('declaration-function-structural-alias',
        lambda r: declaration_shape(r, equivalent=True))
    decl_bad('reject-declaration-function-scalar', 'function', 'execution', some(17))
    for kind, symbol_kind in [('function', 'none'), ('symbol', 'function'), ('import', 'import')]:
        add('reject-declaration-' + kind + '-plan-execution',
            lambda r, k=symbol_kind: declaration_shape(r, k))
    return result


def python_oracle(payload):
    codec = load_codec()
    sections = codec.decode(payload).roots
    sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
    from candidate.context import RootContext
    from candidate.bindings import runtime_package_module
    context = RootContext(sections)
    context.verify_abi()
    context.verify_execution()
    runtime = runtime_package_module('linking')

    def unavailable(*args):
        raise ValueError('INDEPENDENT_COMDAT_OUTSIDE_SCOPE')

    bound = runtime.Context(site=sections[10]['identity'], execution=context.execution,
        nominal=lambda q: context.abi_entity('nominal', q), function=context.function,
        symbol=context.runtime_symbol, execution_equal=context.types.equal,
        nominal_compatible=context.abi_graph.boundary_compatible, storage_layout=context.memory_layout,
        symbol_body=unavailable, symbol_identity=unavailable, abi_entity=context.abi_entity,
        target_entity=context.target_entity, native_symbol=context.native_symbol,
        nominal_layout=context.source_layout, grants=frozenset(),
        signature_compatible=context.abi_graph.signature_compatible,
        source_compatible=context.source_compatible)
    runtime.validate({n: sections[n] for n in runtime.ROOTS}, bound)
    context.assert_snapshot()
    return {'status': 'verified-static-metadata', 'production_admitted': False,
            'provider_selection_performed': False}


def observe(payload):
    python = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), 'oracle'],
                            input=payload, capture_output=True, check=True)
    return json.loads(python.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('generate', 'oracle'))
    args = parser.parse_args()
    if args.command == 'oracle':
        try:
            report = python_oracle(sys.stdin.buffer.read())
        except Exception as error:
            report = {'status': 'rejected', 'code': getattr(error, 'code', str(error).split(':', 1)[0]),
                      'detail': str(error), 'exception': type(error).__name__}
        print(json.dumps(report, sort_keys=True))
        return
    codec = load_codec()
    manifest = []
    for name, roots in cases().items():
        payload = codec.encode(roots)
        (FIXTURES / (name + '.smo')).write_bytes(payload)
        manifest.append({'name': name, 'sha256': hashlib.sha256(payload).hexdigest(),
                         'python': observe(payload)})
    (FIXTURES / 'observed-python.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': len(manifest), 'fixture_directory': str(FIXTURES)}))


if __name__ == '__main__':
    main()
