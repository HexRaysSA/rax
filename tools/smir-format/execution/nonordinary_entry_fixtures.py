"""Source-authored real descriptors matching actual ABI physical source witness."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / 'tools/smir-abi') not in sys.path:
    sys.path.append(str(ROOT / 'tools/smir-abi'))
from candidate.context import RootContext
from function_address.fixtures import ordinary, seal, source, layout
from record_layout.test_source_programs import document, method, q, budget

def physical(*, vtt=False, noexcept=False, escape='propagate', sret=False, destructor=False):
    roots = ordinary(complete_record=True)
    roots[10]['journals'].append(dict(id=700, signature=201, params=[], slots=[], normal_order=[], exception_order=[]))
    roots[10]['types'] += [source(1500, 'void'), source(1501, 'function', elements=[100 if sret else 1500], extent=0, flags=['complete'] + (['noexcept'] if noexcept else [])), source(1510, 'pointer', elements=[100], bits=64, execution=1002, layout_id=1510, representation='value', flags=['complete', 'trivial_copy', 'trivial_destroy'])]
    roots[10]['layouts'].append(layout(1510, 8, 8))
    params = []
    if sret:
        params.append(dict(source_index=None, role='sret', source_type=q(100), value_type=q(1510), mode='sret', align=4, bytes=4, noundef=True, copy=None, move=None, destroy=None))
    params.append(dict(source_index=None, role='this', source_type=q(1510), value_type=q(1510), mode='direct', align=8, bytes=8, noundef=True, copy=None, move=None, destroy=None))
    if vtt:
        roots[10]['types'].append(source(1511, 'pointer', elements=[1500], bits=64, execution=1002, layout_id=1511, representation='value', flags=['complete', 'trivial_copy', 'trivial_destroy']))
        roots[10]['layouts'].append(layout(1511, 8, 8))
        params.append(dict(source_index=None, role='vtt', source_type=q(1511), value_type=q(1511), mode='direct', align=8, bytes=8, noundef=True, copy=None, move=None, destroy=None))
    roots[1]['types'].append(dict(id=1800, kind='function', cc='portable', variadic=False, params=[q(1002)] * len(params), results=[], param_noundef=[True] * len(params), result_noundef=[]))
    roots[3]['functions'].append(dict(id=1800, signature=q(1800), abi_signature=dict(some=q(202)), params=[dict(id=i, type=q(1002)) for i in range(len(params))], entry=0, escape=escape, no_return=False, blocks=[dict(id=0, phis=[], ops=[], term=dict(op='return', values=[]))]))
    roots[10]['signatures'].append(dict(id=202, function_type=q(1501), params=[], result=dict(some=q(100)) if sret else None, this_type=dict(some=q(1510)), vtt=vtt, variadic=False, noexcept=noexcept, lowered_params=params, lowered_results=[], varargs=None, return_noundef=True, execution=q(1800)))
    d = document()
    d['records'][0]['name'] = 'example.R'
    if not sret:
        actual = next((t for t in roots[10]['types'] if t['id'] == 100))
        name = 'example.R::~R' if destructor else 'example.R::R'
        actual['methods'] = [dict(name=name, signature=q(1501), virtual=False, slot=None, noexcept=noexcept)]
        d['methods'] = [method(0, 0, kind='destructor' if destructor else 'constructor', name=name, declaration_index=0, signature=q(1501), trivial=True, user_provided=False, has_definition=True, noexcept=noexcept)]
        if destructor:
            d['programs'][0].update(variant='complete_destructor', method=0, steps=[0])
            d['cleanups'][0]['destructor'] = 0
        else:
            d['programs'][0].update(variant='trivial_init', method=0)
        d['programs'][0]['implementation'] = dict(function=q(1800), call_signature=q(202), execution=q(1800), uses_vtt=vtt)
    seal(roots)
    return (roots, d)

def associated(roots, document, ledger):
    from record_layout import source_programs as S
    owner = RootContext(roots)
    owner.verify_abi()
    stamp = owner.prepare_source_data(budget=ledger)
    key = roots[2]['manifest']['key']
    document['contexts'][0].update(family={n: key[n] for n in ('namespace', 'name', 'abi_major')}, abi_site=roots[10]['identity'], abi_root=dict(stamp.root_digests)[10].hex(), module_root=dict(stamp.root_digests)[2].hex())
    report = S.check_source_associations(document, owner, 0, budget=ledger)
    return (owner, report)

def root_codec():
    """Load the original framing codec without shadowing legacy execution.codec."""
    import importlib.util
    name = '_rax_smir_nonordinary_fixture_codec_v1'
    path = (ROOT / 'tools/smir-format/codec.py').resolve()
    module = sys.modules.get(name)
    if module is not None:
        if Path(module.__file__).resolve() != path:
            raise RuntimeError('Nonordinary fixture codec module identity')
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def encoded(roots):
    import json
    codec = root_codec()
    schemas = {name: json.loads((ROOT / 'docs/specifications/smir/portable/schema' /
                                name / 'candidate.json').read_bytes())
               for name in ('execution', 'runtime', 'abi')}
    manifest = roots[2]['manifest']
    entry = manifest['entry']
    return codec.CandidateCodec(schemas).encode(
        roots, kind={'object': 1, 'image': 2}[manifest['kind']],
        entry=codec.NO_ENTRY if entry is None else entry['some']['id'])


def generated():
    """Reproduce inert source, ABI descriptors and bytes with real owner checks."""
    import json
    outputs = {}
    for name, options in (('constructor', {}), ('constructor-vtt', dict(vtt=True)), ('destructor', dict(destructor=True)), ('method-sret', dict(sret=True))):
        roots, descriptor = physical(**options)
        owner, _ = associated(roots, descriptor, budget())
        owner.verify_execution()
        source = dict(sections={str(k): value for k, value in roots.items()})
        outputs[name + '.source.json'] = (json.dumps(source, indent=2) + '\n').encode()
        outputs[name + '.abi.json'] = (json.dumps(descriptor, indent=2) + '\n').encode()
        outputs[name + '.smo'] = encoded(roots)
    return outputs

def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    arguments = parser.parse_args()
    directory = ROOT / 'docs/specifications/smir/portable/conformance/execution/nonordinary-entry-associations'
    outputs = generated()
    if arguments.check:
        changed = [name for name, contents in outputs.items() if not (directory / name).is_file() or (directory / name).read_bytes() != contents]
        if changed:
            parser.exit(1, 'Fixture mismatch: ' + ', '.join(changed) + '\n')
    else:
        directory.mkdir(parents=True, exist_ok=True)
        for name, contents in outputs.items():
            (directory / name).write_bytes(contents)
    print(str(len(outputs)) + ' nonordinary-entry fixture files ' + ('unchanged' if arguments.check else 'written'))
if __name__ == '__main__':
    main()
