"""Nonwriting reproduction checks for raw original-owner grounding witnesses."""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[6]
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
from reference_grounding import fixture, budget
from reference_cfg import diamond, merged_phi, looping
from reference_retained import retained
from reference_scope_uses import enclosing
from reference_origins import original_cycle
from candidate.context import RootContext
from candidate.bindings import runtime_package_module
from candidate import source_grounding as G


def canonical(value):
    return (json.dumps(value, indent=2) + '\n').encode('utf8')


def emit():
    schemas = {name: json.loads((ROOT / 'docs/specifications/smir/portable/schema' /
                               name / 'candidate.json').read_bytes())
               for name in ('abi', 'execution', 'runtime')}
    codec = runtime_package_module('wire').PRIMITIVES.CandidateCodec(schemas)
    variants = [('published', lambda: fixture()), ('diamond', lambda: diamond()),
                ('phi', merged_phi), ('loop', looping),
                ('missing-exit', lambda: diamond(True)), ('live-reentry', lambda: looping(True)),
                ('caller-leak', lambda: fixture(True)),
                ('retained-live', retained), ('retained-stale', lambda: retained('stale')),
                ('parent-live', enclosing), ('parent-stale', lambda: enclosing('stale')),
                ('origin-rooted', lambda: original_cycle(False)),
                ('origin-cycle', lambda: original_cycle(True))]
    outputs, cases = {}, []
    for name, create in variants:
        owner, request, _ = create()
        packed = codec.encode(owner.sections)
        # Coordinates name the ACTUAL encoded module, including its identity word.
        roots = codec.decode(packed).roots
        owner = RootContext(roots)
        ledger = budget()
        stamp = RootContext.prepare_source_data(owner, budget=ledger)
        context = request['source_join']['contexts'][0]
        family = {key: roots[2]['manifest']['key'][key]
                  for key in ('namespace', 'name', 'abi_major')}
        context.update(family=family, abi_site=roots[10]['identity'],
                       schema_digest=stamp.schema_digest.hex(),
                       roots=[dict(section=n, digest=h.hex()) for n, h in stamp.root_digests])
        request['abi_programs']['contexts'][0].update(
            family=family, abi_site=roots[10]['identity'],
            abi_root=dict(stamp.root_digests)[10].hex(),
            module_root=dict(stamp.root_digests)[2].hex())
        try:
            result = G.ground(owner, request, budget=ledger)
            expected = dict(status='grounded-constraints',
                            canonical_bindings=[list(x) for x in result.canonical_bindings],
                            checked_journals=[list(x) for x in result.checked_journals])
        except Exception as error:
            code = getattr(error, 'code', None)
            if code is None:
                raise
            expected = dict(status='rejected', code=code)
        files = {name + '.smo': packed,
                 name + '.source.json': canonical(dict(sections={str(k): v for k, v in roots.items()})),
                 name + '.request.json': canonical(request)}
        outputs.update(files)
        cases.append(dict(name=name, expected=expected,
                          files={filename: dict(sha256=hashlib.sha256(raw).hexdigest(), octets=len(raw))
                                 for filename, raw in files.items()}))
    outputs['manifest.json'] = canonical(dict(
        format='source-grounding-original-fixtures', revision=1,
        binding='unbound', runtime_authority=False, source_fact_authority=False,
        native_execution=False, cases=cases))
    return outputs


def main():
    if sys.argv[1:] not in ([], ['--check']):
        raise SystemExit('usage: generate_fixtures.py [--check]')
    outputs = emit()
    directory = HERE / 'fixtures'
    if '--check' in sys.argv:
        changed = [name for name, raw in outputs.items()
                   if not (directory / name).is_file() or (directory / name).read_bytes() != raw]
        if changed:
            raise SystemExit('fixture mismatch: ' + ', '.join(changed))
    else:
        directory.mkdir(exist_ok=True)
        for name, raw in outputs.items():
            (directory / name).write_bytes(raw)
    print(json.dumps(dict(files=len(outputs), octets=sum(map(len, outputs.values())),
                          checked='--check' in sys.argv)))


if __name__ == '__main__':
    main()
