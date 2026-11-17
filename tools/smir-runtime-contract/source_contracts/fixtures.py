"""Reproduce ONLY this package's new fixtures; --check never writes outputs."""
import argparse
import hashlib
import json
from . import checker as C
from codec import CandidateCodec

DIRECTORY = C.ROOT / 'docs/specifications/smir/portable/conformance/runtime/source-contracts'


def products():
    schemas = {name: json.loads((C.ROOT / 'docs/specifications/smir/portable/schema' /
                                name / 'candidate.json').read_bytes())
               for name in ('abi', 'execution', 'runtime')}
    codec = CandidateCodec(schemas)
    output = {}
    for source in sorted(DIRECTORY.glob('*.source.json')):
        document = json.loads(source.read_bytes())
        roots = {int(n): value for n, value in document['sections'].items()}
        encoded = codec.encode(roots, kind=document.get('kind', 1),
                               entry=document.get('entry', 0xffffffff))
        output[source.name.removesuffix('.source.json') + '.smo'] = encoded
    from .test_checker import matrix
    output['cases.json'] = (json.dumps(matrix(), indent=2, sort_keys=True) + '\n').encode()
    catalog = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
               for name, raw in sorted(output.items())}
    output['generated-catalog.json'] = (json.dumps(dict(
        format='smir-source-contracts-authored-fixtures', revision=1,
        authority=False, products=catalog), indent=2) + '\n').encode()
    source_inputs = sorted(set(DIRECTORY.glob('*.source.json')) |
                           set(DIRECTORY.glob('*.source-contract.json')) |
                           {DIRECTORY / 'address-only-source-closure-left.json',
                            DIRECTORY / 'address-only-source-closure-right.json'})
    oracles = ['tools/smir-format/codec.py',
               'tools/smir-format/execution/candidate/context.py',
               'tools/smir-format/execution/candidate/type_system.py',
               'tools/smir-format/execution/candidate/verify.py',
               'tools/smir-abi/candidate.py', 'tools/smir-abi/nominal.py',
               'tools/smir-abi/layout.py',
               'tools/smir-runtime-contract/source_contracts/checker.py',
               'tools/smir-runtime-contract/source_contracts/identity.py',
               'tools/smir-runtime-contract/source_contracts/comparison_values.py',
               'tools/smir-runtime-contract/source_contracts/observer.py',
               'tools/smir-runtime-contract/source_contracts/observer_fixtures.py',
               'tools/smir-format/execution/candidate/source_observer.py',
               'tools/smir-format/execution/candidate/source_grounding.py',
               'tools/smir-format/execution/candidate/root3_context.py',
               'tools/smir-format/execution/candidate/root3_profile.py',
               'tools/smir-format/execution/candidate/factory_meter.py',
               'tools/smir-abi/factory_meter.py',
               'tools/smir-runtime-contract/source_contracts/test_checker.py']
    def identity(path):
        raw = path.read_bytes()
        return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    provenance = dict(
        format='smir-source-contracts-fixture-provenance', revision=1, authority=False,
        source_origin='corrected-r6-static-contract-witnesses-plus-independent-abi-two-return-counter',
        oracle_kind='current-project-source',
        source_templates={p.name: identity(p) for p in source_inputs},
        oracle_inputs={name: identity(C.ROOT / name) for name in oracles},
        original_pointer=dict(bytes=6558,
            sha256='aa1261d85724c84b880d3ea37f24692710b1b31ab32c9bb829d57449d5017e3c'),
        interpretation='Reproduction source identity only; no observed verification receipt, compiler-origin witness, runtime source facts or native qualification.')
    output['fixture-provenance.json'] = (json.dumps(provenance, indent=2) + '\n').encode()
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    output = products()
    for name, raw in output.items():
        path = DIRECTORY / name
        if args.check:
            if not path.is_file() or path.read_bytes() != raw:
                raise SystemExit('fixture reproduction mismatch: ' + name)
        else:
            path.write_bytes(raw)
    print('source-contract fixtures:', len(output), 'products;',
          'nonwriting check passed' if args.check else 'written in owned prefix')


if __name__ == '__main__':
    main()
