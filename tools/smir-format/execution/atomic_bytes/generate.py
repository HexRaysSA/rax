"""Author only the new draft scalar Raw8 atomic fixture corpus."""
from copy import deepcopy
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[4]
FOLDER = ROOT/'docs/specifications/smir/portable/conformance/execution/atomic-bytes'
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT/'tools/smir-format/execution'))
from atomic_bytes.contract import cases, observe
from candidate.function_address_contract import source_roots


def codec():
    name = '_rax_raw8_atomic_fixture_codec'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT/'tools/smir-format/codec.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    schemas = {n: json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())
               for n in ('execution', 'abi', 'runtime')}
    return sys.modules[name].CandidateCodec(schemas)


def product():
    encoder = codec()
    base = source_roots()
    encoded = []
    for row in cases():
        actual = observe(row['roots'])
        if actual != row['expected']:
            raise RuntimeError(row['id']+': expected '+row['expected']+', actual '+actual)
        sections = {**deepcopy(base), **dict(zip((1, 3, 8), deepcopy(row['roots'])))}
        sections[2]['symbols'] = []
        wire = encoder.encode(sections)
        encoded.append(dict(id=row['id'], expected=row['expected'], rust_expected=row['rust_expected'],
                            encoded_hex=wire.hex(), sha256=hashlib.sha256(wire).hexdigest()))
    return (json.dumps(dict(format='scalar-raw8-atomic-static-fixtures', revision=1,
        contract='DRAFT ABI-SOURCE-BYTE-TRANSPORT-01+02+03+04',
        scope='Independent execution-local static checks. Enclosing ABI/site/source semantic admission, parallel memory and native execution are not asserted.',
        cases=encoded), indent=2)+'\n').encode()


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['--check']):
        raise SystemExit('usage: generate.py [--check]')
    raw = product()
    path = FOLDER/'cases.json'
    if '--check' in sys.argv:
        if path.read_bytes() != raw:
            raise SystemExit('scalar Raw8 atomic fixture drift')
    else:
        FOLDER.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    print(json.dumps(dict(cases=len(cases()), files=1, bytes=len(raw), checked='--check' in sys.argv)))
