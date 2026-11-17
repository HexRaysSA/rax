"""Provenance and exact payload-size accounting for owned P2 test generators."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
COMMON = ['tools/smir-format/codec.py',
    'tools/smir-runtime-contract/generate_service_type_fixtures.py',
    'tools/smir-abi/nominal.py', 'tools/smir-abi/layout.py', 'tools/smir-abi/graph_identity.py',
    'tools/smir-abi/factory_meter.py', 'tools/smir-abi/contract_json.py',
    'docs/specifications/smir/portable/schema/execution/candidate.json',
    'docs/specifications/smir/portable/schema/runtime/candidate.json',
    'docs/specifications/smir/portable/schema/abi/candidate.json',
    'crates/smir-portable/tests/metadata/fixture_provenance.py']


TRANSITIVE_INPUTS = {'crates/smir-portable/tests/metadata/fixtures.py': ['docs/specifications/smir/portable/schema/runtime/helpers-v1.json'], 'crates/smir-portable/tests/metadata/helper_catalog_fixtures.py': ['crates/smir-portable/tests/metadata/legacy-abi1/atomic_flag_clear.smo', 'crates/smir-portable/tests/metadata/legacy-abi1/atomic_flag_test.smo', 'crates/smir-portable/tests/metadata/legacy-abi1/atomic_flag_test_and_set.smo', 'crates/smir-portable/tests/metadata/legacy-abi1/manifest.json']}

def provenance(generator, inputs, cases):
    generator = Path(generator).resolve()
    paths = sorted(set(COMMON + inputs + TRANSITIVE_INPUTS.get(str(generator.relative_to(ROOT)), [])))
    return {'generator': str(generator.relative_to(ROOT)),
        'generator_sha256': hashlib.sha256(generator.read_bytes()).hexdigest(),
        'input_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths},
        'command': 'python3 -B ' + str(generator.relative_to(ROOT)),
        'object_count': len(cases), 'encoded_object_bytes': sum(case['bytes'] for case in cases.values()),
        'size_justification': 'Complete ten-root objects preserve real framing, content identity and '
            'cross-namespace declarations for independent type/ABI/metadata/program tests. '
            'Each manifest explicitly distinguishes component predicates from complete factories; '
            'no runtime certificate is encoded. Deterministic generator/input SHA256 and per-object '
            'hashes make the generated corpus reproducible.'}


def write_bytes(path, data):
    import sys
    path = Path(path)
    if '--check' in sys.argv:
        if path.read_bytes() != data:
            raise RuntimeError('stale generated object: ' + str(path))
    else:
        path.write_bytes(data)


def write_text(path, value):
    write_bytes(path, value.encode('utf8'))
