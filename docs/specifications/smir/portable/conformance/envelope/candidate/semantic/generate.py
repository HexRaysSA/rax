#!/usr/bin/env python3
"""Reseal declared join-negative inputs; preserve their semantic expectations.

This tool checks representation only. Run the independent reference CLI tests
to establish that each input still reaches its intended semantic rejection.
"""
from pathlib import Path
import copy
import hashlib
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[8]
SPEC = ROOT / 'docs/specifications/smir/portable'
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec
sys.path.insert(0, str(ROOT / 'tools/smir-abi'))
from nominal import NominalGraph

EXPECTED = {
    'function-source-nominal': 'RT_FUNCTION_SOURCE_TYPE',
    'import-symbol-signature': 'RT_IMPORT_SIGNATURE',
    'tls-destructor-signature': 'RT_TLS_HOOK_SIGNATURE',
    'tls-initializer-signature': 'RT_TLS_HOOK_SIGNATURE',
}


def generate(check):
    schemas = {owner: json.loads((SPEC / f'schema/{owner}/candidate.json').read_text())
               for owner in ('execution', 'runtime', 'abi')}
    codec = CandidateCodec(schemas)
    schema_hashes = {owner: hashlib.sha256((SPEC / f'schema/{owner}/candidate.json').read_bytes()).hexdigest()
                     for owner in schemas}
    sources = {Path(__file__).resolve()}
    for module in tuple(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ROOT) and path.suffix == '.py':
                sources.add(path)
    inputs = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(sources)}
    folder = Path(__file__).parent
    if {path.stem for path in folder.glob('*.json')} != set(EXPECTED):
        raise ValueError('Unexpected semantic fixture inventory')
    for name, expected in EXPECTED.items():
        path = folder / (name + '.json')
        original = path.read_text()
        document = json.loads(original)
        if document['expected_error'] != expected:
            raise ValueError('Semantic diagnostic changed: ' + name)
        # Start with current source-authored positives, then apply the original
        # semantic counter. Old encoded bytes are never parsed or upgraded.
        base_name = ('portable-identity.json' if name == 'function-source-nominal'
                     else 'service-wrapper.json' if name == 'import-symbol-signature'
                     else 'storage-tls-wrapper.json')
        base_path = SPEC / 'conformance/execution/candidate' / base_name
        base = json.loads(base_path.read_text())
        roots = {int(key): copy.deepcopy(value) for key, value in base['sections'].items()}
        roots.setdefault(5, {'payload_revision': 2, 'relocations': [], 'constant_initializers': []})
        roots.setdefault(7, {'payload_revision': 1, 'segments': []})
        roots.setdefault(9, {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []})
        # The original import/TLS controls declare memory; the independent CLI
        # supplies that grant before testing the join. The function control
        # deliberately has no capability requirement.
        if name != 'function-source-nominal':
            roots[9]['capabilities'] = ['memory']
        abi = roots[10]
        reference = lambda identifier: {'module': {'kind': 'self'}, 'id': identifier}
        if name == 'function-source-nominal':
            nominal = copy.deepcopy(next(t for t in abi['types'] if t['id'] == 12))
            nominal['id'] = 13
            nominal['flags'] = ['complete', 'c_linkage']
            abi['types'].append(nominal)
            abi['types'].sort(key=lambda typ: typ['id'])
            plan = copy.deepcopy(abi['signatures'][0])
            plan.update(id=1, function_type=reference(13), execution=reference(12))
            abi['signatures'].append(plan)
            roots[2]['symbols'][0].update(nominal={'some': reference(13)},
                                          abi_signature={'some': reference(1)})
        elif name == 'import-symbol-signature':
            symbol = copy.deepcopy(roots[2]['symbols'][0])
            symbol.update(id=1, name='mapping', kind='import', source_linkage='none',
                          execution=reference(12), nominal=None, abi_signature=None,
                          definition={'some': {'kind': 'import', 'import': 0}})
            roots[2]['symbols'].append(symbol)
        else:
            tls = roots[7]['segments'][0]
            if name == 'tls-destructor-signature':
                tls.update(initializers=[], destructors=[reference(0)], initialization='static')
            else:
                tls.update(initializers=[reference(0)], destructors=[], initialization='block_dynamic')
        graph = NominalGraph(abi, 'local')
        for typ in abi['types']:
            if 'complete' in typ['flags']:
                typ['identity']['definition'] = graph.fingerprint(
                    {'module': {'kind': 'self'}, 'id': typ['id']})
        encoded = codec.encode(roots)
        decoded = codec.decode(encoded)
        document['sections'] = {str(key): value for key, value in decoded.roots.items()}
        document['encoded_hex'] = encoded.hex()
        document['sha256'] = hashlib.sha256(encoded).hexdigest()
        document['schema_sha256'] = schema_hashes
        if 'migration_history' not in document:
            document['migration_history'] = [document.get('migration', '')]
        document['migration'] = 'CodeAddress cut: current source positive plus original explicit semantic counter; ABI3/V3 and mandatory call fields authored by source; no old-byte upgrade'
        document['source_recipe'] = {'base': str(base_path.relative_to(ROOT)),
                                     'base_sha256': hashlib.sha256(base_path.read_bytes()).hexdigest(),
                                     'counter': name}
        document['generator'] = str(Path(__file__).resolve().relative_to(ROOT))
        document['generator_inputs'] = inputs
        rendered = json.dumps(document, indent=2) + '\n'
        if check:
            if original != rendered:
                raise ValueError('Stale generated semantic fixture: ' + name)
        else:
            path.write_text(rendered)
        print(name, len(encoded), expected, 'representation-only')


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['--check']):
        raise SystemExit('usage: generate.py [--check]')
    generate(bool(sys.argv[1:]))
