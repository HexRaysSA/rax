"""Owned static profile witnesses, encoded by the independent Python codec.

The positive ABI shapes come from frozen compiler-contract witnesses. Source
execution/EH witnesses are separately identified; none is an execution receipt.
"""
from fixture_provenance import provenance, write_bytes, write_text
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE))
from fixtures import prepare_declared_abi2_source, SCHEMAS, SPEC, ref, some
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec


def complete(name):
    sections = json.loads((SPEC / 'conformance/execution/candidate' / (name + '.json')).read_text())['sections']
    sections = {int(k): v for k, v in sections.items()}
    sections.setdefault(5, {'payload_revision': 2, 'relocations': [], 'constant_initializers': []})
    sections.setdefault(7, {'payload_revision': 1, 'segments': []})
    sections.setdefault(9, {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []})
    return sections


def main():
    codec = CandidateCodec(SCHEMAS)
    cases = {}
    service = complete('service-wrapper')
    service[9]['capabilities'] = ['memory']
    cases['service'] = service
    unused_service = deepcopy(service)
    unused_service[3]['functions'] = unused_service[3]['functions'][:1]
    cases['unused-service'] = unused_service
    bad_unused_service = deepcopy(unused_service)
    bad_unused_service[6]['imports'][0]['catalog'] = '00' * 32
    cases['unused-service-bad-catalog'] = bad_unused_service
    storage = complete('storage-tls-wrapper')
    cases['storage'] = storage
    for name, changes in [
        ('storage-prefix-zero-tail', {'initial': '07', 'poison': '00', 'undef': '00', 'zero_fill': 3}),
        ('storage-readonly', {'mutable': False}),
    ]:
        changed = deepcopy(storage)
        changed[4]['segments'][0].update(changes)
        cases[name] = changed
    for name, changes in [
        ('storage-patch-width', {'width': 4}),
        ('storage-patch-overflow', {'offset': 1}),
        ('storage-patch-function-target', {'target': ref(0)}),
        ('storage-patch-valid-unsupported-addend', {'addend': 1}),
    ]:
        changed = deepcopy(storage)
        changed[5]['relocations'][0].update(changes)
        cases[name] = changed
    for name, changes in [
        ('storage-poison-conflict', {'poison': '01000000', 'undef': '01000000'}),
        ('storage-valid-poison', {'poison': '01000000'}),
        ('storage-valid-undef', {'undef': '01000000'}),
        ('storage-missing-layout', {'layout': None}),
        ('storage-bad-binding', {'abi_binding': some(ref(2))}),
        ('storage-extra-extent', {'zero_fill': 1}),
    ]:
        changed = deepcopy(storage)
        changed[4]['segments'][0].update(changes)
        cases[name] = changed
    changed = deepcopy(storage)
    changed[2]['symbols'] = changed[2]['symbols'][:1]
    cases['storage-orphan'] = changed
    changed = deepcopy(storage)
    changed[7]['segments'][0]['initialization'] = 'namespace_dynamic'
    cases['storage-valid-namespace-tls'] = changed
    for name, changes in [
        ('service-bad-catalog', {'catalog': '00' * 32}),
        ('service-bad-version', {'version': 2}),
        ('service-bad-capability', {'capability': 'clock'}),
        ('service-bad-descriptor', {'descriptor': some(ref(0))}),
    ]:
        changed = deepcopy(service)
        changed[6]['imports'][0].update(changes)
        cases[name] = changed
    changed = deepcopy(service)
    changed[9]['capabilities'] = []
    cases['service-missing-capability'] = changed
    changed = deepcopy(storage)
    changed[6]['imports'][0]['options']['target'] = some(ref(99))
    cases['tls-helper-missing-target'] = changed
    changed = deepcopy(storage)
    changed[6]['imports'][0]['options']['alignment'] = 2
    cases['tls-helper-unused-alignment'] = changed
    baseline = complete('portable-identity')
    for kind in ('type', 'nominal', 'function', 'recipe'):
        changed = deepcopy(baseline)
        declaration = {'id': 99, 'kind': kind, 'symbol_kind': 'none', 'source_linkage': 'none',
            'namespace': 'profile', 'name': 'expected_' + kind, 'execution': None,
            'nominal': None, 'abi_signature': None, 'weak': False}
        if kind == 'type':
            declaration['execution'] = some(ref(17))
        if kind == 'nominal':
            declaration['nominal'] = some(ref(1))
        if kind == 'function':
            declaration.update(execution=some(ref(12)), nominal=some(ref(12)),
                source_linkage='cpp', abi_signature=some(ref(0)))
        changed[2]['manifest']['dependencies'] = [{'slot': 7,
            'key': {'namespace': 'profile', 'name': 'provider', 'abi_major': 1, 'abi_minor': 0},
            'minimum_minor': 0, 'maximum_minor': None, 'site': baseline[10]['identity'],
            'declarations': [declaration]}]
        cases['dependency-' + kind] = changed
    changed = deepcopy(cases['dependency-function'])
    changed[2]['manifest']['dependencies'][0]['minimum_minor'] = 1
    cases['dependency-version-range'] = changed
    # Read-only SEM witnesses supply actual CFG/EH records; encode them again
    # with the independent codec and preserve source file identities below.
    sem_sources = {}
    for filename, wanted in [
        ('core-cases.json', {'alloca': 'stack-allocation'}),
        ('phase-cases.json', {'typed_handler_selector': 'typed-handler',
            'static_external_recipe_obligation': 'external-cleanup-journal'}),
    ]:
        source = HERE.parent / 'execution' / filename
        sem_sources[str(source.relative_to(ROOT))] = hashlib.sha256(source.read_bytes()).hexdigest()
        for case in json.loads(source.read_text())['cases']:
            if case['name'] in wanted:
                cases[wanted[case['name']]] = codec.decode(bytes.fromhex(case['encoded_hex'])).roots
    constant = deepcopy(storage)
    signature_id = max(t['id'] for t in constant[1]['types']) + 1
    function_id = max(f['id'] for f in constant[3]['functions']) + 1
    int_id = next(t['id'] for t in constant[1]['types'] if t['kind'] == 'int' and t['bits'] == 32)
    layout_id = next(l['id'] for l in constant[1]['memory_layouts'] if l['type'] == ref(int_id) and l['size'] == 4)
    constant[1]['types'].append({'id': signature_id, 'kind': 'function', 'params': [],
        'results': [ref(int_id)], 'param_noundef': [], 'result_noundef': [False], 'variadic': False, 'cc': 'portable'})
    constant[3]['functions'].append({'id': function_id, 'signature': ref(signature_id),
        'abi_signature': None, 'params': [], 'entry': 0, 'escape': 'propagate', 'no_return': False,
        'blocks': [{'id': 0, 'phis': [], 'ops': [{'op': 'constant', 'results': [{'id': 0, 'type': ref(int_id)}],
            'operands': [], 'literal': {'kind': 'bits', 'value': '2a000000'}}],
            'term': {'op': 'return', 'values': [0]}}]})
    constant[5]['constant_initializers'] = [{'id': 0, 'source_kind': 'data', 'source': 0,
        'offset': 0, 'layout': ref(layout_id), 'function': ref(function_id), 'association': None}]
    cases['constant-initializer'] = constant
    changed = deepcopy(constant)
    changed[1]['types'][-1]['result_noundef'] = [True]
    cases['constant-bad-noundef'] = changed
    changed = deepcopy(constant)
    changed[5]['constant_initializers'][0]['source'] = 1
    cases['constant-patch-overlap'] = changed
    folder = HERE / 'profile-fixtures'
    folder.mkdir(exist_ok=True)
    manifest = {}
    for name, roots in cases.items():
        prepare_declared_abi2_source(roots)
        encoded = codec.encode(roots)
        decoded = codec.decode(encoded)
        if len(decoded.roots) != 10:
            raise RuntimeError('incomplete object')
        write_bytes(folder / (name + '.smo'), encoded)
        manifest[name] = {'sha256': hashlib.sha256(encoded).hexdigest(), 'bytes': len(encoded),
            'content_identity': decoded.content_digest}
    write_text(folder / 'manifest.json', json.dumps({'scope': 'static factory witnesses; no execution',
        'read_only_sem_sources': sem_sources, 'provenance': provenance(__file__, ['crates/smir-portable/tests/metadata/fixtures.py', 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json', 'docs/specifications/smir/portable/conformance/execution/candidate/service-wrapper.json', 'docs/specifications/smir/portable/conformance/execution/candidate/storage-tls-wrapper.json', *sem_sources], manifest), 'cases': manifest}, indent=2) + '\n')
    print('generated', len(manifest), 'complete independent-codec fixtures')


if __name__ == '__main__':
    main()
