"""Regenerate SEMANTICS-owned candidate fixtures from explicit draft contracts.

Reads the ABI owner's declaration producer without writing its fixtures. Source
digests identify those inputs; synthetic domain labels remain explicitly synthetic.
"""
from copy import deepcopy
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import subprocess
import sys

from common import ROOT, SPEC
from candidate.type_system import ref
from test_candidate import block, constant, decl, fixture, operation

BASE = SPEC / 'conformance/execution/candidate'


@lru_cache(maxsize=1)
def _declared_abi_source():
    """Read the actual ABI2 declaration producer without shadowing candidate.

    This subprocess only calls build(); running its module as a script would
    write ABI-owned fixtures and is deliberately not used here. Returned data is
    fixture source metadata, never a semantic/native certificate.
    """
    result = subprocess.run(
        [sys.executable, '-B', '-c',
         'import json; from candidate_fixtures import build; print(json.dumps(build()))'],
        cwd=ROOT / 'tools/smir-abi', check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def declared_abi_source():
    """Fresh caller-owned copies of explicit source declarations and evidence."""
    return deepcopy(_declared_abi_source())


def seal_declared_abi(document):
    """Recompute V3 identities from declared records, without admitting them."""
    result = subprocess.run(
        [sys.executable, '-B', '-c',
         'import json,sys; from candidate_fixtures import seal; '
         'print(json.dumps(seal(json.load(sys.stdin))))'],
        cwd=ROOT / 'tools/smir-abi', input=json.dumps(document),
        check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def canonical_helper_source(sections, family):
    """Merge accepted ABI034REV2 fixture fragments and seal the actual graph.

    These are explicitly private caller allocations. No public IDs, source AST,
    layout authority or live helper association is inferred by the producer.
    """
    if family not in {'va', 'jmp'}:
        raise ValueError('SEM_SOURCE_FIXTURE_FAMILY')
    source_keys = ['uint32', 'uint64', 'va_state', 'jmp_state', 'va_list', 'jmp_buf']
    execution_keys = ['uint32', 'uint64', 'raw8', 'state_bytes', 'list_wrapper']
    source_ids = dict(zip(source_keys, range(1000, 1006)))
    execution_ids = dict(zip(execution_keys, range(1000, 1005)))
    domains = [d for d in sections[10]['domains'] if d['isa'] == 'portable']
    if len(domains) != 1:
        raise ValueError('SEM_SOURCE_FIXTURE_DOMAIN')
    arguments = dict(source_ids=source_ids, execution_ids=execution_ids, domain_id=domains[0]['id'])
    process = subprocess.run([sys.executable, '-B', '-c',
        'import json,sys; from source_roles.builder import build_builtin_states; '
        'print(json.dumps(build_builtin_states(**json.load(sys.stdin))))'],
        cwd=ROOT / 'tools/smir-abi', input=json.dumps(arguments),
        check=True, capture_output=True, text=True)
    fragment = json.loads(process.stdout)
    for root, table, new in [(10, 'types', fragment['types']),
                             (10, 'layouts', fragment['layouts']),
                             (1, 'types', fragment['execution_graph'])]:
        if {t['id'] for t in sections[root][table]} & {t['id'] for t in new}:
            raise ValueError('SEM_SOURCE_FIXTURE_ID_COLLISION')
        sections[root][table] += new
        sections[root][table].sort(key=lambda t: t['id'])
    sections[10] = seal_declared_abi(sections[10])
    return fragment['va_list' if family == 'va' else 'jmp_buf']


def portable_identity():
    sources = [ROOT / 'tools/smir-abi' / name for name in
               ['candidate_fixtures.py', 'nominal.py', 'execution_shapes.py', 'site_config.py']]
    sources += [SPEC / 'schema/abi' / name for name in ['candidate.json', 'site.json']]
    abi, evidence = declared_abi_source()
    abi['types'] = [item for item in abi['types'] if item['id'] in (1, 12)]
    abi['layouts'] = [item for item in abi['layouts'] if item['id'] == 1]
    abi['signatures'] = [item for item in abi['signatures'] if item['id'] == 0]
    abi['domains'] = [item for item in abi['domains'] if item['id'] == 0]
    for name in ['storage_bindings', 'recipes', 'personalities', 'unwind', 'catches', 'bridges', 'journals']:
        abi[name] = []
    some = lambda value: {'some': value}
    sections = {1: {'payload_revision': 2, 'types': evidence['execution_graph'],
                     'memory_layouts': list(evidence['memory_layouts'].values())},
        2: {'payload_revision': 2, 'manifest': {'identity': '0' * 64,
            'key': {'namespace': 'example', 'name': 'identity', 'abi_major': 1, 'abi_minor': 0},
            'kind': 'object', 'entry': None, 'site': abi['identity'], 'personality': 'linux',
            'foreign_isa': 'none', 'dependencies': [], 'exports': []},
            'symbols': [{'id': 0, 'namespace': 'example', 'name': '_Z8identityi', 'kind': 'function', 'source_linkage': 'cpp',
                'binding': 'strong', 'visibility': 'default', 'execution': ref(12), 'nominal': some(ref(12)),
                'abi_signature': some(ref(0)),
                'definition': some({'kind': 'function', 'target': ref(0)}), 'size': None, 'alignment': 1,
                'comdat': None, 'fallback': None}], 'comdats': [], 'initializers': [], 'finalizers': []},
        3: {'payload_revision': 2, 'functions': [{'id': 0, 'signature': ref(12), 'abi_signature': some(ref(0)),
            'params': [decl(0, 17)], 'entry': 0, 'escape': 'propagate', 'no_return': False,
            'blocks': [block(0, [], {'op': 'return', 'values': [0]})]}]},
        4: {'payload_revision': 1, 'segments': []}, 6: {'payload_revision': 1, 'imports': []},
        8: {'payload_revision': 1, 'functions': []}, 10: abi}
    return {'purpose': 'Portable-only joint-root semantic witness. Domain compiler/runtime/build/library hashes '
            'are synthetic fixture labels, not native runtime provenance. Full ten-root runtime linking still required.',
            'sources': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
            'sections': sections}


def cases():
    result = []
    def add(name, roots, expected):
        result.append({'id': name, 'sections': dict(zip(['1', '3', '8'], deepcopy(roots))), 'expected': expected})
    add('identity42', fixture(), {'kind': 'return', 'bits': 42})
    roots = fixture()
    roots[1]['functions'][0]['blocks'][0]['ops'] = [
        operation('constant', [decl(0, 9)], literal={'kind': 'aggregate', 'elements': [
            {'kind': 'poison'}, {'kind': 'bits', 'value': '2a000000'}]}),
        operation('extract', [decl(1, 2)], [0], indices=[1])]
    roots[1]['functions'][0]['blocks'][0]['term']['values'] = [1]
    add('unobserved_component_poison', roots, {'kind': 'return', 'bits': 42})
    roots = fixture()
    roots[1]['functions'][0]['blocks'][0]['ops'] = [constant(0, 2, '01000000'), constant(1, 2, '00000000'),
        operation('i_udiv', [decl(2, 2)], [0, 1], flags=[])]
    roots[1]['functions'][0]['blocks'][0]['term']['values'] = [2]
    add('executed_divzero', roots, {'kind': 'language_ub', 'reason': 'ub_div_zero'})
    roots = fixture()
    roots[1]['functions'][0]['blocks'][0]['term']['values'] = [99]
    add('undefined_ssa', roots, {'kind': 'reject', 'code': 'ssa_reference'})
    roots = fixture()
    roots[0]['types'][15]['param_noundef'] = [False]
    add('signature_attribute_arity', roots, {'kind': 'reject', 'code': 'type_signature'})
    roots = fixture()
    roots[0]['types'][15]['variadic'] = True
    add('source_ellipsis_not_execution', roots, {'kind': 'reject', 'code': 'calling_convention'})
    roots = fixture()
    roots[1]['functions'][0]['blocks'][0]['ops'][0]['literal']['value'] = '2a00000000'
    add('noncanonical_integer_width', roots, {'kind': 'reject', 'code': 'constant'})
    return {'revision': 'candidate_execution_conformance_v1', 'cases': result}


if __name__ == '__main__':
    BASE.mkdir(exist_ok=True)
    for name, document in [('portable-identity.json', portable_identity()), ('cases.json', cases())]:
        (BASE / name).write_text(json.dumps(document, indent=2) + '\n')
    rejected = portable_identity()
    sections = rejected['sections']
    sections[1]['memory_layouts'].append({'id': 5, 'type': ref(5), 'size': 8, 'alignment': 4,
        'access_bytes': 8, 'fields': [], 'element': None, 'stride': 0})
    sections[10]['storage_bindings'] = [{'id': 0, 'nominal': ref(1), 'execution_layout': ref(5),
        'kind': 'fieldwise', 'view_offset_bits': 0, 'view_width_bits': 32, 'required_alignment': 4,
        'access_bytes': 8, 'fragments': [{'source_offset_bits': 0, 'execution_offset_bits': 0,
            'width_bits': 32, 'source_path': [], 'role': 'value'}]}]
    rejected['purpose'] = 'Reject sourceint32 binding whose 8-byte effect exceeds4-byte nominal object (S044/ABI032).'
    (BASE / 'reject-storage-effect.json').write_text(json.dumps(rejected, indent=2) + '\n')
    from test_candidate_services import service_wrapper
    (BASE / 'service-wrapper.json').write_text(json.dumps({
        'purpose': 'Library Object: internal memory.map multiresult primitive within separately ABI-verified source wrapper. '
                   'Reference adapters only; full runtime admission required.', 'sections': service_wrapper()}, indent=2) + '\n')
    from test_candidate_storage_join import storage_wrapper
    joined = storage_wrapper()
    (BASE / 'storage-tls-wrapper.json').write_text(json.dumps({
        'purpose': 'Library Object: actual source/layout/data/TLS/relocation joins. Source wrapper computes27+7+8=42. '
                   'Allocation bytes differ from typed pointer/integer SSA views. Sequential reference loader only.',
        'sections': joined}, indent=2) + '\n')
    joined[4]['segments'][0]['abi_binding'] = {'some': ref(1)}
    (BASE / 'reject-segment-binding.json').write_text(json.dumps({
        'purpose': 'ABI and code bindings individually valid, but segment B4 references typed-i32 physical binding. '
                   'The actual runtime root validator must reject this cross-section join.',
        'sections': joined}, indent=2) + '\n')
