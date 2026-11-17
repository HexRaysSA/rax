#!/usr/bin/env python3
"""Validate contract accounting; optionally require a compiler freeze candidate.

A normal pass establishes internal consistency, including an honestly closed
admission gate. It never treats the existence of a schema as implementation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from codec import CandidateCodec, RecordCodec

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / 'docs/specifications/smir/portable'
COMPONENT_OWNERS = {
    'envelope-codecs': 'INTEGRATOR',
    'execution-types': 'SEMANTICS',
    'execution-operations': 'SEMANTICS',
    'exception-records': 'SEMANTICS',
    'portable-abi': 'ABI',
    'foreign-descriptors': 'ABI',
    'memory-concurrency': 'RUNTIME',
    'linking-imports': 'RUNTIME',
    'jit-state-transfer': 'RUNTIME',
    'packaging': 'RUNTIME',
    'llvm-frontend': 'LLVM',
    'llvm-lowering': 'LLVM',
    'hosted-baseline': 'LLVM',
}
REQUIRED_DECISIONS = {
    'execution-abi': {'SEMANTICS', 'ABI', 'LLVM'},
    'poison-refinement': {'SEMANTICS', 'LLVM'},
    'memory-imports-eh': {'SEMANTICS', 'ABI', 'RUNTIME', 'LLVM'},
    'frontend-layout': {'ABI', 'LLVM'},
}
REQUIREMENT_STATUSES = {
    'draft', 'specified', 'implemented', 'verified-framing-only',
    'verified-reference-only', 'verified', 'unsupported',
}
CANDIDATE_OWNERS = {
    1: 'SEMANTICS', 2: 'RUNTIME', 3: 'SEMANTICS', 4: 'RUNTIME', 5: 'RUNTIME',
    6: 'RUNTIME', 7: 'RUNTIME', 8: 'SEMANTICS', 9: 'RUNTIME', 10: 'ABI',
}
CANDIDATE_NAMES = dict(enumerate((
    'types', 'symbols', 'functions', 'data', 'relocations', 'imports', 'tls',
    'exceptions', 'capabilities', 'abi-contract'), 1))
SCHEMA_PREFIX = 'docs/specifications/smir/portable/schema/'
ACCOUNTING_PATHS = frozenset('docs/specifications/smir/portable/' + name for name in (
    'status.json', 'validation.json', 'compiler-contract.json', 'contract-closure.json'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def load_json(path):
    def reject_constant(token):
        raise ValueError(f'non-finite JSON constant: {token}')

    return json.loads(path.read_text(), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def artifact_bytes(root, relative):
    require(isinstance(relative, str), 'artifact path must be a string')
    path = Path(relative)
    require(not path.is_absolute() and '..' not in path.parts, 'artifact path escapes root')
    resolved = (root / path).resolve()
    require(resolved.is_relative_to(root.resolve()), 'artifact symlink escapes root')
    require(resolved.is_file(), f'missing artifact: {relative}')
    return resolved.read_bytes()


def check_artifacts(records, root):
    require(isinstance(records, list), 'artifacts must be an array')
    paths = set()
    for record in records:
        require(set(record) == {'path', 'sha256'}, 'artifact record fields')
        require(record['path'] not in paths, 'duplicate artifact path')
        paths.add(record['path'])
        digest = hashlib.sha256(artifact_bytes(root, record['path'])).hexdigest()
        require(record['sha256'] == digest, f'stale artifact: {record["path"]}')
    return paths


def check_input_inventory(receipt, root, paths):
    """New source/test files also invalidate a declared recursive receipt."""
    if 'input_roots' not in receipt:
        return
    require(isinstance(receipt['input_roots'], list) and receipt['input_roots'],
            'receipt input roots')
    current = set()
    for relative in receipt['input_roots']:
        require(isinstance(relative, str) and not Path(relative).is_absolute()
                and '..' not in Path(relative).parts, 'receipt input root escapes root')
        item = root / relative
        require(item.resolve().is_relative_to(root.resolve()), 'receipt input root escapes root')
        require(item.exists(), f'missing receipt input root: {relative}')
        files = [item] if item.is_file() else item.rglob('*')
        for path in files:
            if path.is_file() and '__pycache__' not in path.parts and path.name != '.DS_Store':
                current.add(str(path.relative_to(root)))
    require(current == paths, 'stale receipt input inventory')


def candidate_hash(components):
    """Content identity independent of formatting and validation-receipt order."""
    inputs = {item['path']: item['sha256']
              for component in components for item in component['artifacts']}
    encoded = json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def candidate_review_blockers(manifest):
    """Check exact recorded reviews; text checksums do not authenticate people."""
    reviews = manifest.get('candidate_acknowledgements', [])
    require(type(reviews) is list, 'candidate reviews must be a list')
    owners = {role: {name for name, owner in COMPONENT_OWNERS.items() if owner == role}
              for role in set(COMPONENT_OWNERS.values())}
    seen, blockers = set(), []
    fields = {'role', 'candidate_sha256', 'components', 'statement', 'statement_sha256'}
    for review in reviews:
        require(type(review) is dict and set(review) == fields, 'candidate review fields')
        role = review['role']
        require(type(role) is str and role in owners and role not in seen,
                'unknown or duplicate candidate reviewer')
        seen.add(role)
        digest = review['candidate_sha256']
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
                'candidate review digest')
        components = review['components']
        require(type(components) is list and all(type(name) is str for name in components)
                and len(components) == len(set(components))
                and set(components) <= owners[role], 'candidate review components')
        statement = review['statement']
        require(type(statement) is str and statement.strip(), 'candidate review statement')
        require(review['statement_sha256'] == hashlib.sha256(statement.encode('utf-8')).hexdigest(),
                'candidate review statement checksum')
        if digest != manifest['candidate_sha256']:
            blockers.append(f'candidate: {role} reviewed a different digest')
        if set(components) != owners[role]:
            blockers.append(f'candidate: {role} review omits owned components')
    blockers.extend(f'candidate: missing exact review from {role}' for role in sorted(owners.keys() - seen))
    return blockers


def candidate_registry_blockers(registry, root, contract_paths):
    """Validate candidate0.2 root coverage; never grant semantic completeness.

    Every schema is hashed as part of the reviewed contract; matching all root
    names alone does not qualify a witness or replace any compiler component.
    """
    require(registry['revision'] == '0.2' and type(registry['profile']['id']) is int
            and registry['profile']['id'] == 2, 'candidate profile')
    revisions = registry.get('payload_revisions')
    expected_revisions = {'1': 2, '2': 2, '3': 2, '4': 1, '5': 2,
                          '6': 1, '7': 1, '8': 1, '9': 1, '10': 3}
    require(type(revisions) is dict and set(revisions) == set(expected_revisions)
            and all(type(value) is int and value == expected_revisions[key]
                    for key, value in revisions.items()), 'candidate payload revisions')
    require('payload_revision' not in registry, 'obsolete uniform payload revision')
    require(registry.get('source_nominal_hash_profile') == 'SMIR-NOMINAL-SHAPE-V3',
            'candidate nominal hash profile')
    require(registry['all_semantic_sections_required'] is True, 'candidate required sections')
    require('compiler_freeze_passed' not in registry,
            'candidate registry contains derived compiler freeze state')
    for name, size in [('header_bytes', 48), ('directory_entry_bytes', 24), ('alignment_bytes', 8)]:
        require(type(registry[name]) is int and registry[name] == size, 'candidate framing layout')
    require(type(registry['sections']) is list and len(registry['sections']) == 10,
            'candidate section coverage')
    require(all(type(item['id']) is int for item in registry['sections'])
            and [item['id'] for item in registry['sections']] == list(range(1, 11)),
            'candidate section IDs')
    blockers, schemas = [], {}
    for section in registry['sections']:
        identifier = section['id']
        require(section['owner'] == CANDIDATE_OWNERS[identifier], 'candidate section ownership')
        require(section['name'] == CANDIDATE_NAMES[identifier], 'candidate section name')
        require(section['root'] == CandidateCodec.ROOTS[identifier], 'candidate section root')
        owner = {'SEMANTICS': 'execution', 'RUNTIME': 'runtime', 'ABI': 'abi'}[section['owner']]
        relative = SCHEMA_PREFIX + owner + '/candidate.json'
        require(section['schema'] == 'schema/' + owner + '/candidate.json', 'candidate schema path')
        if relative not in contract_paths:
            blockers.append(f'section {identifier}: schema omitted from candidate inputs')
        if owner not in schemas:
            # artifact_bytes checks both ordinary and symlink path containment.
            artifact_bytes(root, relative)
            schemas[owner] = load_json(root / relative)
        require(section['root'] in schemas[owner]['records'], 'candidate root absent from schema')
        fields = schemas[owner]['records'][section['root']].get('fields', [])
        require(fields and fields[0] == ['payload_revision', 'u32'], 'candidate root revision field')
        require(section['schema_state'] in ('pending-full-role-review', 'decision-complete'),
                'candidate schema review state')
        if section['schema_state'] != 'decision-complete':
            blockers.append(f'section {identifier}: payload not frozen')
    # Audit primitive/record grammar and exact cross-role duplicate definitions.
    codec = CandidateCodec(schemas)
    require(isinstance(codec.records, RecordCodec), 'candidate primitive audit')
    return blockers


def compiler_blockers(manifest, registry, ledger, receipts, root=ROOT):
    """Check evidence structure and return explicit unmet freeze prerequisites.

    Complexity is O(total artifact bytes + manifest/receipt records), excluding
    sorting for the candidate hash. This is an evidence-accounting check, not a
    proof of semantics, witness independence, or runtime qualification.
    """
    require(type(manifest['format_revision']) is int and manifest['format_revision'] in (1, 2),
            'contract manifest revision')
    components = manifest['components']
    require(len(components) == len(COMPONENT_OWNERS), 'missing compiler component')
    require({item['id']: item['owner'] for item in components} == COMPONENT_OWNERS,
            'compiler component ownership')
    decisions = manifest['decisions']
    require(len(decisions) == len(REQUIRED_DECISIONS), 'missing interface decision')
    require({item['id'] for item in decisions} == set(REQUIRED_DECISIONS),
            'interface decision registry')
    receipt_by_id = {}
    for receipt in receipts:
        require(receipt['id'] not in receipt_by_id, 'duplicate witness receipt')
        paths = check_artifacts(receipt['inputs'], root)
        check_input_inventory(receipt, root, paths)
        receipt_by_id[receipt['id']] = receipt
    blockers = []
    covered = set()
    contract_paths = set()
    for component in components:
        name = component['id']
        require(component['state'] in ('incomplete', 'decision-complete'), 'component state')
        require(isinstance(component['blockers'], list)
                and all(isinstance(item, str) and item for item in component['blockers']),
                'component blockers must be nonempty strings')
        requirements = component['requirements']
        require(isinstance(requirements, list) and requirements
                and len(requirements) == len(set(requirements)),
                f'{name}: requirement coverage')
        require(set(requirements) <= ledger.keys(), f'{name}: unknown requirement')
        covered.update(requirements)
        paths = check_artifacts(component['artifacts'], root)
        contract_paths.update(paths)
        if component['state'] != 'decision-complete':
            blockers.append(f'{name}: incomplete decisions')
        blockers.extend(f'{name}: {item}' for item in component['blockers'])
        if not paths:
            blockers.append(f'{name}: no exact contract artifacts')
        if not component['witnesses']:
            blockers.append(f'{name}: no qualifying independent witnesses')
        for identifier in component.get('reference_receipts', []):
            require(identifier in receipt_by_id, f'{name}: unknown reference receipt {identifier}')
        require(isinstance(component['witnesses'], list)
                and len(component['witnesses']) == len(set(component['witnesses'])),
                f'{name}: duplicate or invalid witnesses')
        for identifier in component['witnesses']:
            require(identifier in receipt_by_id, f'{name}: unknown witness {identifier}')
            receipt = receipt_by_id[identifier]
            require(isinstance(receipt['argv'], list) and receipt['argv']
                    and all(isinstance(arg, str) and arg for arg in receipt['argv']),
                    'witness command must be exact argv')
            counts = receipt['counts']
            require(set(counts) == {'passed', 'failed', 'skipped'}
                    and all(type(value) is int and value >= 0 for value in counts.values()),
                    'invalid witness counts')
            if (receipt['outcome'] != 'passed' or counts['passed'] == 0
                    or counts['failed'] != 0 or counts['skipped'] != 0):
                blockers.append(f'{name}: witness {identifier} failed, skipped or empty')
            if receipt['scope'] != 'compiler-reference' or receipt['independent'] is not True:
                blockers.append(f'{name}: witness {identifier} does not qualify')
            if name not in receipt['qualifies']:
                blockers.append(f'{name}: witness {identifier} does not cover component')
            if not paths <= {item['path'] for item in receipt['inputs']}:
                blockers.append(f'{name}: witness {identifier} lacks contract input hashes')
            kinds = receipt['case_kinds']
            if any(type(kinds.get(kind)) is not int or kinds[kind] <= 0
                   for kind in ('positive', 'boundary', 'rejection')):
                blockers.append(f'{name}: witness {identifier} lacks case partitions')
        if any(ledger[item]['status'] in ('draft', 'unsupported') for item in requirements):
            blockers.append(f'{name}: draft or unsupported requirements')
    accounting_targets = {(root / path).resolve() for path in ACCOUNTING_PATHS}
    accounting_identities = {(path.stat().st_dev, path.stat().st_ino)
                             for path in accounting_targets if path.is_file()}
    contract_files = [root / path for path in contract_paths]
    require(not any(path.resolve() in accounting_targets or
                    (path.stat().st_dev, path.stat().st_ino) in accounting_identities
                    for path in contract_files),
            'mutable gate accounting included in candidate inputs')
    required = {identifier for identifier in ledger if not identifier.startswith('CONF-')}
    require(required <= covered, 'unowned compiler requirements')
    for decision in decisions:
        name = decision['id']
        require(decision['state'] in ('proposed', 'draft-acknowledged', 'accepted'),
                'decision state')
        require(set(decision['consumers']) == REQUIRED_DECISIONS[name], 'decision consumers')
        require(len(decision['acknowledged_by']) == len(set(decision['acknowledged_by'])),
                'duplicate decision acknowledgement')
        require(set(decision['acknowledged_by']) <= set(decision['consumers']),
                'unknown decision acknowledgement')
        if (decision['state'] != 'accepted'
                or set(decision['acknowledged_by']) != set(decision['consumers'])):
            blockers.append(f'{name}: missing accepted cross-role decision')
        decision_paths = check_artifacts(decision['artifacts'], root)
        require(decision_paths <= contract_paths, 'decision artifacts omitted from candidate inputs')
        if not decision['artifacts']:
            blockers.append(f'{name}: no recorded decision artifact')
    if manifest['format_revision'] == 2:
        registry_path = manifest['candidate_registry']
        artifact_bytes(root, registry_path)
        require(load_json(root / registry_path) == registry, 'candidate registry selection')
        if registry_path not in contract_paths:
            blockers.append('candidate: registry omitted from candidate inputs')
        blockers.extend(candidate_registry_blockers(registry, root, contract_paths))
    else:
        for section in registry['sections']:
            if section['required'] and section['payload_status'] != 'decision-complete':
                blockers.append(f'section {section["name"]}: payload not frozen')
    digest = candidate_hash(components)
    if manifest['candidate_sha256'] != digest:
        blockers.append('candidate: artifact hash not published or stale')
    if manifest['format_revision'] == 2:
        blockers.extend(candidate_review_blockers(manifest))
    return blockers


def inactive_candidate_blockers(manifest):
    """Historical reviews cannot qualify a current candidate or bind live files.

    Return None for active/ordinary accounting, which must retain all strict
    artifact, receipt and review checks in compiler_blockers.
    """
    if manifest.get('candidate_state') != 'WITHDRAWN_HISTORICAL_DIGEST':
        return None
    require('current_candidate_sha256' in manifest and
            manifest['current_candidate_sha256'] is None,
            'withdrawn candidate claims a current digest')
    return ['candidate: no active compiler candidate; withdrawn receipts are historical']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-compiler-freeze', action='store_true')
    args = parser.parse_args()
    registry = load_json(SPEC / 'registry.json')
    status = load_json(SPEC / 'status.json')
    require(registry['revision'] == status['revision'] == '0.1', 'revision')
    require(registry['header_bytes'] == 48, 'header size')
    require(registry['directory_entry_bytes'] == 24, 'record size')
    require(registry['alignment_bytes'] == 8, 'alignment')
    for group, size in [('header_fields', 48), ('directory_fields', 24)]:
        cursor = 0
        names = set()
        for field in registry[group]:
            require(field['offset_bytes'] == cursor, f'{group}: gap or overlap')
            require(field['name'] not in names, f'{group}: duplicate field')
            require(field['width_bytes'] in (2, 4, 8), f'{group}: width')
            names.add(field['name'])
            cursor += field['width_bytes']
        require(cursor == size, f'{group}: extent')
    require([item['id'] for item in registry['sections']] == list(range(1, 10)) + list(range(0x8000, 0x8003)), 'section registry')
    require([item['code'] for item in registry['diagnostics']] == [f'SMIR-E{i:03}' for i in range(1, 10)], 'diagnostic registry')
    require([item['required'] for item in registry['sections']] == [True] * 9 + [False] * 3, 'section semantics')
    require([item['id'] for item in status['packages']] == [f'P{i}' for i in range(11)], 'package registry')
    require(type(status['compiler_freeze_passed']) is bool, 'compiler gate must be boolean')
    require(status['release_qualified'] is False, 'release qualification not implemented')
    identifiers = []
    files = sorted(SPEC.glob('*.md'))
    for path in files:
        content = path.read_text()
        for target in re.findall(r'\]\(([^)]+)\)', content):
            if '://' not in target and not target.startswith('#'):
                require((path.parent / target.split('#')[0]).exists(), f'{path}: {target}')
        identifiers.extend(re.findall(r'^([A-Z]+-\d{3}):', content, re.MULTILINE))
        require(all(ord(character) < 128 for character in content), f'non-ASCII: {path}')
    require(len(set(identifiers)) == len(identifiers), 'duplicate requirement ID')
    require(len(identifiers) >= 50, 'requirement coverage unexpectedly shrank')
    ledger = load_json(SPEC / 'requirements.json')
    require(set(ledger) == set(identifiers), 'requirements ledger differs from chapter IDs')
    for identifier, record in ledger.items():
        require(record['status'] in REQUIREMENT_STATUSES, f'{identifier}: status')
        if record['test'] is not None:
            artifact_bytes(ROOT, record['test'])
        if record['status'].startswith('verified'):
            require(record['test'] is not None, f'{identifier}: verified without a test')
    for reference in load_json(SPEC / 'references/provenance.json'):
        payload = artifact_bytes(SPEC / 'references', reference['path'])
        require(hashlib.sha256(payload).hexdigest() == reference['sha256'], 'reference checksum')
    repository_sources = SPEC / 'references/repository-sources.json'
    if repository_sources.exists():
        retained = load_json(repository_sources)
        require(type(retained['format_revision']) is int and retained['format_revision'] == 1,
                'retained repository source revision')
        for reference in retained['files']:
            payload = artifact_bytes(ROOT, reference['path'])
            require(hashlib.sha256(payload).hexdigest() == reference['sha256'],
                    'retained repository reference checksum')
    manifest = load_json(SPEC / 'compiler-contract.json')
    require(type(manifest['format_revision']) is int and manifest['format_revision'] == 2,
            'actual compiler contract requires candidate accounting revision2')
    require(manifest['candidate_registry'] == 'docs/specifications/smir/portable/candidate-registry.json',
            'actual compiler candidate registry')
    validation = load_json(SPEC / 'validation.json')
    require('compiler_freeze_passed' not in load_json(SPEC / 'interface-decisions.json'),
            'interface decisions contain derived compiler freeze state')
    if manifest['format_revision'] == 2:
        artifact_bytes(ROOT, manifest['candidate_registry'])
        registry = load_json(ROOT / manifest['candidate_registry'])
    blockers = inactive_candidate_blockers(manifest)
    if blockers is None:
        blockers = compiler_blockers(manifest, registry, ledger, validation.get('receipts', []))
    else:
        # Check the current candidate registry/schema representation even though
        # historical component hashes and reviews do not bind this working tree.
        paths = {item['path'] for component in manifest['components']
                 for item in component['artifacts']}
        blockers.extend(candidate_registry_blockers(registry, ROOT, paths))
    require(status['compiler_freeze_passed'] == (not blockers), 'compiler freeze claim contradicts current evidence')
    print(f'{len(files)} documents; {len(identifiers)} requirements; registries and local links valid')
    print(f'Compiler contract gate: {"PASS" if not blockers else "INCOMPLETE"}; {len(blockers)} blockers')
    if args.require_compiler_freeze and blockers:
        parser.exit(1, '\n'.join(blockers) + '\n')


if __name__ == '__main__':
    main()
