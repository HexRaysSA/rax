#!/usr/bin/env python3
"""Validate the structure of the portable SMIR specification package.

This checks registries, chapter links, requirement identifiers, the requirement
ledger, archived reference checksums and the candidate section registry. It is
a consistency check over documents and schemas. It says nothing about whether
any requirement is implemented; implementation is established by tests that
run programs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from codec import CandidateCodec, RecordCodec

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / 'docs/specifications/smir/portable'
REQUIREMENT_STATUSES = {
    'draft', 'specified', 'implemented', 'verified-framing-only',
    'verified-reference-only', 'verified', 'unsupported',
}
# Historical role names remain the registry's key for each section's schema file.
CANDIDATE_OWNERS = {
    1: 'SEMANTICS', 2: 'RUNTIME', 3: 'SEMANTICS', 4: 'RUNTIME', 5: 'RUNTIME',
    6: 'RUNTIME', 7: 'RUNTIME', 8: 'SEMANTICS', 9: 'RUNTIME', 10: 'ABI',
}
CANDIDATE_NAMES = dict(enumerate((
    'types', 'symbols', 'functions', 'data', 'relocations', 'imports', 'tls',
    'exceptions', 'capabilities', 'abi-contract'), 1))
SCHEMA_DIRECTORIES = {'SEMANTICS': 'execution', 'RUNTIME': 'runtime', 'ABI': 'abi'}
SCHEMA_PREFIX = 'docs/specifications/smir/portable/schema/'
PAYLOAD_REVISIONS = {'1': 2, '2': 2, '3': 2, '4': 1, '5': 2,
                     '6': 1, '7': 1, '8': 1, '9': 1, '10': 3}


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


def check_candidate_registry(registry, root):
    """Check that the candidate 0.2 registry names all ten roots and their schemas.

    Every section must name the root record its schema file defines, and each
    root must start with its payload revision word. This is a structural check
    of the registry against the schemas, not a statement about their semantics.
    """
    require(registry['revision'] == '0.2' and type(registry['profile']['id']) is int
            and registry['profile']['id'] == 2, 'candidate profile')
    revisions = registry.get('payload_revisions')
    require(type(revisions) is dict and set(revisions) == set(PAYLOAD_REVISIONS)
            and all(type(value) is int and value == PAYLOAD_REVISIONS[key]
                    for key, value in revisions.items()), 'candidate payload revisions')
    require('payload_revision' not in registry, 'obsolete uniform payload revision')
    require(registry.get('source_nominal_hash_profile') == 'SMIR-NOMINAL-SHAPE-V3',
            'candidate nominal hash profile')
    require(registry['all_semantic_sections_required'] is True, 'candidate required sections')
    for name, size in [('header_bytes', 48), ('directory_entry_bytes', 24), ('alignment_bytes', 8)]:
        require(type(registry[name]) is int and registry[name] == size, 'candidate framing layout')
    require(type(registry['sections']) is list and len(registry['sections']) == 10,
            'candidate section coverage')
    require(all(type(item['id']) is int for item in registry['sections'])
            and [item['id'] for item in registry['sections']] == list(range(1, 11)),
            'candidate section IDs')
    schemas = {}
    for section in registry['sections']:
        identifier = section['id']
        require(section['owner'] == CANDIDATE_OWNERS[identifier], 'candidate section ownership')
        require(section['name'] == CANDIDATE_NAMES[identifier], 'candidate section name')
        require(section['root'] == CandidateCodec.ROOTS[identifier], 'candidate section root')
        directory = SCHEMA_DIRECTORIES[section['owner']]
        relative = SCHEMA_PREFIX + directory + '/candidate.json'
        require(section['schema'] == 'schema/' + directory + '/candidate.json',
                'candidate schema path')
        if directory not in schemas:
            # artifact_bytes checks both ordinary and symlink path containment.
            artifact_bytes(root, relative)
            schemas[directory] = load_json(root / relative)
        require(section['root'] in schemas[directory]['records'],
                'candidate root absent from schema')
        fields = schemas[directory]['records'][section['root']].get('fields', [])
        require(fields and fields[0] == ['payload_revision', 'u32'],
                'candidate root revision field')
    # Audit primitive/record grammar and exact duplicate definitions across schemas.
    codec = CandidateCodec(schemas)
    require(isinstance(codec.records, RecordCodec), 'candidate primitive audit')


def check_legacy_registry(registry):
    require(registry['revision'] == '0.1', 'revision')
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
    require([item['id'] for item in registry['sections']]
            == list(range(1, 10)) + list(range(0x8000, 0x8003)), 'section registry')
    require([item['code'] for item in registry['diagnostics']]
            == [f'SMIR-E{i:03}' for i in range(1, 10)], 'diagnostic registry')
    require([item['required'] for item in registry['sections']] == [True] * 9 + [False] * 3,
            'section semantics')


def check_chapters():
    """Return (chapter count, requirement identifiers) after link and ID checks."""
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
    return len(files), identifiers


def check_ledger(identifiers):
    ledger = load_json(SPEC / 'requirements.json')
    require(set(ledger) == set(identifiers), 'requirements ledger differs from chapter IDs')
    for identifier, record in ledger.items():
        require(record['status'] in REQUIREMENT_STATUSES, f'{identifier}: status')
        if record['test'] is not None:
            artifact_bytes(ROOT, record['test'])
        if record['status'].startswith('verified'):
            require(record['test'] is not None, f'{identifier}: verified without a test')


def check_references():
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


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    check_legacy_registry(load_json(SPEC / 'registry.json'))
    chapters, identifiers = check_chapters()
    check_ledger(identifiers)
    check_references()
    check_candidate_registry(load_json(SPEC / 'candidate-registry.json'), ROOT)
    print(f'{chapters} documents; {len(identifiers)} requirements; '
          'registries and local links valid')


if __name__ == '__main__':
    main()
