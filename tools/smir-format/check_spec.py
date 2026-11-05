#!/usr/bin/env python3
"""Check local links, requirement IDs, registries and honest admission status."""
import json
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / 'docs/specifications/smir/portable'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    registry = json.loads((SPEC / 'registry.json').read_text())
    status = json.loads((SPEC / 'status.json').read_text())
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
    # Only change these checks alongside actual semantic/runtime admission.
    require(status['compiler_freeze_passed'] is False, 'unexpected compiler admission')
    require(status['release_qualified'] is False, 'unexpected release claim')
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
    ledger = {identifier: {'status': 'specified', 'test': None} for identifier in identifiers}
    for identifier in ('WIRE-001', 'WIRE-002', 'WIRE-003', 'WIRE-005'):
        ledger[identifier] = {'status': 'verified-framing-only', 'test': 'tools/smir-format/test_codec.py'}
    stored = json.loads((SPEC / 'requirements.json').read_text())
    require(stored == ledger, 'requirements ledger differs from chapter IDs/status')
    for reference in json.loads((SPEC / 'references/provenance.json').read_text()):
        payload = (SPEC / 'references' / reference['path']).read_bytes()
        require(hashlib.sha256(payload).hexdigest() == reference['sha256'], 'reference checksum')
    print(f'{len(files)} documents; {len(identifiers)} requirements; registries and local links valid')


if __name__ == '__main__':
    main()
