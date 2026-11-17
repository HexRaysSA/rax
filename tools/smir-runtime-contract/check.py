#!/usr/bin/env python3
"""Check draft runtime fixtures; does not grant executable SMIR admission."""
import argparse
from collections import Counter
import hashlib
import json

from bridge import verify_bridge
from carriers import extract
from link import verify_link
from memory import verify_access
from package import verify_package
from protocols import verify_state
from process import verify_clone, verify_nonlocal, verify_termination
from schema import ContractError, ROOT, canonical, decode, require, validate

SPEC = ROOT / 'docs/specifications/smir/portable'


def verify_carrier(document):
    validate(document, 'carrier')
    return extract(bytes.fromhex(document['encoded_hex']), document['carrier'])


VERIFY = {
    'bridge': verify_bridge,
    'clone': verify_clone,
    'nonlocal': verify_nonlocal,
    'termination': verify_termination,
    'carrier': verify_carrier,
    'link': verify_link,
    'memory': verify_access,
    'state': verify_state,
    'package': verify_package,
}


# Closed original runtime-draft-v1 corpus; additions require explicit inventory.
LEGACY_FIXTURES = (
    'access-acquire.json',
    'access-atomic-align.json',
    'access-atomic-width.json',
    'access-cas-failure.json',
    'access-cas-release.json',
    'access-fence.json',
    'access-last-byte.json',
    'access-load-release.json',
    'access-misaligned.json',
    'access-null.json',
    'access-overflow.json',
    'access-singlethread.json',
    'access-unaligned-ordinary.json',
    'access-zero-width.json',
    'bridge/bridge-early-lease-release.json',
    'bridge/bridge-missing-storage.json',
    'bridge/bridge-native-replay.json',
    'bridge/bridge-premature-frontier.json',
    'bridge/bridge-premature-publication.json',
    'bridge/bridge-ready.json',
    'bridge/bridge-returned-private.json',
    'bridge/bridge-suspend-no-frontier.json',
    'carriers/elf-discovery.json',
    'carriers/elf-missing-note.json',
    'carriers/elf-payload-corrupt.json',
    'carriers/elf-truncated.json',
    'carriers/elf-writable.json',
    'carriers/macho-discovery.json',
    'carriers/macho-duplicate-locator.json',
    'carriers/macho-payload-corrupt.json',
    'carriers/macho-truncated.json',
    'carriers/macho-writable.json',
    'carriers/pe-discovery.json',
    'carriers/pe-payload-corrupt.json',
    'carriers/pe-truncated.json',
    'carriers/pe-writable.json',
    'link-basic.json',
    'link-bool-id.json',
    'link-capability.json',
    'link-domain.json',
    'link-duplicate-symbol.json',
    'link-foreign-isa.json',
    'link-function-type.json',
    'link-import-flags.json',
    'link-import-name.json',
    'link-missing-definition.json',
    'link-namespace.json',
    'link-overlap.json',
    'link-relocation-overrun.json',
    'link-storage-alignment.json',
    'link-storage-overflow.json',
    'link-unknown-key.json',
    'link-unresolved-image.json',
    'package-embedded-unpinned.json',
    'package-embedded.json',
    'package-installed.json',
    'package-no-entry.json',
    'package-overflow.json',
    'package-raw-bootstrap.json',
    'package-raw.json',
    'process/clone-foreign-lease.json',
    'process/clone-live-worker.json',
    'process/clone-mapping-overrun.json',
    'process/clone-quiescent.json',
    'process/clone-shared-without-broker.json',
    'process/clone-wrong-frontier.json',
    'process/nonlocal-live.json',
    'process/nonlocal-mask-without-policy.json',
    'process/nonlocal-missing-result.json',
    'process/nonlocal-zero-cookie.json',
    'process/termination-duplicate.json',
    'process/termination-normal.json',
    'process/termination-odd-token.json',
    'process/termination-thread-mismatch.json',
    'state-commit-lie.json',
    'state-completed-replay.json',
    'state-completed.json',
    'state-duplicate-activation.json',
    'state-duplicate-local.json',
    'state-exception-status.json',
    'state-fenv-duplicate.json',
    'state-generation-zero.json',
    'state-irrevocable.json',
    'state-owner-blocked.json',
    'state-pending-replay.json',
    'state-pending.json',
    'state-running.json',
)
# These compiler corpora have separate closed validators and discovery witnesses.
SEPARATE_COMPILER_CORPORA = frozenset({'source-contracts', 'source-carrier', 'source-observer', 'union-prestore-reference', 'union-nested-reference'})
TYPED_VECTORS = {'code-values-vectors.json': 'pure-code-values-v1', 'retirement-core-vectors.json': 'synthetic-retirement-v1',
                 'normal-scope-outcomes/cases.json': 'conditional-normal-scope-outcome-fixtures'}

def check_fixtures():
    counts = Counter()
    folder = SPEC / 'conformance/runtime'
    actual = {path.relative_to(folder).as_posix() for path in folder.rglob('*.json')
              if 'candidate' not in path.relative_to(folder).parts
              and path.relative_to(folder).parts[0] not in SEPARATE_COMPILER_CORPORA}
    require(actual == set(LEGACY_FIXTURES) | set(TYPED_VECTORS), 'RUNTIME_CORPUS_INVENTORY')
    for name, expected in TYPED_VECTORS.items():
        vector = json.loads((folder / name).read_text())
        require(type(vector) is dict and vector.get('format') == expected,
                'RUNTIME_VECTOR_FORMAT', name)
    paths = [folder / name for name in LEGACY_FIXTURES]
    for path in paths:
        case = json.loads(path.read_text())
        require(type(case) is dict and {'surface', 'document', 'accept', 'expected_code'} <= set(case)
                and set(case) <= {'expected_payload_hex', 'id', 'accept', 'surface', 'expected_code', 'document'} and case['surface'] in VERIFY
                and type(case['accept']) is bool, 'RUNTIME_LEGACY_CASE', str(path))
        document = decode(canonical(case['document']))
        try:
            result = VERIFY[case['surface']](document)
        except ContractError as error:
            require(case['accept'] is False, 'UNEXPECTED_REJECTION', f'{path}: {error}')
            require(error.code == case['expected_code'], 'WRONG_DIAGNOSTIC',
                    f'{path}: {error.code} != {case["expected_code"]}')
            counts[(case['surface'], 'rejected')] += 1
        else:
            require(case['accept'] is True, 'UNEXPECTED_ACCEPTANCE', str(path))
            if case['surface'] == 'carrier':
                require(result.hex() == case['expected_payload_hex'], 'PAYLOAD_MISMATCH')
            counts[(case['surface'], 'accepted')] += 1
    return counts


def check_sources():
    records = json.loads((SPEC / 'schema/runtime/source-manifest.json').read_text())
    for record in records:
        path = SPEC / record['archive_path']
        require(path.is_file(), 'SOURCE_NOT_ARCHIVED', str(path))
        require(hashlib.sha256(path.read_bytes()).hexdigest() == record['sha256'],
                'SOURCE_HASH', str(path))
    return len(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    counts = check_fixtures()
    for surface in VERIFY:
        print(f'{surface}: {counts[surface, "accepted"]} accepted, '
              f'{counts[surface, "rejected"]} rejected')
    print(f'{sum(counts.values())} fixtures passed; {check_sources()} primary-source hashes verified; '
          'production admission absent')


if __name__ == '__main__':
    main()
