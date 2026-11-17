"""Generate independent Python wire oracles; never runs in production."""
from pathlib import Path
import copy
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'tools/smir-format'))
from codec import CandidateCodec
from codec import decode_candidate
from codec import encode_candidate
from codec import RecordError

SPEC = ROOT/'docs/specifications/smir/portable'
schemas = {owner: json.loads((SPEC/f'schema/{owner}/candidate.json').read_text())
           for owner in ('execution', 'runtime', 'abi')}
codec = CandidateCodec(schemas)
output = Path(__file__).parent/'wire-cases.json'
previous = json.loads(output.read_text()) if output.exists() else {}
legacy = previous.get('legacy_revision_cases', [])
# Keep the exact pre-migration identity object as a rejection control. This
# preserves observed bytes, rather than serializing old records with new fields.
for case in previous.get('cases', []):
    if case['name'] != 'identity':
        continue
    raw = bytes.fromhex(case['encoded_hex'])
    envelope = decode_candidate(raw)
    revisions = {section['kind']: int.from_bytes(bytes.fromhex(section['hex'])[:4], 'little')
                 for section in envelope['sections'] if section['kind'] < 0x8000}
    if revisions != codec.PAYLOAD_REVISIONS and not any(
            item['sha256'] == hashlib.sha256(raw).hexdigest() for item in legacy):
        legacy.append({'name': 'archived-pre-CodeAddress-identity', 'encoded_hex': raw.hex(),
                       'sha256': hashlib.sha256(raw).hexdigest(),
                       'expected_error': 'WIRE-REVISION',
                       'payload_revisions': {str(key): value for key, value in revisions.items()},
                       'original_source': previous['source'],
                       'original_source_sha256': previous['source_sha256']})
if not legacy:
    for case in previous.get('cases', []):
        if case['name'] != 'identity':
            continue
        raw = bytes.fromhex(case['encoded_hex'])
        envelope = decode_candidate(raw)
        abi = next(section for section in envelope['sections'] if section['kind'] == 10)
        if bytes.fromhex(abi['hex'])[:4] == b'\x01\0\0\0':
            legacy.append({'name': 'archived-abi1-identity', 'encoded_hex': raw.hex(),
                           'sha256': hashlib.sha256(raw).hexdigest(),
                           'expected_error': 'WIRE-REVISION',
                           'original_source': previous['source'],
                           'original_source_sha256': previous['source_sha256']})
if not legacy:
    raise ValueError('The archived ABI1 identity rejection fixture must be preserved')
source = SPEC/'conformance/execution/candidate/portable-identity.json'
base = {int(key): value for key, value in json.loads(source.read_text())['sections'].items()}
for section, empty in {
    5: {'payload_revision': 2, 'relocations': [], 'constant_initializers': []},
    7: {'payload_revision': 1, 'segments': []},
    9: {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []},
}.items():
    base.setdefault(section, empty)

def count(value):
    if isinstance(value, dict):
        return 1 + sum(count(child) for child in value.values())
    if isinstance(value, list):
        return 1 + sum(count(child) for child in value)
    return 1

cases = []
def add(name, roots, metadata=()):
    encoded = codec.encode(roots, metadata=metadata)
    decoded = codec.decode(encoded)
    cases.append({'name': name, 'encoded_hex': encoded.hex(),
                  'sha256': hashlib.sha256(encoded).hexdigest(),
                  'identity': decoded.content_digest,
                  'nodes': sum(count(value) for value in decoded.roots.values())})

add('identity', base)
add('metadata', base, [
    {'kind': 0x8002, 'required': False, 'hex': '0001ff00'},
    {'kind': 0xffff, 'required': False, 'hex': ''},
])
dependency = copy.deepcopy(base)
dependency[2]['manifest']['dependencies'] = [{
    'slot': 7,
    'key': {'namespace': 'unit', 'name': 'provider', 'abi_major': 1, 'abi_minor': 0},
    'minimum_minor': 0, 'maximum_minor': None,
    'site': base[2]['manifest']['site'],
    'declarations': [{
        'id': 99, 'kind': 'type', 'symbol_kind': 'none', 'source_linkage': 'none',
        'namespace': 'unit', 'name': 'expected_int',
        'execution': {'some': {'module': {'kind': 'self'}, 'id': base[1]['types'][0]['id']}},
        'nominal': None, 'abi_signature': None, 'weak': False,
    }],
}]
add('dependency', dependency)
duplicate = copy.deepcopy(base)
duplicate[1]['types'].append(copy.deepcopy(duplicate[1]['types'][0]))
add('duplicate-type', duplicate)

# Sparse mutations keep the original content identity deliberately stale. The
# independent decoder must report revision before identity or semantic errors.
identity_bytes = bytes.fromhex(cases[0]['encoded_hex'])
revision_words = []
for section in range(1, 11):
    directory = 48 + (section - 1) * 24
    assert int.from_bytes(identity_bytes[directory:directory + 2], 'little') == section
    offset = int.from_bytes(identity_bytes[directory + 8:directory + 16], 'little')
    expected = codec.PAYLOAD_REVISIONS[section]
    assert identity_bytes[offset:offset + 4] == expected.to_bytes(4, 'little')
    for revision in (0, 1 if expected != 1 else 2, 0xffffffff):
        replacement = revision.to_bytes(4, 'little')
        changed = bytearray(identity_bytes)
        changed[offset:offset + 4] = replacement
        try:
            codec.decode(bytes(changed))
        except RecordError as error:
            if str(error) != 'WIRE-REVISION':
                raise
        else:
            raise ValueError('Wrong revision was accepted by independent codec')
        revision_words.append({'section': section, 'offset': offset,
                               'original_hex': expected.to_bytes(4, 'little').hex(),
                               'replacement_hex': replacement.hex(),
                               'sha256': hashlib.sha256(changed).hexdigest(),
                               'expected_error': 'WIRE-REVISION'})

# Whole-wrapper prefix policy differs from a bare ordered-record integer read.
# Compact copy/literal recipes preserve every other original payload without
# storing fifty redundant full objects or rebuilding framing inside the DUT test.
prefix_cases = []
original_envelope = decode_candidate(identity_bytes)
directory_end = 48 + 24 * len(original_envelope['sections'])
for section in range(1, 11):
    directory = 48 + (section - 1) * 24
    original_start = int.from_bytes(identity_bytes[directory + 8:directory + 16], 'little')
    for length in range(5):
        raw = codec.PAYLOAD_REVISIONS[section].to_bytes(4, 'little')[:length]
        envelope = copy.deepcopy(original_envelope)
        envelope['sections'][section - 1]['hex'] = raw.hex()
        changed = encode_candidate(envelope)
        expected_error = 'WIRE-REVISION' if length < 4 else 'WIRE-TRUNCATED'
        try:
            codec.decode(changed)
        except RecordError as error:
            if str(error) != expected_error:
                raise
        else:
            raise ValueError('Missing revision/body was accepted by independent codec')
        segments = [{'hex': changed[:directory_end].hex()},
                    {'source_offset': directory_end,
                     'source_length': original_start - directory_end}]
        if section < 10:
            old_next = int.from_bytes(identity_bytes[directory + 32:directory + 40], 'little')
            new_next = int.from_bytes(changed[directory + 32:directory + 40], 'little')
            segments += [{'hex': changed[original_start:new_next].hex()},
                         {'source_offset': old_next,
                          'source_length': len(identity_bytes) - old_next}]
        else:
            segments.append({'hex': changed[original_start:].hex()})
        rebuilt = b''.join(bytes.fromhex(part['hex']) if 'hex' in part else
                           identity_bytes[part['source_offset']:
                                          part['source_offset'] + part['source_length']]
                           for part in segments)
        if rebuilt != changed:
            raise ValueError('Independent framing copy recipe changed bytes')
        prefix_cases.append({'section': section, 'prefix_bytes': length,
                             'segments': segments,
                             'sha256': hashlib.sha256(changed).hexdigest(),
                             'expected_error': expected_error})
document = {'generator': 'Independent Python CandidateCodec; coherent CodeAddress migration',
            'source': str(source.relative_to(ROOT)),
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'inputs': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in [Path(__file__).resolve(), ROOT/'tools/smir-format/codec.py',
                                    *(SPEC/f'schema/{owner}/candidate.json'
                                      for owner in ('execution', 'runtime', 'abi'))]},
            'cases': cases, 'legacy_revision_cases': legacy,
            'revision_word_cases': revision_words,
            'payload_prefix_cases': prefix_cases}
rendered = json.dumps(document, indent=2)+'\n'
if sys.argv[1:] == ['--check']:
    if output.read_text() != rendered:
        raise SystemExit('Generated wire fixtures are stale')
elif sys.argv[1:]:
    raise SystemExit('usage: generate_wire_cases.py [--check]')
else:
    output.write_text(rendered)
print([(case['name'], case['nodes'], len(case['encoded_hex'])//2) for case in cases])
