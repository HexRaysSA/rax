#!/usr/bin/env python3
"""Cross-check independent codecs and adversarial draft framing."""
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from codec import (
    CandidateCodec, DecodeError, NO_ENTRY, RecordCodec, RecordError, RecordLimits, decode, encode,
    decode_candidate, encode_candidate,
)
from check_spec import (
    ACCOUNTING_PATHS, COMPONENT_OWNERS, REQUIRED_DECISIONS, artifact_bytes, candidate_hash,
    candidate_review_blockers,
    compiler_blockers, candidate_registry_blockers, CANDIDATE_NAMES, CANDIDATE_OWNERS, load_json,
)

ROOT = Path(__file__).resolve().parents[2]


class CodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='rax-smir-codec-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.accepted = 0
        cls.rejected = 0
        cls.probe = Path(cls.directory.name) / 'probe'
        cls.cpp_probe = Path(cls.directory.name) / 'cpp_probe'
        subprocess.run(['rustc', '--edition', '2024', str(ROOT / 'tools/smir-format/rust_probe.rs'), '-o', str(cls.probe)], check=True)
        subprocess.run([os.environ.get('CXX', 'clang++'), '-std=c++20', '-Wall', '-Wextra', '-Werror', str(ROOT / 'tools/smir-format/cpp_probe.cpp'), '-o', str(cls.cpp_probe)], check=True)

    @classmethod
    def tearDownClass(cls):
        print(f'Cross-codec cases: {cls.accepted} accepted, {cls.rejected} rejected; 3 decoders, 2 encoders')
        cls.directory.cleanup()

    def compare(self, payload, *, candidate=False):
        path = Path(self.directory.name) / 'input.smo'
        path.write_bytes(payload)
        arguments = ['--candidate', str(path)] if candidate else [str(path)]
        result = subprocess.run([str(self.probe), *arguments], capture_output=True, text=True)
        cpp_result = subprocess.run([str(self.cpp_probe), *arguments], capture_output=True, text=True)
        self.assertEqual((cpp_result.returncode, cpp_result.stdout), (result.returncode, result.stdout), cpp_result.stderr)
        try:
            module = (decode_candidate if candidate else decode)(payload)
        except DecodeError as error:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout.strip(), str(error))
            type(self).rejected += 1
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], f"OK {module['kind']} {module['entry']}")
            self.assertEqual([line.rstrip() for line in lines[1:]], [f"{s['kind']} {int(s['required'])} {s['hex']}".rstrip() for s in module['sections']])
            self.assertEqual((encode_candidate if candidate else encode)(module), payload)
            type(self).accepted += 1

    @staticmethod
    def candidate_module():
        return {'kind': 1, 'sections': [
            {'kind': kind, 'required': True, 'hex': ''} for kind in range(1, 11)
        ]}

    def test_candidate_independent_golden(self):
        # Hand-derived header and ten zero-length records: payload cursor 288.
        # Zero payloads deliberately demonstrate that framing is not admission.
        header = bytes.fromhex(
            '534d49520d0a1a0a0000020001000000020000000a000000'
            '20010000000000003000000000000000ffffffff00000000')
        records = b''.join(kind.to_bytes(2, 'little') + b'\x01\x00' + bytes(4)
                           + (288).to_bytes(8, 'little') + bytes(8)
                           for kind in range(1, 11))
        payload = header + records
        self.assertEqual(encode_candidate(self.candidate_module()), payload)
        self.compare(payload, candidate=True)
        self.compare(payload)  # Legacy API rejects 0.2, without autodetection.
        legacy = encode({'kind': 1, 'sections': []})
        self.compare(legacy, candidate=True)

    def test_candidate_explicit_fixtures_and_cli(self):
        directory = ROOT / 'docs/specifications/smir/portable/conformance/envelope/candidate'
        fixtures = sorted(directory.glob('*.json'))
        self.assertEqual(len(fixtures), 3)
        for fixture in fixtures:
            document = json.loads(fixture.read_text())
            payload = bytes.fromhex(document['encoded_hex'])
            if document['expected_error'] is None:
                self.assertEqual(decode_candidate(payload), document['module'])
            else:
                with self.assertRaisesRegex(DecodeError, document['expected_error']):
                    decode_candidate(payload)
            self.compare(payload, candidate=True)
        module = Path(self.directory.name) / 'candidate.json'
        encoded = Path(self.directory.name) / 'candidate.smo'
        module.write_text(json.dumps(self.candidate_module()))
        command = [sys.executable, '-B', str(ROOT / 'tools/smir-format/codec.py')]
        result = subprocess.run([*command, 'encode-candidate', str(module), '--output', str(encoded)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([*command, 'inspect-candidate', str(encoded)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), decode_candidate(encoded.read_bytes()))
        result = subprocess.run([*command, 'inspect', str(encoded)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.strip(), 'SMIR-E003')

    def test_candidate_required_sections_and_metadata(self):
        module = self.candidate_module()
        for missing in range(10):
            changed = copy.deepcopy(module)
            del changed['sections'][missing]
            with self.assertRaisesRegex(DecodeError, 'SMIR-E008'):
                encode_candidate(changed)
        module['kind'] = 2
        module['entry'] = 0
        module['sections'][0]['hex'] = 'abcdef'
        module['sections'].append({'kind': 0xffff, 'required': False, 'hex': 'aabb'})
        payload = encode_candidate(module)
        self.compare(payload, candidate=True)
        for offset, data, code in [
            (16, (1).to_bytes(4, 'little'), 4),
            (48 + 9 * 24, (11).to_bytes(2, 'little'), 8),
            (48 + 9 * 24 + 2, bytes(2), 8),
            (48 + 10 * 24 + 2, b'\x01\x00', 8),
            (48 + 10 * 24, (10).to_bytes(2, 'little'), 6),
            (315, b'\x01', 9),
        ]:
            changed = bytearray(payload)
            changed[offset:offset + len(data)] = data
            with self.assertRaisesRegex(DecodeError, f'SMIR-E{code:03}'):
                decode_candidate(changed)
            self.compare(changed, candidate=True)
        with self.assertRaisesRegex(DecodeError, 'SMIR-E005'):
            decode_candidate(payload, max_sections=10)
        with self.assertRaisesRegex(DecodeError, 'SMIR-E005'):
            decode_candidate(payload, max_bytes=len(payload) - 1)

    def test_candidate_adversarial_framing(self):
        payload = encode_candidate(self.candidate_module())
        for end in range(len(payload)):
            self.compare(payload[:end], candidate=True)
        for offset in range(len(payload)):
            changed = bytearray(payload)
            changed[offset] ^= 0x80
            self.compare(changed, candidate=True)
        # Valid framing with a missing root, independently constructed rather
        # than using the rejecting encoder. All remaining offsets stay canonical.
        changed = bytearray(payload[:48] + payload[72:])
        changed[20:24] = (9).to_bytes(4, 'little')
        changed[24:32] = len(changed).to_bytes(8, 'little')
        for record in range(9):
            changed[56 + record * 24:64 + record * 24] = len(changed).to_bytes(8, 'little')
        self.compare(changed, candidate=True)

    def test_golden_vectors(self):
        fixtures = sorted((ROOT / 'docs/specifications/smir/portable/conformance').glob('*.json'))
        self.assertTrue(fixtures, 'golden corpus must not be empty')
        for fixture in fixtures:
            document = json.loads(fixture.read_text())
            payload = bytes.fromhex(document['encoded_hex'])
            self.assertEqual(encode(document['module']), payload)
            self.compare(payload)

    def test_cpp_encoder_boundaries(self):
        result = subprocess.run([str(self.cpp_probe), '--self-test'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'C++ encoder partitions: 13')

    def test_envelope_rejection_and_boundary_fixtures(self):
        fixtures = sorted((ROOT / 'docs/specifications/smir/portable/conformance/envelope').glob('*.json'))
        self.assertTrue(fixtures, 'explicit envelope corpus must not be empty')
        for fixture in fixtures:
            with self.subTest(fixture=fixture.name):
                document = json.loads(fixture.read_text())
                payload = bytes.fromhex(document['encoded_hex'])
                if document['expected_error'] is None:
                    self.assertEqual(decode(payload), document['module'])
                else:
                    with self.assertRaisesRegex(DecodeError, document['expected_error']):
                        decode(payload)
                self.compare(payload)

    def test_diagnostic_precedence(self):
        payload = bytearray(encode({'kind': 1, 'sections': [
            {'kind': 1, 'required': True, 'hex': 'aa'},
        ]}))
        payload[0] = 0
        payload[8] = 1
        payload[14] = 1
        payload[20:24] = (1025).to_bytes(4, 'little')
        payload[48:50] = bytes(2)
        # Remove faults in the exact normative priority order; every codec must
        # report the remaining first fault, including simultaneous later faults.
        for code, offset, replacement in [
            (2, 0, b'S'),
            (3, 8, b'\x00'),
            (4, 14, b'\x00'),
            (5, 20, (1).to_bytes(4, 'little')),
            (6, 48, (1).to_bytes(2, 'little')),
        ]:
            with self.assertRaisesRegex(DecodeError, f'SMIR-E{code:03}'):
                decode(payload)
            self.compare(payload)
            payload[offset:offset + len(replacement)] = replacement
        self.compare(payload)

    def test_zero_length_sections_and_maximum_metadata_kind(self):
        self.compare(encode({'kind': 2, 'sections': [
            {'kind': kind, 'required': kind < 0x8000, 'hex': ''}
            for kind in [*range(1, 10), 0x8000, 0x8001, 0x8002, 0xffff]
        ]}))

    def test_section_count_limit_boundary(self):
        sections = [{'kind': 0x8000 + index, 'required': False, 'hex': ''}
                    for index in range(1024)]
        self.compare(encode({'kind': 1, 'sections': sections}))
        with self.assertRaisesRegex(DecodeError, 'SMIR-E005'):
            encode({'kind': 1, 'sections': sections + [
                {'kind': 0xffff, 'required': False, 'hex': ''},
            ]})

    def test_valid_sizes_and_ordering(self):
        for size in range(17):
            for kind in (1, 2):
                payload = encode({'kind': kind, 'entry': NO_ENTRY if kind == 1 else 0, 'sections': [
                    {'kind': 1, 'required': True, 'hex': bytes(range(size)).hex()},
                    {'kind': 0x9000, 'required': False, 'hex': 'aa'},
                ]})
                self.compare(payload)

    def test_every_header_and_directory_bit(self):
        payload = encode({'kind': 1, 'sections': [{'kind': 1, 'required': True, 'hex': 'abcdef'}]})
        for offset in range(72):
            for bit in range(8):
                changed = bytearray(payload)
                changed[offset] ^= 1 << bit
                self.compare(changed)

    def test_truncation(self):
        payload = encode({'kind': 2, 'entry': 0, 'sections': [{'kind': 1, 'required': True, 'hex': 'aa'}]})
        for end in range(len(payload)):
            self.compare(payload[:end])

    def test_deterministic_mutation_corpus(self):
        rng = random.Random(0x534d4952)
        payload = encode({'kind': 1, 'sections': [
            {'kind': 1, 'required': True, 'hex': 'abcd'},
            {'kind': 0x8000, 'required': False, 'hex': '1234'},
        ]})
        for _ in range(200):
            changed = bytearray(payload)
            changed[rng.randrange(len(changed))] = rng.randrange(256)
            self.compare(changed)

    def test_duplicate_and_unsupported_sections(self):
        for sections in ([{'kind': 1, 'required': False, 'hex': ''}],
                         [{'kind': 10, 'required': True, 'hex': ''}],
                         [{'kind': 0x9000, 'required': True, 'hex': ''}],
                         [{'kind': 1, 'required': True, 'hex': ''}] * 2):
            with self.assertRaises(DecodeError):
                encode({'kind': 1, 'sections': sections})

    def test_independent_rejection_expectations(self):
        original = encode({'kind': 2, 'entry': 0, 'sections': [
            {'kind': 1, 'required': True, 'hex': 'aa'},
            {'kind': 0x9000, 'required': False, 'hex': 'bb'},
        ]})
        cases = [
            (0, b'X', 2),
            (8, b'\x01', 3),
            (14, b'\x01', 4),
            (20, (1025).to_bytes(4, 'little'), 5),
            (48, b'\x00\x00', 6),
            (50, b'\x00\x00', 8),
            (56, (95).to_bytes(8, 'little'), 7),
            (64, ((1 << 64) - 1).to_bytes(8, 'little'), 7),
            (72, b'\x01\x00', 6),
            (97, b'\x01', 9),
        ]
        for offset, replacement, number in cases:
            with self.subTest(offset=offset):
                changed = bytearray(original)
                changed[offset:offset + len(replacement)] = replacement
                with self.assertRaisesRegex(DecodeError, f'SMIR-E{number:03}'):
                    decode(changed)
                self.compare(changed)

    def test_cli_round_trip_and_errors(self):
        directory = Path(self.directory.name)
        source = directory / 'module.json'
        output = directory / 'module.smo'
        module = {'kind': 1, 'entry': NO_ENTRY, 'sections': []}
        source.write_text(json.dumps(module))
        cli = [sys.executable, str(ROOT / 'tools/smir-format/codec.py')]
        subprocess.run(cli + ['encode', str(source), '--output', str(output)], check=True)
        result = subprocess.run(cli + ['inspect', str(output)], check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout), module)
        output.write_bytes(b'bad')
        result = subprocess.run(cli + ['inspect', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.strip(), 'SMIR-E001')


class EncoderInputTests(unittest.TestCase):
    def test_json_types_and_ranges(self):
        invalid = [None, [], {'kind': True, 'sections': []},
                   {'kind': 1, 'entry': False, 'sections': []},
                   {'kind': 2, 'entry': -1, 'sections': []},
                   {'kind': 2, 'entry': 1 << 32, 'sections': []},
                   {'kind': 1, 'sections': {}},
                   {'kind': 1, 'sections': [None]}]
        section = {'kind': 1, 'required': True, 'hex': ''}
        for name, value in [('kind', True), ('kind', -1), ('kind', 65536),
                            ('kind', 1.0), ('required', 1), ('required', '1'),
                            ('hex', []), ('hex', 'not-hex')]:
            invalid.append({'kind': 1, 'sections': [dict(section, **{name: value})]})
        for module in invalid:
            with self.subTest(module=module), self.assertRaises(ValueError):
                encode(module)


class ContractGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='rax-smir-gate-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'contract').write_text('synthetic unit-test contract\n')
        self.artifact = {
            'path': 'contract',
            'sha256': hashlib.sha256((self.root / 'contract').read_bytes()).hexdigest(),
        }
        self.ledger = {'TEST-001': {'status': 'specified', 'test': None}}
        self.manifest = {
            'format_revision': 1,
            'components': [{'id': name, 'owner': owner,
                            'requirements': ['TEST-001'], 'state': 'decision-complete',
                            'artifacts': [dict(self.artifact)], 'witnesses': [name],
                            'blockers': []}
                           for name, owner in COMPONENT_OWNERS.items()],
            'decisions': [{'id': name, 'state': 'accepted',
                           'consumers': sorted(consumers),
                           'acknowledged_by': sorted(consumers),
                           'artifacts': [dict(self.artifact)]}
                          for name, consumers in REQUIRED_DECISIONS.items()],
        }
        self.manifest['candidate_sha256'] = candidate_hash(self.manifest['components'])
        self.registry = {'sections': [{'name': 'types', 'required': True,
                                       'payload_status': 'decision-complete'}]}
        self.receipts = [{'id': name, 'argv': ['synthetic-test'],
                          'counts': {'passed': 3, 'failed': 0, 'skipped': 0},
                          'outcome': 'passed', 'scope': 'compiler-reference',
                          'independent': True, 'qualifies': [name],
                          'case_kinds': {'positive': 1, 'boundary': 1, 'rejection': 1},
                          'inputs': [dict(self.artifact)]}
                         for name in COMPONENT_OWNERS]

    def blockers(self):
        return compiler_blockers(self.manifest, self.registry, self.ledger,
                                 self.receipts, self.root)

    def test_complete_synthetic_accounting(self):
        # This exercises the checker, and supplies no real conformance evidence.
        self.assertEqual(self.blockers(), [])

    def candidate_registry(self):
        registry = {'revision': '0.2', 'profile': {'id': 2},
                    'payload_revisions': {'1': 2, '2': 2, '3': 2, '4': 1, '5': 2,
                                          '6': 1, '7': 1, '8': 1, '9': 1, '10': 3},
                    'source_nominal_hash_profile': 'SMIR-NOMINAL-SHAPE-V3',
                    'all_semantic_sections_required': True, 'sections': [],
                    'header_bytes': 48, 'directory_entry_bytes': 24, 'alignment_bytes': 8}
        paths = set()
        schemas = {owner: {'records': {}} for owner in ('execution', 'runtime', 'abi')}
        for identifier, name in CandidateCodec.ROOTS.items():
            owner = CANDIDATE_OWNERS[identifier]
            directory = {'SEMANTICS': 'execution', 'RUNTIME': 'runtime', 'ABI': 'abi'}[owner]
            schemas[directory]['records'][name] = {'fields': [['payload_revision', 'u32']]}
            registry['sections'].append({'id': identifier, 'name': CANDIDATE_NAMES[identifier],
                'owner': owner, 'root': name,
                'schema': 'schema/' + directory + '/candidate.json', 'schema_state': 'decision-complete'})
        schemas['runtime']['records']['runtime_symbols']['fields'].append(['manifest', 'module_manifest'])
        schemas['runtime']['records']['module_manifest'] = {'fields': [['identity', 'digest32']]}
        for owner, schema in schemas.items():
            relative = f'docs/specifications/smir/portable/schema/{owner}/candidate.json'
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(schema))
            paths.add(relative)
        return registry, paths

    def test_candidate_ten_root_accounting_and_review_gate(self):
        registry, paths = self.candidate_registry()
        self.assertEqual(candidate_registry_blockers(registry, self.root, paths), [])
        registry['sections'][9]['schema_state'] = 'pending-full-role-review'
        self.assertIn('section 10: payload not frozen', candidate_registry_blockers(registry, self.root, paths))
        registry['sections'][9]['schema_state'] = 'decision-complete'
        missing = paths - {'docs/specifications/smir/portable/schema/abi/candidate.json'}
        self.assertIn('section 10: schema omitted from candidate inputs',
                      candidate_registry_blockers(registry, self.root, missing))

    def test_candidate_registry_false_green_partitions(self):
        registry, paths = self.candidate_registry()
        changes = [lambda r: r['sections'].pop(), lambda r: r['profile'].update(id=True),
                   lambda r: r.update(all_semantic_sections_required=False),
                   lambda r: r['sections'][9].update(id=9),
                   lambda r: r['sections'][9].update(owner='RUNTIME'),
                   lambda r: r['sections'][9].update(root='execution_types'),
                   lambda r: r['sections'][9].update(name='types'),
                   lambda r: r.update(header_bytes=24),
                   lambda r: r.update(payload_revision=1),
                   lambda r: r['payload_revisions'].update({'10': 1}),
                   lambda r: r['payload_revisions'].update({'1': True}),
                   lambda r: r['payload_revisions'].update({'1': 1}),
                   lambda r: r['payload_revisions'].pop('10'),
                   lambda r: r['payload_revisions'].update({'11': 1}),
                   lambda r: r.update(source_nominal_hash_profile='SMIR-SOURCE-NOMINAL-V2'),
                   lambda r: r['sections'][9].update(schema='../outside.json'),
                   lambda r: r['sections'][9].update(schema_state='complete')]
        for change in changes:
            changed = copy.deepcopy(registry)
            change(changed)
            with self.assertRaises(ValueError):
                candidate_registry_blockers(changed, self.root, paths)

    def test_candidate_registry_rejects_derived_gate_results(self):
        registry, paths = self.candidate_registry()
        for result in (False, True):
            registry['compiler_freeze_passed'] = result
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, 'derived compiler freeze'):
                candidate_registry_blockers(registry, self.root, paths)

    def test_candidate_inputs_exclude_mutable_gate_accounting(self):
        component = self.manifest['components'][0]
        for relative in sorted(ACCOUNTING_PATHS):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}\n')
            artifact = {'path': relative, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            component['artifacts'] = [dict(self.artifact), artifact]
            with self.subTest(path=relative), self.assertRaisesRegex(ValueError, 'mutable gate accounting'):
                self.blockers()
        # An in-tree alias must not hide a dependency on the same mutable bytes.
        alias = self.root / 'accounting-alias'
        alias.symlink_to(path)
        component['artifacts'] = [dict(self.artifact), {
            'path': 'accounting-alias', 'sha256': hashlib.sha256(alias.read_bytes()).hexdigest()}]
        with self.assertRaisesRegex(ValueError, 'mutable gate accounting'):
            self.blockers()

        hardlink = self.root / 'accounting-hardlink'
        os.link(path, hardlink)
        component['artifacts'] = [dict(self.artifact), {
            'path': hardlink.name, 'sha256': hashlib.sha256(hardlink.read_bytes()).hexdigest()}]
        with self.assertRaisesRegex(ValueError, 'mutable gate accounting'):
            self.blockers()

    def test_revision2_accounting_selects_hashed_candidate_registry(self):
        registry, paths = self.candidate_registry()
        relative = 'docs/specifications/smir/portable/candidate-registry.json'
        (self.root / relative).write_text(json.dumps(registry))
        self.registry = registry
        self.manifest.update(format_revision=2, candidate_registry=relative)
        artifacts = [dict(self.artifact)] + [
            {'path': path, 'sha256': hashlib.sha256((self.root / path).read_bytes()).hexdigest()}
            for path in sorted(paths | {relative})]
        for component in self.manifest['components']: component['artifacts'] = copy.deepcopy(artifacts)
        for receipt in self.receipts: receipt['inputs'] = copy.deepcopy(artifacts)
        self.manifest['candidate_sha256'] = candidate_hash(self.manifest['components'])
        self.manifest['candidate_acknowledgements'] = self.synthetic_candidate_reviews(self.manifest['candidate_sha256'])
        self.assertEqual(self.blockers(), [])
        wrong = copy.deepcopy(registry)
        wrong['sections'][9]['schema_state'] = 'pending-full-role-review'
        with self.assertRaisesRegex(ValueError, 'candidate registry selection'):
            compiler_blockers(self.manifest, wrong, self.ledger, self.receipts, self.root)

    @staticmethod
    def synthetic_candidate_reviews(digest):
        reviews = []
        for role in sorted(set(COMPONENT_OWNERS.values())):
            statement = f'Synthetic checker-only review: {role} {digest}'
            reviews.append({'role': role, 'candidate_sha256': digest,
                'components': sorted(name for name, owner in COMPONENT_OWNERS.items() if owner == role),
                'statement': statement,
                'statement_sha256': hashlib.sha256(statement.encode()).hexdigest()})
        return reviews

    def test_exact_candidate_review_digest_and_component_partitions(self):
        manifest = {'candidate_sha256': '1' * 64}
        self.assertEqual(len(candidate_review_blockers(manifest)), 5)
        manifest['candidate_acknowledgements'] = self.synthetic_candidate_reviews(manifest['candidate_sha256'])
        self.assertEqual(candidate_review_blockers(manifest), [])
        manifest['candidate_acknowledgements'][0]['candidate_sha256'] = '2' * 64
        self.assertRegex(' '.join(candidate_review_blockers(manifest)), 'different digest')
        manifest['candidate_acknowledgements'][0]['candidate_sha256'] = manifest['candidate_sha256']
        manifest['candidate_acknowledgements'][0]['components'] = []
        self.assertRegex(' '.join(candidate_review_blockers(manifest)), 'omits owned components')
        manifest['candidate_acknowledgements'].pop()
        self.assertRegex(' '.join(candidate_review_blockers(manifest)), 'missing exact review')

    def test_exact_candidate_review_rejects_unknown_duplicate_and_tampered_records(self):
        base = {'candidate_sha256': '1' * 64,
                'candidate_acknowledgements': self.synthetic_candidate_reviews('1' * 64)}
        mutations = [lambda rows: rows.append(copy.deepcopy(rows[0])),
                     lambda rows: rows[0].update(role='UNKNOWN'),
                     lambda rows: rows[0].update(candidate_sha256=True),
                     lambda rows: rows[0].update(components=['unknown-component']),
                     lambda rows: rows[0]['components'].append(rows[0]['components'][0]),
                     lambda rows: rows[0].update(statement='altered after review'),
                     lambda rows: rows[0].update(extra='unregistered field')]
        for mutate in mutations:
            changed = copy.deepcopy(base)
            mutate(changed['candidate_acknowledgements'])
            with self.assertRaises(ValueError):
                candidate_review_blockers(changed)

    def test_every_missing_component_is_rejected(self):
        for index in range(len(self.manifest['components'])):
            with self.subTest(index=index):
                manifest = copy.deepcopy(self.manifest)
                del manifest['components'][index]
                with self.assertRaisesRegex(ValueError, 'missing compiler component'):
                    compiler_blockers(manifest, self.registry, self.ledger,
                                      self.receipts, self.root)

    def test_stale_source_or_receipt_rejected(self):
        (self.root / 'contract').write_text('changed after witness\n')
        with self.assertRaisesRegex(ValueError, 'stale artifact'):
            self.blockers()

    def test_new_discovered_input_invalidates_receipt(self):
        self.receipts[0]['input_roots'] = ['.']
        self.assertEqual(self.blockers(), [])
        (self.root / 'new-test').write_text('new test after receipt\n')
        with self.assertRaisesRegex(ValueError, 'stale receipt input inventory'):
            self.blockers()

    def test_gate_prerequisite_partitions(self):
        component = self.manifest['components'][0]
        for field, value in [('state', 'incomplete'), ('blockers', ['unresolved']),
                             ('artifacts', []), ('witnesses', [])]:
            with self.subTest(field=field):
                original = component[field]
                component[field] = value
                self.assertTrue(self.blockers())
                component[field] = original
        for field, value in [('state', 'proposed'), ('acknowledged_by', []),
                             ('artifacts', [])]:
            original = self.manifest['decisions'][0][field]
            self.manifest['decisions'][0][field] = value
            self.assertTrue(self.blockers())
            self.manifest['decisions'][0][field] = original
        self.registry['sections'][0]['payload_status'] = 'unspecified'
        self.assertTrue(self.blockers())
        self.registry['sections'][0]['payload_status'] = 'decision-complete'
        self.manifest['candidate_sha256'] = None
        self.assertTrue(self.blockers())

    def test_witness_false_green_partitions(self):
        original = copy.deepcopy(self.receipts[0])
        invalid = [dict(original, outcome='failed'), dict(original, independent=False),
                   dict(original, scope='framing-only'), dict(original, qualifies=[]),
                   dict(original, inputs=[]), dict(original, case_kinds={})]
        for counts in [{'passed': 0, 'failed': 0, 'skipped': 0},
                       {'passed': 3, 'failed': 1, 'skipped': 0},
                       {'passed': 3, 'failed': 0, 'skipped': 1}]:
            invalid.append(dict(original, counts=counts))
        for receipt in invalid:
            with self.subTest(receipt=receipt):
                self.receipts[0] = receipt
                self.assertTrue(self.blockers())
        self.receipts[0] = original

    def test_negative_and_boolean_witness_counts_rejected(self):
        for value in (-1, True, 1.0):
            self.receipts[0]['counts']['passed'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'counts'):
                self.blockers()

    def test_unknown_witness_and_unowned_requirement_rejected(self):
        self.manifest['components'][0]['witnesses'] = ['absent']
        with self.assertRaisesRegex(ValueError, 'unknown witness'):
            self.blockers()
        self.manifest['components'][0]['witnesses'] = [self.receipts[0]['id']]
        self.manifest['components'][0]['reference_receipts'] = ['absent']
        with self.assertRaisesRegex(ValueError, 'unknown reference receipt'):
            self.blockers()
        del self.manifest['components'][0]['reference_receipts']
        self.ledger['UNOWNED-001'] = {'status': 'specified', 'test': None}
        with self.assertRaisesRegex(ValueError, 'unowned compiler requirements'):
            self.blockers()

    def test_draft_requirement_blocks_freeze(self):
        self.ledger['TEST-001']['status'] = 'draft'
        self.assertTrue(self.blockers())

    def test_decision_artifacts_cannot_escape_candidate_identity(self):
        (self.root / 'decision').write_text('changed interface decision\n')
        self.manifest['decisions'][0]['artifacts'] = [{
            'path': 'decision',
            'sha256': hashlib.sha256((self.root / 'decision').read_bytes()).hexdigest(),
        }]
        with self.assertRaisesRegex(ValueError, 'omitted from candidate inputs'):
            self.blockers()

    def test_duplicate_json_keys_and_escaping_paths_rejected(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"gate": false, "gate": true}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            load_json(path)
        path.write_text('{"count": NaN}')
        with self.assertRaisesRegex(ValueError, 'non-finite JSON'):
            load_json(path)
        for relative in ('../outside', '/outside'):
            with self.subTest(path=relative), self.assertRaisesRegex(ValueError, 'escapes root'):
                artifact_bytes(self.root, relative)

    def test_malformed_revision_command_and_duplicate_witness_rejected(self):
        self.manifest['format_revision'] = True
        with self.assertRaisesRegex(ValueError, 'manifest revision'):
            self.blockers()
        self.manifest['format_revision'] = 1
        self.receipts[0]['argv'] = 'not an argv array'
        with self.assertRaisesRegex(ValueError, 'exact argv'):
            self.blockers()
        self.receipts[0]['argv'] = ['synthetic-test']
        self.manifest['components'][0]['witnesses'] *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate or invalid witnesses'):
            self.blockers()


class OrderedRecordTests(unittest.TestCase):
    RECORDS = {
        'message': {'fields': [['version', 'u16'], ['flag', 'bool'], ['signed', 'i32'],
                               ['label', 'utf8'], ['choice', 'opt:choice'],
                               ['words', 'vec:u16'], ['digest', 'digest32'], ['body', 'hex']]},
        'choice': {'discriminator': 'kind', 'variants': {
            'none': [], 'some': [['amount', 'i64']],
        }},
    }

    def setUp(self):
        self.codec = RecordCodec(self.RECORDS)
        self.message = {'version': 0x1234, 'flag': True, 'signed': -2, 'label': 'A\u03bb',
                        'choice': {'some': {'kind': 'some', 'amount': -1}},
                        'words': [65535, 0], 'digest': bytes(range(32)).hex(), 'body': '00ff'}
        # Hand-derived field bytes, independent of RecordCodec/struct.pack.
        self.golden = bytes.fromhex(
            '3412 01 feffffff 03000000 41cebb 01 04 736f6d65 ffffffffffffffff '
            '02000000 ffff 0000 '
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f '
            '02000000 00ff')

    def test_independent_ordered_record_golden(self):
        self.assertEqual(self.codec.encode('message', self.message), self.golden)
        self.assertEqual(self.codec.decode('message', self.golden), self.message)
        for end in range(len(self.golden)):
            with self.subTest(end=end), self.assertRaises(RecordError):
                self.codec.decode('message', self.golden[:end])
        with self.assertRaisesRegex(RecordError, 'WIRE-TRAILING'):
            self.codec.decode('message', self.golden + b'\x00')

    def test_fixed_width_signed_and_unsigned_boundaries(self):
        for bits in (8, 16, 32, 64):
            size = bits // 8
            for kind, cases in [
                    (f'u{bits}', [(0, bytes(size)), (2**bits - 1, b'\xff' * size)]),
                    (f'i{bits}', [(-2**(bits - 1), bytes(size - 1) + b'\x80'),
                                  (2**(bits - 1) - 1, b'\xff' * (size - 1) + b'\x7f')])]:
                for value, raw in cases:
                    with self.subTest(kind=kind, value=value):
                        self.assertEqual(self.codec.encode(kind, value), raw)
                        self.assertEqual(self.codec.decode(kind, raw), value)
                minimum, maximum = (0, 2**bits - 1) if kind[0] == 'u' else (-2**(bits - 1), 2**(bits - 1) - 1)
                for value in (minimum - 1, maximum + 1):
                    with self.assertRaisesRegex(RecordError, 'WIRE-RANGE'):
                        self.codec.encode(kind, value)
                with self.assertRaisesRegex(RecordError, 'WIRE-TYPE'):
                    self.codec.encode(kind, True)

    def test_nested_options_are_distinct_and_canonical(self):
        for value, payload in [(None, b'\x00'), ({'some': None}, b'\x01\x00'),
                               ({'some': {'some': 7}}, b'\x01\x01\x07')]:
            self.assertEqual(self.codec.encode('opt:opt:u8', value), payload)
            self.assertEqual(self.codec.decode('opt:opt:u8', payload), value)
        with self.assertRaisesRegex(RecordError, 'WIRE-TAG'):
            self.codec.decode('opt:u8', b'\x02')
        for value in (1, {}, {'other': 1}, {'some': 1, 'other': 2}):
            with self.assertRaisesRegex(RecordError, 'WIRE-TYPE'):
                self.codec.encode('opt:u8', value)

    def test_utf8_shortest_scalar_encoding_and_no_normalization(self):
        for raw in (b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\x80'):
            with self.assertRaisesRegex(RecordError, 'WIRE-TEXT'):
                self.codec.decode('utf8', len(raw).to_bytes(4, 'little') + raw)
        with self.assertRaisesRegex(RecordError, 'WIRE-TEXT'):
            self.codec.encode('utf8', '\ud800')
        encodings = []
        for value in ('\u00e9', 'e\u0301', '\U0010ffff', '\x00'):
            raw = self.codec.encode('utf8', value)
            self.assertEqual(self.codec.decode('utf8', raw), value)
            encodings.append(raw)
        self.assertNotEqual(encodings[0], encodings[1])

    def test_exact_fields_tags_and_primitive_representations(self):
        for value in [dict(self.message, extra=0), {k: v for k, v in self.message.items() if k != 'label'}, []]:
            with self.assertRaisesRegex(RecordError, 'WIRE-TYPE'):
                self.codec.encode('message', value)
        for kind, value in [('token', ''), ('token', 'Upper'), ('token', 'a' * 64),
                            ('hex', 'FF'), ('hex', '0'), ('bool', 1), ('bytes', [])]:
            with self.subTest(kind=kind), self.assertRaises(RecordError):
                self.codec.encode(kind, value)
        with self.assertRaisesRegex(RecordError, 'WIRE-TAG'):
            self.codec.decode('choice', b'\x05other')
        with self.assertRaisesRegex(RecordError, 'WIRE-RANGE'):
            self.codec.decode('bool', b'\x02')
        self.assertEqual(self.codec.decode('bytes', self.codec.encode('bytes', b'\x00\xff')), b'\x00\xff')
        self.assertEqual(self.codec.decode('token', self.codec.encode('token', 'a' * 63)), 'a' * 63)

    def test_schema_snapshot_and_invalid_definitions(self):
        records = copy.deepcopy(self.RECORDS)
        codec = RecordCodec(records)
        records['message']['fields'].clear()
        self.assertEqual(codec.decode('message', self.golden), self.message)
        invalid = [{}, {'u8': {'fields': []}}, {'bad': {'fields': [['x', 'unknown']]}},
                   {'bad': {'fields': [['x', 'u8'], ['x', 'u16']]}},
                   {'bad': {'discriminator': 'kind', 'variants': {'a': [['kind', 'u8']]}}},
                   {'bad': {'fields': [], 'extra': True}}]
        for schema in invalid:
            with self.subTest(schema=schema), self.assertRaisesRegex(RecordError, 'WIRE-SCHEMA'):
                RecordCodec(schema)

    def test_record_quotas_and_recursive_shapes(self):
        for limits in [RecordLimits(max_bytes=len(self.golden) - 1), RecordLimits(max_nodes=2),
                       RecordLimits(max_depth=0), RecordLimits(max_list=1), RecordLimits(max_string=2)]:
            codec = RecordCodec(self.RECORDS, limits)
            with self.assertRaisesRegex(RecordError, 'WIRE-LIMIT'):
                codec.encode('message', self.message)
            with self.assertRaisesRegex(RecordError, 'WIRE-LIMIT'):
                codec.decode('message', self.golden)
        for limits in [RecordLimits(max_nodes=-1), RecordLimits(max_depth=129), RecordLimits(max_bytes=True)]:
            with self.assertRaisesRegex(RecordError, 'WIRE-CONFIG'):
                RecordCodec(self.RECORDS, limits)
        recursive = RecordCodec({'node': {'fields': [['next', 'opt:node']]}}, RecordLimits(max_depth=8))
        value = {'next': None}
        for _ in range(9):
            value = {'next': {'some': value}}
        with self.assertRaisesRegex(RecordError, 'WIRE-LIMIT'):
            recursive.encode('node', value)
        with self.assertRaisesRegex(RecordError, 'WIRE-LIMIT'):
            recursive.decode('node', b'\x01' * 9 + b'\x00')


class IndependentRecordTests(unittest.TestCase):
    """Compile schema tables, never generated codec logic, for the C++ oracle."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='rax-smir-record-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.records = copy.deepcopy(OrderedRecordTests.RECORDS)
        cls.records['recursive_test'] = {'fields': [['next', 'opt:recursive_test']]}
        cls.schema_hashes = {}
        cls.schemas = {}
        for owner in ('execution', 'runtime', 'abi'):
            path = ROOT / f'docs/specifications/smir/portable/schema/{owner}/candidate.json'
            payload = path.read_bytes()
            cls.schema_hashes[owner] = hashlib.sha256(payload).hexdigest()
            cls.schemas[owner] = json.loads(payload)
            for name, record in cls.schemas[owner]['records'].items():
                if name in cls.records and cls.records[name] != record:
                    raise AssertionError(f'cross-role record conflict: {name}')
                cls.records[name] = record
        cls.codec = RecordCodec(cls.records)
        cls.accepted = cls.rejected = 0

        def fields(layout):
            return '{' + ','.join('{' + json.dumps(name) + ',' + json.dumps(kind) + '}'
                                  for name, kind in layout) + '}'

        rows = []
        for name, record in sorted(cls.records.items()):
            variants = '{' + ','.join('{' + json.dumps(tag) + ',' + fields(layout) + '}'
                                      for tag, layout in record.get('variants', {}).items()) + '}'
            rows.append('{' + json.dumps(name) + ',{' + json.dumps(record.get('discriminator', ''))
                        + ',' + fields(record.get('fields', [])) + ',' + variants + '}}')
        path = Path(cls.directory.name) / 'schema.inc'
        path.write_text('const rax::smir::records::Schema smir_test_schema = {\n'
                        + ',\n'.join(rows) + '\n};\n')
        cls.probe = Path(cls.directory.name) / 'probe'
        subprocess.run([os.environ.get('CXX', 'clang++'), '-std=c++20', '-Wall', '-Wextra', '-Werror',
                        '-DSMIR_RECORD_TEST_SCHEMA=' + json.dumps(str(path)),
                        str(ROOT / 'tools/smir-format/cpp_probe.cpp'), '-o', str(cls.probe)], check=True)
        def rust_fields(layout):
            return 'vec![' + ','.join('(' + json.dumps(name) + '.into(),'
                                      + json.dumps(kind) + '.into())' for name, kind in layout) + ']'

        rust_rows = []
        for name, record in sorted(cls.records.items()):
            variants = 'BTreeMap::from([' + ','.join('(' + json.dumps(tag) + '.into(),'
                                                     + rust_fields(layout) + ')'
                                                     for tag, layout in record.get('variants', {}).items()) + '])'
            discriminator = ('Some(' + json.dumps(record['discriminator']) + '.into())'
                             if 'discriminator' in record else 'None')
            rust_rows.append('(' + json.dumps(name) + '.into(), Definition{discriminator:'
                             + discriminator + ',fields:' + rust_fields(record.get('fields', []))
                             + ',variants:' + variants + '})')
        rust_schema = Path(cls.directory.name) / 'schema.rs'
        rust_schema.write_text('fn smir_test_schema()->framing::records::Schema {\n'
                               'use std::collections::BTreeMap;use framing::records::Definition;\n'
                               'BTreeMap::from([' + ',\n'.join(rust_rows) + '])}\n')
        cls.rust_probe = Path(cls.directory.name) / 'rust_probe'
        subprocess.run(['rustc', '--edition', '2024', '--cfg', 'smir_record_schema',
                        str(ROOT / 'tools/smir-format/rust_probe.rs'), '-o', str(cls.rust_probe)],
                       env=dict(os.environ, SMIR_RECORD_TEST_SCHEMA=str(rust_schema)), check=True)

    @classmethod
    def tearDownClass(cls):
        print(f'Ordered-record cross-codec cases: {cls.accepted} accepted, {cls.rejected} rejected; '
              f'Python/C++/Rust decoders and encoders, {len(cls.records)} schema definitions')
        print('Ordered-record schema snapshot SHA256: ' + json.dumps(cls.schema_hashes, sort_keys=True))

    def compare(self, kind, payload):
        path = Path(self.directory.name) / 'input.bin'
        path.write_bytes(payload)
        result = subprocess.run([str(self.probe), '--record', kind, str(path)],
                                capture_output=True, text=True)
        rust_result = subprocess.run([str(self.rust_probe), '--record', kind, str(path)],
                                    capture_output=True, text=True)
        self.assertEqual(rust_result.returncode, result.returncode, rust_result.stderr + result.stdout)
        if result.returncode == 0:
            self.assertEqual(json.loads(rust_result.stdout), json.loads(result.stdout))
        else:
            self.assertEqual(rust_result.stdout, result.stdout)
        try:
            value = self.codec.decode(kind, payload)
        except RecordError as error:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout.strip(), str(error))
            type(self).rejected += 1
        else:
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            def json_view(value):
                if type(value) is bytes: return value.hex()
                if type(value) is list: return [json_view(item) for item in value]
                if type(value) is dict: return {key: json_view(item) for key, item in value.items()}
                return value
            self.assertEqual(json.loads(result.stdout), json_view(value))
            self.assertEqual(self.codec.encode(kind, value), payload)
            type(self).accepted += 1

    def test_golden_and_all_truncations(self):
        fixture = OrderedRecordTests()
        fixture.setUp()
        self.compare('message', fixture.golden)
        for end in range(len(fixture.golden)):
            self.compare('message', fixture.golden[:end])
        self.compare('message', fixture.golden + b'\x00')

    def test_cpp_record_encoder_rejection_partitions(self):
        result = subprocess.run([str(self.probe), '--record-self-test'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'C++ record encoder partitions: 15')

    def test_primitive_partitions(self):
        for bits in (8, 16, 32, 64):
            for signed in (False, True):
                kind = ('i' if signed else 'u') + str(bits)
                minimum = -2**(bits - 1) if signed else 0
                maximum = 2**(bits - int(signed)) - 1
                for value in {minimum, maximum, 0}:
                    self.compare(kind, self.codec.encode(kind, value))
        for kind, values in [('utf8', ['\0', '\u00e9', 'e\u0301', '\U0010ffff']),
                             ('token', ['a', 'a' * 63]), ('bytes', [b'\0\xff']),
                             ('bool', [True, False]), ('digest32', ['ab' * 32]),
                             ('opt:opt:u8', [None, {'some': None}, {'some': {'some': 255}}])]:
            for value in values:
                self.compare(kind, self.codec.encode(kind, value))
        for raw in (b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\x80'):
            self.compare('utf8', len(raw).to_bytes(4, 'little') + raw)
        for kind, raw in [('token', b'\x00'), ('token', b'\x01A'), ('bool', b'\x02'),
                          ('opt:u8', b'\x02'), ('choice', b'\x05other'),
                          ('vec:u8', (65537).to_bytes(4, 'little')),
                          ('recursive_test', b'\x01' * 65 + b'\x00')]:
            self.compare(kind, raw)

    def sample(self, kind, variant=None, depth=0):
        self.assertLess(depth, 32, f'unbounded nonoptional schema recursion: {kind}')
        if kind.startswith('vec:'): return []
        if kind.startswith('opt:'): return None
        if kind in RecordCodec.INTEGERS: return 0
        if kind == 'bool': return False
        if kind == 'bytes': return b''
        if kind in {'hex', 'utf8'}: return ''
        if kind == 'token': return 'none'
        if kind == 'digest32': return '00' * 32
        record = self.records[kind]
        discriminator = record.get('discriminator')
        tag = variant or (next(iter(record['variants'])) if discriminator else None)
        layout = record['variants'][tag] if discriminator else record['fields']
        result = {name: self.sample(child, depth=depth + 1) for name, child in layout}
        if discriminator: result[discriminator] = tag
        return result

    def test_every_candidate_record_variant(self):
        # These are representation witnesses for every shape, not positive
        # semantic modules. Semantic checkers must reject invalid field meanings.
        for kind, record in self.records.items():
            for variant in record.get('variants', [None]):
                with self.subTest(kind=kind, variant=variant):
                    self.compare(kind, self.codec.encode(kind, self.sample(kind, variant)))

    def test_explicit_source_call_plans_have_distinct_mandatory_wire_fields(self):
        for kind, variant in [('operation', 'call'), ('terminator', 'invoke'),
                              ('terminator', 'tailcall')]:
            with self.subTest(kind=kind, variant=variant):
                generic = self.sample(kind, variant)
                self.assertIn('source_plan', generic)
                self.assertIsNone(generic['source_plan'])
                source = copy.deepcopy(generic)
                source['source_plan'] = {'some': {'module': {'kind': 'self'}, 'id': 7}}
                raw_generic = self.codec.encode(kind, generic)
                raw_source = self.codec.encode(kind, source)
                self.assertNotEqual(raw_generic, raw_source)
                self.compare(kind, raw_generic)
                self.compare(kind, raw_source)
                missing = copy.deepcopy(generic)
                del missing['source_plan']
                with self.assertRaises(RecordError):
                    self.codec.encode(kind, missing)
                # None's final discriminant byte is mandatory, not an omitted
                # optional tail that an old reader can silently supply.
                self.compare(kind, raw_generic[:-1])

    def test_call_signature_execution_and_code_address_are_explicit_records(self):
        address = {'kind': 'code_address', 'id': 7}
        self.compare('type', self.codec.encode('type', address))
        invalid = dict(address, signature={'module': {'kind': 'self'}, 'id': 8})
        with self.assertRaises(RecordError):
            self.codec.encode('type', invalid)
        signature = self.sample('call_signature')
        self.assertIn('execution', signature)
        self.compare('call_signature', self.codec.encode('call_signature', signature))
        del signature['execution']
        with self.assertRaises(RecordError):
            self.codec.encode('call_signature', signature)

    def bundle(self):
        codec = CandidateCodec(self.schemas)
        roots = {identifier: self.sample(name) for identifier, name in codec.ROOTS.items()}
        for identifier, root in roots.items():
            root['payload_revision'] = codec.PAYLOAD_REVISIONS[identifier]
        roots[2]['manifest']['kind'] = 'object'
        roots[2]['manifest']['identity'] = '7f' * 32
        roots[2]['manifest']['site'] = '7f' * 32
        return codec, roots

    def test_full_payload_bundle_and_independent_hash_preimage(self):
        codec, roots = self.bundle()
        before = copy.deepcopy(roots)
        payload = codec.encode(roots, metadata=[{'kind': 0xffff, 'required': False, 'hex': 'aabb'}])
        decoded = codec.decode(payload)
        self.assertEqual(roots, before, 'encoding must not rewrite caller-owned roots')
        self.assertEqual(decoded.content_digest, codec.content_digest(roots))
        self.assertEqual(decoded.roots[2]['manifest']['identity'], decoded.content_digest)
        digest = hashlib.sha256(b'SMIR0.2\0\x02\x00\x00\x00')
        for section in decoded.envelope['sections']:
            identifier = section['kind']
            if identifier >= 0x8000: continue
            raw = bytes.fromhex(section['hex'])
            if identifier == 2:
                # Independently locate revision:u32 followed by manifest's
                # first identity:digest32. Equal site bytes MUST remain hashed.
                self.assertEqual(raw[:4], b'\x02\0\0\0')
                raw = raw[:4] + bytes(32) + raw[36:]
                self.assertIn(b'\x7f' * 32, raw)
            digest.update(identifier.to_bytes(2, 'little'))
            digest.update(len(raw).to_bytes(8, 'little'))
            digest.update(raw)
            self.compare(codec.ROOTS[identifier], bytes.fromhex(section['hex']))
        self.assertEqual(decoded.content_digest, digest.hexdigest())
        changed = codec.encode(roots, metadata=[{'kind': 0x8000, 'required': False, 'hex': 'deadbeef'}])
        self.assertNotEqual(payload, changed)
        self.assertEqual(codec.decode(changed).content_digest, decoded.content_digest)

    def candidate_records(self, payload):
        path = Path(self.directory.name) / 'candidate-records.smo'
        path.write_bytes(payload)
        return subprocess.run([str(self.probe), '--candidate-records', str(path)],
                              capture_output=True, text=True, timeout=30)

    def test_whole_object_records_and_revision_preflight(self):
        codec, roots = self.bundle()
        payload = codec.encode(roots)
        decoded = codec.decode(payload)
        result = self.candidate_records(payload)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        document = json.loads(result.stdout)
        self.assertEqual(document['status'], 'decoded-records')
        self.assertIs(document['executable_admitted'], False)
        self.assertEqual(document['roots'], {str(key): value for key, value in decoded.roots.items()})
        self.assertEqual({key: root['payload_revision'] for key, root in decoded.roots.items()},
                         {1: 2, 2: 2, 3: 2, 4: 1, 5: 2,
                          6: 1, 7: 1, 8: 1, 9: 1, 10: 3})
        for identifier, expected in codec.PAYLOAD_REVISIONS.items():
            for raw in [b'', b'\x01', b'\x01\x00', b'\x01\x00\x00',
                        (0).to_bytes(4, 'little'), (expected + 1).to_bytes(4, 'little')]:
                with self.subTest(identifier=identifier, raw=raw.hex()):
                    envelope = copy.deepcopy(decoded.envelope)
                    envelope['sections'][identifier - 1]['hex'] = raw.hex()
                    changed = encode_candidate(envelope)
                    with self.assertRaisesRegex(RecordError, '^WIRE-REVISION$'):
                        codec.decode(changed)
                    result = self.candidate_records(changed)
                    self.assertEqual((result.returncode, result.stdout.strip()), (2, 'WIRE-REVISION'),
                                     result.stderr)
        # An old revision must fail at its word, even with no old-schema body.
        envelope = copy.deepcopy(decoded.envelope)
        envelope['sections'][9]['hex'] = '01000000'
        changed = encode_candidate(envelope)
        with self.assertRaisesRegex(RecordError, '^WIRE-REVISION$'):
            codec.decode(changed)
        result = self.candidate_records(changed)
        self.assertEqual((result.returncode, result.stdout.strip()), (2, 'WIRE-REVISION'))

    def test_whole_object_records_do_not_issue_semantic_or_identity_proofs(self):
        codec, roots = self.bundle()
        payload = codec.encode(roots)
        envelope = decode_candidate(payload)
        root = codec.decode(payload).roots[9]
        root['capabilities'] = ['changed']
        envelope['sections'][8]['hex'] = codec.records.encode('runtime_capabilities', root).hex()
        changed = encode_candidate(envelope)
        with self.assertRaisesRegex(RecordError, '^WIRE-IDENTITY$'):
            codec.decode(changed)
        # This independent mode deliberately checks framing and ordered records
        # only. Its result must not be confused with CandidateCodec's identity
        # check or the production verifier's stronger static proof.
        result = self.candidate_records(changed)
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document['status'], 'decoded-records')
        self.assertIs(document['executable_admitted'], False)

    def test_encode_revision_map_requires_exact_integer_words(self):
        codec, roots = self.bundle()
        for identifier, expected in codec.PAYLOAD_REVISIONS.items():
            for invalid in (None, True, float(expected), str(expected), expected + 1):
                with self.subTest(identifier=identifier, invalid=invalid):
                    changed = copy.deepcopy(roots)
                    changed[identifier]['payload_revision'] = invalid
                    with self.assertRaisesRegex(RecordError, '^WIRE-REVISION$'):
                        codec.encode(changed)

    def test_bundle_root_identity_revision_and_schema_rejections(self):
        codec, roots = self.bundle()
        payload = codec.encode(roots)
        envelope = decode_candidate(payload)
        # Canonical, valid record bytes with a changed meaning-bearing token.
        root = codec.decode(payload).roots[9]
        root['capabilities'] = ['changed']
        envelope['sections'][8]['hex'] = codec.records.encode('runtime_capabilities', root).hex()
        with self.assertRaisesRegex(RecordError, 'WIRE-IDENTITY'):
            codec.decode(encode_candidate(envelope))
        envelope = decode_candidate(payload)
        raw = bytes.fromhex(envelope['sections'][0]['hex'])
        envelope['sections'][0]['hex'] = ((1).to_bytes(4, 'little') + raw[4:]).hex()
        with self.assertRaisesRegex(RecordError, 'WIRE-REVISION'):
            codec.decode(encode_candidate(envelope))
        with self.assertRaisesRegex(RecordError, 'WIRE-ROOTS'):
            codec.encode({identifier: root for identifier, root in roots.items() if identifier != 1})
        schemas = copy.deepcopy(self.schemas)
        schemas['runtime']['records']['entity_ref']['fields'].reverse()
        with self.assertRaisesRegex(RecordError, 'WIRE-SCHEMA-CONFLICT'):
            CandidateCodec(schemas)
        with self.assertRaisesRegex(RecordError, 'WIRE-METADATA'):
            codec.encode(roots, metadata=[{'kind': 10, 'required': False, 'hex': ''}])

    def test_complete_abi_fixture_and_mutations(self):
        path = ROOT / 'docs/specifications/smir/portable/conformance/abi/candidate/complete.json'
        document = json.loads(path.read_text())
        # The ABI owner supplies this complete record; the integrator never
        # regenerates it. Wire agreement alone does not validate its metadata.
        payload = self.codec.encode('abi_contract', document)
        self.compare('abi_contract', payload)
        rng = random.Random(0x5245434f5244)
        for _ in range(100):
            changed = bytearray(payload)
            changed[rng.randrange(len(changed))] ^= 0x80
            self.compare('abi_contract', bytes(changed))

    def test_actual_ten_root_reference_object(self):
        self.reference_module_fixture('portable-identity.json', service=False)

    def test_actual_ten_root_service_wrapper(self):
        self.reference_module_fixture('service-wrapper.json', service=True)

    def test_actual_ten_root_source_storage_tls(self):
        self.reference_module_fixture('storage-tls-wrapper.json', service=False)

    def test_actual_ten_root_comdat_selection(self):
        # Real scalar source call plans and typed functions in separately hashed
        # modules; unsupported metadata projection never becomes a fake hash.
        script = r'''import copy,hashlib,json,sys
from pathlib import Path
ROOT=Path(sys.argv[1]);MODE=sys.argv[2];SPEC=ROOT/'docs/specifications/smir/portable'
sys.path.insert(0,str(ROOT/'tools/smir-format'))
from codec import CandidateCodec
sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
from candidate.context import RootContext
from candidate.type_system import ref,key
from candidate.values import Value
from candidate.machine import Machine
from candidate.bindings import runtime_package_module
runtime=runtime_package_module('linking');selection=runtime_package_module('selection');lookup=runtime_package_module('lookup')
sys.path.insert(0,str(ROOT/'tools/smir-abi'))
from nominal import NominalGraph
import graph_identity
sys.path.pop(0)
sys.path.insert(0,str(ROOT/'tools/smir-llvm-contract'))
from candidate_projection import project_function
base={int(k):v for k,v in json.loads((SPEC/'conformance/execution/candidate/portable-identity.json').read_text())['sections'].items()}
for n,v in {5:{'payload_revision':2,'relocations':[],'constant_initializers':[]},7:{'payload_revision':1,'segments':[]},9:{'payload_revision':1,'capabilities':[],'requirements':[],'limits':[]}}.items():base.setdefault(n,v)
codec=CandidateCodec({o:json.loads((SPEC/'schema'/o/'candidate.json').read_text()) for o in ('execution','runtime','abi')})
def module(name,copied=False,mode='any'):
 roots=copy.deepcopy(base);roots[2]['manifest']['key']['name']=name
 roots[2]['manifest'].update(kind='object',entry=None)
 roots[2]['symbols'][0].update(binding='weak',comdat={'some':0})
 roots[2]['comdats']=[{'id':0,'namespace':'example','name':'identity','selection':'exactmatch' if mode=='selector' else mode,'key_symbol':0,'members':[0]}]
 roots[2]['manifest']['exports']=[{'id':0,'namespace':'example','name':'identity','kind':'function',
  'source_linkage':'cpp','target':ref(0),'execution':{'some':ref(12)},'nominal':{'some':ref(12)},'abi_signature':{'some':ref(0)}}]
 # An independently valid, unexported noexcept source descriptor supplies the
 # negative requested ABI. Its execution signature alone matches the provider.
 nominal_id=max(t['id'] for t in roots[10]['types'])+1
 nominal_type=copy.deepcopy(next(t for t in roots[10]['types'] if t['id']==12))
 nominal_type['id']=nominal_id;nominal_type['flags'].append('noexcept');roots[10]['types'].append(nominal_type)
 nominal_type['identity']['definition']=NominalGraph(roots[10],'local').fingerprint(ref(nominal_id))
 requested=copy.deepcopy(roots[10]['signatures'][0]);requested.update(id=1,function_type=ref(nominal_id),noexcept=True);roots[10]['signatures'].append(requested)
 if mode=='selector':
  signature_id=max(t['id'] for t in roots[1]['types'])+1
  roots[1]['types'].append({'id':signature_id,'kind':'function','params':[ref(7)],'results':[ref(17)],'param_noundef':[True],'result_noundef':[True],'variadic':False,'cc':'portable'})
  fn=roots[3]['functions'][0];fn.update(signature=ref(signature_id),abi_signature=None,params=[{'id':0,'type':ref(7)}])
  fn['blocks']=[{'id':0,'phis':[],'ops':[{'op':'landingpad','results':[{'id':100,'type':ref(17)}],'operands':[0],'region':8}],'term':{'op':'return','values':[100]}}]
  roots[8]['functions']=[{'function':0,'actions':[],'regions':[{'id':8,'parent':None,'blocks':[],'exit_actions':[],'escape':'continue',
   'handlers':[{'id':17 if copied else 23,'selector':42 if copied else 73,'kind':'catch_all','nominal':None,'entry':0,'cleanup_actions':[],'catch_copy':None}]}]}]
  roots[2]['symbols'][0].update(source_linkage='none',execution=ref(signature_id),nominal=None,abi_signature=None)
  roots[2]['manifest']['exports'][0].update(source_linkage='none',execution={'some':ref(signature_id)},nominal=None,abi_signature=None)
 elif copied:
  fn=roots[3]['functions'][0];fn['blocks'][0]['ops']=[{'op':'copy','results':[{'id':100,'type':ref(17)}],'operands':[0]}];fn['blocks'][0]['term']['values']=[100]
 pointer_id=max(t['id'] for t in roots[1]['types'])+1;cast_signature=pointer_id+1
 roots[1]['types'] += [
  {'id':pointer_id,'kind':'code_ptr','signature':roots[3]['functions'][0]['signature']},
  {'id':cast_signature,'kind':'function','params':[ref(5)],'results':[ref(pointer_id)],
   'param_noundef':[True],'result_noundef':[True],'variadic':False,'cc':'portable'}]
 roots[3]['functions'].append({'id':1,'signature':ref(cast_signature),'abi_signature':None,
  'params':[{'id':0,'type':ref(5)}],'entry':0,'escape':'propagate','no_return':False,
  'blocks':[{'id':0,'phis':[],'ops':[
   {'op':'inttoptr','results':[{'id':1,'type':ref(pointer_id)}],'operands':[0]},
   {'op':'ptrtoint','results':[{'id':2,'type':ref(5)}],'operands':[1]},
   {'op':'inttoptr','results':[{'id':3,'type':ref(pointer_id)}],'operands':[2]}],
   'term':{'op':'return','values':[3]}}]})
 if mode!='selector':
  wrapper_signature=cast_signature+1
  roots[1]['types'].append({'id':wrapper_signature,'kind':'function','params':[ref(5),ref(pointer_id)],
   'results':[ref(pointer_id),ref(17)],'param_noundef':[True,True],
   'result_noundef':[True,True],'variadic':False,'cc':'portable'})
  roots[3]['functions'].append({'id':2,'signature':ref(wrapper_signature),'abi_signature':None,
   'params':[{'id':0,'type':ref(5)},{'id':1,'type':ref(pointer_id)}],
   'entry':0,'escape':'propagate','no_return':False,'blocks':[{'id':0,'phis':[],'ops':[
    {'op':'call','results':[{'id':2,'type':ref(pointer_id)}],'operands':[0],
     'target':{'kind':'direct','function':ref(1),'signature':ref(cast_signature)},'unwind':'propagate','source_plan':None},
    {'op':'constant','results':[{'id':3,'type':ref(17)}],'operands':[],
     'literal':{'kind':'bits','value':'2a000000'}},
    {'op':'call','results':[{'id':4,'type':ref(17)}],'operands':[3],
     'target':{'kind':'indirect','value':1,'signature':ref(12)},'unwind':'propagate','source_plan':None}],
    'term':{'op':'return','values':[2,4]}}]})
 decoded=codec.decode(codec.encode(roots));ctx=RootContext(decoded.roots);ctx.verify_abi();ctx.verify_execution();return decoded,ctx
A,ca=module('TU_A',True,MODE);B,cb=module('TU_B',False,MODE);contexts={A.content_digest:ca,B.content_digest:cb};objects={a:c.sections for a,c in contexts.items()}
abi=sys.modules['rax_abi_candidate_contract'];graph=abi.NominalGraph(ca.sections[10],A.content_digest,{a:c.sections[10] for a,c in contexts.items()},families={a:runtime.family(c.sections[2]['manifest']['key']) for a,c in contexts.items()})
def fp(artifact,reference):return graph.fingerprint(reference,artifact)
def digest(document):return hashlib.sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def signature_identity(artifact,reference):
 sig=contexts[artifact].abi_entity('signature',reference);out=copy.deepcopy(sig);out.pop('id')
 assert sig['this_type'] is None and not sig['vtt'] and not sig['variadic'] and sig['varargs'] is None
 out['function_type']=fp(artifact,sig['function_type']);out['params']=[fp(artifact,r) for r in sig['params']];out['result']=None if sig['result'] is None else fp(artifact,sig['result']['some'])
 out['lowered_results']=[fp(artifact,r) for r in sig['lowered_results']]
 for p in out['lowered_params']:
  assert p['copy'] is None and p['move'] is None and p['destroy'] is None
  p['source_type']=fp(artifact,p['source_type']);p['value_type']=fp(artifact,p['value_type'])
 return digest(out)
def identity(artifact,namespace,reference):
 assert namespace=='signature', 'prototype uses actual scalar source signatures only'
 return signature_identity(artifact,reference)
def body(artifact,reference):
 ctx=contexts[artifact];symbol=ctx.runtime_symbol(reference);definition=symbol['definition']['some'];assert definition['kind']=='function'
 fn=ctx.function(definition['target']);eh=next((x for x in ctx.sections[8]['functions'] if x['function']==fn['id']),{'function':fn['id'],'actions':[],'regions':[]})
 return project_function(fn,eh,ctx.types,lambda n,r:identity(artifact,n,r))
def exe(a,x,b,y):return contexts[a].types.digest(x)==contexts[b].types.digest(y)
def nominal(a,x,b,y):return graph.boundary_compatible(x,y,a,b)
rc={}
for artifact,ctx in contexts.items():
 rc[artifact]=runtime.Context(
  site=ctx.sections[10]['identity'],execution=ctx.execution,
  nominal=lambda r,c=ctx:c.abi_entity('nominal',r),function=ctx.function,symbol=ctx.runtime_symbol,
  execution_equal=ctx.types.equal,nominal_compatible=ctx.abi_graph.boundary_compatible,
  storage_layout=ctx.memory_layout,symbol_body=lambda r,a=artifact:body(a,r),
  symbol_identity=lambda r,a=artifact:digest([contexts[a].runtime_symbol(r)[field]
   for field in ['namespace','name','kind']]),
  abi_entity=ctx.abi_entity,target_entity=ctx.target_entity,native_symbol=ctx.native_symbol,
  nominal_layout=ctx.source_layout,grants=frozenset(),
  signature_compatible=ctx.abi_graph.signature_compatible,
  source_compatible=ctx.source_compatible)
 runtime.validate({n:ctx.sections[n] for n in runtime.ROOTS},rc[artifact])
if MODE=='selector':
 outputs=[]
 for artifact in [A.content_digest,B.content_digest]:
  ctx=contexts[artifact];machine=Machine(ctx.execution_checked);exception=machine.handle(ref(7),{'nominal':('self',1)})
  machine.start(0,[exception]);outputs.append(machine.run()['values'][0].data)
 assert outputs==[42,73]
 assert selection.function_body(body(A.content_digest,ref(0)))!=selection.function_body(body(B.content_digest,ref(0)))
 print(json.dumps({'actual_selector_results':outputs,'roots_per_module':10}))
def call_plan(a,x,b,y):return graph.signature_compatible(x,y,a,b)
order=[B.content_digest,A.content_digest];selected=selection.select_definitions({a:{n:s[n] for n in runtime.ROOTS} for a,s in objects.items()},rc,order,exe,nominal,signature_compatible=call_plan)
assert selected.function(A.content_digest,0)==(B.content_digest,0)
assert selected.function(B.content_digest,0)==(B.content_digest,0)
deployment={'payload_revision':1,'modules':[{'key':objects[a][2]['manifest']['key'],'artifact':a} for a in order],'edges':[]}
plan=runtime.bind_deployment({a:s[2] for a,s in objects.items()},deployment,exe,nominal,signature_compatible=call_plan)
assert len(plan['components'])==2
winner,fn=selected.function(A.content_digest,0);ctx=contexts[winner];machine=Machine(ctx.execution_checked);issued=[]
def issue(owner,kind,identity,signature):
 assert owner==winner and kind=='function' and identity==fn and signature==ref(0)
 pointer=machine.register_function(ref(0),ref(fn),ctx.function(ref(fn))['signature']);issued.append(pointer);return pointer
args=dict(requester=A.content_digest,function=True,signature_compatible=call_plan,nominal_compatible=nominal,issue=issue)
try:lookup.resolve(objects,rc,selected,A.content_digest,'example','identity',descriptor=ref(1),**args)
except Exception as error:assert getattr(error,'code',None)=='RT_LOOKUP_SIGNATURE',str(error)
else:raise AssertionError('mismatched noexcept descriptor accepted')
assert not issued
pointer=lookup.resolve(objects,rc,selected,A.content_digest,'example','identity',descriptor=ref(0),**args)
assert issued==[pointer] and machine.code_pointers[pointer.address][1]['function']==ref(fn)
pointer_type=ctx.types.get(ctx.function(ref(2))['signature'])['params'][1]
machine.start(2,[Value(ref(5),'concrete',pointer.address),Value(pointer_type,'concrete',pointer)])
results=machine.run()['values'];unprovenanced=results[0].data
assert unprovenanced.address==pointer.address and unprovenanced.origin is None
assert machine.exposed_code==set(), 'numeric code-pointer roundtrip manufactured exposure'
assert results[1].data==42
print(json.dumps({'scope':'actual ten-root two-module COMDAT reference selection and typed lookup','roots_per_module':10,'modules':2,'kept_groups':selected.kept_groups,'discarded_groups':selected.discarded_groups,'redirected_function':[winner,fn],'lookup_tokens_issued':len(issued),'lookup_wrong_source_plan_rejected':True,'reference_result':42,'production_admitted':False}))
'''
        for mode, expected in [('any', None), ('exactmatch', 'RT_COMDAT_EXACTMATCH'),
                               ('selector', 'RT_COMDAT_EXACTMATCH')]:
            with self.subTest(selection=mode):
                command = [sys.executable, '-B', '-c', script, str(ROOT), mode]
                result = subprocess.run(command, capture_output=True, text=True)
                if expected is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['roots_per_module'], 10)
                    self.assertEqual(report['modules'], 2)
                    self.assertEqual(report['reference_result'], 42)
                    self.assertEqual(report['lookup_tokens_issued'], 1)
                    self.assertTrue(report['lookup_wrong_source_plan_rejected'])
                    self.assertEqual(len(report['kept_groups']), 1)
                    self.assertEqual(len(report['discarded_groups']), 1)
                    self.assertFalse(report['production_admitted'])
                else:
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertRegex(result.stderr.splitlines()[-1], r'Reject: ' + expected + r'(?::|$)')
                    if mode == 'selector':
                        self.assertEqual(json.loads(result.stdout)['actual_selector_results'], [42, 73])

    def test_independent_semantic_join_rejections(self):
        directory = ROOT / 'docs/specifications/smir/portable/conformance/envelope/candidate/semantic'
        generated = subprocess.run([sys.executable, '-B', str(directory / 'generate.py'), '--check'],
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        fixtures = sorted(directory.glob('*.json'))
        self.assertEqual(len(fixtures), 4)
        codec = CandidateCodec(self.schemas)
        for fixture in fixtures:
            with self.subTest(fixture=fixture.name):
                case = json.loads(fixture.read_text())
                payload = bytes.fromhex(case['encoded_hex'])
                self.assertEqual(hashlib.sha256(payload).hexdigest(), case['sha256'])
                self.assertEqual(len(codec.decode(payload).roots), 10)
                path = Path(self.directory.name) / fixture.with_suffix('.smo').name
                path.write_bytes(payload)
                command = [sys.executable, '-B', str(ROOT / 'tools/smir-format/codec.py'),
                           'verify-candidate-reference', str(path), '--capability', 'memory']
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                # Both inputs are individually valid ABI/execution records. The
                # runtime join must reject; a framing/schema/import crash is not
                # evidence that the missing association was checked.
                self.assertRegex(result.stderr.strip(), r'^' + case['expected_error'] + r'(?::|$)')

    def reference_module_fixture(self, filename, *, service):
        source = ROOT / 'docs/specifications/smir/portable/conformance/execution/candidate' / filename
        roots = {int(number): value for number, value in json.loads(source.read_text())['sections'].items()}
        for identifier, empty in {5: {'payload_revision': 2, 'relocations': [], 'constant_initializers': []},
                                 7: {'payload_revision': 1, 'segments': []},
                                 9: {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []}}.items():
            roots.setdefault(identifier, empty)
        # The fixture's i32(i32) function is an object-library entry, not the
        # separately specified installed/native executable startup contract.
        roots[2]['manifest'].update(kind='object', entry=None)
        if service:
            roots[9]['capabilities'] = ['memory']
        codec = CandidateCodec(self.schemas)
        script = r'''
import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'tools/smir-format'))
from codec import CandidateCodec
spec=root/'docs/specifications/smir/portable'
schemas={o:json.loads((spec/'schema'/o/'candidate.json').read_text()) for o in ['execution','runtime','abi']}
decoded=CandidateCodec(schemas).decode(Path(sys.argv[2]).read_bytes());sections=decoded.roots
assert not sections[2]['comdats'] and not sections[2]['manifest']['dependencies']
is_service=sys.argv[3]=='service';is_storage=sys.argv[3]=='storage'
assert sections[2]['manifest']['foreign_isa']=='none'
assert len(sections[6]['imports'])==int(is_service or is_storage)
sys.path.insert(0,str(root/'tools/smir-format/execution'))
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.values import Value
from common import require
manifest=sections[2]['manifest']
require(decoded.envelope['kind']=={'object':1,'image':2}[manifest['kind']], 'module_header_kind')
expected_entry=0xffffffff if manifest['entry'] is None else manifest['entry']['some']['id']
require(decoded.envelope['entry']==expected_entry, 'module_header_entry')
for domain in sections[10]['domains']:
    if domain['isa']!='portable':
        require(domain['isa']==manifest['foreign_isa'] and domain['personality']==manifest['personality'],
            'module_native_domain')
context=RootContext(sections);context.verify_abi();program=context.verify_execution()
folder=root/'tools/smir-runtime-contract/candidate';name='_integrated_runtime_candidate'
definition=importlib.util.spec_from_file_location(name,folder/'__init__.py',submodule_search_locations=[str(folder)])
package=importlib.util.module_from_spec(definition);sys.modules[name]=package;definition.loader.exec_module(package)
runtime=importlib.import_module(name+'.linking')
def unimplemented_comdat(*args):raise ValueError('reference object excludes COMDAT projection')
bindings=runtime.Context(site=sections[10]['identity'],execution=context.execution,
    nominal=lambda r:context.abi_entity('nominal',r),function=context.function,symbol=context.runtime_symbol,
    execution_equal=context.types.equal,nominal_compatible=context.abi_graph.boundary_compatible,
    storage_layout=context.memory_layout,symbol_body=unimplemented_comdat,symbol_identity=unimplemented_comdat,
    abi_entity=context.abi_entity,target_entity=context.target_entity,
    native_symbol=context.native_symbol,nominal_layout=context.source_layout,grants=frozenset({'memory'}),
    signature_compatible=context.abi_graph.signature_compatible,
    source_compatible=context.source_compatible)
runtime.validate({n:sections[n] for n in runtime.ROOTS},bindings)
digest=decoded.content_digest
assert runtime.content_identity({s['kind']:bytes.fromhex(s['hex']) for s in decoded.envelope['sections']})==digest
deployment={'payload_revision':1,'modules':[{'key':sections[2]['manifest']['key'],'artifact':digest}],'edges':[]}
def execution_equal(a,x,b,y):
    assert a==b==digest
    return context.types.equal(x,y)
def nominal_compatible(a,x,b,y):
    assert a==b==digest
    return context.abi_graph.boundary_compatible(x,y)
plan=runtime.bind_deployment({digest:sections[2]},deployment,execution_equal,nominal_compatible)
assert plan['components']==[[digest]]
function=sections[3]['functions'][0];parameter=function['params'][0]
kind=context.types.get(parameter['type']);assert kind['kind']=='int' and kind['bits']==32
imports={};events=[]
if is_service:
    services=importlib.import_module(name+'.services')
    sys.path.insert(0,str(root/'tools/smir-runtime-contract'))
    from protocols import EffectFrontier
    from candidate.live import Registry,validate as validate_live
    from candidate.type_system import key
    frontier=EffectFrontier()
    record=sections[6]['imports'][0]
    assert record['kind']=='service' and record['name']=='memory.map'
    def mapping(machine,arguments):
        checked=services.request('memory.map',[v.data for v in arguments],
            capabilities=set(sections[9]['capabilities']),handles={},guard=None)
        ticket=frontier.begin();assert frontier.reserve(ticket)
        assert frontier.result is None
        previous=set(machine.memory.objects)
        pointer=machine.memory.allocate(arguments[0].data,arguments[1].data,source_object=False)
        assert pointer.origin not in previous
        obj=machine.memory.objects[pointer.origin]
        signature=context.types.get(record['signature'])
        live={'type':signature['results'][1],'payload':{'kind':'pointer','address':pointer.address,
            'object':{'some':obj['generation']},'generation':pointer.generation,'domain':'data','range':None,'binding_permit':None}}
        registry=Registry(pointers={('data',obj['generation'],pointer.generation):obj})
        validate_live(live,context.types,registry,0)
        def same_ticket(value):
            return (frontier.ticket['sequence']==ticket and frontier.ticket['state']=='irrevocable'
                and value==live and obj is machine.memory.objects[pointer.origin] and obj['live'])
        status,result=services.result(checked,0,live,authority=same_ticket)
        assert status==0 and result==live
        values=[Value(signature['results'][0],'concrete',status),
                Value(signature['results'][1],'concrete',pointer)]
        assert frontier.complete(ticket,values)
        assert not frontier.complete(ticket,values) and not frontier.cancel(ticket)
        next_operation,committed=frontier.resume()
        assert next_operation==1 and frontier.effects==1
        events.append(checked['arguments'])
        assert not machine.memory.exposed
        return committed
    imports[key({'module':{'kind':'self'},'id':record['id']})]=mapping
if is_storage:
    from test_candidate_storage_join import reference_image
    machine=reference_image(context)
else:
    machine=Machine(program,imports=imports)
machine.start(function['id'],[Value(parameter['type'],'concrete',27 if is_storage else 42)])
assert machine.run()['values'][0].data==42
assert events==([[16,8,3]] if is_service else [])
print(json.dumps({'roots':10,'reference_result':42,'service_calls':len(events),'production_admitted':False}))
'''
        path = Path(self.directory.name) / 'reference-object.smo'
        path.write_bytes(codec.encode(roots))
        inspection = [sys.executable, '-B', str(ROOT / 'tools/smir-format/codec.py'),
                      'verify-candidate-reference', str(path)]
        result = subprocess.run([*inspection, '--capability', 'memory'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['reference_verified'])
        self.assertFalse(report['production_admitted'])
        self.assertFalse(report['abi']['admitted_for_execution'])
        self.assertEqual(report['roots'], 10)
        if service:
            result = subprocess.run(inspection, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stderr.strip(), 'REFERENCE-MANDATORY-CAPABILITY-GRANT')
        changed = copy.deepcopy(roots)
        changed[9]['capabilities'] = sorted(set(changed[9]['capabilities']) | {'clock'})
        path.write_bytes(codec.encode(changed))
        result = subprocess.run([*inspection, '--capability', 'memory'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr.strip(), 'REFERENCE-MANDATORY-CAPABILITY-GRANT')
        path.write_bytes(codec.encode(roots))
        command = [sys.executable, '-B', '-c', script, str(ROOT), str(path),
                   'service' if service else 'storage' if filename == 'storage-tls-wrapper.json' else 'identity']
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'roots': 10, 'reference_result': 42,
                                                     'service_calls': int(service),
                                                     'production_admitted': False})
        # All negative inputs have canonical framing, record shapes and freshly
        # recomputed content identities. Semantic checks must still reject them.
        for name, diagnostic in [('undefined_ssa', 'ssa_reference'),
                                 ('unknown_capability', 'RT_CAPABILITIES'),
                                 ('wrong_site', 'RT_SITE_IDENTITY'),
                                 ('unannounced_native_domain', 'module_native_domain')]:
            changed = copy.deepcopy(roots)
            if name == 'undefined_ssa':
                changed[3]['functions'][0]['blocks'][-1]['term']['values'] = [0xfffffffe]
            elif name == 'unknown_capability':
                changed[9]['capabilities'] = ['nonexistent']
            elif name == 'wrong_site':
                changed[2]['manifest']['site'] = 'ff' * 32
            else:
                domain = copy.deepcopy(changed[10]['domains'][0])
                domain.update(id=max(item['id'] for item in changed[10]['domains']) + 1,
                              isa='x86_64', abi='itanium', personality=changed[2]['manifest']['personality'])
                changed[10]['domains'].append(domain)
            path.write_bytes(codec.encode(changed))
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, name)
            self.assertRegex(result.stderr.splitlines()[-1],
                             r'Reject: ' + diagnostic + r'(?::|$)', name)
        # Framing permits an image header. The unchanged content digest cannot
        # authorize a different manifest kind or entry at semantic admission.
        path.write_bytes(codec.encode(roots, kind=2, entry=0))
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr.splitlines()[-1], r'Reject: module_header_kind(?::|$)')
        if filename == 'storage-tls-wrapper.json':
            changed = copy.deepcopy(roots)
            # Individually valid ABI bindings cannot be substituted for the
            # segment's actual allocation-to-physical-storage association.
            changed[4]['segments'][0]['abi_binding'] = {'some': {
                'module': {'kind': 'self'}, 'id': 1}}
            path.write_bytes(codec.encode(changed))
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertRegex(result.stderr.splitlines()[-1], r'Reject: RT_SEGMENT_SOURCE_BINDING(?::|$)')


if __name__ == '__main__':
    unittest.main()
