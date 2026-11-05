#!/usr/bin/env python3
"""Cross-check independent codecs and adversarial draft framing."""
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from codec import DecodeError, NO_ENTRY, decode, encode

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
        print(f'Cross-codec cases: {cls.accepted} accepted, {cls.rejected} rejected; 3 decoders')
        cls.directory.cleanup()

    def compare(self, payload):
        path = Path(self.directory.name) / 'input.smo'
        path.write_bytes(payload)
        result = subprocess.run([str(self.probe), str(path)], capture_output=True, text=True)
        cpp_result = subprocess.run([str(self.cpp_probe), str(path)], capture_output=True, text=True)
        self.assertEqual((cpp_result.returncode, cpp_result.stdout), (result.returncode, result.stdout), cpp_result.stderr)
        try:
            module = decode(payload)
        except DecodeError as error:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout.strip(), str(error))
            type(self).rejected += 1
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], f"OK {module['kind']} {module['entry']}")
            self.assertEqual([line.rstrip() for line in lines[1:]], [f"{s['kind']} {int(s['required'])} {s['hex']}".rstrip() for s in module['sections']])
            self.assertEqual(encode(module), payload)
            type(self).accepted += 1

    def test_golden_vectors(self):
        fixtures = sorted((ROOT / 'docs/specifications/smir/portable/conformance').glob('*.json'))
        self.assertTrue(fixtures, 'golden corpus must not be empty')
        for fixture in fixtures:
            document = json.loads(fixture.read_text())
            payload = bytes.fromhex(document['encoded_hex'])
            self.assertEqual(encode(document['module']), payload)
            self.compare(payload)

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


if __name__ == '__main__':
    unittest.main()
