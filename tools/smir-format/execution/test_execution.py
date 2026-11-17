"""Standalone semantic, binary-record and independent arithmetic conformance."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from codec import decode, decode_sections, encode, encode_sections
from common import Limits, Reject, ROOT, SPEC, SCHEMA, check_shape
from evaluate import POISON, UNDEF, Trap, Value, integer, run
from generate_fixtures import binary, block, cases, constant, declaration, module
from verify import verify
from reference import load


class ExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='rax-smir-execution-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.probe = Path(cls.directory.name) / 'integer-probe'
        subprocess.run(['rustc', '--edition', '2024', '-D', 'warnings',
                        str(ROOT / 'tools/smir-format/execution/rust_probe.rs'),
                        '-o', str(cls.probe)], check=True)

    def test_checked_in_fixture_reproducibility(self):
        stored = json.loads((SPEC / 'conformance/execution/cases.json').read_text())
        self.assertEqual(stored, {'profile': 'integer_core_draft_v1', 'cases': cases()})

    def test_metaschema_and_primary_source_identity(self):
        for name, record in SCHEMA['records'].items():
            layouts = record.get('variants', {}).values() if 'variants' in record else [record['fields']]
            for layout in layouts:
                names = [field for field, _ in layout]
                self.assertEqual(len(names), len(set(names)), name)
                for _, kind in layout:
                    inner = kind.removeprefix('vec:')
                    self.assertTrue(inner in {'u32', 'u64', 'token', 'hex'} or inner in SCHEMA['records'], kind)
        sources = json.loads((SPEC / 'schema/execution/sources.json').read_text())
        for source in sources:
            self.assertEqual(hashlib.sha256((SPEC / source['archive']).read_bytes()).hexdigest(), source['sha256'])
            self.assertEqual(source['source_revision'], '36763294ef639d8a6a4379d81da653dda1c20686')

    def test_semantic_fixtures(self):
        accepted = rejected = 0
        for case in cases():
            with self.subTest(case=case['name']):
                if 'reject' in case:
                    with self.assertRaises(Reject) as error:
                        verify(case['module'])
                    self.assertEqual(error.exception.code, case['reject'])
                    rejected += 1
                else:
                    result = run(case['module'], case['entry'], case['arguments'])
                    for key, value in case['expected'].items():
                        self.assertEqual(result.get(key), value)
                    accepted += 1
        print(f'Execution fixtures: {accepted} accepted, {rejected} rejected; no skips')

    def test_binary_payload_roundtrip_and_every_truncation(self):
        truncated = 0
        for case in cases():
            document = case['module']
            try:
                check_shape('module', document)
            except Reject:
                # JSON structural rejection has no representable binary record.
                continue
            section_types, section_functions = encode_sections(document)
            self.assertEqual(decode_sections(section_types, section_functions), document)
            for record_type, payload in [('vec:type', section_types), ('vec:function', section_functions)]:
                # The wide arithmetic fixture adds 16 KiB raw constants; sample
                # its byte boundaries separately to keep this test O(n^2)-bounded.
                ends = range(len(payload)) if len(payload) < 4096 else [0, 1, 3, 4, 15, len(payload) - 1]
                for end in ends:
                    with self.assertRaises(Reject):
                        decode(record_type, payload[:end])
                    truncated += 1
                with self.assertRaises(Reject) as error:
                    decode(record_type, payload + b'\0')
                self.assertEqual(error.exception.code, 'trailing')
        print(f'Payload truncations rejected: {truncated}; wide fixture uses sampled boundaries')

    def test_binary_golden_layout(self):
        # Independently computed: count=1, token length=3, 'int', id=7, bits=8.
        payload = bytes.fromhex('01000000 03 696e74 07000000 08000000')
        value = [{'kind': 'int', 'id': 7, 'bits': 8}]
        self.assertEqual(encode('vec:type', value), payload)
        self.assertEqual(decode('vec:type', payload), value)
        # return has no results: token length=6, 'return', u32 zero vector count.
        term = bytes.fromhex('06 72657475726e 00000000')
        self.assertEqual(encode('terminator', {'op': 'return', 'values': []}), term)
        self.assertEqual(decode('terminator', term), {'op': 'return', 'values': []})

    def test_deterministic_payload_mutations_reject_or_reverify(self):
        rng = random.Random(0x45584543)
        source = next(case['module'] for case in cases()
                      if case['name'] == 'recursive_activation_ids_are_isolated')
        types, functions = encode_sections(source)
        decoded = rejected = verified = 0
        for _ in range(2048):
            changed_types, changed_functions = bytearray(types), bytearray(functions)
            changed = changed_types if rng.randrange(2) == 0 else changed_functions
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            try:
                document = decode_sections(bytes(changed_types), bytes(changed_functions))
                self.assertEqual(encode_sections(document), (bytes(changed_types), bytes(changed_functions)))
                decoded += 1
                verify(document)
                # A valid semantic mutation is allowed to change behavior, but
                # must remain inside the verified subset and explicit fuel cap.
                result = run(document, 0, ['03'], fuel=1000, max_frames=32)
                self.assertIn(result['kind'], {'return', 'trap', 'limit'})
                verified += 1
            except Reject:
                rejected += 1
        self.assertGreater(decoded, 0)
        self.assertGreater(rejected, 0)
        self.assertGreater(verified, 0)
        print(f'Payload mutations:2048, {decoded} structurally decoded, {verified} semantic runs, '
              f'{rejected} rejected, seed0x45584543')

    def test_shape_and_resource_rejections(self):
        for item in [None, [], True, {'revision': []}, {'revision': 1},
                     {'revision': 'integer_core_draft_v1', 'types': {}, 'functions': []}]:
            with self.assertRaises(Reject):
                verify(item)
        for tag in [None, [], {}, 4, 'Add', 'not_an_op']:
            with self.assertRaises(Reject):
                check_shape('operation', {'op': tag})
        for value in [True, -1, 2**32, 3.5]:
            with self.assertRaises(Reject):
                check_shape('u32', value)
        for value in ['a', 'FF', 'zz', '\u00e9\u00e9']:
            with self.assertRaises(Reject):
                check_shape('hex', value)
        for payload in [b'\xff' * 4, b'\x01\0\0\0\0', b'\x01\0\0\0\x40',
                        b'\x01\0\0\0\x01\xff']:
            with self.assertRaises(Reject):
                decode('vec:type', payload)
        document = cases()[0]['module']
        for limits in [replace(Limits(), max_nodes=2), replace(Limits(), max_depth=1),
                       replace(Limits(), max_blocks=0), replace(Limits(), max_bits=7),
                       replace(Limits(), max_functions=0)]:
            with self.assertRaises(Reject):
                verify(document, limits)
        for call in [lambda: encode('module', document, replace(Limits(), max_bytes=8)),
                     lambda: decode('vec:type', b'1234', replace(Limits(), max_bytes=3))]:
            with self.assertRaises(Reject):
                call()

    def test_nondominating_branch_operand(self):
        document = module([constant(0, '01', 0)], [1],
                          {'op': 'cbr', 'cond': 0, 'true': 1, 'false': 2})
        document['functions'][0]['blocks'] += [
            block(1, [constant(1, '01')], {'op': 'br', 'target': 3}),
            block(2, [], {'op': 'br', 'target': 3}),
            block(3, [], {'op': 'return', 'values': [1]})]
        with self.assertRaises(Reject) as error:
            verify(document)
        self.assertEqual(error.exception.code, 'dominance')

    def test_entry_loop_and_missing_phi_predecessor_rejected(self):
        document = module([], [], {'op': 'br', 'target': 0})
        with self.assertRaises(Reject) as error:
            verify(document)
        self.assertEqual(error.exception.code, 'cfg')
        document = next(case['module'] for case in cases() if case['name'] == 'phi_swap_cycle_simultaneous')
        document['functions'][0]['blocks'][1]['phis'][0]['incoming'].append({'block': 2, 'value': 0})
        with self.assertRaises(Reject) as error:
            verify(document)
        self.assertEqual(error.exception.code, 'phi')

    def test_conversions_and_all_comparisons(self):
        for op, source, target, input_bits, expected in [
                ('trunc', 8, 1, 'ff', '01'), ('zext', 1, 8, '01', '01'),
                ('sext', 1, 8, '01', 'ff'), ('sext', 8, 65, '80', '80ffffffffffffff01')]:
            document = module([constant(0, input_bits, 1),
                               {'op': op, 'out': declaration(1, 2), 'value': 0}], [2],
                              {'op': 'return', 'values': [1]})
            document['types'] = [{'kind': 'int', 'id': 1, 'bits': source},
                                 {'kind': 'int', 'id': 2, 'bits': target}]
            self.assertEqual(run(document, 0, [])['values'], [{'kind': 'bits', 'bits': expected}])
            document['types'][1]['bits'] = source
            with self.assertRaises(Reject):
                verify(document)
        for predicate, expected in [('eq', 0), ('ne', 1), ('ult', 0), ('ule', 0),
                                    ('ugt', 1), ('uge', 1), ('slt', 1), ('sle', 1),
                                    ('sgt', 0), ('sge', 0)]:
            document = module([constant(0, 'ff'), constant(1, '01'),
                               {'op': 'icmp', 'out': declaration(2, 0), 'a': 0, 'b': 1,
                                'predicate': predicate}], [0])
            self.assertEqual(run(document, 0, [])['values'],
                             [{'kind': 'bits', 'bits': f'{expected:02x}'}])

    def test_switch_void_calls_and_explicit_traps(self):
        document = module([constant(0, '07')], [1],
                          {'op': 'switch', 'index': 0, 'default': 1,
                           'cases': [{'bits': '07', 'target': 2}, {'bits': '09', 'target': 1}]})
        document['functions'][0]['blocks'] += [
            block(1, [constant(1, '01')], {'op': 'return', 'values': [1]}),
            block(2, [constant(2, '02')], {'op': 'return', 'values': [2]})]
        self.assertEqual(run(document, 0, [])['values'][0]['bits'], '02')
        document['functions'][0]['blocks'][0]['term']['cases'].reverse()
        with self.assertRaises(Reject) as error:
            verify(document)
        self.assertEqual(error.exception.code, 'switch')
        for term, expected in [('trap', 'explicit'), ('unreachable', 'ub_unreachable')]:
            result = run(module([], [], {'op': term}), 0, [])
            self.assertEqual((result['kind'], result['code'], result['operation']), ('trap', expected, 0))
        document = module([{'op': 'call', 'outs': [], 'callee': 1, 'args': []}], [],
                          {'op': 'return', 'values': []})
        document['functions'].append({'id': 1, 'params': [], 'results': [], 'entry': 0,
                                      'blocks': [block(0, [], {'op': 'return', 'values': []})]})
        self.assertEqual(run(document, 0, [])['values'], [])

    def test_resource_stops_recursion_and_tailcall(self):
        document = module([{'op': 'call', 'outs': [], 'callee': 0, 'args': []}], [],
                          {'op': 'return', 'values': []})
        result = run(document, 0, [], max_frames=3)
        self.assertEqual((result['kind'], result['code'], len(result['stack'])), ('limit', 'frames', 3))
        document = module([], [], {'op': 'tailcall', 'callee': 0, 'args': []})
        result = run(document, 0, [], fuel=11, max_frames=1)
        self.assertEqual((result['kind'], result['code'], result['steps'], len(result['stack'])),
                         ('limit', 'fuel', 11, 1))
        self.assertEqual(run(document, 0, [], fuel=0)['steps'], 0)

    def test_mutated_verified_document_is_reverified(self):
        document = cases()[0]['module']
        verify(document)
        document['functions'][0]['blocks'][0]['ops'][2]['op'] = 'host_execute'
        with self.assertRaises(Reject):
            run(document, 0, [])

    def test_cli_verification_run_and_pack(self):
        with tempfile.TemporaryDirectory(prefix='rax-smir-cli-') as temporary:
            directory = Path(temporary)
            source = directory / 'module.json'
            source.write_text(json.dumps(cases()[0]['module']))
            command = ['python3', str(ROOT / 'tools/smir-format/execution/reference.py')]
            verified = subprocess.run(command + ['verify', str(source)], capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn('reference-only', verified.stdout)
            evaluated = subprocess.run(command + ['run', str(source)], capture_output=True, text=True)
            self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
            self.assertEqual(json.loads(evaluated.stdout)['values'], [{'kind': 'bits', 'bits': '00'}])
            types, functions = directory / 'types.bin', directory / 'functions.bin'
            packed = subprocess.run(command + ['pack', str(source), '--types', str(types),
                                    '--functions', str(functions)], capture_output=True, text=True)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            self.assertEqual(decode_sections(types.read_bytes(), functions.read_bytes()), cases()[0]['module'])
            repeated = subprocess.run(command + ['pack', str(source), '--types', str(types),
                                      '--functions', str(functions)], capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 2)
            self.assertIn('outputs exist', repeated.stderr)
            invalid_source = directory / 'invalid.json'
            invalid_source.write_text('{"revision":0,"revision":1}')
            with self.assertRaises(Reject):
                load(invalid_source)
            invalid_source.write_text('{"revision":NaN}')
            with self.assertRaises(Reject):
                load(invalid_source)
            invalid_source.write_bytes(b'\xff')
            with self.assertRaises(Reject):
                load(invalid_source)

    def test_independent_integer_witness(self):
        rng = random.Random(0x534d4952)
        operations = list(SCHEMA['records']['operation']['variants'])
        binary_ops = [op for op in operations if op in {
            'add', 'sub', 'mul', 'shl', 'lshr', 'ashr', 'udiv', 'sdiv',
            'urem', 'srem', 'and', 'or', 'xor'}]
        comparison_ops = ['eq', 'ne', 'ult', 'ule', 'ugt', 'uge', 'slt', 'sle', 'sgt', 'sge']
        lines, expected = [], []

        def add(op, width, left, right, flags=()):
            encoding = lambda value: {'poison': 'p', 'undef': 'u'}.get(value.kind, f'{value.bits:x}')
            flag_text = ''.join({'nsw': 's', 'nuw': 'u', 'exact': 'e'}[flag] for flag in flags) or '-'
            lines.append(f'{op} {width} {encoding(left)} {encoding(right)} {flag_text}')
            try:
                value = integer('icmp' if op in comparison_ops else op, width, left, right, flags,
                                op if op in comparison_ops else None)
                expected.append({'poison': 'P', 'undef': 'U'}.get(value.kind, f'{value.bits:x}'))
            except Trap as error:
                expected.append(f'T:{error.code}')

        for width in range(1, 6):
            for a in range(1 << width):
                for b in range(1 << width):
                    for op in binary_ops:
                        flag_sets = [()]
                        if op in {'add', 'sub', 'mul', 'shl'}:
                            flag_sets += [('nsw',), ('nuw',), ('nsw', 'nuw')]
                        if op in {'lshr', 'ashr', 'udiv', 'sdiv'}:
                            flag_sets += [('exact',)]
                        for flags in flag_sets:
                            add(op, width, Value('bits', a), Value('bits', b), flags)
        for width in range(1, 129):
            mask = (1 << width) - 1
            values = [Value('bits', value) for value in {0, 1, mask, mask >> 1, 1 << (width - 1)}]
            values += [POISON, UNDEF]
            for _ in range(12):
                values.append(Value('bits', rng.getrandbits(width)))
            for left in values:
                for right in values[:7]:
                    for op in binary_ops + comparison_ops:
                        add(op, width, left, right)
            for op in ['copy', 'freeze']:
                for value in values:
                    add(op, width, value, Value('bits', 0))
        result = subprocess.run([str(self.probe)], input='\n'.join(lines) + '\n',
                                capture_output=True, text=True, check=True)
        actual = result.stdout.splitlines()
        self.assertEqual(len(actual), len(expected))
        for line, observed, wanted in zip(lines, actual, expected):
            self.assertEqual(observed, wanted, line)
        print(f'Independent integer witness: {len(expected)} cases, widths 1..128, seed 0x534d4952; no skips')


if __name__ == '__main__':
    unittest.main()
