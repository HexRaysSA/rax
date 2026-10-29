"""Primary SVE profile grammar, reserved encodings and access-policy checks."""
import hashlib
import json
import re
import unittest
import xml.etree.ElementTree as ET

from a64_sve_admission import ROOT, SOURCE_SHA256, SOURCE, diagram, primary_records
from a64_sve_model import (
    FEATURES, FEATURE_ALIASES, NORMALIZED_SHA256, PARAMETERS, derive, feature_expression, normal_access_policy,
    normalize_decode, normalized_source,
)
from asl_decode_allocation import evaluate


def record(features, operation='CheckSVEEnabled();', constraints=None):
    return dict(file='primary_probe.xml', iclass='probe', features=features,
                operation=operation, constraints=constraints or [], decode='')


def encoding():
    return dict(name='primary_probe', iset='A64',
                opcode=['Zero'] * 31 + ['Either'],
                fields=[dict(name='field', begin=0, width=1)], decode=[])


class PrimaryAdmission(unittest.TestCase):
    def test_rust_feature_positions_match_every_primary_feature_parameter(self):
        source = (ROOT / 'src/isa/arm/common/features.rs').read_text()
        flags = {name: int(bit) for name, bit in
                 re.findall(r'const (\w+) = 1 << (\d+);', source)}
        self.assertEqual(len(set(flags.values())), len(flags))
        for primary, rust, bit in FEATURES:
            self.assertEqual(flags[rust], bit, primary)

    def test_emitted_rust_buckets_exactly_partition_the_generated_clauses(self):
        source = (ROOT / 'src/isa/arm/aarch64/cpu/sve/profile_encodings.rs').read_text()
        raw_offsets = source.split('const PROFILE_OFFSETS:', 1)[1].split('= &[', 1)[1]
        offsets = [int(value) for value in re.findall(r'\b\d+\b', raw_offsets.split('];', 1)[0])]
        entries = [tuple(int(value.replace('_', ''), 0) for value in values)
                   for values in re.findall(r'\((0x[\da-f_]+), (0x[\da-f_]+), '
                                            r'(0x[\da-f_]+), (\d+)\)', source)]
        metadata = json.loads((ROOT / 'docs/development/a64-sve-profile/encodings.json').read_text())
        self.assertEqual(metadata.get('feature_aliases'), FEATURE_ALIASES)
        self.assertEqual(metadata['features'],
                         [dict(primary=name, rust=rust, bit=bit) for name, rust, bit in FEATURES])
        feature_mask = int(re.search(r'const PROFILE_FEATURES: u64 = (0x[\da-f]+);',
                                     source)[1], 16)
        self.assertEqual(feature_mask, sum(1 << bit for _, _, bit in FEATURES))
        clauses = {(row['mask'], row['value'], row['requirements'], row['access_policy'])
                   for row in metadata['records']}
        self.assertEqual(len(offsets), 257)
        self.assertEqual((offsets[0], offsets[-1]), (0, len(entries)))
        for bucket in range(256):
            word = ((bucket >> 5) << 29) | (((bucket >> 4) & 1) << 24) | (2 << 25)
            word |= (bucket & 15) << 12
            partition = 0xff00_f000
            expected = {entry for entry in clauses
                        if word & entry[0] & partition == entry[1] & partition}
            actual = entries[offsets[bucket]:offsets[bucket + 1]]
            self.assertEqual(set(actual), expected, f'bucket {bucket}')
            self.assertEqual(len(actual), len(expected), f'duplicate in bucket {bucket}')

    def test_pinned_primary_classes_and_normalized_input_are_complete(self):
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), SOURCE_SHA256)
        rows, aliases = primary_records()
        self.assertEqual(len(rows), 1328)
        self.assertEqual(len({row['file'] for row in rows}), 894)
        self.assertEqual(aliases, [])
        self.assertEqual(hashlib.sha256(normalized_source(rows).encode()).hexdigest(),
                         NORMALIZED_SHA256)

    def test_feature_precedence_and_independent_alternatives(self):
        expression = feature_expression('FEAT_SVE && FEAT_BF16 || FEAT_SME2')
        for value in range(8):
            env = dict(zip(['FEAT_SVE', 'FEAT_BF16', 'FEAT_SME2'],
                           [bool(value & (1 << bit)) for bit in range(3)]))
            self.assertEqual(evaluate(expression, env),
                             env['FEAT_SVE'] and env['FEAT_BF16'] or env['FEAT_SME2'])

    def test_unknown_or_negative_feature_grammar_is_not_accepted(self):
        for text in ('', '!FEAT_SVE', 'FEAT_SVE & FEAT_BF16', 'FEAT_SVE ||',
                     '(FEAT_SVE', 'FEAT_SVE)', 'runtime_feature', 'FEAT_SVE FEAT_BF16'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                feature_expression(text)

    def test_independent_positive_feature_alternatives_survive_derivation(self):
        terms, proof, unsupported = derive([record(['FEAT_SVE && FEAT_BF16 || FEAT_SME2'])],
                                           [encoding()])
        self.assertEqual(len(proof), 1)
        self.assertEqual(unsupported, [])
        self.assertEqual({key[2] for key in terms}, {(1 << 13) | (1 << 10), 1 << 20})
        self.assertTrue(all(key[3] == 1 for key in terms))

    def test_unrepresentable_future_class_is_accounted_as_unselectable(self):
        terms, proof, unsupported = derive([record(['FEAT_SVE && FEAT_SVE2p3'],
                                                  operation='UnknownFutureAccess();')],
                                           [encoding()])
        self.assertEqual((terms, proof), ({}, []))
        self.assertEqual(len(unsupported), 1)
        self.assertEqual(unsupported[0]['absent'], ['FEAT_SVE2p3'])

    def test_unsupported_feature_in_an_alternative_does_not_break_current_profiles(self):
        terms, proof, unsupported = derive([record(['FEAT_SVE || FEAT_SVE2p3'])], [encoding()])
        self.assertEqual({key[2] for key in terms}, {1 << 13})
        self.assertEqual((len(proof), unsupported), (1, []))

    def test_primary_inequality_constraint_remains_a_reserved_encoding(self):
        terms, proof, _ = derive([record(['FEAT_SVE'], constraints=[(1, 1)])], [encoding()])
        self.assertEqual(proof[0]['accepted_assignments'], 1)
        self.assertTrue(terms)
        self.assertTrue(all(mask & 1 and value & 1 == 0
                            for mask, value, _, _ in terms))

    def test_unknown_selected_access_policy_stops_derivation(self):
        with self.assertRaisesRegex(ValueError, 'normal-access policy'):
            derive([record(['FEAT_SVE'], operation='CheckFPMREnabled();')], [encoding()])

    def test_scalar_sme_and_conditional_streaming_policies_remain_distinct(self):
        self.assertEqual(normal_access_policy(record([], 'CheckSMEEnabled();')), 2)
        operation = ('if IsFeatureImplemented(FEAT_SVE2p1) then CheckSVEEnabled(); '
                     'else CheckStreamingSVEEnabled(); end;')
        self.assertEqual(normal_access_policy(record([], operation)), 3)
        with self.assertRaisesRegex(ValueError, 'normal-access policy'):
            normal_access_policy(record([], operation.replace('FEAT_SVE2p1', 'FEAT_SVE')))

    def test_effectful_generic_width_is_verified_before_erasure(self):
        for width in ('32', 'runtime_width', 'esize'):
            with self.subTest(width=width), self.assertRaisesRegex(ValueError, 'generic width'):
                normalize_decode(f'(imm, -) = DecodeBitMasks{{{width}}}(n, s, r, TRUE);')
        source = ('let esize : integer{} = 64;\nvar imm : bits(esize);\n'
                  '(imm, -) = DecodeBitMasks{esize}(n, s, r, TRUE);')
        self.assertIn('DecodeBitMasks(n, s, r, TRUE)', normalize_decode(source))

    def test_unknown_modern_constructs_cannot_disappear(self):
        for source in ('EndOfDecode(Decode_NOP);', 'UnknownIntrinsic{64}(x);',
                       'let a, b : integer = 1;'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                normalize_decode(source)

    def test_diagram_inequality_and_bit_coverage_are_explicit(self):
        node = ET.fromstring('<regdiagram><box hibit="31" width="31"><c colspan="31">0</c>'
                             '</box><box hibit="0" width="1" name="field" '
                             'constraint="!= 1"><c>x</c></box></regdiagram>')
        mask, value, fields, constraints, unknown = diagram(node)
        self.assertEqual((mask, value, fields, constraints, unknown),
                         (0xffff_fffe, 0, {'field': [(0, 1)]}, [(1, 1)], []))
        node.remove(node[0])
        with self.assertRaisesRegex(ValueError, 'incomplete diagram'):
            diagram(node)

    def test_feature_parameters_never_overlap_architectural_instruction_bits(self):
        self.assertEqual(len(PARAMETERS), 13)
        self.assertEqual(set(PARAMETERS.values()), {(bit, 1) for bit in range(32, 45)})

    def test_mutually_dependent_aes_and_pmull_names_share_the_existing_feature(self):
        self.assertEqual(FEATURE_ALIASES, {'FEAT_SVE_PMULL128': 'FEAT_SVE_AES'})
        for enabled in (False, True):
            env = {'FEAT_SVE_AES': enabled}
            self.assertEqual(evaluate(feature_expression('FEAT_SVE_PMULL128'), env), enabled)
        terms, _, unsupported = derive([record(['FEAT_SVE_PMULL128'])], [encoding()])
        self.assertEqual(unsupported, [])
        self.assertEqual({row[2] for row in terms}, {1 << 15})


if __name__ == '__main__':
    unittest.main()
