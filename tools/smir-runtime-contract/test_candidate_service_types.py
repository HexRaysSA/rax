"""Fixed catalog integer widths and complete portable-service source objects."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from test_candidate_contract import HERE
from runtime_candidate.helpers import match_type


class ServiceFixedIntegerTests(unittest.TestCase):
    @staticmethod
    def document():
        repository = HERE.parents[1]
        path = repository / 'docs/specifications/smir/portable/conformance/runtime/candidate/joint/service-fixed-integer-types.json'
        return repository, json.loads(path.read_text())

    def verify_complete(self, cases):
        repository, _ = self.document()
        with tempfile.TemporaryDirectory(prefix='smir-service-fixed-') as folder:
            for case in cases:
                with self.subTest(case=case['name']):
                    encoded = bytes.fromhex(case['encoded_hex'])
                    self.assertEqual(hashlib.sha256(encoded).hexdigest(), case['sha256'])
                    path = Path(folder) / (case['name'] + '.smo')
                    path.write_bytes(encoded)
                    command = [sys.executable, '-B']
                    if sys.flags.optimize:
                        command.append('-O')
                    command += [str(repository / 'tools/smir-format/codec.py'),
                                'verify-candidate-reference', str(path), '--capability', case['capability']]
                    result = subprocess.run(command, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0 if case['accept'] else 2, result.stdout + result.stderr)
                    if case['accept']:
                        actual = json.loads(result.stdout)
                        self.assertTrue(actual['reference_verified'])
                        self.assertFalse(actual['production_admitted'])
                        self.assertEqual(actual['roots'], 10)
                        self.assertEqual(actual['content_digest'], case['content_identity'])
                    else:
                        self.assertEqual(result.stderr.strip(), case['expected_error'])

    def test_generated_corpus_provenance_and_byte_exact_reproduction(self):
        repository, document = self.document()
        provenance = document['provenance']
        generator = 'tools/smir-runtime-contract/generate_service_type_fixtures.py'
        self.assertEqual(provenance['generator'], generator)
        self.assertEqual(hashlib.sha256((repository / generator).read_bytes()).hexdigest(),
                         provenance['generator_sha256'])
        self.assertEqual(len(provenance['input_sha256']), 9)
        for relative, digest in provenance['input_sha256'].items():
            self.assertFalse(Path(relative).is_absolute())
            self.assertNotIn('..', Path(relative).parts)
            self.assertEqual(hashlib.sha256((repository / relative).read_bytes()).hexdigest(), digest)
        self.assertTrue(provenance['size_justification'])
        self.assertEqual(provenance['encoded_object_bytes'],
                         sum(len(bytes.fromhex(case['encoded_hex']))
                             for case in document['services'] + document['cases']))
        original = document['legacy_cases'][0]
        self.assertEqual(original['name'], 'legacy-abi1-original-file-seek')
        self.assertEqual(original['sha256'], 'b42a4c54196679f147c16f5bfac826104d195d01a9be7ccd2cc53b9a9cbfb4cb')
        self.assertEqual(original['sha256'], provenance['legacy_original_counter_object_sha256'])
        command = [sys.executable, '-B']
        if sys.flags.optimize:
            command.append('-O')
        result = subprocess.run(command + [str(repository / generator), '--check'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_legacy_abi1_revision_rejection(self):
        _, document = self.document()
        self.verify_complete(document['legacy_cases'])

    def test_file_seek_fixed_i64_complete_objects(self):
        _, document = self.document()
        self.assertEqual(len(document['cases']), 16)
        self.assertEqual(sum(case['accept'] for case in document['cases']), 2)
        self.verify_complete(document['cases'])

    def test_every_service_catalog_signature_complete_object(self):
        repository, document = self.document()
        catalog = json.loads((repository / 'docs/specifications/smir/portable/schema/runtime/services-v1.json').read_text())
        self.assertEqual(len(document['services']), 59)
        self.assertEqual({case['name'] for case in document['services']}, {record['name'] for record in catalog['records']})
        self.verify_complete(document['services'])

    def test_all_actual_fixed_catalog_tokens_and_kind_width_boundaries(self):
        repository, _ = self.document()
        templates = set()
        for name in ['helpers-v1.json', 'services-v1.json']:
            catalog = json.loads((repository / 'docs/specifications/smir/portable/schema/runtime' / name).read_text())
            for record in catalog['records']:
                for side in ['params', 'results']:
                    templates.update(formal['type'] for formal in record[side]
                                     if re.fullmatch('[iu][0-9]+', formal['type']))
        self.assertEqual(templates, {'i1', 'i32', 'i64', 'u8', 'u32', 'u64'})
        # Bounded pure matcher tests; complete checked type graphs are exercised
        # by the independently encoded objects above. No phase proof is issued.
        for template in sorted(templates):
            width = int(template[1:])
            with self.subTest(template=template):
                self.assertTrue(match_type(template, {'kind': 'int', 'bits': width}, []))
                for other in [width - 1, width + 1]:
                    self.assertFalse(match_type(template, {'kind': 'int', 'bits': other}, []))
                for kind in ['raw', 'float', 'data_ptr', 'code_ptr', 'vector', 'exception']:
                    self.assertFalse(match_type(template, {'kind': kind, 'bits': width}, []))
        int64 = {'kind': 'int', 'bits': 64}
        self.assertTrue(match_type('i64', int64, []))
        self.assertTrue(match_type('u64', int64, []))
        self.assertFalse(match_type('i128', {'kind': 'int', 'bits': 128}, []))


if __name__ == '__main__':
    unittest.main()
