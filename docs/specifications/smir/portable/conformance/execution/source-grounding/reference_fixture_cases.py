"""Read actual encoded source artifacts; no prior report is an evidence input."""
from pathlib import Path
import hashlib
import json
import unittest
from reference_grounding import ROOT, budget
from candidate.context import RootContext
from candidate.bindings import runtime_package_module
from candidate import source_grounding as G


class FixtureInputs(unittest.TestCase):
    def test_original_encoded_blueprints_and_expected_constraints(self):
        directory = Path(__file__).resolve().parent / 'fixtures'
        manifest = json.loads((directory / 'manifest.json').read_bytes())
        self.assertEqual(set(manifest), {'format', 'revision', 'binding', 'runtime_authority',
                                         'source_fact_authority', 'native_execution', 'cases'})
        schemas = {name: json.loads((ROOT / 'docs/specifications/smir/portable/schema' /
                                   name / 'candidate.json').read_bytes())
                   for name in ('abi', 'execution', 'runtime')}
        codec = runtime_package_module('wire').PRIMITIVES.CandidateCodec(schemas)
        self.assertEqual(len(manifest['cases']), 13)
        for row in manifest['cases']:
            with self.subTest(name=row['name']):
                self.assertEqual(set(row), {'name', 'expected', 'files'})
                for name, expected in row['files'].items():
                    data = (directory / name).read_bytes()
                    self.assertEqual(len(data), expected['octets'])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), expected['sha256'])
                roots = codec.decode((directory / (row['name'] + '.smo')).read_bytes()).roots
                source = json.loads((directory / (row['name'] + '.source.json')).read_bytes())
                self.assertEqual({str(k): v for k, v in roots.items()}, source['sections'])
                request = json.loads((directory / (row['name'] + '.request.json')).read_bytes())
                owner = RootContext(roots)
                ledger = budget()
                if row['expected']['status'] == 'rejected':
                    with self.assertRaises(Exception) as caught:
                        G.ground(owner, request, budget=ledger)
                    self.assertEqual(caught.exception.code, row['expected']['code'])
                else:
                    result = G.ground(owner, request, budget=ledger)
                    self.assertIs(result.owner, owner)
                    self.assertIs(result.stamp, RootContext.prepare_source_data(owner, budget=ledger))
                    self.assertEqual([list(x) for x in result.canonical_bindings],
                                     row['expected']['canonical_bindings'])
                    self.assertEqual([list(x) for x in result.checked_journals],
                                     row['expected']['checked_journals'])
                    self.assertFalse(result.runtime_authority)
                    self.assertFalse(result.source_fact_authority)


if __name__ == '__main__':
    unittest.main(verbosity=2)
