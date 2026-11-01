"""Fail-closed ownership/provenance checks for the focused correction tool."""
import copy
import json
import unittest
import a64_sysreg_expectations as correction

class CorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = correction.qualified_input()
        cls.source = (correction.ROOT / cls.record['output']).read_text()

    def test_exact_correction_is_idempotent(self):
        _, once = correction.corrected_source(self.record, self.source)
        _, twice = correction.corrected_source(self.record, once)
        self.assertEqual(once, twice)
        self.assertEqual(correction.digest(once.encode()), self.record['corrected_sha256'])

    def test_unrelated_source_changes_reject(self):
        with self.assertRaises(ValueError):
            correction.corrected_source(self.record, self.source + '\n// unrelated edit\n')

    def test_changed_scope_or_primary_rejects(self):
        for key, value in [('word', '0xd5380000'), ('expected', 'Pass'), ('primary_sha256', '0' * 64)]:
            record = copy.deepcopy(self.record)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                correction.qualified_input(record)

    def test_missing_or_extra_cases_reject(self):
        for names in [self.record['tests'][:1], self.record['tests'] + ['unrelated']]:
            record = copy.deepcopy(self.record)
            record['tests'] = names
            with self.assertRaises(ValueError):
                correction.qualified_input(record)

    def test_wrong_exception_or_mutated_identity_rejects(self):
        original = json.loads((correction.ROOT / self.record['oracle']).read_text())
        for index in [1, 2, 3, 4, 5]:
            oracle = copy.deepcopy(original)
            oracle['cases'][0]['values'][index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                correction.validate_oracle(oracle)

if __name__ == '__main__':
    unittest.main()
