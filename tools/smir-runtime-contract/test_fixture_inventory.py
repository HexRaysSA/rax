"""Closed legacy inventory and explicitly separate compiler corpora."""
from pathlib import Path
import shutil,tempfile,unittest
from unittest.mock import patch
import check
from schema import ContractError

class FixtureInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='runtime-inventory-');self.addCleanup(self.temp.cleanup)
        self.spec=Path(self.temp.name);self.corpus=self.spec/'conformance/runtime';original=check.SPEC/'conformance/runtime'
        for name in list(check.LEGACY_FIXTURES)+list(check.TYPED_VECTORS):
            p=self.corpus/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original/name,p)
    def checked(self):
        with patch.object(check,'SPEC',self.spec):return check.check_fixtures()
    def test_exact_legacy_control_preserves_all_classifications(self):
        expected=check.check_fixtures();self.assertEqual(self.checked(),expected);self.assertEqual(sum(expected.values()),len(check.LEGACY_FIXTURES))
    def test_two_owned_compiler_prefixes_are_separate_from_legacy_schema(self):
        before=self.checked()
        for name in ('source-contracts','source-carrier'):
            p=self.corpus/name/'not-a-legacy-case.json';p.parent.mkdir();p.write_text('{"format":"separately-validated-compiler-input"}')
        self.assertEqual(self.checked(),before)
    def test_unknown_top_level_corpus_cannot_silently_expand_inventory(self):
        p=self.corpus/'unregistered'/'rogue.json';p.parent.mkdir();p.write_text('{}')
        with self.assertRaises(ContractError)as e:self.checked()
        self.assertEqual(e.exception.code,'RUNTIME_CORPUS_INVENTORY')
    def test_compiler_prefix_name_only_counts_at_corpus_root(self):
        p=self.corpus/'unregistered'/'source-carrier'/'rogue.json';p.parent.mkdir(parents=True);p.write_text('{}')
        with self.assertRaises(ContractError)as e:self.checked()
        self.assertEqual(e.exception.code,'RUNTIME_CORPUS_INVENTORY')
    def test_source_observer_root_prefix_is_separately_validated(self):
        before=self.checked();p=self.corpus/'source-observer'/'source-contract.json';p.parent.mkdir();p.write_text('{"format":"source-observer-reference-input"}')
        self.assertEqual(self.checked(),before);self.assertEqual(sum(before.values()),87)
    def test_nested_source_observer_name_does_not_exclude_unknown_corpus(self):
        p=self.corpus/'unregistered'/'source-observer'/'rogue.json';p.parent.mkdir(parents=True);p.write_text('{}')
        with self.assertRaises(ContractError)as e:self.checked()
        self.assertEqual(e.exception.code,'RUNTIME_CORPUS_INVENTORY')
    def test_union_reference_root_prefix_is_separately_validated(self):
        before=self.checked();p=self.corpus/'union-prestore-reference'/'cases.json';p.parent.mkdir();p.write_text('{"format":"union-prestore-reference"}')
        self.assertEqual(self.checked(),before);self.assertEqual(sum(before.values()),87)
    def test_nested_union_reference_name_does_not_exclude_unknown_corpus(self):
        p=self.corpus/'unregistered'/'union-prestore-reference'/'rogue.json';p.parent.mkdir(parents=True);p.write_text('{}')
        with self.assertRaises(ContractError) as e:self.checked()
        self.assertEqual(e.exception.code,'RUNTIME_CORPUS_INVENTORY')
    def test_nested_union_reference_root_prefix_is_separately_validated(self):
        before=self.checked();p=self.corpus/'union-nested-reference'/'cases.json';p.parent.mkdir();p.write_text('{"format":"nested-union-prestore-reference"}')
        self.assertEqual(self.checked(),before);self.assertEqual(sum(before.values()),87)
    def test_nested_union_package_name_does_not_exclude_unknown_corpus(self):
        p=self.corpus/'unregistered'/'union-nested-reference'/'rogue.json';p.parent.mkdir(parents=True);p.write_text('{}')
        with self.assertRaises(ContractError)as e:self.checked()
        self.assertEqual(e.exception.code,'RUNTIME_CORPUS_INVENTORY')
if __name__=='__main__':unittest.main()

