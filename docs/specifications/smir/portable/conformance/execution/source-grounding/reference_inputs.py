"""Closed input and original-source guards through the actual published module."""
from copy import deepcopy
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
from candidate import source_grounding as G
from candidate.context import RootContext
from reference_grounding import fixture


class ClosedInputTests(unittest.TestCase):
    def rejected(self, edit, code):
        owner, request, budget = fixture()
        edit(request)
        with self.assertRaises(G.GroundingError) as caught:
            G.ground(owner, request, budget=budget)
        self.assertEqual(caught.exception.code, code)

    def test_unknown_top_field(self):
        self.rejected(lambda d: d.update(extra=True), 'CG_SHAPE')

    def test_missing_top_field(self):
        self.rejected(lambda d: d.pop('lifecycles'), 'CG_SHAPE')

    def test_boolean_revision_is_not_one(self):
        self.rejected(lambda d: d.update(revision=True), 'CG_SHAPE')

    def test_unhashable_label_is_input_error(self):
        self.rejected(lambda d: d['bindings'][0].update(program=[]), 'CG_LINK_LABEL')

    def test_extra_local_binding_field(self):
        self.rejected(lambda d: d['bindings'][0].update(extra=1), 'CG_SHAPE')

    def test_boolean_journal_slot_is_not_zero(self):
        self.rejected(lambda d: d['scopes'][0]['journal_cells'][0].update(slot=False),
                      'CG_JOURNAL_MAPPING_SHAPE')

    def test_negative_local_id(self):
        self.rejected(lambda d: d['bindings'][0].update(root_binding=-1), 'CG_LINK_ID')

    def test_reserved_local_id(self):
        self.rejected(lambda d: d['bindings'][0].update(root_binding=2**32-1), 'CG_LINK_ID')

    def test_unknown_binding_program(self):
        self.rejected(lambda d: d['bindings'][0].update(program='absent'), 'CG_REFERENCE')

    def test_unknown_binding_cell(self):
        self.rejected(lambda d: d['bindings'][0].update(cell='absent'), 'CG_REFERENCE')

    def test_unknown_scope_program(self):
        self.rejected(lambda d: d['scopes'][0].update(program='absent'), 'CG_REFERENCE')

    def test_unknown_journal_cell(self):
        self.rejected(lambda d: d['scopes'][0]['journal_cells'][0].update(cell='absent'),
                      'CG_REFERENCE')

    def test_duplicate_binding_link(self):
        self.rejected(lambda d: d['bindings'].append(deepcopy(d['bindings'][0])), 'CG_DUPLICATE')

    def test_duplicate_journal_mapping(self):
        self.rejected(lambda d: d['scopes'][0]['journal_cells'].append(
            deepcopy(d['scopes'][0]['journal_cells'][0])), 'CG_DUPLICATE')

    def test_boolean_nested_nominal_reference(self):
        self.rejected(lambda d: d['carrier']['contract']['bindings'][0]['source_class'].update(id=True),
                      'CG_SHAPE')

    def test_extra_nested_abi_program_field(self):
        self.rejected(lambda d: d['abi_programs'].update(extra=1), 'CG_SHAPE')

    def test_cyclic_json_container(self):
        self.rejected(lambda d: d['bindings'].append(d), 'CG_SHAPE')

    def test_local_table_cap(self):
        self.rejected(lambda d: d.update(bindings=[deepcopy(d['bindings'][0]) for _ in range(4097)]),
                      'CG_TABLE')

    def test_lifecycle_reference_not_guessed(self):
        self.rejected(lambda d: d['lifecycles'].append(dict(function=0, scope=999, method=0, program=0)),
                      'CG_REFERENCE')


class GuardTests(unittest.TestCase):
    def temporary(self):
        parent = os.environ.get('SMIR_GROUNDING_TEST_DIR', os.environ.get('TMPDIR'))
        return tempfile.TemporaryDirectory(prefix='source-grounding-', dir=parent)

    def test_wrong_owner_class(self):
        _, request, budget = fixture()
        with self.assertRaisesRegex(G.GroundingError, 'CG_OWNER'):
            G.ground(object(), request, budget=budget)

    def test_noncanonical_ledger(self):
        owner, request, _ = fixture()
        with self.assertRaisesRegex(G.GroundingError, 'CG_BUDGET'):
            G.ground(owner, request, budget=object())

    def test_schema_identity_rejects_copy_mutation(self):
        owner, request, budget = fixture()
        with self.temporary() as directory:
            path = Path(directory) / 'schema.json'
            path.write_bytes(G.SCHEMA.read_bytes() + b' ')
            with patch.object(G, 'SCHEMA', path):
                with self.assertRaisesRegex(G.GroundingError, 'CG_SCHEMA_IDENTITY'):
                    G.ground(owner, request, budget=budget)

    def test_schema_afterguard_uses_real_path_proof(self):
        owner, request, budget = fixture()
        original = G.prove_paths
        with self.temporary() as directory:
            path = Path(directory) / 'schema.json'
            path.write_bytes(G.SCHEMA.read_bytes())
            def actual_then_mutate(*args, **kwargs):
                result = original(*args, **kwargs)
                path.write_bytes(path.read_bytes() + b' ')
                return result
            with patch.object(G, 'SCHEMA', path), patch.object(G, 'prove_paths', actual_then_mutate):
                with self.assertRaisesRegex(G.GroundingError, 'CG_SCHEMA_IDENTITY'):
                    G.ground(owner, request, budget=budget)

    def test_original_afterguard_uses_canonical_owner_method(self):
        owner, request, budget = fixture()
        original = G.prove_paths
        def actual_then_mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            owner.sections[2]['manifest']['key']['name'] += '_changed'
            return result
        with patch.object(G, 'prove_paths', actual_then_mutate):
            with self.assertRaises(Exception) as caught:
                G.ground(owner, request, budget=budget)
        self.assertEqual(caught.exception.code, 'context_snapshot_changed')

    def test_editable_owner_prepare_callback_is_not_oracle(self):
        owner, request, budget = fixture()
        def forbidden(**kwargs):
            raise AssertionError('editable owner callback used as source oracle')
        owner.prepare_source_data = forbidden
        result = G.ground(owner, request, budget=budget)
        self.assertIs(result.owner, owner)
        self.assertFalse(result.runtime_authority)


if __name__ == '__main__':
    unittest.main(verbosity=2)
