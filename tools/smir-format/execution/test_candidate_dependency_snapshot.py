"""Original source callback custody and independent mutable certificate snapshots."""
from copy import deepcopy
import unittest

from candidate.context import RootContext
from candidate.operations import Dependencies
from test_candidate_source_join import fixture, ledger, q


class DependencySnapshotTests(unittest.TestCase):
    def original(self, prepared=True):
        unused, unused_abi, owner, budget = fixture()
        if not prepared:
            owner = RootContext(deepcopy(owner.sections))
        stamp = owner.prepare_source_data(budget=budget) if prepared else None
        owner.verify_abi()
        verified = owner.verify_execution()
        if prepared:
            self.assertIs(owner.prepare_source_data(budget=budget), stamp)
        return owner, budget, stamp, verified.dependencies

    def test_actual_prepared_owner_survives_execution_verification(self):
        owner, budget, stamp, dependencies = self.original()
        self.assertIs(dependencies.source_layout.__self__, owner)
        self.assertIs(dependencies.source_compatible.__self__, owner)
        self.assertTrue(dependencies.source_compatible(q(1), q(1)))
        self.assertEqual(dependencies.source_layout(q(1))['size'], 4)
        self.assertIs(owner.prepare_source_data(budget=budget), stamp)

    def test_exact_callback_objects_and_both_directions_nested_isolation(self):
        owner, budget, stamp, original = self.original()
        copied = deepcopy(original)
        self.assertIsNot(copied, original)
        for name in ('nominal_equal', 'source_layout', 'source_compatible'):
            self.assertIs(getattr(copied, name), getattr(original, name))
        callbacks = {'nominal_equal', 'source_layout', 'source_compatible'}
        self.assertEqual(len(vars(original)), 16)
        for name in set(vars(original))-callbacks:
            self.assertIsNot(getattr(copied, name), getattr(original, name))
        identity = next(iter(original.nominals))
        before = copied.nominals[identity]['identity']['entity']
        original.nominals[identity]['identity']['entity'] = 'original-only'
        self.assertEqual(copied.nominals[identity]['identity']['entity'], before)
        copied.nominals[identity]['identity']['entity'] = 'copy-only'
        self.assertEqual(original.nominals[identity]['identity']['entity'], 'original-only')
        self.assertIs(copied.source_layout.__self__, owner)
        self.assertIs(owner.prepare_source_data(budget=budget), stamp)

    def test_shared_maps_dynamic_cycles_and_adapter_backreferences(self):
        owner, budget, stamp, original = self.original()
        shared = {'nested': [1, 2], 'adapter': original}
        original.functions = shared
        original.imports = shared
        original.extra = []
        original.extra.append(original.extra)
        original.extra.append(original)
        original.extra.append(original.source_layout)
        original.data_dictionary = vars(original)
        copied = deepcopy(original)
        self.assertIs(copied.functions, copied.imports)
        self.assertIsNot(copied.functions, shared)
        self.assertIs(copied.functions['adapter'], copied)
        self.assertIs(copied.extra[0], copied.extra)
        self.assertIs(copied.extra[1], copied)
        self.assertIs(copied.extra[2], original.source_layout)
        self.assertIs(copied.data_dictionary, vars(copied))
        copied.functions['nested'].append(3)
        self.assertEqual(shared['nested'], [1, 2])
        shared['nested'].append(4)
        self.assertEqual(copied.functions['nested'], [1, 2, 3])

    def test_original_root_mutation_still_rejected_by_preserved_callbacks(self):
        owner, budget, stamp, original = self.original()
        copied = deepcopy(original)
        owner.sections[10]['identity'] = '00'*32
        for callback, arguments in ((copied.source_layout, (q(1),)),
                                    (copied.source_compatible, (q(1), q(1)))):
            with self.assertRaisesRegex(Exception, 'context_snapshot_changed'):
                callback(*arguments)
        with self.assertRaises(Exception):
            owner.prepare_source_data(budget=budget)

    def test_default_none_and_unprepared_original(self):
        original = Dependencies()
        copied = deepcopy(original)
        self.assertIsNot(original, copied)
        for name in ('nominal_equal', 'source_layout', 'source_compatible'):
            self.assertIsNone(getattr(copied, name))
        owner, budget, unused_stamp, dependencies = self.original(prepared=False)
        self.assertIs(dependencies.source_layout.__self__, owner)
        self.assertTrue(dependencies.source_compatible(q(1), q(1)))


if __name__ == '__main__':
    unittest.main()
