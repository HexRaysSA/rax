"""Shared reference DTO/budget/read tests; not production or source admission.

The callback below is a test double. SEM's actual RootContext suite supplies
schema/root/namespace/storage and immutable-capture integration evidence.
"""
from dataclasses import FrozenInstanceError
import importlib.util
from pathlib import Path
import sys
import tracemalloc
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
NAME = '_rax_smir_source_data_v1'
PATH = HERE / 'source_data.py'
if NAME in sys.modules:
    if Path(sys.modules[NAME].__file__).resolve() != PATH:
        raise RuntimeError('source-data module identity/path mismatch')
else:
    spec = importlib.util.spec_from_file_location(NAME, PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[NAME] = module
    spec.loader.exec_module(module)
M = sys.modules[NAME]


def budget(**overrides):
    limits = dict(max_work=10000, max_edges=1000, max_copied_bytes=1000,
                  max_depth=32)
    limits.update(overrides)
    return M.SourceQueryBudget(**limits)


def view(*, ledger=None, prefix=b'abc', zero_tail=5, offset=0,
         check_snapshot=None):
    ledger = budget() if ledger is None else ledger
    stamp = M.SourceStamp(object(), bytes(32), ((1, bytes(32)),))
    calls = []

    def check(*, stamp: M.SourceStamp, budget: M.SourceQueryBudget):
        calls.append((stamp, budget))

    length = len(prefix) + zero_tail
    result = M._make_local_source_data(
        stamp=stamp, symbol=('self', 1), symbol_record=M.FrozenRecord(()),
        storage=('self', 2), offset=offset, length=length,
        symbol_extent=offset + length, backing_extent=offset + length,
        symbol_alignment=8, backing_alignment=4, prefix=memoryview(prefix),
        zero_tail_bytes=zero_tail, patches=(), budget=ledger,
        check_snapshot=check_snapshot if check_snapshot is not None else check)
    return result, ledger, calls


class SourceDataTypesTests(unittest.TestCase):
    def reject(self, code, action, kind=None):
        with self.assertRaises(M.SourceDataError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        if kind is not None:
            self.assertEqual(caught.exception.kind, kind)
        return caught.exception

    def test_policy_is_mandatory_strict_and_depth_bounded(self):
        with self.assertRaises(TypeError):
            M.SourceQueryBudget()
        for key in ('max_work', 'max_edges', 'max_copied_bytes', 'max_depth'):
            for bad in (-1, True, False, 1.0, '1', None):
                with self.subTest(key=key, bad=bad):
                    self.reject('SOURCE_DATA_BUDGET', lambda: budget(**{key: bad}),
                                'resource')
        for bad in (0, 129):
            self.reject('SOURCE_DATA_BUDGET', lambda: budget(max_depth=bad))
        self.assertEqual(budget(max_depth=1).max_depth, 1)
        self.assertEqual(budget(max_depth=128).max_depth, 128)

    def test_all_dimensions_preflight_atomically_and_never_reset(self):
        b = budget(max_work=2, max_edges=2, max_copied_bytes=2)
        for kwargs in (dict(work=1, edges=3), dict(work=3, copied_bytes=1),
                       dict(edges=1, copied_bytes=3)):
            self.reject('SOURCE_DATA_RESOURCE', lambda: b.charge(**kwargs))
        # A failed dimension must not have consumed any other dimension.
        b.charge(work=2, edges=2, copied_bytes=2)
        self.reject('SOURCE_DATA_BUDGET', lambda: b.__init__(
            max_work=99, max_edges=99, max_copied_bytes=99, max_depth=1))
        for f in (b.work, b.edges, b.reserve_bytes):
            self.reject('SOURCE_DATA_RESOURCE', lambda: f(1), 'resource')
        for key in ('max_work', '_used_work', '_max_work'):
            with self.assertRaises(AttributeError):
                setattr(b, key, 0)
        for key in b.__slots__:
            with self.assertRaisesRegex(AttributeError, 'no reset or policy mutation'):
                delattr(b, key)
        self.assertEqual((b._used_work, b._used_edges, b._used_copied_bytes),
                         (2, 2, 2))
        self.reject('SOURCE_DATA_BUDGET', lambda: b.__init__(
            max_work=99, max_edges=99, max_copied_bytes=99, max_depth=1))

    def test_invalid_charges_do_not_change_ledger(self):
        b = budget(max_work=1, max_edges=1, max_copied_bytes=1)
        for name in ('work', 'edges', 'copied_bytes'):
            for value in (-1, True, 0.5):
                self.reject('SOURCE_DATA_BUDGET',
                            lambda: b.charge(**{name: value}), 'resource')
        b.charge(work=1, edges=1, copied_bytes=1)
        # Mathematical counters do not wrap at machine integer boundaries.
        huge = 1 << 130
        b = budget(max_work=huge, max_edges=0, max_copied_bytes=0)
        b.work(huge)
        self.reject('SOURCE_DATA_RESOURCE', lambda: b.work(1))

    def test_error_preserves_kind_code_detail_and_exact_string(self):
        error = M.SourceDataError('unavailable', 'SOURCE_DATA_CONSTANT_PENDING', 'p')
        self.assertEqual(str(error), 'SOURCE_DATA_CONSTANT_PENDING: p')
        self.assertIsInstance(error, ValueError)
        self.assertEqual((error.kind, error.code, error.detail),
                         ('unavailable', 'SOURCE_DATA_CONSTANT_PENDING', 'p'))
        for key in ('kind', 'code', 'detail', '_kind', '_code', '_detail'):
            with self.assertRaises(AttributeError):
                setattr(error, key, 'changed')
        with self.assertRaises(AttributeError):
            error.__init__('semantic', 'changed')
        self.assertEqual(error.code, 'SOURCE_DATA_CONSTANT_PENDING')
        error.args = ('unrelated generic exception args',)
        self.assertEqual(str(error), 'SOURCE_DATA_CONSTANT_PENDING: p')
        self.assertEqual(str(M.SourceDataError('semantic', 'SOURCE_DATA_RECORD')),
                         'SOURCE_DATA_RECORD')

    def test_records_preserve_order_options_and_vector_distinction(self):
        some = M.FrozenRecord((('some', ('self', 7)),))
        record = M.FrozenRecord((('kind', 'data'), ('none', None),
                                 ('option', some), ('vector', (1, 2))))
        self.assertEqual(record.fields[0], ('kind', 'data'))
        self.assertIsNone(record.field('none'))
        self.assertIs(record.field('option'), some)
        self.assertEqual(some.field('some'), ('self', 7))
        self.assertIs(type(record.field('vector')), tuple)
        for key in (1, None, 'absent'):
            self.reject('SOURCE_DATA_RECORD', lambda: record.field(key))
        for malformed in ((('x', 1), ('x', 2)), (('x', object()),), (('x',),)):
            self.reject('SOURCE_DATA_RECORD',
                        lambda: M.FrozenRecord(malformed).field('x'))
        with self.assertRaises(FrozenInstanceError):
            record.fields = ()

    def test_dependency_view_has_no_provider_bytes_or_extents(self):
        stamp = M.SourceStamp(object(), bytes(32), ())
        owner = M.DependencyOwner(2, M.FrozenRecord(()), 0, None, bytes(32))
        expected = M.FrozenRecord((('symbol_kind', 'data'),))
        dep = M.DependencySourceData('dependency', stamp, ('dependency', 2, 1),
                                     owner, 2, 1, 7, 8, expected)
        self.assertIs(dep.expected, expected)
        for key in ('bytes', 'read', 'prefix', 'zero_tail_bytes', 'storage',
                    'symbol_extent', 'backing_extent', 'patches', 'provider_id'):
            with self.assertRaises(AttributeError):
                getattr(dep, key)

    def test_checked_read_crosses_prefix_and_symbolic_tail(self):
        v, b, calls = view(offset=9)
        self.assertEqual(v.read(0, 3, budget=b), b'abc')
        self.assertEqual(v.read(1, 4, budget=b), b'bc\0\0')
        self.assertEqual(v.read(3, 5, budget=b), bytes(5))
        self.assertEqual(v.read(8, 0, budget=b), b'')
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(s is v.stamp and q is b for s, q in calls))
        self.assertEqual((v.offset, v.symbol_alignment, v.backing_alignment),
                         (9, 8, 4))
        self.assertTrue(v.prefix.readonly)
        self.assertIs(type(v.prefix.obj), bytes)

    def test_huge_symbolic_tail_read_is_bounded(self):
        extent = (1 << 64) - 1
        v, b, _ = view(prefix=b'x', zero_tail=extent - 1,
                       ledger=budget(max_copied_bytes=8))
        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            before, _ = tracemalloc.get_traced_memory()
            actual = v.read(extent - 8, 8, budget=b)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(actual, bytes(8))
        self.assertLess(peak - before, 65536)
        self.reject('SOURCE_DATA_RESOURCE', lambda: v.read(0, 1, budget=b))

    def test_wrong_budget_rejects_before_callback(self):
        v, _, calls = view()
        self.reject('SOURCE_DATA_CONTEXT', lambda: v.read(0, 1, budget=budget()),
                    'semantic')
        self.assertEqual(calls, [])

    def test_zero_length_still_checks_snapshot_and_budget(self):
        changed = False
        calls = []
        def check(*, stamp, budget):
            calls.append(stamp)
            budget.work(1)
            if changed:
                raise M.SourceDataError('semantic', 'context_snapshot_changed')
        v, b, _ = view(check_snapshot=check)
        self.assertEqual(v.read(8, 0, budget=b), b'')
        changed = True
        self.reject('context_snapshot_changed', lambda: v.read(8, 0, budget=b))
        self.assertEqual(calls, [v.stamp, v.stamp])

    def test_snapshot_errors_propagate_without_unknown_conversion(self):
        for code in ('SOURCE_DATA_SCHEMA', 'context_snapshot_changed'):
            error = M.SourceDataError('semantic', code)
            def check(*, stamp, budget):
                raise error
            v, b, _ = view(check_snapshot=check)
            self.assertIs(self.reject(code, lambda: v.read(0, 1, budget=b)), error)
        def host_bug(*, stamp, budget):
            raise RuntimeError('programming error')
        v, b, _ = view(check_snapshot=host_bug)
        with self.assertRaisesRegex(RuntimeError, 'programming error'):
            v.read(0, 1, budget=b)

    def test_ranges_are_strict_u64_and_not_coerced(self):
        v, b, calls = view()
        for offset, length in ((-1, 1), (True, 1), (0, False), (0, 1.0),
                               (9, 0), (7, 2), (1 << 64, 0),
                               ((1 << 64) - 1, 2)):
            self.reject('RT_METADATA_EXTENT',
                        lambda: v.read(offset, length, budget=b), 'semantic')
        self.assertEqual(len(calls), 8)  # Bounds cannot bypass snapshot checking.

    def test_quota_exhaustion_precedes_output_and_preserves_atomic_charge(self):
        b = budget(max_copied_bytes=2)
        v, _, _ = view(ledger=b)
        self.reject('SOURCE_DATA_RESOURCE', lambda: v.read(0, 3, budget=b))
        self.assertEqual(v.read(0, 2, budget=b), b'ab')
        self.reject('SOURCE_DATA_RESOURCE', lambda: v.read(0, 1, budget=b))
        b = budget(max_work=32)
        v, _, calls = view(ledger=b)
        self.reject('SOURCE_DATA_RESOURCE', lambda: v.read(0, 0, budget=b))
        self.assertEqual(calls, [])

    def test_host_size_limit_is_resource_after_source_bounds(self):
        extent = (1 << 64) - 1
        b = budget(max_work=1 << 65, max_copied_bytes=1 << 65)
        v, _, calls = view(prefix=b'x', zero_tail=extent - 1, ledger=b)
        self.reject('SOURCE_DATA_RESOURCE',
                    lambda: v.read(0, sys.maxsize + 1, budget=b), 'resource')
        self.assertEqual(len(calls), 1)
        self.reject('RT_METADATA_EXTENT',
                    lambda: v.read(1, extent, budget=b), 'semantic')
        self.assertEqual(v.read(extent - 8, 8, budget=b), bytes(8))

    def test_injected_output_allocation_errors_map_to_resource_only_at_copy(self):
        v, b, _ = view()
        for error in (MemoryError('allocation'), OverflowError('host size')):
            def refuse(n):
                raise error
            with patch.object(M, 'bytes', refuse, create=True):
                actual = self.reject('SOURCE_DATA_RESOURCE',
                                     lambda: v.read(3, 1, budget=b), 'resource')
            self.assertIs(actual.__cause__, error)
        # A producer callback error is outside the narrow allocation handler.
        def host_bug(*, stamp, budget):
            raise OverflowError('snapshot programming error')
        v, b, _ = view(check_snapshot=host_bug)
        with self.assertRaisesRegex(OverflowError, 'snapshot programming error'):
            v.read(0, 1, budget=b)

    def test_factory_rejects_mutable_typed_strided_or_inconsistent_prefix(self):
        v, _, _ = view()
        args = {name: getattr(v, name) for name in
                ('stamp', 'symbol', 'symbol_record', 'storage', 'offset',
                 'length', 'symbol_extent', 'backing_extent', 'symbol_alignment',
                 'backing_alignment', 'prefix', 'zero_tail_bytes', 'patches')}
        args['check_snapshot'] = lambda **kw: None
        for prefix in (memoryview(bytearray(b'abc')).toreadonly(),
                       memoryview(b'a0b0c')[::2], memoryview(b'abc').cast('b'),
                       memoryview(b'ab'), b'abc'):
            args['prefix'] = prefix
            self.reject('SOURCE_DATA_RECORD', lambda: M._make_local_source_data(
                **args, budget=budget()), 'semantic')
        args['prefix'] = v.prefix
        for key, value in (('length', 0), ('offset', True),
                           ('symbol_extent', v.symbol_extent + 1),
                           ('storage', ('dependency', 0, 2))):
            bad = dict(args, **{key: value})
            self.reject('SOURCE_DATA_RECORD', lambda: M._make_local_source_data(
                **bad, budget=budget()))
        with self.assertRaises(TypeError):
            M.LocalSourceData()
        with self.assertRaises(FrozenInstanceError):
            v.prefix = memoryview(b'changed')

    def test_factory_precharges_before_publication(self):
        for limits in (dict(max_work=31), dict(max_edges=0)):
            self.reject('SOURCE_DATA_RESOURCE', lambda: view(ledger=budget(**limits)),
                        'resource')
        v, b, _ = view(ledger=budget(max_work=32, max_edges=1))
        self.assertIs(v._budget, b)
        self.assertEqual(v.tag, 'local')
        self.reject('SOURCE_DATA_RESOURCE', lambda: v.read(0, 0, budget=b))


if __name__ == '__main__':
    unittest.main()
