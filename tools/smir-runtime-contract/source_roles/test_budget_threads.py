"""Real host-thread charge witnesses; no production parallel-guest claim.

All successful charges execute the original canonical method. Trace hooks only
pause original execution to exercise the preflight/commit boundary.
"""
import importlib.util
import inspect
from pathlib import Path
import sys
import threading
import time
import unittest

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


def ledger(limits):
    return M.SourceQueryBudget(max_work=limits[0], max_edges=limits[1],
                              max_copied_bytes=limits[2], max_depth=128)


def totals(budget):
    # Call only after every worker joins; this is not a concurrent snapshot API.
    return budget._used_work, budget._used_edges, budget._used_copied_bytes


class BudgetThreadTests(unittest.TestCase):
    observations = []

    def concurrent(self, budget, plans):
        barrier = threading.Barrier(len(plans), timeout=10)
        successes = [[] for _ in plans]
        refusals = [0 for _ in plans]
        identities = [None for _ in plans]
        failures = [[] for _ in plans]

        def worker(index):
            try:
                identities[index] = threading.get_native_id()
                barrier.wait()
                for ordinal, vector in enumerate(plans[index]):
                    try:
                        budget.charge(work=vector[0], edges=vector[1],
                                      copied_bytes=vector[2])
                        successes[index].append(vector)
                    except M.SourceDataError as error:
                        if (error.kind, error.code) != ('resource', 'SOURCE_DATA_RESOURCE'):
                            raise
                        refusals[index] += 1
                    if ordinal % 17 == 0:
                        time.sleep(0)  # Permit a genuine host-thread interleaving.
            except BaseException as error:
                failures[index].append(repr(error))

        threads = [threading.Thread(target=worker, args=(i,), daemon=True)
                   for i in range(len(plans))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertFalse(any(thread.is_alive() for thread in threads), 'thread join timeout')
        self.assertEqual(failures, [[] for _ in plans])
        self.assertEqual(len(set(identities)), len(plans))
        successful = [vector for group in successes for vector in group]
        expected = tuple(sum(v[i] for v in successful) for i in range(3))
        self.assertEqual(totals(budget), expected)
        self.assertLessEqual(expected[0], budget.max_work)
        self.assertLessEqual(expected[1], budget.max_edges)
        self.assertLessEqual(expected[2], budget.max_copied_bytes)
        self.assertEqual(len(successful) + sum(refusals), sum(map(len, plans)))
        self.observations.append({'case': self._testMethodName,
                                  'native_thread_ids': identities,
                                  'successes': len(successful), 'refusals': sum(refusals),
                                  'totals': expected})
        return len(successful), sum(refusals)

    def test_shared_composite_charge_conserves_all_counters(self):
        count, refused = self.concurrent(ledger((4000, 8000, 12000)),
                                        [[(1, 2, 3)] * 1200 for _ in range(4)])
        self.assertEqual((count, refused), (4000, 800))

    def test_each_dimension_exhausts_without_consuming_other_dimensions(self):
        for dimension, limit in enumerate((257, 515, 773)):
            with self.subTest(dimension=dimension):
                limits = [10000, 10000, 10000]
                limits[dimension] = limit
                count, refused = self.concurrent(ledger(limits),
                                                 [[(1, 2, 3)] * 300 for _ in range(4)])
                self.assertEqual((count, refused), (257, 943))

    def test_mixed_vectors_conserve_only_successful_original_calls(self):
        vectors = ((1, 2, 3), (4, 0, 1), (0, 5, 1), (1, 1, 0))
        plans = [[vectors[(i + j) % 4] for j in range(400)] for i in range(4)]
        count, refused = self.concurrent(ledger((777, 901, 809)), plans)
        self.assertGreater(count, 0)
        self.assertGreater(refused, 0)

    def test_second_real_thread_cannot_commit_during_first_preflight_commit(self):
        budget = ledger((1, 2, 3))
        lines, start = inspect.getsourcelines(M.SourceQueryBudget.charge)
        commit_line = next(start + i for i, line in enumerate(lines)
                           if "object.__setattr__(self, '_used_work'" in line)
        paused = threading.Event()
        release = threading.Event()
        entered = threading.Event()
        competing_commit = threading.Event()
        results = [None, None]
        identities = [None, None]
        failures = [[], []]

        def worker(index):
            identities[index] = threading.get_native_id()

            def trace(frame, event, arg):
                if frame.f_code is M.SourceQueryBudget.charge.__code__ and event == 'line':
                    if index == 1:
                        entered.set()
                    if frame.f_lineno == commit_line:
                        if index == 0:
                            paused.set()
                            if not release.wait(10):
                                raise RuntimeError('original charge release timeout')
                        else:
                            competing_commit.set()
                return trace

            sys.settrace(trace)
            try:
                budget.charge(work=1, edges=2, copied_bytes=3)
                results[index] = 'success'
            except M.SourceDataError as error:
                results[index] = (error.kind, error.code)
            except BaseException as error:
                failures[index].append(repr(error))
            finally:
                sys.settrace(None)

        first = threading.Thread(target=worker, args=(0,), daemon=True)
        second = threading.Thread(target=worker, args=(1,), daemon=True)
        first.start()
        second_started = False
        try:
            self.assertTrue(paused.wait(10), 'original first charge did not preflight')
            second.start()
            second_started = True
            self.assertTrue(entered.wait(10), 'second did not enter original method')
            # Timeout is a bounded scheduler probe, not a fairness guarantee.
            reached = competing_commit.wait(0.2)
        finally:
            release.set()
            first.join(10)
            if second_started:
                second.join(10)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(failures, [[], []])
        self.assertEqual(len(set(identities)), 2)
        self.assertFalse(reached)
        self.assertEqual(results, ['success', ('resource', 'SOURCE_DATA_RESOURCE')])
        self.assertEqual(totals(budget), (1, 2, 3))
        self.observations.append({'case': self._testMethodName,
                                  'native_thread_ids': identities, 'successes': 1,
                                  'refusals': 1, 'totals': totals(budget)})


if __name__ == '__main__':
    unittest.main()
