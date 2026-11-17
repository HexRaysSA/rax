"""Real-thread canonical source issuance; no supplied facts or result factories."""
import gc
import inspect
import sys
import threading
import unittest
import weakref

from candidate.context import source_registry_api
from candidate.source_data_projection import source_api
from candidate.type_system import ref
from test_candidate_source_registry import actual, ledger
from test_candidate_source_execution import registry_api


def race(context, budget):
    api = source_registry_api()
    code = api._issue.__code__
    lines, start = inspect.getsourcelines(api._issue)
    point = next(start + index for index, line in enumerate(lines)
                 if line.strip() == 'schema, digest = projection._schema(budget)')
    barrier, guard = threading.Barrier(2), threading.Lock()
    results, errors, native_ids = [], [], []
    def worker():
        paused = False
        def local(frame, event, argument):
            nonlocal paused
            if not paused and event == 'line' and frame.f_lineno == point:
                paused = True
                barrier.wait(timeout=10)
            return local
        def trace(frame, event, argument):
            return local if frame.f_code is code else None
        try:
            with guard:
                native_ids.append(threading.get_native_id())
            sys.settrace(trace)
            result = context.source_registry_context(budget=budget)
            with guard:
                results.append(result)
        except BaseException as error:
            with guard:
                errors.append(error)
        finally:
            sys.settrace(None)
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError('source issuance threads did not finish')
    if errors:
        raise errors[0]
    if len(results) != 2 or len(set(native_ids)) != 2:
        raise RuntimeError('two actual successful native threads required')
    return results, native_ids


class SourceRegistryThreadTests(unittest.TestCase):
    def test_losing_revalidation_resource_preserves_the_published_winner(self):
        api, context = source_registry_api(), actual()
        budget = ledger(max_work=10**12, max_edges=10**12, max_copied_bytes=10**12)
        code = api._issue.__code__
        lines, start = inspect.getsourcelines(api._issue)
        miss = next(start + index for index, line in enumerate(lines)
                    if line.strip() == 'schema, digest = projection._schema(budget)')
        losing = next(start + index for index, line in enumerate(lines)
                      if line.strip() == 'return validate_source_registry_context(winner, budget=budget)')
        barrier, guard = threading.Barrier(2), threading.Lock()
        loser_ready, winner_ready, proceed = threading.Event(), threading.Event(), threading.Event()
        results, errors, native_ids = [], [], []
        def worker():
            def local(frame, event, argument):
                if event == 'line' and frame.f_lineno == miss:
                    barrier.wait(timeout=10)
                elif event == 'line' and frame.f_lineno == losing:
                    loser_ready.set()
                    if not proceed.wait(timeout=30):
                        raise RuntimeError('loser resume deadline')
                return local
            def trace(frame, event, argument):
                return local if frame.f_code is code else None
            try:
                with guard:
                    native_ids.append(threading.get_native_id())
                sys.settrace(trace)
                value = context.source_registry_context(budget=budget)
                with guard:
                    results.append(value)
                winner_ready.set()
            except BaseException as error:
                with guard:
                    errors.append(error)
            finally:
                sys.settrace(None)
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        try:
            self.assertTrue(loser_ready.wait(timeout=30))
            self.assertTrue(winner_ready.wait(timeout=30))
            # Actual successful charge consumes the remaining original policy.
            # No counter mutation, reset, fake error or replacement factory.
            budget.charge(work=budget.max_work - budget._used_work)
        finally:
            proceed.set()
            for thread in threads:
                thread.join(timeout=60)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(set(native_ids)), 2)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIs(type(errors[0]), source_api().SourceDataError)
        self.assertEqual(errors[0].code, 'SOURCE_DATA_RESOURCE')
        winner = results[0]
        self.assertIs(api._CACHE[id(context), id(budget)](), winner)
        self.assertIs(api._ISSUED[id(winner)][0](), winner)
        self.assertIs(winner._context, context)
        self.assertIs(winner._budget, budget)

    def test_actual_two_misses_publish_one_view_and_one_registry_owner(self):
        context = actual()
        budget = ledger(max_work=10**12, max_edges=10**12, max_copied_bytes=10**12)
        # Initialize canonical modules on this thread, not inside import races.
        api, runtime = source_registry_api(), registry_api()
        results, native_ids = race(context, budget)
        self.assertEqual(len(set(native_ids)), 2)
        self.assertIs(results[0], results[1])
        for view in results:
            self.assertIs(api.validate_source_registry_context(view, budget=budget), view)
            self.assertIs(view._context, context)
            self.assertIs(view._budget, budget)
        registry = runtime.CodeRegistry(budget=budget, policy=runtime.RegistryPolicy(
            max_targets=32, max_permits=32, max_roots=32, max_activations=32, max_snapshots=32))
        owners = [registry.register_source(view, budget=budget) for view in results]
        self.assertIs(owners[0], owners[1])
        self.assertEqual(len(registry._owners), 1)
        deployment = registry.prepare_deployment((owners[0],), budget=budget)
        addresses = [registry.address(registry.resolve(deployment, owner, 'function', ref(0),
                     budget=budget), budget=budget) for owner in owners]
        self.assertEqual(addresses[0].bits, addresses[1].bits)
        self.assertGreater(addresses[0].bits, 0)
        self.assertEqual(addresses[0].bits % 2, 0)
        for address in addresses:
            registry.drop_lane(address, budget=budget)

    def test_actual_arbitration_resource_does_not_publish_partial_candidate(self):
        api, context = source_registry_api(), actual()
        budget = ledger(max_work=10**12, max_edges=10**12, max_copied_bytes=10**12)
        code = api._issue.__code__
        lines, start = inspect.getsourcelines(api._issue)
        point = next(start + index for index, line in enumerate(lines) if line.strip() == 'budget.work(4)')
        observed = []
        def local(frame, event, argument):
            if event == 'line' and frame.f_lineno == point:
                observed.append(budget._used_work)
            return local
        def trace(frame, event, argument):
            return local if frame.f_code is code else None
        sys.settrace(trace)
        try:
            original = context.source_registry_context(budget=budget)
        finally:
            sys.settrace(None)
        self.assertEqual(len(observed), 1)
        self.assertIs(original._context, context)
        other = actual()
        limited = ledger(max_work=observed[0], max_edges=10**12, max_copied_bytes=10**12)
        key = id(other), id(limited)
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_RESOURCE'):
            other.source_registry_context(budget=limited)
        self.assertEqual(limited._used_work, observed[0])
        self.assertNotIn(key, api._CACHE)
        self.assertFalse(any(entry[1]() is other for entry in api._ISSUED.values()))
        used = limited._used_work, limited._used_edges, limited._used_copied_bytes
        with self.assertRaisesRegex(source_api().SourceDataError, 'SOURCE_DATA_RESOURCE'):
            other.source_registry_context(budget=limited)
        self.assertEqual(used, (limited._used_work, limited._used_edges, limited._used_copied_bytes))
        self.assertNotIn(key, api._CACHE)
        adequate = ledger(max_work=10**12, max_edges=10**12, max_copied_bytes=10**12)
        fresh = other.source_registry_context(budget=adequate)
        self.assertIs(api.validate_source_registry_context(fresh, budget=adequate), fresh)

    def test_racing_loser_cleanup_does_not_pin_or_remove_live_winner(self):
        api, context = source_registry_api(), actual()
        budget = ledger(max_work=10**12, max_edges=10**12, max_copied_bytes=10**12)
        results, native_ids = race(context, budget)
        winner = results[0]
        self.assertIs(winner, results[1])
        gc.collect()
        self.assertIs(context.source_registry_context(budget=budget), winner)
        reference = weakref.ref(winner)
        call_reference = weakref.ref(winner._call_view)
        key = id(context), id(budget)
        del results, winner
        gc.collect()
        self.assertIsNone(reference())
        self.assertIsNone(call_reference())
        self.assertNotIn(key, api._CACHE)
        fresh = context.source_registry_context(budget=budget)
        self.assertIs(api.validate_source_registry_context(fresh, budget=budget), fresh)
        self.assertIsNot(context.source_registry_context(budget=ledger()), fresh)
        another = actual()
        self.assertIsNot(another.source_registry_context(budget=budget), fresh)


if __name__ == '__main__':
    unittest.main()
