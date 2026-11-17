"""Actual R-origin cycle counter and independent finite forest boundary tests."""
from copy import deepcopy
import unittest
from reference_grounding import fixture, budget
from reference_cfg import refreshed
from candidate.source_grounding import ground, verify_root_chains, GroundingError
import source_contracts


def original_cycle(cyclic):
    owner, request, ledger = fixture()
    roots = deepcopy(owner.sections)
    function = roots[3]['functions'][0]
    function['blocks'][0]['ops'].append(dict(
        op='constant', results=[dict(id=31, type=deepcopy(function['params'][0]['type']))],
        operands=[], literal=dict(kind='zero')))
    binding = request['carrier']['contract']['bindings'][0]
    other = deepcopy(binding)
    other.update(id=1, value=31, origin=dict(kind='retained_alias', binding=0, value=0))
    request['carrier']['contract']['bindings'].append(other)
    request['bindings'].append(dict(function=0, binding=1, root_binding=0,
                                    program='cleanup', cell='root'))
    if cyclic:
        binding['origin'] = dict(kind='retained_alias', binding=1, value=31)
    owner, request, ledger = refreshed(roots, request, ledger)
    owner.verify_abi()
    owner.verify_execution()
    return owner, request, ledger


def forest(parents, roots=None, functions=None):
    """Helper-only graph data; never claimed as an admitted source module."""
    functions = functions or [0] * len(parents)
    roots = roots or [0] * len(parents)
    bindings, links = {}, {}
    for identifier, parent in enumerate(parents):
        key = functions[identifier], identifier
        origin = dict(kind='incoming_alias') if parent is None else dict(kind='retained_alias', binding=parent)
        bindings[key] = dict(origin=origin)
        links[key] = dict(function=key[0], binding=key[1], root_binding=roots[identifier],
                          program=None, cell=None)
    return bindings, links


class ActualOriginTests(unittest.TestCase):
    def test_genuine_two_cycle_refuses_after_original_R(self):
        owner, request, ledger = original_cycle(True)
        source_contracts.verify(owner, request['carrier'], budget=ledger)
        with self.assertRaisesRegex(GroundingError, 'CG_ROOT_CUSTODY'):
            ground(owner, request, budget=ledger)

    def test_same_bytes_rooted_control_keeps_operation_truth_deferred(self):
        owner, request, ledger = original_cycle(False)
        result = ground(owner, request, budget=ledger)
        self.assertEqual(result.canonical_bindings, ((0, 0), (0, 1)))
        self.assertIn('ASC_RETAINED_ALIAS_OPERATION_SUBSET', result.deferred)
        self.assertFalse(result.source_fact_authority)


class ForestBoundaryTests(unittest.TestCase):
    def reject(self, parents, roots=None, functions=None):
        bindings, links = forest(parents, roots, functions)
        with self.assertRaisesRegex(GroundingError, 'CG_ROOT_CUSTODY'):
            verify_root_chains(bindings, links, budget())

    def test_shared_tail_resolves_same_true_terminal(self):
        bindings, links = forest([None, 0, 1, 1])
        terminals = verify_root_chains(bindings, links, budget())
        self.assertEqual(terminals, {key: (0, 0) for key in bindings})

    def test_self_cycle_refuses(self):
        self.reject([0])

    def test_two_cycle_refuses(self):
        self.reject([1, 0])

    def test_wrong_declared_terminal_refuses(self):
        self.reject([None, None, 1], [0, 1, 0])

    def test_alias_label_is_not_terminal(self):
        self.reject([None, 0], [0, 1])

    def test_missing_parent_refuses(self):
        self.reject([None, 99])

    def test_same_numeric_root_in_different_function_not_custody(self):
        self.reject([None, 0], [0, 0], [0, 1])

    def test_long_chain_iterative_and_linear_charged_work(self):
        work = []
        for count in (600, 1200):
            bindings, links = forest([None] + list(range(count - 1)))
            ledger = budget()
            terminals = verify_root_chains(bindings, links, ledger)
            self.assertEqual(terminals[0, count - 1], (0, 0))
            work.append(ledger._used_work)
        self.assertLessEqual(work[1], 2 * work[0] + 32)

    def test_zero_quota_refuses_before_walk(self):
        bindings, links = forest([None, 0])
        with self.assertRaises(Exception) as caught:
            verify_root_chains(bindings, links, budget(max_work=0))
        self.assertEqual(caught.exception.code, 'SOURCE_DATA_RESOURCE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
