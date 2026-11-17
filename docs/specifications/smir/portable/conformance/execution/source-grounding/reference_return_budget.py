"""Abstract CFG work-meter stress; no original module or authority is inferred."""
import unittest
from reference_grounding import budget
from candidate.source_grounding import prove_paths


def branch_return_probe(count):
    visits = [0]

    class ObservedReturn(dict):
        def __getitem__(self, key):
            if key == 'exit':
                visits[0] += 1
            return super().__getitem__(key)

    blocks, exits, returns = [], [], []
    phases = [dict(function=0, selector=dict(kind='always'),
                   site=dict(kind='entry', block=0), within=dict(kind='outside'),
                   event=dict(kind='enter_root', scope=0))]
    for block in range(2 * count - 1):
        if block < count - 1:
            term = dict(op='cbranch', condition=block,
                        true=2 * block + 1, false=2 * block + 2)
        else:
            exit_id = block - (count - 1)
            term = dict(op='return')
            exits.append(dict(function=0, id=exit_id, scope_value=0,
                              outcome=dict(kind='normal_no_journal')))
            returns.append(ObservedReturn(function=0, id=exit_id,
                                          exit=exit_id, scope=0))
            phases.append(dict(function=0, selector=dict(kind='always'),
                               site=dict(kind='pre_terminator', block=block),
                               within=dict(kind='outside'),
                               event=dict(kind='scope_exit', exit=exit_id)))
        blocks.append(dict(id=block, ops=[], phis=[], term=term))
    contract = dict(
        scopes=[dict(function=0, id=0, within=dict(kind='outside'), enter_value=0)],
        scope_values=[dict(function=0, id=0, origin=dict(kind='enter'))],
        exits=exits, returns=returns, adoptions=[], phase_sites=phases)
    ledger = budget()
    states = prove_paths(dict(id=0, entry=0, blocks=blocks), contract, ledger)
    return states, visits[0], ledger._used_work


class ReturnBudgetBoundary(unittest.TestCase):
    def test_branch_return_row_visits_fit_charged_work(self):
        # Mutually exclusive returns cannot be rescanned quadratically per path.
        # This is a helper-only stress graph, not an admitted R/ABI large profile.
        states, row_visits, charged = branch_return_probe(1024)
        self.assertEqual(states, 2047)
        self.assertLessEqual(row_visits, charged)


def joined_vector_probe(count, kind, engine=prove_paths):
    """Abstract many-predecessor join: count actual variable-vector row visits."""
    visits = [0]

    class ObservedRow(dict):
        def __getitem__(self, key):
            if key == ('predecessor' if kind == 'phi' else 'id'):
                visits[0] += 1
            return super().__getitem__(key)

    join = 2 * count - 1
    blocks = []
    for block in range(join):
        term = (dict(op='cbranch', condition=block, true=2 * block + 1,
                     false=2 * block + 2) if block < count - 1 else
                dict(op='jump', target=join))
        blocks.append(dict(id=block, ops=[], phis=[], term=term))
    operation = dict(op='opaque', results=[ObservedRow(id=i) for i in range(count)])
    blocks.append(dict(id=join, ops=[] if kind == 'phi' else [operation],
                       phis=[], term=dict(op='return')))
    values = [dict(function=0, id=0, origin=dict(kind='enter'))]
    if kind == 'phi':
        incoming = [ObservedRow(predecessor=i, value=0) for i in range(count - 1, join)]
        values.append(dict(function=0, id=1,
                           origin=dict(kind='phi', block=join, incoming=incoming)))
    phases = [dict(function=0, selector=dict(kind='always'),
                   site=dict(kind='entry', block=0), within=dict(kind='outside'),
                   event=dict(kind='enter_root', scope=0)),
              dict(function=0, selector=dict(kind='always'),
                   site=dict(kind='pre_terminator', block=join), within=dict(kind='outside'),
                   event=dict(kind='scope_exit', exit=0))]
    contract = dict(
        scopes=[dict(function=0, id=0, within=dict(kind='outside'), enter_value=0)],
        scope_values=values,
        exits=[dict(function=0, id=0, scope_value=1 if kind == 'phi' else 0,
                    outcome=dict(kind='normal_no_journal'))],
        returns=[dict(function=0, id=0, exit=0, scope=0)],
        adoptions=[], phase_sites=phases)
    ledger = budget()
    states = engine(dict(id=0, entry=0, blocks=blocks), contract, ledger)
    return states, visits[0], ledger._used_work


class RepeatedVectorBudgetBoundary(unittest.TestCase):
    def test_predecessor_phi_row_visits_fit_charged_work(self):
        states, visits, charged = joined_vector_probe(1024, 'phi')
        self.assertEqual(states, 3071)
        self.assertLessEqual(visits, charged)

    def test_ssa_result_row_visits_fit_charged_work(self):
        states, visits, charged = joined_vector_probe(1024, 'results')
        self.assertEqual(states, 3071)
        self.assertLessEqual(visits, charged)


if __name__ == '__main__':
    unittest.main(verbosity=2)
