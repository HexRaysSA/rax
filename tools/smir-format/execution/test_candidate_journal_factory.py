"""R042 fixed capture signatures resolved from actual ABI cleanup programs."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.type_system import ref
from test_candidate_eh_bindings import journal_package
from test_candidate_storage_join import storage_wrapper


def capture_factory(formals=True):
    roots = storage_wrapper()
    roots[10]['journals'] = deepcopy(journal_package()[0][10]['journals'])
    roots[10]['journals'][0]['params'] = ([{'id': 0, 'type': ref(1)}, {'id': 1, 'type': ref(4)}]
                                         if formals else [])
    roots[1]['types'] += [{'id': 600, 'kind': 'journal'},
        {'id': 601, 'kind': 'function', 'cc': 'portable', 'variadic': False,
         'params': [ref(4)] + ([ref(17), ref(4)] if formals else []),
         'results': [ref(600)], 'param_noundef': [False] * (3 if formals else 1),
         'result_noundef': [False]}]
    helpers = runtime_package_module('helpers')
    roots[6]['imports'].append({'id': 1, 'kind': 'internal', 'namespace': 'smir.internal.v1',
        'name': 'journal_begin', 'version': 1, 'catalog': helpers.digest(), 'signature': ref(601),
        'abi': {'some': ref(0)}, 'types': [], 'contract': 'construction', 'options': deepcopy(helpers.DEFAULT_OPTIONS)})
    return roots


class CandidateJournalFactoryTests(unittest.TestCase):
    def test_actual_source_formals_expand_to_fixed_signature_in_order(self):
        for formals in [False, True]:
            context = RootContext(capture_factory(formals))
            context.verify_abi(); context.verify_execution()
            self.assertEqual(len(context.execution(ref(601))['params']), 3 if formals else 1)
            self.assertFalse(context.execution(ref(601))['variadic'])
        for mutation in ['wrong_order', 'wrong_arity', 'wrong_noundef']:
            roots = capture_factory()
            signature = next(t for t in roots[1]['types'] if t['id'] == 601)
            if mutation == 'wrong_order':
                signature['params'][1:] = [ref(4), ref(17)]
            elif mutation == 'wrong_arity':
                signature['params'].pop(); signature['param_noundef'].pop()
            else:
                signature['param_noundef'][1] = True
            context = RootContext(roots)
            context.verify_abi()
            with self.assertRaisesRegex(Reject, 'RT_HELPER_(TYPE|ARITY|NOUNDEF)'):
                context.verify_execution()

    def test_missing_capture_evidence_differs_from_actual_zero_formal_program(self):
        context = RootContext(capture_factory(False))
        context.verify_abi(); context.verify_execution()
        binding = context.sections[6]['imports'][1]
        helpers = runtime_package_module('helpers')
        with self.assertRaisesRegex(ValueError, 'RT_HELPER_JOURNAL_CAPTURES'):
            helpers.instantiate(binding, context.execution, context.abi_entity, context.target_entity)
        self.assertEqual(helpers.instantiate(binding, context.execution, context.abi_entity,
            context.target_entity, journal_captures=[])['name'], 'journal_begin')


if __name__ == '__main__':
    unittest.main()
