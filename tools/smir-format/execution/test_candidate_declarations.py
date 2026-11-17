"""Consumer opaque declarations authorize static address typing, not provider state."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.type_system import ref
from test_candidate import block, decl, operation
from test_candidate_context import roots


def opaque_consumer():
    candidate = roots()
    opaque = deepcopy(candidate[10]['types'][0])
    opaque.update(id=30, kind='record', bits=0, signed=False, representation='none', execution=None,
                  layout=None, flags=[], elements=[], extent=None, methods=[], enumerators=[])
    opaque['identity'].update(language='cpp23', linkage='external', entity='example.FILE', definition='0' * 64)
    candidate[10]['types'].append(opaque)
    candidate[1]['types'].append({'id': 202, 'kind': 'function', 'params': [], 'results': [ref(4)],
        'variadic': False, 'param_noundef': [], 'result_noundef': [True], 'cc': 'portable'})
    candidate[2]['manifest']['dependencies'] = [{'slot': 0,
        'key': {'namespace': 'example', 'name': 'provider', 'abi_major': 1, 'abi_minor': 0},
        'minimum_minor': 0, 'maximum_minor': None, 'site': candidate[10]['identity'], 'declarations': [
            {'id': 0, 'kind': 'symbol', 'symbol_kind': 'data', 'source_linkage': 'c', 'namespace': 'example', 'name': 'opaque_object',
             'execution': None, 'nominal': {'some': ref(30)}, 'abi_signature': None, 'weak': False}]}]
    candidate[3]['functions'].append({'id': 1, 'signature': ref(202), 'abi_signature': None, 'params': [],
        'entry': 0, 'escape': 'propagate', 'no_return': False,
        'blocks': [block(0, [operation('address_of', [decl(0, 4)], symbol=ref(0, 0))], {'op': 'return', 'values': [0]})]})
    return candidate


class CandidateDeclarationTests(unittest.TestCase):
    def test_actual_opaque_address_typing_requires_real_provider_before_execution(self):
        context = RootContext(opaque_consumer())
        context.verify_abi()
        admitted = context.verify_execution()
        self.assertIsNone(context.nominal(ref(30))['execution'])
        self.assertIsNone(admitted.dependencies.symbols[('dependency', 0, 0)]['execution'])
        self.assertTrue(admitted.dependencies.symbols[('dependency', 0, 0)]['declaration'])
        with self.assertRaisesRegex(Reject, 'symbol_definition_reference'):
            context.runtime_symbol(ref(0, 0))
        with self.assertRaisesRegex(Reject, 'reference_unbound_symbol'):
            Machine(admitted).start(1, [])

    def test_function_declaration_is_not_nominal_namespace(self):
        candidate = opaque_consumer()
        declaration = candidate[2]['manifest']['dependencies'][0]['declarations'][0]
        declaration.update(kind='function', symbol_kind='none', execution={'some': ref(12)}, nominal={'some': ref(12)},
                           abi_signature={'some': ref(0)})
        candidate[3]['functions'].pop()  # Data address op no longer matches function declaration.
        context = RootContext(candidate)
        context.verify_abi()
        context.verify_execution()
        with self.assertRaisesRegex(Reject, 'nominal_context_reference'):
            context.nominal(ref(0, 0))
        with self.assertRaisesRegex(Reject, 'function_definition_reference'):
            context.function(ref(0, 0))


if __name__ == '__main__':
    unittest.main()
