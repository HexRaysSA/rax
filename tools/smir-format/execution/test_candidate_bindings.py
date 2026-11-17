"""Actual section6 catalogs and section10 namespace binding (no fake Deps)."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.bindings import catalog_digest, documents, runtime_package_module
from candidate.context import RootContext
from candidate.type_system import ref
from test_candidate_context import roots


def add_import(name, contract='default', types=(), abi=None, options=None):
    candidate = roots()
    helpers = runtime_package_module('helpers')
    spec = helpers.helper(name)
    typ = {item['id']: item for item in candidate[1]['types']}
    fixed = {'u64': 5, 'u32': 1, 'i32': 1, 'data_ptr': 4, 'exception': 7, 'journal': 300}
    if any(item['type'] == 'code_ptr' for item in spec['params'] + spec['results']):
        candidate[1]['types'] += [
            {'id': 300, 'kind': 'function', 'params': [], 'results': [], 'param_noundef': [],
             'result_noundef': [], 'cc': 'portable', 'variadic': False},
            {'id': 301, 'kind': 'code_ptr', 'signature': ref(300)}]
        fixed['code_ptr'] = 301
    def template(name):
        return types[int(name[4:])] if name.startswith('type') else fixed[name]
    signature = {'id': 201, 'kind': 'function', 'cc': 'portable', 'variadic': False}
    for side, attr in [('params', 'param_noundef'), ('results', 'result_noundef')]:
        signature[side] = [ref(template(item['type'])) for item in spec[side]]
        signature[attr] = [item['noundef'] for item in spec[side]]
    candidate[1]['types'].append(signature)
    candidate[1]['types'].sort(key=lambda item: item['id'])
    binding = {'id': 0, 'kind': 'internal', 'namespace': spec['namespace'], 'name': name,
               'version': 1, 'catalog': helpers.digest(), 'signature': ref(201), 'abi': abi,
               'types': [ref(identifier) for identifier in types], 'contract': contract,
               'options': {**deepcopy(helpers.DEFAULT_OPTIONS), **(options or {})}}
    candidate[6]['imports'] = [binding]
    return candidate, binding


def admit(candidate):
    context = RootContext(candidate)
    context.verify_abi()
    context.verify_execution()
    return context


class CandidateBindingTests(unittest.TestCase):
    def test_real_catalog_nominal_and_alias_shape(self):
        candidate, binding = add_import('va_arg', types=[16], abi={'some': ref(1)})
        # Type16 and source int's execution1 are different IDs of equal i32 shape.
        admit(candidate)
        binding['abi'] = {'some': ref(0)}  # Signature0 exists; nominal0 does not.
        with self.assertRaisesRegex(Reject, 'helper_namespace_reference'):
            admit(candidate)

    def test_anonymous_physical_storage_and_wrong_namespace(self):
        candidate, binding = add_import('memory_load', 'ordinary', [16], options={'alignment': 4, 'target': {'some': ref(0)}})
        admit(candidate)
        binding['options']['target'] = {'some': ref(200)}  # Struct type exists; layout200 absent.
        with self.assertRaisesRegex(Reject, 'helper_namespace_reference'):
            admit(candidate)
        binding['options']['target'] = {'some': ref(1)}  # Valid layout of raw64, not i32.
        with self.assertRaisesRegex(Reject, 'STORAGE_TYPE'):
            admit(candidate)

    def test_unused_options_and_stale_catalog_reject(self):
        candidate, binding = add_import('stack_alloc')
        admit(candidate)
        binding['options']['order'] = 'acquire'
        with self.assertRaisesRegex(Reject, 'UNUSED_ORDER'):
            admit(candidate)
        binding['options']['order'] = 'none'
        binding['catalog'] = '00' * 32
        with self.assertRaisesRegex(Reject, 'HELPER_VERSION'):
            admit(candidate)


if __name__ == '__main__':
    unittest.main()
