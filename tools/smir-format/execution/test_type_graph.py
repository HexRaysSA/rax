"""Exact noninteger/signature graph grammar, width and cross-module checks."""
from copy import deepcopy
import unittest

from codec import decode, encode
from common import Reject
from type_graph import equivalent, verify_types


def graph():
    return {'revision': 'execution_types_draft_v1', 'types': [
        {'id': 0, 'kind': 'int', 'bits': 8},
        {'id': 1, 'kind': 'float', 'format': 'binary128'},
        {'id': 2, 'kind': 'data_ptr', 'space': 'guest_data'},
        {'id': 3, 'kind': 'raw', 'bits': 65},
        {'id': 4, 'kind': 'vector', 'element': 0, 'count': 3},
        {'id': 5, 'kind': 'array', 'element': 4, 'count': 2},
        {'id': 6, 'kind': 'struct', 'fields': [1, 2, 5]},
        {'id': 7, 'kind': 'function', 'params': [6, 8], 'results': [2],
         'variadic': 'no', 'param_noundef': ['yes', 'no'], 'result_noundef': ['yes'], 'cc': 'portable'},
        {'id': 8, 'kind': 'code_ptr', 'signature': 7}]}


class TypeGraphTests(unittest.TestCase):
    def test_exact_shapes_widths_and_recursive_signatures(self):
        document = graph()
        types, widths = verify_types(document)
        self.assertEqual(widths, {0: 8, 1: 128, 2: 64, 3: 65, 4: 24, 5: 48, 6: 240, 7: 0, 8: 64})
        payload = encode('extended_types', document)
        self.assertEqual(decode('extended_types', payload), document)
        # Storage vector width24 is intentionally not ABI allocation size32.
        self.assertEqual(widths[4], 24)

    def test_cross_module_ids_do_not_imply_equal_types(self):
        left, _ = verify_types(graph())
        changed = graph()
        changed['types'][0]['bits'] = 16
        right, _ = verify_types(changed)
        self.assertFalse(equivalent(left, 0, right, 0))
        self.assertFalse(equivalent(left, 8, right, 8))
        changed = graph()
        mapping = {item['id']: item['id'] + 100 for item in changed['types']}
        for item in changed['types']:
            item['id'] = mapping[item['id']]
            for field in ['element', 'signature']:
                if field in item:
                    item[field] = mapping[item[field]]
            for field in ['fields', 'params', 'results']:
                if field in item:
                    item[field] = [mapping[value] for value in item[field]]
        right, _ = verify_types(changed)
        self.assertTrue(equivalent(left, 8, right, 108))

    def test_value_cycles_missing_references_and_signature_rejects(self):
        for mutate, code in [
                (lambda x: x['types'][6].update(fields=[6]), 'type_cycle'),
                (lambda x: x['types'][5].update(element=999), 'type_reference'),
                (lambda x: x['types'][8].update(signature=0), 'type_signature'),
                (lambda x: x['types'][7].update(param_noundef=['yes']), 'type_signature'),
                (lambda x: x['types'][4].update(element=6), 'type_vector'),
                (lambda x: x['types'][4].update(count=0), 'type_vector'),
                (lambda x: x['types'][2].update(space='host'), 'type_space'),
                (lambda x: x['types'][5].update(count=2**64 - 1), 'type_limit')]:
            document = graph()
            mutate(document)
            with self.assertRaises(Reject) as error:
                verify_types(document)
            self.assertEqual(error.exception.code, code)

    def test_zero_sized_aggregates_and_boundaries(self):
        document = {'revision': 'execution_types_draft_v1', 'types': [
            {'id': 0, 'kind': 'int', 'bits': 65535},
            {'id': 1, 'kind': 'struct', 'fields': []},
            {'id': 2, 'kind': 'array', 'element': 1, 'count': 2**64 - 1}]}
        _, widths = verify_types(document)
        self.assertEqual(widths, {0: 65535, 1: 0, 2: 0})
        document['types'][0]['bits'] = 65536
        with self.assertRaises(Reject):
            verify_types(document)


if __name__ == '__main__':
    unittest.main()
