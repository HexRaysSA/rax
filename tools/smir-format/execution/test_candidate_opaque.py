"""Transitive opaque authority restrictions without rejecting SSA EH aggregates."""
import unittest

from common import Reject
from candidate.machine import Machine
from candidate.type_system import Types, ref
from candidate.values import Value, freeze, validate
from candidate.verify import verify
from test_candidate import block, constant, decl, fixture, operation


def package():
    roots = fixture()
    roots[0]['types'] += [
        {'id': 17, 'kind': 'struct', 'fields': [ref(10), ref(2)]},
        {'id': 18, 'kind': 'array', 'element': ref(17), 'count': 2},
        {'id': 19, 'kind': 'array', 'element': ref(17), 'count': 0},
        {'id': 20, 'kind': 'struct', 'fields': [ref(11), ref(2)]}]
    return roots


class CandidateOpaqueTests(unittest.TestCase):
    def test_nested_zero_and_freeze_reject_before_reference_execution(self):
        for identifier in [10, 17, 18, 20]:
            roots = package()
            roots[1]['functions'][0]['blocks'][0]['ops'].insert(0,
                operation('constant', [decl(10, identifier)], literal={'kind': 'zero'}))
            with self.assertRaisesRegex(Reject, 'literal'):
                verify(*roots)
        for identifier in [10, 17, 18]:
            roots = package()
            roots[1]['functions'][0]['blocks'][0]['ops'][:0] = [
                operation('constant', [decl(10, identifier)], literal={'kind': 'poison'}),
                operation('freeze', [decl(11, identifier)], [10])]
            with self.assertRaisesRegex(Reject, 'freeze_opaque'):
                verify(*roots)
        roots = package()
        roots[1]['functions'][0]['blocks'][0]['ops'].insert(0,
            operation('constant', [decl(10, 19)], literal={'kind': 'zero'}))
        machine = Machine(verify(*roots))
        machine.start(0, [])
        self.assertEqual(machine.run()['values'][0].data, 42)

    def test_issued_exception_transport_and_nested_fenv_refinement(self):
        roots = package()
        roots[0]['types'][15]['params'] = [ref(10)]
        roots[0]['types'][15]['param_noundef'] = [True]
        fn = roots[1]['functions'][0]
        fn['params'] = [decl(0, 10)]
        fn['blocks'] = [block(0, [
            operation('constant', [decl(1, 17)], literal={'kind': 'poison'}),
            operation('insert', [decl(2, 17)], [1, 0], indices=[0]),
            operation('extract', [decl(3, 10)], [2], indices=[0]),
            constant(4, 2, '2a000000')], {'op': 'return', 'values': [4]})]
        machine = Machine(verify(*roots))
        exception = machine.handle(ref(10), {'nominal': ('self', 1)})
        machine.start(0, [exception])
        # Capture before return pops the frame: three operations plus phi entry.
        self.assertEqual(machine.run(fuel=4)['kind'], 'resource')
        self.assertEqual(machine.stack[0].values[3], exception)
        self.assertEqual(machine.run()['values'][0].data, 42)
        types = Types(roots[0])
        value = freeze(types, Value(ref(20), 'poison'))
        validate(types, value, {})
        self.assertEqual(value.data, (
            Value(ref(11), 'concrete', {'rounding': 'nearest_even', 'flags': [], 'traps': []}),
            Value(ref(2), 'concrete', 0)))
        with self.assertRaisesRegex(Reject, 'freeze_opaque'):
            freeze(types, Value(ref(17), 'undef'))


if __name__ == '__main__':
    unittest.main()
