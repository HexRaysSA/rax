"""Executable CodeAddress static and nonobserving transport boundaries."""
from copy import deepcopy
import unittest

from common import Reject
from candidate.function_address_contract import local_roots, cases, observe
from candidate.type_system import Types, ref
from candidate.layouts import Layouts
from candidate.values import Pointer, Value, literal, raw_bits, from_raw, zero
from candidate.raw import Raw, concat
from candidate.verify import verify
from candidate.operations import Dependencies, check_operation
from test_candidate import operation, decl


class FunctionAddressTests(unittest.TestCase):
    def test_leaf_needs_no_signature_or_completed_source_type(self):
        root = {'payload_revision': 2, 'types': [{'kind': 'code_address', 'id': 0}], 'memory_layouts': []}
        types = Types(root)
        self.assertEqual(types.width(ref(0)), 64)
        self.assertEqual(types.children(types.get(ref(0))), [])
        self.assertEqual(zero(types, ref(0)).data, Pointer(0, domain='code_address'))
        with self.assertRaisesRegex(Reject, 'block_address_type'):
            check_operation(operation('block_address', [decl(1, 0)], function=0, block=1),
                            types, Dependencies(), lambda _: ref(0), {})

    def test_layout_exact_eight_bytes_and_alignment(self):
        for size, alignment, access, valid in [(8, 8, 8, True), (16, 8, 8, False),
                                               (8, 4, 8, False), (8, 8, 4, False)]:
            root = local_roots()[0]
            root['memory_layouts'] = [dict(id=0, type=ref(300), size=size, alignment=alignment,
                access_bytes=access, fields=[], element=None, stride=0)]
            if valid:
                Layouts(root, Types(root))
            else:
                with self.assertRaisesRegex(Reject, 'code_address_layout'):
                    Layouts(root, Types(root))

    def test_raw_original_permit_and_mixed_permit_rejection(self):
        types = Types(local_roots()[0])
        first = Pointer(2, 'aa' * 32, 1, 'code', None, 7)
        second = Pointer(2, 'aa' * 32, 1, 'code', None, 9)
        raw = Raw.pointer(first)
        complete = concat([raw.slice(0, 23), raw.slice(23, 41)])
        restored = from_raw(types, ref(302), complete)
        self.assertEqual(restored.data, first)
        mixed = concat([raw.slice(0, 23), Raw.pointer(second).slice(23, 41)])
        self.assertIsNone(from_raw(types, ref(302), mixed).data.origin)
        self.assertIsNone(from_raw(types, ref(302), mixed).data.permit)
        address = from_raw(types, ref(300), complete)
        self.assertIsNone(address.data.origin)  # Typed raw destination cannot code_erase.
        self.assertIsNone(address.data.permit)

    def test_raw_address_domain_roundtrip_never_upgrades_to_callable(self):
        types = Types(local_roots()[0])
        pointer = Pointer(4, 'bb' * 32, 8, 'code_address')
        raw = raw_bits(types, Value(ref(300), 'concrete', pointer))
        self.assertEqual(from_raw(types, ref(300), raw).data, pointer)
        self.assertEqual(from_raw(types, ref(302), raw).data.domain, 'code_address')
        self.assertIsNone(from_raw(types, ref(302), raw).data.permit)

    def test_local_static_positive_and_rejection_vectors(self):
        for case in cases():
            if case['scope'] != 'execution-local':
                continue
            with self.subTest(case=case['id']):
                self.assertEqual(observe(case), case['expected'])

    def test_genuine_source_vectors(self):
        for case in cases():
            if case['scope'] != 'abi-and-execution':
                continue
            with self.subTest(case=case['id']):
                self.assertEqual(observe(case), case['expected'])

    def test_static_success_keeps_missing_runtime_producers_unavailable(self):
        from candidate.function_address_contract import verify_source
        from candidate.machine import Machine
        selected = {case['id']: case for case in cases()}
        for name, diagnostic in [('genuine-ordinary-bind-plan', 'reference_code_address_unavailable'),
                                  ('genuine-caller-plan-C', 'reference_source_call_unavailable')]:
            context, checked = verify_source(selected[name]['sections'])
            machine = Machine(checked)
            with self.subTest(name=name), self.assertRaisesRegex(Reject, diagnostic):
                machine.start(0, [Value(ref(17), 'concrete', 42)])
            self.assertEqual(machine.stack, [])
            self.assertEqual(machine.memory.effects, [])
            self.assertEqual(machine.code_pointers, {})
        context, checked = verify_source(selected['explicit-generic-None']['sections'])
        machine = Machine(checked)
        machine.start(0, [Value(ref(17), 'concrete', 42)])
        self.assertEqual(machine.run()['values'][0].data, 42)

    def test_plan_Fn_mismatch_and_nonordinary_without_runtime_issuer(self):
        types = Types(local_roots()[0])
        node = operation('code_bind', [decl(1, 302)], [0], plan=ref(0))
        base = dict(this_type=None, vtt=False, execution=ref(15))
        for change, error in [({'execution': ref(2)}, 'source_plan_execution'),
                              ({'this_type': {'some': ref(0)}}, 'source_plan_ordinary'),
                              ({'vtt': True}, 'source_plan_ordinary')]:
            dependencies = Dependencies(abi_signatures={('self', 0): {**base, **change}})
            with self.subTest(error=error), self.assertRaisesRegex(Reject, error):
                check_operation(node, types, dependencies, lambda _: ref(300), {})
        # This local static map is deliberately NOT an actual ABI/runtime proof.
        # Genuine source vectors above exercise RootContext's independent stage.


if __name__ == '__main__':
    unittest.main()
