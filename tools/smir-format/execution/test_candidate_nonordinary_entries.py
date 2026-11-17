"""Actual checked entry associations and strict ordinary execution boundaries."""
from pathlib import Path
import sys, unittest, importlib.util
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[3]
for directory in ('tools/smir-abi', 'tools/smir-runtime-contract'):
    path = str(ROOT / directory)
    if path not in sys.path:
        sys.path.append(path)
from candidate.context import RootContext
from common import Reject
from nonordinary_entry_fixtures import physical, associated, budget
from function_address.fixtures import ordinary

class EntryAssociationTests(unittest.TestCase):

    def test_genuine_constructor_actual_entry_association(self):
        roots, d = physical()
        o, r = associated(roots, d, budget())
        self.assertTrue(r.checks)
        out = o.verify_execution()
        self.assertIn(1800, [f['id'] for f in out.functions_root['functions']])

    def test_genuine_constructor_vtt_actual_entry_association(self):
        roots, d = physical(vtt=True)
        o, r = associated(roots, d, budget())
        o.verify_execution()

    def test_genuine_destructor_actual_entry_association(self):
        roots, d = physical(destructor=True)
        o, r = associated(roots, d, budget())
        o.verify_execution()

    def test_removing_required_body_association_still_rejects(self):
        roots, d = physical()
        roots[3]['functions'][-1]['abi_signature'] = None
        with self.assertRaisesRegex(Exception, 'ABI_SP_ORIGINAL_IMPLEMENTATION'):
            associated(roots, d, budget())

    def test_ordinary_paths_unchanged(self):
        o = RootContext(ordinary(complete_record=True))
        o.verify_abi()
        before = o.verify_execution()
        after = o.verify_execution()
        self.assertEqual(before.functions_root, after.functions_root)

    def test_noexcept_is_not_body_escape_or_no_return(self):
        for noex in (False, True):
            for escape in ('propagate', 'terminate', 'nothrow'):
                roots, d = physical(noexcept=noex, escape=escape)
                o, r = associated(roots, d, budget())
                out = o.verify_execution()
                f = next((x for x in out.functions_root['functions'] if x['id'] == 1800))
                self.assertEqual(f['escape'], escape)
                self.assertFalse(f['no_return'])

    def test_wrong_actual_fullfn_still_rejects(self):
        roots, d = physical()
        roots[3]['functions'][-1]['signature'] = {'module': {'kind': 'self'}, 'id': 1001}
        o = RootContext(roots)
        o.verify_abi()
        with self.assertRaises(Reject):
            o.verify_execution()

    def test_wrong_actual_parameter_type_still_rejects(self):
        roots, d = physical()
        roots[3]['functions'][-1]['params'][0]['type'] = {'module': {'kind': 'self'}, 'id': 1000}
        o = RootContext(roots)
        o.verify_abi()
        with self.assertRaisesRegex(Reject, 'parameter_signature'):
            o.verify_execution()

    def test_wrong_noundef_still_real_abi_rejects(self):
        roots, d = physical()
        next((t for t in roots[1]['types'] if t['id'] == 1800))['param_noundef'] = [False]
        with self.assertRaisesRegex(Exception, 'ABI_CC_LOWERED_SIGNATURE'):
            RootContext(roots).verify_abi()

    def test_vtt_without_this_still_real_abi_rejects(self):
        roots, d = physical(vtt=True)
        next((p for p in roots[10]['signatures'] if p['id'] == 202))['this_type'] = None
        with self.assertRaisesRegex(Exception, 'ABI_CC_VTT_WITHOUT_THIS'):
            RootContext(roots).verify_abi()

    def test_hidden_sret_order_is_real_abi_not_flattened_source_params(self):
        roots, d = physical(sret=True)
        o = RootContext(roots)
        o.verify_abi()
        out = o.verify_execution()
        f = next((x for x in out.functions_root['functions'] if x['id'] == 1800))
        self.assertEqual(len(f['params']), 2)
        plan = next((p for p in roots[10]['signatures'] if p['id'] == 202))
        self.assertEqual([p['role'] for p in plan['lowered_params']], ['sret', 'this'])
        self.assertEqual(plan['params'], [])

    def test_hidden_sret_wrong_order_still_real_abi_rejects(self):
        roots, d = physical(sret=True)
        next((p for p in roots[10]['signatures'] if p['id'] == 202))['lowered_params'].reverse()
        with self.assertRaisesRegex(Exception, 'ABI_CC_CALL_PARAMETER'):
            RootContext(roots).verify_abi()

class FixtureReproductionTests(unittest.TestCase):

    def test_root_codec_does_not_shadow_legacy_codec_or_search_path(self):
        from nonordinary_entry_fixtures import generated
        import importlib
        legacy = importlib.import_module('codec')
        before = tuple(sys.path)
        generated()
        self.assertIs(sys.modules['codec'], legacy)
        self.assertEqual(tuple(sys.path), before)
        self.assertEqual(Path(legacy.__file__).resolve(),
                         ROOT / 'tools/smir-format/execution/codec.py')

    def test_checked_source_abi_and_smo_fixtures_reproduce(self):
        from nonordinary_entry_fixtures import generated
        directory = ROOT / 'docs/specifications/smir/portable/conformance/execution/nonordinary-entry-associations'
        outputs = generated()
        self.assertEqual(len(outputs), 12)
        for name, contents in outputs.items():
            with self.subTest(name=name):
                self.assertEqual((directory / name).read_bytes(), contents)


class BoundaryTests(unittest.TestCase):

    def test_failed_abi_cannot_execute(self):
        roots, d = physical()
        o = RootContext(roots)
        with self.assertRaisesRegex(Reject, 'abi_before_execution_binding'):
            o.verify_execution()

    def test_no_return_does_not_accept_return(self):
        roots, d = physical()
        roots[3]['functions'][-1]['no_return'] = True
        o = RootContext(roots)
        o.verify_abi()
        with self.assertRaisesRegex(Reject, 'return_signature'):
            o.verify_execution()

    def test_nonordinary_source_call_plan_still_refused(self):
        from candidate.operations import ordinary_plan
        roots, d = physical()
        o, r = associated(roots, d, budget())
        v = o.verify_execution()
        with self.assertRaisesRegex(Reject, 'source_plan_ordinary'):
            ordinary_plan({'module': {'kind': 'self'}, 'id': 202}, {'module': {'kind': 'self'}, 'id': 1800}, v.types, v.dependencies)

    def test_actual_cli_method_entry_is_pre_effect_refusal(self):
        from nonordinary_entry_fixtures import root_codec, encoded
        codec = root_codec()
        from candidate.machine import Machine
        import sys
        # Load the actual canonical registry; constructor wrappers below delegate.
        name = '_rax_smir_code_addresses_v1'
        code = sys.modules.get(name)
        if code is None:
            spec = importlib.util.spec_from_file_location(name, ROOT / 'tools/smir-runtime-contract/source_roles/code_addresses.py')
            code = importlib.util.module_from_spec(spec)
            sys.modules[name] = code
            spec.loader.exec_module(code)
        counts = {'machine': 0, 'registry': 0}
        mi = Machine.__init__
        ri = code.CodeRegistry.__init__

        def measured_machine(*a, **kw):
            counts['machine'] += 1
            return mi(*a, **kw)

        def measured_registry(*a, **kw):
            counts['registry'] += 1
            return ri(*a, **kw)
        roots, d = physical()
        payload = encoded(roots)
        policy = codec.reference_policy((ROOT / 'docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/policy.json').read_bytes())
        with patch.object(Machine, '__init__', measured_machine), patch.object(code.CodeRegistry, '__init__', measured_registry):
            with self.assertRaises(codec.RecordError) as caught:
                codec.run_reference(payload, entry_function=1800, argument_bits=['0000000000000000'], policy=policy)
        self.assertEqual(str(caught.exception), 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')
        self.assertEqual(counts, {'machine': 0, 'registry': 0})
        owner = RootContext(roots)
        owner.verify_abi()
        with self.assertRaisesRegex(codec.RecordError, 'REFERENCE-EXECUTION-SIGNATURE-SCOPE'):
            codec._reference_source_plan_preflight(owner, {'module': {'kind': 'self'}, 'id': 202})
if __name__ == '__main__':
    unittest.main(verbosity=2)
