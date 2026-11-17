"""Actual original scalar-source/body alignment; no interpreter or emitter."""
from pathlib import Path
import copy
from dataclasses import replace
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import scalar_conditions as C
import scalar_alignment as S
HERE = Path(__file__).resolve().parent
FIX = Path(os.environ.get('SCALAR_REFERENCE_FIXTURES', str(C.PROJECT / 'docs/specifications/smir/portable/conformance/llvm/scalar-alignment')))
sys.path.insert(0, str(FIX))
import scalar_fixture_support as F
import scalar_mapping_witness as P

def rejected(case, code, *, mapping_change=None, source_name=None):
    owner, b, w, c, m = P.inputs(case, source_name=source_name)
    if mapping_change:
        mapping_change(m)
    try:
        S.verify(w, owner, m, conditions=c, budget=b)
    except C.AlignmentError as error:
        if error.code != code:
            raise AssertionError((code, error.code)) from error
        return
    raise AssertionError('accepted ' + code)

def altered_owner(owner, b, change):
    from candidate import root3_context as D
    roots = copy.deepcopy(owner.sections)
    change(roots)
    raw = D.codec().encode_module(roots, budget=b)
    return C.A.R.apis()[0].RootContext.from_module(raw, budget=b)

def repin_mapping(m, owner, b):
    stamp = owner.prepare_source_data(budget=b)
    m['smir_module_digest'] = owner.sections[2]['manifest']['identity']
    m['smir_root3_sha256'] = dict(stamp.root_digests)[3].hex()

class Pure(unittest.TestCase):

    def test_schema_exact_fields_bool_ids_full_u32(self):
        b = F.budget()
        d, _ = C.schema(b)
        m = json.loads((FIX / 'one.mapping.json').read_bytes())
        for value in [0, 4294967295]:
            v = copy.deepcopy(m)
            v['parameters'][0]['value'] = value
            v['nodes'][0]['value'] = value
            v['types'][0]['execution']['id'] = value
            C.A.R.shape(d['$defs']['mapping'], v, d['$defs'], b)
        for mode in ['bool', 'extra', 'missing']:
            v = copy.deepcopy(m)
            if mode == 'bool':
                v['nodes'][0]['value'] = True
            elif mode == 'extra':
                v['assume_no_attrs'] = True
            else:
                del v['return_node']
            with self.assertRaises(C.A.R.ProjectionError):
                C.A.R.shape(d['$defs']['mapping'], v, d['$defs'], b)

    def test_unissued_condition_and_result(self):
        b = F.budget()
        cond = C.ConditionWitness({'fabricated': True}, None, b)
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_CONDITION_ISSUANCE'):
            cond.report(budget=b)
        result = S.ScalarAlignment({}, None, None, None, None, b)
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_RESULT_ISSUANCE'):
            result.report(budget=b)

    def test_mathematical_cast_boundaries(self):
        for width in [8, 16, 32, 64]:
            mask = (1 << width) - 1
            for bits in [0, 1, (1 << width - 1) - 1, 1 << width - 1, mask]:
                signed_value = bits if bits < 1 << width - 1 else bits - (1 << width)
                for dest in [8, 16, 32, 64]:
                    for signed in [False, True]:
                        source_value = signed_value if signed else bits
                        expected = source_value % (1 << dest)
                        if dest <= width:
                            actual = bits & (1 << dest) - 1
                        elif signed and bits & 1 << width - 1:
                            actual = bits | (1 << dest - width) - 1 << width
                        else:
                            actual = bits
                        self.assertEqual(actual, expected)

    def test_checker_has_no_encoder_or_generation_import(self):
        import ast
        tree = ast.parse((HERE / 'scalar_alignment.py').read_text())
        names = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        self.assertNotIn('encode_module', names)
        self.assertNotIn('write_bytes', names)
        self.assertNotIn('write_text', names)

class Actual(unittest.TestCase):

    def test_seven_real_original_positives(self):
        for name in P.NODE_ROWS:
            with self.subTest(name=name):
                owner, b, w, c, m = P.inputs(name)
                result = S.verify(w, owner, m, conditions=c, budget=b)
                r = result.report(budget=b)
                self.assertTrue(r['finite_alignment_checked'])
                self.assertIs(result.owner, owner)
                self.assertIs(result.stamp, owner.prepare_source_data(budget=b))
                self.assertIsNone(owner.execution_checked)
                for field in ['executable', 'runtime_authority', 'source_fact_authority', 'semantic_admission', 'active_v3_verified', 'source_to_smir_full_provenance']:
                    self.assertFalse(r[field])

    def test_literal_one_source_two_body_rejected(self):
        rejected('two', 'SCALAR_LITERAL_VALUE', source_name='one')

    def test_wrong_operand_order_real_body(self):
        owner, b, w, c, m = P.inputs('subtract')

        def change(roots):
            roots[3]['functions'][0]['blocks'][0]['ops'][1]['operands'] = [1, 0]
        other = altered_owner(owner, b, change)
        repin_mapping(m, other, b)
        other.verify_abi()
        other.verify_candidate_body(budget=b)
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_BINARY_OPERAND_ORDER'):
            S.verify(w, other, m, conditions=c, budget=b)

    def test_wrong_source_signedness_extension_real_body(self):
        owner, b, w, c, m = P.inputs('signed-casts')

        def change(roots):
            roots[3]['functions'][0]['blocks'][0]['ops'][0]['op'] = 'zext'
        other = altered_owner(owner, b, change)
        repin_mapping(m, other, b)
        other.verify_abi()
        other.verify_candidate_body(budget=b)
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_CAST_SIGN_WIDTH'):
            S.verify(w, other, m, conditions=c, budget=b)

    def test_wrong_return_ssa_real_body(self):
        owner, b, w, c, m = P.inputs('subtract')

        def change(roots):
            roots[3]['functions'][0]['blocks'][0]['term']['values'] = [0]
        other = altered_owner(owner, b, change)
        repin_mapping(m, other, b)
        other.verify_abi()
        other.verify_candidate_body(budget=b)
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_RETURN_SSA'):
            S.verify(w, other, m, conditions=c, budget=b)

    def test_extra_dead_op_bijection_real_body(self):
        owner, b, w, c, m = P.inputs('one')

        def change(roots):
            roots[3]['functions'][0]['blocks'][0]['ops'].append(dict(op='constant', results=[dict(id=2, type=F.ref(17))], operands=[], literal=dict(kind='zero')))
        other = altered_owner(owner, b, change)
        repin_mapping(m, other, b)
        other.verify_abi()
        other.verify_candidate_body(budget=b)
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_OPERATION_EXHAUSTION'):
            S.verify(w, other, m, conditions=c, budget=b)

    def test_width_and_missing_duplicate_mapping(self):
        rejected('one', 'SCALAR_WIDTH', mapping_change=lambda m: m['types'][0].__setitem__('execution', F.ref(2)))
        rejected('one', 'SCALAR_NODE_MAPPING_EXHAUSTION', mapping_change=lambda m: m.__setitem__('nodes', []))
        rejected('one', 'SCALAR_NODE_MAPPING_DUPLICATE', mapping_change=lambda m: m['nodes'].append(copy.deepcopy(m['nodes'][0])))

    def test_wrong_parameter_and_node_ssa(self):
        rejected('one', 'SCALAR_PARAMETER_MAPPING', mapping_change=lambda m: m['parameters'][0].__setitem__('value', 1))
        rejected('one', 'SCALAR_LITERAL_SSA', mapping_change=lambda m: m['nodes'][0].__setitem__('value', 0))

    def test_missing_conditions_and_wrong_original_ledger(self):
        owner, b, w, c, m = P.inputs('one')
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_SOURCE_CONDITIONS_UNAVAILABLE'):
            S.verify(w, owner, m, conditions=None, budget=b)
        with self.assertRaises(Exception):
            S.verify(w, owner, m, conditions=c, budget=F.budget())

    def test_copies_unissued_and_deep_immutability(self):
        owner, b, w, c, m = P.inputs('one')
        r = S.verify(w, owner, m, conditions=c, budget=b)
        for obj in [copy.copy(r), replace(r), replace(r, data={})]:
            with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_RESULT_ISSUANCE'):
                obj.report(budget=b)
        for obj in [copy.copy(c), replace(c), replace(c, data={})]:
            with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_CONDITION_ISSUANCE'):
                obj.report(budget=b)
        with self.assertRaises(TypeError):
            r.data['finite_alignment_checked'] = False

    def test_stale_mapping_and_original_mutation(self):
        rejected('one', 'SCALAR_MODULE_IDENTITY', mapping_change=lambda m: m.__setitem__('smir_root3_sha256', '0' * 64))
        owner, b, w, c, m = P.inputs('one')
        owner.sections[3]['functions'][0]['no_return'] = True
        with self.assertRaises(Exception):
            S.verify(w, owner, m, conditions=c, budget=b)

    def test_full_u32_result_ssa_positive(self):
        owner, b, w, c, m = P.inputs('one')

        def change(roots):
            f = roots[3]['functions'][0]
            f['blocks'][0]['ops'][0]['results'][0]['id'] = 4294967295
            f['blocks'][0]['term']['values'] = [4294967295]
        other = altered_owner(owner, b, change)
        repin_mapping(m, other, b)
        m['nodes'][0]['value'] = 4294967295
        result = S.verify(w, other, m, conditions=c, budget=b)
        self.assertTrue(result.report(budget=b)['finite_alignment_checked'])

    def test_full_u32_physical_type_positive(self):
        owner, b, w, c, m = P.inputs('one')

        def change(roots):
            for t in roots[1]['types']:
                if t['id'] == 17:
                    t['id'] = 4294967295
                if t['kind'] == 'function':
                    for field in ('params', 'results'):
                        t[field] = [F.ref(4294967295) if r == F.ref(17) else r for r in t[field]]
            roots[1]['types'].sort(key=lambda row: row['id'])
            for layout in roots[1]['memory_layouts']:
                if layout['type'] == F.ref(17):
                    layout['type'] = F.ref(4294967295)
            f = roots[3]['functions'][0]
            f['params'][0]['type'] = F.ref(4294967295)
            f['blocks'][0]['ops'][0]['results'][0]['type'] = F.ref(4294967295)
            for nominal in roots[10]['types']:
                if nominal['execution'] == {'some': F.ref(17)}:
                    nominal['execution'] = {'some': F.ref(4294967295)}
        other = altered_owner(owner, b, change)
        repin_mapping(m, other, b)
        m['types'][0]['execution'] = F.ref(4294967295)
        result = S.verify(w, other, m, conditions=c, budget=b)
        self.assertTrue(result.report(budget=b)['finite_alignment_checked'])

    def test_exact_and_one_less_before_real_body(self):
        keep_alive = []
        for offset, expected_calls in [(0, 1), (-1, 0)]:
            owner, b, w, c, m = P.inputs('one')
            actual = type(owner).verify_candidate_body
            start = b._used_work
            at_entry = []

            def observe(*args, **kwargs):
                at_entry.append(b._used_work)
                return actual(*args, **kwargs)
            with patch.object(type(owner), 'verify_candidate_body', observe):
                first = S.verify(w, owner, m, conditions=c, budget=b)
            keep_alive.append(first)
            self.assertEqual(len(at_entry), 1)
            prefix = at_entry[0] - start
            b.charge(work=b.max_work - b._used_work - prefix - offset)
            calls = []

            def observe_low(*args, **kwargs):
                calls.append(1)
                return actual(*args, **kwargs)
            with patch.object(type(owner), 'verify_candidate_body', observe_low):
                with self.assertRaises(Exception):
                    S.verify(w, owner, m, conditions=c, budget=b)
            self.assertEqual(len(calls), expected_calls)

    def test_actual_noreturn_constexpr_typedef_conditions_unavailable(self):
        samples = ['[[noreturn]] unsigned value(unsigned x) { return 1u; }', 'constexpr unsigned value(unsigned x) { return 1u; }', 'typedef unsigned U; U value(U x) { return 1u; }', 'unsigned value(unsigned x=1u); unsigned value(unsigned x) { return 1u; }']
        for code in samples:
            with self.subTest(code=code), tempfile.TemporaryDirectory(dir=os.environ.get('SCALAR_SCRATCH')) as tmp:
                src = Path(tmp) / 'input.cpp'
                src.write_text(code)
                owner, b = F.original('one')
                w = C.A.observe(src, P.AST_ORACLE, budget=b)
                c = C.observe_conditions(src, P.CONDITION_ORACLE, witness=w, budget=b)
                m = P.mapping('one', owner, w, b)
                if code.startswith('typedef'):
                    m['ast_function'] = 1
                    m['parameters'][0]['declaration'] = 2
                with self.assertRaises(C.AlignmentError) as e:
                    S.verify(w, owner, m, conditions=c, budget=b)
                self.assertEqual(e.exception.kind, 'unavailable')

    def test_unknown_attribute_warning_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('SCALAR_SCRATCH')) as tmp:
            src = Path(tmp) / 'input.cpp'
            src.write_text('[[unknown_scalar_attribute]] unsigned value(unsigned x) { return 1u; }')
            owner, b = F.original('one')
            w = C.A.observe(src, P.AST_ORACLE, budget=b)
            c = C.observe_conditions(src, P.CONDITION_ORACLE, witness=w, budget=b)
            self.assertGreater(c.report(budget=b)['warning_count'], 0)
            m = P.mapping('one', owner, w, b)
            with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_COMPILER_WARNINGS_UNAVAILABLE'):
                S.verify(w, owner, m, conditions=c, budget=b)

    def test_pragma_suppression_profile_refused(self):
        codes = [(FIX / 'pragma-suppressed.cpp').read_text(), '/* _Pragma token in comment is conservatively outside profile */ unsigned value(unsigned x) { return 1u; }']
        for code in codes:
            with tempfile.TemporaryDirectory(dir=os.environ.get('SCALAR_SCRATCH')) as tmp:
                src = Path(tmp) / 'input.cpp'
                src.write_text(code)
                owner, b = F.original('one')
                w = C.A.observe(src, P.AST_ORACLE, budget=b)
                with self.assertRaises(C.A.EventError) as e:
                    C.observe_conditions(src, P.CONDITION_ORACLE, witness=w, budget=b)
                self.assertEqual(e.exception.kind, 'unavailable')
                self.assertIn('pragma directives outside finite source profile', e.exception.detail)

    def test_condition_source_and_afterguard(self):
        owner, b, w, c, m = P.inputs('one')
        with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_CONDITION_SOURCE'):
            C.observe_conditions(FIX / 'two.cpp', P.CONDITION_ORACLE, witness=w, budget=b)
        with tempfile.TemporaryDirectory(dir=os.environ.get('SCALAR_SCRATCH')) as tmp:
            src = Path(tmp) / 'input.cpp'
            src.write_bytes((FIX / 'one.cpp').read_bytes())
            actual = C.A.run_native

            def delegate(*args, **kw):
                result = actual(*args, **kw)
                src.write_bytes(src.read_bytes().replace(b'1u', b'2u'))
                return result
            with patch.object(C.A, 'run_native', delegate):
                with self.assertRaisesRegex(C.AlignmentError, 'SCALAR_CONDITION_SOURCE_CHANGED'):
                    C.observe_conditions(src, P.CONDITION_ORACLE, witness=w, budget=b)

    def test_cli_actual_normal_and_optimized(self):
        owner, b, w, c, m = P.inputs('one')
        with tempfile.TemporaryDirectory(dir=os.environ.get('SCALAR_SCRATCH')) as tmp:
            folder = Path(tmp)
            mapping = folder / 'mapping.json'
            budget_file = folder / 'budget.json'
            mapping.write_text(json.dumps(m))
            budget_file.write_text(json.dumps(dict(max_work=10 ** 18, max_edges=10 ** 15, max_copied_bytes=10 ** 18, max_depth=128)))
            outputs = []
            for flags in [[], ['-O']]:
                command = [sys.executable, '-B', *flags, str(HERE / 'scalar_alignment.py'), '--source', str(FIX / 'one.cpp'), '--ast-oracle', str(P.AST_ORACLE), '--condition-oracle', str(P.CONDITION_ORACLE), '--module', str(FIX / 'one.smo'), '--mapping', str(mapping), '--budget', str(budget_file)]
                process = subprocess.run(command, capture_output=True, timeout=60)
                self.assertEqual(process.returncode, 0, process.stderr.decode())
                outputs.append(json.loads(process.stdout))
            self.assertEqual(outputs[0], outputs[1])
            self.assertTrue(outputs[0]['finite_alignment_checked'])
            self.assertFalse(outputs[0]['semantic_admission'])

    def test_zero_quota_before_body(self):
        owner, b, w, c, m = P.inputs('one')
        b.charge(work=b.max_work - b._used_work)
        actual = type(owner).verify_candidate_body
        calls = []

        def delegate(*args, **kw):
            calls.append(1)
            return actual(*args, **kw)
        with patch.object(type(owner), 'verify_candidate_body', delegate):
            with self.assertRaises(Exception):
                S.verify(w, owner, m, conditions=c, budget=b)
        self.assertEqual(calls, [])
if __name__ == '__main__':
    unittest.main(verbosity=2)
