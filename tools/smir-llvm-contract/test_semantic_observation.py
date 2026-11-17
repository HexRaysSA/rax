"""Finite typed native observations: actual compiler, explicit negative graphs."""
from pathlib import Path
import copy, json, os, subprocess, sys, tempfile, unittest
from unittest.mock import patch
import semantic_observation as S
HERE = Path(__file__).resolve().parent
FIX = Path(os.environ.get('CSO_REFERENCE_FIXTURES', str(S.PROJECT / 'docs/specifications/smir/portable/conformance/llvm/semantic-observation')))
ORACLE = Path(os.environ.get('CSO_ORACLE', '/nonexistent/semantic-observation-oracle'))

def budget():
    return S.R.apis()[4].SourceQueryBudget(max_work=10 ** 15, max_edges=10 ** 10, max_copied_bytes=10 ** 15, max_depth=128)

def semantic_nodes(report, kind):
    return [n for f in report['raw']['functions'] for n in f['nodes'] if n['semantic']['kind'] == kind]

def observed(name):
    b = budget()
    w = S.observe(FIX / f'{name}.cpp', ORACLE, budget=b)
    return (w, w.report(budget=b), b)

class Pure(unittest.TestCase):

    def seed(self):
        return json.loads((FIX / 'one.raw.json').read_text())

    def check(self, raw):
        b = budget()
        d, _ = S.schema(b)
        S.R.shape(d['$defs']['raw'], raw, d['$defs'], b)
        S.raw_semantics(raw, (FIX / 'one.cpp').read_bytes(), b)
        S.typed_semantics(raw, b)

    def test_recorded_raw_graph(self):
        self.check(self.seed())

    def test_unissued_constructor_rejected(self):
        b = budget()
        forged = S.ObservationWitness({'source_sha256': '0' * 64, 'raw': {'functions': [{'declaration': 0, 'nodes': [{'fabricated': 777}]}]}}, ledger=b)
        origin = dict(source_sha256='0' * 64, function=0, node=0)
        with self.assertRaisesRegex(S.EventError, 'CSO_ORIGINAL'):
            S.resolve(forged, origin, budget=b)
        with self.assertRaisesRegex(S.EventError, 'CSO_ORIGINAL'):
            forged.report(budget=b)

    def test_public_ledger_class_before_capture(self):
        class Duck:
            def charge(self, **kwargs):
                raise RuntimeError('must reject before caller charge')
        with self.assertRaisesRegex(S.EventError, 'CEW_INPUT'):
            S.match_original({}, FIX / 'one.cpp', ORACLE, budget=Duck())
        with self.assertRaisesRegex(S.EventError, 'CEW_INPUT'):
            S.resolve(None, {}, budget=Duck())
        witness = S.ObservationWitness({}, ledger=Duck())
        with self.assertRaisesRegex(S.EventError, 'CEW_INPUT'):
            witness.report(budget=witness.ledger)

    def test_plain_comparator_charges_and_refuses_unknown(self):
        b = budget()
        self.assertTrue(S.plain_equal({'x': [1, 'abc']}, {'x': [1, 'abc']}, b))
        self.assertFalse(S.plain_equal({'x': [1]}, {'x': [2]}, budget()))
        used = dict(max_work=b._used_work, max_edges=b._used_edges,
                    max_copied_bytes=b._used_copied_bytes, max_depth=128)
        cls = S.R.apis()[4].SourceQueryBudget
        self.assertTrue(S.plain_equal({'x': [1, 'abc']}, {'x': [1, 'abc']}, cls(**used)))
        for key in ('max_work', 'max_edges', 'max_copied_bytes'):
            one_less = dict(used)
            one_less[key] -= 1
            with self.assertRaises(S.R.apis()[4].SourceDataError):
                S.plain_equal({'x': [1, 'abc']}, {'x': [1, 'abc']}, cls(**one_less))


        class Unknown:

            def __eq__(self, other):
                raise RuntimeError('must not run')
        with self.assertRaisesRegex(S.EventError, 'CSO_INPUT'):
            S.plain_equal(Unknown(), Unknown(), budget())
        cls = S.R.apis()[4].SourceQueryBudget
        z = cls(max_work=0, max_edges=0, max_copied_bytes=0, max_depth=128)
        with self.assertRaises(Exception):
            S.plain_equal({'x': ['a' * 1024]}, {'x': ['a' * 1024]}, z)

    def test_missing_operand_rejected(self):
        r = self.seed()
        n = next((n for f in r['functions'] for n in f['nodes'] if n['semantic']['kind'] == 'initializer_list'))
        n['semantic']['operands'] = []
        with self.assertRaisesRegex(S.EventError, 'CSO_OPERAND'):
            self.check(r)

    def test_wrong_role_rejected(self):
        r = self.seed()
        n = next((n for f in r['functions'] for n in f['nodes'] if n['semantic']['kind'] == 'cast'))
        n['semantic']['operands'][0]['role'] = 'base'
        with self.assertRaisesRegex(S.EventError, 'CSO_OPERAND'):
            self.check(r)

    def test_literal_width_and_hex_rejected(self):
        for width, hexval in [(31, '00000001'), (32, '1'), (32, '100000000')]:
            r = self.seed()
            n = next((n for f in r['functions'] for n in f['nodes'] if n['semantic']['kind'] == 'integer_literal'))
            n['semantic']['attributes'].update(apint_width=width, bits_hex=hexval)
            with self.assertRaisesRegex(S.EventError, 'CSO_LITERAL'):
                self.check(r)

    def test_type_namespace_rejected(self):
        r = self.seed()
        r['functions'][0]['nodes'][2]['semantic']['type'] = {'some': 999999}
        with self.assertRaisesRegex(S.EventError, 'CSO_TYPE'):
            self.check(r)

    def test_missing_semantics_and_unknown_field_rejected(self):
        for mode in ['missing', 'extra', 'boolid']:
            r = self.seed()
            n = r['functions'][0]['nodes'][0]
            if mode == 'missing':
                del n['semantic']
            elif mode == 'extra':
                n['semantic']['trusted'] = True
            else:
                n['id'] = True
            with self.assertRaises(S.R.ProjectionError):
                self.check(r)

class Native(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not ORACLE.is_file():
            raise RuntimeError('actual native oracle required; no skip/fallback')

    def test_literal_one_two_differ_beyond_source_hash(self):
        _, one, _ = observed('one')
        _, two, _ = observed('two')
        a = copy.deepcopy(one['raw'])
        b = copy.deepcopy(two['raw'])
        a.pop('source_sha256')
        b.pop('source_sha256')
        self.assertNotEqual(a, b)
        self.assertEqual(semantic_nodes(one, 'integer_literal')[0]['semantic']['attributes'], dict(apint_width=32, bits_hex='00000001'))
        self.assertEqual(semantic_nodes(two, 'integer_literal')[0]['semantic']['attributes'], dict(apint_width=32, bits_hex='00000002'))

    def test_integer_boundaries_cast_operand_order(self):
        _, r, _ = observed('integers')
        l = semantic_nodes(r, 'integer_literal')
        self.assertTrue(any((n['semantic']['attributes'] == dict(apint_width=64, bits_hex='ffffffffffffffff') for n in l)))
        self.assertTrue(any((t['shape'].get('width') == 128 for t in r['raw']['types'])))
        binary = semantic_nodes(r, 'binary')
        self.assertEqual({n['semantic']['attributes']['opcode'] for n in binary}, {'+', '*'})
        for n in binary:
            self.assertEqual([(x['role'], x['index']) for x in n['semantic']['operands']], [('left', 0), ('right', 0)])
        u = semantic_nodes(r, 'unary')
        self.assertEqual(u[0]['semantic']['attributes']['opcode'], '-')

    def test_zero_boolean_void_pointer_boundary(self):
        _, r, _ = observed('boundaries')
        self.assertEqual(semantic_nodes(r, 'boolean_literal')[0]['semantic']['attributes'], {'value': True})
        self.assertEqual(semantic_nodes(r, 'integer_literal')[0]['semantic']['attributes'], {'apint_width': 32, 'bits_hex': '00000000'})
        self.assertTrue(any((t['shape']['kind'] == 'pointer' for t in r['raw']['types'])))
        self.assertTrue(any((t['shape']['kind'] == 'void' for t in r['raw']['types'])))
        f = next((f for f in r['raw']['functions'] if r['raw']['declarations'][f['declaration']]['qualified_name'] == 'empty'))
        ret = next((n for n in f['nodes'] if n['semantic']['kind'] == 'return'))
        self.assertEqual(ret['semantic']['operands'], [{'role': 'value', 'index': 0, 'node': None}])

    def test_actual_constructor_identity_and_argument(self):
        _, r, _ = observed('construct')
        n = semantic_nodes(r, 'construction')[0]
        did = n['semantic']['attributes']['constructor']
        self.assertEqual(r['raw']['declarations'][did]['decl_kind'], 'CXXConstructor')
        self.assertEqual(n['constructor'], {'some': did})
        self.assertEqual(n['semantic']['operands'][0]['role'], 'argument')

    def test_calls_and_record_local_field_identity(self):
        for name, kind in [('calls', 'call'), ('locals', 'member_reference')]:
            _, r, _ = observed(name)
            n = semantic_nodes(r, kind)[0]
            self.assertTrue(n['semantic']['operands'])
            self.assertIsNotNone(n['semantic']['type'])

    def test_original_rerun_accepts_and_literal_tamper_rejects(self):
        _, r, _ = observed('one')
        b = budget()
        w = S.match_original(r, FIX / 'one.cpp', ORACLE, budget=b)
        self.assertEqual(w.report(budget=b), r)
        changed = copy.deepcopy(r)
        semantic_nodes(changed, 'integer_literal')[0]['semantic']['attributes']['bits_hex'] = '00000002'
        with self.assertRaisesRegex(S.EventError, 'CSO_ORIGINAL'):
            S.match_original(changed, FIX / 'one.cpp', ORACLE, budget=budget())

    def test_origin_references_missing_stale_and_ledger(self):
        w, r, b = observed('one')
        origin = dict(source_sha256=r['source_sha256'], function=r['raw']['functions'][0]['declaration'], node=r['raw']['functions'][0]['body'])
        self.assertEqual(S.resolve(w, origin, budget=b)['stmt_class'], 'CompoundStmt')
        for patchrow in [dict(source_sha256='0' * 64), dict(function=999), dict(node=999)]:
            with self.assertRaisesRegex(S.EventError, 'CSO_ORIGIN'):
                S.resolve(w, dict(origin, **patchrow), budget=b)
        with self.assertRaises(S.R.ProjectionError):
            S.resolve(w, dict(source_sha256=r['source_sha256'], function=origin['function']), budget=b)
        with self.assertRaisesRegex(S.EventError, 'CSO_CONTEXT'):
            S.resolve(w, origin, budget=budget())

    def test_copied_or_replaced_witness_is_unissued(self):
        from dataclasses import replace
        w, r, b = observed('one')
        origin = dict(source_sha256=r['source_sha256'], function=r['raw']['functions'][0]['declaration'], node=r['raw']['functions'][0]['body'])
        for other in [copy.copy(w), replace(w), replace(w, data=r)]:
            with self.assertRaisesRegex(S.EventError, 'CSO_ORIGINAL'):
                S.resolve(other, origin, budget=b)
            with self.assertRaisesRegex(S.EventError, 'CSO_ORIGINAL'):
                other.report(budget=b)

    def test_deep_immutable_false_authority(self):
        w, r, b = observed('one')
        with self.assertRaises(TypeError):
            w.data['raw']['types'][0]['shape']['kind'] = 'evil'
        r['raw']['functions'][0]['nodes'][0]['semantic']['kind'] = 'evil'
        self.assertEqual(w.report(budget=b)['raw']['functions'][0]['nodes'][0]['semantic']['kind'], 'compound')
        for key in ['runtime_authority', 'source_fact_authority', 'executable']:
            self.assertIs(w.report(budget=b)[key], False)
        with self.assertRaisesRegex(S.EventError, 'CSO_CONTEXT'):
            w.report(budget=budget())

    def test_zero_quota_before_native(self):
        cls = S.R.apis()[4].SourceQueryBudget
        b = cls(max_work=0, max_edges=0, max_copied_bytes=0, max_depth=128)
        calls = []
        original = S.run_native

        def delegate(*a, **kw):
            calls.append(1)
            return original(*a, **kw)
        with patch.object(S, 'run_native', delegate):
            with self.assertRaises(Exception):
                S.observe(FIX / 'one.cpp', ORACLE, budget=b)
        self.assertEqual(calls, [])

    def test_source_mutation_after_real_native_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('CSO_SCRATCH')) as tmp:
            src = Path(tmp) / 'mutable.cpp'
            src.write_bytes((FIX / 'one.cpp').read_bytes())
            original = S.run_native

            def delegate(*a, **kw):
                result = original(*a, **kw)
                src.write_bytes(src.read_bytes().replace(b'{1}', b'{2}'))
                return result
            with patch.object(S, 'run_native', delegate):
                with self.assertRaisesRegex(S.EventError, 'CEW_PROVENANCE'):
                    S.observe(src, ORACLE, budget=budget())

    def test_reject_unsupported_source_objects(self):
        sources = ['double f(){return 1.;}', 'int f(bool b){if(b)return 1;return 2;}', 'struct X{X():a(1){} int a;};', 'struct X{virtual ~X();};', 'int global=1;', 'int f(){auto q=[](){return 1;};return q();}', 'int f(){return 1/0;}']
        for code in sources[:-1]:
            with tempfile.TemporaryDirectory(dir=os.environ.get('CSO_SCRATCH')) as tmp:
                src = Path(tmp) / 'input.cpp'
                src.write_text(code)
                with self.assertRaises(S.EventError):
                    S.observe(src, ORACLE, budget=budget())

    def test_real_mainbuffer_header_refusal(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('CSO_SCRATCH')) as tmp:
            src = Path(tmp) / 'input.cpp'
            for prefix in ['#include "x.h"\n', '%:include "x.h"\n', '??=include "x.h"\n']:
                src.write_text(prefix + 'int f(){return 1;}')
                with self.assertRaises(S.EventError):
                    S.observe(src, ORACLE, budget=budget())

    def test_cli_actual_normal_and_optimized(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('CSO_SCRATCH')) as tmp:
            path = Path(tmp) / 'budget.json'
            path.write_text(json.dumps(dict(max_work=10 ** 15, max_edges=10 ** 10, max_copied_bytes=10 ** 15, max_depth=128)))
            rows = []
            for flags in [[], ['-O']]:
                command = [sys.executable, '-B', *flags, str(HERE / 'semantic_observation.py'), 'observe', '--source', str(FIX / 'one.cpp'), '--oracle', str(ORACLE), '--budget', str(path)]
                p = subprocess.run(command, capture_output=True, timeout=60)
                self.assertEqual(p.returncode, 0, p.stderr.decode())
                rows.append(json.loads(p.stdout))
            self.assertEqual(rows[0], rows[1])
            self.assertFalse(rows[0]['executable'])
if __name__ == '__main__':
    unittest.main(verbosity=2)
