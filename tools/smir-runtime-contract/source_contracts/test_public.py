"""Public APIs and real child CLI controls, including rejection before owners."""
from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import FrozenInstanceError
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from . import compare, verify, StaticComparison, StaticConstraints, ContractToolError
from . import api, checker as C
from . import __main__ as CLI
from .test_checker import owner, base, scoped, budget, O
from .test_identity import renamed

BUDGET = O / 'explicit-budget.json'
FLAG_KEYS = {'format', 'revision', 'binding', 'source_fact_authority',
             'runtime_authority', 'active_v3_verified'}


def command(args, *, cwd=None, probe=None):
    python = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
    if probe is None:
        python += ['-m', 'source_contracts']
    else:
        python += [str(Path(__file__).with_name('import_probe.py')), probe]
    env = dict(os.environ)
    # Retain a caller-provided audit hook prefix as well as repository discovery.
    env['PYTHONPATH'] = str(C.ROOT / 'tools/smir-runtime-contract') + os.pathsep + env.get('PYTHONPATH', '')
    return subprocess.run(python + [str(a) for a in args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=60)


def verify_args(module='original-pointer', contract='original-pointer', budget_path=BUDGET):
    return ['verify', O / (module + '.smo'), O / (contract + '.source-contract.json'),
            '--budget', budget_path]


class PublicAPI(unittest.TestCase):
    def test_real_original_owner_stamp_and_complete_fields(self):
        o = owner(); ledger = budget(); x = verify(o, scoped(), budget=ledger)
        self.assertIs(type(x), StaticConstraints)
        self.assertIs(x.owner, o)
        self.assertIs(x.stamp, C.RootContext.prepare_source_data(o, budget=ledger))
        self.assertEqual(x.checked_bindings, ((0, 0),))
        self.assertEqual(x.checked_scope_values, ((0, 0), (0, 1), (0, 2), (0, 3)))
        self.assertEqual(x.checked_exits, ((0, 0),))
        self.assertEqual(x.deferred, tuple(sorted(set(x.deferred))))
        for name in ('source_fact_authority', 'runtime_authority', 'active_v3_verified'):
            self.assertIs(getattr(x, name), False)
        self.assertEqual(x.binding, 'unbound')

    def test_real_comparison_retains_both_original_owners_and_closure(self):
        a, b = owner(), owner(); ledger = budget(); d = scoped()
        x = compare(a, d, b, renamed(d), 0, budget=ledger)
        self.assertIs(type(x), StaticComparison); self.assertIs(x.result, True)
        self.assertIs(x.left.owner, a); self.assertIs(x.right.owner, b)
        self.assertEqual(x.functions, (0,)); self.assertEqual(x.function, 0)
        self.assertIs(x.left.stamp, C.RootContext.prepare_source_data(a, budget=ledger))
        self.assertIs(x.right.stamp, C.RootContext.prepare_source_data(b, budget=ledger))
        self.assertEqual(x.deferred, tuple(sorted(set(x.left.deferred) | set(x.right.deferred) |
                                                {'SCV_COMPARISON_FINITE_SUBSET'})))

    def test_false_comparison_is_definite_static_mismatch(self):
        x = compare(owner(), base(), owner(), scoped(), 0, budget=budget())
        self.assertIs(x.result, False); self.assertFalse(x.runtime_authority)

    def test_frozen_false_fields_cannot_be_constructor_overrides(self):
        x = compare(owner(), base(), owner(), base(), 0, budget=budget())
        for field in ('binding', 'runtime_authority', 'source_fact_authority', 'active_v3_verified'):
            with self.assertRaises(FrozenInstanceError):
                setattr(x, field, True)
            with self.assertRaises(TypeError):
                StaticComparison(True, 0, (), x.left, x.right, (), **{field: True})

    def test_reports_and_callbacks_cannot_replace_real_owner_or_budget(self):
        for bad in (None, {}, lambda: owner()):
            with self.assertRaises(C.ConstraintError):
                verify(bad, base(), budget=budget())
        for bad in (None, {}, lambda: budget()):
            with self.assertRaises(C.ConstraintError):
                verify(owner(), base(), budget=bad)

    def test_function_requires_exact_nonsentinel_u32(self):
        for bad in (True, -1, 2**32 - 1, '0', None):
            with self.assertRaises(ContractToolError) as e:
                compare(owner(), base(), owner(), base(), bad, budget=budget())
            self.assertEqual(e.exception.code, 'SCV_FUNCTION')

    def test_report_closed_schema_and_no_private_handles(self):
        ledger = budget(); x = compare(owner(), base(), owner(), scoped(), 0, budget=ledger)
        report = api.report(x, budget=ledger)
        self.assertEqual(set(report), FLAG_KEYS | {'status', 'result', 'function', 'functions',
                                                 'left', 'right', 'deferred'})
        schema = json.loads(C.SCHEMA.read_bytes())
        C.shape(schema['$defs']['comparison_report'], report, schema['$defs'], ledger)
        self.assertEqual([row['section'] for row in report['left']['source']['roots']], list(range(1, 11)))
        self.assertNotIn('owner', json.dumps(report)); self.assertNotIn('context_anchor', json.dumps(report))

    def test_comparison_shares_one_ledger_and_refuses_last_charge(self):
        ledger = budget(); compare(owner(), base(), owner(), base(), 0, budget=ledger)
        with self.assertRaises(C.source_api().SourceDataError) as e:
            compare(owner(), base(), owner(), base(), 0,
                    budget=budget(max_work=ledger._used_work - 1))
        self.assertEqual(e.exception.kind, 'resource')


class PublicCLI(unittest.TestCase):
    def check(self, result, code, kind=None):
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(len(result.stdout.splitlines()), 1)
        output = json.loads(result.stdout)
        self.assertEqual(output['binding'], 'unbound')
        for name in ('source_fact_authority', 'runtime_authority', 'active_v3_verified'):
            self.assertIs(output[name], False)
        if kind is not None:
            self.assertEqual(output['class'], kind)
            self.assertEqual(set(output), FLAG_KEYS | {'status', 'class', 'code', 'detail'})
            self.assertLessEqual(len(output['detail'].encode()), 4096)
        schema = json.loads(C.SCHEMA.read_bytes())
        C.shape(schema['$defs']['report'], output, schema['$defs'], budget())
        return output

    def test_real_verify_from_nonrepository_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.check(command(verify_args(), cwd=directory), 0)
        self.assertEqual(output['status'], 'conditional-static-constraints')
        self.assertEqual(set(output), FLAG_KEYS | {'status', 'source', 'checked', 'deferred'})
        self.assertEqual(output['checked']['bindings'], [{'function': 0, 'id': 0}])

    def test_real_compare_true_and_false_distinct_exits(self):
        common = ['compare', O / 'original-pointer.smo', O / 'original-pointer.source-contract.json',
                  O / 'original-pointer.smo']
        yes = common + [O / 'original-pointer.source-contract.json', '--function', '0', '--budget', BUDGET]
        no = common + [O / 'original-pointer-scoped.source-contract.json', '--function', '0', '--budget', BUDGET]
        self.assertIs(self.check(command(yes), 0)['result'], True)
        self.assertIs(self.check(command(no), 1)['result'], False)

    def test_actual_semantic_rejection_preserves_original_code(self):
        result = self.check(command(verify_args('missing-all-adoptions', 'missing-all-adoptions')), 2, 'semantic')
        self.assertEqual(result['code'], 'ASC_ADOPTION_COMPLETE_SET')
        result = self.check(command(verify_args('negative-definition-digest', 'negative-definition-digest')), 2, 'semantic')
        self.assertEqual(result['code'], 'ABI_CC_DEFINITION_HASH')

    def test_valid_original_wide_module_is_explicitly_unavailable(self):
        from codec import CandidateCodec
        from .test_factory import SCHEMAS
        roots = owner().sections
        roots[1]['types'].extend(dict(id=10000 + n, kind='int', bits=32) for n in range(65))
        actual = C.RootContext(roots); actual.verify_abi(); actual.verify_execution()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wide.smo'; path.write_bytes(CandidateCodec(SCHEMAS).encode(roots))
            args = verify_args(); args[1] = path
            result = self.check(command(args), 3, 'unavailable')
        self.assertEqual(result['code'], 'ASC_ORIGINAL_FACTORY_PROFILE')

    def test_valid_multiple_normal_returns_keep_unavailable_code_and_exit(self):
        from .test_factory import SCHEMAS
        from codec import CandidateCodec
        raw = (O / 'valid-two-normal-returns.smo').read_bytes()
        o = C.RootContext(CandidateCodec(SCHEMAS).decode(raw).roots)
        o.verify_abi(); o.verify_execution()
        document = json.loads((O / 'valid-two-normal-returns.source-contract.json').read_bytes())
        with self.assertRaises(C.ConstraintError) as e:
            verify(o, document, budget=budget())
        self.assertEqual(e.exception.code, 'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS')
        result = self.check(command(verify_args('valid-two-normal-returns', 'valid-two-normal-returns')),
                            3, 'unavailable')
        self.assertEqual(result['code'], 'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS')

    def test_exact_unavailable_constraint_catalog_preserves_semantic_errors(self):
        for code in CLI.UNAVAILABLE_CONSTRAINTS:
            output, result = CLI.diagnostic(C.ConstraintError(code))
            self.assertEqual(result, 3); self.assertEqual(output['class'], 'unavailable')
            self.assertEqual(output['code'], code)
        for code in ('ASC_RETURN_SCOPE_EXIT', 'ASC_ADOPTION_COMPLETE_SET',
                     'ASC_SCOPE_JOURNAL_PROGRAM', 'ASC_STATIC_POINTEE'):
            output, result = CLI.diagnostic(C.ConstraintError(code))
            self.assertEqual(result, 2); self.assertEqual(output['class'], 'semantic')
            self.assertEqual(output['code'], code)

    def check_retained_call_rejection(self, name, expected):
        from codec import CandidateCodec
        from .test_factory import SCHEMAS
        raw = (O / (name + '.smo')).read_bytes()
        original = C.RootContext(CandidateCodec(SCHEMAS).decode(raw).roots)
        original.verify_abi(); original.verify_execution()
        document = json.loads((O / (name + '.source-contract.json')).read_bytes())
        with self.assertRaises(C.ConstraintError) as error:
            verify(original, document, budget=budget())
        self.assertEqual(error.exception.code, expected)
        output = self.check(command(verify_args(name, name)), 2, 'semantic')
        self.assertEqual(output['code'], expected)

    def test_retained_call_requires_actual_return_row(self):
        self.check_retained_call_rejection('retained-call-missing-return', 'ASC_REFERENCE')

    def test_retained_call_requires_retained_disposition(self):
        self.check_retained_call_rejection('retained-call-terminal-disposition', 'ASC_RETURN_RETAINED_OUTCOME')

    def test_retained_call_requires_reciprocal_exit_id(self):
        self.check_retained_call_rejection('retained-call-wrong-exit', 'ASC_RETURN_RETAINED_OUTCOME')

    def test_retained_call_requires_physical_return_boundary(self):
        self.check_retained_call_rejection('retained-call-early-boundary', 'ASC_RETURN_BOUNDARY')

    def test_terminal_row_cannot_alias_another_retained_call_return(self):
        self.check_retained_call_rejection('retained-call-extra-terminal-row', 'ASC_RETURN_RETAINED_OUTCOME')

    def test_declared_scope_parent_reference_must_exist(self):
        self.check_retained_call_rejection('scope-within-undefined-parent', 'ASC_REFERENCE')

    def test_declared_scope_context_must_equal_defining_phase(self):
        self.check_retained_call_rejection('scope-within-mismatched-context', 'ASC_SCOPE_ENTER_WITHIN')

    def test_scope_cannot_parent_its_own_enter_value(self):
        self.check_retained_call_rejection('scope-within-self-parent', 'ASC_SCOPE_VALUE_DOMINANCE')

    def test_scope_cannot_use_later_same_site_parent(self):
        self.check_retained_call_rejection('scope-within-later-same-site', 'ASC_SCOPE_VALUE_DOMINANCE')

    def test_declared_scope_parent_guard_must_match(self):
        self.check_retained_call_rejection('scope-within-incompatible-guard', 'ASC_GUARDED_VALUE_SELECTOR')

    def check_scope_parent_positive(self, name):
        from codec import CandidateCodec
        from .test_factory import SCHEMAS
        original = C.RootContext(CandidateCodec(SCHEMAS).decode((O / (name + '.smo')).read_bytes()).roots)
        original.verify_abi(); original.verify_execution()
        document = json.loads((O / (name + '.source-contract.json')).read_bytes())
        value = verify(original, document, budget=budget())
        self.assertIs(value.owner, original)
        self.assertIn('ASC_FULL_SCOPE_PATH_COVERAGE_NOT_IMPLEMENTED', value.deferred)
        self.assertFalse(value.runtime_authority)
        self.check(command(verify_args(name, name)), 0)

    def test_live_matching_declared_parent_remains_conditional(self):
        self.check_scope_parent_positive('scope-within-live-parent')

    def test_earlier_same_site_parent_is_valid(self):
        self.check_scope_parent_positive('scope-within-earlier-same-site')

    def test_matching_stale_parent_remains_explicit_dynamic_obligation(self):
        # Static SSA custody is represented; dynamic freshness is a separate proof.
        self.check_scope_parent_positive('scope-within-matching-stale-parent')

    def test_zero_policy_is_resource_without_partial_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.json'
            policy = json.loads(BUDGET.read_bytes()); policy['max_work'] = 0
            path.write_text(json.dumps(policy))
            result = self.check(command(verify_args(budget_path=path)), 4, 'resource')
        self.assertEqual(result['code'], 'SOURCE_DATA_RESOURCE')

    def test_duplicate_options_unknown_options_and_missing_budget(self):
        for args in (verify_args() + ['--budget', BUDGET], verify_args() + ['--native'],
                     verify_args()[:-2], verify_args() + ['--function', '0']):
            self.check(command(args), 2, 'input')

    def test_compare_function_syntax_and_long_leading_zero(self):
        args = ['compare', O / 'original-pointer.smo', O / 'original-pointer.source-contract.json',
                O / 'original-pointer.smo', O / 'original-pointer.source-contract.json',
                '--budget', BUDGET, '--function']
        for value in ('-1', '0x0', 'true', '4294967295', ' 0', '+0'):
            self.check(command(args + [value]), 2, 'input')
        self.check(command(args + ['0' * 100]), 0)

    def test_budget_bootstrap_rejects_before_any_owner_or_ledger(self):
        invalid = [b'{"max_work":1,"max_work":2}', b'[]', b'{"max_work":true}',
                   b'\xff', b'{', b'{"max_work":18446744073709551616}',
                   b'{"max_work":' + b'[' * 10 + b'0' + b']' * 10 + b'}',
                   b'{"max_work":NaN}', b' ' * 4097]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.json'
            for raw in invalid:
                path.write_bytes(raw)
                with patch.object(C.RootContext, '__init__', side_effect=AssertionError('owner created')), \
                     patch.object(C.source_api().SourceQueryBudget, '__init__', side_effect=AssertionError('ledger created')):
                    with self.assertRaises(ContractToolError):
                        CLI.bootstrap(path)
                self.check(command(verify_args(budget_path=path)), 2, 'input')

    def test_schema_depth_is_checked_before_import_time_json_parsing(self):
        ledger = budget(max_depth=1)
        with patch.object(json, 'loads', side_effect=AssertionError('schema parsed before depth check')):
            with self.assertRaises(ContractToolError) as e:
                CLI.precharge_schemas(ledger)
        self.assertEqual(e.exception.kind, 'resource')
        self.assertEqual(e.exception.code, 'SCV_JSON_DEPTH')

    def test_budget_closed_shape_exact_counts_and_depth(self):
        policy = json.loads(BUDGET.read_bytes())
        invalid = []
        for key in policy:
            d = dict(policy); del d[key]; invalid.append(d)
        for key, value in [('extra', 1), ('max_work', True), ('max_edges', -1),
                           ('max_copied_bytes', 2**64), ('max_depth', 0), ('max_depth', 129)]:
            d = dict(policy); d[key] = value; invalid.append(d)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.json'
            for d in invalid:
                path.write_text(json.dumps(d))
                with self.assertRaises(ContractToolError): CLI.bootstrap(path)

    def test_contract_duplicate_keys_utf8_float_integer_and_depth_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'contract.json'
            cases = [(b'{"x":1,"x":2}', 2), (b'\xff', 2), (b'{"x":1.5}', 2),
                     (b'{"x":18446744073709551616}', 2), (b'"\\ud800"', 2),
                     (b'[' * 65 + b'0' + b']' * 65, 4)]
            for raw, code in cases:
                path.write_bytes(raw); args = verify_args(); args[2] = path
                self.check(command(args), code, 'resource' if code == 4 else 'input')

    def test_file_bounds_and_invalid_envelope_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'module.smo'; path.write_bytes(b'not SMIR')
            args = verify_args(); args[1] = path
            self.check(command(args), 2, 'input')
            with path.open('wb') as stream: stream.truncate(16 * 1024 * 1024 + 1)
            self.assertEqual(self.check(command(args), 2, 'input')['code'], 'SCV_INPUT_BOUND')

    def test_actual_import_conflicts_are_closed_input_errors(self):
        for name in ('candidate', 'candidate.context', 'common', 'codec', 'layout', 'nominal', '_rax_smir_source_data_v1'):
            output = self.check(command(verify_args(), probe=name), 2, 'input')
            self.assertEqual(output['code'], 'SCV_IMPORT_CONTEXT')

    def test_help_normal_text_exit_zero(self):
        for args in (['--help'], ['verify', '--help'], ['compare', '--help']):
            result = command(args); self.assertEqual(result.returncode, 0)
            self.assertIn('usage:', result.stdout); self.assertEqual(result.stderr, '')

    def test_internal_error_is_70_and_multibyte_detail_is_bounded(self):
        out = io.StringIO()
        with patch.object(CLI, 'execute', side_effect=RuntimeError('unexpected')), redirect_stdout(out):
            result = CLI.main(verify_args())
        self.assertEqual(result, 70); self.assertEqual(json.loads(out.getvalue())['code'], 'SCV_INTERNAL')
        report, code = CLI.diagnostic(ContractToolError('input', 'SCV_IO', '界' * 3000))
        self.assertEqual(code, 2); self.assertLessEqual(len(report['detail'].encode()), 4096)

    def test_mutation_during_bounded_read_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'; path.write_bytes(b'{}')
            original = Path.open
            def mutate(p, *args, **kwargs):
                result = original(p, *args, **kwargs)
                if p == path:
                    with original(p, 'ab') as writer: writer.write(b' ')
                return result
            with patch.object(Path, 'open', mutate):
                with self.assertRaises(ContractToolError) as e:
                    CLI.read_file(path, 4096, budget())
            self.assertEqual(e.exception.code, 'SCV_INPUT_CHANGED')

    def test_schema_and_fixture_checks_do_not_write_products(self):
        from . import fixtures, schema
        paths = list(O.iterdir()) + [C.SCHEMA]
        before = {p: p.read_bytes() for p in paths if p.is_file()}
        with redirect_stdout(io.StringIO()): fixtures.main(['--check'])
        self.assertEqual(C.SCHEMA.read_bytes(), schema.raw)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
