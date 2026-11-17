"""Pinned pass traces/frame geometry and opaque suspension liveness witnesses."""
import re
import subprocess
import unittest

from coroutine_contract import import_policy, normalize_policy, opaque_suspend_check, promise_offset, required_passes
from test_contract import BIN, FIXTURES


def compile_ir(options=(), source='coroutine-state.cpp'):
    argv = [str(BIN/'clang++'), '-target', 'x86_64-unknown-linux-gnu', '-std=c++23',
            *options, '-S', '-emit-llvm', str(FIXTURES/source), '-o', '-']
    return subprocess.run(argv, text=True, capture_output=True)


class CoroutineCompilerWitnesses(unittest.TestCase):
    def test_native_host_inline_resume_precedes_await_suspend_return(self):
        from coroutine_host import observe
        result=observe(BIN/'clang++',FIXTURES/'coroutine-immediate.cpp')
        self.assertTrue(result['inputs_stable'])
        self.assertEqual(len(result['cases']),2)

    def test_actual_default_o0_o2_full_and_thin_prelink_pass_subsequences(self):
        for options, level, phase in [(['-O0'], 0, 'none'), (['-O2'], 2, 'none'),
                (['-O2','-flto=full'], 2, 'full-pre'), (['-O2','-flto=thin'], 2, 'thin-pre')]:
            with self.subTest(phase=phase, level=level):
                result = compile_ir([*options, '-Xclang', '-fdebug-pass-manager'])
                self.assertEqual(result.returncode, 0, result.stderr)
                passes = re.findall(r'Running pass: (Coro\w+Pass)', result.stderr)
                cursor = 0
                for name in required_passes(level, phase):
                    cursor = passes.index(name, cursor) + 1
                if phase == 'thin-pre':
                    self.assertNotIn('CoroSplitPass', passes)
                    self.assertNotIn('CoroCleanupPass', passes)
                    self.assertIn('presplitcoroutine', result.stdout)
                    self.assertIn('@llvm.coro.suspend', result.stdout)
                else:
                    self.assertNotIn('presplitcoroutine', result.stdout)
                    self.assertNotIn('call i8 @llvm.coro.suspend', result.stdout)

    def test_portable_pointer_sized_header_aligned_promise_and_persistent_proxy(self):
        result = compile_ir(['-O0'])
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout
        self.assertIn('%struct.OwnedProxy = type { ptr }', text)
        self.assertRegex(text, r'define internal void @_Z15coroutine_statei.resume\(ptr[^\n]*align 64 dereferenceable\(128\)')
        self.assertIn('store ptr @_Z15coroutine_statei.resume, ptr', text)
        self.assertRegex(text, r'getelementptr inbounds i8, ptr %\d+, i64 8')
        self.assertRegex(text, r'getelementptr inbounds i8, ptr %\d+, i64 64')
        self.assertRegex(text, r'getelementptr inbounds i8, ptr %\d+, i32 -64')
        for token in ('@current_owner()', '@release_owner(', '@inspect_owner(', '__cxa_end_catch'):
            self.assertIn(token, text)
        self.assertEqual(promise_offset(64), 64)
        self.assertEqual(promise_offset(8), 16)

    def test_explicit_aligned_allocation_option_is_distinct_from_default(self):
        default, aligned = compile_ir(['-O0']), compile_ir(['-O0','-fcoro-aligned-allocation'])
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(aligned.returncode, 0, aligned.stderr)
        self.assertRegex(default.stdout, r'call[^\n]*@_Znwm\(i64 noundef 128\)')
        self.assertRegex(aligned.stdout, r'call[^\n]*@_ZnwmSt11align_val_t\(i64 noundef 128, i64 noundef 64\)')
        self.assertRegex(aligned.stdout, r'call void @_ZdlPvmSt11align_val_t\(ptr[^\n]*i64 noundef 128, i64 noundef 64\)')

    def test_pinned_frontend_rejects_suspend_inside_catch_handler(self):
        result = compile_ir(['-O0', '-DREJECT_CATCH_SUSPEND'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("'co_await' cannot be used in the handler", result.stderr)

    def test_source_va_list_storage_can_live_across_source_suspend(self):
        result=compile_ir(['-O0','-fcoro-aligned-allocation'],'coroutine-va-list.cpp')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('%struct.__va_list_tag = type { i32, i32, ptr, ptr }',result.stdout)
        self.assertIn('@llvm.va_copy.p0(',result.stdout)
        self.assertIn('@llvm.va_end.p0(',result.stdout)
        self.assertRegex(result.stdout,r'define internal void @_Z12copy_va_listP13__va_list_tag.resume\(')

    def test_custom_overload_fallback_matching_delete_and_null_before_header(self):
        for fallback in (False, True):
            result = compile_ir(['-O0', '-fcoro-aligned-allocation',
                                 *(['-DNONALIGNED_FALLBACK'] if fallback else [])],
                                'coroutine-allocation.cpp')
            self.assertEqual(result.returncode, 0, result.stderr)
            body = re.search(r'define[^@]+@_Z15allocation_taskv\(\).*?^}',
                             result.stdout, re.M|re.S).group(0)
            suffix = 'm' if fallback else 'mSt11align_val_t'
            self.assertIn('@_ZN14AllocationTask12promise_typenwE' + suffix + '(', body)
            self.assertIn('@_ZN14AllocationTask12promise_typedlEPv' + suffix + '(', body)
            allocation = body.index('@_ZN14AllocationTask12promise_typenwE')
            null_check = body.index('icmp ne ptr', allocation)
            failure = body.index('get_return_object_on_allocation_failure', null_check)
            header = body.index('store ptr @_Z15allocation_taskv.resume', failure)
            self.assertLess(allocation, null_check)
            self.assertLess(null_check, failure)
            self.assertLess(failure, header)
            if fallback:
                self.assertIn('-Wcoro-non-aligned-allocation-function', result.stderr)
            else:
                self.assertIn('i64 noundef 128, i64 noundef 64)', body)

    def test_partial_aggregate_first_child_completes_before_second_suspend(self):
        result = compile_ir(['-O0', '-fcoro-aligned-allocation', '-Xclang', '-disable-llvm-passes'])
        self.assertEqual(result.returncode, 0, result.stderr)
        body = re.search(r'define[^@]+@_Z24aggregate_across_suspendv\(\).*?^}',
                         result.stdout, re.M|re.S).group(0)
        first = body.index('invoke void @_ZN5GuardC1Ei')
        save = body.index('@llvm.coro.save', first)
        second_await = body.index('__await_suspend_wrapper__await2', first)
        second_suspend = body.index('@llvm.coro.suspend', second_await)
        second = body.index('invoke void @_ZN5GuardC1Ei', first + 1)
        self.assertLess(first, save)
        self.assertLess(save, second_await)
        self.assertLess(second_suspend, second)
        self.assertIn('@_ZN5GuardD1Ev', body)


class OpaqueSuspendLivenessWitnesses(unittest.TestCase):
    def test_dead_exception_can_precede_suspend_owner_pointer_can_survive(self):
        blocks = [dict(id=10, defs=[1,2], uses=[], edges=[dict(target=20,uses=[])], suspend=False),
                  dict(id=20, defs=[], uses=[1], edges=[dict(target=30,uses=[])], suspend=True),
                  dict(id=30, defs=[], uses=[2], edges=[], suspend=False)]
        live = opaque_suspend_check(blocks, {1})
        self.assertEqual(live[30], {2})
        # Type-recursive caller marks aggregate2 as containing E as well.
        with self.assertRaisesRegex(ValueError, 'E-CORO-OPAQUE-SPILL'):
            opaque_suspend_check(blocks, {1,2})

    def test_phi_edge_uses_and_cycles_are_live_across_suspend(self):
        blocks = [dict(id=1, defs=[8], uses=[], edges=[dict(target=2,uses=[8])], suspend=True),
                  dict(id=2, defs=[9], uses=[], edges=[dict(target=2,uses=[9])], suspend=False)]
        with self.assertRaisesRegex(ValueError, 'E-CORO-OPAQUE-SPILL'):
            opaque_suspend_check(blocks, {8})
        blocks[0]['suspend'] = False
        opaque_suspend_check(blocks, {8,9})


class CoroutinePolicyLinkWitnesses(unittest.TestCase):
    def test_identical_full_lto_metadata_operands_deduplicate_by_value(self):
        self.assertEqual(normalize_policy([[1,'switch',True],[1,'switch',True]]), [[1,'switch',True]])
        self.assertEqual(import_policy([[1,'switch',True]], [[1,'switch',True]]), [[1,'switch',True]])

    def test_missing_conflicting_unknown_policy_rejects_before_import(self):
        for invalid in ([], [[1,'switch',False]], [[2,'switch',True]],
                        [[True,'switch',True]], [[1,'switch',1]], [[1,'switch',True,0]]):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'E-CORO-ALLOCATION-POLICY'):
                import_policy([[1,'switch',True]], invalid)
        with self.assertRaisesRegex(ValueError, 'E-CORO-ALLOCATION-POLICY'):
            normalize_policy([[1,'switch',True],[1,'switch',False]])
        with self.assertRaisesRegex(ValueError, 'E-CORO-POLICY-RESOURCE'):
            normalize_policy([[1,'switch',True]] * 65537)
