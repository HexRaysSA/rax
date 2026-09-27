//! SDK-derived mode, TLS, fatal-handler and software-signal distinctions.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::crt::tests::{int, invoke, run, void};
use crate::user::windows::heap::HeapError;
use crate::user::windows::hle::{Cont, Value};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::Mem;
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::nt::status::STATUS_STACK_BUFFER_OVERRUN;

const UCRT: RuntimeKind = RuntimeKind::Ucrt;

fn scope(c: &mut Ctx, result: ApiResult, code: Option<u32>) -> ApiResult {
    let Flow::Protected {
        code: got, then, ..
    } = result.unwrap()
    else {
        panic!("owned exception scope")
    };
    assert_eq!(got, code);
    then(c, 0)
}

fn cleanup(c: &mut Ctx, name: &str, args: &[u64]) -> ApiResult {
    let result = invoke(c, UCRT, name, args);
    scope(c, result, Some(0xE06D_7363))
}

fn callback(result: ApiResult, expected: u64, expected_args: &[u64]) -> Cont {
    let Flow::CallChecked { target, args, then } = result.unwrap() else {
        panic!("retained checked callback")
    };
    assert_eq!(target, expected);
    assert_eq!(args, expected_args);
    then
}

fn add(c: &mut Ctx, name: &str, target: u64) {
    assert_eq!(int(invoke(c, UCRT, name, &[target])), 0);
}

fn pending(c: &mut Ctx, kind: Kind) -> Vec<u64> {
    let queues = c.p.crt.runtimes[UCRT.index()].termination.clone();
    let mut drain = queues.begin(kind, c.t.tid).unwrap();
    let mut targets = Vec::new();
    while let Some(target) = drain.next(c.p).unwrap() {
        targets.push(target);
    }
    drain.finish(c.p).unwrap();
    targets
}

#[test]
fn dynamic_termination_named_exports_are_ucrt_only_all_abis() {
    run(|c| {
        for dll in [
            "ucrtbase.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "msvcrt.dll",
        ] {
            let module = loader::load_dll(c.p, dll).unwrap();
            for export in UCRT_EXIT_EXPORTS
                .iter()
                .chain(UCRT_FATAL_EXPORTS)
                .chain(UCRT_SIGNAL_EXPORTS)
            {
                let target = loader::lookup(
                    c.p,
                    module,
                    &SymRef::Name(export.name.as_bytes().to_vec(), None),
                )
                .unwrap();
                assert_eq!(
                    target.is_some(),
                    dll != "msvcrt.dll",
                    "{dll}!{}",
                    export.name
                );
            }
            assert!(
                loader::lookup(
                    c.p,
                    module,
                    &SymRef::Name(b"_is_c_termination_complete".to_vec(), None)
                )
                .unwrap()
                .is_none()
            );
        }
    });
}

#[test]
fn returning_full_tls_precedes_live_lifo_queue_and_repeats_all_abis() {
    run(|c| {
        void(invoke(
            c,
            UCRT,
            "_register_thread_local_exe_atexit_callback",
            &[0x1100],
        ));
        add(c, "_crt_atexit", 0x2200);
        add(c, "_crt_at_quick_exit", 0x6600);
        assert!(!c.p.crt.runtimes[UCRT.index()].exit.entered);
        let tls = callback(cleanup(c, "_cexit", &[]), 0x1100, &[0, 0, 0]);
        assert!(c.p.crt.runtimes[UCRT.index()].exit.entered);
        assert!(!c.p.crt.runtimes[UCRT.index()].exit.completed);
        add(c, "_crt_atexit", 0x3300);
        let a = callback(tls(c, 0), 0x3300, &[]);
        add(c, "_crt_atexit", 0x4400);
        let b = callback(a(c, u64::MAX), 0x4400, &[]);
        let old = callback(b(c, 0), 0x2200, &[]);
        void(old(c, 0));
        assert_eq!(pending(c, Kind::Quick), [0x6600]);
        add(c, "_crt_atexit", 0x5500);
        let tls = callback(cleanup(c, "_cexit", &[]), 0x1100, &[0, 0, 0]);
        let last = callback(tls(c, 0), 0x5500, &[]);
        void(last(c, 0));
        assert_eq!(c.p.crt.runtimes[UCRT.index()].exit.tls_callback, 0x1100);
        assert!(!c.p.crt.runtimes[UCRT.index()].exit.completed);
    });
}

#[test]
fn full_exit_marks_completion_after_callbacks_and_releases_guard_all_abis() {
    run(|c| {
        add(c, "_crt_atexit", 0x1100);
        add(c, "_crt_at_quick_exit", 0x2200);
        let then = callback(cleanup(c, "exit", &[0xFFFF_FFED]), 0x1100, &[]);
        assert!(!c.p.crt.runtimes[UCRT.index()].exit.completed);
        // Formals, API origin and calling convention may all change while a
        // guest callback runs; the request's exact 32-bit status is retained.
        int(invoke(c, RuntimeKind::Msvcrt, "_errno", &[]));
        assert!(matches!(
            then(c, 0).unwrap(),
            Flow::ExitProcess(0xFFFF_FFED)
        ));
        assert!(c.p.crt.runtimes[UCRT.index()].exit.completed);
        let tid = c.t.tid;
        c.t.tid += 1;
        add(c, "_crt_atexit", 0x3300); // no held terminal invocation guard
        c.t.tid = tid;
        void(invoke(c, UCRT, "_cexit", &[])); // completed skips protected work
        assert_eq!(pending(c, Kind::Ordinary), [0x3300]);
        assert_eq!(pending(c, Kind::Quick), [0x2200]);
    });
}

#[test]
fn quick_exit_drains_only_quick_without_tls_all_abis() {
    run(|c| {
        void(invoke(
            c,
            UCRT,
            "_register_thread_local_exe_atexit_callback",
            &[0x1100],
        ));
        add(c, "_crt_atexit", 0x2200);
        add(c, "_crt_at_quick_exit", 0x3300);
        let then = callback(cleanup(c, "quick_exit", &[0x8000_0042]), 0x3300, &[]);
        assert!(matches!(
            then(c, 0).unwrap(),
            Flow::ExitProcess(0x8000_0042)
        ));
        assert_eq!(pending(c, Kind::Ordinary), [0x2200]);
        assert_eq!(c.p.crt.runtimes[UCRT.index()].exit.tls_callback, 0x1100);
    });
}

#[test]
fn minimal_modes_skip_both_queues_tls_and_returning_completion_all_abis() {
    for name in ["_exit", "_Exit", "_c_exit"] {
        run(|c| {
            void(invoke(
                c,
                UCRT,
                "_register_thread_local_exe_atexit_callback",
                &[0x1100],
            ));
            add(c, "_crt_atexit", 0x2200);
            add(c, "_crt_at_quick_exit", 0x3300);
            let returns = name == "_c_exit";
            let args = if returns { &[][..] } else { &[0xFFFF_FFFF][..] };
            let result = cleanup(c, name, args);
            if returns {
                void(result)
            } else {
                assert!(matches!(result.unwrap(), Flow::ExitProcess(u32::MAX)))
            };
            assert!(c.p.crt.runtimes[UCRT.index()].exit.entered);
            assert_eq!(c.p.crt.runtimes[UCRT.index()].exit.completed, !returns);
            assert_eq!(pending(c, Kind::Ordinary), [0x2200]);
            assert_eq!(pending(c, Kind::Quick), [0x3300]);
        });
    }
}

#[test]
fn returning_cleanup_is_recursively_enterable_not_suppressed_all_abis() {
    run(|c| {
        add(c, "_crt_atexit", 0x1100);
        let outer = callback(cleanup(c, "_cexit", &[]), 0x1100, &[]);
        add(c, "_crt_atexit", 0x2200);
        let nested = callback(cleanup(c, "_cexit", &[]), 0x2200, &[]);
        void(nested(c, 0));
        void(outer(c, 0)); // ownership-safe nested reset profile
        assert!(!c.p.crt.runtimes[UCRT.index()].exit.completed);
        assert!(pending(c, Kind::Ordinary).is_empty());
    });
}

#[test]
fn tls_null_registration_is_available_then_any_duplicate_terminates_all_abis() {
    for duplicate in [0, 0x1100, 0x2200] {
        run(|c| {
            for _ in 0..2 {
                void(invoke(
                    c,
                    UCRT,
                    "_register_thread_local_exe_atexit_callback",
                    &[0],
                ));
            }
            void(invoke(
                c,
                UCRT,
                "_register_thread_local_exe_atexit_callback",
                &[0x1100],
            ));
            assert!(matches!(
                invoke(
                    c,
                    UCRT,
                    "_register_thread_local_exe_atexit_callback",
                    &[duplicate]
                )
                .unwrap(),
                Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
            ));
            assert_eq!(c.p.crt.runtimes[UCRT.index()].exit.tls_callback, 0x1100);
        });
    }
}

#[test]
fn duplicate_tls_runs_calling_threads_custom_terminate_handler_all_abis() {
    run(|c| {
        let default = int(invoke(c, UCRT, "_get_terminate", &[]));
        assert_ne!(default, 0);
        assert_eq!(int(invoke(c, UCRT, "set_terminate", &[0x2200])), default);
        void(invoke(
            c,
            UCRT,
            "_register_thread_local_exe_atexit_callback",
            &[0x1100],
        ));
        let result = invoke(c, UCRT, "_register_thread_local_exe_atexit_callback", &[0]);
        let result = scope(c, result, None);
        let then = callback(result, 0x2200, &[]);
        assert!(matches!(
            then(c, 0).unwrap(),
            Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
        ));
        let tid = c.t.tid;
        c.t.tid += 1;
        assert_eq!(int(invoke(c, UCRT, "_get_terminate", &[])), default);
        c.t.tid = tid;
        assert_eq!(int(invoke(c, UCRT, "set_terminate", &[0])), 0x2200);
        assert_eq!(int(invoke(c, UCRT, "_get_terminate", &[])), default);
    });
}

#[test]
fn tls_executes_on_exit_caller_not_main_thread_all_abis() {
    run(|c| {
        void(invoke(
            c,
            UCRT,
            "_register_thread_local_exe_atexit_callback",
            &[0x1100],
        ));
        let main = c.t.tid;
        c.t.tid += 1;
        let worker = c.t.tid;
        let then = callback(cleanup(c, "_cexit", &[]), 0x1100, &[0, 0, 0]);
        assert_eq!(c.t.tid, worker);
        void(then(c, 0));
        c.t.tid = main;
    });
}

#[test]
fn abort_behavior_masks_are_32_bit_and_disabled_reportfault_uses_normal_exit_all_abis() {
    run(|c| {
        assert_eq!(
            int(invoke(
                c,
                UCRT,
                "_set_abort_behavior",
                &[0xDEAD_BEEF, 0xFFFF_FFFF]
            )),
            2
        );
        assert_eq!(
            int(invoke(c, UCRT, "_set_abort_behavior", &[0, 2])),
            0xDEAD_BEEF
        );
        assert_eq!(
            c.p.crt.runtimes[UCRT.index()].exit.abort_behavior,
            0xDEAD_BEED
        );
        let result = invoke(c, UCRT, "abort", &[]);
        let result = scope(c, result, Some(0xE06D_7363));
        assert!(matches!(result.unwrap(), Flow::ExitProcess(3)));
        assert_eq!(
            int(invoke(c, UCRT, "_set_abort_behavior", &[2, 2])),
            0xDEAD_BEED
        );
        assert!(matches!(
            invoke(c, UCRT, "abort", &[]).unwrap(),
            Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
        ));
    });
}

#[test]
fn software_signal_alias_query_reset_and_abort_continuation_all_abis() {
    run(|c| {
        assert_eq!(int(invoke(c, UCRT, "signal", &[6, 0x1100])), 0);
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 2])), 0x1100);
        let then = callback(invoke(c, UCRT, "raise", &[6]), 0x1100, &[6]);
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 2])), 0);
        assert_eq!(int(then(c, 0)), 0);
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 0x2200])), 0);
        let then = callback(invoke(c, UCRT, "abort", &[]), 0x2200, &[22]);
        assert_eq!(int(invoke(c, UCRT, "signal", &[6, 2])), 0);
        // Handler changes are observed after it returns, not a stale abort
        // behavior captured before the signal invocation.
        assert_eq!(int(invoke(c, UCRT, "_set_abort_behavior", &[0, 2])), 2);
        let result = then(c, 0);
        let result = scope(c, result, Some(0xE06D_7363));
        assert!(matches!(result.unwrap(), Flow::ExitProcess(3)));
    });
}

#[test]
fn software_signal_ignore_default_term_and_invalid_paths_all_abis() {
    run(|c| {
        assert_eq!(int(invoke(c, UCRT, "signal", &[15, 1])), 0);
        assert_eq!(int(invoke(c, UCRT, "raise", &[15])), 0);
        assert_eq!(int(invoke(c, UCRT, "signal", &[15, 2])), 1);
        assert_eq!(int(invoke(c, UCRT, "signal", &[15, 0])), 1);
        let result = invoke(c, UCRT, "raise", &[15]);
        let result = scope(c, result, Some(0xE06D_7363));
        assert!(matches!(result.unwrap(), Flow::ExitProcess(3)));
        let cells = int(invoke(c, UCRT, "_errno", &[]));
        for number in [1, 3, 13, 16, 17] {
            c.mem().w32(cells, 123).unwrap();
            assert_eq!(
                int(invoke(c, UCRT, "signal", &[number, 0])),
                c.arch().ptr(u64::MAX)
            );
            assert_eq!(c.mem().u32(cells).unwrap(), 123);
        }
        assert_eq!(
            int(invoke(c, UCRT, "signal", &[999, 0])),
            c.arch().ptr(u64::MAX)
        );
        assert_eq!(c.mem().u32(cells).unwrap(), 22);
        for number in [2, 4, 8, 11, 21] {
            assert!(matches!(
                invoke(c, UCRT, "signal", &[number, 0x1100]),
                Err(ApiErr::Unimplemented(_))
            ));
            assert!(matches!(
                invoke(c, UCRT, "raise", &[number]),
                Err(ApiErr::Unimplemented(_))
            ));
        }
        assert!(matches!(
            invoke(c, UCRT, "raise", &[999]).unwrap(),
            Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
        ));
        int(invoke(c, UCRT, "_set_invalid_parameter_handler", &[0x3300]));
        let result = invoke(c, UCRT, "raise", &[999]).unwrap();
        let Flow::CallChecked { target, args, then } = result else {
            panic!("invalid handler")
        };
        assert_eq!(target, 0x3300);
        assert_eq!(args, [0; 5]);
        assert!(
            matches!(then(c, 0).unwrap(), Flow::Ret(Value::Int(v)) if v == u64::from(u32::MAX))
        );
        assert_eq!(c.mem().u32(cells).unwrap(), 22);
    });
}

#[test]
fn exit_selected_slot_fault_keeps_target_status_and_recursive_lock_all_abis() {
    run(|c| {
        let heap = state::ensure_heap(c, UCRT).unwrap();
        let before = c.p.heaps.blocks(heap);
        add(c, "_crt_atexit", 0x1100);
        let base =
            c.p.heaps
                .blocks(heap)
                .into_iter()
                .find(|block| !before.contains(block))
                .unwrap()
                .0;
        let page = base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let result = cleanup(c, "exit", &[37]);
        let Flow::RetryFault { fault, retry } = result.unwrap() else {
            panic!("slot clear fault")
        };
        assert!(fault.write);
        assert_eq!(fault.addr, base);
        assert!(!c.p.crt.runtimes[UCRT.index()].exit.completed);
        let tid = c.t.tid;
        c.t.tid += 1;
        let blocked = invoke(c, UCRT, "_crt_atexit", &[0x4400]).unwrap();
        assert!(matches!(blocked, Flow::Block { .. }));
        drop(blocked);
        c.t.tid = tid;
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.mem().wptr(base, c.psize(), 0x2200).unwrap();
        c.mem().w32(c.entry_sp + 4, 99).unwrap();
        for register in 0..9 {
            c.t.cpu.set_gpr(register, 99);
        }
        let then = callback(retry(c, 0), 0x1100, &[]);
        assert!(matches!(then(c, 0).unwrap(), Flow::ExitProcess(37)));
        assert!(pending(c, Kind::Ordinary).is_empty());
    });
}

#[test]
fn x86_later_signal_and_abort_formal_fault_retains_first_decoded_argument() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        for (name, first, second) in [("signal", 22, 0x1100), ("_set_abort_behavior", 0, 2)] {
            let (base, _) =
                c.p.vm
                    .allocate(
                        None,
                        2 * PAGE_SIZE,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )
                    .unwrap();
            let sp = base + PAGE_SIZE - 8;
            let old_sp = c.entry_sp;
            c.entry_sp = sp;
            let module = c.p.modules.by_name("ucrtbase.dll").unwrap();
            c.entry_pc = loader::lookup(c.p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                .unwrap()
                .unwrap();
            c.api = crate::user::windows::dll::crt::tests::api(name);
            c.mem().w32(sp + 4, first).unwrap();
            c.mem().w32(sp + 8, second).unwrap();
            c.p.vm
                .protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let Flow::RetryFault { fault, retry } = (c.api.imp)(c).unwrap() else {
                panic!("second formal fault")
            };
            assert_eq!(fault.addr, base + PAGE_SIZE);
            assert!(!fault.write);
            c.mem().w32(sp + 4, 15).unwrap();
            c.p.vm
                .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
                .unwrap();
            assert_eq!(int(retry(c, 0)), if name == "signal" { 0 } else { 2 });
            if name == "signal" {
                assert_eq!(c.p.crt.runtimes[UCRT.index()].signals, [0x1100, 0]);
            } else {
                assert_eq!(c.p.crt.runtimes[UCRT.index()].exit.abort_behavior, 0);
            }
            c.entry_sp = old_sp;
            c.p.vm.release(base).unwrap();
        }
    });
}

#[test]
fn fatal_ptd_oom_runs_abort_policy_not_catchable_no_memory_all_abis() {
    for name in ["terminate", "_get_terminate", "set_terminate"] {
        for custom in [false, true] {
            run(|c| {
                assert!(
                    !c.p.crt.runtimes[UCRT.index()]
                        .contexts
                        .contains_key(&c.t.tid)
                );
                let heap = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
                c.p.crt.runtimes[UCRT.index()].heap = heap;
                let mut exhausted = false;
                for _ in 0..1024 {
                    match c.p.heaps.alloc_checked(&mut c.p.vm, heap, 8, false) {
                        Ok(_) => {}
                        Err(HeapError::NoMemory) => {
                            exhausted = true;
                            break;
                        }
                        Err(error) => panic!("unexpected exhaustion {error:?}"),
                    }
                }
                assert!(exhausted);
                if custom {
                    assert_eq!(int(invoke(c, UCRT, "signal", &[22, 0x1100])), 0);
                }
                let args = if name == "set_terminate" {
                    &[0x2200][..]
                } else {
                    &[][..]
                };
                let result = invoke(c, UCRT, name, args);
                if custom {
                    let then = callback(result, 0x1100, &[22]);
                    assert_eq!(int(invoke(c, UCRT, "_set_abort_behavior", &[0, 2])), 2);
                    let result = then(c, 0);
                    let result = scope(c, result, Some(0xE06D_7363));
                    assert!(matches!(result.unwrap(), Flow::ExitProcess(3)));
                } else {
                    assert!(matches!(
                        result.unwrap(),
                        Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
                    ));
                }
                assert!(
                    !c.p.crt.runtimes[UCRT.index()]
                        .contexts
                        .contains_key(&c.t.tid)
                );
            });
        }
    }
}

#[test]
fn signal_action_precedence_queries_and_global_thread_identity_all_abis() {
    run(|c| {
        let cells = int(invoke(c, UCRT, "_errno", &[]));
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 0x1100])), 0);
        for action in [3, 4] {
            c.mem().w32(cells, 123).unwrap();
            assert_eq!(
                int(invoke(c, UCRT, "signal", &[22, action])),
                c.arch().ptr(u64::MAX)
            );
            assert_eq!(c.mem().u32(cells).unwrap(), 22);
            assert_eq!(int(invoke(c, UCRT, "signal", &[6, 2])), 0x1100);
            assert_eq!(
                int(invoke(c, UCRT, "signal", &[8, action])),
                c.arch().ptr(u64::MAX)
            );
            c.mem().w32(cells, 123).unwrap();
            assert_eq!(
                int(invoke(c, UCRT, "signal", &[13, action])),
                c.arch().ptr(u64::MAX)
            );
            assert_eq!(c.mem().u32(cells).unwrap(), 123);
        }
        let tid = c.t.tid;
        c.t.tid += 1;
        assert_eq!(int(invoke(c, UCRT, "signal", &[6, 2])), 0x1100);
        let then = callback(invoke(c, UCRT, "raise", &[22]), 0x1100, &[22]);
        assert_eq!(int(then(c, 42)), 0);
        c.t.tid = tid;
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 2])), 0);
        // Executable SDK predicate accepts action 5 despite its illegal-code
        // comment. This verifies selection, not successful guest execution at
        // address 0x5 (that address must take ordinary checked fault handling).
        assert_eq!(int(invoke(c, UCRT, "signal", &[15, 5])), 0);
        let then = callback(invoke(c, UCRT, "raise", &[15]), 5, &[15]);
        assert_eq!(int(invoke(c, UCRT, "signal", &[15, 0x2200])), 0);
        assert_eq!(int(then(c, 42)), 0);
        let then = callback(invoke(c, UCRT, "raise", &[15]), 0x2200, &[15]);
        assert_eq!(int(then(c, 42)), 0);
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 1])), 0);
        assert!(matches!(
            invoke(c, UCRT, "abort", &[]).unwrap(),
            Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
        ));
        assert_eq!(int(invoke(c, UCRT, "signal", &[22, 2])), 1);
    });
}

#[test]
fn invalid_raise_errno_fault_never_repeats_handler_or_redecodes_formals_all_abis() {
    run(|c| {
        let cells = int(invoke(c, UCRT, "_errno", &[]));
        int(invoke(c, UCRT, "_set_invalid_parameter_handler", &[0x1100]));
        let then = callback(invoke(c, UCRT, "raise", &[999]), 0x1100, &[0; 5]);
        let page = cells & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let Flow::RetryFault { fault, retry } = then(c, 0).unwrap() else {
            panic!("errno store frontier")
        };
        assert_eq!(fault.addr, cells);
        assert!(fault.write);
        int(invoke(c, UCRT, "_set_invalid_parameter_handler", &[0x2200]));
        int(invoke(c, UCRT, "signal", &[22, 1]));
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.mem().w32(c.entry_sp + 4, 22).unwrap();
        for register in 0..9 {
            c.t.cpu.set_gpr(register, 22);
        }
        assert_eq!(int(retry(c, 0)), u64::from(u32::MAX));
        assert_eq!(c.mem().u32(cells).unwrap(), 22);
        assert_eq!(
            int(invoke(c, UCRT, "_get_invalid_parameter_handler", &[])),
            0x2200
        );
    });
}
