//! Genuine descriptor, policy, PTD and invalid-handler boundary contracts.

use super::super::tests::{api, int, invoke, run, void};
use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::heap::HeapError;
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::STATUS_STACK_BUFFER_OVERRUN;

const U: RuntimeKind = RuntimeKind::Ucrt;

fn config(c: &mut Ctx, mode: u64) -> u64 {
    int(invoke(c, U, "_configthreadlocale", &[mode]))
}

fn exhaust_ptd_heap(c: &mut Ctx) {
    assert!(c.p.crt.runtimes[U.index()].contexts.is_empty());
    let heap = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
    c.p.crt.runtimes[U.index()].heap = heap;
    for _ in 0..1024 {
        match c.p.heaps.alloc_checked(&mut c.p.vm, heap, 8, false) {
            Ok(_) => {}
            Err(HeapError::NoMemory) => return,
            Err(error) => panic!("unexpected exhaustion: {error:?}"),
        }
    }
    panic!("bounded heap must exhaust");
}

fn callback(result: ApiResult, expected: u64) -> Cont {
    let Flow::CallChecked { target, args, then } = result.unwrap() else {
        panic!("checked invalid-parameter callback")
    };
    assert_eq!(target, expected);
    assert_eq!(args, [0; 5]);
    then
}

#[test]
fn six_genuine_ucrt_exports_have_alias_identity_without_legacy_promotion() {
    run(|c| {
        let native = c.p.modules.by_name("ucrtbase.dll").unwrap();
        let legacy = c.p.modules.by_name("msvcrt.dll").unwrap();
        for family in ["runtime", "locale", "math"] {
            let alias =
                loader::load_dll(c.p, &format!("api-ms-win-crt-{family}-l1-1-0.dll")).unwrap();
            for export in UCRT_BOOTSTRAP_EXPORTS {
                let name = SymRef::Name(export.name.as_bytes().to_vec(), None);
                let actual = loader::lookup(c.p, native, &name).unwrap().unwrap();
                assert_eq!(loader::lookup(c.p, alias, &name).unwrap(), Some(actual));
                assert_eq!(loader::lookup(c.p, legacy, &name).unwrap(), None);
            }
        }
        for name in ["__set_app_type", "_matherr"] {
            assert_eq!(
                loader::lookup(c.p, native, &SymRef::Name(name.as_bytes().to_vec(), None)).unwrap(),
                None
            );
        }
        assert_eq!(api("_set_app_type").args.len(), 1);
        assert_eq!(api("__setusermatherr").args.len(), 1);
        assert!(api("__pxcptinfoptrs").args.is_empty());
    });
}

#[test]
fn app_enum_is_unconditional_32_bit_state_without_ptd_allocation() {
    run(|c| {
        assert_eq!(int(invoke(c, U, "_query_app_type", &[])), 0);
        for value in [
            0,
            1,
            2,
            3,
            0x8000_0000,
            0x7FFF_FFFF,
            u64::MAX,
            0x1122_3344_0000_0001,
        ] {
            void(invoke(c, U, "_set_app_type", &[value]));
            assert_eq!(
                int(invoke(c, U, "_query_app_type", &[])),
                u64::from(value as u32)
            );
        }
        assert!(c.p.crt.runtimes[U.index()].contexts.is_empty());
        assert_eq!(c.p.crt.runtimes[U.index()].heap, 0);
        assert_eq!(
            c.p.crt.runtimes[RuntimeKind::Msvcrt.index()]
                .bootstrap
                .app_type,
            0
        );
        let cells = int(invoke(c, U, "_errno", &[]));
        c.mem().w32(cells, 73).unwrap();
        c.mem().w32(cells + 4, 0xABCD_EF01).unwrap();
        void(invoke(c, U, "_set_app_type", &[2]));
        assert_eq!(c.mem().u32(cells).unwrap(), 73);
        assert_eq!(c.mem().u32(cells + 4).unwrap(), 0xABCD_EF01);
    });
}

#[test]
fn math_registration_stores_pointer_identity_without_validation_or_callback() {
    run(|c| {
        for target in [0, 1, 0x1100, u64::MAX, 0x1234_5678_8765_4321] {
            void(invoke(c, U, "__setusermatherr", &[target]));
            assert_eq!(
                c.p.crt.runtimes[U.index()].bootstrap.math_handler,
                c.arch().ptr(target)
            );
            assert!(c.p.crt.runtimes[U.index()].contexts.is_empty());
            assert_eq!(c.p.crt.runtimes[U.index()].heap, 0);
            assert_eq!(
                c.p.crt.runtimes[RuntimeKind::Msvcrt.index()]
                    .bootstrap
                    .math_handler,
                0
            );
        }
    });
}

#[test]
fn locale_returns_previous_mode_and_minus_one_changes_only_global_status() {
    run(|c| {
        assert_eq!(
            c.p.crt.runtimes[U.index()].bootstrap.global_locale_status,
            0xFFFF_FFFE
        );
        for (mode, old, next) in [
            (0, 2, 2),
            (1, 2, 1),
            (1, 1, 1),
            (0, 1, 1),
            (2, 1, 2),
            (2, 2, 2),
        ] {
            assert_eq!(config(c, mode), old);
            assert_eq!(config(c, 0), next);
            assert_eq!(
                c.p.crt.runtimes[U.index()].contexts[&c.t.tid].locale_flags & 1,
                1
            );
        }
        assert_eq!(config(c, 1), 2);
        assert_eq!(config(c, u64::MAX), 1);
        assert_eq!(config(c, 0), 1);
        assert_eq!(
            c.p.crt.runtimes[U.index()].bootstrap.global_locale_status,
            u32::MAX
        );
        assert_eq!(
            c.p.crt.runtimes[RuntimeKind::Msvcrt.index()]
                .bootstrap
                .global_locale_status,
            0xFFFF_FFFE
        );
        let tid = c.t.tid;
        c.t.current_fiber = Some(0x112200);
        assert_eq!(config(c, 0), 1);
        c.t.current_fiber = None;
        c.t.tid = tid + 1;
        assert_eq!(config(c, 0), 2);
        assert_eq!(config(c, 1), 2);
        state::release_thread(c.p, c.t.tid).unwrap();
        c.t.tid = tid;
        assert_eq!(config(c, 0), 1);
    });
}

#[test]
fn exception_slot_is_pointer_width_null_stable_nonoverlapping_and_thread_owned() {
    run(|c| {
        let slot = int(invoke(c, U, "__pxcptinfoptrs", &[]));
        let errno = int(invoke(c, U, "_errno", &[]));
        assert_eq!(slot, errno + 8);
        assert_eq!(int(invoke(c, U, "__doserrno", &[])), errno + 4);
        assert_eq!(c.mem().ptr(slot, c.psize()).unwrap(), 0);
        let value = c.arch().ptr(0x1122_3344_AABB_CCDD);
        c.mem().wptr(slot, c.psize(), value).unwrap();
        c.mem().w32(errno, 91).unwrap();
        c.mem().w32(errno + 4, 0xFFFF_FFFE).unwrap();
        c.t.current_fiber = Some(0x123400);
        assert_eq!(int(invoke(c, U, "__pxcptinfoptrs", &[])), slot);
        assert_eq!(c.mem().ptr(slot, c.psize()).unwrap(), value);
        c.t.current_fiber = None;
        let tid = c.t.tid;
        c.t.tid = tid + 1;
        let other = int(invoke(c, U, "__pxcptinfoptrs", &[]));
        assert_ne!(other, slot);
        assert_eq!(c.mem().ptr(other, c.psize()).unwrap(), 0);
        state::release_thread(c.p, c.t.tid).unwrap();
        assert_eq!(c.p.heaps.owner(other - 8), None);
        c.t.tid = tid;
        assert_eq!(c.mem().u32(errno).unwrap(), 91);
        assert_eq!(c.mem().u32(errno + 4).unwrap(), 0xFFFF_FFFE);
    });
}

#[test]
fn invalid_locale_sets_errno_before_checked_handler_and_preserves_handler_mutations() {
    run(|c| {
        let cells = int(invoke(c, U, "_errno", &[]));
        int(invoke(c, U, "_set_invalid_parameter_handler", &[0x1100]));
        int(invoke(
            c,
            U,
            "_set_thread_local_invalid_parameter_handler",
            &[0x2200],
        ));
        for mode in [3, 16, 32, 256, 512, 0x8000_0000] {
            c.mem().w32(cells, 7).unwrap();
            c.mem().w32(cells + 4, 0x8765_4321).unwrap();
            let then = callback(invoke(c, U, "_configthreadlocale", &[mode]), 0x2200);
            assert_eq!(c.mem().u32(cells).unwrap(), 22);
            c.mem().w32(cells, 73).unwrap();
            config(c, 1);
            assert_eq!(int(then(c, 0xFEDC_BA98)), u64::from(u32::MAX));
            assert_eq!(c.mem().u32(cells).unwrap(), 73);
            assert_eq!(c.mem().u32(cells + 4).unwrap(), 0x8765_4321);
            assert_eq!(config(c, 0), 1);
        }
        int(invoke(
            c,
            U,
            "_set_thread_local_invalid_parameter_handler",
            &[0],
        ));
        let then = callback(invoke(c, U, "_configthreadlocale", &[5]), 0x1100);
        assert_eq!(int(then(c, 0)), u64::from(u32::MAX));
    });
}

#[test]
fn invalid_locale_without_handler_commits_errno_before_forced_exit() {
    run(|c| {
        let cells = int(invoke(c, U, "_errno", &[]));
        assert!(matches!(
            invoke(c, U, "_configthreadlocale", &[3]).unwrap(),
            Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
        ));
        assert_eq!(c.mem().u32(cells).unwrap(), 22);
        assert_eq!(config(c, 0), 2);
    });
}

#[test]
fn invalid_locale_errno_fault_captures_mode_and_does_not_call_handler_early() {
    run(|c| {
        let cells = int(invoke(c, U, "_errno", &[]));
        c.mem().w32(cells, 7).unwrap();
        int(invoke(c, U, "_set_invalid_parameter_handler", &[0x1100]));
        let page = cells & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let Flow::RetryFault { fault, retry } = invoke(c, U, "_configthreadlocale", &[3]).unwrap()
        else {
            panic!("errno store must fault before callback")
        };
        assert!(fault.write);
        assert_eq!(fault.addr, cells);
        assert_eq!(c.mem().u32(cells).unwrap(), 7);
        // A handler/repair may change current formals/API. Captured mode 3
        // must not be re-decoded as valid mode 1 after the committed decode.
        config(c, 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        let then = callback(retry(c, 0), 0x1100);
        assert_eq!(c.mem().u32(cells).unwrap(), 22);
        c.mem().w32(cells, 99).unwrap();
        assert_eq!(int(then(c, 0)), u64::from(u32::MAX));
        assert_eq!(c.mem().u32(cells).unwrap(), 99);
        assert_eq!(config(c, 0), 1);
    });
}

#[test]
fn getptd_bootstrap_oom_uses_existing_actual_abort_policy() {
    for name in ["__pxcptinfoptrs", "_configthreadlocale", "_fpreset"] {
        run(|c| {
            exhaust_ptd_heap(c);
            let args = if name == "_configthreadlocale" {
                &[1][..]
            } else {
                &[][..]
            };
            let result = invoke(c, U, name, args).unwrap();
            if name == "_fpreset" && c.arch() != WinArch::X86 {
                assert!(matches!(
                    result,
                    Flow::Ret(crate::user::windows::hle::Value::None)
                ));
            } else {
                assert!(matches!(
                    result,
                    Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
                ));
            }
            assert!(c.p.crt.runtimes[U.index()].contexts.is_empty());
        });
    }
}

#[test]
fn x86_locale_getptd_oom_precedes_unreadable_stack_formal() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        exhaust_ptd_heap(c);
        let module = c.p.modules.by_name("ucrtbase.dll").unwrap();
        c.entry_pc = loader::lookup(
            c.p,
            module,
            &SymRef::Name(b"_configthreadlocale".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        c.api = api("_configthreadlocale");
        c.entry_sp = 0xFFFF_0000;
        assert!(matches!(
            (c.api.imp)(c).unwrap(),
            Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)
        ));
    });
}

#[test]
fn getptd_oom_abort_runs_registered_signal_then_selected_normal_exit_policy() {
    for name in ["__pxcptinfoptrs", "_configthreadlocale", "_fpreset"] {
        run(|c| {
            if name == "_fpreset" && c.arch() != WinArch::X86 {
                return;
            }
            exhaust_ptd_heap(c);
            assert_eq!(int(invoke(c, U, "signal", &[22, 0x3300])), 0);
            let args = if name == "_configthreadlocale" {
                &[1][..]
            } else {
                &[][..]
            };
            let Flow::CallChecked { target, args, then } = invoke(c, U, name, args).unwrap() else {
                panic!("actual registered SIGABRT callback")
            };
            assert_eq!(target, 0x3300);
            assert_eq!(args, [22]);
            assert_eq!(int(invoke(c, U, "_set_abort_behavior", &[0, 2])), 2);
            let Flow::Protected { code, then, .. } = then(c, 0).unwrap() else {
                panic!("existing normal exit scope")
            };
            assert_eq!(code, Some(0xE06D_7363));
            assert!(matches!(then(c, 0).unwrap(), Flow::ExitProcess(3)));
            assert!(c.p.crt.runtimes[U.index()].contexts.is_empty());
        });
    }
}

#[test]
fn locale_setup_fault_preserves_register_formals_but_x86_reads_stack_after_setup() {
    run(|c| {
        let heap = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
        let probe =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, heap, 16, true)
                .unwrap();
        c.p.heaps.free(heap, probe).unwrap();
        c.p.crt.runtimes[U.index()].heap = heap;
        let page = probe & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let Flow::RetryFault { fault, retry } = invoke(c, U, "_configthreadlocale", &[1]).unwrap()
        else {
            panic!("PTD calloc fault")
        };
        assert!(fault.write);
        assert!(c.p.crt.runtimes[U.index()].contexts.is_empty());
        match c.arch() {
            WinArch::X86 => c.mem().w32(c.entry_sp + 4, 2).unwrap(),
            WinArch::X64 => c.t.cpu.set_gpr(1, 2),
            WinArch::Arm64 => c.t.cpu.set_gpr(0, 2),
        }
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(int(retry(c, 0)), 2);
        assert_eq!(config(c, 0), if c.arch() == WinArch::X86 { 2 } else { 1 });
    });
}

#[test]
fn x86_policy_stack_faults_resume_with_repaired_formals_and_no_early_effect() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        for name in ["_set_app_type", "__setusermatherr"] {
            let page =
                c.p.vm
                    .allocate(None, 2 * PAGE_SIZE, mem::RESERVE, prot::READWRITE)
                    .unwrap()
                    .0;
            c.p.vm
                .allocate(Some(page), PAGE_SIZE, mem::COMMIT, prot::READWRITE)
                .unwrap();
            let old_sp = c.entry_sp;
            c.entry_sp = page + PAGE_SIZE - 4;
            let module = c.p.modules.by_name("ucrtbase.dll").unwrap();
            c.entry_pc = loader::lookup(c.p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                .unwrap()
                .unwrap();
            c.api = api(name);
            let Flow::RetryFault { fault, retry } = (c.api.imp)(c).unwrap() else {
                panic!("unmapped stack formal")
            };
            assert!(!fault.write);
            assert_eq!(fault.addr, page + PAGE_SIZE);
            assert_eq!(c.p.crt.runtimes[U.index()].bootstrap.app_type, 0);
            assert_eq!(c.p.crt.runtimes[U.index()].bootstrap.math_handler, 0);
            c.p.vm
                .allocate(
                    Some(page + PAGE_SIZE),
                    PAGE_SIZE,
                    mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap();
            c.mem().w32(page + PAGE_SIZE, 0x8765_4321).unwrap();
            void(retry(c, 0));
            if name == "_set_app_type" {
                assert_eq!(c.p.crt.runtimes[U.index()].bootstrap.app_type, 0x8765_4321);
                c.p.crt.runtimes[U.index()].bootstrap.app_type = 0;
            } else {
                assert_eq!(
                    c.p.crt.runtimes[U.index()].bootstrap.math_handler,
                    0x8765_4321
                );
            }
            c.entry_sp = old_sp;
            c.p.vm.release(page).unwrap();
        }
    });
}
