//! Cross-ABI tests exercise actual CRT trap origins and descriptor arguments.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, ApiResult, Flow, Item, Value};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::{
    STATUS_HEAP_CORRUPTION, STATUS_NO_MEMORY, STATUS_STACK_BUFFER_OVERRUN,
};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

pub(super) fn api(name: &str) -> &'static Api {
    ALLOCATION_EXPORTS
        .iter()
        .chain(STATE_EXPORTS)
        .chain(UCRT_STATE_EXPORTS)
        .chain(INIT_EXPORTS)
        .chain(UCRT_INIT_EXPORTS)
        .chain(MSVCRT_STARTUP_EXPORTS)
        .chain(UCRT_STARTUP_EXPORTS)
        .chain(UCRT_BOOTSTRAP_EXPORTS)
        .chain(UCRT_ONEXIT_EXPORTS)
        .chain(UCRT_REGISTRATION_EXPORTS)
        .chain(UCRT_EXIT_EXPORTS)
        .chain(UCRT_FATAL_EXPORTS)
        .chain(UCRT_SIGNAL_EXPORTS)
        .chain(STDIO_EXPORTS)
        .chain(MSVCRT_STDIO_EXPORTS)
        .chain(UCRT_STDIO_EXPORTS)
        .chain(UCRT_EXCEPTION_FILTER_EXPORTS)
        .chain(NEW_HANDLER_EXPORTS)
        .find_map(|export| match &export.item {
            Item::Func(api) if api.name == name => Some(api),
            _ => None,
        })
        .unwrap()
}

pub(super) fn run(mut test: impl FnMut(&mut Ctx)) {
    for arch in WinArch::ALL {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut config = WindowsConfig::new("crt-state-test.exe", vec![]);
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        loader::load_dll(p, "msvcrt.dll").unwrap();
        loader::load_dll(p, "ucrtbase.dll").unwrap();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let sp = thread.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut thread,
            api: api("malloc"),
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        c.set_last_error(0x2468).unwrap();
        test(&mut c);
        assert_eq!(c.last_error().unwrap(), 0x2468, "{arch:?}");
    }
}

pub(super) fn invoke(c: &mut Ctx, kind: RuntimeKind, name: &str, args: &[u64]) -> ApiResult {
    let dll = match kind {
        RuntimeKind::Msvcrt => "msvcrt.dll",
        RuntimeKind::Ucrt => "ucrtbase.dll",
    };
    let index = c.p.modules.by_name(dll).unwrap();
    c.entry_pc = loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .expect("admitted export");
    c.api = api(name);
    assert_eq!(args.len(), c.api.args.len());
    for (i, &value) in args.iter().enumerate() {
        match c.arch() {
            WinArch::X86 => c
                .mem()
                .w32(c.entry_sp + 4 + i as u64 * 4, value as u32)
                .unwrap(),
            WinArch::X64 if i < 4 => c.t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::X64 => c.mem().w64(c.entry_sp + 8 + i as u64 * 8, value).unwrap(),
            WinArch::Arm64 => c.t.cpu.set_gpr(i, value),
        }
    }
    (c.api.imp)(c)
}

pub(super) fn int(result: ApiResult) -> u64 {
    match result.unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("integer return"),
    }
}
pub(super) fn void(result: ApiResult) {
    assert!(matches!(result.unwrap(), Flow::Ret(Value::None)));
}
fn terminate(result: ApiResult, status: u32) {
    assert!(matches!(result.unwrap(), Flow::TerminateProcess(actual) if actual == status));
}
pub(super) fn area(c: &mut Ctx) -> u64 {
    c.p.vm
        .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}
fn errno(c: &mut Ctx, kind: RuntimeKind) -> u32 {
    let pointer = int(invoke(c, kind, "_errno", &[]));
    c.mem().u32(pointer).unwrap()
}

#[test]
fn error_cells_are_guest_authoritative_thread_not_fiber_and_runtime_local() {
    run(|c| {
        let a = int(invoke(c, RuntimeKind::Msvcrt, "_errno", &[]));
        let b = int(invoke(c, RuntimeKind::Ucrt, "_errno", &[]));
        assert_ne!(a, b);
        assert_eq!(c.mem().u32(a).unwrap(), 0);
        assert_eq!(c.mem().u32(b + 4).unwrap(), 0);
        assert_eq!(int(invoke(c, RuntimeKind::Ucrt, "__doserrno", &[])), b + 4);
        c.mem().w32(a, 123).unwrap();
        c.mem().w32(b, 456).unwrap();
        c.mem().w32(b + 4, 0xFEDC_BA98).unwrap();
        let out = area(c);
        assert_eq!(int(invoke(c, RuntimeKind::Ucrt, "_get_errno", &[out])), 0);
        assert_eq!(c.mem().u32(out).unwrap(), 456);
        assert_eq!(
            int(invoke(c, RuntimeKind::Ucrt, "_get_doserrno", &[out])),
            0
        );
        assert_eq!(c.mem().u32(out).unwrap(), 0xFEDC_BA98);
        c.t.current_fiber = Some(0x123456);
        assert_eq!(int(invoke(c, RuntimeKind::Ucrt, "_errno", &[])), b);
        c.t.current_fiber = None;
        let original_tid = c.t.tid;
        c.t.tid = original_tid + 1;
        let other = int(invoke(c, RuntimeKind::Ucrt, "_errno", &[]));
        assert_ne!(b, other);
        assert_eq!(c.mem().u32(other).unwrap(), 0);
        state::release_thread(c.p, c.t.tid).unwrap();
        assert_eq!(c.p.heaps.owner(other), None);
        c.t.tid = original_tid;
        assert_eq!(errno(c, RuntimeKind::Msvcrt), 123);
        assert_eq!(errno(c, RuntimeKind::Ucrt), 456);
    });
}

#[test]
fn setters_write_exact_four_bytes_and_success_preserves_error_state() {
    run(|c| {
        let cells = int(invoke(c, RuntimeKind::Ucrt, "_errno", &[]));
        assert_eq!(
            int(invoke(c, RuntimeKind::Ucrt, "_set_errno", &[u64::MAX])),
            0
        );
        assert_eq!(c.mem().u32(cells).unwrap(), u32::MAX);
        assert_eq!(c.mem().u32(cells + 4).unwrap(), 0);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_set_doserrno",
                &[0x89AB_CDEF]
            )),
            0
        );
        let block = int(invoke(c, RuntimeKind::Ucrt, "malloc", &[17]));
        assert_ne!(block, 0);
        assert_eq!(errno(c, RuntimeKind::Ucrt), u32::MAX);
        assert_eq!(c.mem().u32(cells + 4).unwrap(), 0x89AB_CDEF);
        void(invoke(c, RuntimeKind::Ucrt, "free", &[block]));
    });
}

#[test]
fn zero_allocations_alignment_zeroing_and_private_heap_ownership() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let heap = int(invoke(c, kind, "_get_heap_handle", &[]));
            let zero = int(invoke(c, kind, "malloc", &[0]));
            assert_ne!(zero, 0);
            assert_eq!(zero % if c.arch().is64() { 16 } else { 8 }, 0);
            assert_eq!(c.p.heaps.owner(zero), Some(heap));
            assert_eq!(int(invoke(c, kind, "_msize", &[zero])), 0);
            let empty = int(invoke(c, kind, "calloc", &[0, c.arch().ptr(u64::MAX)]));
            assert_ne!(empty, 0);
            assert_eq!(int(invoke(c, kind, "_msize", &[empty])), 1);
            let block = int(invoke(c, kind, "calloc", &[7, 11]));
            assert_eq!(c.mem().bytes(block, 77).unwrap(), [0; 77]);
            for ptr in [zero, empty, block] {
                void(invoke(c, kind, "free", &[ptr]));
            }
            void(invoke(c, kind, "free", &[0]));
        }
        assert_ne!(c.p.crt.runtimes[0].heap, c.p.crt.runtimes[1].heap);
    });
}

#[test]
fn checked_guest_width_oom_and_realloc_failure_preserve_original() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let block = int(invoke(c, kind, "malloc", &[37]));
        c.mem().wr(block, &[0xA7; 37]).unwrap();
        let max = c.arch().ptr(u64::MAX);
        assert_eq!(int(invoke(c, kind, "calloc", &[max, 2])), 0);
        assert_eq!(errno(c, kind), 12);
        assert_eq!(int(invoke(c, kind, "malloc", &[max])), 0);
        assert_eq!(int(invoke(c, kind, "realloc", &[block, max])), 0);
        assert_eq!(int(invoke(c, kind, "_msize", &[block])), 37);
        assert_eq!(c.mem().bytes(block, 37).unwrap(), [0xA7; 37]);
        let larger = int(invoke(c, kind, "realloc", &[block, 190]));
        assert_ne!(larger, 0);
        assert_eq!(c.mem().bytes(larger, 37).unwrap(), [0xA7; 37]);
        let smaller = int(invoke(c, kind, "realloc", &[larger, 11]));
        assert_eq!(c.mem().bytes(smaller, 11).unwrap(), [0xA7; 11]);
        assert_eq!(int(invoke(c, kind, "realloc", &[smaller, 0])), 0);
        assert_eq!(c.p.heaps.owner(smaller), None);
        let null_zero = int(invoke(c, kind, "realloc", &[0, 0]));
        assert_ne!(null_zero, 0);
        void(invoke(c, kind, "free", &[null_zero]));
    });
}

#[test]
fn expand_never_moves_and_failure_does_not_resize_the_old_block() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let a = int(invoke(c, kind, "malloc", &[16]));
        let b = int(invoke(c, kind, "malloc", &[16]));
        c.mem().wr(a, &[0x51; 16]).unwrap();
        assert_eq!(int(invoke(c, kind, "_expand", &[a, PAGE_SIZE])), 0);
        assert_eq!(errno(c, kind), 12);
        assert_eq!(int(invoke(c, kind, "_msize", &[a])), 16);
        assert_eq!(c.mem().bytes(a, 16).unwrap(), [0x51; 16]);
        assert_eq!(int(invoke(c, kind, "_expand", &[a, 8])), a);
        assert_eq!(int(invoke(c, kind, "_msize", &[a])), 8);
        void(invoke(c, kind, "free", &[a]));
        void(invoke(c, kind, "free", &[b]));
    });
}

#[test]
fn strdup_and_wcsdup_preserve_terminators_and_raw_wchar_units() {
    run(|c| {
        let source = area(c);
        c.mem().wr(source, b"copy\xFF\0").unwrap();
        c.mem()
            .put_wunits(source + 32, &[0xD800, 0xFFFF, 0xDC00, 0])
            .unwrap();
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let a = int(invoke(c, kind, "_strdup", &[source]));
            let b = int(invoke(c, kind, "_wcsdup", &[source + 32]));
            assert_eq!(c.mem().bytes(a, 6).unwrap(), b"copy\xFF\0");
            assert_eq!(c.mem().wunits(b, 4).unwrap(), [0xD800, 0xFFFF, 0xDC00, 0]);
            void(invoke(c, kind, "free", &[a]));
            void(invoke(c, kind, "free", &[b]));
            let before = c.p.crt.runtimes[kind.index()].allocations.len();
            assert!(matches!(
                invoke(c, kind, "_strdup", &[0]),
                Err(ApiErr::Fault(_))
            ));
            assert_eq!(c.p.crt.runtimes[kind.index()].allocations.len(), before);
        }
    });
}

#[test]
fn invalid_handler_precedence_arguments_and_continuation_errno() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        assert_eq!(
            int(invoke(c, kind, "_get_invalid_parameter_handler", &[])),
            0
        );
        assert_eq!(
            int(invoke(
                c,
                kind,
                "_set_invalid_parameter_handler",
                &[0x12340]
            )),
            0
        );
        assert_eq!(
            int(invoke(
                c,
                kind,
                "_set_thread_local_invalid_parameter_handler",
                &[0x56780]
            )),
            0
        );
        let args = [1, 2, 3, 0xFFFF_FFFE, c.arch().ptr(0x1122334455667788)];
        match invoke(c, kind, "_invalid_parameter", &args).unwrap() {
            Flow::Call {
                target,
                args: passed,
                then,
            } => {
                assert_eq!(target, 0x56780);
                assert_eq!(passed, args);
                void(then(c, 0));
            }
            _ => panic!("real guest callback required"),
        }
        assert_eq!(
            int(invoke(
                c,
                kind,
                "_set_thread_local_invalid_parameter_handler",
                &[0]
            )),
            0x56780
        );
        match invoke(c, kind, "_get_errno", &[0]).unwrap() {
            Flow::Call { target, args, then } => {
                assert_eq!(target, 0x12340);
                assert_eq!(args, [0; 5]);
                assert_eq!(int(then(c, 0)), 22);
            }
            _ => panic!("global guest callback required"),
        }
        assert_eq!(errno(c, kind), 22);
        match invoke(c, kind, "_msize", &[0]).unwrap() {
            Flow::Call { then, .. } => assert_eq!(int(then(c, 0)), c.arch().ptr(u64::MAX)),
            _ => panic!("validated allocation callback required"),
        }
        match invoke(c, kind, "_expand", &[0, 100]).unwrap() {
            Flow::Call { then, .. } => assert_eq!(int(then(c, 0)), 0),
            _ => panic!("validated allocation callback required"),
        }
        match invoke(c, kind, "_get_doserrno", &[0]).unwrap() {
            Flow::Call { then, .. } => assert_eq!(int(then(c, 0)), 22),
            _ => panic!("doserrno callback required"),
        }
    });
}

#[test]
fn invalid_default_and_noreturn_bypass_guest_exception_notifications() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        terminate(
            invoke(c, kind, "_invalid_parameter_noinfo", &[]),
            STATUS_STACK_BUFFER_OVERRUN,
        );
        int(invoke(
            c,
            kind,
            "_set_invalid_parameter_handler",
            &[0x12340],
        ));
        match invoke(c, kind, "_invalid_parameter_noinfo_noreturn", &[]).unwrap() {
            Flow::Call { then, .. } => terminate(then(c, 0), STATUS_STACK_BUFFER_OVERRUN),
            _ => panic!("handler runs before forced termination"),
        }
        terminate(
            invoke(c, kind, "_invoke_watson", &[0, 0, 0, 0, 0]),
            STATUS_STACK_BUFFER_OVERRUN,
        );
        terminate(
            invoke(c, RuntimeKind::Msvcrt, "_msize", &[0]),
            STATUS_STACK_BUFFER_OVERRUN,
        );
    });
}

#[test]
fn invalid_blocks_are_corruption_not_invalid_parameter_callbacks() {
    run(|c| {
        let a = int(invoke(c, RuntimeKind::Msvcrt, "malloc", &[12]));
        int(invoke(
            c,
            RuntimeKind::Ucrt,
            "_set_invalid_parameter_handler",
            &[0x12340],
        ));
        for (name, args) in [
            ("free", vec![a]),
            ("_msize", vec![a]),
            ("realloc", vec![a, 24]),
            ("_expand", vec![a, 24]),
        ] {
            terminate(
                invoke(c, RuntimeKind::Ucrt, name, &args),
                STATUS_HEAP_CORRUPTION,
            );
        }
        let cells = int(invoke(c, RuntimeKind::Msvcrt, "_errno", &[]));
        terminate(
            invoke(c, RuntimeKind::Msvcrt, "free", &[cells]),
            STATUS_HEAP_CORRUPTION,
        );
        void(invoke(c, RuntimeKind::Msvcrt, "free", &[a]));
        terminate(
            invoke(c, RuntimeKind::Msvcrt, "free", &[a]),
            STATUS_HEAP_CORRUPTION,
        );
    });
}

#[test]
fn readonly_errno_accessors_work_but_writes_and_allocators_preflight() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let cells = int(invoke(c, kind, "_errno", &[]));
        let out = area(c);
        c.mem().w32(cells, 777).unwrap();
        let page = cells & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(int(invoke(c, kind, "_errno", &[])), cells);
        assert_eq!(int(invoke(c, kind, "_get_errno", &[out])), 0);
        assert_eq!(c.mem().u32(out).unwrap(), 777);
        assert_eq!(
            int(invoke(
                c,
                kind,
                "_get_thread_local_invalid_parameter_handler",
                &[]
            )),
            0
        );
        assert!(matches!(invoke(c, kind, "_set_errno", &[9]), Err(ApiErr::Fault(f)) if f.write));
        let before = c.p.crt.runtimes[1].allocations.len();
        assert!(matches!(invoke(c, kind, "malloc", &[10]), Err(ApiErr::Fault(f)) if f.write));
        assert_eq!(c.p.crt.runtimes[1].allocations.len(), before);
        assert_eq!(c.mem().u32(cells).unwrap(), 777);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.p.vm.protect(out, PAGE_SIZE, prot::READONLY).unwrap();
        assert!(matches!(invoke(c, kind, "_get_errno", &[out]), Err(ApiErr::Fault(f)) if f.write));
        assert_eq!(c.mem().u32(cells).unwrap(), 777);
    });
}

#[test]
fn commitment_exhaustion_reports_enomem_and_keeps_realloc_source() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let block = int(invoke(c, kind, "malloc", &[31]));
        c.mem().wr(block, &[0xAB; 31]).unwrap();
        let available = c.p.vm.commit_limit() - c.p.vm.committed_bytes();
        c.p.vm
            .allocate(None, available, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
        assert_eq!(int(invoke(c, kind, "realloc", &[block, 2 << 20])), 0);
        assert_eq!(errno(c, kind), 12);
        assert_eq!(int(invoke(c, kind, "_msize", &[block])), 31);
        assert_eq!(c.mem().bytes(block, 31).unwrap(), [0xAB; 31]);
    });
}

#[test]
fn first_error_context_oom_is_an_explicit_admission_exception() {
    run(|c| {
        let available = c.p.vm.commit_limit() - c.p.vm.committed_bytes();
        c.p.vm
            .allocate(None, available, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
        assert!(matches!(invoke(c, RuntimeKind::Ucrt, "malloc", &[1]),
            Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY));
        assert_eq!(c.p.crt.runtimes[1].heap, 0);
        assert!(c.p.crt.runtimes[1].contexts.is_empty());
        assert!(c.p.crt.runtimes[1].allocations.is_empty());
    });
}

#[test]
fn unsupported_new_handler_registration_and_legacy_compat_wrappers_are_not_exports() {
    run(|c| {
        for name in [
            "_set_new_handler",
            "_query_new_handler",
            "printf",
            "_aligned_malloc",
        ] {
            for dll in ["msvcrt.dll", "ucrtbase.dll"] {
                let index = c.p.modules.by_name(dll).unwrap();
                assert_eq!(
                    loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap(),
                    None
                );
            }
        }
        let legacy = c.p.modules.by_name("msvcrt.dll").unwrap();
        // Universal plain mode names are genuine new startup exports. Legacy
        // mode functions retain decorated names; do not promote local shims.
        for name in ["_set_new_mode", "_query_new_mode"] {
            assert_eq!(
                loader::lookup(c.p, legacy, &SymRef::Name(name.as_bytes().to_vec(), None)).unwrap(),
                None
            );
            let universal = c.p.modules.by_name("ucrtbase.dll").unwrap();
            assert!(
                loader::lookup(
                    c.p,
                    universal,
                    &SymRef::Name(name.as_bytes().to_vec(), None)
                )
                .unwrap()
                .is_some()
            );
        }
        assert_eq!(
            loader::lookup(
                c.p,
                legacy,
                &SymRef::Name(
                    b"_set_thread_local_invalid_parameter_handler".to_vec(),
                    None
                )
            )
            .unwrap(),
            None
        );
    });
}

#[test]
fn handler_queries_answer_from_what_a_guest_can_install() {
    run(|c| {
        // No new handler can be installed (_set_new_handler is not exported),
        // so none runs, in either runtime.
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            assert_eq!(int(invoke(c, kind, "_callnewh", &[64])), 0, "{kind:?}");
        }
        // The exception-class signal actions cannot leave the default, so the
        // filter keeps searching; it never reads its pointer argument.
        for code in [0xC000_0005u64, 0xC000_001D, 0xC000_0094, 0x8000_0003] {
            assert_eq!(
                int(invoke(
                    c,
                    RuntimeKind::Ucrt,
                    "_seh_filter_exe",
                    &[code, 0x10]
                )),
                0
            );
        }
        // That claim holds only while installing such an action is refused.
        assert!(matches!(
            invoke(c, RuntimeKind::Ucrt, "signal", &[11, 0x1000]),
            Err(ApiErr::Unimplemented(_))
        ));
        // msvcrt.dll exports _XcptFilter, not the UCRT filter.
        let legacy = c.p.modules.by_name("msvcrt.dll").unwrap();
        assert_eq!(
            loader::lookup(
                c.p,
                legacy,
                &SymRef::Name(b"_seh_filter_exe".to_vec(), None)
            )
            .unwrap(),
            None
        );
    });
}
