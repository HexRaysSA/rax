//! Actual runtime-origin descriptors and retained continuation frontiers.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::crt::tests::{api, area, int, invoke, run};
use crate::user::windows::hle::{Cont, Item};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{Mem, MemFault, mem, prot};

fn call(result: ApiResult, expected: u64) -> Cont {
    match result.unwrap() {
        Flow::CallChecked { target, args, then } => {
            assert_eq!(target, expected);
            assert!(args.is_empty());
            then
        }
        _ => panic!("expected an owned checked guest call"),
    }
}

fn retry(result: ApiResult) -> (MemFault, Cont) {
    match result.unwrap() {
        Flow::RetryFault { fault, retry } => (fault, retry),
        _ => panic!("expected an exact retained retry frontier"),
    }
}

fn init(c: &mut Ctx, table: u64) {
    assert_eq!(
        int(invoke(
            c,
            RuntimeKind::Ucrt,
            "_initialize_onexit_table",
            &[table]
        )),
        0
    );
}
fn add(c: &mut Ctx, table: u64, target: u64) {
    assert_eq!(
        int(invoke(
            c,
            RuntimeKind::Ucrt,
            "_register_onexit_function",
            &[table, target]
        )),
        0
    );
}

#[test]
fn genuine_table_binding_matrix_and_termination_exclusions_all_abis() {
    run(|c| {
        for dll in [
            "ucrtbase.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "msvcrt.dll",
        ] {
            let index = loader::load_dll(c.p, dll).unwrap();
            for name in [
                "_initialize_onexit_table",
                "_register_onexit_function",
                "_execute_onexit_table",
            ] {
                let target =
                    loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap();
                assert_eq!(target.is_some(), dll != "msvcrt.dll", "{dll}!{name}");
            }
            for name in ["atexit", "_onexit", "exit", "_cexit", "quick_exit"] {
                assert!(
                    loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap()
                        .is_none(),
                    "{dll}!{name}"
                );
            }
            for name in ["_crt_atexit", "_crt_at_quick_exit"] {
                let target =
                    loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap();
                assert_eq!(target.is_some(), dll != "msvcrt.dll", "{dll}!{name}");
            }
        }
        for export in UCRT_ONEXIT_EXPORTS {
            let Item::Func(api) = &export.item else {
                panic!("table export must be a function");
            };
            assert_eq!(api.conv, Cdecl);
            assert_eq!(
                api.args,
                if api.name == "_register_onexit_function" {
                    &[Ptr, Ptr][..]
                } else {
                    &[Ptr][..]
                }
            );
        }
    });
}

#[test]
fn null_uninitialized_empty_and_lifo_lifecycle_all_abis() {
    run(|c| {
        let table = area(c);
        for name in ["_initialize_onexit_table", "_execute_onexit_table"] {
            assert_eq!(
                int(invoke(c, RuntimeKind::Ucrt, name, &[0])),
                u64::from(u32::MAX)
            );
        }
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_register_onexit_function",
                &[0, 0x1110]
            )),
            u64::from(u32::MAX)
        );
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_execute_onexit_table",
                &[table]
            )),
            u64::from(u32::MAX)
        );
        init(c, table);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_execute_onexit_table",
                &[table]
            )),
            0
        );
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_register_onexit_function",
                &[table, 0x1110]
            )),
            u64::from(u32::MAX)
        );
        init(c, table);
        for target in [0x1110, 0, 0x2220, 0x1110] {
            add(c, table, target);
        }
        let base = c.read_ptr(table).unwrap();
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        for i in 0..3 {
            assert_eq!(c.read_ptr(table + i * c.psize()).unwrap(), 0);
        }
        let then = call(then(c, u64::MAX), 0x2220);
        let then = call(then(c, 7), 0x1110);
        assert_eq!(int(then(c, 123)), 0);
        assert_eq!(c.p.heaps.owner(base), None);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_execute_onexit_table",
                &[table]
            )),
            u64::from(u32::MAX)
        );
    });
}

#[test]
fn pending_slot_fault_keeps_cursor_and_clobbered_formal_all_abis() {
    run(|c| {
        let table = area(c);
        let other = area(c);
        init(c, table);
        init(c, other);
        add(c, table, 0x1110);
        add(c, table, 0x2220);
        let base = c.read_ptr(table).unwrap();
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x2220,
        );
        let page = base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::NOACCESS).unwrap();
        let (fault, retry) = retry(then(c, 0));
        assert!(!fault.write);
        assert_eq!(fault.addr, base);
        // An unrelated call clobbers the original table formal. It must not
        // redirect the retained detached drain after actual memory repair.
        let saved_api = c.api;
        let saved_pc = c.entry_pc;
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_execute_onexit_table",
                &[other]
            )),
            0
        );
        c.api = saved_api;
        c.entry_pc = saved_pc;
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.write_ptr(base, 0x3330).unwrap();
        let then = call(retry(c, 0), 0x3330);
        assert_eq!(int(then(c, 0)), 0);
        assert_eq!(c.p.heaps.owner(base), None);
    });
}

#[test]
fn abandoning_old_epoch_does_not_free_reinitialized_epoch_all_abis() {
    run(|c| {
        let table = area(c);
        init(c, table);
        add(c, table, 0x1110);
        add(c, table, 0x2220);
        let old = c.read_ptr(table).unwrap();
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x2220,
        );
        init(c, table);
        add(c, table, 0x3330);
        let new = c.read_ptr(table).unwrap();
        assert_ne!(old, new);
        drop(then); // Context/unwind abandonment, never a fabricated return.
        let error = cleanup_abandoned(c.p, None).unwrap_err();
        assert!(error.contains("CRT onexit continuation abandoned"));
        assert_eq!(c.p.heaps.owner(old), None);
        assert!(c.p.heaps.owner(new).is_some());
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x3330,
        );
        assert_eq!(int(then(c, 0)), 0);
        assert_eq!(c.p.heaps.owner(new), None);
    });
}

#[test]
fn deliberate_terminal_owner_reaps_without_replacing_exit_all_abis() {
    run(|c| {
        let table = area(c);
        init(c, table);
        add(c, table, 0x1110);
        let base = c.read_ptr(table).unwrap();
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        drop(then);
        cleanup_abandoned(c.p, Some(c.t.tid)).unwrap();
        assert_eq!(c.p.heaps.owner(base), None);
        init(c, table);
        add(c, table, 0x2220);
        let pending = c.read_ptr(table).unwrap();
        discard_process(c.p);
        assert_eq!(c.p.heaps.owner(pending), None);
    });
}

#[test]
fn normal_process_retirement_preserves_tables_for_dll_detach_all_abis() {
    run(|c| {
        let table = area(c);
        let draining = area(c);
        init(c, table);
        add(c, table, 0x1110);
        init(c, draining);
        add(c, draining, 0x2220);
        let live = c.read_ptr(table).unwrap();
        let abandoned = c.read_ptr(draining).unwrap();
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[draining]),
            0x2220,
        );
        drop(then);
        retire_process_drains(c.p).unwrap();
        assert_eq!(c.p.heaps.owner(abandoned), None);
        assert!(c.p.heaps.owner(live).is_some());
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        assert_eq!(int(then(c, 0)), 0);
        assert_eq!(c.p.heaps.owner(live), None);
    });
}

#[test]
fn later_x86_formal_fault_preserves_already_decoded_table() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        } // No second-formal stack read on x64/ARM64.
        let table = area(c);
        let other = area(c);
        init(c, table);
        init(c, other);
        let (stack, _) =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap();
        let saved_sp = c.entry_sp;
        c.entry_sp = stack + PAGE_SIZE - 8;
        c.write_ptr(c.entry_sp + 4, table).unwrap();
        c.write_ptr(c.entry_sp + 8, 0x1110).unwrap();
        c.p.vm
            .protect(stack + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        c.api = api("_register_onexit_function");
        let index = c.p.modules.by_name("ucrtbase.dll").unwrap();
        c.entry_pc = loader::lookup(
            c.p,
            index,
            &SymRef::Name(c.api.name.as_bytes().to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let (fault, retry) = retry((c.api.imp)(c));
        assert_eq!(
            fault,
            MemFault {
                addr: stack + PAGE_SIZE,
                write: false
            }
        );
        c.write_ptr(c.entry_sp + 4, other).unwrap();
        c.p.vm
            .protect(stack + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert_eq!(int(retry(c, 0)), 0);
        c.entry_sp = saved_sp;
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        assert_eq!(int(then(c, 0)), 0);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_execute_onexit_table",
                &[other]
            )),
            0
        );
    });
}
