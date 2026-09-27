//! Genuine export frontiers and shared-lock behavior, all three guest ABIs.

use std::time::Instant;

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::dll::crt::tests::{area, int, invoke, run};
use crate::user::windows::hle::{Cont, Item, Value};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{Mem, MemFault, prot};
use crate::user::windows::sync;

fn queues(c: &Ctx) -> TerminationState {
    c.p.crt.runtimes[RuntimeKind::Ucrt.index()]
        .termination
        .clone()
}

fn add(c: &mut Ctx, name: &str, target: u64) {
    assert_eq!(int(invoke(c, RuntimeKind::Ucrt, name, &[target])), 0);
}

fn take(c: &mut Ctx, kind: Kind) -> Vec<u64> {
    let mut drain = queues(c).begin(kind, c.t.tid).unwrap();
    let mut result = Vec::new();
    while let Some(target) = drain.next(c.p).unwrap() {
        result.push(target);
    }
    drain.finish(c.p).unwrap();
    result
}

fn call(result: ApiResult, expected: u64) -> Cont {
    match result.unwrap() {
        Flow::CallChecked { target, args, then } => {
            assert_eq!(target, expected);
            assert!(args.is_empty());
            then
        }
        _ => panic!("checked callback"),
    }
}

fn retry(result: ApiResult) -> (MemFault, Cont) {
    match result.unwrap() {
        Flow::RetryFault { fault, retry } => (fault, retry),
        _ => panic!("retained fault frontier"),
    }
}

fn table(c: &mut Ctx, target: u64) -> u64 {
    let table = area(c);
    assert_eq!(
        int(invoke(
            c,
            RuntimeKind::Ucrt,
            "_initialize_onexit_table",
            &[table]
        )),
        0
    );
    assert_eq!(
        int(invoke(
            c,
            RuntimeKind::Ucrt,
            "_register_onexit_function",
            &[table, target]
        )),
        0
    );
    table
}

#[test]
fn genuine_named_bindings_and_unadmitted_termination_all_abis() {
    run(|c| {
        for dll in [
            "ucrtbase.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "msvcrt.dll",
        ] {
            let index = loader::load_dll(c.p, dll).unwrap();
            for name in ["_crt_atexit", "_crt_at_quick_exit"] {
                let target =
                    loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap();
                assert_eq!(target.is_some(), dll != "msvcrt.dll", "{dll}!{name}");
            }
            for name in [
                "atexit",
                "at_quick_exit",
                "_onexit",
                "exit",
                "_exit",
                "_Exit",
                "_cexit",
                "_c_exit",
                "quick_exit",
                "_register_thread_local_exe_atexit_callback",
            ] {
                assert!(
                    loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap()
                        .is_none(),
                    "{dll}!{name}"
                );
            }
        }
        for export in UCRT_REGISTRATION_EXPORTS {
            let Item::Func(api) = &export.item else {
                panic!("function descriptor")
            };
            assert_eq!(api.conv, Cdecl);
            assert_eq!(api.args, &[Ptr]);
        }
    });
}

#[test]
fn global_null_duplicate_and_separate_lifo_queues_all_abis() {
    run(|c| {
        for (name, values) in [
            ("_crt_atexit", &[0x1110, 0, 0x2220, 0x1110][..]),
            ("_crt_at_quick_exit", &[0x3330, 0, 0x4440][..]),
        ] {
            for &value in values {
                add(c, name, value);
            }
        }
        assert_eq!(take(c, Kind::Quick), [0x4440, 0x3330]);
        assert_eq!(take(c, Kind::Ordinary), [0x1110, 0x2220, 0x1110]);
        assert!(take(c, Kind::Ordinary).is_empty());
        add(c, "_crt_atexit", 0x5550);
        assert_eq!(take(c, Kind::Ordinary), [0x5550]);
    });
}

#[test]
fn global_private_storage_is_not_malloc_ledger_all_abis() {
    run(|c| {
        let heap = state::ensure_heap(c, RuntimeKind::Ucrt).unwrap();
        let before = c.p.heaps.blocks(heap);
        add(c, "_crt_atexit", 0x1110);
        let after = c.p.heaps.blocks(heap);
        let block = *after.iter().find(|block| !before.contains(block)).unwrap();
        assert_eq!(block.1, 32 * c.psize());
        assert!(
            !c.p.crt.runtimes[RuntimeKind::Ucrt.index()]
                .allocations
                .contains_key(&block.0)
        );
        assert_eq!(take(c, Kind::Ordinary), [0x1110]);
        assert_eq!(c.p.heaps.blocks(heap), before);
    });
}

#[test]
fn registration_fault_retains_target_across_formal_clobber_all_abis() {
    run(|c| {
        let heap = state::ensure_heap(c, RuntimeKind::Ucrt).unwrap();
        let before = c.p.heaps.blocks(heap);
        add(c, "_crt_atexit", 0x1110);
        let (base, _) =
            *c.p.heaps
                .blocks(heap)
                .iter()
                .find(|block| !before.contains(block))
                .unwrap();
        let page = base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let (fault, retry) = retry(invoke(c, RuntimeKind::Ucrt, "_crt_atexit", &[0x2220]));
        assert!(fault.write);
        assert_eq!(fault.addr, base + c.psize());
        // Re-entering a different runtime and replacing all formal inputs must
        // not affect the captured registration or release its original lock.
        assert_eq!(
            int(invoke(c, RuntimeKind::Msvcrt, "_errno", &[])) != 0,
            true
        );
        c.mem().w32(c.entry_sp + 4, 0x3330).unwrap();
        for index in 0..9 {
            c.t.cpu.set_gpr(index, 0x3330);
        }
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(int(retry(c, 0)), 0);
        assert_eq!(take(c, Kind::Ordinary), [0x2220, 0x1110]);
    });
}

#[test]
fn expected_first_allocation_oom_returns_negative_and_unlocks_all_abis() {
    run(|c| {
        let heap = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
        c.p.crt.runtimes[RuntimeKind::Ucrt.index()].heap = heap;
        let filler =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, heap, PAGE_SIZE - 0x100, false)
                .unwrap();
        let before = c.p.heaps.blocks(heap);
        assert_eq!(
            int(invoke(c, RuntimeKind::Ucrt, "_crt_atexit", &[0x1110])),
            u64::from(u32::MAX)
        );
        assert_eq!(c.p.heaps.blocks(heap), before);
        assert!(take(c, Kind::Ordinary).is_empty());
        c.p.heaps.free(heap, filler).unwrap();
        let original = c.t.tid;
        c.t.tid += 1;
        add(c, "_crt_at_quick_exit", 0x2220);
        c.t.tid = original;
        assert_eq!(take(c, Kind::Quick), [0x2220]);
    });
}

#[test]
fn explicit_callback_can_register_both_global_kinds_recursively_all_abis() {
    run(|c| {
        let table = table(c, 0x1110);
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        add(c, "_crt_atexit", 0x2220);
        add(c, "_crt_at_quick_exit", 0x3330);
        assert_eq!(int(then(c, u64::MAX)), 0);
        assert_eq!(take(c, Kind::Ordinary), [0x2220]);
        assert_eq!(take(c, Kind::Quick), [0x3330]);
    });
}

#[test]
fn nested_explicit_drain_holds_runtime_lock_until_outer_return_all_abis() {
    run(|c| {
        let outer = table(c, 0x1110);
        let inner = table(c, 0x2220);
        let outer_then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[outer]),
            0x1110,
        );
        let inner_then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[inner]),
            0x2220,
        );
        assert_eq!(int(inner_then(c, 0)), 0);
        let owner = c.t.tid;
        c.t.tid += 1;
        let blocked = invoke(c, RuntimeKind::Ucrt, "_crt_atexit", &[0x3330]).unwrap();
        c.t.tid = owner;
        assert!(matches!(blocked, Flow::Block { .. }));
        assert_eq!(int(outer_then(c, 0)), 0);
        if let Flow::Block { then, .. } = blocked {
            assert_eq!(int(then(c, 0)), 0);
        }
        assert_eq!(take(c, Kind::Ordinary), [0x3330]);
    });
}

#[test]
fn other_thread_can_initialize_independent_table_while_exit_lock_is_held_all_abis() {
    run(|c| {
        let outer = table(c, 0x1110);
        let independent = area(c);
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[outer]),
            0x1110,
        );
        let owner = c.t.tid;
        c.t.tid += 1;
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "_initialize_onexit_table",
                &[independent]
            )),
            0
        );
        for index in 0..3 {
            assert_eq!(c.read_ptr(independent + index * c.psize()).unwrap(), 0);
        }
        assert!(matches!(
            invoke(
                c,
                RuntimeKind::Ucrt,
                "_register_onexit_function",
                &[independent, 0x2220]
            )
            .unwrap(),
            Flow::Block { .. }
        ));
        c.t.tid = owner;
        assert_eq!(int(then(c, 0)), 0);
    });
}

#[test]
fn different_thread_registration_parks_and_retries_captured_target_all_abis() {
    run(|c| {
        let table = table(c, 0x1110);
        let owner_then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        let owner = c.t.tid;
        let worker = owner + 1;
        c.t.tid = worker;
        let (wait, worker_then) =
            match invoke(c, RuntimeKind::Ucrt, "_crt_at_quick_exit", &[0x2220]).unwrap() {
                Flow::Block { wait, then } => (wait, then),
                _ => panic!("different thread must park"),
            };
        sync::on_block(c.p, worker, &wait).unwrap();
        assert_eq!(
            sync::poll(c.p, worker, &wait, Instant::now(), false).unwrap(),
            None
        );
        c.t.tid = owner;
        add(c, "_crt_atexit", 0x3330);
        assert_eq!(
            sync::poll(c.p, worker, &wait, Instant::now(), false).unwrap(),
            None
        );
        assert_eq!(int(owner_then(c, 0)), 0);
        assert_eq!(
            sync::poll(c.p, worker, &wait, Instant::now(), false).unwrap(),
            Some(0)
        );
        sync::on_cancel(c.p, worker, &wait).unwrap();
        c.t.tid = worker;
        c.mem().w32(c.entry_sp + 4, 0x4440).unwrap();
        for index in 0..9 {
            c.t.cpu.set_gpr(index, 0x4440);
        }
        assert_eq!(int(worker_then(c, 0)), 0);
        c.t.tid = owner;
        assert_eq!(take(c, Kind::Quick), [0x2220]);
        assert_eq!(take(c, Kind::Ordinary), [0x3330]);
    });
}

#[test]
fn runtime_locks_do_not_alias_each_other_or_guest_address_waits_all_abis() {
    run(|c| {
        let unrelated = c.t.tid + 2;
        let guest_wait = sync::Wait::Address {
            key: 1,
            deadline: None,
        };
        sync::on_block(c.p, unrelated, &guest_wait).unwrap();
        let table = table(c, 0x1110);
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        let owner = c.t.tid;
        c.t.tid += 1;
        assert!(matches!(
            with_lock(c, RuntimeKind::Msvcrt, Box::new(|_, _| Flow::ret(7))).unwrap(),
            Flow::Ret(Value::Int(7))
        ));
        c.t.tid = owner;
        assert_eq!(int(then(c, 0)), 0);
        assert_eq!(
            sync::poll(c.p, unrelated, &guest_wait, Instant::now(), false).unwrap(),
            None
        );
        sync::on_cancel(c.p, unrelated, &guest_wait).unwrap();
    });
}

#[test]
fn terminal_abandonment_releases_guard_without_global_callback_execution_all_abis() {
    run(|c| {
        add(c, "_crt_atexit", 0x3330);
        let table = table(c, 0x1110);
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        drop(then);
        super::super::onexit::cleanup_abandoned(c.p, Some(c.t.tid)).unwrap();
        cleanup_abandoned(c.p, Some(c.t.tid)).unwrap();
        let owner = c.t.tid;
        c.t.tid += 1;
        add(c, "_crt_atexit", 0x4440);
        c.t.tid = owner;
        assert_eq!(take(c, Kind::Ordinary), [0x4440, 0x3330]);
        cleanup_abandoned(c.p, Some(owner)).unwrap();
    });
}

#[test]
fn nonterminal_abandonment_reports_unfinished_lock_and_reaps_it_all_abis() {
    run(|c| {
        let table = table(c, 0x1110);
        let then = call(
            invoke(c, RuntimeKind::Ucrt, "_execute_onexit_table", &[table]),
            0x1110,
        );
        drop(then);
        assert!(
            super::super::onexit::cleanup_abandoned(c.p, None)
                .unwrap_err()
                .contains("continuation abandoned")
        );
        assert!(
            cleanup_abandoned(c.p, None)
                .unwrap_err()
                .contains("exit lock continuation abandoned")
        );
        let owner = c.t.tid;
        c.t.tid += 1;
        add(c, "_crt_atexit", 0x2220);
        c.t.tid = owner;
        assert_eq!(take(c, Kind::Ordinary), [0x2220]);
    });
}

#[test]
fn raw_process_discard_frees_queues_without_accessing_noaccess_slots_all_abis() {
    run(|c| {
        let heap = state::ensure_heap(c, RuntimeKind::Ucrt).unwrap();
        let before = c.p.heaps.blocks(heap);
        add(c, "_crt_atexit", 0x1110);
        add(c, "_crt_at_quick_exit", 0x2220);
        let blocks = c.p.heaps.blocks(heap);
        let private: Vec<_> = blocks
            .iter()
            .filter(|block| !before.contains(block))
            .copied()
            .collect();
        assert_eq!(private.len(), 2);
        for &(base, _) in &private {
            c.p.vm
                .protect(base & !(PAGE_SIZE - 1), PAGE_SIZE, prot::NOACCESS)
                .unwrap();
        }
        discard_process(c.p).unwrap();
        discard_process(c.p).unwrap();
        for &(base, _) in &private {
            assert_eq!(c.p.heaps.owner(base), None);
        }
        assert_eq!(c.p.heaps.blocks(heap), before);
    });
}
