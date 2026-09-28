//! Checked retry ownership and abandoned-frontier regressions.

use std::cell::Cell;
use std::rc::Rc;

use super::tests::{TEST_API, process};
use super::*;
use crate::user::image::pe::DataDirectory;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::context::EXCEPTION_NONCONTINUABLE;
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_BAD_STACK, STATUS_GUARD_PAGE_VIOLATION, STATUS_STACK_OVERFLOW,
};

fn retry_frame(t: &Thread, retry: super::super::Cont) -> Frame {
    Frame {
        api: &TEST_API,
        entry_pc: 0xAB00,
        entry_sp: t.cpu.sp(),
        ret_addr: 0x1234_5000,
        cursor: t.cpu.sp() - 64,
        cont: None,
        checked_call: false,
        callback_sp: None,
        retry: Some(retry),
        dispatcher_setup_retries: 0,
        exception: Vec::new(),
        exception_caller: None,
    }
}

#[test]
fn repaired_frontier_uses_saved_site_not_clobbered_caller_state_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        let calls = Rc::new(Cell::new(0));
        let observed = calls.clone();
        let frame = retry_frame(
            &t,
            Box::new(move |c, argument| {
                assert_eq!(argument, 0);
                assert_eq!(c.entry_sp, sp);
                assert_eq!(c.cursor, sp - 64);
                assert_eq!(c.ret_addr, 0x1234_5000);
                assert!(std::ptr::eq(c.api, &TEST_API));
                observed.set(observed.get() + 1);
                Flow::ret(77)
            }),
        );
        t.frames.push(frame);
        t.cpu.set_pc(0xAB00);
        if arch == WinArch::Arm64 {
            t.cpu.set_gpr(30, 0x9999_9000);
        }
        p.space.wptr(sp, arch.ptr_size(), 0x9999_9000).unwrap();
        assert_eq!(enter(p, &mut t, &TEST_API, 0xAB00), Outcome::Continue);
        assert_eq!(calls.get(), 1);
        assert_eq!(t.cpu.pc(), 0x1234_5000);
        assert_eq!(t.cpu.gpr(0), 77);
        assert_eq!(
            t.cpu.sp(),
            sp + if arch == WinArch::Arm64 {
                0
            } else {
                arch.ptr_size()
            }
        );
        assert!(t.frames.is_empty());
    }
}

struct DropProbe(Rc<Cell<usize>>);
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn leaving_same_height_frontier_discards_retry_without_executing_it_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let drops = Rc::new(Cell::new(0));
        let probe = DropProbe(drops.clone());
        let frame = retry_frame(
            &t,
            Box::new(move |_, _| {
                let _ = &probe;
                panic!("abandoned retry must not execute");
            }),
        );
        let sp = frame.entry_sp;
        t.frames.push(frame);
        // A handler on a lower stack must not abandon the protected frontier.
        prune_same_height_frontier(&mut t, 0xFFFF, sp - 64);
        assert_eq!(drops.get(), 0);
        assert_eq!(t.frames.len(), 1);
        // CONTEXT restoration to another PC at the original SP abandons it.
        prune_same_height_frontier(&mut t, 0xFFFF, sp);
        assert_eq!(drops.get(), 1);
        assert!(t.frames.is_empty());
    }
}

#[test]
fn context_skip_at_original_stack_height_cannot_reuse_retry_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let frame = retry_frame(&t, Box::new(|_, _| panic!("skipped operation")));
        let sp = frame.entry_sp;
        t.frames.push(frame);
        let mut context = RegContext::capture(&t.cpu);
        context.set_pc(0xAB08);
        let site = CallSite {
            api: &TEST_API,
            entry_pc: 0xDC00,
            entry_sp: sp - 128,
            ret_addr: 0,
            cursor: sp - 160,
            framed: false,
        };
        assert_eq!(
            complete(p, &mut t, site, Ok(Flow::Resume(Box::new(context)))),
            Outcome::Continue
        );
        assert_eq!(t.cpu.pc(), 0xAB08);
        assert!(t.frames.is_empty());
    }
}

#[test]
fn checked_callback_setup_keeps_selected_call_across_repair_all_abis() {
    for arch in WinArch::ALL {
        for (protection, stack_guard, status) in [
            (prot::READONLY, false, STATUS_ACCESS_VIOLATION),
            (
                prot::READWRITE | prot::GUARD,
                false,
                STATUS_GUARD_PAGE_VIOLATION,
            ),
            (prot::READWRITE | prot::GUARD, true, STATUS_STACK_OVERFLOW),
        ] {
            let mut process = process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let (base, size) =
                p.vm.allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap();
            let page = base + 0x8000;
            t.stack_alloc = base;
            t.stack_base = base + size;
            t.stack_limit = if stack_guard { page + 0x1000 } else { base };
            p.vm.protect(page, 0x1000, protection).unwrap();
            let entry_sp = base + 0xF000;
            let site = CallSite {
                api: &TEST_API,
                entry_pc: 0xAB00,
                entry_sp,
                // A terminating synthetic unwind chain. A fabricated ARM64
                // LR with no caller metadata would correctly report a cycle.
                ret_addr: 0,
                // Nine x64 arguments require 88 bytes. Keep the complete
                // retry frame inside the consumed emergency guard page;
                // crossing below it would require repairing another frontier.
                cursor: page + 0x100,
                framed: false,
            };
            t.cpu.set_sp(entry_sp);
            t.cpu.set_pc(site.entry_pc);
            let drops = Rc::new(Cell::new(0));
            let probe = DropProbe(drops.clone());
            let calls = Rc::new(Cell::new(0));
            let observed = calls.clone();
            let result = Flow::call_checked(0x4321, (1..=9).collect(), move |c, result| {
                let _ = &probe;
                assert_eq!(result, 77);
                assert_eq!(c.entry_sp, entry_sp);
                assert_eq!(c.ret_addr, 0);
                observed.set(observed.get() + 1);
                Flow::ret(88)
            });
            // No handler is installed here. Inspect the checked receipt before
            // the scheduler applies the terminal outcome; compiled VEH probes
            // separately exercise actual guest repair/continuation.
            assert_eq!(
                complete(p, &mut t, site, result),
                Outcome::ProcessTerminate(status)
            );
            assert_eq!(drops.get(), 0);
            assert_eq!(calls.get(), 0);
            assert!(t.frames.last().unwrap().retry.is_some());
            p.vm.protect(page, 0x1000, prot::READWRITE).unwrap();
            t.cpu.set_sp(entry_sp);
            t.cpu.set_pc(site.entry_pc);
            for reg in [0, 1, 2, 8, 9] {
                t.cpu.set_gpr(reg, 0xBAD0);
            }
            p.space.wptr(entry_sp, arch.ptr_size(), 0xBAD0).unwrap();
            assert_eq!(
                enter(p, &mut t, &TEST_API, site.entry_pc),
                Outcome::Continue,
                "{arch:?}, protection={protection:#x}, stack_guard={stack_guard}"
            );
            assert_eq!(t.cpu.pc(), 0x4321);
            assert!(t.frames.last().unwrap().retry.is_none());
            assert!(t.frames.last().unwrap().cont.is_some());
            let callback_sp = t.cpu.sp();
            match arch {
                WinArch::X86 => {
                    for i in 0..9 {
                        assert_eq!(p.space.u32(callback_sp + 4 + i * 4).unwrap(), i as u32 + 1);
                    }
                }
                WinArch::X64 => {
                    for (i, reg) in [1, 2, 8, 9].into_iter().enumerate() {
                        assert_eq!(t.cpu.gpr(reg), i as u64 + 1);
                    }
                    assert_eq!(p.space.u64(callback_sp + 72).unwrap(), 9);
                }
                WinArch::Arm64 => {
                    for i in 0..8 {
                        assert_eq!(t.cpu.gpr(i), i as u64 + 1);
                    }
                    assert_eq!(p.space.u64(callback_sp).unwrap(), 9);
                }
            }
            assert_eq!(drops.get(), 0);
            t.cpu.set_gpr(0, 77);
            if arch != WinArch::Arm64 {
                t.cpu.set_sp(callback_sp + arch.ptr_size());
            }
            assert_eq!(callback_return(p, &mut t), Outcome::Continue);
            assert_eq!(calls.get(), 1);
            assert_eq!(drops.get(), 1);
            assert_eq!(t.cpu.gpr(0), 88);
            assert_eq!(t.cpu.pc(), 0);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn checked_callback_fault_abandonment_drops_owner_without_calling_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        let drops = Rc::new(Cell::new(0));
        let probe = DropProbe(drops.clone());
        let site = CallSite {
            api: &TEST_API,
            entry_pc: 0xAB00,
            entry_sp: sp,
            ret_addr: 0,
            cursor: 0,
            framed: false,
        };
        let result = Flow::call_checked(0x4321, vec![1; 9], move |_, _| {
            let _ = &probe;
            panic!("abandoned checked callback must not be fabricated");
        });
        assert_eq!(
            complete(p, &mut t, site, result),
            Outcome::ProcessTerminate(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(drops.get(), 0);
        assert!(t.frames.last().unwrap().retry.is_some());
        prune_same_height_frontier(&mut t, 0xCD00, sp);
        assert_eq!(drops.get(), 1);
        assert!(t.frames.is_empty());
    }
}

#[test]
fn same_height_context_escape_retires_successfully_started_callback_all_abis() {
    for arch in WinArch::ALL {
        for restored_pc in [0x1234_5000, 0xAB00] {
            let mut process = process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let sp = t.cpu.sp();
            let drops = Rc::new(Cell::new(0));
            let probe = DropProbe(drops.clone());
            let site = CallSite {
                api: &TEST_API,
                entry_pc: 0xAB00,
                entry_sp: sp,
                ret_addr: 0x1234_5000,
                cursor: sp - 64,
                framed: false,
            };
            let result = Flow::call_checked(0x4321, Vec::new(), move |_, _| {
                let _ = &probe;
                panic!("context escape cannot fabricate a callback return");
            });
            assert_eq!(complete(p, &mut t, site, result), Outcome::Continue);
            assert_eq!(drops.get(), 0);
            assert!(t.frames.last().unwrap().cont.is_some());
            let mut context = RegContext::capture(&t.cpu);
            context.set_sp(sp);
            context.set_pc(restored_pc);
            let restore = CallSite {
                api: &TEST_API,
                entry_pc: 0xCD00,
                entry_sp: sp - 128,
                ret_addr: 0,
                cursor: sp - 160,
                framed: false,
            };
            assert_eq!(
                complete(p, &mut t, restore, Ok(Flow::Resume(Box::new(context)))),
                Outcome::Continue
            );
            assert_eq!(drops.get(), 1);
            assert!(t.frames.is_empty());
            assert_eq!(t.cpu.pc(), restored_pc);
            assert_eq!(t.cpu.sp(), sp);
        }
    }
}

/// Places the original dispatcher records and x64 EHANDLER scratch above
/// `guard_page`, while its callback return-address write lands below it.
/// `guard_page - PAGE_SIZE` is deliberately not the stack-growth frontier.
fn x64_ehandler_setup_fixture(p: &mut Proc, t: &mut Thread, protection: u32) -> (u64, u64, u64) {
    let (stack, size) =
        p.vm.allocate(None, 0x1_0000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let guard_page = stack + 0x8000;
    t.stack_alloc = stack;
    t.stack_base = stack + size;
    t.stack_limit = stack;
    let image = p.modules.exe().base;
    p.vm.protect(image, p.modules.exe().size, prot::READWRITE)
        .unwrap();
    p.space.wr(image + 0x10, &[0x90; 0x70]).unwrap();
    p.space.w32(image + 0x1000, 0x10).unwrap();
    p.space.w32(image + 0x1004, 0x80).unwrap();
    p.space.w32(image + 0x1008, 0x1800).unwrap();
    p.space.wr(image + 0x1800, &[9, 0, 0, 0]).unwrap();
    p.space.w32(image + 0x1804, 0x400).unwrap();
    p.modules.list[0].pdata = DataDirectory {
        rva: 0x1000,
        size: 12,
    };
    let veh = image + 0x500;
    p.seh.veh.push((1, veh));
    let original_sp = guard_page + 0xAD0;
    t.cpu.set_sp(original_sp);
    t.cpu.set_pc(image + 0x40);
    p.space.w64(original_sp, 0).unwrap();
    p.vm.protect(guard_page - PAGE_SIZE, PAGE_SIZE, protection)
        .unwrap();
    (guard_page, image + 0x400, veh)
}

fn return_x64_callback(p: &mut Proc, t: &mut Thread, value: u64) -> Outcome {
    t.cpu.set_gpr(0, value);
    t.cpu.set_sp(t.cpu.sp() + 8);
    t.cpu.set_pc(p.traps.callback_return());
    callback_return(p, t)
}

#[test]
fn x64_ehandler_callback_guard_fault_veh_repair_preserves_selected_handler() {
    let mut process = process(WinArch::X64);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (guard_page, ehandler, veh) =
        x64_ehandler_setup_fixture(p, &mut t, prot::READWRITE | prot::GUARD);
    let original_pc = t.cpu.pc();
    let original_sp = t.cpu.sp();
    let original = RegContext::capture(&t.cpu);
    assert_eq!(
        seh::raise(
            p,
            &mut t,
            ExceptionRecord::new(0xE123_4567, original_pc, Vec::new()),
            original
        ),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh, "first VEH sees the original exception");
    let pointers = t.cpu.gpr(1);
    let original_record = p.space.u64(pointers).unwrap();
    let original_context = p.space.u64(pointers + 8).unwrap();
    let record_before = p
        .space
        .bytes(
            original_record,
            ExceptionRecord::size(WinArch::X64) as usize,
        )
        .unwrap();
    let context_before = p
        .space
        .bytes(original_context, RegContext::size(WinArch::X64))
        .unwrap();

    // Return ExceptionContinueSearch from the first VEH. The table search
    // selects the EHANDLER, then its x64 callback-return write crosses into
    // the one-shot nonstack guard. A second VEH must see that setup fault.
    assert_eq!(
        return_x64_callback(p, &mut t, 0),
        Outcome::Continue,
        "the selected EHANDLER continuation must survive setup repair"
    );
    assert_eq!(t.cpu.pc(), veh, "second VEH sees callback setup fault");
    let nested_pointers = t.cpu.gpr(1);
    let nested_record = ExceptionRecord::read(
        &p.space,
        WinArch::X64,
        p.space.u64(nested_pointers).unwrap(),
    )
    .unwrap();
    assert_eq!(nested_record.code, STATUS_GUARD_PAGE_VIOLATION);
    assert_eq!(nested_record.params[0], 1, "callback setup was a write");
    assert!(
        (guard_page - PAGE_SIZE..guard_page).contains(&nested_record.params[1]),
        "fault address must be in the protected callback page"
    );
    assert_eq!(
        p.vm.query(guard_page - PAGE_SIZE).unwrap().protect,
        prot::READWRITE,
        "nonstack guard is consumed exactly once"
    );
    assert_eq!(
        p.space
            .bytes(
                original_record,
                ExceptionRecord::size(WinArch::X64) as usize
            )
            .unwrap(),
        record_before,
        "nested dispatch must not overwrite original EXCEPTION_RECORD"
    );
    assert_eq!(
        p.space
            .bytes(original_context, RegContext::size(WinArch::X64))
            .unwrap(),
        context_before,
        "nested dispatch must not overwrite original CONTEXT"
    );
    let outer = &t.frames[0];
    assert!(std::ptr::eq(outer.api, &seh::DISPATCHER));
    assert!(outer.retry.is_some(), "selected call remains owned");
    assert_eq!(outer.cursor, guard_page + 0x10);
    assert_eq!(p.space.u64(outer.cursor).unwrap(), original_pc);
    assert_eq!(p.space.u64(outer.cursor + 0x30).unwrap(), ehandler);

    // The repair VEH continues the nested fault at the private retry
    // frontier. Re-entering that retained dispatcher starts exactly the
    // originally selected EHANDLER, then its disposition resumes the fault.
    assert_eq!(return_x64_callback(p, &mut t, u64::MAX), Outcome::Continue);
    let retry_pc = t.cpu.pc();
    assert_ne!(retry_pc, 0);
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), ehandler);
    assert_eq!(return_x64_callback(p, &mut t, 0), Outcome::Continue);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty(), "completed dispatcher must not linger");
}

#[test]
fn x64_ehandler_callback_persistent_setup_fault_is_bounded() {
    let mut process = process(WinArch::X64);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (guard_page, ehandler, veh) = x64_ehandler_setup_fixture(p, &mut t, prot::READONLY);
    let original = RegContext::capture(&t.cpu);
    assert_eq!(
        seh::raise(
            p,
            &mut t,
            ExceptionRecord::new(0xE123_4567, original.pc(), Vec::new()),
            original
        ),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh);
    let pointers = t.cpu.gpr(1);
    let record = p.space.u64(pointers).unwrap();
    let before = p
        .space
        .bytes(record, ExceptionRecord::size(WinArch::X64) as usize)
        .unwrap();
    let outcome = return_x64_callback(p, &mut t, 0);
    assert!(
        matches!(
            outcome,
            Outcome::Fail(_) | Outcome::ProcessTerminate(STATUS_BAD_STACK)
        ),
        "persistent fault must end without recursive host dispatch: {outcome:?}"
    );
    assert_ne!(t.cpu.pc(), ehandler);
    assert_eq!(
        p.vm.query(guard_page - PAGE_SIZE).unwrap().protect,
        prot::READONLY
    );
    assert_eq!(
        p.space
            .bytes(record, ExceptionRecord::size(WinArch::X64) as usize)
            .unwrap(),
        before
    );
}

#[test]
fn arm64_four_register_callback_args_need_no_stack_write() {
    let mut process = process(WinArch::Arm64);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (stack, size) =
        p.vm.allocate(None, 0x1_0000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let page = stack + 0x8000;
    t.stack_alloc = stack;
    t.stack_limit = stack;
    t.stack_base = stack + size;
    p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
    let site = CallSite {
        api: &TEST_API,
        entry_pc: 0xAB00,
        entry_sp: page + 0x800,
        ret_addr: 0,
        cursor: page + 0x10,
        framed: false,
    };
    assert_eq!(
        complete(
            p,
            &mut t,
            site,
            Flow::call(0x4321, vec![1, 2, 3, 4], |_, _| { Flow::void() })
        ),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), 0x4321);
    assert_eq!(t.cpu.sp(), page + 0x10);
    assert_eq!(p.vm.query(page).unwrap().protect, prot::READONLY);
}

#[test]
fn private_dispatcher_retry_trap_rejects_fresh_and_resume_half_entries() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let retry_pc = p.traps.dispatcher_retry();
        assert_ne!(retry_pc, 0, "{arch:?}");
        assert!(matches!(
            p.traps.lookup(retry_pc),
            Some(crate::user::windows::traps::Trap::DispatcherRetry)
        ));
        assert!(p.traps.lookup(retry_pc + 8).is_none());
        assert!(p.traps.address_of(&seh::DISPATCHER).is_none());
        for pc in [retry_pc, retry_pc + 8] {
            t.cpu.set_pc(pc);
            let before = RegContext::capture(&t.cpu);
            assert!(
                matches!(dispatcher_retry(p, &mut t, pc), Outcome::Fail(message)
                    if message.contains("no matching checked callback")),
                "{arch:?}, pc={pc:#x}"
            );
            assert_eq!(RegContext::capture(&t.cpu), before);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn x64_dispatcher_retry_is_abandoned_when_nested_veh_changes_context_pc_or_sp() {
    for change_sp in [false, true] {
        let mut process = process(WinArch::X64);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let (_guard_page, ehandler, veh) =
            x64_ehandler_setup_fixture(p, &mut t, prot::READWRITE | prot::GUARD);
        let original_pc = t.cpu.pc();
        let original_sp = t.cpu.sp();
        let original = RegContext::capture(&t.cpu);
        assert_eq!(
            seh::raise(
                p,
                &mut t,
                ExceptionRecord::new(0xE123_4567, original_pc, Vec::new()),
                original
            ),
            Outcome::Continue
        );
        assert_eq!(t.cpu.pc(), veh);
        assert_eq!(return_x64_callback(p, &mut t, 0), Outcome::Continue);
        assert_eq!(t.cpu.pc(), veh, "second VEH sees setup guard fault");
        let retry_sp = t.frames[0].entry_sp;
        assert!(t.frames[0].retry.is_some());
        let pointers = t.cpu.gpr(1);
        let context_at = p.space.u64(pointers + 8).unwrap();
        let mut context = RegContext::read(&p.space, WinArch::X64, context_at).unwrap();
        assert_eq!(context.pc(), p.traps.dispatcher_retry());
        assert_eq!(context.sp(), retry_sp);
        context.set_pc(original_pc);
        context.set_sp(if change_sp { original_sp } else { retry_sp });
        context.write(&p.space, context_at).unwrap();
        assert_eq!(return_x64_callback(p, &mut t, u64::MAX), Outcome::Continue);
        assert_eq!(t.cpu.pc(), original_pc);
        assert_eq!(t.cpu.sp(), if change_sp { original_sp } else { retry_sp });
        assert!(
            t.frames.is_empty(),
            "abandoned checked call must be dropped"
        );
        assert_ne!(t.cpu.pc(), ehandler);
        let retry_pc = p.traps.dispatcher_retry();
        assert!(matches!(
            dispatcher_retry(p, &mut t, retry_pc),
            Outcome::Fail(_)
        ));
    }
}

#[test]
fn x64_rearmed_dispatcher_callback_guard_faults_stop_before_fifth_nested_dispatch() {
    let mut process = process(WinArch::X64);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (guard_page, ehandler, veh) =
        x64_ehandler_setup_fixture(p, &mut t, prot::READWRITE | prot::GUARD);
    let original = RegContext::capture(&t.cpu);
    assert_eq!(
        seh::raise(
            p,
            &mut t,
            ExceptionRecord::new(0xE123_4567, original.pc(), Vec::new()),
            original
        ),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh);
    let pointers = t.cpu.gpr(1);
    let record = p.space.u64(pointers).unwrap();
    let original_record = p
        .space
        .bytes(record, ExceptionRecord::size(WinArch::X64) as usize)
        .unwrap();
    assert_eq!(return_x64_callback(p, &mut t, 0), Outcome::Continue);

    // The initial guard fault and three repaired/rearmed retries are allowed.
    // Rearming after each nested VEH continuation forces the same selected
    // EHANDLER setup to fault again without ever starting that guest handler.
    for fault_number in 1..=4u8 {
        assert_eq!(t.cpu.pc(), veh, "fault {fault_number} must reach VEH");
        let nested_pointers = t.cpu.gpr(1);
        let nested_record = ExceptionRecord::read(
            &p.space,
            WinArch::X64,
            p.space.u64(nested_pointers).unwrap(),
        )
        .unwrap();
        assert_eq!(nested_record.code, STATUS_GUARD_PAGE_VIOLATION);
        assert_eq!(t.frames[0].dispatcher_setup_retries, fault_number);
        assert!(t.frames[0].retry.is_some());
        assert_ne!(t.cpu.pc(), ehandler);
        assert_eq!(
            p.space
                .bytes(record, ExceptionRecord::size(WinArch::X64) as usize)
                .unwrap(),
            original_record,
            "fault {fault_number} must preserve the original record"
        );

        assert_eq!(return_x64_callback(p, &mut t, u64::MAX), Outcome::Continue);
        let retry_pc = p.traps.dispatcher_retry();
        assert_eq!(t.cpu.pc(), retry_pc);
        p.vm.protect(
            guard_page - PAGE_SIZE,
            PAGE_SIZE,
            prot::READWRITE | prot::GUARD,
        )
        .unwrap();
        let outcome = dispatcher_retry(p, &mut t, retry_pc);
        if fault_number < 4 {
            assert_eq!(outcome, Outcome::Continue);
        } else {
            assert!(
                matches!(outcome, Outcome::Fail(_)),
                "fifth fault: {outcome:?}"
            );
            assert_ne!(t.cpu.pc(), ehandler);
            assert_ne!(t.cpu.pc(), veh, "fifth nested VEH must not start");
            assert_eq!(t.frames[0].dispatcher_setup_retries, 4);
            assert_eq!(
                p.space
                    .bytes(record, ExceptionRecord::size(WinArch::X64) as usize)
                    .unwrap(),
                original_record
            );
        }
    }
}

#[test]
fn x64_nested_guard_search_bridges_pending_dispatcher_retry_to_ehandler_rax_profile() {
    let mut process = process(WinArch::X64);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (guard_page, ehandler, veh) =
        x64_ehandler_setup_fixture(p, &mut t, prot::READWRITE | prot::GUARD);
    let original_pc = t.cpu.pc();
    let original = RegContext::capture(&t.cpu);
    let original_sp = original.sp();
    assert_eq!(
        seh::raise(
            p,
            &mut t,
            ExceptionRecord::new(0xE123_4567, original_pc, Vec::new()),
            original
        ),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh);
    let original_pointers = t.cpu.gpr(1);
    let original_record_at = p.space.u64(original_pointers).unwrap();
    let original_context_at = p.space.u64(original_pointers + 8).unwrap();
    let original_record = p
        .space
        .bytes(
            original_record_at,
            ExceptionRecord::size(WinArch::X64) as usize,
        )
        .unwrap();
    let original_context = p
        .space
        .bytes(original_context_at, RegContext::size(WinArch::X64))
        .unwrap();
    assert_eq!(return_x64_callback(p, &mut t, 0), Outcome::Continue);
    assert_eq!(t.cpu.pc(), veh, "guard setup fault reaches repair VEH");
    let nested_pointers = t.cpu.gpr(1);
    let nested_record_at = p.space.u64(nested_pointers).unwrap();
    assert_eq!(
        ExceptionRecord::read(&p.space, WinArch::X64, nested_record_at)
            .unwrap()
            .code,
        STATUS_GUARD_PAGE_VIOLATION
    );
    let original_scratch = t.frames[0].cursor;
    assert_eq!(original_scratch, guard_page + 0x10);
    assert!(t.frames[0].retry.is_some());

    // RAX profile: declining the nested guard exception searches past the
    // exact pending private retry frontier to the original caller frame.
    // This does not assert native Windows nested-handler precedence.
    assert_eq!(return_x64_callback(p, &mut t, 0), Outcome::Continue);
    assert_eq!(t.cpu.pc(), ehandler);
    assert_eq!(t.cpu.gpr(1), nested_record_at);
    assert_eq!(
        t.cpu.gpr(2),
        original_sp,
        "nested search bridged to caller frame"
    );
    let nested_dc = t.cpu.gpr(9);
    assert_eq!(p.space.u64(nested_dc).unwrap(), original_pc);
    assert_eq!(p.space.u64(nested_dc + 0x18).unwrap(), original_sp);
    assert_eq!(
        t.frames.len(),
        2,
        "outer and nested dispatchers remain owned"
    );
    assert!(std::ptr::eq(t.frames[0].api, &seh::DISPATCHER));
    assert!(
        t.frames[0].retry.is_some(),
        "outer selected call is not consumed"
    );
    assert_eq!(t.frames[0].cursor, original_scratch);
    assert_eq!(p.space.u64(original_scratch).unwrap(), original_pc);
    assert_eq!(p.space.u64(original_scratch + 0x30).unwrap(), ehandler);
    assert_eq!(
        p.space
            .bytes(
                original_record_at,
                ExceptionRecord::size(WinArch::X64) as usize
            )
            .unwrap(),
        original_record
    );
    assert_eq!(
        p.space
            .bytes(original_context_at, RegContext::size(WinArch::X64))
            .unwrap(),
        original_context
    );
}

#[test]
fn x64_repaired_dispatcher_rejects_unsupported_ehandler_raise_without_scratch_search() {
    for (flags, disposition) in [(0, 0xBADu64), (EXCEPTION_NONCONTINUABLE, 0u64)] {
        let mut process = process(WinArch::X64);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let (_guard_page, ehandler, veh) =
            x64_ehandler_setup_fixture(p, &mut t, prot::READWRITE | prot::GUARD);
        let original = RegContext::capture(&t.cpu);
        let mut record = ExceptionRecord::new(0xE123_4567, original.pc(), Vec::new());
        record.flags = flags;
        assert_eq!(seh::raise(p, &mut t, record, original), Outcome::Continue);
        assert_eq!(t.cpu.pc(), veh);
        let pointers = t.cpu.gpr(1);
        let original_record_at = p.space.u64(pointers).unwrap();
        let original_record = p
            .space
            .bytes(
                original_record_at,
                ExceptionRecord::size(WinArch::X64) as usize,
            )
            .unwrap();
        assert_eq!(return_x64_callback(p, &mut t, 0), Outcome::Continue);
        assert_eq!(t.cpu.pc(), veh, "guard setup fault reaches repair VEH");
        assert_eq!(return_x64_callback(p, &mut t, u64::MAX), Outcome::Continue);
        let retry_pc = t.cpu.pc();
        assert_eq!(retry_pc, p.traps.dispatcher_retry());
        assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
        assert_eq!(t.cpu.pc(), ehandler);

        // Invalid disposition and noncontinuable ContinueExecution both ask
        // the synthetic dispatcher to raise another exception. Once rebased
        // to private retry scratch, RAX fails closed rather than treating the
        // retry slot's +8 byte or DC words as a guest return/unwind frame.
        let outcome = return_x64_callback(p, &mut t, disposition);
        assert!(
            matches!(outcome, Outcome::Fail(_)),
            "flags={flags:#x}, disposition={disposition:#x}: {outcome:?}"
        );
        assert!(
            t.frames
                .iter()
                .all(|frame| frame.cont.is_none() && frame.callback_sp.is_none()),
            "fail-closed return must not publish another guest callback"
        );
        assert_eq!(
            p.space
                .bytes(
                    original_record_at,
                    ExceptionRecord::size(WinArch::X64) as usize
                )
                .unwrap(),
            original_record,
            "original exception record must remain intact"
        );
    }
}
