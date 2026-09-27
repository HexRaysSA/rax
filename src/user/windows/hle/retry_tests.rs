//! Checked retry ownership and abandoned-frontier regressions.

use std::cell::Cell;
use std::rc::Rc;

use super::tests::{TEST_API, process};
use super::*;
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION, STATUS_STACK_OVERFLOW,
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
        retry: Some(retry),
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
