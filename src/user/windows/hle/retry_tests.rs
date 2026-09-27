//! Checked retry ownership and abandoned-frontier regressions.

use std::cell::Cell;
use std::rc::Rc;

use super::tests::{TEST_API, process};
use super::*;

fn retry_frame(t: &Thread, retry: super::super::Cont) -> Frame {
    Frame {
        api: &TEST_API,
        entry_pc: 0xAB00,
        entry_sp: t.cpu.sp(),
        ret_addr: 0x1234_5000,
        cursor: t.cpu.sp() - 64,
        cont: None,
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
        prune_retry_frontier(&mut t, 0xFFFF, sp - 64);
        assert_eq!(drops.get(), 0);
        assert_eq!(t.frames.len(), 1);
        // CONTEXT restoration to another PC at the original SP abandons it.
        prune_retry_frontier(&mut t, 0xFFFF, sp);
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
