//! Synthetic scopes use actual smoke-process memory/TEB/stack mappings.

use std::cell::Cell;
use std::rc::Rc;

use super::*;
use crate::user::windows::hle::dispatch::{self, CallSite, Outcome};
use crate::user::windows::hle::{Api, Flow, Frame};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::{STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use crate::user::windows::seh::{self, Records, disposition};

const CPP: u32 = 0xE06D_7363;
static API: Api = Api {
    name: "synthetic-protection-test",
    args: &[],
    conv: Conv::Cdecl,
    imp: |_| Flow::void(),
};

fn process(arch: WinArch) -> WindowsProcess {
    let image: &[u8] = match arch {
        WinArch::X86 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
        WinArch::X64 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::Arm64 => {
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut cfg = WindowsConfig::new("synthetic-protection.exe", Vec::new());
    cfg.seed = Some(1);
    cfg.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap()
}

fn with_context(arch: WinArch, test: impl FnOnce(&mut Ctx)) {
    let mut process = process(arch);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let sp = t.cpu.sp() - 0x2000;
    test(&mut Ctx {
        p,
        t: &mut t,
        api: &seh::DISPATCHER,
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp - 32,
    });
}

fn owner(sp: u64, cursor: u64, callback_sp: Option<u64>) -> Frame {
    Frame {
        api: &API,
        entry_pc: 0xAB00,
        entry_sp: sp,
        ret_addr: 0x4560,
        cursor,
        cont: Some(Box::new(|_, _| {
            panic!("exception search is not a callback return")
        })),
        checked_call: true,
        callback_sp,
        exception_caller: None,
        retry: None,
        dispatcher_setup_retries: 0,
        exception: Vec::new(),
    }
}

fn records(c: &mut Ctx, code: u32, context: &RegContext) -> (ExceptionRecord, Records) {
    let at = c
        .stack_alloc_checked(ExceptionRecord::size(c.p.arch), 16)
        .unwrap();
    let context_at = c
        .stack_alloc_checked(RegContext::size(c.p.arch) as u64, 16)
        .unwrap();
    let pointers = c.stack_alloc_checked(2 * c.psize(), 16).unwrap();
    let rec = ExceptionRecord::new(code, context.pc(), Vec::new());
    rec.write(&c.p.space, c.p.arch, at).unwrap();
    context.write(&c.p.space, context_at).unwrap();
    c.write_ptr(pointers, at).unwrap();
    c.write_ptr(pointers + c.psize(), context_at).unwrap();
    (
        rec,
        Records {
            record: at,
            context: context_at,
            pointers,
        },
    )
}

struct DropProbe(Rc<Cell<usize>>);
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn normal_protected_callbacks_keep_scope_until_owner_returns_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        let site = CallSite {
            api: &API,
            entry_pc: 0xAB00,
            entry_sp: sp,
            ret_addr: 0x4560,
            cursor: sp - 64,
            framed: false,
        };
        let drops = Rc::new(Cell::new(0));
        let probe = DropProbe(drops.clone());
        let result = Flow::Protected {
            code: Some(CPP),
            handler: Box::new(move |_, _| {
                let _ = &probe;
                panic!("normal callback")
            }),
            then: Box::new(move |c, input| {
                assert_eq!(input, 0);
                assert_eq!(c.t.frames.len(), 1);
                assert_eq!(c.t.frames[0].exception.len(), 1);
                Flow::call_checked(0x1234, vec![7], |_, value| Flow::ret(value + 1))
            }),
        };
        assert_eq!(
            dispatch::complete(p, &mut t, site, Ok(result)),
            Outcome::Continue
        );
        assert_eq!(drops.get(), 0);
        let callback_sp = t.frames[0].callback_sp.unwrap();
        t.cpu.set_sp(
            callback_sp
                + if arch == WinArch::X86 {
                    8
                } else if arch == WinArch::X64 {
                    8
                } else {
                    0
                },
        );
        t.cpu.set_gpr(0, 17);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x4560);
        assert_eq!(t.cpu.gpr(0), 18);
        assert_eq!(drops.get(), 1);
        assert!(t.frames.is_empty());
    }
}

#[test]
fn selected_handler_disables_itself_and_does_not_drop_pending_owners_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let sp = c.t.cpu.sp();
            let calls = Rc::new(Cell::new(0));
            let observed = calls.clone();
            let mut frame = owner(sp, sp - 64, Some(sp - 128));
            let drops = Rc::new(Cell::new(0));
            let probe = DropProbe(drops.clone());
            frame.cont = Some(Box::new(move |_, _| {
                let _ = &probe;
                panic!("pending owner")
            }));
            frame.exception.push(ExceptionBoundary::new(
                Some(CPP),
                sp - 64,
                Box::new(move |c, code| {
                    assert!(std::ptr::eq(c.api, &seh::DISPATCHER));
                    assert_eq!(code, u64::from(CPP));
                    assert!(c.t.frames[0].cont.is_some());
                    assert!(c.t.frames[0].exception[0].handler.is_none());
                    observed.set(observed.get() + 1);
                    Ok(Flow::TerminateProcess(91))
                }),
            ));
            c.t.frames.push(frame);
            let rec = ExceptionRecord::new(CPP, 0x1234, Vec::new());
            let result = x86(c, &rec, u64::MAX, &mut Search::default())
                .unwrap()
                .unwrap();
            assert!(matches!(
                result.invoke(c).unwrap(),
                Flow::TerminateProcess(91)
            ));
            assert_eq!(calls.get(), 1);
            assert_eq!(drops.get(), 0);
            // A fresh recursive exception search cannot call the disabled one.
            assert!(
                x86(c, &rec, u64::MAX, &mut Search::default())
                    .unwrap()
                    .is_none()
            );
            c.t.frames.clear();
            assert_eq!(drops.get(), 1);
        });
    }
}

#[test]
fn exact_filters_skip_unrelated_codes_and_nest_inner_first_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let sp = c.t.cpu.sp();
            let mut outer = owner(sp, sp - 64, None);
            outer.exception.push(ExceptionBoundary::new(
                None,
                sp - 64,
                Box::new(|_, code| Flow::ret(code + 1)),
            ));
            let mut inner = owner(sp - 256, sp - 320, None);
            inner.exception.push(ExceptionBoundary::new(
                Some(CPP),
                sp - 320,
                Box::new(|_, code| Flow::ret(code + 2)),
            ));
            c.t.frames.extend([outer, inner]);
            let rec = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0, Vec::new());
            let result = x86(c, &rec, u64::MAX, &mut Search::default())
                .unwrap()
                .unwrap()
                .invoke(c)
                .unwrap();
            assert!(
                matches!(result, Flow::Ret(super::super::Value::Int(value)) if value == u64::from(rec.code) + 1)
            );
            assert!(c.t.frames[1].exception[0].handler.is_some());
            let rec = ExceptionRecord::new(CPP, 0, Vec::new());
            let result = x86(c, &rec, u64::MAX, &mut Search::default())
                .unwrap()
                .unwrap()
                .invoke(c)
                .unwrap();
            assert!(
                matches!(result, Flow::Ret(super::super::Value::Int(value)) if value == u64::from(CPP) + 2)
            );
        });
    }
}

#[test]
fn x86_inner_guest_registration_precedes_boundary_and_outer_record_follows_decline() {
    for code in [CPP, STATUS_ACCESS_VIOLATION] {
        with_context(WinArch::X86, |c| {
            let sp = c.t.cpu.sp();
            let cursor = sp - 0x100;
            let inner_record = cursor - 0x100;
            let outer_record = cursor + 0x40;
            let target = c.p.modules.exe().entry;
            c.p.modules.list[0].no_seh = false;
            c.p.modules.list[0].safe_seh = None;
            c.p.space.w32(inner_record, outer_record as u32).unwrap();
            c.p.space.w32(inner_record + 4, target as u32).unwrap();
            c.p.space
                .w32(outer_record, seh::x86::CHAIN_END as u32)
                .unwrap();
            c.p.space.w32(outer_record + 4, target as u32).unwrap();
            c.p.space
                .w32(
                    c.t.teb + offsets(WinArch::X86).teb_exception_list,
                    inner_record as u32,
                )
                .unwrap();
            let mut frame = owner(sp, cursor, Some(cursor - 4));
            frame.exception.push(ExceptionBoundary::new(
                Some(CPP),
                cursor,
                Box::new(|_, _| Ok(Flow::TerminateProcess(91))),
            ));
            c.t.frames.push(frame);
            let context = RegContext::capture(&c.t.cpu);
            let (rec, recs) = records(c, code, &context);
            let Flow::CallChecked {
                target: handler,
                args,
                then,
            } = seh::x86::dispatch(c, rec, recs).unwrap()
            else {
                panic!("inner registration first")
            };
            assert_eq!(handler, target);
            assert_eq!(args[1], inner_record);
            assert!(c.t.frames[0].exception[0].handler.is_some());
            let result = then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap();
            if code == CPP {
                let Flow::CallChecked { args, then, .. } = result else {
                    panic!("inner unwind registration before selected handler")
                };
                assert_eq!(args[1], inner_record);
                assert_eq!(
                    c.p.space.u32(recs.record + 4).unwrap()
                        & crate::user::windows::context::EXCEPTION_UNWINDING,
                    crate::user::windows::context::EXCEPTION_UNWINDING
                );
                assert!(c.t.frames[0].exception[0].handler.is_none());
                assert!(matches!(
                    then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap(),
                    Flow::TerminateProcess(91)
                ));
                assert_eq!(
                    c.p.space
                        .u32(c.t.teb + offsets(WinArch::X86).teb_exception_list)
                        .unwrap(),
                    outer_record as u32
                );
                assert!(c.t.frames[0].cont.is_some());
            } else {
                assert!(
                    matches!(result, Flow::CallChecked { args, .. } if args[1] == outer_record)
                );
                assert!(c.t.frames[0].exception[0].handler.is_some());
            }
        });
    }
}

#[test]
fn table_sentinel_bridges_unprotected_owner_without_fabricating_callback_return() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        with_context(arch, |c| {
            let sp = c.t.cpu.sp();
            let mut frame = owner(sp, sp - 64, Some(sp - 128));
            frame.exception.push(ExceptionBoundary::new(
                Some(CPP),
                sp - 64,
                Box::new(|_, _| panic!("unrelated code")),
            ));
            c.t.frames.push(frame);
            let mut ctx = RegContext::capture(&c.t.cpu);
            ctx.set_pc(c.p.traps.callback_return());
            ctx.set_sp(sp - 128 + if arch == WinArch::X64 { 8 } else { 0 });
            let rec = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0, Vec::new());
            let mut walk = Search::default();
            assert!(matches!(
                table(c, &rec, &mut ctx, &mut walk).unwrap(),
                Crossing::Bridged
            ));
            assert_eq!(ctx.pc(), 0x4560);
            assert_eq!(ctx.sp(), sp + if arch == WinArch::X64 { 8 } else { 0 });
            assert!(c.t.frames[0].cont.is_some());
            assert!(c.t.frames[0].exception[0].handler.is_some());
            c.t.frames[0].exception.clear();
            ctx.set_pc(c.p.traps.callback_return());
            ctx.set_sp(sp - 128 + if arch == WinArch::X64 { 8 } else { 0 });
            assert!(matches!(
                table(c, &rec, &mut ctx, &mut Search::default()).unwrap(),
                Crossing::Bridged
            ));
            ctx.set_pc(c.p.traps.callback_return());
            ctx.set_sp(sp - 128 + if arch == WinArch::X64 { 8 } else { 0 });
            assert!(matches!(
                table(c, &rec, &mut ctx, &mut walk),
                Err(ApiErr::Internal(_))
            ));
        });
    }
}

#[test]
fn table_bridges_only_exact_pending_dispatcher_retry_frontier() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        with_context(arch, |c| {
            let retry_pc = c.p.traps.dispatcher_retry();
            assert_ne!(retry_pc, 0);
            let retry_sp = c.t.cpu.sp() - 0x100;
            let caller = RegContext::capture(&c.t.cpu);
            let mut frame = owner(retry_sp, retry_sp, None);
            frame.api = &seh::DISPATCHER;
            frame.entry_pc = retry_pc;
            frame.ret_addr = 0;
            frame.cont = None;
            frame.retry = Some(Box::new(|_, _| Flow::void()));
            frame.exception_caller = Some(Box::new(caller.clone()));
            c.t.frames.push(frame);
            let rec = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, retry_pc, Vec::new());
            let mut ctx = caller.clone();
            ctx.set_pc(retry_pc);
            ctx.set_sp(retry_sp);
            assert!(matches!(
                table(c, &rec, &mut ctx, &mut Search::default()).unwrap(),
                Crossing::Bridged
            ));
            assert_eq!(ctx, caller);

            for pc in [retry_pc + 8, retry_pc - 8] {
                let mut wrong = caller.clone();
                wrong.set_pc(pc);
                wrong.set_sp(retry_sp);
                assert!(matches!(
                    table(c, &rec, &mut wrong, &mut Search::default()).unwrap(),
                    Crossing::None
                ));
                assert_eq!(wrong.pc(), pc);
                assert_eq!(wrong.sp(), retry_sp);
            }
            let mut wrong = caller;
            wrong.set_pc(retry_pc);
            wrong.set_sp(retry_sp + 16);
            assert!(matches!(
                table(c, &rec, &mut wrong, &mut Search::default()).unwrap(),
                Crossing::None
            ));
        });
    }
}

#[test]
fn table_inner_language_handler_precedes_synthetic_boundary() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        with_context(arch, |c| {
            let base = c.p.modules.exe().base;
            let size = c.p.modules.exe().size;
            c.p.vm.protect(base, size, prot::READWRITE).unwrap();
            c.p.space.wr(base + 0x10, &[0x90; 0x70]).unwrap();
            c.p.space.w32(base + 0x1000, 0x10).unwrap();
            if arch == WinArch::X64 {
                c.p.space.w32(base + 0x1004, 0x80).unwrap();
                c.p.space.w32(base + 0x1008, 0x1800).unwrap();
                c.p.space.wr(base + 0x1800, &[25, 0, 0, 0]).unwrap();
                c.p.space.w32(base + 0x1804, 0x400).unwrap();
            } else {
                c.p.space.w32(base + 0x1004, 0x1800).unwrap();
                c.p.space
                    .w32(base + 0x1800, 64 | (1 << 20) | (1 << 27))
                    .unwrap();
                c.p.space.wr(base + 0x1804, &[0xE4, 0, 0, 0]).unwrap();
                c.p.space.w32(base + 0x1808, 0x400).unwrap();
            }
            c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                rva: 0x1000,
                size: if arch == WinArch::X64 { 12 } else { 8 },
            };
            let sp = c.t.cpu.sp();
            let callback_sp = sp - 128;
            let mut frame = owner(sp, sp - 64, Some(callback_sp));
            frame.exception.push(ExceptionBoundary::new(
                Some(CPP),
                sp - 64,
                Box::new(|_, _| Ok(Flow::TerminateProcess(91))),
            ));
            c.t.frames.push(frame);
            let mut context = RegContext::capture(&c.t.cpu);
            context.set_pc(base + 0x40);
            context.set_sp(callback_sp);
            if arch == WinArch::X64 {
                c.p.space
                    .w64(callback_sp, c.p.traps.callback_return())
                    .unwrap();
            } else {
                context.set_gpr(30, c.p.traps.callback_return());
            }
            let (rec, recs) = records(c, CPP, &context);
            let Flow::CallChecked { target, then, .. } =
                seh::unwind::dispatch(c, rec, recs).unwrap()
            else {
                panic!("inner language handler first")
            };
            assert_eq!(target, base + 0x400);
            assert!(c.t.frames[0].exception[0].handler.is_some());
            let Flow::CallChecked { target, args, then } =
                then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap()
            else {
                panic!("inner termination handler before selected handler")
            };
            assert_eq!(target, base + 0x400);
            assert_eq!(
                c.p.space.u32(recs.record + 4).unwrap()
                    & crate::user::windows::context::EXCEPTION_UNWINDING,
                crate::user::windows::context::EXCEPTION_UNWINDING
            );
            assert_eq!(c.p.space.u64(args[3]).unwrap(), base + 0x40);
            assert_eq!(c.p.space.u64(args[3] + 0x28).unwrap(), args[2]);
            assert!(c.t.frames[0].exception[0].handler.is_none());
            assert!(matches!(
                then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap(),
                Flow::TerminateProcess(91)
            ));
            assert!(c.t.frames[0].cont.is_some());
        });
    }
}

#[test]
fn prune_and_fiber_switch_move_or_drop_scope_ownership_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let sp = c.t.cpu.sp();
            let original = crate::user::windows::process::fiber::convert(c.p, c.t, 0, 1).unwrap();
            let other = crate::user::windows::process::fiber::create(
                c.p, c.t, 0x10000, 0x1000, 1, 0x1234, 0,
            )
            .unwrap();
            let drops = Rc::new(Cell::new(0));
            let probe = DropProbe(drops.clone());
            let mut frame = owner(sp, sp - 64, None);
            frame.exception.push(ExceptionBoundary::new(
                None,
                sp - 64,
                Box::new(move |_, _| {
                    let _ = &probe;
                    Flow::void()
                }),
            ));
            c.t.frames.push(frame);
            crate::user::windows::process::fiber::switch(c.p, c.t, other).unwrap();
            assert_eq!(drops.get(), 0);
            assert!(c.t.frames.is_empty());
            crate::user::windows::process::fiber::switch(c.p, c.t, original).unwrap();
            assert_eq!(c.t.frames[0].exception.len(), 1);
            assert_eq!(drops.get(), 0);
            dispatch::prune(c.t, sp + 1);
            assert!(c.t.frames.is_empty());
            assert_eq!(drops.get(), 1);
        });
    }
}

#[test]
fn callback_setup_av_and_guard_are_not_cpp_and_repair_keeps_protected_capture_all_abis() {
    for arch in WinArch::ALL {
        for (protection, code) in [
            (prot::READONLY, STATUS_ACCESS_VIOLATION),
            (prot::READWRITE | prot::GUARD, STATUS_GUARD_PAGE_VIOLATION),
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
            t.stack_limit = base;
            t.stack_base = base + size;
            let sp = base + 0xF000;
            t.cpu.set_sp(sp);
            t.cpu.set_pc(0xAB00);
            p.space.wptr(sp, arch.ptr_size(), 0x4560).unwrap();
            p.vm.protect(page, 0x1000, protection).unwrap();
            p.seh.veh.push((1, 0x9870));
            let site = CallSite {
                api: &API,
                entry_pc: 0xAB00,
                entry_sp: sp,
                ret_addr: 0x4560,
                cursor: page + 0x100,
                framed: false,
            };
            let result = Flow::Protected {
                code: Some(CPP),
                handler: Box::new(|_, _| panic!("AV/guard is not CPP")),
                then: Box::new(|_, _| {
                    Flow::call_checked(0x1234, vec![7; 9], |_, value| Flow::ret(value + 1))
                }),
            };
            assert_eq!(
                dispatch::complete(p, &mut t, site, Ok(result)),
                Outcome::Continue
            );
            assert!(t.frames[0].retry.is_some());
            assert_eq!(t.frames[0].exception.len(), 1);
            let record_pointer = if arch == WinArch::X86 {
                p.space.u32(t.cpu.sp() + 4).unwrap().into()
            } else {
                t.cpu.gpr(if arch == WinArch::X64 { 1 } else { 0 })
            };
            let record = p.space.ptr(record_pointer, arch.ptr_size()).unwrap();
            assert_eq!(p.space.u32(record).unwrap(), code);
            p.vm.protect(page, 0x1000, prot::READWRITE).unwrap();
            let callback_sp = t.frames.last().unwrap().callback_sp.unwrap();
            t.cpu.set_sp(
                callback_sp
                    + if arch == WinArch::X86 {
                        8
                    } else if arch == WinArch::X64 {
                        8
                    } else {
                        0
                    },
            );
            t.cpu.set_gpr(0, u32::MAX.into());
            assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.pc(), site.entry_pc);
            assert_eq!(t.cpu.sp(), sp);
            assert_eq!(
                dispatch::enter(p, &mut t, &API, site.entry_pc),
                Outcome::Continue
            );
            let callback_sp = t.frames[0].callback_sp.unwrap();
            t.cpu.set_sp(
                callback_sp
                    + if arch == WinArch::X86 {
                        40
                    } else if arch == WinArch::X64 {
                        8
                    } else {
                        0
                    },
            );
            t.cpu.set_gpr(0, 17);
            assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 18);
            assert_eq!(t.cpu.pc(), 0x4560);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn protected_wait_keeps_scope_until_wait_continuation_completes_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        let site = CallSite {
            api: &API,
            entry_pc: 0xAB00,
            entry_sp: sp,
            ret_addr: 0x4560,
            cursor: sp - 64,
            framed: false,
        };
        let drops = Rc::new(Cell::new(0));
        let probe = DropProbe(drops.clone());
        let result = Flow::Protected {
            code: None,
            handler: Box::new(move |_, _| {
                let _ = &probe;
                panic!("normal wait")
            }),
            then: Box::new(|_, _| {
                Flow::block(
                    crate::user::windows::sync::Wait::Sleep {
                        deadline: None,
                        alertable: true,
                    },
                    |_, status| Flow::ret(status + 1),
                )
            }),
        };
        assert_eq!(
            dispatch::complete(p, &mut t, site, Ok(result)),
            Outcome::Park
        );
        assert_eq!(t.frames[0].exception.len(), 1);
        assert!(t.frames[0].callback_sp.is_none());
        assert_eq!(drops.get(), 0);
        crate::user::windows::sync::on_cancel(
            p,
            tid,
            &crate::user::windows::sync::Wait::Sleep {
                deadline: None,
                alertable: true,
            },
        )
        .unwrap();
        assert_eq!(dispatch::wait_complete(p, &mut t, 17), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 18);
        assert_eq!(t.cpu.pc(), 0x4560);
        assert!(t.frames.is_empty());
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn veh_continue_precedes_matching_scope_and_resume_trap_retires_it_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp();
        p.space.wptr(sp, arch.ptr_size(), 0x4560).unwrap();
        let site = CallSite {
            api: &API,
            entry_pc: 0xAB00,
            entry_sp: sp,
            ret_addr: 0x4560,
            cursor: sp - 64,
            framed: false,
        };
        p.seh.veh.push((1, 0x9870));
        let drops = Rc::new(Cell::new(0));
        let probe = DropProbe(drops.clone());
        let result = Flow::Protected {
            code: Some(CPP),
            handler: Box::new(move |_, _| {
                let _ = &probe;
                panic!("VEH continues first")
            }),
            then: Box::new(|_, _| Ok(Flow::Raise(ExceptionRecord::new(CPP, 0, Vec::new())))),
        };
        assert_eq!(
            dispatch::complete(p, &mut t, site, Ok(result)),
            Outcome::Continue
        );
        assert_eq!(drops.get(), 0);
        let callback_sp = t.frames.last().unwrap().callback_sp.unwrap();
        t.cpu
            .set_sp(callback_sp + if arch == WinArch::Arm64 { 0 } else { 8 });
        t.cpu.set_gpr(0, u32::MAX.into());
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), site.entry_pc + RESUME_OFFSET);
        assert_eq!(t.frames.len(), 1);
        assert_eq!(dispatch::resume_return(p, &mut t, &API), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x4560);
        assert!(t.frames.is_empty());
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn nested_dispatcher_containment_disables_each_filter_then_searches_real_outer_handler_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let sp = t.cpu.sp() - 0x1000;
        t.cpu.set_sp(sp);
        let base = p.modules.exe().base;
        let handler = if arch == WinArch::X86 {
            let handler = p.modules.exe().entry;
            p.modules.list[0].no_seh = false;
            p.modules.list[0].safe_seh = None;
            let registration = sp + 0x80;
            p.space
                .w32(registration, seh::x86::CHAIN_END as u32)
                .unwrap();
            p.space.w32(registration + 4, handler as u32).unwrap();
            p.space
                .w32(
                    t.teb + offsets(arch).teb_exception_list,
                    registration as u32,
                )
                .unwrap();
            handler
        } else {
            let size = p.modules.exe().size;
            p.vm.protect(base, size, prot::READWRITE).unwrap();
            p.space.wr(base + 0x10, &[0x90; 0x70]).unwrap();
            p.space.w32(base + 0x1000, 0x10).unwrap();
            if arch == WinArch::X64 {
                p.space.w32(base + 0x1004, 0x80).unwrap();
                p.space.w32(base + 0x1008, 0x1800).unwrap();
                p.space.wr(base + 0x1800, &[9, 0, 0, 0]).unwrap();
                p.space.w32(base + 0x1804, 0x400).unwrap();
                p.space.w64(sp + 8, 0).unwrap();
            } else {
                p.space.w32(base + 0x1004, 0x1800).unwrap();
                p.space
                    .w32(base + 0x1800, 64 | (1 << 20) | (1 << 27))
                    .unwrap();
                p.space.wr(base + 0x1804, &[0xE4, 0, 0, 0]).unwrap();
                p.space.w32(base + 0x1808, 0x400).unwrap();
            }
            p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                rva: 0x1000,
                size: if arch == WinArch::X64 { 12 } else { 8 },
            };
            base + 0x400
        };
        let site = CallSite {
            api: &API,
            entry_pc: 0xAB00,
            entry_sp: sp,
            ret_addr: base + 0x40,
            cursor: sp - 64,
            framed: false,
        };
        let hits = Rc::new(Cell::new(0));
        let observed = hits.clone();
        let drops = Rc::new(Cell::new(0));
        let probe = DropProbe(drops.clone());
        let protected = Flow::Protected {
            code: Some(CPP),
            handler: Box::new(move |_, code| {
                assert_eq!(code, u64::from(CPP));
                Ok(Flow::Protected {
                    code: None,
                    handler: Box::new(move |_, code| {
                        assert_eq!(code, u64::from(STATUS_ACCESS_VIOLATION));
                        observed.set(observed.get() + 1);
                        Flow::call_checked(0x8760, Vec::new(), |_, _| {
                            panic!("recursive callback did not return")
                        })
                    }),
                    then: Box::new(|_, _| {
                        Flow::call_checked(0x5670, Vec::new(), |_, _| {
                            panic!("terminate-like callback did not return")
                        })
                    }),
                })
            }),
            then: Box::new(move |_, _| {
                Flow::call_checked(0x1230, Vec::new(), move |_, _| {
                    let _ = &probe;
                    panic!("exit-like callback did not return")
                })
            }),
        };
        assert_eq!(
            dispatch::complete(p, &mut t, site, Ok(protected)),
            Outcome::Continue
        );
        // Synthetic leaf callbacks really return to the callback trap in their
        // prepared stack/LR; raise from each actual prepared register context.
        let ctx = RegContext::capture(&t.cpu);
        assert_eq!(
            seh::raise(
                p,
                &mut t,
                ExceptionRecord::new(CPP, ctx.pc(), Vec::new()),
                ctx
            ),
            Outcome::Continue
        );
        assert_eq!(t.cpu.pc(), 0x5670);
        assert_eq!(drops.get(), 0);
        let ctx = RegContext::capture(&t.cpu);
        assert_eq!(
            seh::raise(
                p,
                &mut t,
                ExceptionRecord::new(STATUS_ACCESS_VIOLATION, ctx.pc(), Vec::new()),
                ctx
            ),
            Outcome::Continue
        );
        assert_eq!(t.cpu.pc(), 0x8760);
        assert_eq!(hits.get(), 1);
        assert_eq!(drops.get(), 0);
        let ctx = RegContext::capture(&t.cpu);
        assert_eq!(
            seh::raise(
                p,
                &mut t,
                ExceptionRecord::new(STATUS_ACCESS_VIOLATION, ctx.pc(), Vec::new()),
                ctx
            ),
            Outcome::Continue
        );
        assert_eq!(t.cpu.pc(), handler);
        assert_eq!(hits.get(), 1, "disabled inner filter must not catch itself");
        assert_eq!(
            drops.get(),
            0,
            "search must not drop the pending exit owner"
        );
        assert!(t.frames[0].cont.is_some());
        t.frames.clear();
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn selected_unwind_runs_inner_cleanup_before_handler_and_preserves_outer_all_abis() {
    use crate::user::windows::context::EXCEPTION_UNWINDING;
    use std::cell::RefCell;

    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let sp = c.t.cpu.sp();
            let cursor = sp - 64;
            let callback_sp = sp - 128;
            let base = c.p.modules.exe().base;
            let inner = base + 0x400;
            let outer = base + 0x600;
            let inner_record = cursor - 0x100;
            // The smoke entry SP is near StackBase: keep the caller record
            // above the scope cursor but below the actual mapped stack top.
            let outer_record = cursor + 32;
            if arch == WinArch::X86 {
                c.p.modules.list[0].no_seh = false;
                c.p.modules.list[0].safe_seh = None;
                c.p.space.w32(inner_record, outer_record as u32).unwrap();
                c.p.space.w32(inner_record + 4, inner as u32).unwrap();
                c.p.space
                    .w32(outer_record, seh::x86::CHAIN_END as u32)
                    .unwrap();
                c.p.space.w32(outer_record + 4, outer as u32).unwrap();
                c.p.space
                    .w32(
                        c.t.teb + offsets(arch).teb_exception_list,
                        inner_record as u32,
                    )
                    .unwrap();
            } else {
                c.p.vm
                    .protect(base, c.p.modules.exe().size, prot::READWRITE)
                    .unwrap();
                for (index, begin, unwind, handler) in
                    [(0, 0x10, 0x1800, 0x400), (1, 0x210, 0x1900, 0x600)]
                {
                    let entry_size = if arch == WinArch::X64 { 12 } else { 8 };
                    let entry = base + 0x1000 + index * entry_size;
                    c.p.space.wr(base + begin, &[0x90; 0x70]).unwrap();
                    c.p.space.w32(entry, begin as u32).unwrap();
                    if arch == WinArch::X64 {
                        c.p.space.w32(entry + 4, (begin + 0x70) as u32).unwrap();
                        c.p.space.w32(entry + 8, unwind as u32).unwrap();
                        c.p.space.wr(base + unwind, &[25, 0, 0, 0]).unwrap();
                        c.p.space.w32(base + unwind + 4, handler).unwrap();
                    } else {
                        c.p.space.w32(entry + 4, unwind as u32).unwrap();
                        c.p.space
                            .w32(base + unwind, 64 | (1 << 20) | (1 << 27))
                            .unwrap();
                        c.p.space.wr(base + unwind + 4, &[0xE4, 0, 0, 0]).unwrap();
                        c.p.space.w32(base + unwind + 8, handler).unwrap();
                    }
                }
                c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                    rva: 0x1000,
                    size: if arch == WinArch::X64 { 24 } else { 16 },
                };
            }
            let trace = Rc::new(RefCell::new(Vec::new()));
            let handler_trace = trace.clone();
            let mut frame = owner(sp, cursor, Some(callback_sp));
            frame.ret_addr = base + 0x240;
            frame.exception.push(ExceptionBoundary::new(
                None,
                cursor,
                Box::new(move |c, code| {
                    assert!(std::ptr::eq(c.api, &seh::DISPATCHER));
                    assert_eq!(code, u64::from(CPP));
                    assert_eq!(&*handler_trace.borrow(), &[1, 2]);
                    assert!(c.t.frames[0].cont.is_some());
                    handler_trace.borrow_mut().push(3);
                    Ok(Flow::TerminateProcess(91))
                }),
            ));
            c.t.frames.push(frame);
            let mut context = RegContext::capture(&c.t.cpu);
            context.set_pc(base + 0x40);
            context.set_sp(callback_sp);
            if arch == WinArch::X64 {
                c.p.space
                    .w64(callback_sp, c.p.traps.callback_return())
                    .unwrap();
            } else if arch == WinArch::Arm64 {
                context.set_gpr(30, c.p.traps.callback_return());
            }
            let (rec, recs) = records(c, CPP, &context);
            let first = if arch == WinArch::X86 {
                seh::x86::dispatch(c, rec, recs)
            } else {
                seh::unwind::dispatch(c, rec, recs)
            }
            .unwrap();
            let (target, then) = match first {
                Flow::CallChecked { target, then, .. } => (target, then),
                _ => panic!("guest inner search first"),
            };
            assert_eq!(target, inner);
            trace.borrow_mut().push(1);
            let Flow::CallChecked { target, args, then } =
                then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap()
            else {
                panic!("guest inner cleanup before selected handler")
            };
            assert_eq!(target, inner);
            trace.borrow_mut().push(2);
            assert_ne!(c.p.space.u32(args[0] + 4).unwrap() & EXCEPTION_UNWINDING, 0);
            assert!(c.t.frames[0].exception[0].handler.is_none());

            // A recursive exception during cleanup searches guest handlers,
            // but cannot select the already-disabled synthetic catch again.
            let (nested, nested_recs) = records(c, CPP, &context);
            let nested = if arch == WinArch::X86 {
                seh::x86::dispatch(c, nested, nested_recs)
            } else {
                seh::unwind::dispatch(c, nested, nested_recs)
            }
            .unwrap();
            let (target, nested_then) = match nested {
                Flow::CallChecked { target, then, .. } => (target, then),
                _ => panic!("recursive inner search"),
            };
            assert_eq!(target, inner);
            let (target, nested_args) =
                match nested_then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap() {
                    Flow::CallChecked { target, args, .. } => (target, args),
                    _ => panic!("disabled catch must permit outer search"),
                };
            assert_eq!(target, outer);
            if arch == WinArch::X86 {
                assert_eq!(nested_args[1], outer_record);
            }

            assert!(matches!(
                then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap(),
                Flow::TerminateProcess(91)
            ));
            assert_eq!(&*trace.borrow(), &[1, 2, 3]);
            if arch == WinArch::X86 {
                assert_eq!(
                    c.p.space
                        .u32(c.t.teb + offsets(arch).teb_exception_list)
                        .unwrap(),
                    outer_record as u32
                );
            }
            assert!(c.t.frames[0].cont.is_some());
        });
    }
}

#[test]
fn selected_unwind_data_fault_is_terminal_without_veh_or_owner_drop_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let sp = c.t.cpu.sp();
            let callback_sp = sp - 128;
            let owner_drops = Rc::new(Cell::new(0));
            let owner_probe = DropProbe(owner_drops.clone());
            let selected_drops = Rc::new(Cell::new(0));
            let selected_probe = DropProbe(selected_drops.clone());
            let mut frame = owner(sp, sp - 64, Some(callback_sp));
            frame.cont = Some(Box::new(move |_, _| {
                let _ = &owner_probe;
                panic!("the protected operation must not be completed")
            }));
            frame.exception.push(ExceptionBoundary::new(
                Some(CPP),
                sp - 64,
                Box::new(move |_, _| {
                    let _ = &selected_probe;
                    panic!("failed cleanup must not invoke the selected handler")
                }),
            ));
            c.t.frames.push(frame);
            let mut context = RegContext::capture(&c.t.cpu);
            context.set_pc(c.p.traps.callback_return());
            context.set_sp(callback_sp + if arch == WinArch::X64 { 8 } else { 0 });
            if arch == WinArch::X86 {
                c.p.space
                    .w32(
                        c.t.teb + offsets(arch).teb_exception_list,
                        seh::x86::CHAIN_END as u32,
                    )
                    .unwrap();
            }
            let (rec, recs) = records(c, CPP, &context);
            let record_page = recs.record & !4095;
            // Keep dispatcher's new CONTEXT/DC allocations on another page,
            // so only the checked write after selecting the scope faults.
            c.cursor = record_page - 4096;
            c.p.vm.protect(record_page, 4096, prot::READONLY).unwrap();
            c.p.seh.veh.push((1, 0x9870));
            let result = if arch == WinArch::X86 {
                seh::x86::dispatch(c, rec, recs)
            } else {
                seh::unwind::dispatch(c, rec, recs)
            };
            let Err(ApiErr::Fault(fault)) = result else {
                panic!("the selected-unwind record write must fail")
            };
            assert_eq!(fault.addr, recs.record + 4);
            assert!(fault.write);
            assert!(c.t.frames[0].exception[0].handler.is_none());
            assert_eq!(selected_drops.get(), 1);
            assert_eq!(owner_drops.get(), 0);
            let site = CallSite {
                api: &seh::DISPATCHER,
                entry_pc: c.entry_pc,
                entry_sp: c.entry_sp,
                ret_addr: 0,
                cursor: c.cursor,
                framed: false,
            };
            let before_pc = c.t.cpu.pc();
            let outcome = dispatch::complete(c.p, c.t, site, Err(ApiErr::Fault(fault)));
            assert!(
                matches!(outcome, Outcome::Fail(ref message) if message.contains("exception dispatch cannot redispatch its own fault"))
            );
            assert_eq!(c.t.cpu.pc(), before_pc, "no invented VEH repair callback");
            assert_eq!(c.t.frames.len(), 1);
            assert!(c.t.frames[0].cont.is_some());
            assert_eq!(owner_drops.get(), 0);
            // The terminal scheduler owns disposal, represented explicitly
            // here; diagnosis itself did not abandon the protected guard.
            c.t.frames.clear();
            assert_eq!(owner_drops.get(), 1);
        });
    }
}

#[test]
fn selected_unwind_rejects_nonsearch_dispositions_without_handler_or_owner_drop_all_abis() {
    for arch in WinArch::ALL {
        for rejected in [
            disposition::CONTINUE_EXECUTION,
            disposition::NESTED_EXCEPTION,
            disposition::COLLIDED_UNWIND,
        ] {
            with_context(arch, |c| {
                let sp = c.t.cpu.sp();
                let callback_sp = sp - 128;
                let cursor = sp - 64;
                let base = c.p.modules.exe().base;
                let handler = base + 0x400;
                let inner_record = cursor - 0x100;
                if arch == WinArch::X86 {
                    c.p.modules.list[0].no_seh = false;
                    c.p.modules.list[0].safe_seh = None;
                    c.p.space
                        .w32(inner_record, seh::x86::CHAIN_END as u32)
                        .unwrap();
                    c.p.space.w32(inner_record + 4, handler as u32).unwrap();
                    c.p.space
                        .w32(
                            c.t.teb + offsets(arch).teb_exception_list,
                            inner_record as u32,
                        )
                        .unwrap();
                } else {
                    c.p.vm
                        .protect(base, c.p.modules.exe().size, prot::READWRITE)
                        .unwrap();
                    c.p.space.wr(base + 0x10, &[0x90; 0x70]).unwrap();
                    c.p.space.w32(base + 0x1000, 0x10).unwrap();
                    if arch == WinArch::X64 {
                        c.p.space.w32(base + 0x1004, 0x80).unwrap();
                        c.p.space.w32(base + 0x1008, 0x1800).unwrap();
                        c.p.space.wr(base + 0x1800, &[25, 0, 0, 0]).unwrap();
                        c.p.space.w32(base + 0x1804, 0x400).unwrap();
                    } else {
                        c.p.space.w32(base + 0x1004, 0x1800).unwrap();
                        c.p.space
                            .w32(base + 0x1800, 64 | (1 << 20) | (1 << 27))
                            .unwrap();
                        c.p.space.wr(base + 0x1804, &[0xE4, 0, 0, 0]).unwrap();
                        c.p.space.w32(base + 0x1808, 0x400).unwrap();
                    }
                    c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                        rva: 0x1000,
                        size: if arch == WinArch::X64 { 12 } else { 8 },
                    };
                }
                let drops = Rc::new(Cell::new(0));
                let probe = DropProbe(drops.clone());
                let calls = Rc::new(Cell::new(0));
                let observed = calls.clone();
                let mut frame = owner(sp, cursor, Some(callback_sp));
                frame.cont = Some(Box::new(move |_, _| {
                    let _ = &probe;
                    panic!("unfinished protected operation")
                }));
                frame.exception.push(ExceptionBoundary::new(
                    Some(CPP),
                    cursor,
                    Box::new(move |_, _| {
                        observed.set(observed.get() + 1);
                        Ok(Flow::TerminateProcess(91))
                    }),
                ));
                c.t.frames.push(frame);
                let mut context = RegContext::capture(&c.t.cpu);
                context.set_pc(base + 0x40);
                context.set_sp(callback_sp);
                if arch == WinArch::X64 {
                    c.p.space
                        .w64(callback_sp, c.p.traps.callback_return())
                        .unwrap();
                } else if arch == WinArch::Arm64 {
                    context.set_gpr(30, c.p.traps.callback_return());
                }
                let (rec, recs) = records(c, CPP, &context);
                let first = if arch == WinArch::X86 {
                    seh::x86::dispatch(c, rec, recs)
                } else {
                    seh::unwind::dispatch(c, rec, recs)
                }
                .unwrap();
                let then = match first {
                    Flow::CallChecked { then, .. } => then,
                    _ => panic!("first-pass handler"),
                };
                let Flow::CallChecked { target, then, .. } =
                    then(c, u64::from(disposition::CONTINUE_SEARCH)).unwrap()
                else {
                    panic!("unwind handler")
                };
                assert_eq!(target, handler);
                let Err(ApiErr::Internal(message)) = then(c, u64::from(rejected)) else {
                    panic!("unsupported cleanup disposition must reject")
                };
                assert_eq!(
                    message,
                    format!("synthetic SEH unwind unsupported disposition {rejected:#x}")
                );
                assert_eq!(calls.get(), 0);
                assert!(c.t.frames[0].exception[0].handler.is_none());
                assert!(c.t.frames[0].cont.is_some());
                assert_eq!(drops.get(), 0);
                if arch == WinArch::X86 {
                    assert_eq!(
                        c.p.space
                            .u32(c.t.teb + offsets(arch).teb_exception_list)
                            .unwrap(),
                        inner_record as u32,
                        "failed cleanup is not popped"
                    );
                }
                let site = CallSite {
                    api: &seh::DISPATCHER,
                    entry_pc: c.entry_pc,
                    entry_sp: c.entry_sp,
                    ret_addr: 0,
                    cursor: c.cursor,
                    framed: false,
                };
                assert_eq!(
                    dispatch::complete(c.p, c.t, site, Err(ApiErr::Internal(message.clone()))),
                    Outcome::Fail(message)
                );
                assert_eq!(drops.get(), 0);
                c.t.frames.clear();
                assert_eq!(drops.get(), 1);
            });
        }
    }
}
