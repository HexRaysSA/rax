//! x86 frame-based handlers: the `EXCEPTION_REGISTRATION_RECORD` chain.
//!
//! Each record is `{ Next, Handler }` on the stack, headed by
//! `TEB.NtTib.ExceptionList` and ended by 0xFFFFFFFF. Dispatch calls each
//! record's handler as
//! `EXCEPTION_DISPOSITION handler(EXCEPTION_RECORD*, void *EstablisherFrame,
//! CONTEXT*, void *DispatcherContext)` (`__cdecl`).
//!
//! A record is used only if it lies inside the thread's stack
//! (`StackLimit`..`StackBase`) and is 4-byte aligned; otherwise the
//! exception gets `EXCEPTION_STACK_INVALID` and dispatch stops. A handler
//! is called only if it is valid for SafeSEH: not on the stack, not in an
//! image marked `IMAGE_DLLCHARACTERISTICS_NO_SEH`, and, in an image with a
//! SafeSEH table, listed in it.
//!
//! The admitted `RtlUnwind(TargetFrame, TargetIp, ExceptionRecord,
//! ReturnValue)` profile has a non-null target record and continuation PC.
//! It calls each inner handler with `EXCEPTION_UNWINDING`, removes that
//! record only after `ExceptionContinueSearch`, then resumes at `TargetIp`
//! with `ReturnValue` in EAX. Exit and collided unwinds reject explicitly.

use super::{Records, disposition, handler_continue, unhandled};
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::{
    EXCEPTION_NESTED_CALL, EXCEPTION_NONCONTINUABLE, EXCEPTION_STACK_INVALID, EXCEPTION_UNWINDING,
    ExceptionRecord, RegContext,
};
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use std::collections::BTreeSet;

/// End of the registration chain.
pub const CHAIN_END: u64 = 0xFFFF_FFFF;

/// Whether `record` is a usable registration record of the current
/// thread.
fn record_valid(c: &Ctx, record: u64) -> bool {
    record % 4 == 0
        && record >= c.t.stack_limit
        && record
            .checked_add(8)
            .is_some_and(|end| end <= c.t.stack_base)
}

/// Whether `handler` may be called under SafeSEH rules.
fn handler_valid(c: &Ctx, handler: u64) -> bool {
    if handler >= c.t.stack_alloc && handler < c.t.stack_base {
        return false;
    }
    match c.p.modules.by_address(handler) {
        Some((_, m)) => {
            if m.no_seh {
                return false;
            }
            match &m.safe_seh {
                Some(table) => {
                    let rva = (handler - m.base) as u32;
                    table.binary_search(&rva).is_ok()
                }
                None => true,
            }
        }
        // Outside every image (dynamically generated code): allowed when
        // the page is executable, as the loader's check permits.
        None => {
            c.p.vm
                .accessible(handler, crate::error::MemoryAccessKind::Fetch)
        }
    }
}

fn exception_list(c: &Ctx) -> Result<u64, MemFault> {
    let off = offsets(c.p.arch).teb_exception_list;
    c.p.space.u32(c.t.teb + off).map(u64::from)
}

fn set_exception_list(c: &Ctx, value: u64) -> Result<(), MemFault> {
    let off = offsets(c.p.arch).teb_exception_list;
    c.p.space.w32(c.t.teb + off, value as u32)
}

/// The 4096-record cap is a personality policy, not a native Windows limit.
/// O(n log n) time and O(n) space, retained across guest handler calls.
#[derive(Default)]
struct ChainWalk {
    seen: BTreeSet<u64>,
    exception: crate::user::windows::hle::exception::Search,
}

impl ChainWalk {
    fn visit(&mut self, record: u64) -> Result<(), ApiErr> {
        if self.seen.len() >= 4096 || !self.seen.insert(record) {
            return Err(ApiErr::Internal(format!(
                "SEH registration chain cyclic or exceeds 4096 records at {record:#x}"
            )));
        }
        Ok(())
    }
}

/// Dispatches to the registration chain.
pub fn dispatch(c: &mut Ctx, rec: ExceptionRecord, recs: Records) -> ApiResult {
    let first = exception_list(c)?;
    walk(c, rec, recs, first, ChainWalk::default())
}

fn walk(
    c: &mut Ctx,
    rec: ExceptionRecord,
    recs: Records,
    record: u64,
    mut chain: ChainWalk,
) -> ApiResult {
    let frontier = if record == CHAIN_END || record == 0 {
        u64::MAX
    } else {
        record
    };
    if let Some(selected) =
        crate::user::windows::hle::exception::x86(c, &rec, frontier, &mut chain.exception)?
    {
        let dc = c.stack_alloc_checked(4, 4)?;
        c.p.space.w32(dc, 0)?;
        c.p.space
            .w32(recs.record + 4, rec.flags | EXCEPTION_UNWINDING)?;
        return unwind_selected(c, recs, dc, selected, ChainWalk::default());
    }
    if record == CHAIN_END || record == 0 {
        return unhandled(c, rec, recs);
    }
    chain.visit(record)?;
    if !record_valid(c, record) {
        let mut rec = rec;
        rec.flags |= EXCEPTION_STACK_INVALID;
        c.p.space.w32(recs.record + 4, rec.flags)?;
        return unhandled(c, rec, recs);
    }
    let handler = u64::from(c.p.space.u32(record + 4)?);
    if !handler_valid(c, handler) {
        let mut rec = rec;
        rec.flags |= EXCEPTION_STACK_INVALID;
        c.p.space.w32(recs.record + 4, rec.flags)?;
        return unhandled(c, rec, recs);
    }
    // DispatcherContext: a word receiving the establisher of a nested
    // exception.
    let dc = c.stack_alloc_checked(4, 4)?;
    c.p.space.w32(dc, 0)?;
    Flow::call(
        handler,
        vec![recs.record, record, recs.context, dc],
        move |c, ret| {
            let rec = ExceptionRecord::read(&c.p.space, c.p.arch, recs.record)?;
            match ret as u32 {
                disposition::CONTINUE_EXECUTION => handler_continue(c, &rec, recs),
                disposition::CONTINUE_SEARCH | disposition::NESTED_EXCEPTION => {
                    let mut rec = rec;
                    if ret as u32 == disposition::NESTED_EXCEPTION {
                        rec.flags |= EXCEPTION_NESTED_CALL;
                    }
                    let next = u64::from(c.p.space.u32(record)?);
                    walk(c, rec, recs, next, chain)
                }
                _ => Ok(Flow::Raise(ExceptionRecord {
                    code: STATUS_INVALID_DISPOSITION,
                    flags: EXCEPTION_NONCONTINUABLE,
                    nested: recs.record,
                    address: rec.address,
                    params: Vec::new(),
                })),
            }
        },
    )
}

/// Unwind only guest registrations inside the selected synthetic scope. The
/// TEB is reread after every callback; no caller registration is consumed.
/// A changed current link/head or collided unwind is rejected explicitly,
/// rather than fabricating a completed cleanup or repeating a handler.
fn unwind_selected(
    c: &mut Ctx,
    recs: Records,
    dc: u64,
    selected: crate::user::windows::hle::exception::Selected,
    mut chain: ChainWalk,
) -> ApiResult {
    let record = exception_list(c)?;
    if record == CHAIN_END || record == 0 || record >= selected.cursor {
        return selected.invoke(c);
    }
    chain.visit(record)?;
    if !record_valid(c, record) {
        return Err(ApiErr::Internal(format!(
            "synthetic SEH unwind has invalid registration {record:#x}"
        )));
    }
    let next = u64::from(c.p.space.u32(record)?);
    let handler = u64::from(c.p.space.u32(record + 4)?);
    if !handler_valid(c, handler) {
        return Err(ApiErr::Internal(format!(
            "synthetic SEH unwind has invalid handler {handler:#x}"
        )));
    }
    let flags = c.p.space.u32(recs.record + 4)?;
    c.p.space
        .w32(recs.record + 4, flags | EXCEPTION_UNWINDING)?;
    Flow::call_checked(
        handler,
        vec![recs.record, record, recs.context, dc],
        move |c, ret| {
            if ret as u32 != disposition::CONTINUE_SEARCH {
                return Err(ApiErr::Internal(format!(
                    "synthetic SEH unwind unsupported disposition {ret:#x}"
                )));
            }
            // A handler may mutate guest memory. Validate both links before
            // removing exactly the registration whose cleanup just completed.
            if exception_list(c)? != record || u64::from(c.p.space.u32(record)?) != next {
                return Err(ApiErr::Internal(
                    "synthetic SEH unwind registration changed during cleanup".into(),
                ));
            }
            set_exception_list(c, next)?;
            unwind_selected(c, recs, dc, selected, chain)
        },
    )
}

/// `RtlUnwind` (x86, `__stdcall`, 4 arguments).
pub fn rtl_unwind(c: &mut Ctx) -> ApiResult {
    if c.arch() != WinArch::X86 {
        return Err(c.unsupported("RtlUnwind on non-x86 guest"));
    }
    let target = c.ptr(0)?;
    let target_ip = c.ptr(1)?;
    let rec_arg = c.ptr(2)?;
    let ret_value = c.arg(3)?;
    let psize = c.psize();
    let arch = c.p.arch;
    if target == 0 {
        return Err(c.unsupported("RtlUnwind exit unwind"));
    }
    if target_ip == 0 {
        return Err(c.unsupported("RtlUnwind null target IP"));
    }
    if !record_valid(c, target) {
        return Err(unwind_status(c, STATUS_INVALID_UNWIND_TARGET));
    }
    // Even when the target is already the TEB head, its complete registration
    // must be readable before any callback or synthetic-context allocation.
    // The target handler is not invoked, so its address is not validated here.
    c.p.space.u32(target)?;
    c.p.space.u32(target + 4)?;

    // The post-stdcall caller state is the RAX x86 continuation profile.
    // The handler receives this guest context and may update it before resume.
    let mut ctx = RegContext::capture(&c.t.cpu);
    ctx.set_pc(c.ret_addr);
    let caller_sp = c
        .entry_sp
        .checked_add(4 + 16)
        .ok_or_else(|| c.unsupported("RtlUnwind caller stack overflow"))?;
    ctx.set_sp(caller_sp);
    ctx.set_gpr(0, ret_value);
    let ctx_addr = c.stack_alloc_checked(RegContext::size(arch) as u64, 4)?;
    ctx.write(&c.p.space, ctx_addr)?;

    let rec_addr = if rec_arg != 0 {
        let old = c.p.space.u32(rec_arg + 4)?;
        c.p.space.w32(rec_arg + 4, old | EXCEPTION_UNWINDING)?;
        rec_arg
    } else {
        let a = c.stack_alloc_checked(ExceptionRecord::size(arch), 4)?;
        let mut r = ExceptionRecord::new(STATUS_UNWIND, c.ret_addr, Vec::new());
        r.flags = EXCEPTION_UNWINDING;
        r.write(&c.p.space, arch, a)?;
        a
    };
    let dc = c.stack_alloc_checked(psize, 4)?;
    unwind_step(
        c,
        target,
        target_ip,
        rec_addr,
        ctx_addr,
        dc,
        ret_value,
        ChainWalk::default(),
    )
}

fn unwind_status(c: &Ctx, code: u32) -> ApiErr {
    ApiErr::Raise(ExceptionRecord {
        code,
        flags: EXCEPTION_NONCONTINUABLE,
        nested: 0,
        address: c.entry_pc,
        params: Vec::new(),
    })
}

/// A guest callback has completed. Re-entering this export after a repairable
/// fault would call that cleanup a second time; stop without replay instead.
fn after_unwind_callback(result: ApiResult) -> ApiResult {
    match result {
        Err(ApiErr::Fault(fault)) => Err(ApiErr::Internal(format!(
            "RtlUnwind post-handler memory fault at {:#x} (write={})",
            fault.addr, fault.write
        ))),
        other => other,
    }
}

fn unwind_step(
    c: &mut Ctx,
    target: u64,
    target_ip: u64,
    rec: u64,
    ctx: u64,
    dc: u64,
    ret: u64,
    mut chain: ChainWalk,
) -> ApiResult {
    let record = exception_list(c)?;
    if record == target {
        let mut resume = RegContext::read(&c.p.space, c.p.arch, ctx)?;
        resume.set_flags(RegContext::all_flags(c.p.arch));
        resume.set_pc(target_ip);
        resume.set_gpr(0, ret);
        resume.validate(&c.t.cpu).map_err(|status| {
            ApiErr::Internal(format!(
                "RtlUnwind target context rejected with status {status:#010x}"
            ))
        })?;
        return Ok(Flow::Resume(Box::new(resume)));
    }
    if record == CHAIN_END || record == 0 || record > target {
        return Err(unwind_status(c, STATUS_INVALID_UNWIND_TARGET));
    }
    chain.visit(record)?;
    if !record_valid(c, record) {
        return Err(unwind_status(c, STATUS_BAD_STACK));
    }
    let handler = u64::from(c.p.space.u32(record + 4)?);
    if !handler_valid(c, handler) {
        return Err(unwind_status(c, STATUS_BAD_STACK));
    }
    let next = u64::from(c.p.space.u32(record)?);
    Flow::call_checked(handler, vec![rec, record, ctx, dc], move |c, value| {
        let continuation = (|| {
            match value as u32 {
                disposition::CONTINUE_SEARCH => {}
                disposition::COLLIDED_UNWIND => {
                    return Err(c.unsupported("RtlUnwind collided unwind"));
                }
                _ => return Err(unwind_status(c, STATUS_INVALID_DISPOSITION)),
            }
            if exception_list(c)? != record || u64::from(c.p.space.u32(record)?) != next {
                return Err(ApiErr::Internal(
                    "RtlUnwind registration changed during cleanup".into(),
                ));
            }
            set_exception_list(c, next)?;
            unwind_step(c, target, target_ip, rec, ctx, dc, ret, chain)
        })();
        after_unwind_callback(continuation)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::hle::{Api, Arg, Conv};
    use crate::user::windows::memory::prot;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    static RTL_UNWIND_API: Api = Api {
        name: "RtlUnwind",
        args: &[Arg::Ptr, Arg::Ptr, Arg::Ptr, Arg::Ptr],
        conv: Conv::Stdcall,
        imp: rtl_unwind,
    };

    fn with_context(test: impl FnOnce(&mut Ctx)) {
        let image = include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe");
        let mut cfg = WindowsConfig::new("seh-test.exe", Vec::new());
        cfg.seed = Some(1);
        cfg.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let cursor = t.cpu.sp();
        test(&mut Ctx {
            p,
            t: &mut t,
            api: &super::super::DISPATCHER,
            entry_pc: 0,
            entry_sp: cursor,
            ret_addr: 0,
            cursor,
        });
    }

    fn records(c: &mut Ctx) -> (ExceptionRecord, Records, u64) {
        let at = c.t.stack_limit + 0x8000;
        let rec = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1234, vec![]);
        rec.write(&c.p.space, WinArch::X86, at).unwrap();
        let ctx = RegContext::capture(&c.t.cpu);
        ctx.write(&c.p.space, at + 0x1000).unwrap();
        (
            rec,
            Records {
                record: at,
                context: at + 0x1000,
                pointers: at + 0x2000,
            },
            c.t.stack_limit + 0x4000,
        )
    }

    fn registration(c: &mut Ctx, at: u64, next: u64) {
        c.p.modules.list[0].no_seh = false;
        c.p.modules.list[0].safe_seh = None;
        c.p.space.w32(at, next as u32).unwrap();
        c.p.space
            .w32(at + 4, c.p.modules.exe().entry as u32)
            .unwrap();
        set_exception_list(c, at).unwrap();
    }

    #[test]
    fn unreadable_teb_and_registration_do_not_become_end_or_null_handler() {
        with_context(|c| {
            let (rec, recs, at) = records(c);
            registration(c, at, CHAIN_END);
            c.p.vm.protect(c.t.teb, 0x1000, prot::NOACCESS).unwrap();
            assert!(matches!(
                dispatch(c, rec.clone(), recs),
                Err(ApiErr::Fault(MemFault { write: false, .. }))
            ));
            c.p.vm.protect(c.t.teb, 0x1000, prot::READWRITE).unwrap();
            c.p.vm.protect(at, 0x1000, prot::NOACCESS).unwrap();
            assert!(matches!(
                dispatch(c, rec, recs),
                Err(ApiErr::Fault(MemFault { write: false, .. }))
            ));
        });
    }

    #[test]
    fn record_flags_and_dispatcher_word_write_faults_are_reported() {
        with_context(|c| {
            let (rec, recs, at) = records(c);
            registration(c, at, CHAIN_END);
            c.p.vm.protect(recs.record, 0x1000, prot::READONLY).unwrap();
            assert!(matches!(
                walk(c, rec.clone(), recs, 3, ChainWalk::default()),
                Err(ApiErr::Fault(MemFault { write: true, .. }))
            ));
            c.p.vm
                .protect(recs.record, 0x1000, prot::READWRITE)
                .unwrap();
            let dc_page = c.t.stack_limit + 0x6000;
            c.cursor = dc_page + 4;
            c.p.vm.protect(dc_page, 0x1000, prot::NOACCESS).unwrap();
            assert!(
                matches!(dispatch(c, rec, recs), Err(ApiErr::Fault(MemFault { addr, write: true })) if addr == dc_page)
            );
        });
    }

    #[test]
    fn handler_continuation_reads_are_checked_and_self_chain_is_rejected() {
        with_context(|c| {
            let (rec, recs, at) = records(c);
            registration(c, at, at);
            let Flow::Call { then, .. } = dispatch(c, rec.clone(), recs).unwrap() else {
                panic!("handler call expected");
            };
            assert!(
                matches!(then(c, disposition::CONTINUE_SEARCH.into()), Err(ApiErr::Internal(message)) if message.contains("cyclic"))
            );
            let Flow::Call { then, .. } = dispatch(c, rec.clone(), recs).unwrap() else {
                panic!("handler call expected");
            };
            c.p.vm.protect(recs.record, 0x1000, prot::NOACCESS).unwrap();
            assert!(matches!(
                then(c, disposition::CONTINUE_EXECUTION.into()),
                Err(ApiErr::Fault(MemFault { write: false, .. }))
            ));
            c.p.vm
                .protect(recs.record, 0x1000, prot::READWRITE)
                .unwrap();
            let Flow::Call { then, .. } = dispatch(c, rec, recs).unwrap() else {
                panic!("handler call expected");
            };
            c.p.vm.protect(at, 0x1000, prot::NOACCESS).unwrap();
            assert!(matches!(
                then(c, disposition::CONTINUE_SEARCH.into()),
                Err(ApiErr::Fault(MemFault { write: false, .. }))
            ));
        });
    }

    #[test]
    fn valid_chain_end_and_exact_registration_cap() {
        with_context(|c| {
            let (rec, recs, at) = records(c);
            registration(c, at, CHAIN_END);
            let Flow::Call { then, .. } = dispatch(c, rec, recs).unwrap() else {
                panic!("handler call expected");
            };
            assert!(matches!(
                then(c, disposition::CONTINUE_SEARCH.into()),
                Ok(Flow::TerminateProcess(STATUS_ACCESS_VIOLATION))
            ));
        });
        let mut chain = ChainWalk::default();
        for i in 0..4096 {
            chain.visit(4 * (i + 1)).unwrap();
        }
        assert!(chain.visit(4 * 4097).is_err());
        assert_eq!(chain.seen.len(), 4096);
    }

    #[test]
    fn rtl_unwind_rejects_invalid_disposition_before_unlinking() {
        with_context(|c| {
            let (_rec, recs, inner) = records(c);
            let outer = inner + 0x10;
            registration(c, inner, outer);
            c.p.space.w32(outer, CHAIN_END as u32).unwrap();
            let Flow::CallChecked { then, .. } = unwind_step(
                c,
                outer,
                0x1234,
                recs.record,
                recs.context,
                recs.pointers,
                0x1234,
                ChainWalk::default(),
            )
            .unwrap() else {
                panic!("inner unwind handler call expected");
            };
            assert!(matches!(
                then(c, disposition::CONTINUE_EXECUTION.into()),
                Err(ApiErr::Raise(ExceptionRecord {
                    code: STATUS_INVALID_DISPOSITION,
                    ..
                }))
            ));
            assert_eq!(exception_list(c).unwrap(), inner);
        });
    }

    #[test]
    fn rtl_unwind_rejects_exit_and_null_ip_before_changing_the_chain() {
        with_context(|c| {
            c.api = &RTL_UNWIND_API;
            let at = c.t.stack_limit + 0x4000;
            registration(c, at, CHAIN_END);
            let sp = c.entry_sp;
            c.p.space.w32(sp + 8, 0x1234).unwrap();
            c.p.space.w32(sp + 12, 0).unwrap();
            c.p.space.w32(sp + 16, 0x5678).unwrap();

            c.p.space.w32(sp + 4, 0).unwrap();
            assert!(matches!(
                rtl_unwind(c),
                Err(ApiErr::Unimplemented(message)) if message.contains("exit unwind")
            ));
            assert_eq!(exception_list(c).unwrap(), at);

            c.p.space.w32(sp + 4, at as u32).unwrap();
            c.p.space.w32(sp + 8, 0).unwrap();
            assert!(matches!(
                rtl_unwind(c),
                Err(ApiErr::Unimplemented(message)) if message.contains("null target IP")
            ));
            assert_eq!(exception_list(c).unwrap(), at);
        });
    }

    #[test]
    fn rtl_unwind_rejects_unreadable_head_target_before_allocating() {
        for crosses_page in [false, true] {
            with_context(|c| {
                c.api = &RTL_UNWIND_API;
                let target = c.t.stack_limit + if crosses_page { 0x5000 - 4 } else { 0x4000 };
                registration(c, target, CHAIN_END);
                let sp = c.entry_sp;
                c.p.space.w32(sp + 4, target as u32).unwrap();
                c.p.space
                    .w32(sp + 8, c.p.modules.exe().entry as u32)
                    .unwrap();
                c.p.space.w32(sp + 12, 0).unwrap();
                c.p.space.w32(sp + 16, 0).unwrap();
                let fault_at = if crosses_page { target + 4 } else { target };
                c.p.vm.protect(fault_at, 0x1000, prot::NOACCESS).unwrap();
                assert!(matches!(
                    rtl_unwind(c),
                    Err(ApiErr::Fault(MemFault { addr, write: false })) if addr == fault_at
                ));
                assert_eq!(exception_list(c).unwrap(), target);
                assert_eq!(c.cursor, sp);
            });
        }
    }

    #[test]
    fn rtl_unwind_rejects_collided_without_fabricating_a_pop() {
        with_context(|c| {
            let (_rec, recs, inner) = records(c);
            let outer = inner + 0x10;
            registration(c, inner, outer);
            let Flow::CallChecked { then, .. } = unwind_step(
                c,
                outer,
                0x1234,
                recs.record,
                recs.context,
                recs.pointers,
                0x5678,
                ChainWalk::default(),
            )
            .unwrap() else {
                panic!("inner unwind handler call expected");
            };
            assert!(matches!(
                then(c, disposition::COLLIDED_UNWIND.into()),
                Err(ApiErr::Unimplemented(message)) if message.contains("collided unwind")
            ));
            assert_eq!(exception_list(c).unwrap(), inner);
        });
    }

    #[test]
    fn rtl_unwind_post_handler_fault_is_terminal_without_unlinking() {
        for fault_teb in [true, false] {
            with_context(|c| {
                let (_rec, recs, inner) = records(c);
                let outer = inner + 0x10;
                registration(c, inner, outer);
                let Flow::CallChecked { then, .. } = unwind_step(
                    c,
                    outer,
                    0x1234,
                    recs.record,
                    recs.context,
                    recs.pointers,
                    0x5678,
                    ChainWalk::default(),
                )
                .unwrap() else {
                    panic!("inner unwind handler call expected");
                };
                let page = if fault_teb { c.t.teb } else { inner } & !0xfff;
                c.p.vm.protect(page, 0x1000, prot::NOACCESS).unwrap();
                assert!(matches!(
                    then(c, disposition::CONTINUE_SEARCH.into()),
                    Err(ApiErr::Internal(message)) if message.contains("post-handler memory fault")
                ));
                c.p.vm.protect(page, 0x1000, prot::READWRITE).unwrap();
                assert_eq!(exception_list(c).unwrap(), inner);
            });
        }
    }

    #[test]
    fn rtl_unwind_rejects_changed_link_and_self_cycle() {
        with_context(|c| {
            let (_rec, recs, inner) = records(c);
            let outer = inner + 0x10;
            registration(c, inner, outer);
            let Flow::CallChecked { then, .. } = unwind_step(
                c,
                outer,
                0x1234,
                recs.record,
                recs.context,
                recs.pointers,
                0x5678,
                ChainWalk::default(),
            )
            .unwrap() else {
                panic!("inner unwind handler call expected");
            };
            c.p.space.w32(inner, inner as u32).unwrap();
            assert!(matches!(
                then(c, disposition::CONTINUE_SEARCH.into()),
                Err(ApiErr::Internal(message)) if message.contains("registration changed")
            ));
            assert_eq!(exception_list(c).unwrap(), inner);
            let Flow::CallChecked { then, .. } = unwind_step(
                c,
                outer,
                0x1234,
                recs.record,
                recs.context,
                recs.pointers,
                0x5678,
                ChainWalk::default(),
            )
            .unwrap() else {
                panic!("inner unwind handler call expected");
            };
            assert!(matches!(
                then(c, disposition::CONTINUE_SEARCH.into()),
                Err(ApiErr::Internal(message)) if message.contains("cyclic")
            ));
            assert_eq!(exception_list(c).unwrap(), inner);
        });
    }
}
