//! Owned synthetic SEH scopes for host-implemented guest operations.
//!
//! These are HLE scopes, not registrations in the guest TEB or invented image
//! unwind metadata. The x86 registration walk crosses a scope only after inner
//! records. The table walk crosses it at an exact callback-return sentinel (or
//! a fault at the scope's own export frontier), after guest unwind handlers.
//! Unmatched scopes bridge to their owner's caller without calling or dropping
//! the pending operation. Matched handlers are taken before invocation, so a
//! recursive exception cannot invoke that handler a second time. Selection
//! itself executes no handler: SEH runs a separate bounded guest unwind pass
//! from the original fault to this exact owner before invoking its handler.

use std::collections::BTreeSet;

use super::args::stdcall_bytes;
use super::{ApiErr, ApiResult, Cont, Conv, Ctx};
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::{ExceptionRecord, RegContext};
use crate::user::windows::traps::RESUME_OFFSET;

/// A scope owned by one HLE frame; its continuation is not clonable.
pub struct ExceptionBoundary {
    /// Exact matching code, or any SEH code.
    pub code: Option<u32>,
    /// Original protected stack frontier, before the protected operation ran.
    pub cursor: u64,
    handler: Option<Cont>,
}

impl ExceptionBoundary {
    pub(crate) fn new(code: Option<u32>, cursor: u64, handler: Cont) -> Self {
        Self {
            code,
            cursor,
            handler: Some(handler),
        }
    }
}

/// Search-local crossing receipts. A scope is offered once per exception,
/// including when its code filter declines. Frame indices stay stable while
/// the lower exception dispatcher calls/returns through guest search handlers.
/// Abandoning that dispatcher drops this search rather than reusing receipts.
/// For N guest walk steps, F retained HLE frames and H scopes: worst-case
/// O(N (F + H log(H + 1))) time, O(H + F) crossing-receipt space. The existing
/// 4096-step cap remains; 4096 scopes is also a personality ceiling.
#[derive(Clone, Default)]
pub(crate) struct Search {
    offered: BTreeSet<(usize, usize)>,
    bridged: BTreeSet<usize>,
}

/// A table-walk synthetic frontier, never a fabricated callback return.
pub(crate) enum Crossing {
    /// This remains an ordinary guest frame.
    None,
    /// `ctx` now describes the HLE owner's caller; continue virtual search.
    Bridged,
    /// Unwind the fault's guest frames before running this disabled handler.
    Selected(Selected),
}

/// A disabled filter's exact owner, retained across the separate unwind pass.
/// No protected operation continuation is consumed by selection or unwinding.
pub(crate) struct Selected {
    owner: usize,
    scope: usize,
    api: &'static super::Api,
    entry_pc: u64,
    entry_sp: u64,
    pub(crate) cursor: u64,
    code: u32,
    handler: Cont,
}

impl Selected {
    fn validate(&self, c: &Ctx) -> Result<(), ApiErr> {
        let valid = c.t.frames.get(self.owner).is_some_and(|frame| {
            std::ptr::eq(frame.api, self.api)
                && frame.entry_pc == self.entry_pc
                && frame.entry_sp == self.entry_sp
                && frame
                    .exception
                    .get(self.scope)
                    .is_some_and(|scope| scope.cursor == self.cursor && scope.handler.is_none())
        });
        if valid {
            Ok(())
        } else {
            Err(ApiErr::Internal(
                "selected synthetic SEH owner disappeared during unwind".into(),
            ))
        }
    }

    pub(crate) fn invoke(self, c: &mut Ctx) -> ApiResult {
        self.validate(c)?;
        (self.handler)(c, u64::from(self.code))
    }
}

pub(crate) enum UnwindCrossing {
    None,
    Bridged,
    Reached,
}

fn offer(
    c: &mut Ctx,
    rec: &ExceptionRecord,
    search: &mut Search,
    eligible: impl Fn(usize, u64) -> bool,
) -> Result<Option<Selected>, ApiErr> {
    let mut count = 0usize;
    for frame in &c.t.frames {
        count = count
            .checked_add(frame.exception.len())
            .ok_or_else(|| ApiErr::Internal("synthetic SEH scope count overflow".into()))?;
    }
    if count > 4096 {
        return Err(ApiErr::Internal(
            "synthetic SEH search exceeds 4096 scopes".into(),
        ));
    }
    let mut handler = None;
    'frames: for (owner, frame) in c.t.frames.iter_mut().enumerate().rev() {
        for (index, boundary) in frame.exception.iter_mut().enumerate().rev() {
            if !eligible(owner, boundary.cursor) || !search.offered.insert((owner, index)) {
                continue;
            }
            if boundary.code.is_none_or(|code| code == rec.code)
                && let Some(selected) = boundary.handler.take()
            {
                handler = Some(Selected {
                    owner,
                    scope: index,
                    api: frame.api,
                    entry_pc: frame.entry_pc,
                    entry_sp: frame.entry_sp,
                    cursor: boundary.cursor,
                    code: rec.code,
                    handler: selected,
                });
                break 'frames;
            }
        }
    }
    Ok(handler)
}

/// Before a caller registration at/above `record`, offer every crossed scope
/// from inner to outer. End-of-chain uses `u64::MAX` and offers all scopes.
pub(crate) fn x86(
    c: &mut Ctx,
    rec: &ExceptionRecord,
    record: u64,
    search: &mut Search,
) -> Result<Option<Selected>, ApiErr> {
    offer(c, rec, search, |_, cursor| record >= cursor)
}

/// Table search recognizes the exact prepared callback stack height, not a
/// guess based on where a return sentinel happened to appear in memory.
pub(crate) fn table(
    c: &mut Ctx,
    rec: &ExceptionRecord,
    ctx: &mut RegContext,
    search: &mut Search,
) -> Result<Crossing, ApiErr> {
    let Some(owner) = table_owner(c, ctx)? else {
        return Ok(Crossing::None);
    };
    cross_once(search, owner)?;
    if let Some(selected) = offer(c, rec, search, |index, _| index == owner)? {
        return Ok(Crossing::Selected(selected));
    }
    bridge(c, ctx, owner)?;
    Ok(Crossing::Bridged)
}

/// A second, unwind-only traversal never offers another synthetic filter.
/// It stops at the selected owner, not a coincidentally equal guest SP.
pub(crate) fn table_unwind(
    c: &Ctx,
    ctx: &mut RegContext,
    search: &mut Search,
    selected: &Selected,
) -> Result<UnwindCrossing, ApiErr> {
    selected.validate(c)?;
    let Some(owner) = table_owner(c, ctx)? else {
        return Ok(UnwindCrossing::None);
    };
    cross_once(search, owner)?;
    if owner == selected.owner {
        return Ok(UnwindCrossing::Reached);
    }
    bridge(c, ctx, owner)?;
    Ok(UnwindCrossing::Bridged)
}

fn cross_once(search: &mut Search, owner: usize) -> Result<(), ApiErr> {
    if !search.bridged.insert(owner) {
        return Err(ApiErr::Internal(
            "SEH synthetic callback owner crossed twice".into(),
        ));
    }
    Ok(())
}

fn table_owner(c: &Ctx, ctx: &RegContext) -> Result<Option<usize>, ApiErr> {
    if c.p.arch == WinArch::X86 {
        return Err(ApiErr::Internal("x86 synthetic table SEH search".into()));
    }
    let sentinel = ctx.pc() == c.p.traps.callback_return();
    let owner = c.t.frames.iter().enumerate().rev().find_map(|(i, f)| {
        let callback = sentinel
            && f.cont.is_some()
            && f.callback_sp.is_some_and(|sp| {
                if c.p.arch == WinArch::X64 {
                    sp.checked_add(8) == Some(ctx.sp())
                } else {
                    sp == ctx.sp()
                }
            });
        let frontier = !sentinel
            && !f.exception.is_empty()
            && ctx.sp() == f.entry_sp
            && (ctx.pc() == f.entry_pc || f.entry_pc.checked_add(RESUME_OFFSET) == Some(ctx.pc()));
        (callback || frontier).then_some(i)
    });
    let Some(owner) = owner else {
        return if sentinel {
            Err(ApiErr::Internal(format!(
                "SEH callback-return sentinel has no owner at SP {:#x}",
                ctx.sp()
            )))
        } else {
            Ok(None)
        };
    };
    Ok(Some(owner))
}

fn bridge(c: &Ctx, ctx: &mut RegContext, owner: usize) -> Result<(), ApiErr> {
    let frame = &c.t.frames[owner];
    if let Some(caller) = &frame.exception_caller {
        *ctx = (**caller).clone();
        return Ok(());
    }
    if std::ptr::eq(frame.api, &crate::user::windows::seh::DISPATCHER) {
        return Err(ApiErr::Internal(
            "SEH dispatcher callback has no captured exception caller".into(),
        ));
    }
    let pop = match c.p.arch {
        WinArch::X64 => 8,
        WinArch::Arm64 => 0,
        WinArch::X86 => {
            4 + if frame.api.conv == Conv::Stdcall {
                stdcall_bytes(frame.api.args)
            } else {
                0
            }
        }
    };
    let sp = frame
        .entry_sp
        .checked_add(pop)
        .ok_or_else(|| ApiErr::Internal("SEH synthetic caller stack overflow".into()))?;
    ctx.set_pc(frame.ret_addr);
    ctx.set_sp(sp);
    if c.p.arch == WinArch::Arm64 {
        ctx.set_gpr(30, frame.ret_addr);
    }
    Ok(())
}

#[cfg(test)]
#[path = "exception_tests.rs"]
mod tests;
