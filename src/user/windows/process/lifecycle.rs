//! Thread startup and DLL/TLS initialization continuations.

use super::{Proc, Thread};
use crate::user::windows::hle::dispatch::{self, CallSite, Outcome};
use crate::user::windows::hle::{Api, ApiResult, Conv, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

static START: Api = Api {
    name: "RtlUserThreadStart",
    args: &[],
    conv: Conv::Custom,
    imp: start,
};

fn start(c: &mut Ctx) -> ApiResult {
    let mut calls = Vec::new();
    let order: Vec<usize> = if c.t.main {
        c.p.modules
            .init_order
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect()
    } else {
        (0..c.p.modules.list.len()).collect()
    };
    for idx in order {
        let module = &c.p.modules.list[idx];
        let reason = if c.t.main { 1 } else { 2 };
        if !c.t.main && !module.thread_calls {
            continue;
        }
        if let Some(tls) = module.tls {
            if tls.callbacks != 0 {
                let mut terminated = false;
                for i in 0..4096 {
                    let addr = tls.callbacks.checked_add(i * c.psize()).ok_or(
                        crate::user::windows::memory::MemFault {
                            addr: u64::MAX,
                            write: false,
                        },
                    )?;
                    let callback = c.read_ptr(addr)?;
                    if callback == 0 {
                        terminated = true;
                        break;
                    }
                    calls.push((callback, vec![module.base, reason, 0], false));
                }
                if !terminated {
                    return Ok(Flow::ExitProcess(STATUS_INVALID_IMAGE_FORMAT));
                }
            }
        }
        if module.has_dll_main() && (c.t.main && !module.initialized || !c.t.main) {
            calls.push((module.entry, vec![module.base, reason, 0], c.t.main));
        }
    }
    initialize(c, calls.into_iter())
}

fn initialize(c: &mut Ctx, mut calls: std::vec::IntoIter<(u64, Vec<u64>, bool)>) -> ApiResult {
    if let Some((target, args, check)) = calls.next() {
        return Flow::call(target, args, move |c, value| {
            if check && value as u32 == 0 {
                return Ok(Flow::ExitProcess(STATUS_DLL_INIT_FAILED));
            }
            initialize(c, calls)
        });
    }
    if c.t.main {
        for module in &mut c.p.modules.list {
            module.initialized = true;
        }
    }
    c.t.attached = true;
    let args = if c.t.main {
        Vec::new()
    } else {
        vec![c.t.param]
    };
    let main = c.t.main;
    Flow::call(c.t.start, args, move |_, result| {
        Ok(if main {
            Flow::ExitProcess(result as u32)
        } else {
            Flow::ExitThread(result as u32)
        })
    })
}

/// Begins a newly created thread at the personality's startup trap.
pub fn thread_start(p: &mut Proc, t: &mut Thread) -> Outcome {
    let sp = t.cpu.sp();
    let site = CallSite {
        api: &START,
        entry_pc: p.traps.thread_start(),
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !15,
        framed: false,
    };
    dispatch::run(p, t, site, start)
}
