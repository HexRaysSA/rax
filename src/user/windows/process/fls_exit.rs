//! Final normal-exit FLS continuation, after DLL notification staging.

use super::{Proc, Thread};
use crate::user::windows::hle::Flow;
use crate::user::windows::hle::dispatch::{self, CallSite, Outcome};
use crate::user::windows::hle::{Api, ApiErr, ApiResult, Conv};

static EXIT: Api = Api {
    name: "RaxFlsExitCleanup",
    args: &[],
    conv: Conv::Custom,
    imp: synthetic,
};

fn synthetic(_: &mut crate::user::windows::hle::Ctx) -> ApiResult {
    Err(ApiErr::Internal("FLS exit requires an exit code".into()))
}

pub(super) fn begin(p: &mut Proc, t: &mut Thread, code: u32, process: bool) -> Outcome {
    let sp = t.cpu.sp();
    let site = CallSite {
        api: &EXIT,
        entry_pc: t.cpu.pc(),
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !15,
        framed: false,
    };
    dispatch::run(p, t, site, move |c| {
        let key = c.t.fls_key();
        crate::user::windows::dll::fls::cleanup(
            c,
            key,
            Box::new(move |_, _| {
                Ok(if process {
                    Flow::ExitProcess(code)
                } else {
                    Flow::ExitThread(code)
                })
            }),
        )
    })
}
