//! CRT FILE/descriptor storage and real bounded byte I/O.
//! Primary contracts and explicit private profiles: windows-crt-stdio.md.

mod api;
mod backend;
mod exports;
mod io;
mod storage;

#[cfg(test)]
mod tests;

pub(crate) use exports::{MSVCRT_STDIO_EXPORTS, STDIO_EXPORTS, UCRT_STDIO_EXPORTS};
pub(super) use storage::StdioState;
pub(crate) use storage::{PreparedStdio, prepare};

use crate::user::windows::hle::{ApiErr, Ctx};
use crate::user::windows::process::Proc;

use super::RuntimeKind;

const O_TEXT: i32 = 0x4000;
const O_BINARY: i32 = 0x8000;
const O_WTEXT: i32 = 0x1_0000;
const O_U16TEXT: i32 = 0x2_0000;
const O_U8TEXT: i32 = 0x4_0000;

fn state(c: &Ctx, kind: RuntimeKind) -> Result<StdioState, ApiErr> {
    c.p.crt.runtimes[kind.index()]
        .stdio
        .clone()
        .ok_or_else(|| ApiErr::Internal("CRT stream storage is not initialized".into()))
}

/// Process teardown does not perform invented CRT normal-exit flushing. That
/// belongs to the actual CRT termination exports, not TerminateProcess or raw
/// ExitProcess. Discard only host-owned resources, without guest writes.
pub(crate) fn discard_process(p: &mut Proc) -> Result<(), String> {
    let mut failure = None;
    for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
        if let Some(streams) = p.crt.runtimes[kind.index()].stdio.take() {
            if let Err(error) = streams.discard(p) {
                failure.get_or_insert_with(|| format!("CRT stdio teardown: {error:?}"));
            }
        }
    }
    failure.map_or(Ok(()), Err)
}
