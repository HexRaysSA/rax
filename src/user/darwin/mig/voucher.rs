//! The `mach_voucher` subsystem (`osfmk/mach/mach_voucher.defs`, served by
//! `osfmk/ipc/ipc_voucher.c`): content and recipe extraction, attribute
//! commands, and the debug information a release kernel does not give.
//!
//! The request port converts to a voucher (`convert_port_to_voucher`);
//! any other port makes the routine fail with `KERN_INVALID_ARGUMENT`.
//! Each output array is bounded by its MIG maximum and then by the count
//! the request asks for, and comes back padded to a 4-byte multiple.

use std::sync::Arc;

use super::{Buf, MigResult, Out, Req, ids};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::voucher::{self, Attrs};
use crate::user::darwin::syscall::Ctx;

/// The voucher the request's port stands for.
fn target(req: &Req) -> Result<Arc<Attrs>, KernReturn> {
    voucher::attrs_of(&req.port)
        .cloned()
        .ok_or(kr::KERN_INVALID_ARGUMENT)
}

/// An array reply: its count, then its bytes padded to 4.
fn array(data: &[u8]) -> Out {
    let mut b = Buf::new().u32(data.len() as u32).bytes(data).done();
    b.resize(b.len() + (4 - data.len() % 4) % 4, 0);
    Out::Simple(b)
}

/// Serves the `mach_voucher` subsystem.
pub fn serve(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    use ids::mach_voucher as v;
    let pid = ctx.proc.pid;
    match req.id {
        v::MACH_VOUCHER_EXTRACT_ATTR_CONTENT => {
            req.simple(40)?;
            let a = target(req)?;
            let (key, room) = (
                req.u32(32),
                (req.u32(36) as usize).min(voucher::MAX_CONTENT),
            );
            if !a.has(key) {
                return Ok(array(&[]));
            }
            let (_, content) = voucher::extract(&a, key, room, pid)?;
            Ok(array(&content))
        }
        v::KERNELRPC_MACH_VOUCHER_EXTRACT_ATTR_RECIPE => {
            req.simple(40)?;
            let a = target(req)?;
            let size = (req.u32(36) as usize).min(voucher::MAX_CONTENT);
            Ok(array(&voucher::extract_recipe(&a, req.u32(32), size, pid)?))
        }
        v::MACH_VOUCHER_EXTRACT_ALL_ATTR_RECIPES => {
            req.simple(36)?;
            let a = target(req)?;
            let size = (req.u32(32) as usize).min(voucher::MAX_RECIPE_ARRAY);
            Ok(array(&voucher::extract_all(&a, size, pid)?))
        }
        v::MACH_VOUCHER_ATTR_COMMAND => {
            // key, command, in_content[in_contentCnt], out_contentCnt.
            let max = 48 + voucher::MAX_CONTENT;
            if req.complex() || req.size() < 48 || req.size() > max {
                return Err(kr::MIG_BAD_ARGUMENTS);
            }
            let n = req.u32(40) as usize;
            let padded = n.next_multiple_of(4);
            if n > voucher::MAX_CONTENT || req.size() != 48 + padded {
                return Err(kr::MIG_BAD_ARGUMENTS);
            }
            let out_size = (req.u32(44 + padded) as usize).min(voucher::MAX_CONTENT);
            let a = target(req)?;
            let input = req.bytes(44, n).to_vec();
            let out = voucher::command(&a, req.u32(32), req.u32(36), &input, out_size, pid)?;
            Ok(array(&out))
        }
        v::MACH_VOUCHER_DEBUG_INFO => {
            // DEVELOPMENT and DEBUG kernels only.
            req.simple(40)?;
            Err(kr::KERN_NOT_SUPPORTED)
        }
        _ => Err(kr::MIG_BAD_ID),
    }
}
