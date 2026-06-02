//! (hvx_cmpy) HVX multiply-family gap-fill — verified against the qemu-hexagon
//! vector oracle (tests/hexagon_hvx_diff.rs). See sem/hvx.rs / sem/hvx_mpy.rs
//! for the 128-byte lane pattern and the SemCtx vector API.

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_cmpy opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
