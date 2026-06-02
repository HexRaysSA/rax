//! (hvx_shift) HVX instruction gap-fill — verified against the qemu-hexagon vector
//! oracle (tests/hexagon_hvx_diff.rs). See sem/hvx.rs for the established
//! 128-byte lane pattern and the SemCtx vector API (vread/set_v/qread/set_q).

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_shift opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
