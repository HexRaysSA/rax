//! (hvx_round) rounding / saturating narrowing converts and accumulating shifts (vround*, vsat*, vasrv*sat, vasr/vasl*_acc, vasr_into).
//! STUB — semantics filled in by the HVX wave-2 workflow and verified against
//! the qemu-hexagon vector oracle (tests/hexagon_hvx_diff.rs).

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_round opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
