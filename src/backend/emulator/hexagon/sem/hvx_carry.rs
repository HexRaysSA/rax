//! (hvx_carry) HVX carry-chain add/sub with a vector-predicate carry (vaddcarry,
//! vsubcarry and the saturating/overflow variants), plus the leftover unsigned
//! saturating subtract and the set-predicate-v2 op.
//! STUB — filled by the HVX wave-3 workflow and verified against the
//! qemu-hexagon vector oracle (tests/hexagon_hvx_diff.rs).

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_carry opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
