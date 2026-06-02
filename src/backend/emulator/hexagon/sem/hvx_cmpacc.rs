//! (hvx_cmpacc) compare-accumulate vector predicates (vgt*/veq* with .and/.or/.xor into an existing Q).
//! STUB — semantics filled in by the HVX wave-2 workflow and verified against
//! the qemu-hexagon vector oracle (tests/hexagon_hvx_diff.rs).

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_cmpacc opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
