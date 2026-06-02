//! (hvx_v6mpy) HVX V69 byte-matrix multiply v6mpy (vertical/horizontal phases),
//! with packed sign-extended 10-bit coefficients and a 2-bit phase immediate.
//! STUB — filled by the HVX V69 workflow and verified against the qemu-hexagon
//! v69 vector oracle (tests/hexagon_hvx_diff.rs).

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_v6mpy opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
