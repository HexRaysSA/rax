//! (hvx_hist) HVX histogram instructions (vhist / vhistq / vwhist128* /
//! vwhist256*): each tallies byte/halfword values from the vector register file
//! into histogram bins held in the register file.
//! STUB — filled by the HVX wave-3 workflow and verified against the
//! qemu-hexagon vector oracle (tests/hexagon_hvx_diff.rs).

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a hvx_hist opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
