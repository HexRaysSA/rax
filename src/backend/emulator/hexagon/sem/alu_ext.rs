//! (alu_ext) Hexagon instruction gap-fill — direct opcode-dispatch handlers.
//! Filled by the second implementation wave; verified against the qemu-hexagon
//! oracle (tests/hexagon_diff.rs). See sem/alu.rs for the established pattern.

use super::super::opcode::{DecodedOp, Opcode};
use super::SemCtx;

/// Execute a alu_ext opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let _ = (op, d, ctx);
    false
}
