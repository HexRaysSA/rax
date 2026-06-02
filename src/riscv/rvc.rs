//! RVC (compressed, 16-bit) instruction decoding.
//!
//! Each compressed parcel expands to exactly one base-ISA operation; the
//! expansion is performed at decode time so the execution path is shared with
//! the 32-bit encodings. Filled in by the C-extension phase.

use super::decode::Insn;
use super::{Isa, Xlen};

/// Decode a non-zero compressed parcel. (Implemented in the C-extension phase.)
pub fn decode_rvc(half: u16, _xlen: Xlen, _isa: &Isa) -> Insn {
    // Placeholder until the C-extension phase; see `decode_compressed`.
    Insn::illegal_compressed(half)
}
