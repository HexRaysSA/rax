//! Xtensa LX interpreter.
//!
//! The opcodes are recognized by a decoder generated from the libisa tables of a
//! Tensilica core configuration (`tools/xtensa/gen_opcodes.py`); the semantics
//! are written by hand. The core configuration is the ESP32-S3's (LX7): windowed
//! registers (64 AR), zero-overhead loops, MUL16/MUL32/DIV32, MAC16, booleans,
//! S32C1I, single-precision FPU, XEA2 exceptions with six interrupt levels and
//! NMI, three CCOMPARE timers, region protection. The PIE SIMD instructions
//! (`ee.*`) are recognized but raise IllegalInstruction.
//!
//! This ISA is interpreter-only: it has no SMIR lifter.

pub mod config;
pub mod cpu;
pub mod decode;
mod exec;
mod fpu;
pub mod generated;
mod mac16;
pub mod regs;

pub use config::XtensaConfig;
pub use cpu::{Exit, Profile, XtensaBus, XtensaCpu};
pub use decode::{Format, Insn, decode};
pub use generated::opcodes::Opcode;

#[cfg(test)]
mod tests;
