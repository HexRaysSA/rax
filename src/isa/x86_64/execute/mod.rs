//! x86_64 instruction implementations organized by category.

pub mod arith;
pub mod bit;
pub mod bmi;
pub mod control;
mod crc32;
pub(crate) mod crypto;
pub(crate) use crc32::crc32c;
pub mod data;
pub mod fpu;
mod imul;
pub mod io;
pub mod logic;
pub mod shift;
pub mod simd;
pub mod string;
pub mod system;
