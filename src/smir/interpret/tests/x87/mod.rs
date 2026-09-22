//! tests::x87 tests

use super::*;
use crate::smir::interpret::*;
use crate::smir::ir::FunctionBuilder;
use crate::smir::ir::flags::{FlagSet, FlagUpdate, MaterializedFlags};
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::ir::types::ShiftOp;

// ---- even-chunked tests ----
#[cfg(test)]
mod control;
#[cfg(test)]
mod fxsave_restore;
#[cfg(test)]
mod part1;
#[cfg(test)]
mod part2;
#[cfg(test)]
mod part3;
