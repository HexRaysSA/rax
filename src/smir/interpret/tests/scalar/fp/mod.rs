//! scalar::fp tests

use super::*;
use crate::smir::interpret::tests::*;
use crate::smir::interpret::*;

// ---- even-chunked tests ----
#[cfg(test)]
mod part1;
#[cfg(test)]
mod part2;
#[cfg(test)]
mod part3;
#[cfg(test)]
mod x86_fp_convert;
#[cfg(test)]
mod x86_fp_to_int;
#[cfg(test)]
mod x86_int_to_fp;
#[cfg(test)]
mod x86_round_scale;
