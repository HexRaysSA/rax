//! Where no native code can be made: hosts whose instructions or whose way
//! of mapping code this crate does not know.

use crate::ir::Module;
use crate::{Error, ErrorClass};

use super::exec::Frame;
use super::process::{Context, Ended};

/// Native code for one module. There is none for this host.
pub struct Code(std::convert::Infallible);

impl Code {
    /// Always fails on this host.
    ///
    /// # Errors
    ///
    /// `EXEC_UNIMPLEMENTED`.
    pub fn compile(_: &Module) -> Result<Self, Error> {
        Err(Error::new(
            ErrorClass::Unimplemented,
            "EXEC_UNIMPLEMENTED",
            "native code for this host",
        ))
    }

    pub(super) fn is_for(&self, _: &Module) -> bool {
        match self.0 {}
    }
}

pub(super) fn run(_: &Context, code: &Code, _: Vec<Frame>) -> Result<Ended, Error> {
    match code.0 {}
}
