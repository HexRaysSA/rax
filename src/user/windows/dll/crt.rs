//! Process state shared by C runtime implementations.

/// State whose lifetime is the guest process.
#[derive(Default)]
pub struct CrtState {
    /// Registered process termination callbacks.
    pub atexit: Vec<u64>,
    /// Storage for `errno`, allocated lazily in guest memory.
    pub errno: u64,
}
