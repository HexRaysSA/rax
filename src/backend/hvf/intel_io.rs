//! Portable Intel native transaction plans, shared by execution and checkpoint admission.
pub(crate) use crate::isa::x86_64::execute::crypto::aes;
#[path = "guest_translation.rs"]
pub(crate) mod guest_translation;
#[path = "mmio.rs"]
pub(crate) mod mmio;
#[path = "port_io.rs"]
pub(crate) mod port_io;
