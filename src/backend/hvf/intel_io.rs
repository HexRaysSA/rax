//! Portable Intel native transaction plans, shared by execution and checkpoint admission.
#[path = "guest_translation.rs"]
pub(crate) mod guest_translation;
#[path = "mmio.rs"]
pub(crate) mod mmio;
#[path = "port_io.rs"]
pub(crate) mod port_io;
