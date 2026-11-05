//! The portable lifetime harness retains the production backend hierarchy.
#[path = "../../../../src/backend/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::CheckpointBoundary;

#[path = "../../../../src/backend/software_irq.rs"]
mod software_irq;

#[path = "lifetime.rs"]
mod lifetime;
