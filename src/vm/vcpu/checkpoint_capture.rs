//! Source-bound immutable media prepared while a software CPU is stopped.
use crate::vm::snapshot::CheckpointResource;
use std::sync::Arc;

/// Opaque preparation token. It is not a serialized record or a publication
/// permit. The producing backend verifies owner and source state again before
/// binding its resources into the scoped CPU record.
pub struct PreparedCheckpointCapture {
    pub(crate) owner: Arc<()>,
    pub(crate) witness: Vec<u8>,
    pub(crate) resources: Vec<CheckpointResource>,
}
