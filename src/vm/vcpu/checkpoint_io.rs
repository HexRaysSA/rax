//! Actual device replies used while closing a stopped native I/O frontier.

pub enum CheckpointIoReply {
    Input(Vec<u8>),
    Output,
    /// A device powered the VM off. Retain the remaining owned transaction;
    /// no further native entry or device effect is permitted. The producer
    /// must represent that terminal transfer explicitly in its private record.
    PowerOff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointIoState {
    Complete,
    Deferred,
}
