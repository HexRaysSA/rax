//! Typed requests inside the private channel framing. This is an internal
//! protocol, not a public ABI. Sources and lifetime objects stay in the broker;
//! mapping requests refer to its endpoint-scoped backing catalog.

use serde::{Deserialize, Serialize};
use std::io;

use super::BackingId;
use crate::error::{GuestMemoryFault, MemoryAccessKind};
use crate::user::mm::MmError;

/// Per-request byte limit. Larger guest transfers must be chunked by their
/// caller, preserving that caller's fault/atomicity contract. Even worst-case
/// JSON byte arrays fit comfortably inside the channel's 1 MiB frame.
pub(super) const TRANSFER_BYTES: usize = 64 * 1024;

/// MM personality operations carry small typed control records, never memory
/// contents, live counters or backing objects. Worst-case JSON expansion of
/// this byte array stays below 25 KiB inside the 1 MiB channel frame.
pub(super) const PERSONALITY_BYTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Map {
    pub(crate) start: u64,
    pub(crate) len: u64,
    pub(crate) perms: u8,
    pub(crate) backing: Option<BackingId>,
    pub(crate) offset: u64,
    pub(crate) shared: bool,
    pub(crate) copy: bool,
    pub(crate) name: Option<String>,
    pub(crate) flags: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) enum ReadKind {
    Read,
    Fetch,
    Raw,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(crate) enum Operation {
    ReleaseBacking {
        backing: BackingId,
    },
    Read {
        address: u64,
        len: u32,
        kind: ReadKind,
    },
    Write {
        address: u64,
        bytes: Vec<u8>,
        raw: bool,
    },
    Translate {
        address: u64,
        access: MemoryAccessKind,
        raw: bool,
    },
    Probe {
        address: u64,
        len: u32,
        access: MemoryAccessKind,
    },
    Map {
        mapping: Map,
    },
    Unmap {
        start: u64,
        len: u64,
    },
    Protect {
        start: u64,
        len: u64,
        perms: u8,
    },
    SetFlags {
        start: u64,
        len: u64,
        mask: u32,
        bits: u32,
    },
    Remap {
        old: u64,
        len: u64,
        new: u64,
    },
    Discard {
        start: u64,
        len: u64,
    },
    FileCopyPolicy {
        start: u64,
        len: u64,
        copy: bool,
    },
    CodeChanges {
        epoch: u64,
    },
    Stats,
    ResidentAccessible {
        address: u64,
    },
    Mappings {
        offset: u64,
    },
}

impl Operation {
    pub(super) fn mutates(&self) -> bool {
        match self {
            Self::Read { .. }
            | Self::CodeChanges { .. }
            | Self::Stats
            | Self::Mappings { .. }
            | Self::ResidentAccessible { .. } => false,
            Self::Translate { access, .. } | Self::Probe { access, .. } => {
                *access == MemoryAccessKind::Write
            }
            _ => true,
        }
    }

    pub(super) fn valid_size(&self) -> bool {
        match self {
            Self::Read { len, .. } | Self::Probe { len, .. } => *len as usize <= TRANSFER_BYTES,
            Self::Write { bytes, .. } => bytes.len() <= TRANSFER_BYTES,
            _ => true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "request", deny_unknown_fields)]
pub(super) enum Request {
    Begin {
        pid: libc::pid_t,
    },
    End {
        serial: u64,
    },
    Memory {
        serial: u64,
        operation: Operation,
    },
    Personality {
        serial: u64,
        bytes: Vec<u8>,
    },
    Fork {
        serial: u64,
        private: bool,
    },
    View {
        serial: u64,
        operation: ViewOperation,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(super) enum ViewOperation {
    Arena,
    Translate {
        address: u64,
        access: MemoryAccessKind,
        raw: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "storage", deny_unknown_fields)]
pub(super) enum Translation {
    Private {
        address: u64,
    },
    File {
        address: u64,
        base: u64,
        len: u64,
        offset: u64,
        writable: bool,
        identity: [u64; 2],
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "view", deny_unknown_fields)]
pub(super) enum ViewValue {
    Arena { bytes: u64 },
    Translation { translation: Translation },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "failure", deny_unknown_fields)]
pub(super) enum ViewFailure {
    Memory {
        error: Failure,
    },
    Preparation {
        error: PreparationFailure,
    },
    /// File descriptors cannot transfer a Mach memory-entry right. This
    /// remains an explicit import failure until its native adapter is wired.
    HostMemory,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "value", deny_unknown_fields)]
pub(crate) enum Value {
    Unit,
    ResidentAccessible {
        accessible: bool,
    },
    Bytes {
        bytes: Vec<u8>,
    },
    Physical {
        address: u64,
    },
    Code {
        epoch: u64,
        all: bool,
        ranges: Vec<(u64, u64)>,
    },
    Mappings {
        total: u64,
        bytes: Vec<u8>,
    },
    Stats {
        va_limit: u64,
        resident_pages: u64,
        attached_extents: u64,
    },
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "error", deny_unknown_fields)]
pub(crate) enum Failure {
    InvalidArgument { detail: String },
    OutOfRange,
    NotMapped { address: u64 },
    OutOfMemory,
    Fault { fault: GuestMemoryFault },
}

impl From<MmError> for Failure {
    fn from(error: MmError) -> Self {
        match error {
            MmError::InvalidArgument(detail) => Self::InvalidArgument {
                detail: detail.into(),
            },
            MmError::OutOfRange => Self::OutOfRange,
            MmError::NotMapped { addr } => Self::NotMapped { address: addr },
            MmError::OutOfMemory => Self::OutOfMemory,
        }
    }
}

impl From<GuestMemoryFault> for Failure {
    fn from(fault: GuestMemoryFault) -> Self {
        Self::Fault { fault }
    }
}

/// Classification is portable across the Unix broker adapters. Keep the
/// native error separately for diagnostics; it is not a guest errno value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum PreparationKind {
    ProcessDescriptorLimit,
    SystemDescriptorLimit,
    OutOfMemory,
    NoBuffers,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparationFailure {
    pub(crate) kind: PreparationKind,
    pub(crate) native_errno: Option<i32>,
}

impl From<io::Error> for PreparationFailure {
    fn from(error: io::Error) -> Self {
        let native_errno = error.raw_os_error();
        let kind = match native_errno {
            Some(libc::EMFILE) => PreparationKind::ProcessDescriptorLimit,
            Some(libc::ENFILE) => PreparationKind::SystemDescriptorLimit,
            Some(libc::ENOMEM) => PreparationKind::OutOfMemory,
            Some(libc::ENOBUFS) => PreparationKind::NoBuffers,
            _ if error.kind() == io::ErrorKind::OutOfMemory => PreparationKind::OutOfMemory,
            _ => PreparationKind::Other,
        };
        Self { kind, native_errno }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
pub(super) enum Response {
    Grant {
        serial: u64,
        space: u64,
    },
    Ended,
    Result {
        result: Result<Value, Failure>,
    },
    Personality {
        bytes: Vec<u8>,
    },
    Forked,
    ForkFailed {
        failure: PreparationFailure,
    },
    View {
        result: Result<ViewValue, ViewFailure>,
    },
}
