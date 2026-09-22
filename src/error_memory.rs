//! Typed faults at the boundary between a guest access and its physical backing.
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryAccessKind {
    Read,
    Write,
    Fetch,
}
impl fmt::Display for MemoryAccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Fetch => "fetch",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryFaultKind {
    Unmapped,
    Permission,
    Other,
}

/// `address` is the first inaccessible byte, not the beginning of a crossing
/// access. `size` is the requested inaccessible chunk width (0 if unavailable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemoryFault {
    pub address: u64,
    pub size: u32,
    pub access: MemoryAccessKind,
    pub kind: MemoryFaultKind,
}
impl GuestMemoryFault {
    pub fn unmapped(address: u64, size: usize, access: MemoryAccessKind) -> Self {
        Self {
            address,
            size: size.min(u32::MAX as usize) as u32,
            access,
            kind: MemoryFaultKind::Unmapped,
        }
    }
}
impl fmt::Display for GuestMemoryFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let why = match self.kind {
            MemoryFaultKind::Unmapped => "physical range is unmapped",
            MemoryFaultKind::Permission => "memory permission violation",
            MemoryFaultKind::Other => "guest memory access failed",
        };
        write!(f, "failed to {} at {:#x}: {why}", self.access, self.address)
    }
}
impl std::error::Error for GuestMemoryFault {}
