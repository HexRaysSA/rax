//! Captured class-14 availability is independent of extension payload presence.
use crate::user::windows::nt::status::*;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionQuery {
    #[default]
    Both,
    NativeOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Read,
    ClassUnavailable,
    KindUnavailable,
}

/// O(1) time and storage. Only the measured native AMD64 type-1 rejection is
/// optional; other failures retain their status and abort the host snapshot.
pub(crate) fn classify(machine: Option<u16>, kind: u32, status: u32) -> Result<Disposition, u32> {
    match (kind, status) {
        (0 | 1, STATUS_SUCCESS) => Ok(Disposition::Read),
        (0, STATUS_INVALID_INFO_CLASS) => Ok(Disposition::ClassUnavailable),
        (1, STATUS_NOT_SUPPORTED) if machine == Some(0x8664) => Ok(Disposition::KindUnavailable),
        _ if kind >= 2 => Err(STATUS_INVALID_PARAMETER),
        _ => Err(status),
    }
}

#[cfg(test)]
mod tests;
