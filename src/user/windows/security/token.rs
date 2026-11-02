//! Captured primary-token opening rights and measured native access ordering.

use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS,
};

pub(crate) mod attributes;
pub(crate) mod bno;
pub(crate) mod scalars;
pub(crate) mod statistics;

const ALL_ACCESS: u32 = 0x000F_01FF;
const LEGAL_ACCESS: u32 = 0x031F_FFFF;
const SYSTEM_SECURITY: u32 = 0x0100_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// A native-selection snapshot, never a host token handle or a guest override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Access {
    maximum: u32,
    security_status: u32,
}

impl Access {
    pub(crate) fn new(maximum: u32, security_status: u32) -> Option<Self> {
        if maximum == 0
            || maximum & !ALL_ACCESS != 0
            || !matches!(
                security_status,
                STATUS_SUCCESS | STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD
            )
        {
            return None;
        }
        Some(Self {
            maximum,
            security_status,
        })
    }

    /// O(1) time and storage. Generic mappings are the measured token object
    /// mappings, which differ from the TOKEN_READ/TOKEN_WRITE convenience masks.
    pub(crate) fn grant(self, desired: u32) -> Result<u32, u32> {
        let mut requested = desired & 0x0FFF_FFFF;
        for (generic, specific) in [
            (0x8000_0000, 0x0002_001A),
            (0x4000_0000, 0x0002_01E0),
            (0x2000_0000, 0x0002_0005),
            (0x1000_0000, ALL_ACCESS),
        ] {
            if desired & generic != 0 {
                requested |= specific;
            }
        }
        // Illegal ACCESS_MASK bits precede the security privilege check.
        // Legal but ungranted object-specific bits follow it.
        if requested & !LEGAL_ACCESS != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if requested & SYSTEM_SECURITY != 0 && self.security_status != STATUS_SUCCESS {
            return Err(self.security_status);
        }
        if requested == 0 || requested & !(self.maximum | SYSTEM_SECURITY | MAXIMUM_ALLOWED) != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if requested & MAXIMUM_ALLOWED != 0 {
            requested = (requested & !MAXIMUM_ALLOWED) | self.maximum;
        }
        Ok(requested)
    }
}

#[cfg(test)]
mod tests;
