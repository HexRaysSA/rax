//! Captured NT key access ceilings and the measured key-object generic mapping.
use super::super::nt::status::STATUS_ACCESS_DENIED;
pub(super) const KEY_ALL_ACCESS: u32 = 0x000F_003F;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyAccess {
    pub(crate) maximum_access: u32,
    pub(crate) system_security_status: u32,
}
impl KeyAccess {
    pub(crate) fn grant(self, access: u32) -> Result<u32, u32> {
        let mut requested = access & !(0xF200_0300);
        // Native key-object mappings, including the observed CREATE_LINK bit
        // in generic execute. View bits select routes, not granted rights.
        for (generic, specific) in [
            (0x8000_0000, 0x0002_0019),
            (0x4000_0000, 0x0002_0006),
            (0x2000_0000, 0x0002_0039),
            (0x1000_0000, KEY_ALL_ACCESS),
        ] {
            if access & generic != 0 {
                requested |= specific;
            }
        }
        if requested & !(KEY_ALL_ACCESS | 0x0100_0000) != 0
            || requested & KEY_ALL_ACCESS & !self.maximum_access != 0
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if requested & 0x0100_0000 != 0 && self.system_security_status != 0 {
            return Err(self.system_security_status);
        }
        if access & 0x0200_0000 != 0 {
            requested |= self.maximum_access;
        }
        if requested == 0 {
            Err(STATUS_ACCESS_DENIED)
        } else {
            Ok(requested)
        }
    }
}
