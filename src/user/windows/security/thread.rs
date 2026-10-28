//! Opening rights of the selected process subject's default thread objects.
use super::super::nt::status::{STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS};

const ALL: u32 = 0x001F_FFFF;
const SECURITY: u32 = 0x0100_0000;
const MAXIMUM: u32 = 0x0200_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Access {
    maximum: u32,
    security_status: u32,
    bypass: bool,
    maximum_security: Option<u32>,
}

impl Access {
    pub(crate) fn new(
        maximum: u32,
        security_status: u32,
        bypass: bool,
        maximum_security: Option<u32>,
    ) -> Option<Self> {
        if maximum == 0
            || maximum & !ALL != 0
            || !matches!(
                security_status,
                STATUS_SUCCESS | STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD
            )
            || (security_status == STATUS_SUCCESS) != maximum_security.is_some()
            || maximum_security.is_some_and(|grant| grant != maximum && grant != maximum | SECURITY)
        {
            return None;
        }
        Some(Self {
            maximum,
            security_status,
            bypass,
            maximum_security,
        })
    }

    /// The synthetic personality's fixed default subject has no security privilege.
    pub(crate) fn modeled() -> Self {
        Self::new(ALL, STATUS_PRIVILEGE_NOT_HELD, false, None)
            .expect("fixed synthetic thread subject")
    }

    /// O(1) time/storage. Keep the native zero-request check distinct from
    /// stripping non-object bits: a nonzero reserved request can grant zero.
    pub(crate) fn grant(self, desired: u32) -> Result<u32, u32> {
        if desired == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if !self.bypass && desired & 0x0CE0_0000 != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mut requested = desired & (ALL | SECURITY);
        for (generic, specific) in [
            (0x8000_0000, 0x0002_0848),
            (0x4000_0000, 0x0002_1437),
            (0x2000_0000, 0x0012_1800),
            (0x1000_0000, ALL),
        ] {
            if desired & generic != 0 {
                requested |= specific;
            }
        }
        if requested & 0x40 != 0 {
            requested |= 0x800;
        }
        if requested & 0x20 != 0 {
            requested |= 0x400;
        }
        if requested & 2 != 0 {
            requested |= 0x1000;
        }
        if requested & SECURITY != 0 && self.security_status != STATUS_SUCCESS {
            return Err(self.security_status);
        }
        if requested & !(self.maximum | SECURITY) != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if desired & MAXIMUM != 0 {
            requested = if requested & SECURITY != 0 {
                self.maximum_security.expect("validated security profile")
            } else {
                self.maximum
            };
        }
        Ok(requested)
    }
}

#[cfg(windows)]
#[path = "thread/installed.rs"]
mod installed;

pub(crate) fn snapshot() -> Result<Access, String> {
    #[cfg(windows)]
    {
        installed::capture()
    }
    #[cfg(not(windows))]
    {
        Err("native thread opening rights require Windows".into())
    }
}
