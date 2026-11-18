//! File-backed image bytes and object grants, independent of guest pointers.
use super::{ImageTemplate, SectionGrantError as GrantError};
use std::fs::File;
use std::sync::Arc;

mod portable;

const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_IMAGE_NO_EXECUTE: u32 = 0x1100_0000;

/// A native64 SectionImageInformation record in guest address coordinates.
#[derive(Debug)]
pub(crate) struct SectionImageInformation([u8; 64]);

impl SectionImageInformation {
    pub(crate) fn capture(image: &ImageTemplate, mut bytes: [u8; 64]) -> Option<Self> {
        let machine = u16::from_le_bytes(bytes[48..50].try_into().unwrap());
        let characteristics = u16::from_le_bytes(bytes[44..46].try_into().unwrap());
        let entry = image.entry_rva();
        let recorded_transfer = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let recorded_base = recorded_transfer.checked_sub(entry)?;
        if !matches!(machine, 0xaa64 | 0x8664 | 0x014c)
            || machine != image.machine
            || characteristics & 0x2000 != 0
            || bytes[50] != 1
            || entry == 0
            || entry >= image.bytes.len() as u64
            || recorded_base % 65536 != 0
        {
            return None;
        }
        let transfer = image.preferred.checked_add(entry)?;
        if machine == 0x014c && u32::try_from(transfer).is_err() {
            return None;
        }
        bytes[..8].copy_from_slice(&transfer.to_le_bytes());
        bytes[12..16].fill(0);
        Some(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub(crate) fn wow64_bytes(&self) -> Option<[u8; 48]> {
        if u16::from_le_bytes(self.0[48..50].try_into().unwrap()) != 0x014c {
            return None;
        }
        let mut bytes = [0; 48];
        // TransferAddress and the two stack sizes narrow to the caller width.
        for (destination, source) in [(0, 0), (8, 16), (12, 24)] {
            let value = u64::from_le_bytes(self.0[source..source + 8].try_into().unwrap());
            bytes[destination..destination + 4]
                .copy_from_slice(&u32::try_from(value).ok()?.to_le_bytes());
        }
        bytes[4..8].copy_from_slice(&self.0[8..12]);
        bytes[16..].copy_from_slice(&self.0[32..]);
        Some(bytes)
    }
}

pub(crate) struct Backing {
    pub(crate) template: Arc<ImageTemplate>,
    pub(crate) maximum: u64,
    pub(crate) attributes: u32,
    pub(crate) no_execute: bool,
    pub(crate) information: Option<SectionImageInformation>,
    #[cfg(windows)]
    pub(crate) source: Option<Arc<super::installed::image::Source>>,
}

#[derive(Debug)]
pub(crate) enum Error {
    Status(u32),
    Unavailable(String),
}

pub(crate) fn grant(access: u32, security: Option<u32>) -> Result<u32, GrantError> {
    if access & 0x0100_0000 != 0 {
        match security {
            Some(0) => {}
            Some(status) => return Err(GrantError::Status(status)),
            None => {
                return Err(GrantError::Unavailable(
                    "created section security privilege is not captured",
                ));
            }
        }
    }
    let mut grant = access & 0x011F_001F;
    for (generic, specific) in [
        (0x8000_0000, 0x0002_0005),
        (0x4000_0000, 0x0002_0002),
        (0x2000_0000, 0x0002_0008),
        (0x1000_0000, 0x000F_001F),
        (0x0200_0000, 0x000F_001F),
    ] {
        if access & generic != 0 {
            grant |= specific;
        }
    }
    Ok(grant)
}

pub(crate) fn acquire(
    file: &File,
    maximum: u64,
    protection: u32,
    flags: u32,
    native: bool,
) -> Result<Backing, Error> {
    let no_execute = match flags & !1 {
        SEC_IMAGE => false,
        SEC_IMAGE_NO_EXECUTE => true,
        _ => {
            return Err(Error::Unavailable(
                "file-backed image allocation mode is not selected".into(),
            ));
        }
    };
    #[cfg(windows)]
    if native {
        return admitted(super::installed::file_image::acquire(
            file, maximum, protection, flags, no_execute,
        )?);
    }
    #[cfg(not(windows))]
    let _ = native;
    let _ = protection;
    admitted(portable::acquire(file, maximum, no_execute)?)
}

fn admitted(backing: Backing) -> Result<Backing, Error> {
    // Native v14 proves shared writable image pages alias across independently
    // created Sections. The current image VM owns private frames; accepting
    // these runs would return success with incorrect sharing semantics.
    if backing
        .template
        .regions
        .iter()
        .any(|region| matches!(region.protection & 0xFF, 4 | 0x40))
    {
        return Err(Error::Unavailable(
            "file-backed image shared writable section coherence is not implemented".into(),
        ));
    }
    Ok(backing)
}
