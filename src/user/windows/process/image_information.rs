//! Immutable image-section metadata captured from the admitted executable.
//!
//! Private SECTION_IMAGE_INFORMATION fields are qualified by the owned native
//! controls in `docs/specifications/windows/native-process-image-information/`.
//! Guest writes to mapped PE headers never change this process-owned snapshot.

use crate::user::image::pe::{
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_FILE_RELOCS_STRIPPED, IMAGE_SUBSYSTEM_WINDOWS_CUI,
    IMAGE_SUBSYSTEM_WINDOWS_GUI, PeHeaders, PeImage, dir,
};
use crate::user::windows::arch::WinArch;

#[derive(Clone, Debug)]
pub(crate) struct ImageInformation {
    transfer_address: u64,
    headers: PeHeaders,
    file_size: u32,
}

impl ImageInformation {
    /// Capture ordinary executable metadata after the loader chose its entry.
    /// Other image profiles remain explicit unsupported states; spawn behavior
    /// and unrelated loader services do not change because a query is unavailable.
    pub(crate) fn capture(pe: &PeImage, transfer_address: u64) -> Result<Self, &'static str> {
        let headers = pe.headers();
        let arch = WinArch::from_machine(headers.machine).ok_or("unknown executable machine")?;
        if headers.is_dll()
            || pe.low_alignment()
            || headers.directory(dir::COM_DESCRIPTOR).is_present()
            || !matches!(
                headers.subsystem,
                IMAGE_SUBSYSTEM_WINDOWS_GUI | IMAGE_SUBSYSTEM_WINDOWS_CUI
            )
            || !pe.sections().iter().any(|section| section.executable())
            || headers.entry_rva == 0
        {
            return Err("unqualified managed, flat, resource-only or non-executable image profile");
        }
        if arch == WinArch::X86 && transfer_address > u64::from(u32::MAX) {
            return Err("32-bit executable entry exceeds the guest pointer width");
        }
        let file_size = u32::try_from(pe.bytes().len())
            .map_err(|_| "executable file size exceeds SECTION_IMAGE_INFORMATION's ULONG")?;
        Ok(Self {
            transfer_address,
            headers: headers.clone(),
            file_size,
        })
    }

    /// Explicit little-endian native64 (64-byte) or WoW64 (48-byte) layout.
    /// The native padding at bytes 12..16 is zeroed but excluded from native
    /// byte-equivalence claims. The record owns no host pointer or live PE view.
    pub(crate) fn encode(&self, arch: WinArch) -> Result<([u8; 64], usize), &'static str> {
        let h = &self.headers;
        if WinArch::from_machine(h.machine) != Some(arch) {
            return Err("executable machine differs from the process guest architecture");
        }
        let mut bytes = [0u8; 64];
        let (subsystem, size) = if arch == WinArch::X86 {
            bytes[..4].copy_from_slice(&(self.transfer_address as u32).to_le_bytes());
            bytes[8..12].copy_from_slice(&(h.stack_reserve as u32).to_le_bytes());
            bytes[12..16].copy_from_slice(&(h.stack_commit as u32).to_le_bytes());
            (16, 48)
        } else {
            bytes[..8].copy_from_slice(&self.transfer_address.to_le_bytes());
            bytes[16..24].copy_from_slice(&h.stack_reserve.to_le_bytes());
            bytes[24..32].copy_from_slice(&h.stack_commit.to_le_bytes());
            (32, 64)
        };
        // ZeroBits is zero in all qualified executable profiles. Its position
        // and native padding are already initialized.
        bytes[subsystem..subsystem + 4].copy_from_slice(&u32::from(h.subsystem).to_le_bytes());
        for (offset, value) in [
            (4, h.subsystem_version.1),
            (6, h.subsystem_version.0),
            (8, h.os_version.0),
            (10, h.os_version.1),
            (12, h.characteristics),
            (14, h.dll_characteristics),
            (16, h.machine),
        ] {
            bytes[subsystem + offset..subsystem + offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[subsystem + 18] = 1;
        // This is the image's dynamic-base/relocation policy, not a test of
        // whether this particular load happened to move from its preferred base.
        bytes[subsystem + 19] = if h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            != 0
            && h.characteristics & IMAGE_FILE_RELOCS_STRIPPED == 0
        {
            4
        } else {
            0
        };
        for (offset, value) in [(20, h.loader_flags), (24, self.file_size), (28, h.checksum)] {
            bytes[subsystem + offset..subsystem + offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        Ok((bytes, size))
    }
}
