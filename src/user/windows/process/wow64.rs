//! Process-owned WoW64 startup metadata and the software-emulator work section.
//!
//! Layouts are bound to the independent startup-information controls. Host
//! pointers, handles and the native XtA callback never enter guest memory.
//! RAX executes instructions and performs code-coherency work in its own CPU
//! adapter; it has no native XtA instrumentation callback to publish.

use std::sync::Arc;

use super::Proc;
use crate::user::mm::{PAGE_SIZE, SharedObject};
use crate::user::windows::arch::WinArch;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, SharedViewOwner, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const WORK_BYTES: u64 = 0x4000;
const WORK_HEADER: usize = 48;
const WORK_ENTRY: usize = 40;
const WORK_ENTRIES: usize = (WORK_BYTES as usize - WORK_HEADER) / WORK_ENTRY;

#[derive(Clone, Copy, Debug)]
struct Profile {
    machine: u16,
    kernel: (u32, u32, u32),
    flags: u32,
    information_offset: u64,
}

impl Profile {
    fn kernel(version: &super::WinVersion, machine: u16) -> Result<Self, u32> {
        let (flags, information_offset) =
            match (version.major, version.minor, version.build, machine) {
                (10, 0, 20348 | 26100, 0x8664) => (1, 0x488),
                (10, 0, 29683 | 29695, 0xaa64) => (2, 0x490),
                _ => return Err(STATUS_NOT_SUPPORTED),
            };
        Ok(Self {
            machine,
            kernel: (version.major, version.minor, version.build),
            flags,
            information_offset,
        })
    }

    fn select(p: &Proc) -> Result<Option<Self>, u32> {
        if p.arch != WinArch::X86 {
            return Ok(None);
        }
        let Some(native) = p.native.as_ref() else {
            return Ok(None);
        };
        let version = &native.version;
        let machine = native
            .object_namespace
            .native_machine
            .ok_or(STATUS_NOT_SUPPORTED)?;
        Self::kernel(version, machine).map(Some)
    }
}

#[derive(Debug)]
pub(crate) struct State {
    pub(crate) information: u64,
    pub(crate) native_peb: u64,
    pub(crate) machine: u16,
    pub(crate) kernel: (u32, u32, u32),
    pub(crate) csr: Option<CsrConnection>,
    _work_view: Option<SharedViewOwner>,
}

/// The port table owns the peer and writable view; the VM owns this readonly
/// alias. Both identities are checked before a later bridge call reuses them.
#[derive(Debug)]
pub(crate) struct CsrConnection {
    pub(crate) section: Arc<crate::user::windows::object_namespace::DataSection>,
    pub(crate) base: u64,
    pub(crate) port: u32,
    pub(crate) object: crate::user::windows::objects::ObjId,
}

#[cfg(test)]
pub(crate) fn initialize_test_profile(p: &mut Proc, machine: u16) -> Result<(), u32> {
    initialize_profile(p, Profile::kernel(&p.cfg.version, machine)?)
}

/// Called once after executable/dependency admission and before any guest code.
pub(super) fn initialize(p: &mut Proc) -> Result<(), u32> {
    match Profile::select(p)? {
        None => Ok(()),
        Some(profile) => initialize_profile(p, profile),
    }
}

fn work_bytes() -> Vec<u8> {
    let mut bytes = vec![0; WORK_BYTES as usize];
    let mut previous = 0u32;
    for index in 0..WORK_ENTRIES {
        let offset = WORK_HEADER + index * WORK_ENTRY;
        bytes[offset..offset + 4].copy_from_slice(&previous.to_le_bytes());
        previous = offset as u32;
    }
    bytes[..4].copy_from_slice(&previous.to_le_bytes());
    bytes[4..8].copy_from_slice(&(WORK_ENTRIES as u32).to_le_bytes());
    bytes
}

fn initialize_profile(p: &mut Proc, profile: Profile) -> Result<(), u32> {
    if p.wow64.is_some() || p.arch != WinArch::X86 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (native_peb, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .map_err(|error| error.status())?;
    let mut section_handle = None;
    let mut work_view = None;
    let result = (|| {
        let native_offsets = offsets(WinArch::X64);
        // There is no guest native64 RTL instance. Its identity page describes
        // the same process; loader/heap/parameter pointers remain absent.
        p.space
            .w64(
                native_peb + native_offsets.peb_image_base,
                p.modules.exe().base,
            )
            .map_err(|_| STATUS_NO_MEMORY)?;
        for (offset, value) in [
            (native_offsets.peb_number_of_processors, 1),
            (native_offsets.peb_os_major, p.cfg.version.major),
            (native_offsets.peb_os_minor, p.cfg.version.minor),
            (native_offsets.peb_os_platform_id, 2),
        ] {
            p.space
                .w32(native_peb + offset, value)
                .map_err(|_| STATUS_NO_MEMORY)?;
        }
        p.space
            .w16(
                native_peb + native_offsets.peb_os_build,
                p.cfg.version.build as u16,
            )
            .map_err(|_| STATUS_NO_MEMORY)?;

        if profile.flags & 2 != 0 {
            let shared =
                Arc::new(SharedObject::anonymous(WORK_BYTES).map_err(|_| STATUS_NO_MEMORY)?);
            let view =
                p.vm.map_shared_view(shared.clone(), None, 0, WORK_BYTES)
                    .map_err(|error| error.status())?;
            let base = view.base;
            work_view = Some(view);
            p.space
                .wr(base, &work_bytes())
                .map_err(|_| STATUS_NO_MEMORY)?;
            let id = p
                .objects
                .try_create(Object::Mapping {
                    file: None,
                    size: WORK_BYTES,
                    protect: prot::READWRITE,
                    attributes: 0x0800_0000,
                    shared: Some(shared),
                })
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            let Some(handle) = p.objects.open_access(id, false, 0x000f_001f) else {
                p.objects.release(id);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            };
            section_handle = Some(handle);
        }

        let information = p
            .peb
            .checked_add(profile.information_offset)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let mut bytes = [0u8; 40];
        bytes[..4].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&profile.flags.to_le_bytes());
        bytes[16..24].copy_from_slice(&u64::from(section_handle.unwrap_or(0)).to_le_bytes());
        bytes[24..32]
            .copy_from_slice(&work_view.as_ref().map_or(0, |view| view.base).to_le_bytes());
        bytes[32..34].copy_from_slice(&profile.machine.to_le_bytes());
        bytes[34..36].copy_from_slice(&WinArch::X86.machine().to_le_bytes());
        p.space
            .wr(information, &bytes)
            .map_err(|_| STATUS_NO_MEMORY)?;
        Ok(information)
    })();
    match result {
        Ok(information) => {
            p.wow64 = Some(State {
                information,
                native_peb,
                machine: profile.machine,
                kernel: profile.kernel,
                csr: None,
                _work_view: work_view,
            });
            Ok(())
        }
        Err(status) => {
            if let Some(handle) = section_handle {
                let _ = p.objects.close(u64::from(handle));
            }
            if let Some(view) = work_view {
                let _ = p.vm.release(view.base);
            }
            let _ = p.vm.release(native_peb);
            Err(status)
        }
    }
}

#[cfg(test)]
mod tests;
