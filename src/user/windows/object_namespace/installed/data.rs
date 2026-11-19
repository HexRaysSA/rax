//! Fixed read-only host acquisition for installed CSR and theme data.
use super::{Handle, basic, check, invalid, section};
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::csr::CsrMetadata;
use crate::user::windows::object_namespace::data::{
    DataRegion, DataSection, MAX_SIZE, THEME_ATTRIBUTES, theme_directory, theme_header_path,
};
use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;
use std::sync::Arc;

#[repr(C)]
#[derive(Default)]
struct Region {
    base: usize,
    allocation: usize,
    allocation_protection: u32,
    #[cfg(target_pointer_width = "64")]
    partition_and_padding: u32,
    size: usize,
    state: u32,
    protection: u32,
    kind: u32,
}
const _: [(); if std::mem::size_of::<usize>() == 8 {
    48
} else {
    28
}] = [(); std::mem::size_of::<Region>()];
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtMapViewOfSection(
        section: Handle,
        process: Handle,
        base: *mut Handle,
        zero: usize,
        commit: usize,
        offset: *mut i64,
        size: *mut usize,
        inherit: u32,
        flags: u32,
        protection: u32,
    ) -> i32;
    fn NtUnmapViewOfSection(process: Handle, base: Handle) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualQuery(address: *const c_void, output: *mut Region, length: usize) -> usize;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        output: *mut c_void,
        size: usize,
        returned: *mut usize,
    ) -> i32;
}
struct View(Handle);
impl Drop for View {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: uniquely owned successful current-process view; no guest aliases.
            unsafe {
                NtUnmapViewOfSection((-1isize) as Handle, self.0);
            }
        }
    }
}
impl View {
    fn close(mut self) -> io::Result<()> {
        // SAFETY: the unique successful map is alive and consumed exactly once.
        check(
            unsafe { NtUnmapViewOfSection((-1isize) as Handle, self.0) },
            "unmap selected named data",
        )?;
        self.0 = null_mut();
        Ok(())
    }
}
pub(super) fn regions(base: usize, size: usize) -> io::Result<Vec<DataRegion>> {
    let mut offset = 0;
    let mut regions = Vec::new();
    let mut committed = 0usize;
    while offset < size {
        let address = base
            .checked_add(offset)
            .ok_or_else(|| invalid("CSR native view address overflow"))?;
        let mut region = Region::default();
        // SAFETY: queried address is a checked offset within our live host view;
        // exclusive initialized native ABI output, no dereference of guest data.
        let returned = unsafe {
            VirtualQuery(
                address as *const c_void,
                &mut region,
                std::mem::size_of::<Region>(),
            )
        };
        if returned != std::mem::size_of::<Region>()
            || region.base > address
            || region.allocation != base
            || region.kind != mem::MAPPED
            || region.size == 0
            || regions.len() >= 16384
        {
            return Err(invalid("selected CSR region identity/layout changed"));
        }
        let within = address - region.base;
        let span = region
            .size
            .checked_sub(within)
            .filter(|&n| n != 0)
            .ok_or_else(|| invalid("selected CSR region extent invalid"))?
            .min(size - offset);
        if span % 4096 != 0 {
            return Err(invalid("selected CSR region is not page aligned"));
        }
        let bytes = match region.state {
            mem::RESERVE if region.protection == 0 => None,
            mem::COMMIT if region.protection == prot::READONLY => {
                committed = committed
                    .checked_add(span)
                    .filter(|&n| n <= 16 << 20)
                    .ok_or_else(|| invalid("selected CSR committed bytes exceed bounds"))?;
                let mut bytes = vec![0u8; span];
                let mut got = 0usize;
                // SAFETY: live bounded read-only host view, exclusive initialized
                // destination of exactly span bytes and native SIZE_T output.
                // ReadProcessMemory handles concurrent unmapping/protection faults.
                let ok = unsafe {
                    ReadProcessMemory(
                        (-1isize) as Handle,
                        address as *const c_void,
                        bytes.as_mut_ptr().cast(),
                        span,
                        &mut got,
                    )
                };
                if ok == 0 || got != span {
                    return Err(io::Error::last_os_error());
                }
                Some(bytes.into())
            }
            _ => {
                return Err(invalid(
                    "selected CSR region is outside read-only snapshot profile",
                ));
            }
        };
        regions.push(DataRegion {
            offset: offset as u64,
            size: span as u64,
            bytes,
        });
        offset += span;
    }
    Ok(regions)
}
struct Snapshot {
    maximum_access: u32,
    security: u32,
    force_case_insensitive: bool,
    size: u64,
    regions: Vec<DataRegion>,
    csr: Option<CsrMetadata>,
}

pub(super) fn capture(
    session: Option<u32>,
    capture_client: bool,
) -> io::Result<(Arc<DataSection>, Option<CsrMetadata>)> {
    let path = DataSection::path_for_session(session);
    let view = snapshot(&path, capture_client, None)?;
    let selected = DataSection::selected_for_session(
        session,
        view.maximum_access,
        view.security,
        view.force_case_insensitive,
        view.size,
        view.regions,
    )?;
    Ok((selected, view.csr))
}

fn theme_section(session: u32, path: Vec<u16>, expected_size: u64) -> io::Result<Arc<DataSection>> {
    let view = snapshot(&path, false, Some(expected_size))?;
    DataSection::selected_theme(
        session,
        path,
        view.maximum_access,
        view.security,
        view.force_case_insensitive,
        view.size,
        view.regions,
    )
}

pub(super) fn capture_theme(session: u32) -> io::Result<[Arc<DataSection>; 3]> {
    let path = theme_header_path(session);
    let header = theme_section(session, path.clone(), 4096)?;
    let bytes = header
        .regions
        .first()
        .and_then(|region| region.bytes.as_deref())
        .ok_or_else(|| invalid("selected theme directory has no readable header"))?;
    let [(global, global_size), (local, local_size)] = theme_directory(session, bytes)?;
    let global = theme_section(session, global, global_size)?;
    let local = theme_section(session, local, local_size)?;
    if !global
        .regions
        .first()
        .and_then(|region| region.bytes.as_deref())
        .is_some_and(|bytes| bytes.starts_with(b"BEGINTHM"))
    {
        return Err(invalid(
            "selected global theme resource has an unmeasured layout",
        ));
    }
    let current = theme_section(session, path, 4096)?;
    if current.regions != header.regions
        || current.grant(0x0200_0000, false) != header.grant(0x0200_0000, false)
        || current.grant(0x0100_0000, false) != header.grant(0x0100_0000, false)
    {
        return Err(invalid(
            "selected theme directory changed during resource capture",
        ));
    }
    Ok([header, global, local])
}

fn snapshot(path: &[u16], capture_client: bool, theme_size: Option<u64>) -> io::Result<Snapshot> {
    let handle = section::open_section(path, 0x0200_0000, 0x40)?
        .map_err(|status| invalid(&format!("open selected named data: {status:#010x}")))?;
    let maximum_access = basic(&handle)?;
    if let Some(size) = theme_size {
        section::validate(&handle, THEME_ATTRIBUTES, size)?;
    }
    let security = match section::open_section(path, 0x0100_0000, 0x40)? {
        Ok(security) => {
            if basic(&security)? != 0x0100_0000 {
                return Err(invalid("selected data security grant differs"));
            }
            security.close()?;
            0
        }
        Err(status @ (STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD)) => status,
        Err(status) => {
            return Err(invalid(&format!(
                "selected data security status: {status:#010x}"
            )));
        }
    };
    let altered: Vec<_> = path
        .iter()
        .map(|&unit| match unit {
            65..=90 => unit + 32,
            97..=122 => unit - 32,
            _ => unit,
        })
        .collect();
    let explicit = section::open_section(&altered, 0x0200_0000, 0x40)?.map_err(|status| {
        invalid(&format!(
            "selected data explicit case status: {status:#010x}"
        ))
    })?;
    if basic(&explicit)? != maximum_access {
        return Err(invalid("selected data folded grant differs"));
    }
    explicit.close()?;
    let force_case_insensitive = match section::open_section(&altered, 0x0200_0000, 0)? {
        Ok(folded) => {
            if basic(&folded)? != maximum_access {
                return Err(invalid("selected data case grant differs"));
            }
            folded.close()?;
            true
        }
        Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => false,
        Err(status) => {
            return Err(invalid(&format!(
                "selected data case status: {status:#010x}"
            )));
        }
    };
    let (mut address, mut size) = (null_mut(), 0usize);
    // SAFETY: fixed successfully owned host section; current-process pseudo
    // handle, exclusive native address/SIZE_T outputs, no guest inputs, and a
    // read-only view with zero commitment request. No installed bytes are written.
    check(
        unsafe {
            NtMapViewOfSection(
                handle.0,
                (-1isize) as Handle,
                &mut address,
                0,
                0,
                null_mut(),
                &mut size,
                2,
                0,
                prot::READONLY,
            )
        },
        "map selected named data snapshot",
    )?;
    let view = View(address);
    if address.is_null()
        || size == 0
        || size as u64 > MAX_SIZE
        || size % 4096 != 0
        || theme_size.is_some_and(|expected| size as u64 != expected)
    {
        return Err(invalid("selected native data map exceeds bounds"));
    }
    let mut captured = None;
    for _ in 0..3 {
        let first = regions(view.0 as usize, size)?;
        if first == regions(view.0 as usize, size)? {
            captured = Some(first);
            break;
        }
    }
    let captured =
        captured.ok_or_else(|| invalid("selected data changed during bounded snapshot"))?;
    let metadata = if capture_client {
        super::csr::capture(&captured)?
    } else {
        None
    };
    if basic(&handle)? != maximum_access {
        return Err(invalid("selected data grant changed during snapshot"));
    }
    if let Some(size) = theme_size {
        section::validate(&handle, THEME_ATTRIBUTES, size)?;
        if captured.iter().any(|region| region.bytes.is_none()) {
            return Err(invalid("selected theme section is not fully committed"));
        }
    }
    view.close()?;
    handle.close()?;
    Ok(Snapshot {
        maximum_access,
        security,
        force_case_insensitive,
        size: size as u64,
        regions: captured,
        csr: metadata,
    })
}
