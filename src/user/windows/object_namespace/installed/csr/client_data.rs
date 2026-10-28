//! Fixed current-process CSR client query, acquired before guest publication.
use crate::user::windows::object_namespace::csr::CsrMetadata;
use crate::user::windows::object_namespace::csr::client_data::{
    ClientView, CsrClientData, INFORMATION_BYTES,
};
use crate::user::windows::object_namespace::data::DataSection;
use crate::user::windows::object_namespace::installed::{check, data, invalid};
use std::ffi::c_void;
use std::io;
use std::sync::Arc;

#[repr(C)]
#[derive(Default)]
struct Region {
    base: usize,
    allocation: usize,
    allocation_protection: u32,
    partition_and_padding: u32,
    size: usize,
    state: u32,
    protection: u32,
    kind: u32,
}
const _: [(); 48] = [(); std::mem::size_of::<Region>()];

#[link(name = "ntdll")]
unsafe extern "system" {
    fn CsrClientConnectToServer(
        directory: *const u16,
        server: u32,
        information: *mut c_void,
        bytes: u32,
        inside_server: *mut u8,
    ) -> i32;
    fn CsrGetProcessId() -> usize;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualQuery(address: *const c_void, output: *mut Region, bytes: usize) -> usize;
}

/// A native pointer is validated by VirtualQuery/RPM, never dereferenced here.
fn allocation(base: u64, size: usize) -> io::Result<Arc<DataSection>> {
    let base = usize::try_from(base).map_err(|_| invalid("CSR client base exceeds host width"))?;
    let mut cursor = 0usize;
    while cursor < size {
        let address = base
            .checked_add(cursor)
            .ok_or_else(|| invalid("CSR client address overflow"))?;
        let mut region = Region::default();
        // SAFETY: current-process address value supplied by a fixed native
        // query; exclusive initialized repr(C) output. No guest inputs.
        let got = unsafe {
            VirtualQuery(
                address as *const c_void,
                &mut region,
                std::mem::size_of::<Region>(),
            )
        };
        if got != std::mem::size_of::<Region>()
            || region.allocation != base
            || region.base != address
            || region.size == 0
            || region.size > size - cursor
        {
            return Err(invalid("CSR client allocation extent/identity differs"));
        }
        cursor += region.size;
    }
    let mut following = Region::default();
    let end = base
        .checked_add(size)
        .ok_or_else(|| invalid("CSR client extent overflow"))?;
    // SAFETY: query only, bounded host address and exclusive ABI output.
    if unsafe {
        VirtualQuery(
            end as *const c_void,
            &mut following,
            std::mem::size_of::<Region>(),
        )
    } != std::mem::size_of::<Region>()
        || following.allocation == base
    {
        return Err(invalid("CSR client allocation exceeds selected extent"));
    }
    // The common capture routine requires readonly MEM_MAPPED runs, reserves,
    // full bounded reads and checked region identities. These views belong to
    // NTDLL/USER; this code never unmaps or closes them.
    for _ in 0..3 {
        let first = data::regions(base, size)?;
        if first == data::regions(base, size)? {
            return DataSection::private_readonly(size as u64, first);
        }
    }
    Err(invalid("CSR client data changed during bounded capture"))
}

pub(super) fn capture(metadata: &CsrMetadata) -> io::Result<Arc<CsrClientData>> {
    if metadata.arch != crate::user::windows::arch::WinArch::Arm64 || metadata.session != 0 {
        return Err(invalid(
            "CSR client capture requires matched ARM64/session0 profile",
        ));
    }
    let mut directory: Vec<_> = "\\Windows".encode_utf16().chain([0]).collect();
    let mut information = [0u8; INFORMATION_BYTES];
    let mut inside = 0xA5;
    // SAFETY: reached only after the existing current-process build29683/29695,
    // architecture/session/section checks. Scalar ULONG ABI was measured in
    // native V4-V7 and an independent syscall entry/return controller. Fixed
    // directory, server3, zero initialized584B buffer; no guest data/callback.
    check(
        unsafe {
            CsrClientConnectToServer(
                directory.as_mut_ptr(),
                3,
                information.as_mut_ptr().cast(),
                INFORMATION_BYTES as u32,
                &mut inside,
            )
        },
        "capture fixed CSR USER connection data",
    )?;
    // SAFETY: fixed no-argument export under the same verified native profile.
    if inside != 0 || unsafe { CsrGetProcessId() } != metadata.server_pid as usize {
        return Err(invalid("CSR USER reply server identity differs"));
    }
    let base = |offset| {
        u64::from_le_bytes(
            information[offset..offset + 8]
                .try_into()
                .expect("fixed CSR base field"),
        )
    };
    let handle_base = base(16);
    let shared_base = base(40);
    let views = [
        ClientView {
            base: handle_base,
            section: allocation(handle_base, 1 << 21)?,
        },
        ClientView {
            base: shared_base,
            section: allocation(shared_base, 32768)?,
        },
    ];
    CsrClientData::selected(information, views)
}
