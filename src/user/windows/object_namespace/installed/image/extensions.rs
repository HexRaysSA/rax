//! Bounded copies from the tail of this adapter's own SEC_IMAGE view.
use super::*;
use crate::user::windows::object_namespace::image::MAX_EXTENSION_BYTES;
use crate::user::windows::object_namespace::image::extension_query::{
    Disposition, ExtensionQuery, classify,
};

#[repr(C)]
#[derive(Default)]
struct Information {
    kind: u32,
    flags: u32,
    rva: usize,
    size: usize,
}
const _: [(); if std::mem::size_of::<usize>() == 8 {
    24
} else {
    16
}] = [(); std::mem::size_of::<Information>()];
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryVirtualMemory(
        process: Handle,
        address: Handle,
        class: u32,
        output: Handle,
        size: usize,
        returned: *mut usize,
    ) -> i32;
}

pub(super) fn capture(
    address: Handle,
    image_size: usize,
    native_machine: Option<u16>,
) -> io::Result<([Option<ImageExtension>; 2], ExtensionQuery)> {
    let mut result = [None, None];
    let mut query = ExtensionQuery::Both;
    for kind in 0..2 {
        let mut info = Information {
            kind,
            ..Default::default()
        };
        let mut returned = 0;
        // SAFETY: a live independently owned view and current process, fixed
        // class, correctly aligned initialized exclusive host ABI outputs.
        // No guest pointer, address, handle, size, or policy enters this call.
        let status = unsafe {
            NtQueryVirtualMemory(
                (-1isize) as Handle,
                address,
                14,
                (&mut info as *mut Information).cast(),
                std::mem::size_of::<Information>(),
                &mut returned,
            )
        };
        match classify(native_machine, kind, status as u32) {
            Ok(Disposition::ClassUnavailable) => {
                return Ok((result, ExtensionQuery::Unavailable));
            }
            Ok(Disposition::KindUnavailable) => {
                // Native AMD64 has no emulated CFG/SCP extension kind. Keep
                // the independently captured native type-0 mapping intact.
                if returned != 0
                    || info.kind != kind
                    || info.flags != 0
                    || info.rva != 0
                    || info.size != 0
                {
                    return Err(invalid("unavailable image extension modified outputs"));
                }
                query = ExtensionQuery::NativeOnly;
                continue;
            }
            Ok(Disposition::Read) => {}
            Err(status) => {
                return Err(invalid(&format!(
                    "NtQueryVirtualMemory selected image extension: {status:#010x}"
                )));
            }
        }
        if returned != std::mem::size_of::<Information>() || info.kind != kind || info.flags != 0 {
            return Err(invalid("selected native image extension ABI changed"));
        }
        if info.rva == 0 && info.size == 0 {
            continue;
        }
        if info.rva < image_size
            || info.rva % 4096 != 0
            || info.size == 0
            || info.size % 4096 != 0
            || info.size as u64 > MAX_EXTENSION_BYTES
            || info
                .rva
                .checked_add(info.size)
                .is_none_or(|end| end as u64 > image_size as u64 + 2 * MAX_EXTENSION_BYTES)
        {
            return Err(invalid("selected native image extension exceeds bounds"));
        }
        let at = (address as usize)
            .checked_add(info.rva)
            .ok_or_else(|| invalid("selected native extension address overflow"))?;
        let mut region = Region::default();
        // SAFETY: bounded tail address described by the live owned view's
        // kernel metadata; VirtualQuery receives an exclusive exact ABI output.
        if unsafe {
            VirtualQuery(
                at as *const c_void,
                &mut region,
                std::mem::size_of::<Region>(),
            )
        } != std::mem::size_of::<Region>()
        {
            return Err(io::Error::last_os_error());
        }
        if region.base != at
            || region.allocation != address as usize
            || region.kind != mem::IMAGE
            || region.state != mem::COMMIT
            || region.protection != prot::EXECUTE_READ
            || region.size < info.size
        {
            return Err(invalid("selected native extension page policy changed"));
        }
        let mut bytes = vec![0; info.size];
        let mut copied = 0;
        // SAFETY: metadata and VirtualQuery independently bound this source to
        // our owned readable view. The initialized Vec is exclusive and exactly
        // the requested length. The kernel copies bytes; no code is executed.
        if unsafe {
            ReadProcessMemory(
                (-1isize) as Handle,
                at as *const c_void,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                &mut copied,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if copied != bytes.len() {
            return Err(invalid("selected native extension short copy"));
        }
        result[kind as usize] = Some(ImageExtension {
            rva: info.rva as u64,
            bytes: bytes.into(),
        });
    }
    Ok((result, query))
}
