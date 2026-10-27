//! Pinned native section identity; only host-owned pointers enter these APIs.
use super::*;
use crate::user::windows::memory::{mem, prot};
use std::fmt;
mod extensions;

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
        zero_bits: usize,
        commit: usize,
        offset: *mut i64,
        size: *mut usize,
        inherit: u32,
        allocation: u32,
        protection: u32,
    ) -> i32;
    fn NtUnmapViewOfSection(process: Handle, address: Handle) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualQuery(address: *const c_void, output: *mut Region, size: usize) -> usize;
    fn VirtualProtect(address: Handle, size: usize, protection: u32, old: *mut u32) -> i32;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        output: Handle,
        size: usize,
        returned: *mut usize,
    ) -> i32;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
}
pub(crate) struct Source {
    handle: Owned,
    _creation: Option<Owned>,
    attributes: u32,
    size: u64,
}
impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedImageSection")
            .field("size", &self.size)
            .finish()
    }
}
// SAFETY: the HANDLE is a kernel-refcounted immutable Section object. It is
// never closed until the final Arc drops and is never exposed to guest code.
// NT read/query/map operations accept the same live handle across host threads;
// each image acquisition creates an independently owned current-process view.
unsafe impl Send for Source {}
unsafe impl Sync for Source {}

struct View(Handle);
impl Drop for View {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: sole owned successful current-process map; no guest aliases.
            unsafe {
                NtUnmapViewOfSection((-1isize) as Handle, self.0);
            }
        }
    }
}
impl View {
    fn close(mut self) -> io::Result<()> {
        let address = self.0;
        // SAFETY: sole successful current-process map, consumed exactly once.
        check(
            unsafe { NtUnmapViewOfSection((-1isize) as Handle, address) },
            "NtUnmapViewOfSection selected image template",
        )?;
        self.0 = null_mut();
        Ok(())
    }
}
impl Source {
    pub(super) fn new(handle: Owned, attributes: u32, size: u64) -> Arc<Self> {
        Arc::new(Self {
            handle,
            _creation: None,
            attributes,
            size,
        })
    }
    pub(super) fn with_creation(
        handle: Owned,
        attributes: u32,
        size: u64,
        creation: Owned,
    ) -> Arc<Self> {
        Arc::new(Self {
            handle,
            attributes,
            size,
            _creation: Some(creation),
        })
    }
    pub(crate) fn image(&self) -> io::Result<Arc<ImageTemplate>> {
        self.acquire(None)
    }
    pub(crate) fn image_machine(&self, machine: u16) -> io::Result<Arc<ImageTemplate>> {
        self.acquire(Some(machine))
    }
    fn acquire(&self, machine: Option<u16>) -> io::Result<Arc<ImageTemplate>> {
        let (original, view) = self.capture(machine, 0)?;
        let image = if original.extensions.iter().any(Option::is_some) {
            // Keep all three independent views alive until comparison completes;
            // otherwise the kernel may reuse an identical temporary address.
            let (first, first_view) = self.capture(machine, 0x0080_0000)?;
            let (second, second_view) = self.capture(machine, 0x0080_0000)?;
            let image = ImageTemplate::with_rebase(original, &first, &second)?;
            second_view.close()?;
            first_view.close()?;
            image
        } else {
            original
        };
        view.close()?;
        Ok(image)
    }
    fn capture(&self, machine: Option<u16>, flags: u32) -> io::Result<(Arc<ImageTemplate>, View)> {
        if !(4096..=super::super::image::MAX_IMAGE_BYTES).contains(&self.size) {
            return Err(invalid("selected kernel image template exceeds 64 MiB"));
        }
        section::validate(&self.handle, self.attributes, self.size)?;
        let (mut address, mut size) = (null_mut(), 0usize);
        // SAFETY: pinned selected section, current-process pseudo handle, exclusive
        // initialized host HANDLE/SIZE_T outputs, NULL optional host offset. No
        // guest rights, address, flag, handle, or pointer enters the kernel.
        let status = if let Some(machine) = machine {
            // MEM_EXTENDED_PARAMETER_TYPE ImageMachine=6. The fixed architecture
            // selector requests the kernel's ARM64X projection; all buffers,
            // outputs and the current-process view belong to this adapter.
            #[repr(C, align(8))]
            struct Extended {
                kind: u64,
                value: u64,
            }
            type MapEx = unsafe extern "system" fn(
                Handle,
                Handle,
                *mut Handle,
                *mut i64,
                *mut usize,
                u32,
                u32,
                *mut Extended,
                u32,
            ) -> i32;
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            // SAFETY: terminated owned UTF-16 name and already-loaded process-
            // lifetime module; the fixed ASCII export is also terminated.
            let module = unsafe { GetModuleHandleW(name.as_ptr()) };
            if module.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: live process-lifetime module, fixed terminated export.
            let entry = unsafe { GetProcAddress(module, c"NtMapViewOfSectionEx".as_ptr().cast()) };
            if entry.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "installed image projection requires NtMapViewOfSectionEx",
                ));
            }
            // SAFETY: exact NTAPI prototype from PHNT and Microsoft DDI; resolved
            // executable code remains live. No call or callback crosses unwind.
            let map: MapEx = unsafe { std::mem::transmute(entry) };
            let mut parameter = Extended {
                kind: 6,
                value: u64::from(machine),
            };
            // SAFETY: pinned selected section, current process, initialized
            // exclusive native outputs and exactly one aligned host parameter.
            unsafe {
                map(
                    self.handle.0,
                    (-1isize) as Handle,
                    &mut address,
                    null_mut(),
                    &mut size,
                    flags,
                    prot::READONLY,
                    &mut parameter,
                    1,
                )
            }
        } else {
            unsafe {
                NtMapViewOfSection(
                    self.handle.0,
                    (-1isize) as Handle,
                    &mut address,
                    0,
                    0,
                    null_mut(),
                    &mut size,
                    2,
                    flags,
                    prot::READONLY,
                )
            }
        };
        check(status, "NtMapViewOfSection selected image template")?;
        if address.is_null() {
            return Err(invalid("selected native image view is NULL"));
        }
        let view = View(address);
        if size as u64 != self.size || (address as usize).checked_add(size).is_none() {
            return Err(invalid("selected native image view extent changed"));
        }
        let mut bytes = vec![0u8; size];
        let mut regions = Vec::new();
        let mut reserved_tail = 0;
        let mut offset = 0usize;
        while offset < size {
            let at = (address as usize) + offset;
            let mut region = Region::default();
            // SAFETY: live bounded owned host view and exact exclusive native ABI output.
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
            if regions.len() >= 256 {
                return Err(invalid("selected native image region exceeds its view"));
            }
            let selected = super::super::image::region::Query {
                base: region.base as u64,
                allocation: region.allocation as u64,
                size: region.size as u64,
                state: region.state,
                protection: region.protection,
                kind: region.kind,
            }
            .select(address as usize as u64, size as u64, offset as u64)?;
            reserved_tail = reserved_tail.max(selected.reserved_tail);
            // The selected span is at most the 64 MiB logical image, including
            // on 32-bit hosts. Never copy/protect native allocation padding.
            let region_size = selected.region.size as usize;
            regions.push(selected.region);
            if region.state == mem::COMMIT {
                let mut old = 0;
                let altered = region.protection & (prot::NOACCESS | prot::GUARD) != 0;
                // SAFETY: alters only this adapter's independently owned host view;
                // capture preserves the original protection and never executes it.
                if altered
                    && unsafe {
                        VirtualProtect(at as Handle, region_size, prot::READONLY, &mut old)
                    } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let mut returned = 0;
                // SAFETY: checked host source run and exclusive equally sized initialized
                // Vec slice; ReadProcessMemory safely reports inaccessible host pages.
                let copied = unsafe {
                    ReadProcessMemory(
                        (-1isize) as Handle,
                        at as *const c_void,
                        bytes[offset..].as_mut_ptr().cast(),
                        region_size,
                        &mut returned,
                    )
                };
                let error = io::Error::last_os_error();
                let mut ignored = 0;
                // SAFETY: restores only the region changed immediately above; live owned view.
                if altered
                    && unsafe { VirtualProtect(at as Handle, region_size, old, &mut ignored) } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                if copied == 0 {
                    return Err(error);
                }
                if returned != region_size {
                    return Err(invalid("selected native image short read"));
                }
            } else if region.state != mem::RESERVE {
                return Err(invalid(
                    "selected native image region is neither committed nor reserved",
                ));
            }
            offset += region_size;
        }
        section::validate(&self.handle, self.attributes, self.size)?;
        let extensions = extensions::capture(address, size)?;
        let image = ImageTemplate::selected_extended(bytes, regions, extensions)?;
        let payload = image.allocation_size();
        let at = (address as usize)
            .checked_add(payload as usize)
            .ok_or_else(|| invalid("selected native image tail address overflow"))?;
        let mut tail = Region::default();
        // SAFETY: metadata-only query immediately after this owned view's
        // bounded explicit image/extension bytes. No memory is dereferenced.
        if unsafe {
            VirtualQuery(
                at as *const c_void,
                &mut tail,
                std::mem::size_of::<Region>(),
            )
        } != std::mem::size_of::<Region>()
        {
            return Err(io::Error::last_os_error());
        }
        let padding = super::super::image::region::Query {
            base: tail.base as u64,
            allocation: tail.allocation as u64,
            size: tail.size as u64,
            state: tail.state,
            protection: tail.protection,
            kind: tail.kind,
        }
        .reserved_after(address as usize as u64, payload)?;
        if payload + padding < size as u64 + reserved_tail {
            return Err(invalid(
                "selected native image reserved tail changed during capture",
            ));
        }
        let image = ImageTemplate::with_reserved_tail(image, padding)?;
        if flags & 0x0080_0000 != 0 && image.preferred != address as usize as u64 {
            return Err(invalid(
                "native flagged image did not publish its actual base",
            ));
        }
        let native_machine = section::native_machine()?;
        if native_machine.is_none() && image.extensions.iter().any(Option::is_some) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "image extensions require native machine identity",
            ));
        }
        let image = if native_machine.is_some_and(|machine| image.machine != machine) {
            ImageTemplate::without_large_pages(image)?
        } else {
            image
        };
        Ok((image, view))
    }
}
