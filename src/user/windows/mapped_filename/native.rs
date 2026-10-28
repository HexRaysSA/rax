//! Native queries receive exclusively adapter-owned handles, views and buffers.
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

#[cfg(test)]
pub(crate) mod tests;

type Handle = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileMappingW(
        file: Handle,
        security: *const c_void,
        protection: u32,
        high: u32,
        low: u32,
        name: *const u16,
    ) -> Handle;
    fn MapViewOfFile(section: Handle, access: u32, high: u32, low: u32, size: usize) -> Handle;
    fn UnmapViewOfFile(address: Handle) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryVirtualMemory(
        process: Handle,
        address: Handle,
        class: u32,
        output: Handle,
        length: usize,
        returned: *mut usize,
    ) -> i32;
}

#[derive(Debug)]
pub(crate) struct View(Handle);

// SAFETY: this independently owned read-only host view has no guest pointer
// aliases. The kernel supports concurrent metadata queries; final ownership
// alone unmaps it. No guest operation can alter this host view or its lifetime.
unsafe impl Send for View {}
unsafe impl Sync for View {}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: one successful owned MapViewOfFile, retired exactly once.
        unsafe { UnmapViewOfFile(self.0) };
    }
}

impl View {
    pub(super) fn image(file: &File) -> io::Result<Self> {
        // SAFETY: retained live loader file, fixed read-only SEC_IMAGE_NO_EXECUTE
        // policy, NULL security/name, and no guest handle or address forwarded.
        let section = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                0x1100_0002,
                0,
                0,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: newly owned section, fixed read access, offset zero/full view.
        let result = unsafe { Self::section(section) };
        // SAFETY: this function owns the section handle. A successful mapped
        // view independently retains its file/section reference after closing.
        unsafe { CloseHandle(section) };
        result
    }

    /// # Safety
    /// `section` is a live adapter-owned image section for this synchronous map.
    pub(crate) unsafe fn section(section: Handle) -> io::Result<Self> {
        // SAFETY: caller supplies a live section; all remaining inputs are fixed.
        let view = unsafe { MapViewOfFile(section, 4, 0, 0, 0) };
        if view.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(view))
        }
    }

    /// O(L) time/space, bounded by the NT UNICODE_STRING byte-length ceiling.
    pub(crate) fn name(&self) -> io::Result<Vec<u16>> {
        // u64 elements provide native pointer alignment without treating bytes
        // returned by the kernel as a Rust reference or following its pointer.
        let mut output = vec![0u64; 8194];
        let capacity = output.len() * 8;
        let mut returned = 0;
        // SAFETY: current host process and independently owned live host view;
        // exact initialized/aligned host buffer plus exclusive SIZE_T output.
        let status = unsafe {
            NtQueryVirtualMemory(
                (-1isize) as Handle,
                self.0,
                2,
                output.as_mut_ptr().cast(),
                capacity,
                &mut returned,
            )
        };
        if status != 0 {
            return Err(io::Error::other(format!(
                "selected mapped filename query: {status:#010x}"
            )));
        }
        let header = 2 * std::mem::size_of::<usize>();
        let bytes: Vec<u8> = output.iter().flat_map(|word| word.to_le_bytes()).collect();
        let length = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
        let maximum = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let pointer_offset = std::mem::size_of::<usize>();
        let pointer = usize::from_le_bytes(bytes[pointer_offset..header].try_into().unwrap());
        if length % 2 != 0
            || length == 0
            || maximum != length + 2
            || returned != header + maximum
            || returned > capacity
            || pointer != output.as_ptr() as usize + header
            || bytes[header + length..header + maximum] != [0, 0]
        {
            return Err(io::Error::other("selected mapped filename layout changed"));
        }
        Ok(bytes[header..header + length]
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect())
    }
}
