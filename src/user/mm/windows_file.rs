//! Positional access to Windows mapping backing files without moving their
//! shared file cursor. Views are bounded to 1 MiB plus the alignment prefix.
//! The kernel copies bytes from/to each view: an in-page I/O error must become
//! an `io::Error`, not an access violation from dereferencing the view in Rust.
//! Writes flush the modified view and file before returning to ordinary file
//! I/O consumers. This is O(n) time and O(1) additional address space.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::NonNull;
use std::sync::OnceLock;

type Handle = *mut c_void;
const CHUNK: usize = 1 << 20;
const PAGE_READONLY: u32 = 2;
const PAGE_READWRITE: u32 = 4;
const FILE_MAP_WRITE: u32 = 2;
const FILE_MAP_READ: u32 = 4;

#[repr(C)]
#[derive(Default)]
struct SystemInfo {
    architecture: u32,
    page_size: u32,
    minimum: *mut c_void,
    maximum: *mut c_void,
    processor_mask: usize,
    processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

const _: () = assert!(std::mem::size_of::<SystemInfo>() == 24 + 3 * size_of::<usize>());

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemInfo(info: *mut SystemInfo);
    fn GetCurrentProcess() -> Handle;
    fn CreateFileMappingW(
        file: Handle,
        attributes: *const c_void,
        protection: u32,
        max_high: u32,
        max_low: u32,
        name: *const u16,
    ) -> Handle;
    fn MapViewOfFile(
        mapping: Handle,
        access: u32,
        offset_high: u32,
        offset_low: u32,
        bytes: usize,
    ) -> *mut c_void;
    fn UnmapViewOfFile(base: *const c_void) -> i32;
    fn ReadProcessMemory(
        process: Handle,
        source: *const c_void,
        destination: *mut c_void,
        bytes: usize,
        copied: *mut usize,
    ) -> i32;
    fn WriteProcessMemory(
        process: Handle,
        destination: *mut c_void,
        source: *const c_void,
        bytes: usize,
        copied: *mut usize,
    ) -> i32;
    fn FlushViewOfFile(base: *const c_void, bytes: usize) -> i32;
}

fn granularity() -> io::Result<u64> {
    static GRANULARITY: OnceLock<u32> = OnceLock::new();
    let granularity = *GRANULARITY.get_or_init(|| {
        let mut info = SystemInfo::default();
        // SAFETY: exclusively borrowed, initialized SYSTEM_INFO with the
        // native pointer-width layout. The API retains no pointer.
        unsafe { GetSystemInfo(&raw mut info) };
        info.allocation_granularity
    });
    if granularity == 0 || !granularity.is_power_of_two() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(u64::from(granularity))
}

struct View {
    base: NonNull<c_void>,
    offset: usize,
    _section: OwnedHandle,
}

impl View {
    fn new(file: &File, offset: u64, count: usize, write: bool) -> io::Result<Self> {
        debug_assert!(count != 0 && count <= CHUNK);
        let granularity = granularity()?;
        let start = offset & !(granularity - 1);
        let prefix = usize::try_from(offset - start).map_err(|_| io::ErrorKind::InvalidInput)?;
        let bytes = prefix
            .checked_add(count)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let protection = if write { PAGE_READWRITE } else { PAGE_READONLY };
        // SAFETY: file is borrowed for the call; zero maximum size selects
        // its current size. Null attributes/name create an unnamed,
        // non-inherited section. The returned handle has unique ownership.
        let section = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                protection,
                0,
                0,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful CreateFileMappingW returned a new owned handle.
        let section = unsafe { OwnedHandle::from_raw_handle(section) };
        let access = if write { FILE_MAP_WRITE } else { FILE_MAP_READ };
        // SAFETY: the section is live; the offset has native allocation
        // alignment, bytes is positive and checked, and no fixed address
        // can replace unrelated memory. Invalid/truncated ranges fail here.
        let base = unsafe {
            MapViewOfFile(
                section.as_raw_handle(),
                access,
                (start >> 32) as u32,
                start as u32,
                bytes,
            )
        };
        let base = NonNull::new(base).ok_or_else(io::Error::last_os_error)?;
        Ok(Self {
            base,
            offset: prefix,
            _section: section,
        })
    }

    fn data(&self) -> *mut c_void {
        // SAFETY: offset is the prefix inside this live mapped view.
        unsafe { self.base.as_ptr().byte_add(self.offset) }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the original MapViewOfFile
        // base, and all synchronous copy/flush calls have returned. The
        // section handle remains live until after this destructor.
        unsafe { UnmapViewOfFile(self.base.as_ptr()) };
    }
}

fn checked_range(offset: u64, count: usize) -> io::Result<()> {
    if offset > i64::MAX as u64 || offset.checked_add(count as u64).is_none() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

pub(super) fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    checked_range(offset, buf.len())?;
    let mut done = 0;
    while done < buf.len() {
        let at = offset + done as u64;
        let available = file.metadata()?.len().saturating_sub(at);
        let count = available.min((buf.len() - done).min(CHUNK) as u64) as usize;
        if count == 0 {
            break;
        }
        let view = View::new(file, at, count, false)?;
        let mut copied = 0;
        // SAFETY: only this process is addressed. The source is a live
        // owned view containing count bytes, and the exclusive destination
        // slice contains count initialized bytes. The kernel checks the
        // view's accessibility; no borrowed pointer escapes the call.
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                view.data(),
                buf[done..].as_mut_ptr().cast(),
                count,
                &raw mut copied,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if copied != count {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        done += count;
    }
    Ok(done)
}

pub(super) fn write_all_at(file: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    checked_range(offset, data.len())?;
    if offset + data.len() as u64 > file.metadata()?.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (index, chunk) in data.chunks(CHUNK).enumerate() {
        let at = offset + (index * CHUNK) as u64;
        let view = View::new(file, at, chunk.len(), true)?;
        let mut copied = 0;
        // SAFETY: only this process's owned writable view is addressed.
        // Source and destination contain chunk.len() bytes and remain live
        // for this synchronous kernel copy; no pointers escape or alias a
        // mutable Rust reference to the mapped destination.
        let ok = unsafe {
            WriteProcessMemory(
                GetCurrentProcess(),
                view.data(),
                chunk.as_ptr().cast(),
                chunk.len(),
                &raw mut copied,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if copied != chunk.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        // SAFETY: the byte range remains inside this owned live view.
        if unsafe { FlushViewOfFile(view.data(), chunk.len()) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    file.sync_all()
}
