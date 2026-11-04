//! File-backed native memory without an extra file handle. Section/view
//! references survive file cleanup, but do not preserve a closed open's share
//! reservation. Independent native views retain kernel file-cache coherence.
use super::{HostMemory, Keep, PAGE_SIZE};
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::Arc;

type Handle = *mut c_void;
const GRANULARITY: u64 = 65536;
const CHUNK: usize = 1 << 20;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn MapViewOfFile(section: Handle, access: u32, high: u32, low: u32, bytes: usize) -> Handle;
    fn UnmapViewOfFile(base: Handle) -> i32;
    fn ReadProcessMemory(
        process: Handle,
        from: Handle,
        to: Handle,
        bytes: usize,
        copied: *mut usize,
    ) -> i32;
}

pub(super) struct FileMemory {
    // Retire the section before the final file-lifetime notification.
    section: Arc<OwnedHandle>,
    maximum: u64,
    writable: bool,
    _keep: Option<Keep>,
}

impl fmt::Debug for FileMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSectionMemory")
            .field("maximum", &self.maximum)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

impl FileMemory {
    pub(super) fn new(
        section: Arc<OwnedHandle>,
        maximum: u64,
        writable: bool,
        keep: Option<Keep>,
    ) -> io::Result<Self> {
        if maximum == 0 || maximum.checked_add(PAGE_SIZE - 1).is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if !super::windows_arena::WindowsArena::supported() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        Ok(Self {
            section,
            maximum,
            writable,
            _keep: keep,
        })
    }

    fn rounded(&self) -> u64 {
        self.maximum.div_ceil(PAGE_SIZE) * PAGE_SIZE
    }
}

struct View(Handle);
impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: uniquely owned MapViewOfFile base, after synchronous copying.
        unsafe { UnmapViewOfFile(self.0) };
    }
}

impl HostMemory for FileMemory {
    fn size(&self) -> u64 {
        self.rounded()
    }

    unsafe fn map_at(&self, at: *mut u8, offset: u64, len: u64, writable: bool) -> io::Result<()> {
        if writable && !self.writable {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if offset % GRANULARITY != 0
            || len == 0
            || len % PAGE_SIZE != 0
            || offset
                .checked_add(len)
                .is_none_or(|end| end > self.rounded())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // The kernel rounds this logical count to placeholder pages. Passing
        // a rounded count beyond the section's byte maximum is rejected.
        let bytes = usize::try_from(len.min(self.maximum - offset))
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: the caller supplies a quiescent exact placeholder; this
        // owner supplies a live section and checked range/access.
        unsafe { super::windows_arena::map_section_at(&self.section, at, offset, bytes, writable) }
    }

    /// O(n) copying with at most 1 MiB plus one alignment prefix mapped.
    /// Kernel-mediated reads turn an in-page error into an io::Error.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        offset
            .checked_add(buf.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let count = self.rounded().saturating_sub(offset).min(buf.len() as u64) as usize;
        let mut done = 0;
        while done < count {
            let at = offset + done as u64;
            let start = at & !(GRANULARITY - 1);
            let prefix = (at - start) as usize;
            let chunk = (count - done).min(CHUNK);
            let bytes = (prefix as u64 + chunk as u64).min(self.maximum - start) as usize;
            // SAFETY: exclusively owned readable section, aligned offset and
            // positive bounded size; no requested address or guest pointer.
            let address = unsafe {
                MapViewOfFile(
                    self.section.as_raw_handle(),
                    4,
                    (start >> 32) as u32,
                    start as u32,
                    bytes,
                )
            };
            if address.is_null() {
                return Err(io::Error::last_os_error());
            }
            let view = View(address);
            let mut copied = 0;
            // SAFETY: only this process's owned view is read. Its page-rounded
            // extent contains the checked chunk, including the native zero
            // tail. The exclusive output slice contains chunk initialized bytes.
            let ok = unsafe {
                ReadProcessMemory(
                    (-1isize) as Handle,
                    view.0.byte_add(prefix),
                    buf[done..].as_mut_ptr().cast(),
                    chunk,
                    &mut copied,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if copied != chunk {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += chunk;
        }
        Ok(done)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::windows::io::FromRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use vm_memory::{Bytes, GuestAddress};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileMappingW(
            file: Handle,
            security: Handle,
            protection: u32,
            high: u32,
            low: u32,
            name: *const u16,
        ) -> Handle;
    }

    fn section(file: &std::fs::File) -> Arc<OwnedHandle> {
        // SAFETY: borrowed task-owned file; unnamed read-only section with
        // native file size, no inheritance, and exclusively owned output.
        let handle = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null_mut(),
                2,
                0,
                0,
                std::ptr::null(),
            )
        };
        assert!(!handle.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: successful creation transfers one unique section handle.
        Arc::new(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    #[test]
    fn file_section_memory_reads_partial_pages_without_moving_the_file_cursor() {
        let mut file = super::super::anonymous_file().unwrap();
        file.set_len(4097).unwrap();
        file.write_all(&[0x11]).unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.write_all(&[0x66]).unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let memory = FileMemory::new(section(&file), 4097, false, None).unwrap();
        let mut bytes = [0xA5; 8192];
        assert_eq!(memory.read_at(0, &mut bytes).unwrap(), 8192);
        assert_eq!(bytes[0], 0x11);
        assert_eq!(bytes[4096], 0x66);
        assert!(bytes[4097..].iter().all(|byte| *byte == 0));
        assert_eq!(memory.read_at(8192, &mut bytes[..1]).unwrap(), 0);
        assert!(memory.read_at(u64::MAX, &mut bytes[..1]).is_err());
        assert_eq!(memory.read_at(u64::MAX, &mut []).unwrap(), 0);
        assert_eq!(file.stream_position().unwrap(), 7);
    }

    struct Retired(Arc<AtomicBool>);
    impl Drop for Retired {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn file_section_memory_owner_survives_arena_drop_until_last_memory_clone() {
        let mut file = super::super::anonymous_file().unwrap();
        file.set_len(1).unwrap();
        file.write_all(&[0x59]).unwrap();
        let retired = Arc::new(AtomicBool::new(false));
        let memory: Arc<dyn HostMemory> = Arc::new(
            FileMemory::new(
                section(&file),
                1,
                false,
                Some(Arc::new(Retired(retired.clone()))),
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&memory);
        drop(file);
        let arena = super::super::FrameArena::new(2 * super::super::EXTENT, &[]).unwrap();
        let pa = arena.alloc_extent().unwrap();
        arena
            .attach_memory_keeping(pa, &memory, 0, 4096, false)
            .unwrap();
        let clone = arena.memory().clone();
        drop(memory);
        drop(arena);
        assert!(weak.upgrade().is_some());
        assert!(!retired.load(Ordering::Acquire));
        let mut byte = [0];
        clone.read_slice(&mut byte, GuestAddress(pa)).unwrap();
        assert_eq!(byte, [0x59]);
        drop(clone);
        assert!(weak.upgrade().is_none());
        assert!(retired.load(Ordering::Acquire));
    }
}
