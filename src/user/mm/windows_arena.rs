//! Windows placeholder-backed frame storage. All mapping changes are serialized
//! by the address-space owner; CPU execution and borrowed memory slices must be
//! quiescent until a change returns. See the archived Microsoft memoryapi
//! references in docs/specifications/windows/services/shared-memory/.
//!
//! Each extent can contain a shared file view and a private tail. A failed
//! replacement restores the previous views; failed restoration quarantines the
//! arena without releasing its addresses. Cached CPU pointers must be gated on
//! `available()` before execution resumes.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use vm_memory::mmap::ExternalMappingAccess;

use super::arena::EXTENT;

type Handle = *mut c_void;
type Alloc = unsafe extern "system" fn(
    Handle,
    *mut c_void,
    usize,
    u32,
    u32,
    *mut c_void,
    u32,
) -> *mut c_void;
type Map = unsafe extern "system" fn(
    Handle,
    Handle,
    *mut c_void,
    u64,
    usize,
    u32,
    u32,
    *mut c_void,
    u32,
) -> *mut c_void;
type Unmap = unsafe extern "system" fn(Handle, *mut c_void, u32) -> i32;
const RESERVE: u32 = 0x2000;
const COMMIT: u32 = 0x1000;
const REPLACE: u32 = 0x4000;
const PLACEHOLDER: u32 = 0x40000;
const RELEASE: u32 = 0x8000;
const PRESERVE: u32 = 2;
const COALESCE: u32 = 1;
const NOACCESS: u32 = 1;
const READWRITE: u32 = 4;
const WRITECOPY: u32 = 8;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> Handle;
    fn VirtualFree(base: *mut c_void, size: usize, kind: u32) -> i32;
    fn CreateFileMappingW(
        file: Handle,
        attributes: *const c_void,
        protection: u32,
        max_high: u32,
        max_low: u32,
        name: *const u16,
    ) -> Handle;
    fn FlushViewOfFile(base: *const c_void, bytes: usize) -> i32;
}

#[derive(Clone, Copy, Debug)]
struct Api {
    alloc: Alloc,
    map: Map,
    unmap: Unmap,
}

impl Api {
    fn get() -> Option<Self> {
        static API: OnceLock<Option<Api>> = OnceLock::new();
        *API.get_or_init(|| {
            let name: Vec<u16> = "kernelbase.dll\0".encode_utf16().collect();
            // SAFETY: NUL-terminated system module name. KernelBase is an
            // already-loaded process-lifetime module; no unload is performed.
            let module = unsafe { GetModuleHandleW(name.as_ptr()) };
            if module.is_null() {
                return None;
            }
            // SAFETY: exact exported names and documented system ABI below.
            let (alloc, map, unmap) = unsafe {
                (
                    GetProcAddress(module, c"VirtualAlloc2".as_ptr().cast()),
                    GetProcAddress(module, c"MapViewOfFile3".as_ptr().cast()),
                    GetProcAddress(module, c"UnmapViewOfFile2".as_ptr().cast()),
                )
            };
            if alloc.is_null() || map.is_null() || unmap.is_null() {
                return None;
            }
            // SAFETY: the three non-null exports have these memoryapi.h
            // signatures. Extended parameters are always null with count 0.
            Some(unsafe {
                Self {
                    alloc: std::mem::transmute::<*mut c_void, Alloc>(alloc),
                    map: std::mem::transmute::<*mut c_void, Map>(map),
                    unmap: std::mem::transmute::<*mut c_void, Unmap>(unmap),
                }
            })
        })
    }
}

#[derive(Debug)]
struct Section {
    handle: OwnedHandle,
    file: File,
}

#[derive(Clone, Debug)]
enum Kind {
    Placeholder,
    Private,
    PrivateView(Arc<OwnedHandle>),
    View {
        section: Arc<Section>,
        offset: u64,
        view_size: usize,
        writable: bool,
    },
}

#[derive(Clone, Debug)]
struct Part {
    len: usize,
    kind: Kind,
}

/// Owns the complete reservation, including every inaccessible placeholder.
/// The pointer is stored as an address; only serialized operations below touch
/// it. The owner may outlive FrameArena through GuestMemoryMmap clones.
#[derive(Debug)]
pub(super) struct WindowsArena {
    base: usize,
    size: usize,
    api: Api,
    valid: AtomicBool,
    parts: Mutex<BTreeMap<usize, Part>>,
    #[cfg(test)]
    fail_installs: std::sync::atomic::AtomicUsize,
}

impl ExternalMappingAccess for WindowsArena {
    fn is_accessible(&self, offset: usize, count: usize) -> bool {
        self.available()
            && offset
                .checked_add(count)
                .is_some_and(|end| end <= self.size)
    }
}

impl WindowsArena {
    pub(super) fn supported() -> bool {
        Api::get().is_some()
    }

    /// None means the OS lacks placeholder APIs. Other failures are real
    /// allocation failures, not evidence that the capability is absent.
    pub(super) fn new(size: usize) -> io::Result<Option<Arc<Self>>> {
        let Some(api) = Api::get() else {
            return Ok(None);
        };
        if size == 0 || size > isize::MAX as usize || size % 4096 != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: no requested address, a positive page-aligned size, and
        // exactly the documented placeholder reservation flags.
        let base = unsafe {
            (api.alloc)(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                size,
                RESERVE | PLACEHOLDER,
                NOACCESS,
                std::ptr::null_mut(),
                0,
            )
        };
        if base.is_null() {
            return Err(io::Error::last_os_error());
        }
        let arena = Arc::new(Self {
            base: base as usize,
            size,
            api,
            valid: AtomicBool::new(true),
            #[cfg(test)]
            fail_installs: std::sync::atomic::AtomicUsize::new(0),
            parts: Mutex::new(BTreeMap::from([(
                0,
                Part {
                    len: size,
                    kind: Kind::Placeholder,
                },
            )])),
        });
        {
            let mut parts = arena.parts.lock().unwrap();
            for start in (0..size).step_by(EXTENT as usize) {
                let len = (size - start).min(EXTENT as usize);
                arena.split(&mut parts, start, len)?;
                arena.install(&mut parts, start, Kind::Private)?;
            }
        }
        Ok(Some(arena))
    }

    pub(super) fn as_ptr(&self) -> *mut u8 {
        self.base as *mut u8
    }
    pub(super) fn available(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }
    fn at(&self, offset: usize) -> *mut c_void {
        (self.base + offset) as *mut c_void
    }

    fn os_error(&self, operation: &str, offset: usize, len: usize) -> io::Error {
        let error = io::Error::last_os_error();
        io::Error::new(
            error.kind(),
            format!("{operation} at arena offset {offset:#x}, size {len:#x}: {error}"),
        )
    }

    /// Splits one placeholder, preserving both resulting reservations.
    fn split(&self, parts: &mut BTreeMap<usize, Part>, start: usize, len: usize) -> io::Result<()> {
        let part = parts.get(&start).ok_or(io::ErrorKind::InvalidInput)?;
        if !matches!(part.kind, Kind::Placeholder) || len == 0 || len > part.len {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if len == part.len {
            return Ok(());
        }
        let tail = part.len - len;
        // SAFETY: [start,start+len) is a strict prefix of this owned placeholder.
        if unsafe { VirtualFree(self.at(start), len, RELEASE | PRESERVE) } == 0 {
            return Err(self.os_error("split placeholder", start, len));
        }
        parts.get_mut(&start).unwrap().len = len;
        parts.insert(
            start + len,
            Part {
                len: tail,
                kind: Kind::Placeholder,
            },
        );
        Ok(())
    }

    fn install(
        &self,
        parts: &mut BTreeMap<usize, Part>,
        start: usize,
        mut kind: Kind,
    ) -> io::Result<()> {
        let part = parts.get(&start).ok_or(io::ErrorKind::InvalidInput)?;
        if !matches!(part.kind, Kind::Placeholder) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(test)]
        if self
            .fail_installs
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(io::Error::other("injected mapping failure"));
        }
        // VirtualAlloc2 private allocations require allocation-granularity
        // alignment even when replacing a placeholder. A file view prefix can
        // leave a tail at a 4 KiB offset. MapViewOfFile3 explicitly permits
        // page-aligned placeholder replacement, so use a private pagefile
        // section for tails instead of a misaligned VirtualAlloc2 allocation.
        if matches!(kind, Kind::Private) && start % EXTENT as usize != 0 {
            // SAFETY: INVALID_HANDLE_VALUE selects the pagefile; the positive
            // size is bounded by one extent. No name or inheritance is used.
            let handle = unsafe {
                CreateFileMappingW(
                    (-1isize) as Handle,
                    std::ptr::null(),
                    READWRITE,
                    0,
                    part.len as u32,
                    std::ptr::null(),
                )
            };
            if handle.is_null() {
                return Err(self.os_error("create private tail", start, part.len));
            }
            // SAFETY: the new section handle has unique ownership.
            kind = Kind::PrivateView(Arc::new(unsafe { OwnedHandle::from_raw_handle(handle) }));
        }
        // SAFETY: exact base/size of an owned placeholder; all pointers into
        // the extent are quiescent. Sections remain owned across replacement.
        let result = unsafe {
            match &kind {
                Kind::Placeholder => return Ok(()),
                Kind::Private => (self.api.alloc)(
                    GetCurrentProcess(),
                    self.at(start),
                    part.len,
                    RESERVE | COMMIT | REPLACE,
                    READWRITE,
                    std::ptr::null_mut(),
                    0,
                ),
                Kind::PrivateView(section) => (self.api.map)(
                    section.as_raw_handle(),
                    GetCurrentProcess(),
                    self.at(start),
                    0,
                    part.len,
                    REPLACE,
                    READWRITE,
                    std::ptr::null_mut(),
                    0,
                ),
                Kind::View {
                    section,
                    offset,
                    view_size,
                    writable,
                } => (self.api.map)(
                    section.handle.as_raw_handle(),
                    GetCurrentProcess(),
                    self.at(start),
                    *offset,
                    *view_size,
                    REPLACE,
                    if *writable { READWRITE } else { WRITECOPY },
                    std::ptr::null_mut(),
                    0,
                ),
            }
        };
        if result.is_null() {
            return Err(self.os_error("replace placeholder", start, part.len));
        }
        parts.get_mut(&start).unwrap().kind = kind;
        Ok(())
    }

    fn clear(&self, parts: &mut BTreeMap<usize, Part>, start: usize) -> io::Result<()> {
        let part = parts.get_mut(&start).ok_or(io::ErrorKind::InvalidInput)?;
        // SAFETY: the original base of exactly one owned allocation/view.
        // PRESERVE keeps its address reserved even while no memory is mapped.
        let ok = unsafe {
            match part.kind {
                Kind::Placeholder => return Ok(()),
                // PRESERVE operates on the exact replacement range. The zero
                // size convention belongs to an ordinary MEM_RELEASE; using
                // zero here is rejected by native Windows with ERROR_INVALID_PARAMETER.
                Kind::Private => VirtualFree(self.at(start), part.len, RELEASE | PRESERVE),
                Kind::View { .. } | Kind::PrivateView(_) => {
                    (self.api.unmap)(GetCurrentProcess(), self.at(start), PRESERVE)
                }
            }
        };
        if ok == 0 {
            return Err(self.os_error("preserve allocation", start, part.len));
        }
        part.kind = Kind::Placeholder;
        Ok(())
    }

    fn replace(
        &self,
        parts: &mut BTreeMap<usize, Part>,
        start: usize,
        plan: &[Part],
    ) -> io::Result<()> {
        let end = start + EXTENT as usize;
        let keys: Vec<usize> = parts.range(start..end).map(|(&at, _)| at).collect();
        for &at in &keys {
            self.clear(parts, at)?;
        }
        if keys.len() > 1 {
            // SAFETY: all adjacent placeholders cover exactly this extent;
            // these are the original bases, never subranges of private memory.
            if unsafe { VirtualFree(self.at(start), EXTENT as usize, RELEASE | COALESCE) } == 0 {
                return Err(self.os_error("coalesce placeholders", start, EXTENT as usize));
            }
            for &at in &keys[1..] {
                parts.remove(&at);
            }
            parts.get_mut(&start).unwrap().len = EXTENT as usize;
        }
        let mut at = start;
        for part in plan {
            self.split(parts, at, part.len)?;
            self.install(parts, at, part.kind.clone())?;
            at += part.len;
        }
        Ok(())
    }

    fn change(&self, start: usize, plan: &[Part]) -> io::Result<()> {
        if !self.available() {
            return Err(io::Error::other("Windows arena is inaccessible"));
        }
        if start % EXTENT as usize != 0
            || start
                .checked_add(EXTENT as usize)
                .is_none_or(|end| end > self.size)
            || plan.iter().map(|p| p.len).sum::<usize>() != EXTENT as usize
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut parts = self.parts.lock().unwrap();
        let old: Vec<Part> = parts
            .range(start..start + EXTENT as usize)
            .map(|(_, p)| p.clone())
            .collect();
        if let Err(error) = self.replace(&mut parts, start, plan) {
            if self.replace(&mut parts, start, &old).is_err() {
                self.valid.store(false, Ordering::Release);
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn attach(
        &self,
        start: usize,
        file: &File,
        offset: u64,
        len: usize,
        writable: bool,
    ) -> io::Result<()> {
        if len == 0 || len > EXTENT as usize || len % 4096 != 0 || offset % EXTENT != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let remaining = file.metadata()?.len().saturating_sub(offset);
        // Retain the logical count for a partial last page. Native Windows
        // MapViewOfFile3 rounds this count to the placeholder pages. Zero
        // returns error 87; a page-rounded count past EOF returns error 5.
        // See the independent windows_section_probe.py and archived evidence.
        let view_size = if remaining < len as u64
            && remaining.div_ceil(4096).saturating_mul(4096) == len as u64
        {
            remaining as usize
        } else {
            len
        };
        let retained_file = file.try_clone()?;
        // SAFETY: borrowed file, unnamed non-inheritable section sized from
        // the file. Create it before replacing any existing arena memory.
        // WRITECOPY permits safe physical-memory writes without granting write
        // access to the underlying read-only file; guest writes are VMA-gated.
        let handle = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                if writable { READWRITE } else { WRITECOPY },
                0,
                0,
                std::ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful call transfers a unique handle to this owner.
        let section = Arc::new(Section {
            handle: unsafe { OwnedHandle::from_raw_handle(handle) },
            file: retained_file,
        });
        let mut plan = vec![Part {
            len,
            kind: Kind::View {
                section,
                offset,
                view_size,
                writable,
            },
        }];
        if len < EXTENT as usize {
            plan.push(Part {
                len: EXTENT as usize - len,
                kind: Kind::Private,
            });
        }
        self.change(start, &plan)
    }

    pub(super) fn detach(&self, start: usize) -> io::Result<()> {
        self.change(
            start,
            &[Part {
                len: EXTENT as usize,
                kind: Kind::Private,
            }],
        )
    }

    pub(super) fn sync(&self, start: usize) -> io::Result<()> {
        if !self.available() {
            return Err(io::Error::other("Windows arena is inaccessible"));
        }
        let parts = self.parts.lock().unwrap();
        for (&at, part) in parts.range(start..start.saturating_add(EXTENT as usize)) {
            if let Kind::View {
                section,
                writable: true,
                ..
            } = &part.kind
            {
                // SAFETY: this entire view is owned and cannot be replaced
                // while the parts mutex is held.
                if unsafe { FlushViewOfFile(self.at(at), part.len) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                section.file.sync_all()?;
            }
        }
        Ok(())
    }
}

impl Drop for WindowsArena {
    fn drop(&mut self) {
        let parts = self.parts.get_mut().unwrap_or_else(|e| e.into_inner());
        for (&at, part) in parts.iter() {
            let address = (self.base + at) as *mut c_void;
            // SAFETY: last owner; all guest memory clones and CPU references
            // have gone. Each original allocation/view base is released once.
            unsafe {
                match part.kind {
                    Kind::View { .. } | Kind::PrivateView(_) => {
                        (self.api.unmap)(GetCurrentProcess(), address, 0);
                    }
                    Kind::Private | Kind::Placeholder => {
                        VirtualFree(address, 0, RELEASE);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{AddressSpace, Backing, Mapping, Perms, SharedObject, SpaceConfig};
    use super::*;
    use vm_memory::{Bytes, GuestAddress, GuestMemory};

    #[test]
    fn private_replacement_returns_to_exact_placeholder_and_recommits() {
        let arena = WindowsArena::new(2 * EXTENT as usize)
            .unwrap()
            .expect("placeholder APIs");
        let mut parts = arena.parts.lock().unwrap();
        for _ in 0..3 {
            arena.clear(&mut parts, EXTENT as usize).unwrap();
            assert!(matches!(parts[&(EXTENT as usize)].kind, Kind::Placeholder));
            assert_eq!(parts[&(EXTENT as usize)].len, EXTENT as usize);
            assert!(matches!(parts[&0].kind, Kind::Private));
            arena
                .install(&mut parts, EXTENT as usize, Kind::Private)
                .unwrap();
        }
        assert!(arena.available());
    }

    fn space() -> AddressSpace {
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 2 * EXTENT,
            reserved_phys: vec![],
        })
        .unwrap()
    }

    fn mapping(object: &Arc<SharedObject>, perms: Perms) -> Mapping {
        Mapping {
            perms,
            backing: Backing::Shared {
                object: object.clone(),
                offset: 0,
            },
            shared: true,
            name: None,
            flags: 0,
        }
    }

    #[test]
    fn partial_views_share_bytes_preserve_neighbors_and_detach() {
        let left = space();
        let right = space();
        let object = Arc::new(SharedObject::anonymous(3 * 4096).unwrap());
        let rw = Perms::READ | Perms::WRITE;
        left.map(0x10000, 3 * 4096, mapping(&object, rw)).unwrap();
        right.map(0x10000, 3 * 4096, mapping(&object, rw)).unwrap();
        left.map(0x20000, 4096, Mapping::anonymous(rw)).unwrap();
        left.write(0x20000, &[0x59]).unwrap();
        let mut byte = [0];
        right.read(0x12fff, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        left.write(0x12fff, &[0x83]).unwrap();
        right.read(0x12fff, &mut byte).unwrap();
        assert_eq!(byte, [0x83]);
        object.read_at(0x2fff, &mut byte).unwrap();
        assert_eq!(byte, [0x83]);
        object.write_all_at(0x2fff, &[0x47]).unwrap();
        left.read(0x12fff, &mut byte).unwrap();
        assert_eq!(byte, [0x47]);
        left.sync(0x10000, 3 * 4096).unwrap();
        left.unmap(0x10000, 3 * 4096).unwrap();
        left.read(0x20000, &mut byte).unwrap();
        assert_eq!(byte, [0x59]);
        let fresh = Arc::new(SharedObject::anonymous(4096).unwrap());
        left.map(0x30000, 4096, mapping(&fresh, rw)).unwrap();
        left.read(0x30000, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        right.read(0x12fff, &mut byte).unwrap();
        assert_eq!(byte, [0x47]);
    }

    #[test]
    fn short_file_maps_its_last_partial_page_without_growing_the_file() {
        // Exercise the adapter directly first: AddressSpace intentionally
        // translates allocation errors into guest faults, losing the native
        // operation and GetLastError value needed to diagnose a regression.
        for offset in [0, EXTENT] {
            let arena = super::super::FrameArena::new(2 * EXTENT, &[]).unwrap();
            let pa = arena.alloc_extent().unwrap();
            let file = super::super::anonymous_file().unwrap();
            file.set_len(offset + 4097).unwrap();
            arena.attach(pa, &file, offset, 8192, true).unwrap();
            assert_eq!(file.metadata().unwrap().len(), offset + 4097);
        }

        let space = space();
        let object = Arc::new(SharedObject::anonymous(4097).unwrap());
        let rw = Perms::READ | Perms::WRITE;
        space.map(0x10000, 3 * 4096, mapping(&object, rw)).unwrap();
        space.write(0x11000, &[0x61]).unwrap();
        let mut byte = [0xff];
        space.read(0x11fff, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        assert!(space.read(0x12000, &mut byte).is_err());
        assert_eq!(object.len(), 4097);
        object.read_at(4096, &mut byte).unwrap();
        assert_eq!(byte, [0x61]);
    }

    #[test]
    fn read_only_mapping_upgrades_without_changing_physical_address() {
        let space = space();
        let file = super::super::anonymous_file().unwrap();
        file.set_len(4096).unwrap();
        let read = Arc::new(SharedObject::file(file.try_clone().unwrap(), false).unwrap());
        let write = Arc::new(SharedObject::file(file, true).unwrap());
        space
            .map(0x10000, 4096, mapping(&read, Perms::READ))
            .unwrap();
        let before = space
            .translate(0x10000, crate::error::MemoryAccessKind::Read)
            .unwrap();
        assert!(space.write(0x10000, &[1]).is_err());
        assert!(space.write_raw(0x10000, &[1]).is_err());
        space
            .map(0x20000, 4096, mapping(&write, Perms::READ | Perms::WRITE))
            .unwrap();
        space.write(0x20000, &[0xa7]).unwrap();
        let mut byte = [0];
        space.read(0x10000, &mut byte).unwrap();
        assert_eq!(byte, [0xa7]);
        assert_eq!(
            before,
            space
                .translate(0x20000, crate::error::MemoryAccessKind::Read)
                .unwrap()
        );
    }

    #[test]
    fn failed_replacement_restores_shared_view_and_private_tail() {
        let arena = super::super::FrameArena::new(2 * EXTENT, &[]).unwrap();
        let pa = arena.alloc_extent().unwrap();
        let file = super::super::anonymous_file().unwrap();
        file.set_len(4096).unwrap();
        arena.attach(pa, &file, 0, 4096, true).unwrap();
        arena.write(pa, &[0xab]);
        arena
            .windows_owner()
            .fail_installs
            .store(1, Ordering::Release);
        assert!(arena.attach(pa, &file, 0, 4096, true).is_err());
        assert!(arena.available());
        let mut byte = [0];
        arena.read(pa, &mut byte);
        assert_eq!(byte, [0xab]);
        // The whole tail is restored as private RW memory, including its end.
        arena
            .memory()
            .write_slice(&[0xcd], GuestAddress(pa + EXTENT - 1))
            .unwrap();
        arena
            .memory()
            .read_slice(&mut byte, GuestAddress(pa + EXTENT - 1))
            .unwrap();
        assert_eq!(byte, [0xcd]);
    }

    #[test]
    fn failed_rollback_blocks_checked_access_and_every_cpu_entry() {
        use crate::user::cpu::{
            aarch64::{A64Exit, A64UserCpu},
            arm::{A32Exit, A32UserCpu},
            riscv64::{RvExit, RvUserCpu},
            x86_64::{X86Exit, X86UserCpu},
        };
        let space = space();
        // CPU creation can cache the host RAM pointer before quarantine.
        let mut x86 = X86UserCpu::new(&space);
        let mut a64 = A64UserCpu::new(&space);
        let mut rv = RvUserCpu::new(&space, Default::default());
        let mut a32 = A32UserCpu::new(&space);
        let arena = &space.inner.arena;
        let pa = arena.alloc_extent().unwrap();
        let file = super::super::anonymous_file().unwrap();
        file.set_len(4096).unwrap();
        arena.attach(pa, &file, 0, 4096, true).unwrap();
        arena
            .windows_owner()
            .fail_installs
            .store(2, Ordering::Release);
        assert!(arena.attach(pa, &file, 0, 4096, true).is_err());
        assert!(!space.available());
        assert!(arena.memory().get_host_address(GuestAddress(pa)).is_err());
        assert!(
            arena
                .memory()
                .read_slice(&mut [0], GuestAddress(pa))
                .is_err()
        );
        assert!(arena.memory().write_slice(&[0], GuestAddress(pa)).is_err());
        assert!(space.read(0x10000, &mut [0]).is_err());
        assert!(space.read_raw(0x10000, &mut [0]).is_err());
        assert!(arena.alloc_zeroed().is_err());
        assert!(arena.alloc_extent().is_err());
        assert!(matches!(x86.run(), X86Exit::Internal(_)));
        assert!(matches!(x86.step(), X86Exit::Internal(_)));
        assert!(matches!(a64.run(1), A64Exit::Internal(_)));
        assert!(matches!(rv.run(1), RvExit::Internal(_)));
        assert!(matches!(a32.run(1), A32Exit::Internal(_)));
        assert!(matches!(a32.step_instruction(), Some(A32Exit::Internal(_))));
    }

    #[test]
    fn retained_guest_memory_owns_views_after_arena_drop() {
        let arena = super::super::FrameArena::new(2 * EXTENT, &[]).unwrap();
        let pa = arena.alloc_extent().unwrap();
        let file = super::super::anonymous_file().unwrap();
        file.set_len(4096).unwrap();
        arena.attach(pa, &file, 0, 4096, true).unwrap();
        let memory = arena.memory().clone();
        let owner = Arc::downgrade(arena.windows_owner());
        drop(arena);
        drop(file);
        memory.write_slice(&[0x91], GuestAddress(pa)).unwrap();
        let mut byte = [0];
        memory.read_slice(&mut byte, GuestAddress(pa)).unwrap();
        assert_eq!(byte, [0x91]);
        assert!(owner.upgrade().is_some());
        drop(memory);
        assert!(owner.upgrade().is_none());
    }
}
