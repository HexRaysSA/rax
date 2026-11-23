//! Compare native app reads of an ordinary view and an exact placeholder view.
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

type Handle = *mut c_void;
const PAGE: usize = 4096;
const EXTENT: usize = 256 << 10;
const READ_ONLY: u32 = 2;
const RELEASE: u32 = 0x8000;
const RESERVE: u32 = 0x2000;
const RESERVE_PLACEHOLDER: u32 = 0x40000;
const REPLACE_PLACEHOLDER: u32 = 0x4000;
const PRESERVE_PLACEHOLDER: u32 = 2;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn VirtualFree(address: Handle, size: usize, kind: u32) -> i32;
    fn CreateFileMappingW(
        file: Handle,
        attributes: Handle,
        protection: u32,
        high: u32,
        low: u32,
        name: *const u16,
    ) -> Handle;
    fn MapViewOfFile(section: Handle, access: u32, high: u32, low: u32, size: usize) -> Handle;
    fn UnmapViewOfFile(address: Handle) -> i32;
}

#[link(name = "kernelbase")]
unsafe extern "system" {
    fn VirtualAlloc2(
        process: Handle,
        address: Handle,
        size: usize,
        kind: u32,
        protection: u32,
        parameters: Handle,
        count: u32,
    ) -> Handle;
    fn MapViewOfFile3(
        section: Handle,
        process: Handle,
        address: Handle,
        offset: u64,
        size: usize,
        kind: u32,
        protection: u32,
        parameters: Handle,
        count: u32,
    ) -> Handle;
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn create(path: &Path, size: usize, unlink_before_write: bool, sync: bool) -> io::Result<File> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)?;
    if unlink_before_write {
        std::fs::remove_file(path)?;
    }
    file.set_len(size as u64)?;
    file.write_all(&[0x59])?;
    if size > 1 {
        file.seek(SeekFrom::Start((size - 1) as u64))?;
        file.write_all(&[0x6a])?;
    }
    if sync {
        file.sync_all()?;
    }
    Ok(file)
}

fn section(file: &File) -> io::Result<OwnedHandle> {
    // SAFETY: the live fixture supplies its own size to an unnamed read-only section.
    let handle =
        unsafe { CreateFileMappingW(file.as_raw_handle(), null_mut(), READ_ONLY, 0, 0, null()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful creation transfers the section handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn observe(view: Handle, size: usize) -> String {
    if view.is_null() {
        return format!(
            "winerror={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
    }
    // SAFETY: a successful mapping contains these initialized file offsets.
    let first = unsafe { view.cast::<u8>().read_volatile() };
    let last = unsafe { view.cast::<u8>().add(size - 1).read_volatile() };
    // SAFETY: this is the base of the owned view returned by Windows.
    assert_ne!(unsafe { UnmapViewOfFile(view) }, 0);
    format!("bytes={first:02x},{last:02x}")
}

fn ordinary(section: &OwnedHandle, size: usize) -> String {
    // SAFETY: the live section covers the full logical count.
    observe(
        unsafe { MapViewOfFile(section.as_raw_handle(), 4, 0, 0, size) },
        size,
    )
}

fn fixed(section: &OwnedHandle, size: usize, view_size: usize) -> String {
    let pages = size.div_ceil(PAGE) * PAGE;
    // SAFETY: reserve an owned range in the current process.
    let (process, base) = unsafe {
        let process = GetCurrentProcess();
        let base = VirtualAlloc2(
            process,
            null_mut(),
            EXTENT,
            RESERVE | RESERVE_PLACEHOLDER,
            1,
            null_mut(),
            0,
        );
        (process, base)
    };
    assert!(!base.is_null(), "reserve: {}", io::Error::last_os_error());
    // SAFETY: split the page-rounded prefix of the owned placeholder reservation.
    assert_ne!(
        unsafe { VirtualFree(base, pages, RELEASE | PRESERVE_PLACEHOLDER) },
        0
    );
    // SAFETY: the section is readable, and the request can replace only the owned prefix.
    let view = unsafe {
        MapViewOfFile3(
            section.as_raw_handle(),
            process,
            base,
            0,
            view_size,
            REPLACE_PLACEHOLDER,
            READ_ONLY,
            null_mut(),
            0,
        )
    };
    let result = observe(view, size);
    if view.is_null() {
        // SAFETY: the failed replacement left the owned prefix reserved.
        assert_ne!(unsafe { VirtualFree(base, 0, RELEASE) }, 0);
    } else {
        assert_eq!(view, base);
    }
    // SAFETY: splitting created an independently owned suffix placeholder.
    assert_ne!(unsafe { VirtualFree(base.byte_add(pages), 0, RELEASE) }, 0);
    result
}

fn main() -> io::Result<()> {
    for size in [1usize, 4097, 65537] {
        for (unlink, sync) in [(false, false), (true, false), (true, true)] {
            let pages = size.div_ceil(PAGE) * PAGE;
            for (mode, count) in [
                ("ordinary", size),
                ("logical", size),
                ("aligned", pages),
                ("entire", 0),
            ] {
                let fixture = Fixture(std::env::temp_dir().join(format!(
                    "rax-section-{}-{size}-{unlink}-{sync}-{mode}",
                    std::process::id()
                )));
                let file = create(&fixture.0, size, unlink, sync)?;
                let mapping = section(&file)?;
                drop(file);
                let outcome = if mode == "ordinary" {
                    ordinary(&mapping, size)
                } else {
                    fixed(&mapping, size, count)
                };
                println!("section size={size} unlink={unlink} sync={sync} mode={mode} {outcome}");
            }
        }
    }
    Ok(())
}
