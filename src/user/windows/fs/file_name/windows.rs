use std::ffi::{OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

const FILE_NAME_OPENED: u32 = 8;
const VOLUME_NAME_NT: u32 = 2;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFinalPathNameByHandleW(
        file: *mut c_void,
        output: *mut u16,
        capacity: u32,
        flags: u32,
    ) -> u32;
}

pub(super) fn open_root(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(path)
}

pub(super) fn current(file: &File) -> io::Result<PathBuf> {
    file_path(file, FILE_NAME_OPENED)
}

/// Resolve the path of the held file, including any reparse point traversed
/// during open. Use DOS volume names for both the root and the file.
pub(super) fn resolved(file: &File) -> io::Result<PathBuf> {
    file_path(file, 0)
}

pub(super) fn current_nt(file: &File) -> io::Result<PathBuf> {
    file_path(file, FILE_NAME_OPENED | VOLUME_NAME_NT)
}

pub(super) fn local_device(path: &Path) -> io::Result<Vec<u16>> {
    let device_start = "\\Device\\HarddiskVolume";
    let name: Vec<_> = path
        .as_os_str()
        .encode_wide()
        .enumerate()
        .take_while(|&(index, unit)| index < device_start.len() || unit != u16::from(b'\\'))
        .map(|(_, unit)| unit)
        .collect();
    let prefix = device_start.encode_utf16();
    if name.len() <= device_start.len()
        || !name
            .iter()
            .copied()
            .zip(prefix)
            .all(|(left, right)| left == right)
        || !name[device_start.len()..]
            .iter()
            .all(|unit| (48..=57).contains(unit))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "retained root is outside the local disk name profile",
        ));
    }
    Ok(name)
}

fn file_path(file: &File, flags: u32) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the borrowed handle and initialized UTF-16 allocation remain
        // live for this synchronous system call.
        let count = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                flags,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if (count as usize) < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(
                &buffer[..count as usize],
            )));
        }
        // NT counted names are bounded by a 16-bit byte length. This also
        // leaves room for the Win32 volume prefix and terminating character.
        let capacity = (count as usize)
            .checked_add(1)
            .filter(|n| *n <= 65536)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "native file name length"))?;
        buffer.resize(capacity, 0);
    }
}
