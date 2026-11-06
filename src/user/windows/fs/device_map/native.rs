//! Snapshot the selected Windows subject's real drive types and logon scope.
use super::super::DriveMap;
use std::ffi::c_void;
use std::io;

mod logon_directory;

#[repr(C)]
struct Record {
    mask: u32,
    types: [u8; 32],
    trailer: [u32; 3],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: isize,
        class: u32,
        output: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

fn capture(logon_only: bool) -> io::Result<[u8; 36]> {
    let length = if logon_only { 48 } else { 36 };
    let mut record = Record {
        mask: 0,
        types: [0; 32],
        trailer: [0; 3],
    };
    if logon_only {
        record.trailer[1] = 1;
    }
    let mut returned = 0;
    let output = (&mut record as *mut Record).cast();
    // SAFETY: repr(C) record is four-byte aligned and owns 48 writable bytes;
    // length is 36 or 48, ReturnLength owns four bytes, and -1 selects only
    // the current process. The call is synchronous and retains no pointers.
    let status = unsafe { NtQueryInformationProcess(-1, 23, output, length, &mut returned) };
    if status < 0 || returned != length {
        return Err(io::Error::other(format!(
            "native ProcessDeviceMap: status {:#010x}, returned {returned}, expected {length}",
            status as u32
        )));
    }
    let mut bytes = [0; 36];
    bytes[..4].copy_from_slice(&record.mask.to_le_bytes());
    bytes[4..].copy_from_slice(&record.types);
    Ok(bytes)
}

impl DriveMap {
    /// Snapshot native drive roots, types and logon visibility before execution.
    /// Guest queries subsequently use this owned map without host forwarding.
    pub fn from_host() -> io::Result<Self> {
        let all = capture(false)?;
        #[cfg(target_pointer_width = "64")]
        let logon = capture(true)?;
        #[cfg(target_pointer_width = "32")]
        let logon = logon_directory::capture(&all)?;
        let mask = u32::from_le_bytes(all[..4].try_into().unwrap());
        let mut drives = Self::empty();
        for index in 0..26 {
            if mask & (1 << index) != 0 {
                let letter = char::from(b'A' + index);
                drives.set(letter, format!("{letter}:\\"));
            }
        }
        drives
            .apply_device_maps(all, logon)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(drives)
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod tests {
    #[test]
    fn native_logon_directory_matches_the_independent_extended_process_query() {
        let all = super::capture(false).unwrap();
        assert_eq!(
            super::logon_directory::capture(&all).unwrap(),
            super::capture(true).unwrap()
        );
    }
}
