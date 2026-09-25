//! Extended attributes on host objects.
//!
//! A Linux host stores them as they are. A macOS host keeps a flat
//! namespace of UTF-8 names of at most 127 bytes and attributes of its own
//! (`com.apple.*`); Linux names are stored under themselves when they fit,
//! and otherwise under `rax.x.` and a 128-bit hash of the name, whose value
//! starts with a header holding the name ([`MAGIC`], its length, the name),
//! so every Linux name up to `XATTR_NAME_MAX` bytes can be stored and
//! listed back. The system calls
//! ([`syscall::xattr`](super::super::syscall::xattr)) decide which names
//! exist for the guest; this module moves bytes.

use std::ffi::CString;
use std::path::Path;

use super::super::abi::errno::{Errno, from_host};
use super::super::abi::errno_table::*;

/// The object an attribute call acts on.
#[derive(Clone, Copy, Debug)]
pub enum Obj<'a> {
    /// A host path, following a final symbolic link or not.
    Path(&'a Path, bool),
    /// An open host descriptor.
    Fd(i32),
}

/// `XATTR_CREATE`.
pub const CREATE: u32 = 1;
/// `XATTR_REPLACE`.
pub const REPLACE: u32 = 2;

/// Header of the value stored under a hashed name.
const MAGIC: &[u8; 4] = b"rxa1";
/// Prefix of hashed names.
const HASHED: &str = "rax.x.";
/// `XATTR_MAXNAMELEN` on macOS.
#[cfg_attr(target_os = "linux", allow(dead_code))]
const HOST_NAME_MAX: usize = 127;

fn last_errno() -> Errno {
    Errno(from_host(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    ))
}

fn cpath(p: &Path) -> Result<CString, Errno> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).map_err(|_| Errno(EINVAL))
}

/// FNV-1a over `name` from `basis`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn fnv(basis: u64, name: &[u8]) -> u64 {
    name.iter().fold(basis, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The host name of Linux attribute `name`, and whether it is hashed.
#[cfg(target_os = "linux")]
fn host_name(name: &[u8]) -> (CString, bool) {
    (CString::new(name).expect("names have no NUL"), false)
}

/// The host name of Linux attribute `name`, and whether it is hashed.
#[cfg(not(target_os = "linux"))]
fn host_name(name: &[u8]) -> (CString, bool) {
    if name.len() <= HOST_NAME_MAX && std::str::from_utf8(name).is_ok() {
        return (CString::new(name).expect("names have no NUL"), false);
    }
    let h = format!(
        "{HASHED}{:016x}{:016x}",
        fnv(0xcbf2_9ce4_8422_2325, name),
        fnv(0x6c62_272e_07bb_0142, name)
    );
    (CString::new(h).expect("hex has no NUL"), true)
}

/// The header stored before the value of a hashed `name`.
fn header(name: &[u8]) -> Vec<u8> {
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(&(name.len() as u16).to_le_bytes());
    h.extend_from_slice(name);
    h
}

/// The name a hashed value's header holds, and where its value starts.
fn parse_header(v: &[u8]) -> Option<(&[u8], usize)> {
    if v.len() < 6 || &v[..4] != MAGIC {
        return None;
    }
    let n = u16::from_le_bytes([v[4], v[5]]) as usize;
    let end = 6 + n;
    (v.len() >= end).then(|| (&v[6..end], end))
}

/// A host `*getxattr` into `buf` (`None`: the size only).
fn raw_get(o: Obj<'_>, name: &CString, buf: Option<&mut [u8]>) -> Result<usize, Errno> {
    let (ptr, len) = match buf {
        Some(b) if !b.is_empty() => (b.as_mut_ptr().cast::<libc::c_void>(), b.len()),
        // A null buffer asks for the size (macOS refuses a non-null one of
        // size 0 with ERANGE).
        _ => (std::ptr::null_mut(), 0),
    };
    // SAFETY: `name` and a path are NUL-terminated and owned for the call;
    // `ptr` is null or writable for `len` bytes.
    let r = unsafe {
        match o {
            #[cfg(target_os = "linux")]
            Obj::Path(p, follow) => {
                let c = cpath(p)?;
                if follow {
                    libc::getxattr(c.as_ptr(), name.as_ptr(), ptr, len)
                } else {
                    libc::lgetxattr(c.as_ptr(), name.as_ptr(), ptr, len)
                }
            }
            #[cfg(target_os = "linux")]
            Obj::Fd(fd) => libc::fgetxattr(fd, name.as_ptr(), ptr, len),
            #[cfg(not(target_os = "linux"))]
            Obj::Path(p, follow) => {
                let c = cpath(p)?;
                let opt = if follow { 0 } else { libc::XATTR_NOFOLLOW };
                libc::getxattr(c.as_ptr(), name.as_ptr(), ptr, len, 0, opt)
            }
            #[cfg(not(target_os = "linux"))]
            Obj::Fd(fd) => libc::fgetxattr(fd, name.as_ptr(), ptr, len, 0, 0),
        }
    };
    if r < 0 {
        return Err(last_errno());
    }
    Ok(r as usize)
}

/// A host `*getxattr` of the whole value.
fn raw_get_all(o: Obj<'_>, name: &CString) -> Result<Vec<u8>, Errno> {
    loop {
        let n = raw_get(o, name, None)?;
        let mut v = vec![0u8; n];
        match raw_get(o, name, Some(&mut v)) {
            Ok(m) => {
                v.truncate(m);
                return Ok(v);
            }
            // It grew between the calls.
            Err(Errno(ERANGE)) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// A host `*setxattr` with Linux `flags`.
fn raw_set(o: Obj<'_>, name: &CString, value: &[u8], flags: u32) -> Result<(), Errno> {
    let ptr = value.as_ptr().cast::<libc::c_void>();
    #[cfg(target_os = "linux")]
    let hf = flags as libc::c_int;
    #[cfg(not(target_os = "linux"))]
    let hf = (if flags & CREATE != 0 {
        libc::XATTR_CREATE
    } else {
        0
    }) | (if flags & REPLACE != 0 {
        libc::XATTR_REPLACE
    } else {
        0
    });
    // SAFETY: `name`, a path, and `value` are owned for the call; `value`
    // is readable for its length.
    let r = unsafe {
        match o {
            #[cfg(target_os = "linux")]
            Obj::Path(p, follow) => {
                let c = cpath(p)?;
                if follow {
                    libc::setxattr(c.as_ptr(), name.as_ptr(), ptr, value.len(), hf)
                } else {
                    libc::lsetxattr(c.as_ptr(), name.as_ptr(), ptr, value.len(), hf)
                }
            }
            #[cfg(target_os = "linux")]
            Obj::Fd(fd) => libc::fsetxattr(fd, name.as_ptr(), ptr, value.len(), hf),
            #[cfg(not(target_os = "linux"))]
            Obj::Path(p, follow) => {
                let c = cpath(p)?;
                let opt = hf | if follow { 0 } else { libc::XATTR_NOFOLLOW };
                libc::setxattr(c.as_ptr(), name.as_ptr(), ptr, value.len(), 0, opt)
            }
            #[cfg(not(target_os = "linux"))]
            Obj::Fd(fd) => libc::fsetxattr(fd, name.as_ptr(), ptr, value.len(), 0, hf),
        }
    };
    if r != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// A host `*removexattr`.
fn raw_remove(o: Obj<'_>, name: &CString) -> Result<(), Errno> {
    // SAFETY: `name` and a path are NUL-terminated and owned for the call.
    let r = unsafe {
        match o {
            #[cfg(target_os = "linux")]
            Obj::Path(p, follow) => {
                let c = cpath(p)?;
                if follow {
                    libc::removexattr(c.as_ptr(), name.as_ptr())
                } else {
                    libc::lremovexattr(c.as_ptr(), name.as_ptr())
                }
            }
            #[cfg(target_os = "linux")]
            Obj::Fd(fd) => libc::fremovexattr(fd, name.as_ptr()),
            #[cfg(not(target_os = "linux"))]
            Obj::Path(p, follow) => {
                let c = cpath(p)?;
                let opt = if follow { 0 } else { libc::XATTR_NOFOLLOW };
                libc::removexattr(c.as_ptr(), name.as_ptr(), opt)
            }
            #[cfg(not(target_os = "linux"))]
            Obj::Fd(fd) => libc::fremovexattr(fd, name.as_ptr(), 0),
        }
    };
    if r != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// The host's attribute names, NUL-separated.
fn raw_list(o: Obj<'_>) -> Result<Vec<u8>, Errno> {
    let call = |buf: &mut [u8]| -> isize {
        let (ptr, len) = if buf.is_empty() {
            (std::ptr::null_mut(), 0)
        } else {
            (buf.as_mut_ptr().cast::<libc::c_char>(), buf.len())
        };
        // SAFETY: `ptr` is null or writable for `len` bytes; a path is
        // NUL-terminated and owned for the call.
        unsafe {
            match o {
                #[cfg(target_os = "linux")]
                Obj::Path(p, follow) => match cpath(p) {
                    Ok(c) if follow => libc::listxattr(c.as_ptr(), ptr, len),
                    Ok(c) => libc::llistxattr(c.as_ptr(), ptr, len),
                    Err(_) => -2,
                },
                #[cfg(target_os = "linux")]
                Obj::Fd(fd) => libc::flistxattr(fd, ptr, len),
                #[cfg(not(target_os = "linux"))]
                Obj::Path(p, follow) => match cpath(p) {
                    Ok(c) => {
                        let opt = if follow { 0 } else { libc::XATTR_NOFOLLOW };
                        libc::listxattr(c.as_ptr(), ptr, len, opt)
                    }
                    Err(_) => -2,
                },
                #[cfg(not(target_os = "linux"))]
                Obj::Fd(fd) => libc::flistxattr(fd, ptr, len, 0),
            }
        }
    };
    loop {
        let n = call(&mut []);
        if n == -2 {
            return Err(Errno(EINVAL));
        }
        if n < 0 {
            return Err(last_errno());
        }
        let mut v = vec![0u8; n as usize];
        let m = call(&mut v);
        if m < 0 {
            let e = last_errno();
            if e.0 == ERANGE {
                continue;
            }
            return Err(e);
        }
        v.truncate(m as usize);
        return Ok(v);
    }
}

/// The value of Linux attribute `name`: its length, copied into `buf`
/// when given (`ERANGE` if it does not fit); `ENODATA` when absent.
pub fn get(o: Obj<'_>, name: &[u8], buf: Option<&mut [u8]>) -> Result<usize, Errno> {
    let (hname, hashed) = host_name(name);
    if !hashed {
        return raw_get(o, &hname, buf);
    }
    let v = raw_get_all(o, &hname)?;
    let Some((stored, at)) = parse_header(&v) else {
        return Err(Errno(ENODATA));
    };
    if stored != name {
        return Err(Errno(ENODATA));
    }
    let value = &v[at..];
    if let Some(b) = buf
        && !b.is_empty()
    {
        if b.len() < value.len() {
            return Err(Errno(ERANGE));
        }
        b[..value.len()].copy_from_slice(value);
    }
    Ok(value.len())
}

/// Sets Linux attribute `name` to `value` with `XATTR_*` `flags`.
pub fn set(o: Obj<'_>, name: &[u8], value: &[u8], flags: u32) -> Result<(), Errno> {
    let (hname, hashed) = host_name(name);
    if !hashed {
        return raw_set(o, &hname, value, flags);
    }
    let mut v = header(name);
    v.extend_from_slice(value);
    raw_set(o, &hname, &v, flags)
}

/// Removes Linux attribute `name`.
pub fn remove(o: Obj<'_>, name: &[u8]) -> Result<(), Errno> {
    let (hname, hashed) = host_name(name);
    if hashed {
        // Only its own record: a hash shared with another name is not it.
        get(o, name, None)?;
    }
    raw_remove(o, &hname)
}

/// The names of the object's attributes, as Linux names (the hashed ones
/// decoded; host names that are not Linux names are left to the caller).
pub fn list(o: Obj<'_>) -> Result<Vec<Vec<u8>>, Errno> {
    let raw = raw_list(o)?;
    let mut out = Vec::new();
    for n in raw.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        if cfg!(not(target_os = "linux")) && n.starts_with(HASHED.as_bytes()) {
            let c = CString::new(n).expect("split at NUL");
            if let Ok(v) = raw_get_all(o, &c)
                && let Some((name, _)) = parse_header(&v)
            {
                out.push(name.to_vec());
            }
            continue;
        }
        out.push(n.to_vec());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rax-xattr-{tag}-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        p
    }

    #[test]
    fn values_round_trip_under_every_name() {
        let p = file("rt");
        let o = Obj::Path(&p, true);
        let long = [b"user.".to_vec(), vec![b'n'; 250]].concat();
        let odd = b"user.\xff\xfe".to_vec();
        for name in [b"user.a".to_vec(), long.clone(), odd.clone()] {
            set(o, &name, b"value", 0).unwrap();
            assert_eq!(get(o, &name, None), Ok(5));
            let mut b = [0u8; 8];
            assert_eq!(get(o, &name, Some(&mut b)), Ok(5));
            assert_eq!(&b[..5], b"value");
            let mut small = [0u8; 2];
            assert_eq!(get(o, &name, Some(&mut small)), Err(Errno(ERANGE)));
            assert_eq!(set(o, &name, b"x", CREATE), Err(Errno(EEXIST)));
        }
        let names = list(o).unwrap();
        for n in [b"user.a".to_vec(), long.clone(), odd.clone()] {
            assert!(names.contains(&n), "{names:?}");
        }
        for name in [b"user.a".to_vec(), long, odd] {
            remove(o, &name).unwrap();
            assert_eq!(get(o, &name, None), Err(Errno(ENODATA)));
            assert_eq!(remove(o, &name), Err(Errno(ENODATA)));
            assert_eq!(set(o, &name, b"x", REPLACE), Err(Errno(ENODATA)));
        }
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn hashed_records_carry_their_names() {
        let h = header(b"user.long");
        assert_eq!(parse_header(&h), Some((&b"user.long"[..], h.len())));
        assert_eq!(parse_header(b"rxa1\x05\x00ab"), None);
        assert_eq!(parse_header(b"nope\x00\x00"), None);
        // The two halves of the hash differ.
        assert_ne!(
            fnv(0xcbf2_9ce4_8422_2325, b"x"),
            fnv(0x6c62_272e_07bb_0142, b"x")
        );
    }
}
