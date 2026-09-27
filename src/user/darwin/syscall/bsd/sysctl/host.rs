//! The host kernel's sysctl nodes, for the operating-system subtrees the
//! guest shares with the host (it runs on the host's user space): a
//! request goes to the host with the guest's buffer size, so the host's
//! own copy-out rules apply. Only a macOS host has them.

use crate::user::darwin::abi::Errno;

/// Whether the host has the nodes (a macOS host).
pub const AVAILABLE: bool = cfg!(target_os = "macos");

/// A host request's outcome: the result, the bytes the host wrote into the
/// buffer, and the length it reported.
pub struct Reply {
    /// `Ok`, or the error (`ENOMEM` still reports a length).
    pub result: Result<(), Errno>,
    /// What the host wrote to the buffer.
    pub data: Vec<u8>,
    /// The length it stored in `*oldlenp`.
    pub len: u64,
}

/// `sysctl(oid)` on the host with a buffer of `room` bytes (none for a
/// size query) and `new` as the new value.
pub fn sysctl(oid: &[i32], room: Option<u64>, new: Option<&[u8]>) -> Option<Reply> {
    #[cfg(target_os = "macos")]
    {
        let mut mib = oid.to_vec();
        let mut buf = vec![0u8; room.unwrap_or(0) as usize];
        let mut len = room.unwrap_or(0) as usize;
        let (np, nl) = match new {
            Some(n) => (n.as_ptr() as *mut libc::c_void, n.len()),
            None => (std::ptr::null_mut(), 0),
        };
        let old = if room.is_some() {
            buf.as_mut_ptr().cast()
        } else {
            std::ptr::null_mut()
        };
        // SAFETY: `mib` holds `mib.len()` names, `old` is null or `buf`
        // with `len` bytes, and `np` is null or `new` with `nl` bytes.
        let r = unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, old, &mut len, np, nl) };
        let result = if r == 0 {
            Ok(())
        } else {
            Err(Errno::from_host(
                std::io::Error::last_os_error().raw_os_error()?,
            ))
        };
        buf.truncate(len.min(buf.len()));
        Some(Reply {
            result,
            data: buf,
            len: len as u64,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (oid, room, new);
        None
    }
}

/// The host's OID of `name` (`name2oid`).
pub fn oid_of(name: &str) -> Result<Vec<i32>, Errno> {
    let r = sysctl(&[0, 3], Some(4 * 12), Some(name.as_bytes())).ok_or(Errno::ENOENT)?;
    r.result?;
    Ok(r.data
        .chunks_exact(4)
        .map(|c| i32::from_le_bytes(c.try_into().expect("4 bytes")))
        .collect())
}

/// The host's name of `oid` (`sysctl.name`).
pub fn name_of(oid: &[i32]) -> Option<String> {
    let mut q = vec![0, 1];
    q.extend_from_slice(oid);
    let r = sysctl(&q, Some(1024), None)?;
    r.result.ok()?;
    let mut n = r.data;
    while n.last() == Some(&0) {
        n.pop();
    }
    String::from_utf8(n).ok()
}

/// The host's leaf after `oid` (`sysctl.next`), `None` at the end.
pub fn next(oid: &[i32]) -> Option<Vec<i32>> {
    let mut q = vec![0, 2];
    q.extend_from_slice(oid);
    let r = sysctl(&q, Some(4 * 12), None)?;
    r.result.ok()?;
    Some(
        r.data
            .chunks_exact(4)
            .map(|c| i32::from_le_bytes(c.try_into().expect("4 bytes")))
            .collect(),
    )
}
