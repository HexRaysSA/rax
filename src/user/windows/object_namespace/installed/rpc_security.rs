use super::super::rpc_security::{
    CAPTURED_SECURITY_INFORMATION, READ_CONTROL, RpcSecurity, SE_SELF_RELATIVE,
};
use super::{Handle, Owned, check, invalid, null_mut};
use crate::user::windows::nt::status::STATUS_BUFFER_TOO_SMALL;
use std::ffi::c_void;
use std::io;

const HEADER_SIZE: usize = 20;
// Two ACLs with 16-bit lengths and two SIDs of at most 68 bytes.
const MAX_DESCRIPTOR_SIZE: usize = HEADER_SIZE + 2 * (u16::MAX as usize + 68);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySecurityObject(
        handle: Handle,
        mask: u32,
        descriptor: *mut c_void,
        length: u32,
        required: *mut u32,
    ) -> i32;
}

pub(super) fn capture(directory: &Owned, access: u32) -> io::Result<RpcSecurity> {
    let mut descriptors = std::array::from_fn(|_| None);
    if access & READ_CONTROL == 0 {
        descriptors[0] = Some(query(directory, 0)?);
    } else {
        let full = query(directory, CAPTURED_SECURITY_INFORMATION)?;
        for (index, descriptor) in descriptors[..15].iter_mut().enumerate() {
            let index = index as u32;
            let mask = (index & 7) | ((index & 8) << 1);
            *descriptor = Some(query(directory, mask)?);
        }
        if full != query(directory, CAPTURED_SECURITY_INFORMATION)? {
            return Err(invalid("RPC directory security changed during capture"));
        }
        descriptors[15] = Some(full);
    }
    Ok(RpcSecurity { descriptors })
}

fn query(directory: &Owned, mask: u32) -> io::Result<Box<[u8]>> {
    let mut required = 0;
    // SAFETY: the owned directory stays live, there is no data buffer, and
    // ReturnLength points into this call's stack.
    let status = unsafe { NtQuerySecurityObject(directory.0, mask, null_mut(), 0, &mut required) };
    let length = required as usize;
    if status as u32 != STATUS_BUFFER_TOO_SMALL
        || !(HEADER_SIZE..=MAX_DESCRIPTOR_SIZE).contains(&length)
    {
        return Err(invalid(
            "RPC directory security sizing is outside its bounds",
        ));
    }
    let mut output = vec![0u32; length.div_ceil(4)];
    // SAFETY: aligned, initialized storage has at least the advertised
    // length, and the native call retains neither output pointer.
    let status = unsafe {
        NtQuerySecurityObject(
            directory.0,
            mask,
            output.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    check(status, "NtQuerySecurityObject selected RPC directory")?;
    if required as usize != length {
        return Err(invalid(
            "RPC directory security length changed during capture",
        ));
    }
    let mut bytes = Vec::with_capacity(length);
    for word in output {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.truncate(length);
    if bytes[0] != 1 || u16::from_le_bytes([bytes[2], bytes[3]]) & SE_SELF_RELATIVE == 0 {
        return Err(invalid(
            "RPC directory security is not a revision 1 relative descriptor",
        ));
    }
    Ok(bytes.into_boxed_slice())
}
