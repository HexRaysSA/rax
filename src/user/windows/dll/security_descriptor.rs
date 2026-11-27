//! Win32 construction of guest ACLs and absolute security descriptors.

use crate::error::MemoryAccessKind;
use crate::user::windows::{
    hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::{Mem, MemFault},
    nt::error::{
        ERROR_ALLOTTED_SPACE_EXCEEDED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_ACL,
        ERROR_INVALID_PARAMETER, ERROR_INVALID_SECURITY_DESCR, ERROR_INVALID_SID,
        ERROR_UNKNOWN_REVISION,
    },
};

pub(super) static EXPORTS: &[Export] = &[
    Export::func("InitializeAcl", Stdcall, &[Ptr, I32, I32], initialize_acl),
    Export::func(
        "AddAccessAllowedAce",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        add_allowed_ace,
    ),
    Export::func(
        "InitializeSecurityDescriptor",
        Stdcall,
        &[Ptr, I32],
        initialize_descriptor,
    ),
    Export::func(
        "SetSecurityDescriptorDacl",
        Stdcall,
        &[Ptr, I32, Ptr, I32],
        set_dacl,
    ),
];

const ACL_HEADER_BYTES: usize = 8;
const DACL_PRESENT: u16 = 0x0004;
const DACL_DEFAULTED: u16 = 0x0008;
const SELF_RELATIVE: u16 = 0x8000;

fn initialize_acl(c: &mut Ctx) -> ApiResult {
    let (acl, size, revision) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?);
    if size < ACL_HEADER_BYTES as u32 {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    if !(2..=4).contains(&revision) || size > 0xfffc {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut header = [0; ACL_HEADER_BYTES];
    header[0] = revision as u8;
    header[2..4].copy_from_slice(&((size & !3) as u16).to_le_bytes());
    c.mem().wr(acl, &header)?;
    Flow::bool(true)
}

fn add_allowed_ace(c: &mut Ctx) -> ApiResult {
    let (acl, revision, mask, sid) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?, c.ptr(3)?);
    let current_revision = c.mem().u8(acl)?;
    if !(2..=4).contains(&revision) || !(2..=4).contains(&current_revision) {
        return c.fail(ERROR_UNKNOWN_REVISION, 0);
    }
    let size = usize::from(c.mem().u16(acl + 2)?);
    let count = c.mem().u16(acl + 4)?;
    if size < ACL_HEADER_BYTES || usize::from(count) > (size - ACL_HEADER_BYTES) / 4 {
        return c.fail(ERROR_INVALID_ACL, 0);
    }
    let mut next = ACL_HEADER_BYTES;
    for _ in 0..count {
        if next + 4 > size {
            return c.fail(ERROR_INVALID_ACL, 0);
        }
        let length = usize::from(c.mem().u16(acl + next as u64 + 2)?);
        if length < 4 || length % 4 != 0 || next + length > size {
            return c.fail(ERROR_INVALID_ACL, 0);
        }
        next += length;
    }
    if c.mem().u8(sid)? != 1 {
        return c.fail(ERROR_INVALID_SID, 0);
    }
    let subauthorities = usize::from(c.mem().u8(sid + 1)?);
    if subauthorities > 15 {
        return c.fail(ERROR_INVALID_SID, 0);
    }
    let sid_length = 8 + subauthorities * 4;
    let length = 8 + sid_length;
    if next + length > size {
        return c.fail(ERROR_ALLOTTED_SPACE_EXCEEDED, 0);
    }
    let mut ace = [0; 76];
    ace[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    ace[4..8].copy_from_slice(&mask.to_le_bytes());
    ace[8..length].copy_from_slice(&c.mem().bytes(sid, sid_length)?);
    let address = acl + next as u64;
    probe(c, acl, ACL_HEADER_BYTES)?;
    probe(c, address, length)?;
    c.mem().wr(address, &ace[..length])?;
    c.mem().w8(acl, current_revision.max(revision as u8))?;
    c.mem().w16(acl + 4, count + 1)?;
    Flow::bool(true)
}

fn initialize_descriptor(c: &mut Ctx) -> ApiResult {
    let (output, revision) = (c.ptr(0)?, c.u32(1)?);
    if revision != 1 {
        return c.fail(ERROR_UNKNOWN_REVISION, 0);
    }
    let mut descriptor = [0; 40];
    descriptor[0] = 1;
    c.mem().wr(output, &descriptor[..5 * c.psize() as usize])?;
    Flow::bool(true)
}

fn set_dacl(c: &mut Ctx) -> ApiResult {
    let (descriptor, present, dacl, defaulted) =
        (c.ptr(0)?, c.u32(1)? != 0, c.ptr(2)?, c.u32(3)? != 0);
    if c.mem().u8(descriptor)? != 1 {
        return c.fail(ERROR_UNKNOWN_REVISION, 0);
    }
    let control = descriptor + 2;
    let flags = c.mem().u16(control)?;
    if flags & SELF_RELATIVE != 0 {
        return c.fail(ERROR_INVALID_SECURITY_DESCR, 0);
    }
    if present {
        probe(c, control, 2)?;
        c.write_ptr(descriptor + 4 * c.psize(), dacl)?;
        c.mem().w16(
            control,
            ((flags | DACL_PRESENT) & !DACL_DEFAULTED) | (u16::from(defaulted) * DACL_DEFAULTED),
        )?;
    } else {
        c.mem().w16(control, flags & !DACL_PRESENT)?;
    }
    Flow::bool(true)
}

fn probe(c: &Ctx, address: u64, length: usize) -> Result<(), MemFault> {
    c.mem()
        .probe(address, length, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}
