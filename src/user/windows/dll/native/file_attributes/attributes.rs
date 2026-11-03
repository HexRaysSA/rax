//! WoW64 conversion captures headers and short non-NULL names before the
//! kernel output probe. Security child structures are visited afterwards.

use super::super::named_object::{Checked, status};
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INVALID_PARAMETER, STATUS_INVALID_SID,
    STATUS_OBJECT_NAME_INVALID, STATUS_UNKNOWN_REVISION,
};

const INVALID_ACL: u32 = 0xc000_0077;
const BAD_IMPERSONATION_LEVEL: u32 = 0xc000_00a5;

pub(in super::super) struct Attributes {
    pub(in super::super) root: u64,
    pub(in super::super) flags: u32,
    name: Option<Name>,
    security: Option<Security>,
    qos: Option<Vec<u8>>,
}

struct Name {
    length: usize,
    buffer: u64,
    converted: Option<Vec<u8>>,
}

struct Security {
    address: u64,
    header: Vec<u8>,
    relative: bool,
    wide: bool,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn pointer(bytes: &[u8], offset: usize, wide: bool) -> u64 {
    if wide {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    } else {
        u64::from(u32_at(bytes, offset))
    }
}

fn capture_name(c: &Ctx, name_address: u64, wow: bool) -> Checked<Option<Name>> {
    let width = if wow { 4 } else { 8 };
    let result = if name_address == 0 {
        None
    } else {
        let descriptor = c.mem().bytes(name_address, width * 2)?;
        let length = usize::from(u16::from_le_bytes(descriptor[..2].try_into().unwrap()));
        let buffer = pointer(&descriptor, width, !wow);
        Some(Name {
            length,
            buffer,
            converted: None,
        })
    };
    Ok(result)
}

fn capture_security(c: &Ctx, security_address: u64, wow: bool) -> Checked<Option<Security>> {
    let result = if security_address == 0 {
        None
    } else {
        if !wow && security_address % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        let prefix = c.mem().bytes(security_address, 20)?;
        let relative = u16::from_le_bytes(prefix[2..4].try_into().unwrap()) & 0x8000 != 0;
        let wide = !wow && !relative;
        let header = if wide && prefix[0] == 1 {
            c.mem().bytes(security_address, 40)?
        } else {
            prefix
        };
        Some(Security {
            address: security_address,
            header,
            relative,
            wide,
        })
    };
    Ok(result)
}

fn capture_qos(c: &Ctx, qos_address: u64, wow: bool) -> Checked<Option<Vec<u8>>> {
    let result = if qos_address == 0 {
        None
    } else {
        if !wow && qos_address % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        Some(c.mem().bytes(qos_address, 12)?)
    };
    Ok(result)
}

fn validate_qos(qos: &[u8]) -> Checked<()> {
    if qos[8] > 1 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if u32_at(qos, 4) > 3 {
        return status(BAD_IMPERSONATION_LEVEL);
    }
    Ok(())
}

pub(in super::super) fn capture(c: &Ctx, address: u64, wow: bool) -> Checked<Option<Attributes>> {
    capture_with(c, address, wow, 0x11ff2, false, false)
}

pub(in super::super) fn capture_open(
    c: &Ctx,
    address: u64,
    wow: bool,
) -> Checked<Option<Attributes>> {
    capture_with(c, address, wow, 0x11ec2, true, false)
}

pub(in super::super) fn capture_create(
    c: &Ctx,
    address: u64,
    wow: bool,
) -> Checked<Option<Attributes>> {
    capture_with(c, address, wow, 0x11ec2, true, true)
}

fn capture_with(
    c: &Ctx,
    address: u64,
    wow: bool,
    allowed: u32,
    opening: bool,
    capture_null_name: bool,
) -> Checked<Option<Attributes>> {
    if address == 0 {
        return Ok(None);
    }
    let size = if wow { 24 } else { 48 };
    if !wow && address % 8 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if wow && c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    let header = c.mem().bytes(address, size as usize)?;
    if u32_at(&header, 0) != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    let width = if wow { 4 } else { 8 };
    let flags = u32_at(&header, width * 3);
    if !wow && flags & !allowed != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let name_address = pointer(&header, width * 2, !wow);
    let security_address = pointer(&header, if wow { 16 } else { 32 }, !wow);
    let qos_address = pointer(&header, if wow { 20 } else { 40 }, !wow);
    let (name, security, qos) = if wow {
        // The wrapper visits the name and the two converted headers before
        // the caller output. Semantic security children remain deferred.
        let mut name = capture_name(c, name_address, true)?;
        let security = capture_security(c, security_address, true)?;
        let qos = capture_qos(c, qos_address, true)?;
        // Header conversion precedes reachable character reads. Malformed
        // odd/overlong names reach kernel syntax validation without visiting
        // their character buffer, including a guarded/unmapped buffer.
        // The measured WoW64 open wrapper cannot redirect an invalid root.
        // It still captures headers, but leaves its character buffer for the
        // native capture and consequently publishes a zero failed handle.
        let root = pointer(&header, width, false);
        let deferred_root = opening && root != 0 && c.p.objects.get(root).is_none();
        if let Some(name) = &mut name
            && !deferred_root
            && (name.buffer != 0 || capture_null_name)
            && name.length % 2 == 0
            && name.length < 65534
        {
            name.converted = Some(c.mem().bytes(name.buffer, name.length)?);
        }
        (name, security, qos)
    } else {
        // Native output was already probed. Object capture copies QoS first,
        // then validates security before QoS semantics and the name header.
        let qos = capture_qos(c, qos_address, false)?;
        if let Some(security) = capture_security(c, security_address, false)? {
            security_validate(c, &security)?;
        }
        if let Some(qos) = qos {
            validate_qos(&qos)?;
        }
        (capture_name(c, name_address, false)?, None, None)
    };
    Ok(Some(Attributes {
        root: pointer(&header, width, !wow),
        flags,
        name,
        security,
        qos,
    }))
}

fn security_validate(c: &Ctx, captured: &Security) -> Checked<()> {
    let header = &captured.header;
    if header[0] != 1 {
        return status(STATUS_UNKNOWN_REVISION);
    }
    let control = u16::from_le_bytes(header[2..4].try_into().unwrap());
    let width = if captured.wide { 8 } else { 4 };
    let first = if captured.wide { 8 } else { 4 };
    for index in 0..4 {
        if (index == 2 && control & 0x10 == 0) || (index == 3 && control & 4 == 0) {
            continue;
        }
        let value = pointer(header, first + index * width, captured.wide);
        if value == 0 {
            continue;
        }
        let address = if captured.relative {
            captured.address.checked_add(value).ok_or_else(|| {
                c.unsupported("relative file-query security descriptor pointer overflow")
            })?
        } else {
            value
        };
        let prefix = c.mem().bytes(address, 8)?;
        if index < 2 {
            if prefix[0] != 1 || prefix[1] > 15 {
                return status(STATUS_INVALID_SID);
            }
            c.mem().bytes(address, 8 + usize::from(prefix[1]) * 4)?;
        } else {
            let length = usize::from(u16::from_le_bytes(prefix[2..4].try_into().unwrap()));
            if !matches!(prefix[0], 2 | 4) || length < 8 {
                return status(INVALID_ACL);
            }
            let acl = c.mem().bytes(address, length)?;
            let count = u16::from_le_bytes(prefix[4..6].try_into().unwrap());
            let mut at = 8usize;
            for _ in 0..count {
                let Some(ace) = acl.get(at..at + 4) else {
                    return status(INVALID_ACL);
                };
                let bytes = usize::from(u16::from_le_bytes(ace[2..4].try_into().unwrap()));
                if bytes < 4 || bytes % 4 != 0 || bytes > length - at {
                    return status(INVALID_ACL);
                }
                at += bytes;
            }
        }
    }
    Ok(())
}

pub(in super::super) fn validate(c: &Ctx, attrs: &Attributes) -> Checked<Option<Vec<u16>>> {
    if attrs.flags & !0x11ff2 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if let Some(descriptor) = &attrs.security {
        security_validate(c, descriptor)?;
    }
    if let Some(qos) = &attrs.qos {
        validate_qos(qos)?;
    }
    let Some(name) = &attrs.name else {
        return Ok(None);
    };
    if name.length != 0 && name.buffer % 2 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if name.length % 2 != 0 || name.length >= 65534 {
        return status(STATUS_OBJECT_NAME_INVALID);
    }
    let raw = match &name.converted {
        Some(bytes) => bytes.clone(),
        None => c.mem().bytes(name.buffer, name.length)?,
    };
    Ok(Some(
        raw.chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    ))
}
