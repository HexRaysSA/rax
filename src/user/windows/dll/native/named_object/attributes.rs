//! Capture precedes caller publication, including aliased attributes/output.
use super::*;

#[derive(Default)]
pub(in super::super) struct Attributes {
    pub(in super::super) root: u64,
    pub(in super::super) flags: u32,
    pub(in super::super) name: Option<Vec<u16>>,
    security: u64,
    qos: u64,
}

fn name_fields(c: &Ctx, pointer: u64, wow: bool) -> Checked<Option<(usize, u64)>> {
    if pointer == 0 {
        return Ok(None);
    }
    if !wow {
        c.mem().bytes(pointer, 16)?;
    }
    let length = c.mem().u16(pointer)? as usize;
    if wow {
        c.mem().u16(pointer + 2)?;
    }
    let buffer = c.read_ptr(pointer + c.psize())?;
    Ok(Some((length, buffer)))
}

fn name(c: &Ctx, pointer: u64, wow: bool) -> Checked<Option<Vec<u16>>> {
    let Some((length, buffer)) = name_fields(c, pointer, wow)? else {
        return Ok(None);
    };
    if length != 0 && buffer % 2 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if length % 2 != 0 || length >= 65534 {
        return status(STATUS_OBJECT_NAME_INVALID);
    }
    let bytes = c.mem().bytes(buffer, length)?;
    Ok(Some(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    ))
}

pub(in super::super) fn capture(c: &Ctx, address: u64, wow: bool) -> Checked<Option<Attributes>> {
    capture_inner(c, address, wow, false).map(|(attrs, _)| attrs)
}

/// WoW64 touches bounded name bytes during conversion, but kernel alignment
/// and length failures occur after the caller HANDLE probe. Keep those stages
/// separate so opening can perform the measured final zero-HANDLE copy.
fn open_name(c: &Ctx, pointer: u64, wow: bool) -> Checked<(Option<Vec<u16>>, Option<u32>)> {
    if !wow {
        return name(c, pointer, false).map(|name| (name, None));
    }
    let Some((length, buffer)) = name_fields(c, pointer, true)? else {
        return Ok((None, None));
    };
    let bytes = if length != 0 && length < 65534 {
        c.mem().bytes(buffer, length)?
    } else {
        Vec::new()
    };
    let pending = if length != 0 && buffer % 2 != 0 {
        Some(STATUS_DATATYPE_MISALIGNMENT)
    } else if length % 2 != 0 || length >= 65534 {
        Some(STATUS_OBJECT_NAME_INVALID)
    } else {
        None
    };
    let units = pending.is_none().then(|| {
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    });
    Ok((units, pending))
}

pub(in super::super) fn capture_event_open(
    c: &Ctx,
    address: u64,
    wow: bool,
) -> Checked<(Option<Attributes>, Option<u32>)> {
    capture_inner(c, address, wow, true)
}

fn capture_inner(
    c: &Ctx,
    address: u64,
    wow: bool,
    event_open: bool,
) -> Checked<(Option<Attributes>, Option<u32>)> {
    if address == 0 {
        return Ok((None, None));
    }
    let size = if wow { 24 } else { 48 };
    if !wow && address % 8 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if wow && c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    if !wow {
        c.mem().bytes(address, size as usize)?;
    }
    if c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    let width = c.psize();
    let root = c.read_ptr(address + width)?;
    let np = c.read_ptr(address + 2 * width)?;
    let converted_name = if wow {
        Some(if event_open {
            open_name(c, np, true)?
        } else {
            (name(c, np, true)?, None)
        })
    } else {
        None
    };
    let flags = c.mem().u32(address + 3 * width)?;
    let security = c.read_ptr(address + if wow { 16 } else { 32 })?;
    let qos = c.read_ptr(address + if wow { 20 } else { 40 })?;
    if !wow && flags & !0x1EF2 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    for (pointer, size) in [(qos, 12), (security, 20)] {
        if pointer != 0 {
            if !wow && pointer % 4 != 0 {
                return status(STATUS_DATATYPE_MISALIGNMENT);
            }
            c.mem().bytes(pointer, size)?;
        }
    }
    let (name, pending) = match converted_name {
        Some(name) => name,
        None => (name(c, np, false)?, None),
    };
    Ok((
        Some(Attributes {
            root,
            flags,
            name,
            security,
            qos,
        }),
        pending,
    ))
}

pub(in super::super) fn supported(c: &Ctx, attrs: &Attributes, kind: &str) -> Checked<()> {
    if attrs.security != 0 {
        return Err(c
            .unsupported(format!("NT {kind} explicit security descriptor"))
            .into());
    }
    if attrs.qos != 0 {
        return Err(c
            .unsupported(format!("NT {kind} security quality of service"))
            .into());
    }
    Ok(())
}
