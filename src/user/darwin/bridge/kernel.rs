//! Kernel calls sent on the host through a proxy that name memory of the
//! calling task (IOKit's, `device.defs`; request and reply layouts as the
//! SDK's `IOKit/iokitmig.h` gives them). The calling task on the host is the
//! emulator, so a guest address in such a call would name the emulator's
//! memory: each is given a host buffer instead, filled from the guest's
//! memory before the call (an input) or copied into it after the reply (an
//! output, as long as the reply says). Calls that map memory into a task
//! or unmap it cannot reach the guest's memory and are answered here, as
//! unsupported, without reaching the host.

use super::host;
use crate::user::darwin::mach::kr::KernReturn;
use crate::user::darwin::mach::msg::HEADER_SIZE;
use crate::user::darwin::process::Proc;

/// IOKit routines (`iokit` subsystem 2800).
mod id {
    pub const MAP_SHARED_MEMORY: i32 = 2815;
    pub const MAP_MEMORY_INTO_TASK: i32 = 2863;
    pub const UNMAP_MEMORY_FROM_TASK: i32 = 2864;
    pub const METHOD: i32 = 2865;
    pub const ASYNC_METHOD: i32 = 2866;
    pub const METHOD_VAR_OUTPUT: i32 = 2872;
    pub const PROPERTIES_BIN_BUF: i32 = 2888;
    pub const PROPERTY_BIN_BUF: i32 = 2889;
}

/// `kIOReturnUnsupported`.
pub const IO_RETURN_UNSUPPORTED: KernReturn = 0xe000_02c7_u32 as KernReturn;
/// `kIOReturnBadArgument`.
const IO_RETURN_BAD_ARGUMENT: KernReturn = 0xe000_02c2_u32 as KernReturn;
/// The largest buffer a call is given.
const MAX_BUFFER: u64 = 64 << 20;

/// Whether routine `id` is answered here as unsupported.
pub fn refused(id: i32) -> bool {
    matches!(
        id,
        id::MAP_SHARED_MEMORY | id::MAP_MEMORY_INTO_TASK | id::UNMAP_MEMORY_FROM_TASK
    )
}

/// Whether routine `id` names memory of the calling task.
pub fn names_memory(id: i32) -> bool {
    matches!(
        id,
        id::METHOD
            | id::ASYNC_METHOD
            | id::METHOD_VAR_OUTPUT
            | id::PROPERTIES_BIN_BUF
            | id::PROPERTY_BIN_BUF
    )
}

/// The host buffers a call was given, and where their contents go.
#[derive(Default)]
pub struct Fixup {
    /// The call's buffers (kept until the reply is in).
    buffers: Vec<Vec<u8>>,
    /// An output: the guest address and the buffer that holds it.
    output: Option<(u64, usize)>,
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// A MIG variable-length array of `count` elements of `size` bytes at `o`
/// (after its count): the offset past it (arrays pad to 4 bytes).
fn past(o: usize, count: u32, size: usize) -> usize {
    o + (count as usize * size).div_ceil(4) * 4
}

/// The offsets of the `ool_input` and `ool_output` fields (the latter
/// absent for `io_connect_method_var_output`) of an `io_connect_*method`
/// request whose selector is at `o`.
fn method_fields(b: &[u8], mut o: usize, output: bool) -> Option<(usize, Option<usize>)> {
    o += 4; // selector
    let scalars = u32_at(b, o)?;
    o = past(o + 4, scalars, 8);
    let inband = u32_at(b, o)?;
    o = past(o + 4, inband, 1);
    let ool_input = o;
    o += 16; // ool_input, ool_input_size
    o += 8; // inband_outputCnt, scalar_outputCnt
    Some((ool_input, output.then_some(o)))
}

/// Gives the call in `buf` (a host message, header first) host buffers for
/// the guest memory it names.
pub fn prepare(proc: &Proc, id: i32, buf: &mut [u8]) -> Result<Fixup, KernReturn> {
    let mut fix = Fixup::default();
    let bad = IO_RETURN_BAD_ARGUMENT;
    // The address and size fields to replace: (address offset, is output).
    let mut fields: Vec<(usize, bool)> = Vec::new();
    let ndr = HEADER_SIZE;
    match id {
        id::PROPERTIES_BIN_BUF => fields.push((ndr + 8, true)),
        id::PROPERTY_BIN_BUF => {
            let mut o = ndr + 8 + 4; // planeOffset
            let plane = u32_at(buf, o).ok_or(bad)?;
            o = past(o + 4, plane, 1) + 4; // property_nameOffset
            let name = u32_at(buf, o).ok_or(bad)?;
            o = past(o + 4, name, 1) + 4; // options
            fields.push((o, true));
        }
        id::METHOD | id::METHOD_VAR_OUTPUT => {
            let (i, out) = method_fields(buf, ndr + 8, id == id::METHOD).ok_or(bad)?;
            fields.push((i, false));
            fields.extend(out.map(|o| (o, true)));
        }
        id::ASYNC_METHOD => {
            // The wake port's descriptor comes first.
            let ndr = HEADER_SIZE + 4 + 12;
            let refs = u32_at(buf, ndr + 8).ok_or(bad)?;
            let sel = past(ndr + 12, refs, 8);
            let (i, out) = method_fields(buf, sel, true).ok_or(bad)?;
            fields.push((i, false));
            fields.extend(out.map(|o| (o, true)));
        }
        _ => return Ok(fix),
    }
    for (at, output) in fields {
        let (addr, size) = (u64_at(buf, at).ok_or(bad)?, u64_at(buf, at + 8).ok_or(bad)?);
        if addr == 0 || size == 0 {
            continue;
        }
        if size > MAX_BUFFER {
            return Err(bad);
        }
        let mut b = vec![0u8; size as usize];
        if !output {
            proc.space.read_raw(addr, &mut b).map_err(|_| bad)?;
        }
        buf[at..at + 8].copy_from_slice(&(b.as_ptr() as u64).to_le_bytes());
        if output {
            fix.output = Some((addr, fix.buffers.len()));
        }
        fix.buffers.push(b);
    }
    Ok(fix)
}

/// Copies what the reply `raw` (a host message) says the call wrote to its
/// output buffer into the guest's memory.
pub fn finish(proc: &Proc, id: i32, fix: Fixup, raw: &[u8]) {
    let Some((guest, i)) = fix.output else {
        return;
    };
    let complex = u32_at(raw, 0).is_some_and(|b| b & 0x8000_0000 != 0);
    let written = match id {
        // A complex reply: the properties descriptor, NDR, bufsize.
        id::PROPERTIES_BIN_BUF | id::PROPERTY_BIN_BUF if complex => {
            u64_at(raw, HEADER_SIZE + 4 + 16 + 8)
        }
        id::METHOD | id::ASYNC_METHOD if !complex => {
            // NDR, RetCode, the inband output, the scalar output, then
            // ool_output_size.
            let o = HEADER_SIZE + 8 + 4;
            u32_at(raw, o)
                .map(|n| past(o + 4, n, 1))
                .and_then(|o| u32_at(raw, o).map(|n| past(o + 4, n, 8)))
                .and_then(|o| u64_at(raw, o))
        }
        _ => None,
    };
    let b = &fix.buffers[i];
    if let Some(n) = written.filter(|&n| n > 0) {
        let n = (n as usize).min(b.len());
        let _ = proc.space.write_raw(guest, &b[..n]);
    }
}

/// Whether host name `name` is the emulator's own task port, or the host
/// port: rights to them a service hands back stand for the guest's own
/// task and host.
pub fn own(name: u32) -> Option<bool> {
    if name == host::task() {
        return Some(true);
    }
    // IKOT_HOST: there is one host.
    (host::kobject(name) == 3).then_some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_fields_follow_the_variable_arrays() {
        // io_connect_method: NDR, selector, 2 scalars, 5 inband bytes.
        let mut b = vec![0u8; 256];
        let sel = HEADER_SIZE + 8;
        b[sel + 4..sel + 8].copy_from_slice(&2u32.to_le_bytes());
        let inband = sel + 8 + 16;
        b[inband..inband + 4].copy_from_slice(&5u32.to_le_bytes());
        // 5 bytes pad to 8: ool_input follows.
        let (i, o) = method_fields(&b, sel, true).unwrap();
        assert_eq!(i, inband + 4 + 8);
        assert_eq!(o, Some(i + 16 + 8));
        assert_eq!(method_fields(&b, sel, false).unwrap().1, None);
        assert_eq!(past(0, 3, 1), 4);
        assert_eq!(past(0, 4, 1), 4);
        assert_eq!(past(0, 2, 8), 16);
        assert!(refused(2863) && !refused(2865));
        assert!(names_memory(2889) && !names_memory(2809));
    }
}
