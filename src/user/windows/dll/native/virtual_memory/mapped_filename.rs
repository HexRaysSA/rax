//! Class 2 follows the measured native64 and WoW64 filename conversion paths.
use super::process_status;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::native::query::probe_write;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::{AllocKind, Mem, MemFault, mem, prot};
use crate::user::windows::nt::status::*;

pub(super) fn query(
    c: &mut Ctx,
    process: u64,
    address: u64,
    output: u64,
    length: u64,
    returned: u64,
) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    // The filename converter reads its optional slot before dispatch. A read
    // fault consumes its guard and disables publication. A readable readonly
    // slot instead survives capture and can fail at the final caller store.
    let returned = if wow && returned != 0 {
        match c.read_ptr(returned) {
            Ok(_) => returned,
            Err(fault) => {
                c.p.vm.take_guard(fault.addr);
                0
            }
        }
    } else {
        returned
    };
    if address >= c.p.vm.high() {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if !wow {
        if length != 0 {
            if output % 8 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            if output >= c.p.vm.high() || length > c.p.vm.high() - output {
                return Flow::ret(STATUS_ACCESS_VIOLATION.into());
            }
            let bytes = usize::try_from(length).map_err(|_| MemFault {
                addr: output,
                write: true,
            })?;
            probe_write(c, output, bytes)?;
        }
        if returned != 0 {
            if returned >= c.p.vm.high() || 8 > c.p.vm.high() - returned {
                return Flow::ret(STATUS_ACCESS_VIOLATION.into());
            }
            probe_write(c, returned, 8)?;
        }
    }
    let finish = |c: &Ctx, status: u32, bytes: Option<u64>| -> ApiResult {
        if returned != 0
            && let Some(bytes) = bytes
        {
            c.write_ptr(returned, bytes)?;
        }
        Flow::ret(status.into())
    };
    let unchanged = wow.then_some(length + 8);
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        return finish(c, status, unchanged);
    }
    let Some(allocation) = c.p.vm.allocation(address) else {
        return finish(c, STATUS_INVALID_ADDRESS, unchanged);
    };
    if !matches!(allocation.kind, AllocKind::Image | AllocKind::Mapped) {
        return finish(c, STATUS_INVALID_ADDRESS, unchanged);
    }
    let Some(name) =
        c.p.vm
            .mapped_filename(address)
            .map_err(|error| c.unsupported(format!("mapped filename: {error}")))?
    else {
        return finish(c, STATUS_FILE_INVALID, unchanged);
    };
    if name.is_empty() || name.len() > 32766 || name.contains(&0) {
        return Err(c.unsupported("mapped filename exceeds the NT string profile"));
    }
    let header = 2 * c.psize();
    let required = header + 2 * (name.len() as u64 + 1);
    if length < header {
        return finish(c, STATUS_INFO_LENGTH_MISMATCH, Some(required));
    }
    if length < required {
        if !wow {
            return short_native(c, output, length, returned, &name, required);
        }
        let device = device_length(&name);
        if ((length - header) / 2) as usize == device + 1 {
            return finish(c, STATUS_OBJECT_PATH_INVALID, Some(0));
        }
        return finish(c, STATUS_BUFFER_OVERFLOW, Some(required));
    }
    if wow {
        copy_wow(c, output, length, &name)?;
    } else {
        write_record(c, output, output + header, &name)?;
    }
    finish(c, STATUS_SUCCESS, Some(required))
}

fn write_record(c: &Ctx, output: u64, buffer: u64, name: &[u16]) -> Result<(), MemFault> {
    let length = (name.len() * 2) as u16;
    c.mem().w16(output, length)?;
    c.mem().w16(output + 2, length + 2)?;
    // Native64 leaves the four padding bytes untouched.
    c.write_ptr(output + c.psize(), buffer)?;
    c.mem().put_wstr(output + 2 * c.psize(), name)
}

fn copy_wow(
    c: &mut Ctx,
    output: u64,
    length: u64,
    name: &[u16],
) -> Result<(), crate::user::windows::hle::ApiErr> {
    let encoded: Vec<u8> = name
        .iter()
        .copied()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    // Capture caller permissions before creating private conversion storage.
    // Otherwise an invalid caller address could become the allocator's next
    // temporary base and falsely become a writable destination. Probes do not
    // consume guards; the reached copy fault below retains the measured order.
    let operations = [(output, 2), (output + 2, 2), (output + 4, 4)]
        .into_iter()
        .chain(
            encoded
                .chunks(16)
                .enumerate()
                .map(|(index, block)| (output + 8 + index as u64 * 16, block.len())),
        );
    let blocked = operations
        .enumerate()
        .find_map(|(index, (address, bytes))| {
            probe_write(c, address, bytes)
                .err()
                .map(|fault| (index, fault))
        });
    // The native temporary pointer can remain in a partially copied 32-bit
    // header. Give it guest-owned backing, retire it on every path, and fix
    // Buffer only after the entire converted record has reached the caller.
    let size = length + 8;
    let base = c
        .p
        .vm
        .allocate(None, size, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .map_err(|error| c.unsupported(format!("mapped filename conversion storage: {error:?}")))?
        .0;
    let result = (|| {
        c.mem().put_wstr(base + 16, name)?;
        let bytes = (name.len() * 2) as u16;
        let store = |index, address, data: &[u8]| -> Result<(), MemFault> {
            if let Some((blocked, fault)) = blocked
                && blocked == index
            {
                return Err(fault);
            }
            c.mem().wr(address, data)
        };
        store(0, output, &bytes.to_le_bytes())?;
        store(1, output + 2, &(bytes + 2).to_le_bytes())?;
        store(2, output + 4, &((base + 16) as u32).to_le_bytes())?;
        // The recorded converter copies 16-byte blocks. A straddling block
        // faults before that block's stores, preserving earlier full blocks.
        for (index, block) in encoded.chunks(16).enumerate() {
            store(index + 3, output + 8 + index as u64 * 16, block)?;
        }
        c.write_ptr(output + 4, output + 8)?;
        Ok(())
    })();
    c.p.vm.release(base).map_err(|error| {
        c.unsupported(format!("mapped filename conversion retirement: {error:?}"))
    })?;
    result
}

fn short_native(
    c: &Ctx,
    output: u64,
    length: u64,
    returned: u64,
    name: &[u16],
    required: u64,
) -> ApiResult {
    let header = 16;
    let device = device_length(name);
    let capacity = ((length - header) / 2) as usize;
    if capacity > device {
        let copied = (capacity - 1).min(name.len());
        write_record(c, output, output + header, &name[..copied])?;
        if copied == device {
            if returned != 0 {
                c.write_ptr(returned, 0)?;
            }
            return Flow::ret(STATUS_OBJECT_PATH_INVALID.into());
        }
    }
    if returned != 0 {
        c.write_ptr(returned, required)?;
    }
    Flow::ret(STATUS_BUFFER_OVERFLOW.into())
}

fn device_length(name: &[u16]) -> usize {
    name.iter()
        .enumerate()
        .filter(|(_, unit)| **unit == b'\\' as u16)
        .nth(2)
        .map(|(at, _)| at)
        .unwrap_or(name.len())
}
