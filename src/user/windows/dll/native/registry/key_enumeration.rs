//! Native and WoW64 enumeration entry over immutable ordered child metadata.
use super::*;

pub(in super::super) fn enumerate_key(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    finish(c, result)
}

fn checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, index, class, output, length, returned) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    // Invalid selectors bypass both native probes and WoW64 conversion.
    if class > 2 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let converted = c.arch() == WinArch::X86 && output % 8 != 0;
    let mut scratch = if converted {
        // The measured WoW64 thunk cannot allocate a zero-length conversion;
        // this follows selector admission and precedes destination/handle checks.
        if length == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        if length as usize > MAX_CONVERSION_BYTES {
            return Err(c
                .unsupported("WoW64 key enumeration conversion exceeds 16 MiB")
                .into());
        }
        // Unlike key-tag query, enumeration copies the caller's entire input
        // buffer into aligned private storage, preserving its undefined tail.
        Some(c.mem().bytes(output, length as usize)?)
    } else {
        None
    };
    let result = native(
        c,
        handle,
        index,
        class,
        output,
        length,
        returned,
        scratch.as_deref_mut(),
    );
    if matches!(&result, Err(Failure::Api(ApiErr::Unimplemented(_)))) {
        return result;
    }
    if let Some(scratch) = scratch {
        // Kernel probe failures return before the thunk's unconditional copy
        // back. Consume that reached guard before visiting the output again.
        let result = match result {
            Err(Failure::Api(ApiErr::Fault(fault))) if c.p.vm.take_guard(fault.addr) => {
                Ok(STATUS_GUARD_PAGE_VIOLATION)
            }
            other => other,
        };
        super::super::virtual_memory::copy_thunk_bytes(c, output, &scratch).map_err(|error| {
            match error {
                ApiErr::Unimplemented(_) => {
                    c.unsupported("key enumeration WoW64 copy kernel profile is not captured")
                }
                error => error,
            }
        })?;
        result
    } else {
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn native(
    c: &Ctx,
    handle: u64,
    index: u32,
    class: u32,
    output: u64,
    length: u32,
    returned: u64,
    scratch: Option<&mut [u8]>,
) -> Checked<u32> {
    let key = key(c, handle, false)?;
    if c.p.objects.access(handle).unwrap_or(0) & 8 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    if scratch.is_none() && length != 0 {
        if output % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, output, length as usize)?;
    }
    // Mandatory ULONG output, byte-aligned; probe before enumeration itself.
    probe_write(c, returned, 4)?;
    if class != 0 {
        return Err(c
            .unsupported(format!(
                "registry enumeration class {class} is not captured"
            ))
            .into());
    }
    if index >= key.children {
        return Ok(STATUS_NO_MORE_ENTRIES);
    }
    let entries = key
        .child_metadata()
        .ok_or_else(|| c.unsupported("registry child metadata is not captured"))?;
    // Selection validates the exact count, component bounds and ordinal
    // uniqueness. Native enumeration order is independent of body lookup.
    let child = &entries[index as usize];
    let required = 16 + child.name.len() * 2;
    c.mem().w32(returned, required as u32)?;
    if length < 16 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let mut record = Vec::with_capacity(required);
    record.extend(child.last_write.to_le_bytes());
    record.extend(0u32.to_le_bytes()); // Reserved TitleIndex in all native controls.
    record.extend((child.name.len() as u32 * 2).to_le_bytes());
    record.extend(child.name.iter().flat_map(|u| u.to_le_bytes()));
    let count = (length as usize).min(required);
    // Native partial names copy whole WCHARs and zero an odd trailing byte.
    // NameLength still describes the complete untruncated name.
    if count % 2 != 0 {
        record[count - 1] = 0;
    }
    if let Some(scratch) = scratch {
        scratch[..count].copy_from_slice(&record[..count]);
    } else {
        c.mem().wr(output, &record[..count])?;
    }
    Ok(if count == required {
        STATUS_SUCCESS
    } else {
        STATUS_BUFFER_OVERFLOW
    })
}
