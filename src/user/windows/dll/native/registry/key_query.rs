//! NtQueryKey capture/probe order and the key-body handle-tags record.
use super::*;

pub(in super::super) fn query_key(c: &mut Ctx) -> ApiResult {
    let result = query_checked(c);
    finish(c, result)
}

fn query_checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    let converted = c.arch() == WinArch::X86 && output % 8 != 0;
    let mut scratch = if converted {
        if length as usize > MAX_CONVERSION_BYTES {
            return Err(c
                .unsupported("WoW64 key query conversion exceeds 16 MiB")
                .into());
        }
        // The thunk copies undefined native scratch tails even after failure.
        // Initialize those bytes rather than exposing host allocator contents.
        Some(vec![0; length as usize])
    } else {
        None
    };
    let result = query_native(
        c,
        handle,
        class,
        output,
        length,
        returned,
        scratch.as_deref_mut(),
    );
    if let Some(scratch) = scratch {
        let result = match result {
            Err(Failure::Api(ApiErr::Fault(fault))) if c.p.vm.take_guard(fault.addr) => {
                Ok(STATUS_GUARD_PAGE_VIOLATION)
            }
            result => result,
        };
        // Copy-out is reached after native status failures too. Captured native
        // store widths determine which completed writes precede a fault.
        copy_back(c, output, &scratch)?;
        result
    } else {
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn query_native(
    c: &Ctx,
    handle: u64,
    class: u32,
    output: u64,
    length: u32,
    returned: u64,
    scratch: Option<&mut [u8]>,
) -> Checked<u32> {
    if scratch.is_none() && length != 0 {
        if output % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, output, length as usize)?;
    }
    // ResultLength is mandatory, byte-aligned, and probed before class/handle
    // validation; it remains unchanged on their failure paths.
    probe_write(c, returned, 4)?;
    if class > 8 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let _key = key(c, handle, !matches!(class, 3 | 7))?;
    if matches!(class, 3 | 7) && c.p.objects.access(handle).unwrap_or(0) == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    if class != 7 {
        return Err(c
            .unsupported(&format!(
                "uncaptured registry key information class {class}"
            ))
            .into());
    }
    let tags =
        c.p.objects
            .registry_tags(handle)
            .expect("validated key body");
    c.mem().w32(returned, 4)?;
    if length < 4 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    if let Some(scratch) = scratch {
        scratch[..4].copy_from_slice(&tags.to_le_bytes());
    } else {
        c.mem().w32(output, tags)?;
    }
    Ok(STATUS_SUCCESS)
}

fn copy_back(c: &Ctx, output: u64, bytes: &[u8]) -> Checked<()> {
    let amd64 = c.p.native.as_ref().is_some_and(|native| {
        matches!(
            (
                native.version.major,
                native.version.minor,
                native.version.build,
                native.object_namespace.native_machine
            ),
            (10, 0, 20348 | 26100, Some(0x8664))
        )
    });
    if bytes.is_empty() {
        return Ok(());
    }
    if !amd64 || bytes.len() > 16 {
        return Ok(super::super::virtual_memory::copy_thunk_bytes(
            c, output, bytes,
        )?);
    }
    // The native AMD64 WoW64 key-query short copier publishes the tail word
    // before the leading word. ARM64 uses the other captured store sequence.
    // Every individual store probes its entire width before publishing bytes.
    let width = match bytes.len() {
        0 => return Ok(()),
        1 => 1,
        2..=3 => 2,
        4..=8 => 4,
        _ => 8,
    };
    let tail = bytes.len() - width;
    if bytes.len() <= 8 {
        c.mem().wr(output + tail as u64, &bytes[tail..])?;
        c.mem().wr(output, &bytes[..width])?;
    } else {
        c.mem().wr(output, &bytes[..width])?;
        c.mem().wr(output + tail as u64, &bytes[tail..])?;
    }
    Ok(())
}
