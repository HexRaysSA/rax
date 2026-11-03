//! SystemPolicyInformation has nested byte buffers. Native64 requires32 outer
//! bytes; WoW64 converts20bytes independently of the caller length/alignment.

use super::{ApiErr, ApiResult, Ctx, Flow, Mem, STATUS_INFO_LENGTH_MISMATCH, return_length};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL, STATUS_GUARD_PAGE_VIOLATION,
};
use crate::user::windows::policy::{self, Error};

pub(super) fn native(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    if length != 32 {
        return_length(c, returned, 32)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    perform(c, output, returned, 8)
}

pub(super) fn wow64(c: &mut Ctx, output: u64, returned: u64) -> ApiResult {
    perform(c, output, returned, 4)
}

fn perform(c: &mut Ctx, descriptor: u64, returned: u64, pointer_bytes: usize) -> ApiResult {
    // Snapshot caller fields before touching nested output or aliased returns.
    let mut bytes = [0u8; 32];
    c.mem().rd(
        descriptor,
        &mut bytes[..if pointer_bytes == 4 { 20 } else { 32 }],
    )?;
    if pointer_bytes == 4 && returned != 0 {
        // WoW64 first captures the20-byte descriptor, then probes the caller's
        // ULONG ReturnLength before forwarding its private native descriptor.
        super::probe_write(c, returned, 4)?;
    }
    let ptr = |at: usize| {
        if pointer_bytes == 4 {
            u64::from(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()))
        } else {
            u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
        }
    };
    let input = ptr(0);
    let output = ptr(pointer_bytes);
    let size_at = pointer_bytes * 2;
    let input_size = u32::from_le_bytes(bytes[size_at..size_at + 4].try_into().unwrap()) as usize;
    let output_size =
        u32::from_le_bytes(bytes[size_at + 4..size_at + 8].try_into().unwrap()) as usize;
    if input != 0 && input_size > policy::MAX_PACKET_BYTES {
        return Err(c.unsupported("SystemPolicyInformation input exceeds 2 MiB"));
    }
    let nested = (|| -> Result<u32, ApiErr> {
        let result = if input == 0 || input_size == 0 {
            Err(Error::Status(STATUS_BUFFER_TOO_SMALL))
        } else {
            let mut packet = vec![0; input_size];
            c.mem().rd(input, &mut packet)?;
            let runtime = c.p.native.as_ref().ok_or_else(|| {
                c.unsupported("SystemPolicyInformation requires selected native inputs")
            })?;
            let catalog = runtime.policy_catalog.as_ref().map_err(|reason| {
                c.unsupported(format!("SystemPolicyInformation unavailable: {reason}"))
            })?;
            policy::query(catalog, &packet)
        };
        Ok(match result {
            Err(Error::Status(status)) => status,
            Err(Error::Unsupported(reason)) => return Err(c.unsupported(reason)),
            Ok(reply) => {
                if output != 0 && output_size < reply.len() {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    if output != 0 {
                        // Native's checked user copy retains complete reached
                        // pages when a later page faults. The generic bulk writer
                        // preflights its full span, so split this copy at pages.
                        let mut at = output;
                        let mut rest = reply.as_slice();
                        while !rest.is_empty() {
                            let size = rest.len().min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                            c.mem().wr(at, &rest[..size])?;
                            at += size as u64;
                            rest = &rest[size..];
                        }
                    }
                    if pointer_bytes == 8 {
                        c.mem()
                            .w32(descriptor + size_at as u64 + 4, reply.len() as u32)?;
                    }
                    0
                }
            }
        })
    })();
    let status = match nested {
        Ok(status) => status,
        Err(ApiErr::Fault(fault)) => {
            // The kernel catches nested user-buffer faults before the outer
            // system-information entry writes its ULONG ReturnLength.
            if c.p.vm.take_guard(fault.addr) {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            }
        }
        Err(error) => return Err(error),
    };
    return_length(c, returned, 32)?;
    Flow::ret(status.into())
}
