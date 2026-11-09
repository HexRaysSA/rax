//! Byte-aligned native processor queries with complete preflight publication.
use super::query::write_guard_result;
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinCpu;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER,
};

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    information_with(c, 1, |c| sample(c).map(|record| vec![record]))
}

pub(crate) fn information_with(
    c: &mut Ctx,
    processors: usize,
    capture: impl FnOnce(&Ctx) -> Result<Vec<[u32; 6]>, ApiErr>,
) -> ApiResult {
    let result = checked(c, processors, capture);
    let result = write_guard_result(c, result);
    match result {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn probe(c: &Ctx, address: u64, bytes: u32, write: bool) -> Result<(), MemFault> {
    c.mem()
        .probe(
            address,
            bytes as usize,
            if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            },
        )
        .map_err(|fault| MemFault {
            addr: fault.address,
            write,
        })
}

fn checked(
    c: &mut Ctx,
    processors: usize,
    capture: impl FnOnce(&Ctx) -> Result<Vec<[u32; 6]>, ApiErr>,
) -> ApiResult {
    let (level, input, input_bytes, output, output_bytes) =
        (c.u32(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?, c.u32(4)?);
    if level != 11 {
        return Err(c.unsupported(format!("NtPowerInformation level {level}")));
    }
    // Native copies/probes nonempty input before visiting output. Null input
    // ignores its length, and a nonnull pointer with zero length is not visited.
    if input != 0 && input_bytes != 0 {
        probe(c, input, input_bytes, false)?;
    }
    if output != 0 && output_bytes != 0 {
        // Alignment is one byte. Probe the supplied span, including excess
        // capacity, before checking whether the processor array would fit.
        probe(c, output, output_bytes, true)?;
    }
    if input != 0 && input_bytes != 0 || output == 0 || output_bytes == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let required = processors
        .checked_mul(24)
        .and_then(|bytes| u32::try_from(bytes).ok())
        .filter(|_| processors != 0)
        .ok_or_else(|| c.unsupported("invalid modeled processor count"))?;
    if output_bytes < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    let records = capture(c)?;
    if records.len() != processors
        || records
            .iter()
            .enumerate()
            .any(|(index, record)| record[0] as usize != index)
    {
        return Err(c.unsupported("processor power sample does not match selected topology"));
    }
    for (index, record) in records.iter().enumerate() {
        let mut bytes = [0u8; 24];
        for (field, value) in record.iter().enumerate() {
            bytes[field * 4..field * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        c.mem().wr(output + index as u64 * 24, &bytes)?;
    }
    Flow::ret(0)
}

fn sample(c: &Ctx) -> Result<[u32; 6], ApiErr> {
    if c.p.native.is_some() {
        return crate::user::windows::native::processor_power::capture()
            .map_err(|error| c.unsupported(error));
    }
    // Built-in mode describes virtual hardware. Its x86 frequencies are the
    // same MHz values as CPUID16. The synthetic ARM64 CPU uses the nominal
    // 3GHz virtual profile, with no modeled idle states on either ISA.
    let (base, maximum) = match &c.t.cpu {
        WinCpu::X86(cpu, _) => {
            let (base, maximum, _, _) = cpu.vcpu().cpuid(0x16, 0);
            (base & 0xffff, maximum & 0xffff)
        }
        WinCpu::Arm64Ec(cpu) => {
            let (base, maximum, _, _) = cpu.x64().vcpu().cpuid(0x16, 0);
            (base & 0xffff, maximum & 0xffff)
        }
        WinCpu::Arm64(_) => (3000, 3000),
    };
    Ok([0, maximum, base, maximum, 0, 0])
}
