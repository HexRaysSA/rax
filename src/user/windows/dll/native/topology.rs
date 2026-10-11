//! Extended system query for the modeled single-processor group and NUMA node.
//!
//! Class 107 and its six-argument signature are pinned in PHNT; the public
//! group layout is SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX. Probe/conversion
//! ordering is a Windows 10.0.29683.1000 observation, retained with native
//! originals in `docs/specifications/windows/native-processor-groups/` and
//! `docs/specifications/windows/native-numa-node/`.

use super::query::{guard_result, probe_write, return_length};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER,
};

const SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION: u32 = 107;
const RELATION_NUMA_NODE: u32 = 1;
const RELATION_GROUP: u32 = 4;
const RELATION_NUMA_NODE_EX: u32 = 6;

fn user_span(c: &Ctx, address: u64, bytes: u32) -> bool {
    address
        .checked_add(u64::from(bytes))
        .is_some_and(|end| end <= c.p.vm.high())
}

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    guard_result(c, result)
}

fn query(c: &mut Ctx) -> ApiResult {
    let (class, input, input_bytes, output, output_bytes, returned) = (
        c.u32(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    // This entry rejects absent input before any destination probe. A short,
    // nonempty input still requires ULONG alignment; its pages are not read.
    if input == 0 || input_bytes == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if input % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if c.arch() != WinArch::X86 {
        // ProbeForRead's address-range check does not touch input pages. The
        // WoW64 wrapper captures only the relationship DWORD, including when
        // the supplied input length is ULONG_MAX.
        if !user_span(c, input, input_bytes) {
            // No input page was touched, so a guard at its first byte must
            // remain armed. Returning a memory fault would consume that guard.
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
        if output_bytes != 0 {
            if output % 4 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            if !user_span(c, output, output_bytes) {
                return Flow::ret(STATUS_ACCESS_VIOLATION.into());
            }
            probe_write(c, output, output_bytes as usize)?;
        }
        if returned != 0 {
            // ReturnLength is touched directly. A first-page guard wins even
            // when the four-byte store crosses the user-address limit.
            probe_write(c, returned, 4)?;
        }
    }
    if class != SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION {
        return Err(c.unsupported(format!("NtQuerySystemInformationEx class {class}")));
    }
    if input_bytes < 4 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // Capture before output/ReturnLength writes, including input aliases.
    let relationship = c.mem().u32(input)?;
    match relationship {
        RELATION_GROUP => group(c, output, output_bytes, returned),
        RELATION_NUMA_NODE | RELATION_NUMA_NODE_EX => numa_node(c, output, output_bytes, returned),
        _ => Err(c.unsupported(format!(
            "NtQuerySystemInformationEx class {class} relationship {relationship}"
        ))),
    }
}

fn numa_node(c: &mut Ctx, output: u64, output_bytes: u32, returned: u64) -> ApiResult {
    let required: u32 = if c.arch() == WinArch::X86 { 44 } else { 48 };
    if output_bytes < required {
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // Both requests return RelationNumaNode. A single group agrees with the
    // existing group query, class55 affinity and PEB processor count.
    if c.arch() == WinArch::X86 {
        // The matching installed WoW64 converter publishes these fields in
        // this order, including the initially zero 12-byte GROUP_AFFINITY.
        // Preserve partial writes on page faults; header/length come last.
        c.mem().w32(output + 8, 0)?;
        c.mem().wr(output + 12, &[0; 16])?;
        c.mem().w16(output + 28, 0)?;
        c.mem().w16(output + 30, 1)?;
        c.mem().w64(output + 32, 0)?;
        c.mem().w32(output + 40, 0)?;
        c.mem().w16(output + 36, 0)?;
        c.mem().w32(output + 32, 1)?;
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&RELATION_NUMA_NODE.to_le_bytes());
        header[4..].copy_from_slice(&required.to_le_bytes());
        c.mem().wr(output, &header)?;
    } else {
        let mut data = [0u8; 48];
        data[..4].copy_from_slice(&RELATION_NUMA_NODE.to_le_bytes());
        data[4..8].copy_from_slice(&required.to_le_bytes());
        data[30..32].copy_from_slice(&1u16.to_le_bytes());
        data[32] = 1;
        c.mem().wr(output, &data)?;
    }
    return_length(c, returned, required)?;
    Flow::ret(0)
}

fn group(c: &mut Ctx, output: u64, output_bytes: u32, returned: u64) -> ApiResult {
    let required = if c.arch() == WinArch::X86 { 76 } else { 80 };
    if output_bytes < required {
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // One guest CPU agrees with PEB.NumberOfProcessors and the existing
    // SystemBasicInformation active mask. Host counts/affinity are not copied.
    if c.arch() == WinArch::X86 {
        // Recorded WoW64 conversion order. Separate writes retain precisely
        // the observed partial publication when the next guest page faults.
        c.mem().w32(output + 8, 0x0001_0001)?;
        c.mem().wr(output + 12, &[0; 16])?;
        c.mem().w32(output + 28, 0)?;
        c.mem().w8(output + 32, 1)?;
        c.mem().w8(output + 33, 1)?;
        c.mem().w32(output + 72, 1)?;
        c.mem().wr(output + 34, &[0; 38])?;
        c.mem().w32(output, RELATION_GROUP)?;
        c.mem().w32(output + 4, required)?;
    } else {
        let mut data = [0u8; 80];
        data[..4].copy_from_slice(&RELATION_GROUP.to_le_bytes());
        data[4..8].copy_from_slice(&required.to_le_bytes());
        data[8..12].copy_from_slice(&[1, 0, 1, 0]);
        data[32..34].copy_from_slice(&[1, 1]);
        data[72] = 1;
        c.mem().wr(output, &data)?;
    }
    return_length(c, returned, required)?;
    Flow::ret(0)
}
