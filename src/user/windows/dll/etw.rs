//! Portable ETW provider exports. Registrations belong to the guest process.
//! No session enables a provider in this profile.

use super::super::hle::{
    ApiResult,
    Arg::{I32, I64, Ptr},
    Conv::{Stdcall, Variadic},
    Ctx, Export, Flow,
};
use super::super::memory::{Mem, MemFault};
use super::super::nt::error::{
    ERROR_FILE_CORRUPT, ERROR_GEN_FAILURE, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED,
};
use super::super::objects::Object;
use crate::error::MemoryAccessKind;

pub(super) static NTDLL_EXPORTS: &[Export] = &[
    Export::func("EtwEventRegister", Stdcall, &[Ptr, Ptr, Ptr, Ptr], register),
    Export::func("EtwEventUnregister", Stdcall, &[I64], unregister),
    Export::func(
        "EtwEventSetInformation",
        Stdcall,
        &[I64, I32, Ptr, I32],
        set_information,
    ),
    Export::func("EtwEventEnabled", Stdcall, &[I64, Ptr], enabled),
    Export::func(
        "EtwEventProviderEnabled",
        Stdcall,
        &[I64, I32, I64],
        enabled,
    ),
    Export::func("EtwEventWrite", Stdcall, &[I64, Ptr, I32, Ptr], write),
    Export::func(
        "EtwEventWriteEx",
        Stdcall,
        &[I64, Ptr, I64, I32, Ptr, Ptr, I32, Ptr],
        write,
    ),
    Export::func(
        "EtwEventWriteTransfer",
        Stdcall,
        &[I64, Ptr, Ptr, Ptr, I32, Ptr],
        write,
    ),
    Export::func("EtwEventWriteString", Stdcall, &[I64, I32, I64, Ptr], write),
    Export::func(
        "EtwEventWriteStartScenario",
        Stdcall,
        &[I64, Ptr, I32, Ptr],
        write,
    ),
    Export::func(
        "EtwEventWriteEndScenario",
        Stdcall,
        &[I64, Ptr, I32, Ptr],
        write,
    ),
    Export::func(
        "EtwEventActivityIdControl",
        Stdcall,
        &[I32, Ptr],
        activity_id_control,
    ),
    Export::func("EtwCreateTraceInstanceId", Stdcall, &[Ptr, Ptr], dormant),
    Export::func(
        "EtwTraceEventInstance",
        Stdcall,
        &[I64, Ptr, Ptr, Ptr],
        dormant,
    ),
    Export::func(
        "EtwRegisterTraceGuidsW",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, Ptr, Ptr, Ptr, Ptr],
        register_classic,
    ),
    Export::func(
        "EtwRegisterTraceGuidsA",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, Ptr, Ptr, Ptr, Ptr],
        register_classic,
    ),
    Export::func("EtwUnregisterTraceGuids", Stdcall, &[I64], dormant),
    Export::func("EtwLogTraceEvent", Stdcall, &[I64, Ptr], dormant),
    Export::func("EtwTraceMessage", Variadic, &[I64, I32, Ptr, I32], dormant),
    Export::func(
        "EtwTraceMessageVa",
        Stdcall,
        &[I64, I32, Ptr, I32, Ptr],
        dormant,
    ),
    Export::func("EtwGetTraceEnableFlags", Stdcall, &[I64], dormant),
    Export::func("EtwGetTraceEnableLevel", Stdcall, &[I64], dormant),
    Export::func("EtwGetTraceLoggerHandle", Stdcall, &[Ptr], logger_handle),
];

pub(super) static SQM_EXPORTS: &[Export] = &[Export::func("WinSqmIsOptedIn", Stdcall, &[], |_| {
    Flow::bool(false)
})];

pub(super) static KERNEL_FORWARDS: &[Export] = &[
    Export::forward("EventRegister", "NTDLL.EtwEventRegister"),
    Export::forward("EventUnregister", "NTDLL.EtwEventUnregister"),
    Export::forward("EventSetInformation", "NTDLL.EtwEventSetInformation"),
    Export::forward("EventEnabled", "NTDLL.EtwEventEnabled"),
    Export::forward("EventProviderEnabled", "NTDLL.EtwEventProviderEnabled"),
    Export::forward("EventWrite", "NTDLL.EtwEventWrite"),
    Export::forward("EventWriteEx", "NTDLL.EtwEventWriteEx"),
    Export::forward("EventWriteTransfer", "NTDLL.EtwEventWriteTransfer"),
    Export::forward("EventWriteString", "NTDLL.EtwEventWriteString"),
    Export::forward(
        "EventWriteStartScenario",
        "NTDLL.EtwEventWriteStartScenario",
    ),
    Export::forward("EventWriteEndScenario", "NTDLL.EtwEventWriteEndScenario"),
    Export::forward("EventActivityIdControl", "NTDLL.EtwEventActivityIdControl"),
    Export::forward("CreateTraceInstanceId", "NTDLL.EtwCreateTraceInstanceId"),
    Export::forward("TraceEventInstance", "NTDLL.EtwTraceEventInstance"),
    Export::forward("RegisterTraceGuidsW", "NTDLL.EtwRegisterTraceGuidsW"),
    Export::forward("RegisterTraceGuidsA", "NTDLL.EtwRegisterTraceGuidsA"),
    Export::forward("UnregisterTraceGuids", "NTDLL.EtwUnregisterTraceGuids"),
    Export::forward("TraceEvent", "NTDLL.EtwLogTraceEvent"),
    Export::forward("TraceMessage", "NTDLL.EtwTraceMessage"),
    Export::forward("TraceMessageVa", "NTDLL.EtwTraceMessageVa"),
    Export::forward("GetTraceEnableFlags", "NTDLL.EtwGetTraceEnableFlags"),
    Export::forward("GetTraceEnableLevel", "NTDLL.EtwGetTraceEnableLevel"),
    Export::forward("GetTraceLoggerHandle", "NTDLL.EtwGetTraceLoggerHandle"),
];

fn probe_output(c: &Ctx, output: u64, bytes: usize) -> Result<(), MemFault> {
    c.mem()
        .probe(output, bytes, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}

fn register(c: &mut Ctx) -> ApiResult {
    let guid = c.ptr(0)?;
    if guid == 0 {
        return Flow::ret(ERROR_INVALID_PARAMETER.into());
    }
    let output = c.ptr(3)?;
    probe_output(c, output, 8)?;
    // Output can overlap the GUID. Capture before publishing the registration.
    let mut request = Box::new([0; 160]);
    c.mem().rd(guid, &mut request[..16])?;
    let Some(handle) = c.p.objects.register_etw_provider(request) else {
        return Flow::ret(ERROR_NOT_ENOUGH_MEMORY.into());
    };
    let handle = u64::from(handle);
    if let Err(fault) = c.mem().w64(output, handle) {
        let _ = c.p.objects.close(handle);
        return Err(fault.into());
    }
    Flow::ret(0)
}

fn is_registration(c: &Ctx, handle: u64) -> bool {
    matches!(
        c.p.objects.get(handle),
        Some(Object::EtwRegistration { .. })
    )
}

fn unregister(c: &mut Ctx) -> ApiResult {
    let handle = c.arg(0)?;
    if !is_registration(c, handle) || c.p.objects.close(handle).is_err() {
        return Flow::ret(ERROR_INVALID_HANDLE.into());
    }
    Flow::ret(0)
}

fn set_information(c: &mut Ctx) -> ApiResult {
    let (handle, class, info, length) = (c.arg(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?);
    let Some(Object::EtwRegistration {
        traits,
        binary_tracking_class,
        descriptor_type,
        ..
    }) = c.p.objects.get_mut(handle)
    else {
        return Flow::ret(ERROR_INVALID_HANDLE.into());
    };
    match class {
        0 if length == 0 => *binary_tracking_class = Some(0),
        2 if info != 0 && (3..=u32::from(u16::MAX)).contains(&length) => {
            if traits.is_some() {
                return Flow::ret(ERROR_GEN_FAILURE.into());
            }
            let bytes = c.p.space.bytes(info, length as usize)?;
            if !valid_traits(&bytes) {
                return Flow::ret(ERROR_FILE_CORRUPT.into());
            }
            *traits = Some(bytes.into_boxed_slice());
        }
        3 if info != 0 && length == 1 => {
            *descriptor_type = match c.p.space.u8(info)? {
                0 => Some(false),
                1 => Some(true),
                _ => return Flow::ret(ERROR_INVALID_PARAMETER.into()),
            };
        }
        0 | 2 | 3 => return Flow::ret(ERROR_INVALID_PARAMETER.into()),
        _ => return Flow::ret(ERROR_NOT_SUPPORTED.into()),
    }
    Flow::ret(0)
}

fn enabled(c: &mut Ctx) -> ApiResult {
    // Both an unknown handle and a dormant registration report FALSE.
    let _handle = c.arg(0)?;
    Flow::bool(false)
}

fn write(c: &mut Ctx) -> ApiResult {
    if is_registration(c, c.arg(0)?) {
        Flow::ret(0)
    } else {
        Flow::ret(ERROR_INVALID_HANDLE.into())
    }
}

fn activity_id_control(c: &mut Ctx) -> ApiResult {
    const EVENT_ACTIVITY_CTRL_GET_ID: u32 = 1;
    if c.u32(0)? == EVENT_ACTIVITY_CTRL_GET_ID {
        let output = c.ptr(1)?;
        probe_output(c, output, 16)?;
        c.mem().wr(output, &[0; 16])?;
    }
    Flow::ret(0)
}

fn register_classic(c: &mut Ctx) -> ApiResult {
    let output = c.ptr(7)?;
    probe_output(c, output, 8)?;
    c.mem().w64(output, 0)?;
    Flow::ret(0)
}

fn dormant(_: &mut Ctx) -> ApiResult {
    Flow::ret(0)
}

fn logger_handle(_: &mut Ctx) -> ApiResult {
    Flow::ret64(0)
}

/// Bounded native structural parser, O(T) time and O(1) auxiliary space.
/// Names remain bytes: the installed kernel does not validate UTF-8 here.
pub(super) fn valid_traits(bytes: &[u8]) -> bool {
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) as usize != bytes.len() {
        return false;
    }
    let Some(name_end) = bytes[2..].iter().position(|&b| b == 0) else {
        return false;
    };
    let mut at = name_end + 3;
    while at < bytes.len() {
        if bytes.len() - at < 3 {
            return false;
        }
        let record = u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize;
        if record < 3 || record > bytes.len() - at {
            return false;
        }
        // Known and unknown record types retain their original bytes.
        at += record;
    }
    true
}

#[cfg(test)]
mod tests;
