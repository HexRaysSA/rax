//! Measured NtTraceControl registration and configuration for dormant guest ETW.
use super::super::etw::valid_traits;
use super::query::{guard_result, probe_write};
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const SEND_BINARY_TRACKING_INFO: u32 = 26;
const USE_DESCRIPTOR_TYPE: u32 = 31;
const SEND_BINARY_TRACKING_INFO_CLASS_4: u32 = 47;

pub(super) fn control(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}
fn checked(c: &mut Ctx) -> ApiResult {
    let function = c.u32(0)?;
    let configures_provider = matches!(
        function,
        SEND_BINARY_TRACKING_INFO | USE_DESCRIPTOR_TYPE | SEND_BINARY_TRACKING_INFO_CLASS_4
    );
    let measured_caller =
        c.arch() == WinArch::Arm64 || (c.arch() == WinArch::X86 && c.p.wow64.is_some());
    if !matches!(function, 15 | 27 | 30)
        && !(configures_provider
            && measured_caller
            && c.p.native.as_ref().is_some_and(|native| {
                native.object_namespace.native_machine == Some(0xaa64)
                    && (
                        native.version.major,
                        native.version.minor,
                        native.version.build,
                    ) == (10, 0, 29708)
            }))
    {
        return Err(c.unsupported(format!("NtTraceControl function {function}")));
    }
    let (input, input_bytes, output, output_bytes, returned) =
        (c.ptr(1)?, c.u32(2)?, c.ptr(3)?, c.u32(4)?, c.ptr(5)?);
    // All four measured profiles ignore a NULL optional output, even with a
    // nonzero length. Nonempty non-NULL output is probed before ReturnLength.
    if output != 0 && output_bytes != 0 {
        probe_write(c, output, output_bytes as usize)?;
    }
    if returned == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    probe_write(c, returned, 4)?;
    if function == 15 {
        return register_provider(c, input, input_bytes, output, output_bytes, returned);
    }
    if function == 30 {
        return provider_traits(c, input, input_bytes, output, output_bytes, returned);
    }
    if configures_provider {
        return configure_provider(
            c,
            function,
            input,
            input_bytes,
            output != 0 && output_bytes != 0,
            returned,
        );
    }
    // The private input is exactly one ULONG in native64 as well as WoW64.
    // Length validation precedes capture; byte-aligned buffers are accepted.
    if input_bytes != 4 || input == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let handle = u64::from(c.mem().u32(input)?);
    if handle == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let Some(id) = c.p.objects.id(handle) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    if !matches!(c.p.objects.obj(id), Some(Object::Event { .. })) {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    if c.p.objects.access(handle).unwrap_or(0) & 2 == 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    let registered =
        c.p.objects
            .register_etw_event(id)
            .map_err(|message| ApiErr::Internal(message.into()))?;
    if !registered {
        return Flow::ret(STATUS_ALREADY_REGISTERED.into());
    }
    // Capture and publication precede this store, so input/output aliases
    // observe the zero only after the original handle has been retained.
    c.mem().w32(returned, 0)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn configure_provider(
    c: &mut Ctx,
    function: u32,
    input: u64,
    input_bytes: u32,
    has_output: bool,
    returned: u64,
) -> ApiResult {
    let uses_descriptor_type = function == USE_DESCRIPTOR_TYPE;
    if input == 0
        || input_bytes != if uses_descriptor_type { 16 } else { 8 }
        || (has_output && uses_descriptor_type)
    {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }

    let mut request = [0; 16];
    c.mem().rd(input, &mut request[..input_bytes as usize])?;
    let handle = u64::from_le_bytes(request[..8].try_into().unwrap());
    let (binary_tracking_class, descriptor_type) = match c.p.objects.get_mut(handle) {
        Some(Object::EtwRegistration {
            binary_tracking_class,
            descriptor_type,
            ..
        }) => (binary_tracking_class, descriptor_type),
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    };
    if uses_descriptor_type {
        // BOOLEAN is at byte 8. The seven trailing bytes are ignored.
        *descriptor_type = match request[8] {
            0 => Some(false),
            1 => Some(true),
            _ => return Flow::ret(STATUS_INVALID_PARAMETER.into()),
        };
    } else {
        // Installed EtwEventSetInformation selects operation 47 for class 4.
        *binary_tracking_class = Some(if function == SEND_BINARY_TRACKING_INFO {
            0
        } else {
            4
        });
    }
    // No payload is produced. ReturnLength can alias the captured input.
    c.mem().w32(returned, 0)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn register_provider(
    c: &mut Ctx,
    input: u64,
    input_bytes: u32,
    output: u64,
    output_bytes: u32,
    returned: u64,
) -> ApiResult {
    // Unlike function27, generic function15 capture reaches a nonempty input
    // span before class-specific size checks. NULL input is not read.
    if input != 0 && input_bytes != 0 {
        c.mem()
            .probe(input, input_bytes as usize, MemoryAccessKind::Read)
            .map_err(|fault| MemFault {
                addr: fault.address,
                write: false,
            })?;
    }
    if input == 0 || input_bytes != 160 || output == 0 || output_bytes < 160 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // Capture before any publication: output/ReturnLength may alias input.
    let bytes = c.mem().bytes(input, 160)?;
    let request: Box<[u8; 160]> = bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ApiErr::Internal("ETW registration capture width".into()))?;
    let mut reply = *request;
    let Some(handle) = c.p.objects.register_etw_provider(request) else {
        return Flow::ret(STATUS_NO_MEMORY.into());
    };
    reply[24..32].copy_from_slice(&u64::from(handle).to_le_bytes());
    reply[44..48].copy_from_slice(&160u32.to_le_bytes());
    // No guest tracing controller has enabled this dormant registration.
    reply[112..160].fill(0);
    // Full probes above guarantee stable writable spans. Preserve native copy
    // order, including ReturnLength overwriting a reply handle when aliased.
    if let Err(fault) = c.mem().wr(output, &reply) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    c.mem().w32(returned, 160)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn provider_traits(
    c: &mut Ctx,
    input: u64,
    input_bytes: u32,
    output: u64,
    output_bytes: u32,
    returned: u64,
) -> ApiResult {
    // Generic input capture follows destination probes, before class lengths.
    if input != 0 && input_bytes != 0 {
        c.mem()
            .probe(input, input_bytes as usize, MemoryAccessKind::Read)
            .map_err(|fault| MemFault {
                addr: fault.address,
                write: false,
            })?;
    }
    if input == 0 || input_bytes != 24 || output == 0 || output_bytes < 120 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // Both private handle and referenced pointer are 64-bit even in WoW64.
    let mut header = [0; 24];
    c.mem().rd(input, &mut header)?;
    let handle = u64::from_le_bytes(header[..8].try_into().unwrap());
    let pointer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let length = u16::from_le_bytes(header[16..18].try_into().unwrap()) as usize;
    // The six remaining header bytes are ignored by every measured profile.
    if pointer == 0 || length == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    match c.p.objects.get(handle) {
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
        Some(Object::EtwRegistration {
            traits: Some(_), ..
        }) => {
            return Flow::ret(STATUS_UNSUCCESSFUL.into());
        }
        Some(Object::EtwRegistration { traits: None, .. }) => {}
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
    }
    // Type and once-only state precede referenced-buffer access/guard faults.
    c.mem()
        .probe(pointer, length, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        return Flow::ret(STATUS_NO_MEMORY.into());
    }
    bytes.resize(length, 0);
    c.mem().rd(pointer, &mut bytes)?;
    if !valid_traits(&bytes) {
        return Flow::ret(STATUS_FILE_CORRUPT_ERROR.into());
    }
    let Some(Object::EtwRegistration { traits, .. }) = c.p.objects.get_mut(handle) else {
        return Err(ApiErr::Internal(
            "ETW registration changed during capture".into(),
        ));
    };
    // Capture before ReturnLength: it may alias the header or referenced blob.
    *traits = Some(bytes.into_boxed_slice());
    c.mem().w32(returned, 0)?;
    // The output buffer is probed but has no reply bytes in this dormant profile.
    Flow::ret(STATUS_SUCCESS.into())
}
