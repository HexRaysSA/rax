//! Selected synchronous controls on guest-owned device files.
//! Each device profile supplies its own request and reply layout.

use super::named_object::{Checked, finish_with, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use crate::user::windows::object_namespace::security_device::{
    CNG_DEVICE_TYPE, KSEC_DEVICE_TYPE, SecurityDevice,
};
use crate::user::windows::objects::Object;

const PROVIDER_CONTROL: u32 = 0x39_0400;
const ENTROPY_CONTROL: u32 = 0x39_0008;
const ENTROPY_BYTES: usize = 48;
const WATCH_BYTES: usize = 104;
const LOOKUP_BYTES: usize = 64;
const REPLY_BYTES: usize = 224;
const ABSENT: u64 = u64::MAX;

const WATCH_HEADER: [u64; 12] = [
    0x0001_0500_1a2b_3c4d,
    0,
    ABSENT,
    0,
    ABSENT,
    ABSENT,
    ABSENT,
    0,
    ABSENT,
    ABSENT,
    0,
    ABSENT,
];
const LOOKUP_HEADER: [u64; 6] = [
    0x0002_0000_1a2b_3c4d,
    ABSENT,
    0,
    0x30,
    ABSENT,
    0x0000_0002_0000_0001,
];

pub(super) fn control(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    finish_with(c, result, true)
}

fn checked(c: &mut Ctx) -> Checked<u32> {
    let handle = c.ptr(0)?;
    let code = c.u32(5)?;
    let device = match c.p.objects.get(handle) {
        Some(Object::SecurityFile(device)) => *device,
        Some(Object::GameOsXvcFile) => return super::gameos_xvc::control(c, code),
        Some(_) => {
            return Err(c
                .unsupported("NtDeviceIoControlFile object type is not selected")
                .into());
        }
        None => return status(STATUS_INVALID_HANDLE),
    };
    match device.device_type {
        KSEC_DEVICE_TYPE => provider(c, handle, device, code),
        CNG_DEVICE_TYPE => entropy(c, handle, device, code),
        _ => Err(c
            .unsupported("NtDeviceIoControlFile device identity is not selected")
            .into()),
    }
}

fn provider(c: &mut Ctx, handle: u64, device: SecurityDevice, code: u32) -> Checked<u32> {
    let sha256_profile =
        c.arch() == WinArch::Arm64 && device.kernel == (10, 0, 29708) && device.revision == 1003;
    let amd64_registration = c.arch() == WinArch::X64
        && (device.server_2022_profile() || super::super::gameos::enabled(c));
    if !(sha256_profile || amd64_registration)
        || code != PROVIDER_CONTROL
        || c.p.objects.file_mode(handle) != Some(0x20)
        || (c.ptr(1)?, c.ptr(2)?, c.ptr(3)?) != (0, 0, 0)
    {
        return Err(c
            .unsupported(format!(
                "NtDeviceIoControlFile KsecDD control {code:#x} is not selected"
            ))
            .into());
    }
    if c.p.objects.access(handle).unwrap_or(0) & 3 != 3 {
        return status(STATUS_ACCESS_DENIED);
    }

    let (io, input, input_len, output, output_len) = (
        c.ptr(4)?,
        c.ptr(6)?,
        c.u32(7)? as usize,
        c.ptr(8)?,
        c.u32(9)? as usize,
    );
    tracing::trace!(
        target: "rax::windows::ntstatus",
        pid = c.p.pid,
        input_len,
        output_len,
        "guest KsecDD provider request"
    );
    if (input_len, output_len) != (WATCH_BYTES, 8)
        && !(sha256_profile && (input_len, output_len) == (LOOKUP_BYTES, 384))
    {
        return Err(c
            .unsupported("KsecDD provider message sizes are not selected")
            .into());
    }
    probe_write(c, io, 16)?;
    probe_write(c, output, output_len)?;
    let mut request = [0; WATCH_BYTES];
    let request = &mut request[..input_len];
    c.mem().rd(input, request)?;

    let information = if input_len == WATCH_BYTES && words_match(request, &WATCH_HEADER) {
        let event = u64::from_le_bytes(request[96..].try_into().unwrap());
        register_event(c, handle, event)?;
        0
    } else if input_len == LOOKUP_BYTES && is_sha256_lookup(request) {
        c.mem().wr(output, &sha256_reply())?;
        REPLY_BYTES as u64
    } else {
        return Err(c
            .unsupported("KsecDD provider message is not selected")
            .into());
    };
    // Both destinations were probed before processing the buffered request.
    c.mem().w64(io, 0)?;
    c.mem().w64(io + 8, information)?;
    Ok(STATUS_SUCCESS)
}

fn entropy(c: &mut Ctx, handle: u64, device: SecurityDevice, code: u32) -> Checked<u32> {
    if c.arch() != WinArch::Arm64
        || !device.cng_profile()
        || code != ENTROPY_CONTROL
        || c.p.objects.file_mode(handle) != Some(0x20)
        || (c.ptr(1)?, c.ptr(2)?, c.ptr(3)?) != (0, 0, 0)
        || (c.ptr(6)?, c.u32(7)?, c.u32(9)? as usize) != (0, 0, ENTROPY_BYTES)
    {
        return Err(c.unsupported("CNG entropy request is not selected").into());
    }
    // The selected control is FILE_ANY_ACCESS. Native accepts a duplicate
    // of this device handle even when the duplicate has zero granted access.
    let (io, output) = (c.ptr(4)?, c.ptr(8)?);
    probe_write(c, io, 16)?;
    probe_write(c, output, ENTROPY_BYTES)?;

    // The process seed governs repeatable startup state. This request supplies
    // fresh entropy to the installed library independently of that seed.
    let mut bytes = [0u8; ENTROPY_BYTES];
    if crate::user::entropy::fill(&mut bytes).is_err() {
        return status(STATUS_UNSUCCESSFUL);
    }
    c.mem().wr(output, &bytes)?;
    c.mem().w64(io, 0)?;
    c.mem().w64(io + 8, ENTROPY_BYTES as u64)?;
    Ok(STATUS_SUCCESS)
}

fn register_event(c: &mut Ctx, file: u64, event: u64) -> Checked<()> {
    match c.p.objects.get(event) {
        Some(Object::Event { manual: false, .. }) => {}
        Some(Object::Event { .. }) => {
            return Err(c
                .unsupported("KsecDD provider event type is not selected")
                .into());
        }
        Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        None => return status(STATUS_INVALID_HANDLE),
    }
    if c.p.objects.access(event).unwrap_or(0) & 2 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    let id = c.p.objects.id(event).expect("validated event");
    let state = c.p.objects.file_state(file).expect("validated KsecDD file");
    if let Some(registered) = state.security_provider_event {
        return if registered == id {
            Ok(())
        } else {
            Err(c
                .unsupported("replacing a KsecDD provider event is not selected")
                .into())
        };
    }
    if c.p.objects.retain_many(&[id]).is_err() {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    }
    c.p.objects
        .file_state_mut(file)
        .expect("validated KsecDD file")
        .security_provider_event = Some(id);
    Ok(())
}

fn words_match(request: &[u8], words: &[u64]) -> bool {
    request
        .get(..std::mem::size_of_val(words))
        .is_some_and(|prefix| {
            prefix
                .chunks_exact(8)
                .zip(words)
                .all(|(bytes, word)| bytes == word.to_le_bytes())
        })
}

fn is_sha256_lookup(request: &[u8]) -> bool {
    let mut function = [0; 16];
    put_utf16(&mut function, "SHA256");
    words_match(request, &LOOKUP_HEADER) && request[48..] == function
}

fn sha256_reply() -> [u8; REPLY_BYTES] {
    let mut reply = [0; REPLY_BYTES];
    // The buffered transport uses offsets from the start of the reply.
    // It carries one provider reference with one user-mode image.
    reply[..4].copy_from_slice(&1u32.to_le_bytes());
    reply[4..8].copy_from_slice(&0x0002_0000u32.to_le_bytes());
    for (at, value) in [
        (0x08, 0x10),   // reference array
        (0x10, 0x18),   // reference
        (0x18, 2),      // BCRYPT_HASH_INTERFACE
        (0x20, 0x50),   // algorithm name
        (0x28, 0x60),   // provider name
        (0x38, ABSENT), // property array
        (0x40, 0xa0),   // user-mode image
        (0x48, ABSENT), // kernel-mode image
        (0xa0, 0xb0),   // user-mode image name
        (0xa8, 1),      // image flags
    ] {
        reply[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    put_utf16(&mut reply[0x50..0x60], "SHA256");
    put_utf16(&mut reply[0x60..0xa0], "Microsoft Primitive Provider");
    put_utf16(&mut reply[0xb0..], "bcryptprimitives.dll");
    reply
}

fn put_utf16(destination: &mut [u8], value: &str) {
    for (pair, unit) in destination.chunks_exact_mut(2).zip(value.encode_utf16()) {
        pair.copy_from_slice(&unit.to_le_bytes());
    }
}
