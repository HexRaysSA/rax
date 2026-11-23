//! Stock executable cache replies captured through `BasepQueryAppCompat`.

use super::{number, pointer};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};
use crate::user::windows::objects::Object;
use crate::user::windows::registry::RegistryView;

const NATIVE_PACKET_BYTES: usize = 392;
const WOW64_IMAGE_HANDLE: usize = 0x10;
const INITIAL_CAPACITY: u32 = 4096;
const MAX_NAME_BYTES: usize = 512;

// Each item has a u32 type and byte length, followed by its payload.
// The three eight-byte payloads are zero in the observed stock replies.
const STOCK_RECORD: [u32; 16] = [2, 0, 8, 8, 0, 0, 4, 8, 0, 0, 16, 8, 0, 0, 1, 0];

pub(super) fn lookup(c: &mut Ctx<'_>) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    let (packet_bytes, name_length_at, name_buffer_at, output_buffer_at, output_size_at) = if wow {
        (204, 0x1c, 0x20, 0xc4, 0xc8)
    } else {
        (NATIVE_PACKET_BYTES, 0x30, 0x38, 0x178, 0x180)
    };
    let arch = c.arch();
    let native =
        c.p.native
            .as_ref()
            .filter(|native| {
                (native.version.major, native.version.minor) == (10, 0)
                    && matches!(
                        (
                            arch,
                            native.object_namespace.native_machine,
                            native.version.build
                        ),
                        (WinArch::X86 | WinArch::Arm64, Some(0xaa64), 29708)
                            | (WinArch::X64, Some(0x8664), 20348 | 26100)
                    )
            })
            .ok_or_else(|| c.unsupported("AppHelp executable-cache profile is not captured"));
    let mut packet = [0; NATIVE_PACKET_BYTES];
    if native.is_err()
        && tracing::enabled!(target: "rax::windows::ntstatus", tracing::Level::TRACE)
        && let Ok(input) = c.ptr(1)
        && c.mem().rd(input, &mut packet[..packet_bytes]).is_ok()
    {
        tracing::trace!(
            target: "rax::windows::ntstatus",
            pid = c.p.pid,
            arch = ?c.arch(),
            mask = %format_args!("{:#010x}", number(&packet, 0)),
            flags = %format_args!("{:#010x}", number(&packet, 4)),
            name_bytes = u16::from_le_bytes([packet[name_length_at], packet[name_length_at + 1]]),
            output_capacity = number(&packet, output_size_at),
            "guest AppHelp executable-cache lookup outside captured profile"
        );
    }
    let native = native?;
    let input = c.ptr(1)?;
    c.mem().rd(input, &mut packet[..packet_bytes])?;
    let flags = number(&packet, 4);
    let supported_flags = if arch == WinArch::X64 {
        // Hosted Server CMD supplied 0x30. Closed CMD reached the same
        // installed lookup with bit 2 set.
        matches!(flags, 0x30 | 0x34)
    } else {
        matches!(flags, 0x10 | 0x30)
    };
    if number(&packet, 0) != 0x1f
        || !supported_flags
        || number(&packet, output_size_at) != INITIAL_CAPACITY
    {
        return Err(
            c.unsupported("AppHelp executable-cache request is outside the captured profile")
        );
    }

    let name_length = usize::from(u16::from_le_bytes(
        packet[name_length_at..name_length_at + 2]
            .try_into()
            .unwrap(),
    ));
    if name_length == 0 || name_length > MAX_NAME_BYTES || name_length % 2 != 0 {
        return Err(c.unsupported("AppHelp executable-cache name is outside the captured profile"));
    }
    let mut bytes = [0; MAX_NAME_BYTES];
    c.mem().rd(
        pointer(&packet, name_buffer_at, wow),
        &mut bytes[..name_length],
    )?;
    let name: Vec<_> = bytes[..name_length]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let path = String::from_utf16(&name)
        .map_err(|_| c.unsupported("AppHelp executable-cache name is not a Windows path"))?;
    let directory = native.guest_directory.trim_end_matches('\\');
    let captured = if wow {
        let windows = native.guest_root.trim_end_matches('\\');
        let names = [
            format!("{directory}\\cmd.exe"),
            format!("{windows}\\System32\\cmd.exe"),
        ];
        let stock_cmd = |path: &str| names.iter().any(|name| path.eq_ignore_ascii_case(name));
        if !stock_cmd(&path) {
            return Err(
                c.unsupported("AppHelp executable-cache result is not captured for this image")
            );
        }
        let file = match c
            .p
            .objects
            .get(u64::from(number(&packet, WOW64_IMAGE_HANDLE)))
        {
            Some(Object::File(file)) => file,
            None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
            _ => return Err(c.unsupported("AppHelp executable-cache image handle is not a file")),
        };
        let opened_path = file.path.strip_prefix(r"\??\").unwrap_or(&file.path);
        !file.directory
            && !file.null
            && stock_cmd(opened_path)
            && names.iter().all(|name| {
                let units: Vec<_> = name.encode_utf16().collect();
                [RegistryView::Native64, RegistryView::Wow32]
                    .into_iter()
                    .all(|view| c.p.registry.creator_compat_layer_absent(&units, view))
            })
    } else {
        let images: &[_] = if arch == WinArch::X64 {
            &["cmd.exe"]
        } else {
            &[
                "cmd.exe",
                "where.exe",
                "findstr.exe",
                "sort.exe",
                "find.exe",
            ]
        };
        images
            .iter()
            .any(|image| path.eq_ignore_ascii_case(&format!("{directory}\\{image}")))
            && c.p
                .registry
                .creator_compat_layer_absent(&name, RegistryView::Native64)
    };
    if !captured {
        return Err(c.unsupported("AppHelp executable-cache result is not captured for this image"));
    }

    let mut record = [0; 64];
    for (slot, value) in record.chunks_exact_mut(4).zip(STOCK_RECORD) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let destination = pointer(&packet, output_buffer_at, wow);
    let size = input + output_size_at as u64;
    if destination < input + packet_bytes as u64
        && input < destination.saturating_add(record.len() as u64)
    {
        return Err(c.unsupported("AppHelp executable-cache outputs overlap the request"));
    }
    super::super::query::probe_write(c, destination, record.len())?;
    super::super::query::probe_write(c, size, 4)?;
    c.mem().wr(destination, &record)?;
    c.mem().w32(size, record.len() as u32)?;
    Flow::ret(STATUS_SUCCESS.into())
}
