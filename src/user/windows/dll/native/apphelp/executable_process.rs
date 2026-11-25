//! Stock executable cache replies captured through `BasepQueryAppCompat`.

use super::{number, pointer};
use crate::user::windows::appcompat::{EXECUTABLE_REPLY_CAPACITY, EXECUTABLE_REPLY_GROUP};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};
use crate::user::windows::objects::Object;
use crate::user::windows::registry::RegistryView;

const NATIVE_PACKET_BYTES: usize = 392;
const NATIVE_IMAGE_HANDLE: usize = 0x18;
const WOW64_IMAGE_HANDLE: usize = 0x10;
const MAX_NAME_BYTES: usize = 512;

const STOCK_TERMINATOR: [u32; 2] = [1, 0];
const GROUP_BYTES: usize = EXECUTABLE_REPLY_GROUP.len() * 4;

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
                            | (WinArch::Arm64, Some(0xaa64), 26200)
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
    let windows_11_arm = native.version.build == 26200;
    let input = c.ptr(1)?;
    c.mem().rd(input, &mut packet[..packet_bytes])?;
    let flags = number(&packet, 4);
    let arm_29708_file_flags =
        arch == WinArch::Arm64 && native.version.build == 29708 && matches!(flags, 0x14 | 0x34);
    // Closed process creation can set bit 2. The stock WoW64 CMD replies
    // match the replies for 0x10 and 0x30 on the captured ARM64 build.
    let wow_29708 = wow && native.version.build == 29708;
    let request_flags = if arch == WinArch::X64 || windows_11_arm || wow_29708 {
        flags & !0x04
    } else {
        flags
    };
    let supported_flags = if arch == WinArch::X64 {
        request_flags == 0x30
    } else {
        matches!(request_flags, 0x10 | 0x30) || arm_29708_file_flags
    };
    let mask = number(&packet, 0);
    let output_capacity = number(&packet, output_size_at);
    if mask != 0x1f || !supported_flags || output_capacity as usize != EXECUTABLE_REPLY_CAPACITY {
        tracing::trace!(
            target: "rax::windows::ntstatus",
            pid = c.p.pid,
            arch = ?arch,
            build = native.version.build,
            mask = %format_args!("{mask:#010x}"),
            flags = %format_args!("{flags:#010x}"),
            output_capacity,
            "guest AppHelp executable-cache request outside captured profile"
        );
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
    #[cfg(all(windows, target_arch = "aarch64"))]
    {
        let handle = pointer(&packet, NATIVE_IMAGE_HANDLE, false);
        if native.supports_installed_apphelp(arch) && c.p.objects.runtime_library(handle) {
            let reply = query_installed(c, native, handle, &path, &name, flags)?;
            let output = pointer(&packet, output_buffer_at, false);
            return publish(
                c,
                input,
                packet_bytes,
                output_size_at,
                output,
                reply.as_bytes(),
            );
        }
    }
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
        let images: &[_] = if arm_29708_file_flags {
            &["cmd.exe", "findstr.exe"]
        } else if arch == WinArch::X64 || windows_11_arm {
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
    if arm_29708_file_flags {
        let handle = pointer(&packet, NATIVE_IMAGE_HANDLE, false);
        let file = match c.p.objects.get(handle) {
            Some(Object::File(file)) => file,
            None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
            _ => return Err(c.unsupported("AppHelp executable-cache image handle is not a file")),
        };
        let opened_path = file.path.strip_prefix(r"\??\").unwrap_or(&file.path);
        if file.directory || file.null || !opened_path.eq_ignore_ascii_case(&path) {
            return Err(c.unsupported(
                "AppHelp executable-cache image handle is outside the captured profile",
            ));
        }
    }

    let groups = if windows_11_arm { 3 } else { 1 };
    let mut record = [0; 3 * GROUP_BYTES + STOCK_TERMINATOR.len() * 4];
    let record = &mut record[..groups * GROUP_BYTES + STOCK_TERMINATOR.len() * 4];
    let words = EXECUTABLE_REPLY_GROUP
        .into_iter()
        .cycle()
        .take(groups * EXECUTABLE_REPLY_GROUP.len())
        .chain(STOCK_TERMINATOR);
    for (slot, value) in record.chunks_exact_mut(4).zip(words) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let destination = pointer(&packet, output_buffer_at, wow);
    publish(c, input, packet_bytes, output_size_at, destination, record)
}

#[cfg(all(windows, target_arch = "aarch64"))]
fn query_installed(
    c: &Ctx<'_>,
    native: &crate::user::windows::native::NativeRuntime,
    handle: u64,
    path: &str,
    name: &[u16],
    flags: u32,
) -> Result<crate::user::windows::appcompat::ExecutableReply, crate::user::windows::hle::ApiErr> {
    use crate::user::windows::appcompat::query_executable;
    use crate::user::windows::fs::FileNameOrigin;

    let invalid_file =
        || c.unsupported("AppHelp handle does not name the selected installed executable");
    let Some(Object::File(file)) = c.p.objects.get(handle) else {
        return Err(invalid_file());
    };
    let host = file
        .host
        .as_ref()
        .filter(|_| !file.directory && !file.null)
        .ok_or_else(invalid_file)?;
    let (directory, basename) = path.rsplit_once('\\').ok_or_else(invalid_file)?;
    if !directory.eq_ignore_ascii_case(native.guest_directory.trim_end_matches('\\'))
        || !native.admits_child_executable(c.arch(), basename)
        || !c
            .p
            .registry
            .creator_compat_layer_absent(name, RegistryView::Native64)
    {
        return Err(invalid_file());
    }

    let scope = FileNameOrigin::capture(&native.directory, Vec::new()).map_err(|error| {
        c.unsupported(format!("AppHelp installed executable naming root: {error}"))
    })?;
    let retained = scope.name(host, &file.host_path).map_err(|error| {
        c.unsupported(format!("AppHelp installed executable identity: {error}"))
    })?;
    let requested: Vec<_> = std::iter::once(u16::from(b'\\'))
        .chain(basename.encode_utf16())
        .collect();
    if !super::super::file_attributes::path::equal(c, &retained, &requested) {
        return Err(invalid_file());
    }
    query_executable(host, path, flags)
        .map_err(|error| c.unsupported(format!("AppHelp installed executable policy: {error}")))
}

fn publish(
    c: &mut Ctx<'_>,
    input: u64,
    packet_bytes: usize,
    output_size_at: usize,
    destination: u64,
    record: &[u8],
) -> ApiResult {
    let size = input + output_size_at as u64;
    if destination < input + packet_bytes as u64
        && input < destination.saturating_add(record.len() as u64)
    {
        return Err(c.unsupported("AppHelp executable-cache outputs overlap the request"));
    }
    super::super::query::probe_write(c, destination, record.len())?;
    super::super::query::probe_write(c, size, 4)?;
    c.mem().wr(destination, record)?;
    c.mem().w32(size, record.len() as u32)?;
    Flow::ret(STATUS_SUCCESS.into())
}
