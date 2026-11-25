use super::{Catalog, invalid};
use std::ffi::c_void;
use std::io;
use std::path::Path;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtApphelpCacheControl(operation: u32, context: *mut c_void) -> i32;
}

#[repr(align(16))]
struct Packet([u8; 512]);

fn lookup(name: &[u16]) -> io::Result<u32> {
    const SENTINEL: u32 = 0xa5a5_a5a5;
    // The offsets describe the ABI of this host process.
    let width = size_of::<usize>();
    let (name_at, output_at) = if width == 8 { (248, 376) } else { (132, 196) };
    let text: Vec<_> = name.iter().copied().chain([0]).collect();
    let length = u16::try_from(name.len() * 2)
        .map_err(|_| invalid("installed AppCompat name length exceeds u16"))?;
    let limit = length
        .checked_add(2)
        .ok_or_else(|| invalid("installed AppCompat name capacity exceeds u16"))?;
    let mut packet = Packet([0; 512]);
    packet.0[name_at..name_at + 2].copy_from_slice(&length.to_le_bytes());
    packet.0[name_at + 2..name_at + 4].copy_from_slice(&limit.to_le_bytes());
    packet.0[name_at + width..name_at + width * 2]
        .copy_from_slice(&(text.as_ptr() as usize).to_le_bytes());
    let mut output = SENTINEL;
    packet.0[output_at..output_at + width]
        .copy_from_slice(&((&mut output as *mut u32) as usize).to_le_bytes());
    packet.0[output_at + width..output_at + width + 4].copy_from_slice(&4u32.to_le_bytes());
    // SAFETY: all addresses belong to this capture, the counted name and
    // aligned output live for the whole call, and operation 6 reads name flags.
    let status = unsafe { NtApphelpCacheControl(6, packet.0.as_mut_ptr().cast()) };
    if status != 0 || output == SENTINEL {
        return Err(invalid(&format!(
            "installed AppCompat name query failed ({status:#010x})"
        )));
    }
    Ok(output)
}

impl Catalog {
    pub(crate) fn with_native_lookup(self, root: &Path) -> io::Result<Self> {
        self.with_installed_lookup(root, lookup)
    }
}

/// Query a retained installed file using a host-owned operation 11 packet.
#[cfg(target_arch = "aarch64")]
pub(crate) fn query_executable(
    file: &std::fs::File,
    path: &str,
    flags: u32,
) -> io::Result<super::executable::ExecutableReply> {
    use super::{EXECUTABLE_REPLY_CAPACITY, executable::ExecutableReply};
    use std::os::windows::io::AsRawHandle;

    if !matches!(flags, 0x10 | 0x14 | 0x30 | 0x34) || path.contains('\0') {
        return Err(invalid(
            "installed executable AppHelp query is outside the native profile",
        ));
    }
    let text: Vec<_> = path.encode_utf16().chain([0]).collect();
    let maximum = u16::try_from(text.len() * 2)
        .map_err(|_| invalid("installed executable AppHelp path exceeds u16"))?;
    let length = maximum - 2;
    let mut packet = Packet([0; 512]);
    let mut output = [0xa5; EXECUTABLE_REPLY_CAPACITY];
    packet.0[0..4].copy_from_slice(&0x1fu32.to_le_bytes());
    packet.0[4..8].copy_from_slice(&flags.to_le_bytes());
    packet.0[0x18..0x20].copy_from_slice(&(file.as_raw_handle() as usize).to_le_bytes());
    packet.0[0x30..0x32].copy_from_slice(&length.to_le_bytes());
    packet.0[0x32..0x34].copy_from_slice(&maximum.to_le_bytes());
    packet.0[0x38..0x40].copy_from_slice(&(text.as_ptr() as usize).to_le_bytes());
    packet.0[0x178..0x180].copy_from_slice(&(output.as_mut_ptr() as usize).to_le_bytes());
    packet.0[0x180..0x184].copy_from_slice(&(EXECUTABLE_REPLY_CAPACITY as u32).to_le_bytes());

    // SAFETY: the packet is aligned and describes only live host-owned
    // buffers and a borrowed read-only installed file. The caller checks the
    // host build, machine, matching file identity and known operation shape.
    let status = unsafe { NtApphelpCacheControl(11, packet.0.as_mut_ptr().cast()) };
    if status != 0 {
        return Err(invalid(&format!(
            "installed executable AppHelp query failed ({status:#010x})"
        )));
    }
    let written = u32::from_le_bytes(packet.0[0x180..0x184].try_into().unwrap());
    ExecutableReply::capture(&output, written as usize)
}
