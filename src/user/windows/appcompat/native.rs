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
