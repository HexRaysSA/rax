//! Stock executable cache replies captured through `BasepQueryAppCompat`.

use super::{number, pointer};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::STATUS_SUCCESS;

const PACKET_BYTES: usize = 392;
const NAME_LENGTH: usize = 0x30;
const NAME_BUFFER: usize = 0x38;
const OUTPUT_BUFFER: usize = 0x178;
const OUTPUT_SIZE: usize = 0x180;
const INITIAL_CAPACITY: u32 = 4096;
const MAX_NAME_BYTES: usize = 512;

// Each item has a u32 type and byte length, followed by its payload.
// The three eight-byte payloads are zero in the observed stock replies.
const STOCK_RECORD: [u32; 16] = [2, 0, 8, 8, 0, 0, 4, 8, 0, 0, 16, 8, 0, 0, 1, 0];

pub(super) fn lookup(c: &mut Ctx<'_>) -> ApiResult {
    let native =
        c.p.native
            .as_ref()
            .filter(|native| {
                c.arch() == WinArch::Arm64
                    && native.object_namespace.native_machine == Some(0xaa64)
                    && (
                        native.version.major,
                        native.version.minor,
                        native.version.build,
                    ) == (10, 0, 29708)
            })
            .ok_or_else(|| c.unsupported("AppHelp executable-cache profile is not captured"))?;
    let input = c.ptr(1)?;
    let mut packet = [0; PACKET_BYTES];
    c.mem().rd(input, &mut packet)?;
    if number(&packet, 0) != 0x1f
        || !matches!(number(&packet, 4), 0x10 | 0x30)
        || number(&packet, OUTPUT_SIZE) != INITIAL_CAPACITY
    {
        return Err(
            c.unsupported("AppHelp executable-cache request is outside the captured profile")
        );
    }

    let name_length = usize::from(u16::from_le_bytes(
        packet[NAME_LENGTH..NAME_LENGTH + 2].try_into().unwrap(),
    ));
    if name_length == 0 || name_length > MAX_NAME_BYTES || name_length % 2 != 0 {
        return Err(c.unsupported("AppHelp executable-cache name is outside the captured profile"));
    }
    let mut bytes = [0; MAX_NAME_BYTES];
    c.mem().rd(
        pointer(&packet, NAME_BUFFER, false),
        &mut bytes[..name_length],
    )?;
    let name: Vec<_> = bytes[..name_length]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let path = String::from_utf16(&name)
        .map_err(|_| c.unsupported("AppHelp executable-cache name is not a Windows path"))?;
    let directory = native.guest_directory.trim_end_matches('\\');
    let known_image = ["cmd.exe", "where.exe", "findstr.exe"]
        .iter()
        .any(|image| path.eq_ignore_ascii_case(&format!("{directory}\\{image}")));
    if !known_image || !c.p.registry.creator_compat_layer_absent(&name) {
        return Err(c.unsupported("AppHelp executable-cache result is not captured for this image"));
    }

    let mut record = [0; 64];
    for (slot, value) in record.chunks_exact_mut(4).zip(STOCK_RECORD) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let destination = pointer(&packet, OUTPUT_BUFFER, false);
    let size = input + OUTPUT_SIZE as u64;
    if destination < input + PACKET_BYTES as u64
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
