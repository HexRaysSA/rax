//! Capture regular executable entries from a retained local system directory.
use super::super::super::{Checked, Ctx, Layout, Request, host, records};
use super::executable_name;
use crate::user::windows::dll::native::{file_attributes::path::Resolved, file_open};
use crate::user::windows::nt::status::{STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_SUCCESS};
use crate::user::windows::objects::DirectoryEntry;
use std::path::Path;

pub(super) fn collect(c: &Ctx, root: &Path) -> Checked<Vec<DirectoryEntry>> {
    let directory = Resolved {
        host: root.to_owned(),
        base: root.to_owned(),
        root: None,
        relative: None,
        directory: true,
        runtime_library: true,
    };
    // SYNCHRONIZE | FILE_LIST_DIRECTORY and a synchronous directory open.
    // Refuse name reparsing and keep the host handle private for the full scan.
    let opened = file_open::host::open(c, &directory, 0x100001, 7, 0x21, 0x1040)?;
    const CLASS: u32 = 38; // FileIdFullDirectoryInformation
    let layout = Layout::of(CLASS).unwrap();
    let mut pattern = Some("*.exe".encode_utf16().collect());
    let mut entries = Vec::new();
    let mut estimated_bytes = 0;
    loop {
        let result = host::query_retained(
            &opened.file,
            Request {
                handle: 0,
                class: CLASS,
                flags: 0,
                pattern: pattern.take(),
                bytes: vec![0; 32 << 10],
            },
        )?;
        if matches!(result.code, STATUS_NO_MORE_FILES | STATUS_NO_SUCH_FILE) {
            return Ok(entries);
        }
        if result.code != STATUS_SUCCESS {
            return Err(c
                .unsupported(format!(
                    "installed directory read failed: {:#x}",
                    result.code
                ))
                .into());
        }
        records::validate(c, layout, &result)?;
        let count = result.information.unwrap_or(0) as usize;
        if count == 0 {
            return Err(c
                .unsupported("installed directory scan made no progress")
                .into());
        }
        let mut data = &result.bytes[..count];
        loop {
            let next = read_u32(data, 0) as usize;
            let attributes = read_u32(data, 56);
            // The native search can also match short names. Publish regular
            // entries whose actual names match, excluding all reparse tags.
            if attributes & (0x10 | 0x400) == 0 {
                let name_bytes = read_u32(data, 60) as usize;
                let name: Vec<_> = data[layout.name..layout.name + name_bytes]
                    .chunks_exact(2)
                    .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                    .collect();
                if executable_name(&name) {
                    estimated_bytes += 256 + name_bytes;
                    if estimated_bytes > 16 << 20 || entries.len() >= 65536 {
                        return Err(c
                            .unsupported(
                                "installed directory snapshot exceeds 16 MiB or 65536 entries",
                            )
                            .into());
                    }
                    entries.push(DirectoryEntry {
                        name,
                        short_name: Vec::new(),
                        times: [8, 16, 24, 32].map(|offset| read_u64(data, offset)),
                        size: read_u64(data, 40),
                        allocation: read_u64(data, 48),
                        attributes,
                        ea: None,
                        file_id: read_u64(data, 72),
                    });
                }
            }
            if next == 0 {
                break;
            }
            data = &data[next..];
        }
    }
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}
