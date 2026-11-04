//! Mapped-volume enumeration state; native Windows uses the retained NT cursor.
mod encode;

mod pattern;
#[cfg(test)]
#[path = "portable/replay.rs"]
mod replay;
mod snapshot;

use super::{Checked, Completion, Ctx, Layout, Request};
use crate::user::windows::hle::ApiErr;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::DirectoryScan;

pub(super) fn query(c: &mut Ctx, request: Request) -> Checked<Completion> {
    if c.p.objects.directory_scan(request.handle).is_none() {
        let entries = snapshot::collect(c, request.handle)?;
        let scan = DirectoryScan {
            entries,
            pattern: vec![42],
            cursor: 0,
            started: false,
        };
        if !c.p.objects.set_directory_scan(request.handle, scan) {
            return Err(c
                .unsupported("directory object changed during capture")
                .into());
        }
    }
    let Some(scan) = c.p.objects.directory_scan_mut(request.handle) else {
        return Err(c
            .unsupported("directory cursor missing after capture")
            .into());
    };
    enumerate(scan, request).map_err(Into::into)
}

fn enumerate(scan: &mut DirectoryScan, mut request: Request) -> Result<Completion, ApiErr> {
    let layout = Layout::of(request.class).unwrap();
    let no_update = request.flags & 16 != 0;
    let first = !scan.started;
    let restart = first || request.flags & 1 != 0 || no_update;
    let mut cursor = if restart { 0 } else { scan.cursor };
    let selected = if restart {
        request
            .pattern
            .take()
            .unwrap_or_else(|| scan.pattern.clone())
    } else {
        scan.pattern.clone()
    };
    let selected = if selected.is_empty() {
        vec![42]
    } else {
        selected
    };
    let mut used = 0usize;
    let mut previous: Option<usize> = None;
    let mut code = STATUS_SUCCESS;
    while cursor < scan.entries.len() {
        let entry = &scan.entries[cursor];
        if !pattern::matches(&selected, &entry.name)
            && (entry.short_name.is_empty() || !pattern::matches(&selected, &entry.short_name))
        {
            cursor += 1;
            continue;
        }
        // NTFS packs all admitted directory records on eight-byte boundaries,
        // including NamesInformation whose caller buffer only needs four.
        let start = used.next_multiple_of(8);
        let record = encode::record(entry, request.class, layout)?;
        let end = start + record.len();
        if end > request.bytes.len() {
            if used == 0 && first {
                let count = request.bytes.len();
                request.bytes.copy_from_slice(&record[..count]);
                used = count;
                code = STATUS_BUFFER_OVERFLOW;
            }
            break;
        }
        if let Some(before) = previous {
            request.bytes[before..before + 4]
                .copy_from_slice(&((start - before) as u32).to_le_bytes());
            request.bytes[used..start].fill(0);
        }
        request.bytes[start..end].copy_from_slice(&record);
        previous = Some(start);
        used = end;
        cursor += 1;
        if request.flags & 2 != 0 {
            break;
        }
    }
    let exhausted_without_data = used == 0 && cursor == scan.entries.len();
    if exhausted_without_data {
        code = if first {
            STATUS_NO_SUCH_FILE
        } else {
            STATUS_NO_MORE_FILES
        };
    }
    if !no_update {
        scan.cursor = cursor;
        scan.pattern = selected;
        scan.started = true;
    }
    let publish = !(first && exhausted_without_data);
    Ok(Completion {
        code,
        bytes: request.bytes,
        status: publish.then_some(code),
        information: publish.then_some(used as u64),
    })
}
