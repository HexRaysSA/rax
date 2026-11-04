//! Variable UTF-16 names retain the full required byte length on overflow.
use super::super::named_object::{Checked, status};
use super::records::{Publication, Record};
use crate::user::windows::fs::FileNameOrigin;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn query(c: &Ctx, handle: u64, object: &Object, length: u32) -> Checked<Record> {
    let name = match object {
        Object::File(file) if !file.null => {
            let reopened;
            let retained = if let Some(file) = &file.host {
                file
            } else {
                reopened = FileNameOrigin::metadata_file(&file.host_path)
                    .map_err(|e| c.unsupported(format!("metadata-only naming handle: {e}")))?;
                &reopened
            };
            let identity = FileNameOrigin::identity(retained, &file.host_path)
                .map_err(|e| c.unsupported(format!("retained name identity: {e}")))?;
            if identity != file.lifetime.identity {
                return Err(c.unsupported("file naming pathname was replaced").into());
            }
            let fallback;
            let origin = if let Some(origin) = c.p.objects.file_name_origin(handle) {
                origin
            } else {
                fallback = super::super::file_name_origin::win32(c, &file.path)
                    .map(|origin| origin.bind(retained, &file.host_path));
                &fallback
            };
            origin
                .as_ref()
                .map_err(|e| c.unsupported(e.clone()))?
                .name(retained, &file.host_path)
                .map_err(|e| c.unsupported(format!("retained guest file name: {e}")))?
        }
        Object::Console(_) => return status(0xc000_0010),
        Object::Null | Object::File(_) => return status(STATUS_INVALID_INFO_CLASS),
        Object::Pipe { .. } => Vec::new(),
        _ => unreachable!("caller admitted only file resources"),
    };
    let required = name
        .len()
        .checked_mul(2)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| c.unsupported("guest file name exceeds ULONG byte length"))?;
    let copied = name.len().min(((length - 4) / 2) as usize);
    let mut data = Vec::with_capacity(4 + copied * 2);
    data.extend_from_slice(&required.to_le_bytes());
    for unit in &name[..copied] {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    let synchronous =
        c.p.objects
            .file_state(handle)
            .expect("resolved file object")
            .mode
            & 0x30
            != 0;
    Ok(Record {
        status: if copied == name.len() {
            STATUS_SUCCESS
        } else {
            STATUS_BUFFER_OVERFLOW
        },
        information: data.len() as u32,
        data,
        publication: if synchronous {
            Publication::InformationFirst
        } else {
            Publication::Full
        },
        ignore_late_fault: synchronous,
    })
}
