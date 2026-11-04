use super::super::named_object::{Checked, status};
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object};

pub(super) enum Publication {
    Full,
    InformationFirst,
    StatusFirst,
}

pub(super) struct Record {
    pub data: Vec<u8>,
    pub information: u32,
    pub publication: Publication,
    pub ignore_late_fault: bool,
}

fn mapped(mut access: u32) -> u32 {
    for (generic, specific) in [
        (0x8000_0000, 0x120089),
        (0x4000_0000, 0x120116),
        (0x2000_0000, 0x1200a0),
        (0x1000_0000, 0x1f01ff),
    ] {
        if access & generic != 0 {
            access = (access & !generic) | specific;
        }
    }
    access
}

fn access(c: &Ctx, handle: u64, object: &Object) -> u32 {
    let grant = c.p.objects.access(handle).expect("resolved file handle");
    if grant != u32::MAX {
        return mapped(grant);
    }
    // Legacy standard objects use the unrestricted internal handle grant.
    // Their guest-visible FILE_* rights still have the actual stream role.
    match object {
        Object::File(file) => mapped(file.access),
        Object::Pipe { write, .. } => {
            if *write {
                0x120196
            } else {
                0x120189
            }
        }
        _ => 0x12019f,
    }
}

fn value(data: Vec<u8>, publication: Publication, ignore_late_fault: bool) -> Record {
    Record {
        information: data.len() as u32,
        data,
        publication,
        ignore_late_fault,
    }
}

pub(super) fn query(c: &Ctx, handle: u64, object: &Object, class: u32) -> Checked<Record> {
    let grant = access(c, handle, object);
    let file = match object {
        Object::File(file) if !file.null => Some(file),
        _ => None,
    };
    let state =
        c.p.objects
            .file_state(handle)
            .expect("resolved file object");
    let synchronous = state.mode & 0x30 != 0;
    if matches!(class, 4 | 34 | 35) && grant & 0x80 == 0 || class == 43 && grant & 1 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    let inline = |data: Vec<u8>, publication| Ok(value(data, publication, true));
    match class {
        8 => inline(grant.to_le_bytes().to_vec(), Publication::StatusFirst),
        16 => inline(
            c.p.objects
                .file_mode(handle)
                .unwrap_or(0)
                .to_le_bytes()
                .to_vec(),
            Publication::InformationFirst,
        ),
        41 => inline(
            state.notification.to_le_bytes().to_vec(),
            Publication::InformationFirst,
        ),
        43 => inline(
            state.priority.to_le_bytes().to_vec(),
            Publication::InformationFirst,
        ),
        51 => inline(
            if let Some(file) = file {
                super::host::query(c, file, class)?
            } else {
                vec![0]
            },
            Publication::Full,
        ),
        17 if file.is_none() => inline(0u32.to_le_bytes().to_vec(), Publication::InformationFirst),
        17 => inline(
            super::host::query(c, file.expect("ordinary file"), class)?,
            Publication::InformationFirst,
        ),
        14 if file.is_none()
            || file.is_some_and(|f| f.host.is_none() || cfg!(unix) && f.directory) =>
        {
            inline(state.position.to_le_bytes().to_vec(), Publication::Full)
        }
        _ => {
            if let Some(file) = file {
                let data = super::host::query(c, file, class)?;
                let publication = if matches!(class, 4 | 5 | 14) || !synchronous {
                    Publication::Full
                } else {
                    Publication::InformationFirst
                };
                return Ok(value(data, publication, synchronous));
            }
            match object {
                Object::Console(_) => status(0xc000_0010),
                Object::Null | Object::File(FileObj { null: true, .. }) if class == 5 => {
                    let mut data = vec![0; 24];
                    data[16..20].copy_from_slice(&1u32.to_le_bytes());
                    inline(data, Publication::InformationFirst)
                }
                Object::Null | Object::File(FileObj { null: true, .. }) => {
                    status(STATUS_INVALID_INFO_CLASS)
                }
                Object::Pipe { .. } if matches!(class, 34 | 35 | 59) => {
                    status(STATUS_INVALID_PARAMETER)
                }
                Object::Pipe { .. } if class == 7 => {
                    inline(0u32.to_le_bytes().to_vec(), Publication::InformationFirst)
                }
                Object::Pipe { .. } => Err(c
                    .unsupported("pipe file metadata requires guest pipe-resource accounting")
                    .into()),
                _ => unreachable!("caller admitted only file resources"),
            }
        }
    }
}
