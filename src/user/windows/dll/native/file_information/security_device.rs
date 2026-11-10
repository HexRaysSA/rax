//! File-object state is guest-owned; a security device has no disk metadata.
use super::super::named_object::{Checked, status};
use super::records::{Publication, Record};
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
};

pub(super) fn query(c: &Ctx, handle: u64, class: u32) -> Checked<Record> {
    let access = c.p.objects.access(handle).expect("admitted device handle");
    let state =
        c.p.objects
            .file_state(handle)
            .expect("admitted device file state");
    if matches!(class, 41 | 51) && access & 0x80 == 0 || class == 43 && access & 1 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    let (data, publication) = match class {
        5 => {
            let mut data = vec![0; 24];
            data[16..20].copy_from_slice(&1u32.to_le_bytes());
            (data, Publication::InformationFirst)
        }
        8 => (access.to_le_bytes().to_vec(), Publication::StatusFirst),
        14 if state.mode & 0x30 != 0 => (state.position.to_le_bytes().to_vec(), Publication::Full),
        14 => return status(STATUS_INVALID_INFO_CLASS),
        16 => (
            state.mode.to_le_bytes().to_vec(),
            Publication::InformationFirst,
        ),
        17 => (0u32.to_le_bytes().to_vec(), Publication::InformationFirst),
        41 => (
            state.notification.to_le_bytes().to_vec(),
            Publication::InformationFirst,
        ),
        43 => (
            state.priority.to_le_bytes().to_vec(),
            Publication::InformationFirst,
        ),
        51 => (vec![0], Publication::Full),
        _ => {
            return Err(c
                .unsupported(format!("security-device file information class {class}"))
                .into());
        }
    };
    Ok(Record {
        status: STATUS_SUCCESS,
        information: data.len() as u32,
        data,
        publication,
        ignore_late_fault: true,
    })
}
