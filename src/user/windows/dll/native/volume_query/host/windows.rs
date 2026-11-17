//! Query the retained Windows file's actual volume through private native buffers.
mod request;
use super::{Error, Record};
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::objects::FileObj;
use std::os::windows::fs::OpenOptionsExt;

fn retained<T>(
    file: &FileObj,
    query: impl FnOnce(&std::fs::File) -> Result<T, Error>,
) -> Result<T, Error> {
    let reopened;
    let handle = if let Some(handle) = &file.host {
        handle
    } else {
        // Legacy metadata-only objects may lack a retained File. A new
        // metadata handle is admitted only when its identity still matches.
        reopened = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(7)
            .custom_flags(0x02000000)
            .open(&file.host_path)
            .map_err(|e| Error::Unavailable(format!("metadata-only file open: {e}")))?;
        if FileIdentity::retained(&reopened)
            .map_err(|e| Error::Unavailable(format!("metadata identity: {e}")))?
            != file.lifetime.identity
        {
            return Err(Error::Unavailable(
                "metadata-only handle pathname was replaced".into(),
            ));
        }
        &reopened
    };
    query(handle)
}

pub(super) fn device(file: &FileObj) -> Result<(u32, u32), String> {
    retained(file, |handle| {
        let (status, data) = request::run(handle, 4, 8)?;
        if status != 0 {
            return Err(Error::Status(status));
        }
        if data.len() != 8 {
            return Err(Error::Unavailable(
                "unexpected native device information length".into(),
            ));
        }
        Ok((
            u32::from_le_bytes(data[..4].try_into().unwrap()),
            u32::from_le_bytes(data[4..].try_into().unwrap()),
        ))
    })
    .map_err(|e| match e {
        Error::Status(code) => format!("native volume status {code:#010x}"),
        Error::Unavailable(message) => message,
    })
}

fn filesystem_record(handle: &std::fs::File, class: u32, length: u32) -> Result<Record, Error> {
    let mut capacity = length.min(512);
    loop {
        let (status, data) = request::run(handle, class, capacity)?;
        if status != 0x8000_0005 || capacity >= length {
            return Ok(Record { status, data });
        }
        if capacity == 16 * 1024 * 1024 {
            return Err(Error::Unavailable(
                "native filesystem name exceeds 16 MiB query buffer".into(),
            ));
        }
        // Providers may report different length fields on overflow, so repeat
        // the same read-only query with the next bounded private buffer.
        capacity = (capacity * 2).min(length).min(16 * 1024 * 1024);
    }
}

pub(super) fn attributes(file: &FileObj, length: u32) -> Result<Record, Error> {
    retained(file, |handle| {
        let record = filesystem_record(handle, 5, length)?;
        let data = &record.data;
        if data.len() < 12 {
            return Err(Error::Unavailable(
                "short native filesystem attribute header".into(),
            ));
        }
        if record.status == 0 {
            let name_bytes = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
            if name_bytes % 2 != 0 || name_bytes > data.len() - 12 {
                return Err(Error::Unavailable(
                    "invalid native filesystem name extent".into(),
                ));
            }
        }
        Ok(record)
    })
}

pub(super) fn volume(file: &FileObj, length: u32) -> Result<Record, Error> {
    retained(file, |handle| {
        let record = filesystem_record(handle, 1, length)?;
        let Some(label) = record.data.get(18..) else {
            return Err(Error::Unavailable(
                "short native volume identity header".into(),
            ));
        };
        let declared = u32::from_le_bytes(record.data[12..16].try_into().unwrap()) as usize;
        if declared % 2 != 0
            || label.len() > declared
            || (record.status == 0) != (label.len() == declared)
        {
            return Err(Error::Unavailable(
                "invalid native volume label extent".into(),
            ));
        }
        Ok(record)
    })
}
