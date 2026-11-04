//! Filesystem mechanics; synthetic device policy stays in the shared service.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
use crate::user::windows::objects::FileObj;

pub(super) struct Record {
    pub status: u32,
    pub data: Vec<u8>,
}
impl Record {
    pub fn encode(
        flags: u32,
        maximum: i32,
        name: &[u8],
        length: u32,
        full_name_length: bool,
    ) -> Self {
        let copied = name.len().min(length as usize - 12);
        let mut data = Vec::with_capacity(12 + copied);
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&maximum.to_le_bytes());
        data.extend_from_slice(
            &(if full_name_length { name.len() } else { copied } as u32).to_le_bytes(),
        );
        data.extend_from_slice(&name[..copied]);
        Self {
            status: if copied == name.len() { 0 } else { 0x8000_0005 },
            data,
        }
    }
    pub fn pipe(length: u32) -> Self {
        Self::encode(2, -1, b"N\0P\0F\0S\0", length, true)
    }
}
pub(super) enum Error {
    #[cfg(windows)]
    Status(u32),
    Unavailable(String),
}
pub(super) fn attributes(file: &FileObj, length: u32) -> Result<Record, Error> {
    #[cfg(windows)]
    {
        windows::attributes(file, length)
    }
    #[cfg(unix)]
    {
        unix::attributes(file, length).map_err(Error::Unavailable)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, length);
        Err(Error::Unavailable(
            "host filesystem adapter unavailable".into(),
        ))
    }
}

pub(super) fn device(file: &FileObj) -> Result<(u32, u32), String> {
    #[cfg(windows)]
    {
        windows::device(file)
    }
    #[cfg(unix)]
    {
        unix::device(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err("host filesystem adapter unavailable".into())
    }
}
