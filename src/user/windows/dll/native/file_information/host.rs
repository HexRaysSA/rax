//! Narrow mechanics for already admitted files, independent of guest addresses.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
use super::super::named_object::Checked;
use crate::user::windows::hle::Ctx;
use crate::user::windows::objects::FileObj;

pub(super) fn query(c: &Ctx, file: &FileObj, class: u32) -> Checked<Vec<u8>> {
    #[cfg(windows)]
    return windows::query(c, file, class);
    #[cfg(unix)]
    return unix::query(c, file, class);
    #[cfg(not(any(windows, unix)))]
    Err(c
        .unsupported("owned file-information adapter unavailable")
        .into())
}

#[cfg(windows)]
pub(in super::super) fn set(
    c: &Ctx,
    handle: &std::fs::File,
    class: u32,
    value: u64,
) -> Checked<()> {
    windows::set(c, handle, class, value)
}
