//! Native mechanics receive only validated masks and resolved host paths.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
use super::super::file_attributes::path::Resolved;
use super::super::named_object::{Checked, status};
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Ctx;
use std::fs::File;

pub(super) struct Acquired {
    pub file: File,
    pub path: std::path::PathBuf,
    pub identity: FileIdentity,
    pub directory: bool,
    pub access: u32,
}

pub(super) fn open(
    c: &Ctx,
    path: &Resolved,
    access: u32,
    share: u32,
    options: u32,
    flags: u32,
) -> Checked<Acquired> {
    #[cfg(windows)]
    {
        windows::open(c, path, access, share, options, flags)
    }
    #[cfg(unix)]
    {
        let _ = share;
        unix::open(c, path, access, options, flags)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, access, share, options, flags);
        Err(c
            .unsupported("host file open has no platform adapter")
            .into())
    }
}

#[cfg(unix)]
fn io_error(c: &Ctx, e: std::io::Error, path: &std::path::Path) -> Checked<Acquired> {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::PermissionDenied => status(0xc000_0022),
        ErrorKind::NotFound | ErrorKind::NotADirectory => {
            status(if path.parent().is_some_and(|p| !p.is_dir()) {
                0xc000_003a
            } else {
                0xc000_0034
            })
        }
        ErrorKind::AlreadyExists => status(0xc000_0035),
        _ => Err(c
            .unsupported(format!("native mapped file open: {e}"))
            .into()),
    }
}
