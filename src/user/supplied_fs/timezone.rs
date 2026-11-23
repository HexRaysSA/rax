//! Read-only selection of the host's default timezone for native POSIX guests.
use super::{Error, Files};
use crate::user::mm::HostFileSource;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    path::Path,
};

const LOCALTIME: &str = "/etc/localtime";

pub(in crate::user) fn has_tzif_header(mut file: &File) -> io::Result<bool> {
    // RFC 9636 section 3.1. Guest libc interprets the remaining TZif bytes.
    let mut header = [0; 44];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(&header[..4] == b"TZif" && matches!(header[4], 0 | b'2' | b'3' | b'4')),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

fn open_localtime(path: &Path) -> io::Result<HostFileSource> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || !has_tzif_header(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed TZif localtime",
        ));
    }
    HostFileSource::new(file)
}

pub(in crate::user) fn select_default(files: Files, root: &Path) -> io::Result<Files> {
    if matches!(
        files.lookup_with_follow(LOCALTIME, false),
        Err(Error::NotFound)
    ) && let Ok(source) = open_localtime(&root.join("etc/localtime"))
    {
        return files
            .with_selected_backings(BTreeMap::from([(LOCALTIME.into(), source.into())]))
            .map_err(io::Error::other);
    }
    Ok(files)
}
