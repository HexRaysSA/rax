use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) fn open_root(path: &Path) -> io::Result<File> {
    open_metadata(path, true)
}

pub(super) fn open_metadata(path: &Path, directory: bool) -> io::Result<File> {
    let mut flags = libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 };
    #[cfg(target_os = "linux")]
    {
        flags |= libc::O_PATH;
    }
    #[cfg(target_os = "macos")]
    {
        flags |= libc::O_EVTONLY;
    }
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

pub(super) fn current(file: &File, opened: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(opened) = opened {
        let retained = file.metadata()?;
        if let Ok(candidate) = std::fs::metadata(opened)
            && candidate.dev() == retained.dev()
            && candidate.ino() == retained.ino()
        {
            // Preserve the opened hard-link spelling while it still identifies
            // this object. A replacement must never substitute a different file.
            return opened.canonicalize();
        }
    }
    #[cfg(target_os = "linux")]
    {
        let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if file.metadata()?.nlink() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "an unlinked host file has no captured guest deletion name",
            ));
        }
        Ok(path)
    }
    #[cfg(target_os = "macos")]
    {
        if opened.is_some() && file.metadata()?.is_file() && file.metadata()?.nlink() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a renamed hard link requires a captured Darwin link identifier",
            ));
        }
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let mut bytes = [0u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH receives the retained descriptor and a writable
        // PATH_MAX-byte local allocation. It retains no pointer or callback.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(Path::new(OsStr::from_bytes(&bytes[..end])).to_owned())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
