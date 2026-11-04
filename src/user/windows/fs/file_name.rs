//! A per-open guest volume retains its root independently of pathname changes.
use std::fs::File;
use std::io;
use std::path::{Component, Path};
use std::sync::Arc;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Clone, Debug)]
pub(crate) struct FileNameOrigin {
    root: Arc<File>,
    /// Selected installed libraries can have a separate guest directory name.
    prefix: Vec<u16>,
    #[cfg(target_os = "macos")]
    link: Option<Result<macos::Link, String>>,
}

impl FileNameOrigin {
    pub(crate) fn identity(file: &File, opened: &Path) -> io::Result<super::FileIdentity> {
        #[cfg(windows)]
        {
            // FileIdInfo accepts synchronization-only handles. General file
            // metadata would add a read-attributes requirement to class 9.
            let _ = opened;
            super::FileIdentity::retained(file)
        }
        #[cfg(not(windows))]
        {
            let metadata = file.metadata()?;
            super::FileIdentity::of_open(opened, Some(file), &metadata)
        }
    }

    pub(crate) fn metadata_file(path: &Path) -> io::Result<File> {
        #[cfg(unix)]
        return unix::open_metadata(path, false);
        #[cfg(windows)]
        return windows::open_root(path);
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    pub(crate) fn capture(root: &Path, prefix: Vec<u16>) -> io::Result<Self> {
        if !prefix.is_empty() && prefix.first() != Some(&u16::from(b'\\')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest name prefix",
            ));
        }
        Ok(Self {
            root: Arc::new(open_root(root)?),
            prefix,
            #[cfg(target_os = "macos")]
            link: None,
        })
    }

    pub(crate) fn bind(self, file: &File, opened: &Path) -> Self {
        #[cfg(target_os = "macos")]
        {
            let mut origin = self;
            origin.link = Some(macos::Link::capture(file, opened).map_err(|e| e.to_string()));
            origin
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (file, opened);
            self
        }
    }

    pub(crate) fn name(&self, file: &File, opened: &Path) -> io::Result<Vec<u16>> {
        let root = current(&self.root, None)?;
        #[cfg(target_os = "macos")]
        let path = match &self.link {
            Some(Ok(link)) => link.current(file)?,
            _ => current(file, Some(opened))?,
        };
        #[cfg(not(target_os = "macos"))]
        let path = current(file, Some(opened))?;
        let relative = path.strip_prefix(&root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "retained file moved outside its guest volume",
            )
        })?;
        let mut result = self.prefix.clone();
        if result.is_empty() {
            result.push(u16::from(b'\\'));
        }
        for part in relative.components() {
            let Component::Normal(part) = part else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "retained name component",
                ));
            };
            if result.last() != Some(&u16::from(b'\\')) {
                result.push(u16::from(b'\\'));
            }
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                result.extend(part.encode_wide());
            }
            #[cfg(not(windows))]
            {
                let text = part.to_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "host file name is not representable as guest UTF-16",
                    )
                })?;
                result.extend(text.encode_utf16());
            }
        }
        Ok(result)
    }
}

fn open_root(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    return unix::open_root(path);
    #[cfg(windows)]
    return windows::open_root(path);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

fn current(file: &File, opened: Option<&Path>) -> io::Result<std::path::PathBuf> {
    #[cfg(unix)]
    return unix::current(file, opened);
    #[cfg(windows)]
    {
        let _ = opened;
        windows::current(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, opened);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
