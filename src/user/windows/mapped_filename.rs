//! Backing-file names are attached to allocation identity, never guest addresses.
use std::fs::File;
use std::io;

#[derive(Debug)]
pub(crate) enum Filename {
    #[cfg(test)]
    Captured(std::sync::Arc<[u16]>),
    #[cfg(windows)]
    Native(native::View),
}

impl Filename {
    /// The file was opened and read by the loader, under its existing policy.
    /// A separate read-only host view pins that same file object across renames
    /// and pathname replacement. No native image code is executed.
    pub(crate) fn image(file: &File) -> io::Result<Option<Self>> {
        #[cfg(windows)]
        {
            native::View::image(file).map(|view| Some(Self::Native(view)))
        }
        #[cfg(not(windows))]
        {
            let _ = file;
            Ok(None)
        }
    }

    pub(crate) fn read(&self) -> io::Result<Vec<u16>> {
        match *self {
            #[cfg(test)]
            Self::Captured(ref name) => Ok(name.to_vec()),
            #[cfg(windows)]
            Self::Native(ref view) => view.name(),
        }
    }
}

#[cfg(windows)]
pub(crate) mod native;
