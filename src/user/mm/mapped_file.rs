//! The host descriptors that mappings of host files keep.
//!
//! A mapping of a host file holds a descriptor of its own, as a kernel
//! mapping holds a reference to its file. Closing that descriptor is not
//! always neutral on the host: under POSIX, closing *any* descriptor of a
//! file releases every record lock the closing process holds on it, while
//! a Linux `munmap` releases none. A personality that implements its
//! guests' locks with host locks registers a hook ([`set_retire`]) that
//! decides when a mapping's descriptor may really be closed. What else
//! the personality ties to the mapping's reference to its file (a [`Keep`])
//! lives as long as the descriptor.

use std::fs::File;
use std::sync::OnceLock;

static RETIRE: OnceLock<fn(File)> = OnceLock::new();

/// Hands every descriptor a mapping no longer needs to `hook` instead of
/// closing it. The first registration wins; without one, descriptors are
/// closed at once.
pub fn set_retire(hook: fn(File)) {
    let _ = RETIRE.set(hook);
}

/// What a personality keeps alive while a mapping refers to its file (a
/// file-system notification token, whose last reference reports the
/// file's close).
pub type Keep = std::sync::Arc<dyn std::any::Any + Send + Sync>;

/// A host file owned by a mapping; dropping it retires the descriptor,
/// then drops what it keeps.
pub(crate) struct MappedFile {
    file: Option<File>,
    _keep: Option<Keep>,
    #[cfg(windows)]
    identity: std::sync::Mutex<Option<std::sync::Arc<super::windows_identity::Identity>>>,
}

impl std::fmt::Debug for MappedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MappedFile")
            .field(&self.file)
            .finish_non_exhaustive()
    }
}

impl MappedFile {
    pub(crate) fn new(file: File) -> Self {
        Self::keeping(file, None)
    }

    pub(crate) fn keeping(file: File, keep: Option<Keep>) -> Self {
        MappedFile {
            file: Some(file),
            _keep: keep,
            #[cfg(windows)]
            identity: std::sync::Mutex::new(None),
        }
    }

    /// Read positional bytes without changing the file's shared cursor.
    pub(crate) fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            if offset.checked_add(buf.len() as u64).is_none() {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            let mut done = 0;
            while done < buf.len() {
                match FileExt::read_at(&**self, &mut buf[done..], offset + done as u64) {
                    Ok(0) => break,
                    Ok(n) => done += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            Ok(done)
        }
        #[cfg(windows)]
        super::windows_file::read_at(self, offset, buf)
    }

    /// Write positional bytes without changing the file's shared cursor.
    pub(crate) fn write_all_at(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            FileExt::write_all_at(&**self, data, offset)
        }
        #[cfg(windows)]
        super::windows_file::write_all_at(self, offset, data)
    }

    /// Native object identity, retained until this mapping drops its file.
    pub(crate) fn identity(&self) -> std::io::Result<super::SourceIdentity> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = self.metadata()?;
            Ok(super::SourceIdentity {
                dev: m.dev(),
                ino: m.ino(),
            })
        }
        #[cfg(windows)]
        {
            let mut cached = self.identity.lock().unwrap();
            if cached.is_none() {
                *cached = Some(super::windows_identity::for_file(self)?);
            }
            Ok(cached.as_ref().expect("identity was populated").source())
        }
    }
}

impl std::ops::Deref for MappedFile {
    type Target = File;

    fn deref(&self) -> &File {
        self.file
            .as_ref()
            .expect("a mapped file is present until dropped")
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            match RETIRE.get() {
                Some(hook) => hook(file),
                None => drop(file),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{HostFileSource, PageSource, SharedObject, anonymous_file};

    #[test]
    fn duplicate_handles_share_identity_across_private_and_shared_sources() {
        let file = anonymous_file().unwrap();
        file.set_len(4096).unwrap();
        let source = HostFileSource::new(file.try_clone().unwrap()).unwrap();
        let shared = SharedObject::file(file.try_clone().unwrap(), true).unwrap();
        let mapped = MappedFile::new(file);
        assert_eq!(source.identity(), shared.identity());
        assert_eq!(mapped.identity().unwrap(), shared.identity());
        assert_eq!(mapped.identity().unwrap(), mapped.identity().unwrap());

        let other = SharedObject::anonymous(4096).unwrap();
        assert_ne!(shared.identity(), other.identity());
        // Dropping one source must not retire the identity of the others.
        drop(source);
        let another = HostFileSource::new(mapped.try_clone().unwrap()).unwrap();
        assert_eq!(another.identity(), shared.identity());
    }
}
