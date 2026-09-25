//! The host descriptors that mappings of host files keep.
//!
//! A mapping of a host file holds a descriptor of its own, as a kernel
//! mapping holds a reference to its file. Closing that descriptor is not
//! always neutral on the host: under POSIX, closing *any* descriptor of a
//! file releases every record lock the closing process holds on it, while
//! a Linux `munmap` releases none. A personality that implements its
//! guests' locks with host locks registers a hook ([`set_retire`]) that
//! decides when a mapping's descriptor may really be closed.

use std::fs::File;
use std::sync::OnceLock;

static RETIRE: OnceLock<fn(File)> = OnceLock::new();

/// Hands every descriptor a mapping no longer needs to `hook` instead of
/// closing it. The first registration wins; without one, descriptors are
/// closed at once.
pub fn set_retire(hook: fn(File)) {
    let _ = RETIRE.set(hook);
}

/// A host file owned by a mapping; dropping it retires the descriptor.
#[derive(Debug)]
pub(crate) struct MappedFile(Option<File>);

impl MappedFile {
    pub(crate) fn new(file: File) -> Self {
        MappedFile(Some(file))
    }
}

impl std::ops::Deref for MappedFile {
    type Target = File;

    fn deref(&self) -> &File {
        self.0
            .as_ref()
            .expect("a mapped file is present until dropped")
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        if let Some(file) = self.0.take() {
            match RETIRE.get() {
                Some(hook) => hook(file),
                None => drop(file),
            }
        }
    }
}
