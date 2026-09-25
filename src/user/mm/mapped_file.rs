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
pub(crate) struct MappedFile(Option<File>, Option<Keep>);

impl std::fmt::Debug for MappedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MappedFile")
            .field(&self.0)
            .finish_non_exhaustive()
    }
}

impl MappedFile {
    pub(crate) fn new(file: File) -> Self {
        MappedFile(Some(file), None)
    }

    pub(crate) fn keeping(file: File, keep: Option<Keep>) -> Self {
        MappedFile(Some(file), keep)
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
