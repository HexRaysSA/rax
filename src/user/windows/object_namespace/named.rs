//! Names for private guest synchronization objects in selected directories.
use super::*;

#[derive(Debug, Clone)]
pub(crate) struct Name {
    directory: Arc<Directory>,
    leaf: Vec<u16>,
    insensitive: bool,
}

impl Name {
    pub(crate) fn matches(&self, stored: &Self) -> bool {
        Arc::ptr_eq(&self.directory, &stored.directory)
            && self.leaf.len() == stored.leaf.len()
            && self.leaf.iter().zip(&stored.leaf).all(|(&a, &b)| {
                if self.insensitive {
                    self.directory.upcase[usize::from(a)] == self.directory.upcase[usize::from(b)]
                } else {
                    a == b
                }
            })
    }
}

impl Namespace {
    pub(crate) fn is_selected(&self) -> bool {
        self.root.is_some()
    }

    /// Resolve only the parent using captured directory/link identities. Host
    /// synchronization objects are never acquired, opened, or mutated. The leaf
    /// belongs to the guest's independent object table, including exact UTF-16.
    pub(crate) fn named(
        &self,
        root: Option<Arc<Directory>>,
        name: &[u16],
        flags: u32,
    ) -> Result<Name, LookupError> {
        if name.len() > MAX_UNITS {
            return Err(LookupError::Status(STATUS_OBJECT_NAME_INVALID));
        }
        if root.is_some() && name.first() == Some(&92) {
            return Err(LookupError::Status(STATUS_OBJECT_PATH_SYNTAX_BAD));
        }
        let separator = name.iter().rposition(|&unit| unit == 92);
        let (directory, leaf) = match separator {
            Some(index) => {
                let parent = if index == 0 {
                    &name[..1]
                } else {
                    &name[..index]
                };
                let directory = self
                    .lookup(root, parent, flags)
                    .map_err(|error| match error {
                        LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND) => {
                            LookupError::Status(STATUS_OBJECT_PATH_NOT_FOUND)
                        }
                        error => error,
                    })?;
                (directory, &name[index + 1..])
            }
            None => (
                root.ok_or(LookupError::Status(STATUS_OBJECT_PATH_SYNTAX_BAD))?,
                name,
            ),
        };
        if leaf.is_empty() {
            return Err(LookupError::Status(STATUS_OBJECT_NAME_INVALID));
        }
        // Fixed selection admits only public and primary-token session roots.
        // Other captured directories retain their own immutable contracts.
        if !directory
            .path
            .ends_with(&"\\BaseNamedObjects".encode_utf16().collect::<Vec<_>>())
        {
            return Err(LookupError::Unselected);
        }
        let insensitive = directory.force_case_insensitive || flags & 0x40 != 0;
        if let Some(entry) = directory
            .entries
            .get(&fold(&directory.upcase, leaf))
            .filter(|entry| insensitive || entry.captured.name == leaf)
        {
            if is(&entry.captured.kind, "Directory") {
                return Err(LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH));
            }
            if is(&entry.captured.kind, "SymbolicLink") {
                self.lookup(Some(directory.clone()), leaf, flags)?;
                return Err(LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH));
            }
        }
        Ok(Name {
            directory,
            leaf: leaf.to_vec(),
            insensitive,
        })
    }

    /// Win32 callers use the selected session root. The installed NT links own
    /// Local/Global routing; embedded profiles keep Objects' legacy name keys.
    pub(crate) fn named_win32(&self, session: u32, name: &[u16]) -> Result<Name, LookupError> {
        let base = if session == 0 {
            "\\BaseNamedObjects".to_owned()
        } else {
            format!("\\Sessions\\{session}\\BaseNamedObjects")
        };
        let root = self.lookup(None, &base.encode_utf16().collect::<Vec<_>>(), 0x40)?;
        self.named(Some(root), name, 0)
    }
}

#[cfg(test)]
#[path = "named_tests.rs"]
mod tests;
