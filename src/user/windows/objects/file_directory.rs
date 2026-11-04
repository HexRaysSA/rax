//! Portable directory cursors belong to an open object, not a pathname or handle.
use super::Objects;

#[derive(Clone, Debug)]
pub(crate) struct DirectoryEntry {
    pub name: Vec<u16>,
    /// Alternate filename supplied by the volume; POSIX mapped volumes omit it.
    pub short_name: Vec<u16>,
    pub times: [u64; 4],
    pub allocation: u64,
    pub size: u64,
    pub attributes: u32,
    pub ea: Option<Vec<u8>>,
    pub file_id: u64,
}

#[derive(Debug)]
pub(crate) struct DirectoryScan {
    pub entries: Vec<DirectoryEntry>,
    pub pattern: Vec<u16>,
    pub cursor: usize,
    pub started: bool,
}

impl Objects {
    pub(crate) fn directory_scan(&self, handle: u64) -> Option<&DirectoryScan> {
        self.objs.get(&self.id(handle)?)?.directory_scan.as_ref()
    }

    pub(crate) fn directory_scan_mut(&mut self, handle: u64) -> Option<&mut DirectoryScan> {
        let id = self.id(handle)?;
        self.objs.get_mut(&id)?.directory_scan.as_mut()
    }

    pub(crate) fn set_directory_scan(&mut self, handle: u64, scan: DirectoryScan) -> bool {
        let Some(id) = self.id(handle) else {
            return false;
        };
        let Some(entry) = self.objs.get_mut(&id) else {
            return false;
        };
        entry.directory_scan = Some(scan);
        true
    }
}
