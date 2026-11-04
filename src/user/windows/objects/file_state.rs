//! Per-open state, shared by duplicate handles rather than by file identity.
use super::{ObjId, Objects};

#[derive(Clone, Copy, Debug)]
pub(crate) struct FileState {
    pub mode: u32,
    pub position: u64,
    pub notification: u32,
    pub priority: u32,
    /// A retained open has completed nonempty cached data I/O.
    pub cached_io_initialized: bool,
}

impl FileState {
    pub(super) fn new(mode: u32) -> Self {
        Self {
            mode,
            position: 0,
            notification: 0,
            priority: 2,
            cached_io_initialized: false,
        }
    }
}

impl Objects {
    pub(crate) fn file_state(&self, handle: u64) -> Option<FileState> {
        self.objs
            .get(&self.id(handle)?)
            .map(|entry| entry.file_state)
    }

    pub(crate) fn file_state_mut(&mut self, handle: u64) -> Option<&mut FileState> {
        let id = self.id(handle)?;
        self.objs.get_mut(&id).map(|entry| &mut entry.file_state)
    }

    pub(crate) fn note_file_io(&mut self, handle: u64) {
        if let Some(state) = self.file_state_mut(handle) {
            if state.mode & 8 == 0 {
                state.cached_io_initialized = true;
            }
        }
    }

    pub(crate) fn note_file_io_by_id(&mut self, id: ObjId) {
        if let Some(entry) = self.objs.get_mut(&id) {
            if entry.file_state.mode & 8 == 0 {
                entry.file_state.cached_io_initialized = true;
            }
        }
    }

    pub(crate) fn file_mode_by_id(&self, id: ObjId) -> Option<u32> {
        self.objs.get(&id).map(|entry| entry.file_state.mode)
    }
}

/// Windows applies write-through on the retained native file object. The
/// portable mounted-disk implementation commits completed writes explicitly.
pub(crate) fn finish_file_write(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    if mode & 2 != 0 {
        return file.sync_all();
    }
    let _ = (file, mode);
    Ok(())
}
