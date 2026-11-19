//! The selected process window station and its borrowed guest handle.
use super::{Object, Objects};
use std::io;
use std::sync::Arc;

/// Installed metadata for the assigned station. The host handle remains private
/// to the native observer and is never represented in the guest handle table.
#[derive(Debug, PartialEq, Eq)]
pub struct WindowStation {
    pub(crate) name: Box<[u16]>,
    pub(crate) access: u32,
    pub(crate) handle_flags: u32,
    pub(crate) user_flags: u32,
    pub(crate) sid: Box<[u8]>,
}

impl WindowStation {
    pub(crate) fn selected(
        name: Vec<u16>,
        access: u32,
        handle_flags: u32,
        user_flags: u32,
        sid: Vec<u8>,
    ) -> io::Result<Arc<Self>> {
        let valid_sid = sid.is_empty()
            || (sid.len() >= 8
                && sid[0] == 1
                && sid[1] <= 15
                && sid.len() == 8 + 4 * usize::from(sid[1]));
        if name.is_empty()
            || name.len() > 1023
            || name.contains(&0)
            || handle_flags & !3 != 0
            || !valid_sid
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid selected window station metadata",
            ));
        }
        Ok(Arc::new(Self {
            name: name.into(),
            access,
            handle_flags,
            user_flags,
            sid: sid.into(),
        }))
    }
}

impl Objects {
    pub(crate) fn assign_window_station(&mut self, station: Arc<WindowStation>) -> Option<u32> {
        if self.window_station.is_some() {
            return self.window_station_handle(&station);
        }
        let flags = station.handle_flags;
        let access = station.access;
        let id = self.try_create(Object::WindowStation(station))?;
        let Some(handle) = self.open_access(id, flags & 1 != 0, access) else {
            self.release(id);
            return None;
        };
        self.set_flags(u64::from(handle), 3, flags);
        self.window_station = Some((id, handle));
        Some(handle)
    }

    pub(crate) fn window_station_handle(&self, station: &Arc<WindowStation>) -> Option<u32> {
        let (id, handle) = self.window_station?;
        (self.id(u64::from(handle)) == Some(id)
            && matches!(self.obj(id), Some(Object::WindowStation(selected)) if Arc::ptr_eq(selected, station)))
        .then_some(handle)
    }

    pub(crate) fn assigned_window_station_handle(&self, handle: u64) -> bool {
        self.window_station.is_some_and(|(id, assigned)| {
            Self::key(handle) == Some(assigned) && self.id(handle) == Some(id)
        })
    }

    pub(crate) fn attached_user_handle(&self, handle: u64) -> bool {
        self.assigned_desktop_handle(handle) || self.assigned_window_station_handle(handle)
    }
}
