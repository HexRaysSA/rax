//! Inode and notification state held by a mapping's duplicated host handle.
//! The open description itself must still close independently: retaining it
//! would delay its descriptor-close and record-lock bookkeeping.

use super::OpenFile;
use crate::user::mm::Keep;
use std::sync::Arc;

struct MappingKeep {
    _memfd: Option<Arc<super::super::memfd::Memfd>>,
    #[cfg(unix)]
    _notify: Option<Arc<super::super::super::fsnotify::hub::Token>>,
}

impl OpenFile {
    /// Retain the actual inode seals and notification token, without retaining
    /// this description's cursor, descriptor or close/record-lock lifecycle.
    pub(crate) fn mapping_keep(&self) -> Option<Keep> {
        let needed = self.memfd.is_some();
        #[cfg(unix)]
        let needed = needed || self.notify.get().is_some();
        needed.then(|| {
            Arc::new(MappingKeep {
                _memfd: self.memfd.clone(),
                #[cfg(unix)]
                _notify: self.notify.get().cloned(),
            }) as Keep
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::linux::abi::open::O_RDWR;
    use crate::user::linux::fs::fd::{FileObject, FileType};
    use crate::user::linux::fs::memfd::{Memfd, seal};
    use crate::user::mm::{
        AddressSpace, Backing, EXTENT, Mapping, PAGE_SIZE, Perms, SharedObject, SpaceConfig,
        anonymous_file,
    };

    #[test]
    fn mapping_retains_actual_inode_through_private_snapshot_but_releases_description() {
        let file = anonymous_file().unwrap();
        file.set_len(2 * PAGE_SIZE).unwrap();
        let identity_owner = SharedObject::file(file.try_clone().unwrap(), true).unwrap();
        let identity = identity_owner.identity();
        let inode = Memfd::new(seal::FUTURE_WRITE, false, identity).unwrap();
        let retained = Arc::downgrade(&inode);
        let description = OpenFile::with_memfd(
            FileObject::Host(file),
            FileType::Regular,
            "/memfd:mapped",
            None,
            O_RDWR,
            Some(inode),
        );
        let closed = Arc::downgrade(&description);
        let object = Arc::new(
            SharedObject::file_keeping(
                description.host_file().unwrap().try_clone().unwrap(),
                true,
                description.mapping_keep(),
            )
            .unwrap(),
        );
        assert_eq!(object.identity(), identity);
        drop(identity_owner);
        drop(description);
        assert!(closed.upgrade().is_none(), "the open description closed");
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 30,
            arena_bytes: 8 * EXTENT,
            reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
        })
        .unwrap();
        let address = 0x2_0000;
        space
            .map(
                address,
                2 * PAGE_SIZE,
                Mapping {
                    perms: Perms::READ | Perms::WRITE,
                    backing: Backing::Shared { object, offset: 0 },
                    shared: true,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        let snapshot = space.process_snapshot().unwrap();
        space.unmap(address, 2 * PAGE_SIZE).unwrap();
        drop(space);
        assert!(retained.upgrade().is_some());
        let found = Memfd::find(identity).expect("snapshot retains the actual inode");
        assert_eq!(found.seals(), seal::FUTURE_WRITE);
        assert!(Arc::ptr_eq(&found, &retained.upgrade().unwrap()));
        drop(found);
        snapshot.unmap(address, PAGE_SIZE).unwrap();
        assert!(
            retained.upgrade().is_some(),
            "a remaining VMA holds the inode"
        );
        snapshot.unmap(address + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(
            retained.upgrade().is_none(),
            "the last VMA releases the inode"
        );
        assert!(Memfd::find(identity).is_none());
    }

    #[test]
    fn ordinary_description_needs_no_mapping_state() {
        let file = OpenFile::new(FileObject::PathOnly, FileType::Regular, "/path", None, 0);
        assert!(file.mapping_keep().is_none());
    }
}
