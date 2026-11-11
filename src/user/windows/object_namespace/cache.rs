//! Selected translation-cache service with an isolated, guest-owned peer.
use super::{LookupError, Namespace, invalid};
use crate::user::mm::{AddressSpace, SharedObject, SpaceConfig};
use crate::user::windows::memory::{VirtualMemory, VmError};
use crate::user::windows::objects::{LpcPort, Object, Objects};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) const PORT_NAME: &str = "\\{BEC19D6F-D7B2-41A8-860C-8787BB964F2D}";
pub(crate) const SECTION_BYTES: u64 = 65536;
pub(crate) const LOOKUP_ACCESS: u32 = 0xa1;
pub(crate) const SERVICE_SID: [u8; 32] = [
    1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 226, 171, 119, 216, 188, 124, 30, 146, 72, 114, 14, 244,
    131, 25, 194, 1, 84, 253, 208, 30,
];

pub(crate) fn server_security() -> [u8; 100] {
    let mut descriptor = [0; 100];
    descriptor[..4].copy_from_slice(&[1, 0, 0x14, 0x80]);
    descriptor[12..16].copy_from_slice(&20u32.to_le_bytes());
    descriptor[16..20].copy_from_slice(&52u32.to_le_bytes());
    descriptor[20..52].copy_from_slice(&[
        2, 0, 32, 0, 1, 0, 0, 0, 20, 0, 24, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 19, 0, 2, 0, 0, 0,
        16, 0, 0,
    ]);
    descriptor[52..68].copy_from_slice(&[2, 0, 48, 0, 1, 0, 0, 0, 0, 0, 40, 0, 1, 0, 0, 0]);
    descriptor[68..].copy_from_slice(&SERVICE_SID);
    descriptor
}

pub(crate) fn lookup_request() -> [u8; 80] {
    let mut message = [0; 80];
    message[..4].copy_from_slice(&[40, 0, 80, 0]);
    message[40] = 2;
    message
}

/// Captured service identity is immutable and independent of guest PEB edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheMetadata {
    pub(crate) kernel: (u32, u32, u32),
    pub(crate) native_machine: u16,
    pub(crate) server_pid: u32,
}

#[derive(Debug)]
pub(crate) struct CacheServer {
    pub(crate) metadata: CacheMetadata,
    connections: Arc<AtomicU32>,
    next_message: Arc<AtomicU32>,
}

impl CacheServer {
    pub(crate) fn selected(metadata: CacheMetadata) -> io::Result<Arc<Self>> {
        if metadata.kernel != (10, 0, 29704)
            || metadata.native_machine != 0xAA64
            || metadata.server_pid == 0
            || metadata.server_pid % 4 != 0
        {
            return Err(invalid("translation-cache service profile is not measured"));
        }
        Ok(Arc::new(Self {
            metadata,
            connections: Arc::new(AtomicU32::new(0)),
            next_message: Arc::new(AtomicU32::new(1)),
        }))
    }

    /// The peer maps its own writable pagefile backing. Transferred client
    /// handles and mappings retain the backing independently of this endpoint.
    /// O(P) backing initialization and O(P log P) VM metadata for P pages.
    pub(crate) fn peer(&self) -> Result<CachePeer, VmError> {
        self.connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < 32).then_some(count + 1)
            })
            .map_err(|_| VmError::NoMemory)?;
        let lease = ConnectionLease(self.connections.clone());
        let connection_message = self
            .next_message
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| VmError::NoMemory)?;
        let backing =
            Arc::new(SharedObject::anonymous(SECTION_BYTES).map_err(|_| VmError::NoMemory)?);
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 1 << 20,
            reserved_phys: vec![],
        })
        .map_err(|_| VmError::NoMemory)?;
        let mut vm = VirtualMemory::new(space, 65536, 1 << 47);
        let view = vm.map_shared_view(backing.clone(), Some(0x1_0000_0000), 0, SECTION_BYTES)?;
        let base = view.base;
        let mut objects = Objects::default();
        let endpoint = objects
            .try_create(Object::LpcPort(LpcPort::new(Some(view))))
            .ok_or(VmError::NoMemory)?;
        let handle = objects
            .open_access(endpoint, false, 0x001F_0001)
            .ok_or(VmError::NoMemory)?;
        objects
            .try_create(Object::Process {
                pid: self.metadata.server_pid,
                exit_code: None,
            })
            .ok_or(VmError::NoMemory)?;
        let server_thread = 4;
        objects
            .try_create(Object::Thread {
                tid: server_thread,
                exit_code: None,
            })
            .ok_or(VmError::NoMemory)?;
        Ok(CachePeer {
            vm,
            objects,
            handle,
            base,
            backing,
            server_pid: self.metadata.server_pid,
            server_thread,
            connection_message,
            pending_reply: None,
            lookup_slot: 0,
            next_message: self.next_message.clone(),
            _lease: lease,
        })
    }
}

pub(crate) struct CachePeer {
    pub(crate) vm: VirtualMemory,
    objects: Objects,
    handle: u32,
    pub(crate) base: u64,
    pub(crate) backing: Arc<SharedObject>,
    pub(crate) server_pid: u32,
    pub(crate) server_thread: u32,
    pub(crate) connection_message: u32,
    pub(crate) pending_reply: Option<Vec<u8>>,
    pub(crate) lookup_slot: u32,
    next_message: Arc<AtomicU32>,
    _lease: ConnectionLease,
}

impl CachePeer {
    pub(crate) fn next_callback(&self) -> Option<u32> {
        self.next_message
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()
    }
}

pub(crate) fn lookup_file(file: &std::fs::File) -> io::Result<Option<Arc<super::FileSection>>> {
    #[cfg(windows)]
    return super::installed::cache::lookup_file(file);
    #[cfg(not(windows))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed translation-cache lookup requires Windows",
        ))
    }
}

impl std::fmt::Debug for CachePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachePeer")
            .field("base", &self.base)
            .field("handle", &self.handle)
            .field("handles", &self.objects.handle_count())
            .field("committed-bytes", &self.vm.committed_bytes())
            .finish()
    }
}

struct ConnectionLease(Arc<AtomicU32>);
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Namespace {
    pub(crate) fn capture_cache_server(&mut self, kernel: (u32, u32, u32)) -> io::Result<()> {
        #[cfg(windows)]
        {
            super::installed::cache::select(self, kernel)
        }
        #[cfg(not(windows))]
        {
            let _ = kernel;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed translation-cache identity requires Windows",
            ))
        }
    }

    pub(crate) fn select_cache_server(&mut self, server: Arc<CacheServer>) -> io::Result<()> {
        if self.cache_server.is_some()
            || self.native_machine != Some(server.metadata.native_machine)
        {
            return Err(invalid(
                "translation-cache selection conflicts with namespace identity",
            ));
        }
        self.lookup_port(&PORT_NAME.encode_utf16().collect::<Vec<_>>())
            .map_err(|_| invalid("selected translation-cache port is absent"))?;
        self.cache_server = Some(server);
        Ok(())
    }

    pub(crate) fn cache_server(&self, name: &[u16]) -> Result<Arc<CacheServer>, LookupError> {
        self.lookup_port(name)?;
        if !name.iter().copied().eq(PORT_NAME.encode_utf16()) {
            return Err(LookupError::Unselected);
        }
        self.cache_server.clone().ok_or(LookupError::Unselected)
    }
}

#[cfg(test)]
mod tests;
