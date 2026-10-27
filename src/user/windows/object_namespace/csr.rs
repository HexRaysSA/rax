//! Matched CSR metadata and a private server address space, without host IPC.
use super::{DataSection, LookupError, Namespace, SelectedSection, invalid};
use crate::user::mm::{AddressSpace, SharedObject, SpaceConfig};
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::{Mem, VirtualMemory, VmError, mem, prot};
use crate::user::windows::objects::{LpcPort, Object, Objects};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) mod client_data;
pub(crate) mod pid_export;

/// Measured CSR build set. Callers also bind ARM64/session0 and the exact
/// selected section, peer, packet and readonly view identities. O(1).
pub(crate) fn supports_kernel(major: u32, minor: u32, build: u32) -> bool {
    major == 10 && minor == 0 && matches!(build, 29683 | 29695)
}

pub(crate) fn supports_profile(arch: WinArch, major: u32, minor: u32, build: u32) -> bool {
    match arch {
        WinArch::Arm64 => supports_kernel(major, minor, build),
        WinArch::X64 => major == 10 && minor == 0 && matches!(build, 20348 | 26100),
        WinArch::X86 => false,
    }
}

/// Native server pointers remain protocol address values; the selected
/// readonly section supplies their bytes independently at a guest-owned base.
#[derive(Debug, Clone)]
pub(crate) struct CsrMetadata {
    pub(crate) arch: WinArch,
    /// Independently captured native kernel; guest PEB version edits cannot
    /// admit a different bridge layout or server protocol.
    pub(crate) kernel: (u32, u32, u32),
    pub(crate) session: u32,
    pub(crate) server_base: u64,
    pub(crate) statics_offset: u64,
    pub(crate) server_pid: u32,
}

impl CsrMetadata {
    fn supported(&self) -> bool {
        supports_profile(self.arch, self.kernel.0, self.kernel.1, self.kernel.2)
            && (self.arch != WinArch::Arm64 || self.session == 0)
    }

    fn namespace_session(&self) -> Option<u32> {
        (self.session != 0).then_some(self.session)
    }

    fn port_path(&self) -> Vec<u16> {
        match self.namespace_session() {
            Some(session) => format!("\\Sessions\\{session}\\Windows\\ApiPort")
                .encode_utf16()
                .collect(),
            None => "\\Windows\\ApiPort".encode_utf16().collect(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CsrServer {
    pub(crate) metadata: CsrMetadata,
    section: Arc<DataSection>,
    connections: Arc<AtomicU32>,
    pub(crate) client_data: Option<Arc<client_data::CsrClientData>>,
}

impl CsrServer {
    pub(crate) fn section(&self) -> Arc<DataSection> {
        self.section.clone()
    }

    pub(crate) fn selected(
        section: Arc<DataSection>,
        metadata: CsrMetadata,
    ) -> io::Result<Arc<Self>> {
        Self::selected_with_client_data(section, metadata, None)
    }

    pub(crate) fn selected_with_client_data(
        section: Arc<DataSection>,
        metadata: CsrMetadata,
        client_data: Option<Arc<client_data::CsrClientData>>,
    ) -> io::Result<Arc<Self>> {
        let prefix = section
            .regions
            .first()
            .and_then(|region| region.bytes.as_ref())
            .ok_or_else(|| invalid("CSR metadata has no committed prefix"))?;
        let server_end = metadata.server_base.checked_add(section.size);
        let statics = metadata.statics_offset.checked_add(8);
        if !metadata.supported()
            || section.size != 1 << 20
            || section.regions.len() != 2
            || section.regions[0].size != 5 * 4096
            || section.regions[1].bytes.is_some()
            || metadata.server_pid == 0
            || metadata.server_pid % 4 != 0
            || metadata.server_base == 0
            || metadata.server_base % 65536 != 0
            || server_end.is_none_or(|end| end > 1 << 47)
            || metadata.statics_offset != 0x750
            || statics.is_none_or(|end| end > prefix.len() as u64)
            || prefix.get(40..48) != Some(metadata.server_base.to_le_bytes().as_slice())
            || prefix.get(48..56) != Some(metadata.server_base.to_le_bytes().as_slice())
        {
            return Err(invalid(
                "CSR metadata differs from selected native section profile",
            ));
        }
        Ok(Arc::new(Self {
            metadata,
            section,
            connections: Arc::new(AtomicU32::new(0)),
            client_data,
        }))
    }

    /// A separate modeled server maps the real pagefile backing and selected
    /// readonly section. No address in the host's CSR process is dereferenced.
    /// The server mapping owns a typed peer endpoint until this connection ends.
    pub(crate) fn peer(&self, backing: Arc<SharedObject>, size: u64) -> Result<CsrPeer, VmError> {
        self.connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                if count < 32 { Some(count + 1) } else { None }
            })
            .map_err(|_| VmError::NoMemory)?;
        let lease = ConnectionLease(self.connections.clone());
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 1 << 20,
            reserved_phys: vec![],
        })
        .map_err(|_| VmError::NoMemory)?;
        let mut vm = VirtualMemory::new(space, 65536, 1 << 47);
        vm.map_data_section(
            self.section.clone(),
            self.metadata.server_base,
            0,
            self.section.size,
            prot::READONLY,
        )?;
        let view = vm.map_shared_view(backing, Some(0x1_0000_0000), 0, size)?;
        let base = view.base;
        let mut objects = Objects::default();
        let id = objects
            .try_create(Object::LpcPort(LpcPort::new(Some(view))))
            .ok_or(VmError::NoMemory)?;
        let handle = objects
            .open_access(id, false, 0x001F_0001)
            .ok_or(VmError::NoMemory)?;
        // These are modeled server identities, not handles to host processes.
        // The private server owns the records for the lifetime of this peer.
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
        Ok(CsrPeer {
            vm,
            objects,
            handle,
            base,
            client_data: self.client_data.clone(),
            server_pid: self.metadata.server_pid,
            server_thread,
            next_message: 1,
            capture_storage: None,
            _lease: lease,
        })
    }
}

/// The server side of one connection, isolated from the caller address space.
/// Dropping the connection releases its entire private server VM/object table.
pub(crate) struct CsrPeer {
    pub(crate) vm: VirtualMemory,
    objects: Objects,
    handle: u32,
    pub(crate) base: u64,
    pub(crate) client_data: Option<Arc<client_data::CsrClientData>>,
    pub(crate) server_pid: u32,
    pub(crate) server_thread: u32,
    next_message: u32,
    capture_storage: Option<u64>,
    _lease: ConnectionLease,
}

impl CsrPeer {
    /// Bounded private server storage for one synchronous CSR capture. Each
    /// peer reuses one page and one increasing message identifier; neither
    /// address nor identity is acquired from a host server process.
    pub(crate) fn prepare_capture(
        &mut self,
        header: &[u8; 40],
        information: &[u8; client_data::INFORMATION_BYTES],
    ) -> Result<(u64, u32), VmError> {
        let next = self.next_message.checked_add(1).ok_or(VmError::NoMemory)?;
        let (base, newly_allocated) = match self.capture_storage {
            Some(base) => (base, false),
            None => (
                self.vm
                    .allocate(
                        Some(0x2_0000_0000),
                        4096,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )?
                    .0,
                true,
            ),
        };
        let mut bytes = [0; 628];
        bytes[..40].copy_from_slice(header);
        bytes[8..16].fill(0);
        bytes[40..40 + information.len()].copy_from_slice(information);
        if self.vm.space().wr(base, &bytes).is_err() {
            if newly_allocated {
                self.vm.release(base)?;
            }
            return Err(VmError::NoMemory);
        }
        self.capture_storage = Some(base);
        let message = self.next_message;
        self.next_message = next;
        Ok((base, message))
    }
}
struct ConnectionLease(Arc<AtomicU32>);
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
impl std::fmt::Debug for CsrPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrPeer")
            .field("base", &self.base)
            .field("handle", &self.handle)
            .field("handles", &self.objects.handle_count())
            .field("committed-bytes", &self.vm.committed_bytes())
            .finish()
    }
}

impl Namespace {
    pub(crate) fn select_csr_server(&mut self, server: Arc<CsrServer>) -> io::Result<()> {
        if self.csr_server.is_some() {
            return Err(invalid("CSR server selection is immutable"));
        }
        let name = server.metadata.port_path();
        self.lookup_port(&name)
            .map_err(|_| invalid("selected CSR port entry is absent"))?;
        let name = DataSection::path_for_session(server.metadata.namespace_session());
        match self.lookup_installed_section(None, &name, 0, false) {
            Ok(SelectedSection::Data(section)) if Arc::ptr_eq(&section, &server.section) => {}
            _ => {
                return Err(invalid(
                    "CSR server and namespace section identities differ",
                ));
            }
        }
        self.csr_server = Some(server);
        Ok(())
    }

    pub(crate) fn csr_server(&self, name: &[u16]) -> Result<Arc<CsrServer>, LookupError> {
        self.lookup_port(name)?;
        let server = self.csr_server.clone().ok_or(LookupError::Unselected)?;
        if name != server.metadata.port_path() {
            return Err(LookupError::Unselected);
        }
        Ok(server)
    }
}
