//! Native vCPU ownership retained independently of the public VM handle.
use super::MemoryOwner;
use kvm_ioctls::{SyncReg, VcpuExit, VcpuFd};
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

/// A native CPU and the VM/RAM owner required for its entire lifetime.
/// Immutable native ioctl methods remain available through Deref. Mutable
/// operations are forwarded explicitly so safe code cannot replace the inner
/// FD and detach it from its backing owner. There is no consuming raw escape.
///
/// ```compile_fail
/// fn detach(cpu: &mut rax::backend::kvm::OwnedVcpuFd) {
///     let _: &mut kvm_ioctls::VcpuFd = &mut **cpu;
/// }
/// ```
pub struct OwnedVcpuFd {
    // Field drop order is intentional: close the CPU and its run mapping
    // before releasing the VM and all backing retained by its memory slots.
    native: VcpuFd,
    _owner: Arc<MemoryOwner>,
}

impl OwnedVcpuFd {
    pub(super) fn new(native: VcpuFd, owner: Arc<MemoryOwner>) -> Self {
        Self {
            native,
            _owner: owner,
        }
    }

    pub fn run(&mut self) -> std::result::Result<VcpuExit<'_>, kvm_ioctls::Error> {
        self.native.run()
    }

    pub fn get_kvm_run(&mut self) -> &mut kvm_bindings::kvm_run {
        self.native.get_kvm_run()
    }

    pub fn set_kvm_immediate_exit(&mut self, value: u8) {
        self.native.set_kvm_immediate_exit(value);
    }

    pub fn set_sync_valid_reg(&mut self, register: SyncReg) {
        self.native.set_sync_valid_reg(register);
    }

    pub fn set_sync_dirty_reg(&mut self, register: SyncReg) {
        self.native.set_sync_dirty_reg(register);
    }

    pub fn clear_sync_valid_reg(&mut self, register: SyncReg) {
        self.native.clear_sync_valid_reg(register);
    }

    pub fn clear_sync_dirty_reg(&mut self, register: SyncReg) {
        self.native.clear_sync_dirty_reg(register);
    }

    pub fn sync_regs_mut(&mut self) -> &mut kvm_bindings::kvm_sync_regs {
        self.native.sync_regs_mut()
    }

    pub fn map_coalesced_mmio_ring(&mut self) -> std::result::Result<(), kvm_ioctls::Error> {
        self.native.map_coalesced_mmio_ring()
    }

    pub fn coalesced_mmio_read(
        &mut self,
    ) -> std::result::Result<Option<kvm_bindings::kvm_coalesced_mmio>, kvm_ioctls::Error> {
        self.native.coalesced_mmio_read()
    }
}

impl std::fmt::Debug for OwnedVcpuFd {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedVcpuFd")
            .field("native", &self.native)
            .finish_non_exhaustive()
    }
}

impl Deref for OwnedVcpuFd {
    type Target = VcpuFd;

    fn deref(&self) -> &Self::Target {
        &self.native
    }
}

impl AsRawFd for OwnedVcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.native.as_raw_fd()
    }
}
