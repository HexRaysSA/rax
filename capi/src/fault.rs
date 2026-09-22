//! Typed execution faults. Querying diagnostics never clears the underlying error.
use crate::engine::{Engine, engine_ref};
use crate::{RaxStatus, guard};
use rax_engine::error::{Error, MemoryAccessKind, MemoryFaultKind};

pub const RAX_FAULT_INFO_VERSION: u32 = 1;
pub const RAX_FAULT_NONE: u32 = 0;
pub const RAX_FAULT_UNMAPPED: u32 = 1;
pub const RAX_FAULT_PERMISSION: u32 = 2;
pub const RAX_FAULT_INVALID_INSTRUCTION: u32 = 3;
pub const RAX_FAULT_OTHER: u32 = 4;
pub const RAX_FAULT_ACCESS_NONE: u32 = 0;
pub const RAX_FAULT_ACCESS_READ: u32 = 1;
pub const RAX_FAULT_ACCESS_WRITE: u32 = 2;
pub const RAX_FAULT_ACCESS_FETCH: u32 = 3;
pub const RAX_FAULT_ADDRESS_VALID: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RaxFaultInfo {
    pub struct_size: u32,
    pub version: u32,
    pub kind: u32,
    pub access: u32,
    pub pc: u64,
    pub address: u64,
    pub size: u32,
    pub flags: u32,
    pub retired_instructions: u64,
}
impl Default for RaxFaultInfo {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            version: RAX_FAULT_INFO_VERSION,
            kind: RAX_FAULT_NONE,
            access: RAX_FAULT_ACCESS_NONE,
            pc: 0,
            address: 0,
            size: 0,
            flags: 0,
            retired_instructions: 0,
        }
    }
}
impl RaxFaultInfo {
    pub(crate) fn from_error(pc: u64, error: &Error) -> Self {
        let mut info = Self {
            pc,
            kind: RAX_FAULT_OTHER,
            ..Self::default()
        };
        match error {
            Error::FaultDelivery { fault, .. } => return Self::from_error(pc, fault),
            Error::GuestAccess(fault) => {
                info.kind = match fault.kind {
                    MemoryFaultKind::Unmapped => RAX_FAULT_UNMAPPED,
                    MemoryFaultKind::Permission => RAX_FAULT_PERMISSION,
                    MemoryFaultKind::Other => RAX_FAULT_OTHER,
                };
                info.access = match fault.access {
                    MemoryAccessKind::Read => RAX_FAULT_ACCESS_READ,
                    MemoryAccessKind::Write => RAX_FAULT_ACCESS_WRITE,
                    MemoryAccessKind::Fetch => RAX_FAULT_ACCESS_FETCH,
                };
                info.address = fault.address;
                info.size = fault.size;
                info.flags = RAX_FAULT_ADDRESS_VALID;
            }
            // Guest page-table faults are not missing host backing. An embedder
            // must not map physical memory using this virtual address.
            Error::PageFault { vaddr, error_code } => {
                info.kind = if error_code & 1 != 0 {
                    RAX_FAULT_PERMISSION
                } else {
                    RAX_FAULT_OTHER
                };
                info.address = *vaddr;
                info.flags = RAX_FAULT_ADDRESS_VALID;
                info.access = if error_code & 0x10 != 0 {
                    RAX_FAULT_ACCESS_FETCH
                } else if error_code & 2 != 0 {
                    RAX_FAULT_ACCESS_WRITE
                } else {
                    RAX_FAULT_ACCESS_READ
                };
            }
            Error::GeneralProtection { .. } => info.kind = RAX_FAULT_PERMISSION,
            Error::InvalidInstruction { pc, .. } => {
                info.kind = RAX_FAULT_INVALID_INSTRUCTION;
                info.pc = *pc;
            }
            _ => {}
        }
        info
    }
}

/// `out` must point to writable storage whose initialized size/version header
/// describes at least one v1 record. Only the v1 bytes are written; a future
/// caller's tail remains untouched. NULL, short buffers, and unknown versions
/// fail without modifying the caller's output or the stored execution fault.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_last_fault(engine: *const Engine, out: *mut RaxFaultInfo) -> RaxStatus {
    guard(|| {
        // SAFETY: the C API requires a valid handle and, when non-NULL, aligned
        // caller-owned storage for the declared record. Validate the header
        // before writing the v1 record; no reference escapes this call.
        let Some(engine) = (unsafe { engine_ref(engine) }) else {
            return RaxStatus::Handle;
        };
        if out.is_null() {
            return RaxStatus::Arg;
        }
        unsafe {
            if (*out).struct_size < std::mem::size_of::<RaxFaultInfo>() as u32 {
                return RaxStatus::Arg;
            }
            if (*out).version != RAX_FAULT_INFO_VERSION {
                return RaxStatus::Unsupported;
            }
            out.write(engine.last_fault);
        }
        RaxStatus::Ok
    })
}
