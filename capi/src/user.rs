//! User-mode (process-level) execution, `RAX_MODE_USER` (ABI 1.5).
//!
//! A user-mode engine runs guest code unprivileged — x86-64 CPL 3 (64-bit or
//! compatibility mode), AArch64 EL0, RV64 U-mode — while the embedder plays
//! the operating system. Mapped regions become the process address space:
//! every guest access is checked against the region's `RAX_PROT_*` bits,
//! system-call instructions stop with `RAX_STOP_SYSCALL` or call a syscall
//! hook, and exceptions are reported with `RAX_STOP_EXCEPTION` and the typed
//! record [`rax_emu_last_exception`] returns, instead of being delivered
//! through guest vector tables that user mode does not have.

use std::sync::RwLock;

use rax_engine::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use rax_engine::memory::FlatTranslation;

use crate::engine::{Engine, engine_ref};
use crate::mem::{RAX_PROT_EXEC, RAX_PROT_READ, RAX_PROT_WRITE};
use crate::{RaxStatus, guard};

// System-call instruction classes. Mirror `RAX_SYSCALL_INSN_*` in `rax.h`.
/// x86 `SYSCALL` (RCX and R11 hold the architectural save values).
pub const RAX_SYSCALL_INSN_SYSCALL: u32 = 1;
/// x86 `SYSENTER` (no register was modified).
pub const RAX_SYSCALL_INSN_SYSENTER: u32 = 2;
/// AArch64 `SVC #imm16`.
pub const RAX_SYSCALL_INSN_SVC: u32 = 3;
/// RISC-V `ECALL`.
pub const RAX_SYSCALL_INSN_ECALL: u32 = 4;

// Typed exception record. Mirror `RAX_EXCEPTION_*` in `rax.h`.
pub const RAX_EXCEPTION_INFO_VERSION: u32 = 1;
/// The last run/step reported an exception.
pub const RAX_EXCEPTION_VALID: u32 = 1 << 0;
/// `syndrome` holds architectural detail.
pub const RAX_EXCEPTION_SYNDROME: u32 = 1 << 1;
/// Raised by an instruction whose purpose is to raise it (x86 `INT n`,
/// `INT3`, `INTO`; AArch64 `BRK`; RISC-V `EBREAK`).
pub const RAX_EXCEPTION_SOFTWARE: u32 = 1 << 2;

/// Mirrors `rax_exception_info` in `rax.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaxExceptionInfo {
    pub struct_size: u32,
    pub version: u32,
    /// x86 IDT vector; AArch64 `ESR_EL1.EC`; RISC-V `mcause`.
    pub vector: u32,
    pub flags: u32,
    /// The instruction that raised the exception.
    pub pc: u64,
    /// The architectural return address, which the PC holds after the report.
    pub return_pc: u64,
    /// x86 error code; AArch64 `ESR_EL1.ISS`; RISC-V `mtval`.
    pub syndrome: u64,
}

impl Default for RaxExceptionInfo {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            version: RAX_EXCEPTION_INFO_VERSION,
            vector: 0,
            flags: 0,
            pc: 0,
            return_pc: 0,
            syndrome: 0,
        }
    }
}

/// The user-mode address space: an identity mapping of the engine's regions
/// that enforces their `RAX_PROT_*` permissions. Every user-mode core
/// consults it one 4 KiB page at a time.
#[derive(Debug, Default)]
pub(crate) struct RegionTranslation {
    /// `(base, size, perms)`, sorted by base and non-overlapping.
    regions: RwLock<Vec<(u64, u64, u32)>>,
}

impl RegionTranslation {
    pub(crate) fn new(specs: Vec<(u64, u64, u32)>) -> Self {
        let translation = Self::default();
        translation.set(specs);
        translation
    }

    /// Replaces the mapping. `specs` must be non-overlapping.
    pub(crate) fn set(&self, mut specs: Vec<(u64, u64, u32)>) {
        specs.sort_by_key(|&(base, _, _)| base);
        *self
            .regions
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = specs;
    }
}

impl FlatTranslation for RegionTranslation {
    fn translate(&self, linear: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        let regions = self
            .regions
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let index = regions.partition_point(|&(base, _, _)| base <= linear);
        let Some(&(base, size, perms)) = index.checked_sub(1).map(|i| &regions[i]) else {
            return Err(GuestMemoryFault::unmapped(linear, 0, access));
        };
        if linear - base >= size {
            return Err(GuestMemoryFault::unmapped(linear, 0, access));
        }
        let need = match access {
            MemoryAccessKind::Read => RAX_PROT_READ,
            MemoryAccessKind::Write => RAX_PROT_WRITE,
            MemoryAccessKind::Fetch => RAX_PROT_EXEC,
        };
        if perms & need == 0 {
            return Err(GuestMemoryFault {
                address: linear,
                size: 0,
                access,
                kind: MemoryFaultKind::Permission,
            });
        }
        Ok(linear)
    }
}

/// Copies the exception the last run or step reported into `out`, whose
/// `struct_size`/`version` header the caller initializes. Like
/// `rax_emu_last_fault`, NULL and short records return `RAX_ERR_ARG` and an
/// unknown version `RAX_ERR_UNSUPPORTED`, leaving `out` unchanged; exactly
/// the v1 bytes are written.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_last_exception(
    engine: *const Engine,
    out: *mut RaxExceptionInfo,
) -> RaxStatus {
    guard(|| {
        let Some(engine) = (unsafe { engine_ref(engine) }) else {
            return RaxStatus::Handle;
        };
        if out.is_null() {
            return RaxStatus::Arg;
        }
        // SAFETY: the caller supplies writable, aligned storage whose
        // initialized header describes at least one v1 record; the header is
        // validated before the record is written and no reference escapes.
        unsafe {
            if (*out).struct_size < std::mem::size_of::<RaxExceptionInfo>() as u32 {
                return RaxStatus::Arg;
            }
            if (*out).version != RAX_EXCEPTION_INFO_VERSION {
                return RaxStatus::Unsupported;
            }
            out.write(engine.last_exception);
        }
        RaxStatus::Ok
    })
}

/// Version of the typed system-call record.
pub const RAX_SYSCALL_INFO_VERSION: u32 = 1;
/// A system call was observed in the current or most recent run/step.
pub const RAX_SYSCALL_VALID: u32 = 1;

/// Mirrors `rax_syscall_info`; captured before calling the embedder's hook.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaxSyscallInfo {
    pub struct_size: u32,
    pub version: u32,
    pub flags: u32,
    pub instruction: u32,
    pub pc: u64,
    pub resume_pc: u64,
    pub size: u32,
    pub immediate: u32,
}

impl Default for RaxSyscallInfo {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            version: RAX_SYSCALL_INFO_VERSION,
            flags: 0,
            instruction: 0,
            pc: 0,
            resume_pc: 0,
            size: 0,
            immediate: 0,
        }
    }
}

/// Copies the last system call of this run/step, including hook-serviced calls.
/// The caller initializes the size/version header; failures leave it unchanged.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_last_syscall(
    engine: *const Engine,
    out: *mut RaxSyscallInfo,
) -> RaxStatus {
    guard(|| {
        let Some(engine) = (unsafe { engine_ref(engine) }) else {
            return RaxStatus::Handle;
        };
        if out.is_null() {
            return RaxStatus::Arg;
        }
        // SAFETY: the caller provides aligned writable storage of its declared
        // size. Read only the header before checking the supported record size.
        unsafe {
            if (*out).struct_size < std::mem::size_of::<RaxSyscallInfo>() as u32 {
                return RaxStatus::Arg;
            }
            if (*out).version != RAX_SYSCALL_INFO_VERSION {
                return RaxStatus::Unsupported;
            }
            out.write(engine.last_syscall);
        }
        RaxStatus::Ok
    })
}
