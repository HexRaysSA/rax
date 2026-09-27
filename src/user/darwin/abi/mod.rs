//! The XNU user-space ABI: system-call conventions, numbering, and the
//! machine parameters a Darwin process observes.
//!
//! [`tables`] is generated from the vendored XNU 12377.121.6 sources by
//! `tools/darwin/gen_abi.py`; the rest of this module describes how a
//! machine's registers carry a call (`bsd/dev/{arm,i386}/systemcalls.c`,
//! `osfmk/arm64/sleh.c`, `osfmk/x86_64/idt64.s`).

pub mod errno;
pub mod tables;
pub mod types;

use crate::user::image::macho::{self, HostCpu};

pub use errno::Errno;

/// How a BSD system call's success value reaches the caller's registers
/// (`sy_return_type`, `_SYSCALL_RET_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ret {
    /// `_SYSCALL_RET_NONE`: the result registers are left as they were.
    None,
    /// `_SYSCALL_RET_INT_T`: two sign-extended 32-bit words.
    Int,
    /// `_SYSCALL_RET_UINT_T`: two zero-extended 32-bit words.
    UInt,
    /// `_SYSCALL_RET_OFF_T`.
    Off,
    /// `_SYSCALL_RET_ADDR_T`.
    Addr,
    /// `_SYSCALL_RET_SIZE_T`.
    Size,
    /// `_SYSCALL_RET_SSIZE_T`.
    SSize,
    /// `_SYSCALL_RET_UINT64_T`.
    U64,
}

/// What a `sysent` slot does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A system call.
    Call,
    /// `nosys`: `SIGSYS` to the calling thread and `ENOSYS`.
    Nosys,
    /// `enosys`: `ENOSYS` alone.
    Enosys,
}

/// One `sysent` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BsdSyscall {
    /// The name in `syscalls.c` (without a `sys_` prefix).
    pub name: &'static str,
    /// What the slot does.
    pub kind: Kind,
    /// How the result is returned.
    pub ret: Ret,
    /// Argument count in 64-bit words.
    pub nargs: u8,
}

/// One `mach_trap_table` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachTrap {
    /// The routine; `kern_invalid` for an empty slot.
    pub name: &'static str,
    /// Argument count in 64-bit words.
    pub nargs: u8,
    /// Whether the trap returns a port name (`mach_trap_returns_port`).
    pub returns_port: bool,
}

impl MachTrap {
    /// Whether the slot is empty (`kern_invalid`).
    pub fn is_invalid(&self) -> bool {
        self.name == "kern_invalid"
    }
}

/// The `sysent` entry for `nr`, or `SYS_invalid` (entry 63, `nosys`) for
/// a number past the table, as `unix_syscall` substitutes it.
pub fn bsd_syscall(nr: u32) -> &'static BsdSyscall {
    tables::BSD_SYSCALLS
        .get(nr as usize)
        .unwrap_or(&tables::BSD_SYSCALLS[SYS_INVALID as usize])
}

/// `SYS_invalid`: the slot a number past the table selects.
pub const SYS_INVALID: u32 = 63;

/// The Mach trap `nr`, if the table has that slot.
pub fn mach_trap(nr: u32) -> Option<&'static MachTrap> {
    tables::MACH_TRAPS.get(nr as usize)
}

/// A Darwin process ABI: the machine and its conventions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DarwinAbi {
    /// x86-64 (`CPU_TYPE_X86_64`) on an Intel Mac.
    X86_64,
    /// arm64 (`CPU_TYPE_ARM64`) on an Apple silicon Mac.
    Arm64,
}

/// x86-64 system-call classes (`osfmk/mach/i386/syscall_sw.h`).
pub mod class {
    /// `SYSCALL_CLASS_SHIFT`.
    pub const SHIFT: u32 = 24;
    /// `SYSCALL_CLASS_MACH`.
    pub const MACH: u32 = 1;
    /// `SYSCALL_CLASS_UNIX`.
    pub const UNIX: u32 = 2;
    /// `SYSCALL_CLASS_MDEP`.
    pub const MDEP: u32 = 3;
    /// `SYSCALL_CLASS_DIAG`.
    pub const DIAG: u32 = 4;
}

/// arm64 `svc` selector for the platform calls (`PLATFORM_SYSCALL_TRAP_NO`).
pub const PLATFORM_SYSCALL_TRAP_NO: u32 = 0x8000_0000;
/// arm64 fast trap: `mach_absolute_time` (`MACH_ARM_TRAP_ABSTIME`).
pub const MACH_ARM_TRAP_ABSTIME: i32 = -3;
/// arm64 fast trap: `mach_continuous_time` (`MACH_ARM_TRAP_CONTTIME`).
pub const MACH_ARM_TRAP_CONTTIME: i32 = -4;

impl DarwinAbi {
    /// Every supported ABI.
    pub const ALL: [DarwinAbi; 2] = [DarwinAbi::X86_64, DarwinAbi::Arm64];

    /// The `uname -m`/`hw.machine` spelling.
    pub fn name(self) -> &'static str {
        match self {
            DarwinAbi::X86_64 => "x86_64",
            DarwinAbi::Arm64 => "arm64",
        }
    }

    /// The machine the emulated kernel runs on, for image grading.
    pub fn host_cpu(self) -> HostCpu {
        match self {
            DarwinAbi::X86_64 => HostCpu::X86_64H,
            DarwinAbi::Arm64 => HostCpu::ARM64E,
        }
    }

    /// The ABI of a Mach-O CPU type.
    pub fn from_cputype(cputype: u32) -> Option<Self> {
        match cputype {
            macho::CPU_TYPE_X86_64 => Some(DarwinAbi::X86_64),
            macho::CPU_TYPE_ARM64 => Some(DarwinAbi::Arm64),
            _ => None,
        }
    }

    /// The kernel's page size: 4 KiB on Intel, 16 KiB on Apple silicon.
    pub fn page_size(self) -> u64 {
        self.host_cpu().page_size()
    }

    /// The page size user processes see (`vm_page_size`): 16 KiB for
    /// 64-bit processes on Apple silicon.
    pub fn user_page_size(self) -> u64 {
        self.page_size()
    }

    /// `MACH_VM_MAX_ADDRESS`: the top of the user address space.
    pub fn max_address(self) -> u64 {
        match self {
            // osfmk/mach/i386/vm_param.h: 0x00007FFFFFE00000.
            DarwinAbi::X86_64 => 0x0000_7FFF_FFE0_0000,
            // The arm64 user address space ends below the commpage
            // nesting region's end on macOS (MACH_VM_MAX_ADDRESS_RAW).
            DarwinAbi::Arm64 => 0x0000_7FFF_FE00_0000,
        }
    }

    /// Base of the commpage (`_COMM_PAGE64_BASE_ADDRESS`).
    pub fn commpage_base(self) -> u64 {
        match self {
            DarwinAbi::X86_64 => 0x0000_7FFF_FFE0_0000,
            DarwinAbi::Arm64 => 0x0000_000F_FFFF_C000,
        }
    }

    /// The shared region's default base (`SHARED_REGION_BASE_*` in
    /// `osfmk/mach/shared_region.h`). A cache names its own base and size,
    /// which is what the region takes: macOS 27's arm64e cache spans
    /// 0x1_cb0f_8000 bytes, more than the 6 GiB `SHARED_REGION_SIZE_ARM64`
    /// of XNU 12377.
    pub fn shared_region_base(self) -> u64 {
        match self {
            DarwinAbi::X86_64 => 0x0000_7FF8_0000_0000,
            DarwinAbi::Arm64 => 0x0000_0001_8000_0000,
        }
    }
}
