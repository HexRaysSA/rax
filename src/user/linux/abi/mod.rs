//! Linux user ABIs.
//!
//! A [`LinuxAbi`] fixes everything about the kernel interface that depends
//! on the guest architecture: system-call numbering, the address-space
//! layout `binfmt_elf` and `mmap` produce with address-space randomization
//! disabled, flag encodings that differ between architectures, and the
//! layout of structures copied across the system-call boundary. Values cite
//! the Linux 6.19 sources and the UAPI headers vendored in
//! `docs/specifications/linux/uapi-6.19`.

pub mod errno;
pub mod errno_table;
pub mod syscalls;
pub mod types;

pub use syscalls::Sysno;

use crate::user::cpu::Isa;
use crate::user::image::elf::{EM_AARCH64, EM_RISCV, EM_X86_64, ElfClass, ElfData};

/// A 64-bit Linux user ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinuxAbi {
    /// x86-64 (`arch/x86`), the 64-bit SYSCALL ABI.
    X86_64,
    /// AArch64 (`arch/arm64`), little-endian, 4 KiB pages, 48-bit VA.
    Aarch64,
    /// RV64 (`arch/riscv`), with the Sv48 user address-space size.
    Riscv64,
}

/// Page size of every supported ABI configuration, in bytes.
pub const PAGE_SIZE: u64 = 4096;

/// Default `vm.mmap_min_addr` (`CONFIG_DEFAULT_MMAP_MIN_ADDR` on the x86,
/// arm64, and riscv defconfigs): 64 KiB.
pub const MMAP_MIN_ADDR: u64 = 0x10000;

/// Default `RLIMIT_STACK` soft limit (`_STK_LIM`): 8 MiB.
pub const DEFAULT_STACK_LIMIT: u64 = 8 << 20;

/// `stack_guard_gap` default: 256 pages.
pub const STACK_GUARD_GAP: u64 = 256 * PAGE_SIZE;

/// `personality(2)` flag `READ_IMPLIES_EXEC` (`linux/personality.h`):
/// `PROT_READ` in `mmap`/`mprotect` also grants `PROT_EXEC`.
pub const READ_IMPLIES_EXEC: u32 = 0x0040_0000;

/// Linux VMA properties the personality keeps in
/// [`Vma::flags`](crate::user::mm::Vma::flags). Clear bits are the common
/// case, so a mapping created without personality flags behaves like an
/// ordinary Linux VMA with every `VM_MAY*` bit set.
pub mod vma_flags {
    /// `VM_GROWSDOWN`: the main thread's `[stack]`. `mprotect` with
    /// `PROT_GROWSDOWN` extends to its start, and `brk` and `mmap` keep
    /// `stack_guard_gap` below it.
    pub const GROWSDOWN: u32 = 1 << 0;
    /// `VM_MAYWRITE` and `VM_SHARED` clear: a `MAP_SHARED` mapping of a file
    /// not open for writing, which can never become writable (`do_mmap`).
    pub const DENY_WRITE: u32 = 1 << 1;
    /// `VM_READ` clear: the protection lacked `PROT_READ` (`PF_R` for an
    /// ELF segment). The pages may still read in user mode, as write-only
    /// mappings and, where execute implies read, execute-only ones do, but
    /// `/proc/<pid>/maps` shows no `r` and `get_user_pages` refuses to
    /// read them (`check_vma_flags`).
    pub const NO_READ: u32 = 1 << 2;
    /// `VM_LOCKED`: `mlock`, `mlockall`, `MAP_LOCKED`, or `MCL_FUTURE`;
    /// counted in `VmLck`, never dropped by `madvise`.
    pub const LOCKED: u32 = 1 << 3;
    /// `VM_LOCKONFAULT`: locked as pages fault in, not populated at once
    /// (`MLOCK_ONFAULT`, `MCL_ONFAULT`).
    pub const LOCKONFAULT: u32 = 1 << 4;
    /// `VM_LOCKED_MASK`.
    pub const LOCKED_MASK: u32 = LOCKED | LOCKONFAULT;
    /// A special mapping (`VM_DONTEXPAND`, of `_install_special_mapping`
    /// and of an AIO ring): the `[vdso]` page or `/[aio]`. It is never
    /// locked, grown, duplicated, or kept by `MREMAP_DONTUNMAP`.
    pub const SPECIAL: u32 = 1 << 5;
    /// `VM_SEALED` (`mseal`): never unmapped, remapped, reprotected, or
    /// discarded where it could not be written; never unsealed.
    pub const SEALED: u32 = 1 << 6;
    /// An AIO context's ring (`aio_ring_vm_ops`): with [`SPECIAL`] it is
    /// never locked or resized, and moving it moves its context's
    /// identifier (`aio_ring_mremap`).
    pub const AIO_RING: u32 = 1 << 7;
}

impl LinuxAbi {
    /// Every supported ABI.
    pub const ALL: [LinuxAbi; 3] = [LinuxAbi::X86_64, LinuxAbi::Aarch64, LinuxAbi::Riscv64];

    /// The ABI for an ELF machine and class, if supported.
    pub fn from_elf(machine: u16, class: Option<ElfClass>) -> Option<LinuxAbi> {
        match (machine, class) {
            (EM_X86_64, _) => Some(LinuxAbi::X86_64),
            (EM_AARCH64, _) => Some(LinuxAbi::Aarch64),
            // arch/riscv elf_check_arch() also requires ELFCLASS64 for RV64.
            (EM_RISCV, Some(ElfClass::Elf64)) => Some(LinuxAbi::Riscv64),
            _ => None,
        }
    }

    /// The guest ISA.
    pub fn isa(self) -> Isa {
        match self {
            LinuxAbi::X86_64 => Isa::X86_64,
            LinuxAbi::Aarch64 => Isa::Aarch64,
            LinuxAbi::Riscv64 => Isa::Riscv64,
        }
    }

    /// `uname -m`.
    pub fn machine(self) -> &'static str {
        self.isa().name()
    }

    /// The ELF machine this ABI executes.
    pub fn elf_machine(self) -> u16 {
        match self {
            LinuxAbi::X86_64 => EM_X86_64,
            LinuxAbi::Aarch64 => EM_AARCH64,
            LinuxAbi::Riscv64 => EM_RISCV,
        }
    }

    /// The native ELF class and data encoding the kernel decodes with.
    pub fn elf_encoding(self) -> (ElfClass, ElfData) {
        (ElfClass::Elf64, ElfData::Lsb)
    }

    /// The system call the number register `nr` selects: x86-64 and
    /// arm64 read the register as an `int` (`do_syscall_64`,
    /// `el0_svc_common`), RV64 as a `long` (`do_trap_ecall_u`).
    pub fn sysno(self, nr: u64) -> Option<Sysno> {
        match self {
            LinuxAbi::X86_64 => syscalls::x86_64_sysno(u64::from(nr as u32)),
            LinuxAbi::Aarch64 => syscalls::aarch64_sysno(u64::from(nr as u32)),
            LinuxAbi::Riscv64 => syscalls::riscv64_sysno(nr),
        }
    }

    /// The ABI number of `sysno`, if the ABI defines the call.
    pub fn number(self, sysno: Sysno) -> Option<u64> {
        let table = match self {
            LinuxAbi::X86_64 => syscalls::X86_64_TABLE,
            LinuxAbi::Aarch64 => syscalls::AARCH64_TABLE,
            LinuxAbi::Riscv64 => syscalls::RISCV64_TABLE,
        };
        table.iter().find(|(_, s)| *s == sysno).map(|(n, _)| *n)
    }

    /// `TASK_SIZE`: exclusive upper bound of user addresses.
    ///
    /// - x86-64: `TASK_SIZE_MAX = (1 << 47) - PAGE_SIZE` (4-level paging;
    ///   the top page is excluded so the SYSCALL return address stays
    ///   canonical).
    /// - arm64: `TASK_SIZE_64 = 1 << VA_BITS` with `VA_BITS = 48`.
    /// - riscv: Sv48 `TASK_SIZE_64 = PGDIR_SIZE * PTRS_PER_PGD / 2 = 1 << 47`.
    pub fn task_size(self) -> u64 {
        match self {
            LinuxAbi::X86_64 => (1 << 47) - PAGE_SIZE,
            LinuxAbi::Aarch64 => 1 << 48,
            LinuxAbi::Riscv64 => 1 << 47,
        }
    }

    /// `STACK_TOP` (and the default mmap window end) without randomization:
    /// `DEFAULT_MAP_WINDOW` on x86-64 and riscv, `TASK_SIZE_64` on arm64.
    pub fn stack_top(self) -> u64 {
        self.task_size()
    }

    /// `ELF_ET_DYN_BASE`, the load address of a PIE with an interpreter
    /// before `maximum_alignment()` rounding: two thirds of the default
    /// mmap window (`DEFAULT_MAP_WINDOW / 3 * 2` on x86-64 and riscv,
    /// `2 * DEFAULT_MAP_WINDOW_64 / 3` on arm64).
    pub fn elf_et_dyn_base(self) -> u64 {
        match self {
            LinuxAbi::X86_64 | LinuxAbi::Riscv64 => self.stack_top() / 3 * 2,
            LinuxAbi::Aarch64 => 2 * self.stack_top() / 3,
        }
    }

    /// `mmap_base()` of `mm/util.c` (the top of the top-down mmap area)
    /// for a stack rlimit of `stack_limit` bytes and no randomization:
    /// `PAGE_ALIGN(STACK_TOP - gap)`, `gap = rlimit + stack_guard_gap`
    /// clamped to `[128 MiB, STACK_TOP / 6 * 5]`.
    pub fn mmap_base(self, stack_limit: u64) -> u64 {
        let top = self.stack_top();
        let min_gap = 128 << 20;
        let max_gap = top / 6 * 5;
        let mut gap = stack_limit.saturating_add(STACK_GUARD_GAP);
        if gap < min_gap {
            gap = min_gap;
        } else if gap > max_gap {
            gap = max_gap;
        }
        (top - gap).div_ceil(PAGE_SIZE) * PAGE_SIZE
    }

    /// The architecture's `O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT`, and
    /// `O_LARGEFILE` encodings; every other open flag is shared
    /// (`asm-generic/fcntl.h`). arm64 overrides these four in
    /// `arch/arm64/include/uapi/asm/fcntl.h`.
    pub fn open_flags(self) -> OpenFlagLayout {
        match self {
            LinuxAbi::Aarch64 => OpenFlagLayout {
                directory: 0o40000,
                nofollow: 0o100000,
                direct: 0o200000,
                largefile: 0o400000,
            },
            LinuxAbi::X86_64 | LinuxAbi::Riscv64 => OpenFlagLayout {
                directory: 0o200000,
                nofollow: 0o400000,
                direct: 0o40000,
                largefile: 0o100000,
            },
        }
    }

    /// Whether `PROT_EXEC` implies read access. x86 and arm64 page tables
    /// cannot express execute-only user pages, so their `protection_map`
    /// makes them readable; RISC-V maps `PROT_EXEC` alone to `PAGE_EXEC`.
    pub fn exec_implies_read(self) -> bool {
        !matches!(self, LinuxAbi::Riscv64)
    }

    /// Whether the ABI's `struct sigaction` has an `sa_restorer` field and
    /// honors `SA_RESTORER` (riscv has neither and returns through the vDSO).
    pub fn has_sa_restorer(self) -> bool {
        !matches!(self, LinuxAbi::Riscv64)
    }

    /// `syscall_get_arch`: the `AUDIT_ARCH_*` value seccomp filters see
    /// (`uapi/linux/audit.h`: machine, `__AUDIT_ARCH_64BIT`,
    /// `__AUDIT_ARCH_LE`).
    pub fn audit_arch(self) -> u32 {
        match self {
            LinuxAbi::X86_64 => 0xC000_003E,
            LinuxAbi::Aarch64 => 0xC000_00B7,
            LinuxAbi::Riscv64 => 0xC000_00F3,
        }
    }
}

/// `AUDIT_ARCH_I386`: the architecture of an x86-64 thread's `INT 0x80`
/// calls.
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;

/// Architecture-specific open-flag encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFlagLayout {
    /// `O_DIRECTORY`.
    pub directory: u32,
    /// `O_NOFOLLOW`.
    pub nofollow: u32,
    /// `O_DIRECT`.
    pub direct: u32,
    /// `O_LARGEFILE`.
    pub largefile: u32,
}

/// Open flags shared by every ABI (`asm-generic/fcntl.h`), in octal as the
/// header writes them.
pub mod open {
    /// `O_ACCMODE`.
    pub const O_ACCMODE: u32 = 0o3;
    /// `O_RDONLY`.
    pub const O_RDONLY: u32 = 0o0;
    /// `O_WRONLY`.
    pub const O_WRONLY: u32 = 0o1;
    /// `O_RDWR`.
    pub const O_RDWR: u32 = 0o2;
    /// `O_CREAT`.
    pub const O_CREAT: u32 = 0o100;
    /// `O_EXCL`.
    pub const O_EXCL: u32 = 0o200;
    /// `O_NOCTTY`.
    pub const O_NOCTTY: u32 = 0o400;
    /// `O_TRUNC`.
    pub const O_TRUNC: u32 = 0o1000;
    /// `O_APPEND`.
    pub const O_APPEND: u32 = 0o2000;
    /// `O_NONBLOCK`.
    pub const O_NONBLOCK: u32 = 0o4000;
    /// `O_DSYNC`.
    pub const O_DSYNC: u32 = 0o10000;
    /// `FASYNC`.
    pub const FASYNC: u32 = 0o20000;
    /// `O_NOATIME`.
    pub const O_NOATIME: u32 = 0o1000000;
    /// `O_CLOEXEC`.
    pub const O_CLOEXEC: u32 = 0o2000000;
    /// `__O_SYNC`.
    pub const O_SYNC_BIT: u32 = 0o4000000;
    /// `O_PATH`.
    pub const O_PATH: u32 = 0o10000000;
    /// `__O_TMPFILE`.
    pub const O_TMPFILE_BIT: u32 = 0o20000000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_constants_match_linux_no_aslr_addresses() {
        // Values observed on real kernels with `setarch -R`: the PIE base,
        // the stack top, and the first interpreter mapping just below the
        // mmap base.
        let x86 = LinuxAbi::X86_64;
        assert_eq!(x86.stack_top(), 0x7fff_ffff_f000);
        assert_eq!(x86.elf_et_dyn_base() & !(PAGE_SIZE - 1), 0x5555_5555_4000);
        assert_eq!(x86.mmap_base(DEFAULT_STACK_LIMIT), 0x7fff_f7ff_f000);
        let arm = LinuxAbi::Aarch64;
        assert_eq!(arm.stack_top(), 0x1_0000_0000_0000);
        assert_eq!(arm.elf_et_dyn_base(), 0xaaaa_aaaa_aaaa);
        assert_eq!(arm.elf_et_dyn_base() & !0xFFFF, 0xaaaa_aaaa_0000);
        assert_eq!(arm.mmap_base(DEFAULT_STACK_LIMIT), 0xffff_f800_0000);
        let rv = LinuxAbi::Riscv64;
        assert_eq!(rv.stack_top(), 0x8000_0000_0000);
        assert_eq!(rv.elf_et_dyn_base(), 0x5555_5555_5554);
    }

    #[test]
    fn mmap_base_gap_is_clamped() {
        let x86 = LinuxAbi::X86_64;
        // rlimit + guard below 128 MiB is raised to 128 MiB.
        assert_eq!(x86.mmap_base(0), x86.stack_top() - (128 << 20));
        // A 1 GiB rlimit is used as-is (plus the guard gap).
        assert_eq!(
            x86.mmap_base(1 << 30),
            x86.stack_top() - (1 << 30) - STACK_GUARD_GAP
        );
        // RLIM_INFINITY saturates at five sixths of the stack top.
        let top = x86.stack_top();
        assert_eq!(
            x86.mmap_base(u64::MAX),
            (top - top / 6 * 5).div_ceil(PAGE_SIZE) * PAGE_SIZE
        );
    }

    #[test]
    fn arm64_overrides_four_open_flags() {
        let g = LinuxAbi::X86_64.open_flags();
        let a = LinuxAbi::Aarch64.open_flags();
        assert_eq!(g, LinuxAbi::Riscv64.open_flags());
        assert_eq!((a.directory, a.nofollow), (0o40000, 0o100000));
        assert_eq!((g.directory, g.nofollow), (0o200000, 0o400000));
        assert_eq!((a.direct, a.largefile), (0o200000, 0o400000));
        assert_eq!((g.direct, g.largefile), (0o40000, 0o100000));
    }

    #[test]
    fn syscall_numbers_resolve_both_ways() {
        assert_eq!(LinuxAbi::X86_64.sysno(0), Some(Sysno::Read));
        assert_eq!(LinuxAbi::X86_64.sysno(60), Some(Sysno::Exit));
        assert_eq!(LinuxAbi::Aarch64.sysno(93), Some(Sysno::Exit));
        assert_eq!(LinuxAbi::Riscv64.sysno(259), Some(Sysno::RiscvFlushIcache));
        assert_eq!(LinuxAbi::Aarch64.sysno(259), None);
        assert_eq!(LinuxAbi::X86_64.number(Sysno::Openat), Some(257));
        assert_eq!(LinuxAbi::Aarch64.number(Sysno::Openat), Some(56));
        assert_eq!(LinuxAbi::Aarch64.number(Sysno::Open), None);
        for abi in LinuxAbi::ALL {
            for nr in 0..1024 {
                if let Some(s) = abi.sysno(nr) {
                    assert_eq!(abi.number(s), Some(nr), "{abi:?} {nr}");
                }
            }
        }
    }
}
