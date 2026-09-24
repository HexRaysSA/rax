//! Initial process stack and auxiliary vector.
//!
//! Builds the stack `execve` hands a new program, byte-for-byte as Linux
//! 6.19 lays it out (`fs/exec.c` `copy_strings`, `fs/binfmt_elf.c`
//! `create_elf_tables`) with stack randomization disabled. From the top:
//!
//! ```text
//! STACK_TOP  ─┬─ 8 zero bytes             (bprm->p = vm_end - sizeof(void *))
//!             ├─ execve filename           (AT_EXECFN)
//!             ├─ envp strings, argv strings (argv[0] lowest)
//!             ├─ (aligned down to 16)
//!             ├─ AT_PLATFORM string        (x86-64, arm64)
//!             ├─ 16 random bytes           (AT_RANDOM)
//!             ├─ gap from rounding
//!             ├─ auxv pairs, AT_NULL
//!             ├─ envp[], NULL
//!             ├─ argv[], NULL
//! sp (16-aligned) argc
//! ```

use super::abi::{LinuxAbi, PAGE_SIZE, vma_flags};
use crate::user::mm::{AddressSpace, Mapping, MmError, Perms};

/// Auxiliary-vector tags (`linux/auxvec.h`, `asm/auxvec.h`).
pub mod at {
    /// End of vector.
    pub const AT_NULL: u64 = 0;
    /// Entry to ignore.
    pub const AT_IGNORE: u64 = 1;
    /// Program headers.
    pub const AT_PHDR: u64 = 3;
    /// Program header entry size.
    pub const AT_PHENT: u64 = 4;
    /// Program header count.
    pub const AT_PHNUM: u64 = 5;
    /// Page size.
    pub const AT_PAGESZ: u64 = 6;
    /// Interpreter base.
    pub const AT_BASE: u64 = 7;
    /// Flags.
    pub const AT_FLAGS: u64 = 8;
    /// Program entry.
    pub const AT_ENTRY: u64 = 9;
    /// Real uid.
    pub const AT_UID: u64 = 11;
    /// Effective uid.
    pub const AT_EUID: u64 = 12;
    /// Real gid.
    pub const AT_GID: u64 = 13;
    /// Effective gid.
    pub const AT_EGID: u64 = 14;
    /// Platform string.
    pub const AT_PLATFORM: u64 = 15;
    /// Hardware capabilities.
    pub const AT_HWCAP: u64 = 16;
    /// `times()` frequency.
    pub const AT_CLKTCK: u64 = 17;
    /// Secure mode.
    pub const AT_SECURE: u64 = 23;
    /// Random bytes.
    pub const AT_RANDOM: u64 = 25;
    /// Hardware capabilities, second word.
    pub const AT_HWCAP2: u64 = 26;
    /// rseq feature size.
    pub const AT_RSEQ_FEATURE_SIZE: u64 = 27;
    /// rseq alignment.
    pub const AT_RSEQ_ALIGN: u64 = 28;
    /// Executed filename.
    pub const AT_EXECFN: u64 = 31;
    /// vDSO base.
    pub const AT_SYSINFO_EHDR: u64 = 33;
    /// RISC-V L1 instruction cache size.
    pub const AT_L1I_CACHESIZE: u64 = 40;
    /// RISC-V L1 instruction cache geometry.
    pub const AT_L1I_CACHEGEOMETRY: u64 = 41;
    /// RISC-V L1 data cache size.
    pub const AT_L1D_CACHESIZE: u64 = 42;
    /// RISC-V L1 data cache geometry.
    pub const AT_L1D_CACHEGEOMETRY: u64 = 43;
    /// RISC-V L2 cache size.
    pub const AT_L2_CACHESIZE: u64 = 44;
    /// RISC-V L2 cache geometry.
    pub const AT_L2_CACHEGEOMETRY: u64 = 45;
    /// RISC-V L3 cache size.
    pub const AT_L3_CACHESIZE: u64 = 46;
    /// RISC-V L3 cache geometry.
    pub const AT_L3_CACHEGEOMETRY: u64 = 47;
    /// Minimum signal stack size.
    pub const AT_MINSIGSTKSZ: u64 = 51;
}

/// `CLOCKS_PER_SEC`/`USER_HZ` reported as `AT_CLKTCK`.
pub const USER_HZ: u64 = 100;

/// `offsetof(struct rseq, end)` (`linux/rseq.h`): 28 bytes.
pub const RSEQ_FEATURE_SIZE: u64 = 28;
/// `__alignof__(struct rseq)`: 32 bytes.
pub const RSEQ_ALIGN: u64 = 32;

/// Everything `create_elf_tables` needs besides the strings.
#[derive(Clone, Debug)]
pub struct AuxInfo {
    /// `AT_PHDR`.
    pub phdr: u64,
    /// `AT_PHENT`.
    pub phent: u64,
    /// `AT_PHNUM`.
    pub phnum: u64,
    /// `AT_BASE`.
    pub base: u64,
    /// `AT_ENTRY`.
    pub entry: u64,
    /// Real and effective user IDs.
    pub uid: (u32, u32),
    /// Real and effective group IDs.
    pub gid: (u32, u32),
    /// `AT_SECURE`.
    pub secure: bool,
    /// `AT_HWCAP`.
    pub hwcap: u64,
    /// `AT_HWCAP2`, for ABIs that define `ELF_HWCAP2`.
    pub hwcap2: Option<u64>,
    /// `AT_PLATFORM` string, for ABIs that define `ELF_PLATFORM`.
    pub platform: Option<&'static str>,
    /// `AT_MINSIGSTKSZ`.
    pub minsigstksz: u64,
    /// `AT_SYSINFO_EHDR`, when a vDSO is mapped.
    pub vdso: Option<u64>,
}

/// The layout of a built initial stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialStack {
    /// Initial stack pointer (points at `argc`).
    pub sp: u64,
    /// Address of `argv[0]`'s string (`mm->arg_start`).
    pub arg_start: u64,
    /// End of the argument strings (`mm->arg_end`).
    pub arg_end: u64,
    /// Start of the environment strings (`mm->env_start`).
    pub env_start: u64,
    /// End of the environment strings (`mm->env_end`).
    pub env_end: u64,
    /// `AT_EXECFN` string address.
    pub execfn: u64,
    /// `AT_RANDOM` bytes address.
    pub random: u64,
    /// The auxiliary vector exactly as written, including `AT_NULL`.
    pub auxv: Vec<(u64, u64)>,
    /// The stack VMA's lowest address.
    pub stack_bottom: u64,
}

/// Errors while building the stack.
#[derive(Debug)]
pub enum StackError {
    /// The strings do not fit (`E2BIG`).
    TooBig,
    /// The address space refused the mapping.
    Memory(MmError),
}

impl std::fmt::Display for StackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackError::TooBig => f.write_str("argument list too long"),
            StackError::Memory(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StackError {}

/// The architecture's `ARCH_DLINFO` entries, placed before the generic ones.
fn arch_dlinfo(abi: LinuxAbi, aux: &AuxInfo) -> Vec<(u64, u64)> {
    use at::*;
    let mut v = Vec::new();
    if let Some(vdso) = aux.vdso {
        v.push((AT_SYSINFO_EHDR, vdso));
    }
    if abi == LinuxAbi::Riscv64 {
        // Cache geometry is unknown to the emulated platform; the kernel
        // reports zero when the device tree gives none.
        for tag in [
            AT_L1I_CACHESIZE,
            AT_L1I_CACHEGEOMETRY,
            AT_L1D_CACHESIZE,
            AT_L1D_CACHEGEOMETRY,
            AT_L2_CACHESIZE,
            AT_L2_CACHEGEOMETRY,
            AT_L3_CACHESIZE,
            AT_L3_CACHEGEOMETRY,
        ] {
            v.push((tag, 0));
        }
    }
    v.push((AT_MINSIGSTKSZ, aux.minsigstksz));
    v
}

/// Size of the `[stack]` mapping for a stack rlimit: the limit itself
/// (populated on demand, so the growth the kernel performs on fault is
/// already in place), at least 128 KiB and at most a quarter of the stack
/// top, page-aligned.
pub fn stack_mapping_size(abi: LinuxAbi, stack_limit: u64) -> u64 {
    stack_limit.clamp(128 << 10, abi.stack_top() / 4) & !(PAGE_SIZE - 1)
}

/// Maps the `[stack]` VMA below `STACK_TOP` (`setup_arg_pages`). Returns its
/// lowest address. `exec_stack` follows `PT_GNU_STACK`.
pub fn map_stack(
    abi: LinuxAbi,
    space: &AddressSpace,
    stack_limit: u64,
    exec_stack: bool,
) -> Result<u64, StackError> {
    let top = abi.stack_top();
    let size = stack_mapping_size(abi, stack_limit);
    let bottom = top - size;
    let mut perms = Perms::READ | Perms::WRITE;
    if exec_stack {
        perms |= Perms::EXEC;
    }
    let mut mapping = Mapping::anonymous(perms).named("[stack]");
    mapping.flags = vma_flags::GROWSDOWN;
    space
        .map(bottom, size, mapping)
        .map_err(StackError::Memory)?;
    Ok(bottom)
}

/// Writes the initial stack into the mapped `[stack]` VMA.
///
/// `random` supplies the 16 `AT_RANDOM` bytes.
#[allow(clippy::too_many_arguments)]
pub fn write_initial_stack(
    abi: LinuxAbi,
    space: &AddressSpace,
    stack_limit: u64,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    execfn: &[u8],
    aux: &AuxInfo,
    random: [u8; 16],
) -> Result<InitialStack, StackError> {
    let top = abi.stack_top();
    let bottom = top - stack_mapping_size(abi, stack_limit);

    // Strings may use at most a quarter of the stack limit (fs/exec.c
    // `bprm_stack_limits`), and never less than ARG_MAX's 32 pages.
    let strings: u64 = argv
        .iter()
        .chain(envp)
        .map(|s| s.len() as u64 + 1)
        .sum::<u64>()
        + execfn.len() as u64
        + 1;
    let limit = (stack_limit / 4).max(32 * PAGE_SIZE);
    if strings > limit {
        return Err(StackError::TooBig);
    }

    let write = |addr: u64, bytes: &[u8]| {
        space
            .write(addr, bytes)
            .map_err(|_| StackError::Memory(MmError::OutOfMemory))
    };
    let push_str = |p: &mut u64, s: &[u8]| -> Result<u64, StackError> {
        *p -= s.len() as u64 + 1;
        let mut with_nul = s.to_vec();
        with_nul.push(0);
        write(*p, &with_nul)?;
        Ok(*p)
    };

    let mut p = top - 8;
    let execfn_addr = push_str(&mut p, execfn)?;
    let env_end = p;
    let mut env_ptrs = vec![0u64; envp.len()];
    for (i, s) in envp.iter().enumerate().rev() {
        env_ptrs[i] = push_str(&mut p, s)?;
    }
    let env_start = p;
    let arg_end = p;
    let mut arg_ptrs = vec![0u64; argv.len()];
    for (i, s) in argv.iter().enumerate().rev() {
        arg_ptrs[i] = push_str(&mut p, s)?;
    }
    let arg_start = p;

    // arch_align_stack() without randomization.
    p &= !0xF;
    let platform = match aux.platform {
        Some(name) => Some(push_str(&mut p, name.as_bytes())?),
        None => None,
    };
    p -= 16;
    write(p, &random)?;
    let random_addr = p;

    use at::*;
    let mut auxv = arch_dlinfo(abi, aux);
    auxv.extend([
        (AT_HWCAP, aux.hwcap),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_CLKTCK, USER_HZ),
        (AT_PHDR, aux.phdr),
        (AT_PHENT, aux.phent),
        (AT_PHNUM, aux.phnum),
        (AT_BASE, aux.base),
        (AT_FLAGS, 0),
        (AT_ENTRY, aux.entry),
        (AT_UID, u64::from(aux.uid.0)),
        (AT_EUID, u64::from(aux.uid.1)),
        (AT_GID, u64::from(aux.gid.0)),
        (AT_EGID, u64::from(aux.gid.1)),
        (AT_SECURE, u64::from(aux.secure)),
        (AT_RANDOM, random_addr),
    ]);
    if let Some(hwcap2) = aux.hwcap2 {
        auxv.push((AT_HWCAP2, hwcap2));
    }
    auxv.push((AT_EXECFN, execfn_addr));
    if let Some(platform) = platform {
        auxv.push((AT_PLATFORM, platform));
    }
    auxv.push((AT_RSEQ_FEATURE_SIZE, RSEQ_FEATURE_SIZE));
    auxv.push((AT_RSEQ_ALIGN, RSEQ_ALIGN));
    auxv.push((AT_NULL, 0));

    // sp = STACK_ADD(p, ei_index); bprm->p = STACK_ROUND(sp, items).
    let aux_words = auxv.len() as u64 * 2;
    let items = (argv.len() as u64 + 1) + (envp.len() as u64 + 1) + 1;
    let sp = (p - aux_words * 8 - items * 8) & !0xF;

    let mut words: Vec<u64> = Vec::with_capacity((items + aux_words) as usize);
    words.push(argv.len() as u64);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    for &(tag, val) in &auxv {
        words.push(tag);
        words.push(val);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    write(sp, &bytes)?;

    Ok(InitialStack {
        sp,
        arg_start,
        arg_end,
        env_start,
        env_end,
        execfn: execfn_addr,
        random: random_addr,
        auxv,
        stack_bottom: bottom,
    })
}
