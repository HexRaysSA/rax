//! Program images: what `execve` builds and installs (`fs/exec.c`,
//! `fs/binfmt_elf.c`, `fs/binfmt_script.c`).
//!
//! [`load_image`] builds a complete new image — address space, stack,
//! program and interpreter, auxiliary vector, and entry register state —
//! without touching the running process, so a failure leaves the caller as
//! it was. [`LinuxProcess::commit_exec`] then does what `begin_new_exec` and
//! `setup_new_exec` do past the point of no return: the calling thread
//! becomes the only one, with the leader's ID (`de_thread`); handlers reset
//! to their defaults while ignored signals stay ignored; close-on-exec
//! descriptors close; the alternate stack, robust list, and TID words are
//! dropped; and the thread takes the file's name as its `comm`. The mask,
//! pending signals, and interval timers survive.
//!
//! Every ABI can execute every other ABI's programs, as on a kernel with
//! `binfmt_misc` handlers registered for them.

use std::path::PathBuf;

use super::abi::LinuxAbi;
use super::arch::{CpuOptions, GuestCpu};
use super::fs::Vfs;
use super::loader::{ImageFile, LoadError, load_program};
use super::process::{Entropy, LinuxProcess, MmState, SigAction, SpawnError};
use super::signal::{AltStack, SIG_IGN};
use super::stack::{AuxInfo, map_stack, write_initial_stack};
use crate::user::cpu::x86_64::RESERVED_PHYS;
use crate::user::image::elf::identify;
use crate::user::mm::{AddressSpace, SpaceConfig};

/// `BINPRM_BUF_SIZE`: the bytes binary handlers examine.
pub const BINPRM_BUF_SIZE: usize = 256;

/// A program image ready to run.
pub struct ProgramImage {
    /// Its ABI.
    pub abi: LinuxAbi,
    /// The new address space.
    pub space: AddressSpace,
    /// The CPU in the entry state.
    pub cpu: GuestCpu,
    /// Memory bookkeeping.
    pub mm: MmState,
    /// The signal-return trampoline (0 on x86-64).
    pub sigtramp: u64,
    /// The auxiliary vector written.
    pub auxv: Vec<(u64, u64)>,
    /// `/proc/self/cmdline`.
    pub cmdline: Vec<u8>,
    /// `/proc/self/environ`.
    pub environ: Vec<u8>,
    /// Guest path of the executable (`/proc/self/exe`).
    pub exe_path: String,
    /// Its host path.
    pub exe_host_path: Option<PathBuf>,
    /// The new `comm`.
    pub comm: Vec<u8>,
    /// What the image keeps open: its executable and interpreter
    /// (`mm->exe_file` and their mappings), as file-system notification
    /// tokens.
    pub keep: Vec<crate::user::mm::Keep>,
}

/// What to load.
pub struct ImageRequest<'a> {
    /// The ELF file's contents.
    pub bytes: std::sync::Arc<[u8]>,
    /// Absolute, resolved guest path of the file (`d_path`).
    pub exe_path: String,
    /// Its host path.
    pub exe_host: PathBuf,
    /// `AT_EXECFN`: the file name as `execve` got it.
    pub execfn: &'a [u8],
    /// `comm`: the file name's last component (at most 15 bytes).
    pub comm: Vec<u8>,
    /// Arguments.
    pub argv: &'a [Vec<u8>],
    /// Environment.
    pub envp: &'a [Vec<u8>],
    /// `RLIMIT_STACK` soft limit.
    pub stack_limit: u64,
    /// Guest-memory arena size.
    pub arena_bytes: u64,
    /// CPU options.
    pub cpu: &'a CpuOptions,
}

/// The `comm` of a file name: its last component, at most 15 bytes
/// (`kbasename` and `__set_task_comm`).
pub fn comm_of(name: &[u8]) -> Vec<u8> {
    let base = name.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
    base.iter().take(15).copied().collect()
}

/// Concatenates strings with NUL terminators (`/proc/self/cmdline`).
fn join0(v: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in v {
        out.extend_from_slice(s);
        out.push(0);
    }
    out
}

/// Builds the image `req` describes, resolving its interpreter through
/// `vfs`; `creds` and `entropy` supply the auxiliary vector.
pub fn load_image(
    req: ImageRequest<'_>,
    vfs: &Vfs,
    creds: (u32, u32, u32, u32),
    entropy: &mut Entropy,
) -> Result<ProgramImage, SpawnError> {
    let ident = identify(&req.bytes)
        .map_err(|e| SpawnError::Unsupported(format!("{}: {e}", req.exe_path)))?;
    let abi = LinuxAbi::from_elf(ident.e_machine, ident.elf_class()).ok_or_else(|| {
        SpawnError::Unsupported(format!(
            "{}: ELF machine {} (class {}) is not a supported Linux ABI",
            req.exe_path, ident.e_machine, ident.class
        ))
    })?;
    let reserved = if abi == LinuxAbi::X86_64 {
        RESERVED_PHYS.to_vec()
    } else {
        Vec::new()
    };
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: req.arena_bytes,
        reserved_phys: reserved,
    })
    .map_err(SpawnError::Memory)?;
    let mut cpu = GuestCpu::new(abi, &space, req.cpu);
    let image = ImageFile::new(req.bytes.clone(), req.exe_path.clone());

    // setup_arg_pages() precedes the segment mappings.
    let exec_stack = {
        let (class, data) = abi.elf_encoding();
        crate::user::image::elf::ElfImage::parse(&image.bytes, class, data)
            .map_err(|e| SpawnError::Load(LoadError::Elf(e)))?
            .gnu_stack_executable()
            .unwrap_or(false)
    };
    map_stack(abi, &space, req.stack_limit, exec_stack).map_err(SpawnError::Stack)?;

    let mut resolver = |path: &[u8]| -> std::io::Result<ImageFile> {
        let guest = String::from_utf8_lossy(path).into_owned();
        let host = vfs.host_path(&guest, true);
        Ok(ImageFile::new(std::fs::read(&host)?, guest))
    };
    let program = load_program(abi, &space, &image, &mut resolver, req.stack_limit)
        .map_err(SpawnError::Load)?;
    // ARCH_SETUP_ADDITIONAL_PAGES follows the image and interpreter.
    let sigtramp = super::signal::frame::map_sigtramp(abi, &space, abi.mmap_base(req.stack_limit))
        .map_err(SpawnError::Memory)?;

    let caps = cpu.caps();
    let mut random = [0u8; 16];
    entropy
        .fill(&mut random)
        .map_err(|e| SpawnError::Unsupported(format!("no entropy source: {e}")))?;
    let aux = AuxInfo {
        phdr: program.phdr,
        phent: program.phent,
        phnum: program.phnum,
        base: program.interp_base,
        entry: program.program_entry,
        uid: (creds.0, creds.1),
        gid: (creds.2, creds.3),
        secure: false,
        hwcap: caps.hwcap,
        hwcap2: caps.hwcap2,
        platform: caps.platform,
        minsigstksz: caps.minsigstksz,
        vdso: None,
    };
    let stack = write_initial_stack(
        abi,
        &space,
        req.stack_limit,
        req.argv,
        req.envp,
        req.execfn,
        &aux,
        random,
    )
    .map_err(SpawnError::Stack)?;
    cpu.start(program.entry, stack.sp);
    Ok(ProgramImage {
        abi,
        space,
        cpu,
        mm: MmState {
            start_brk: program.brk,
            brk: program.brk,
            mmap_base: abi.mmap_base(req.stack_limit),
            program,
            stack: stack.clone(),
            def_lock: 0,
            locked_vm: 0,
        },
        sigtramp,
        auxv: stack.auxv.clone(),
        cmdline: join0(req.argv),
        environ: join0(req.envp),
        exe_path: req.exe_path,
        exe_host_path: Some(req.exe_host),
        comm: req.comm,
        keep: Vec::new(),
    })
}

/// Why a `#!` line cannot start an interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptError {
    /// Not a script (`ENOEXEC` from this handler).
    NotScript,
    /// No interpreter, or a truncated interpreter path (`ENOEXEC`).
    Bad,
}

/// `load_script`: the interpreter and optional argument of a `#!` line in
/// the first [`BINPRM_BUF_SIZE`] bytes of a file.
pub fn parse_script(buf: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), ScriptError> {
    if buf.len() < 2 || buf[0] != b'#' || buf[1] != b'!' {
        return Err(ScriptError::NotScript);
    }
    let mut b = [0u8; BINPRM_BUF_SIZE];
    let n = buf.len().min(BINPRM_BUF_SIZE);
    b[..n].copy_from_slice(&buf[..n]);
    let spacetab = |c: u8| c == b' ' || c == b'\t';
    // The buffer's last byte is kept as a terminator, as the kernel's is.
    let buf_end = BINPRM_BUF_SIZE - 1;
    let next_non_spacetab = |from: usize, to: usize| (from..to).find(|&i| !spacetab(b[i]));
    let next_terminator =
        |from: usize, to: usize| (from..to).find(|&i| spacetab(b[i]) || b[i] == 0);
    let mut i_end = match b.iter().position(|&c| c == b'\n') {
        Some(nl) => nl,
        None => {
            let start = next_non_spacetab(2, buf_end).ok_or(ScriptError::Bad)?;
            // No later space, tab, or NUL: the path may be truncated.
            next_terminator(start, buf_end).ok_or(ScriptError::Bad)?;
            buf_end
        }
    };
    while i_end > 2 && spacetab(b[i_end - 1]) {
        i_end -= 1;
    }
    let i_name = match next_non_spacetab(2, i_end) {
        Some(i) if i != i_end => i,
        _ => return Err(ScriptError::Bad),
    };
    let i_sep = next_terminator(i_name, i_end);
    let arg = match i_sep {
        Some(sep) if b[sep] != 0 => next_non_spacetab(sep, i_end).map(|a| {
            let end = b[a..i_end]
                .iter()
                .position(|&c| c == 0)
                .map_or(i_end, |z| a + z);
            b[a..end].to_vec()
        }),
        _ => None,
    };
    let name_end = i_sep.unwrap_or(i_end);
    Ok((b[i_name..name_end].to_vec(), arg))
}

impl LinuxProcess {
    /// Installs `image` for the process after thread `idx` executed it:
    /// the point of no return of `execve`.
    pub fn commit_exec(&mut self, idx: usize, image: ProgramImage) {
        // de_thread: the caller is the only thread and takes the leader's
        // ID.
        let mut t = self.threads.swap_remove(idx);
        self.threads.clear();
        let p = &mut self.state;
        t.tid = p.pid;
        // The other threads' children passed to the caller as they died
        // (forget_original_parent); all are now children of the leader ID.
        for ch in p.children.list.iter_mut() {
            ch.creator = p.pid;
        }
        t.cpu = image.cpu;
        // arch_setup_new_exec re-enables CPUID but keeps TIF_NOTSC.
        t.cpu.set_tsc_disabled(t.notsc);
        t.altstack = AltStack::DISABLED;
        t.robust_list = (0, 0);
        t.clear_child_tid = 0;
        t.set_child_tid = 0;
        t.vfork_parent = None;
        t.saved_sigmask = None;
        t.syscall = None;
        t.restart = None;
        t.blocked = None;
        t.real_blocked = 0;
        t.fault = Default::default();
        t.comm = image.comm.clone();
        // flush_signal_handlers: ignored signals stay ignored.
        for a in p.sigactions.iter_mut() {
            *a = SigAction {
                handler: if a.handler == SIG_IGN { SIG_IGN } else { 0 },
                ..SigAction::default()
            };
        }
        p.fds.close_on_exec();
        // SET_PERSONALITY: x86-64 drops READ_IMPLIES_EXEC; arm64 and riscv
        // keep the flags with PER_LINUX.
        p.persona = match image.abi {
            LinuxAbi::X86_64 => p.persona & !super::abi::READ_IMPLIES_EXEC,
            _ => p.persona & !0xff,
        };
        p.abi = image.abi;
        p.space = image.space;
        // exit_mmap: the old image's System V attaches go.
        super::syscall::ipc::sync_shm(p);
        p.mm = image.mm;
        p.sigtramp = image.sigtramp;
        p.auxv = image.auxv;
        p.cmdline = image.cmdline;
        p.environ = image.environ;
        p.exe_path = image.exe_path;
        p.exe_host_path = image.exe_host_path;
        // The old image's files close (exec_mmap), the new one's stay open.
        p.exec_keep = image.keep;
        p.comm = image.comm;
        p.futex = Default::default();
        // exit_itimers, flush_itimer_signals: POSIX timers and their
        // queued signals go; interval timers stay.
        p.timers.clear();
        p.shared_pending.flush_timer_signals();
        t.pending.flush_timer_signals();
        p.curr_target = p.pid;
        p.leader_exit = None;
        p.exec_id += 1;
        // mm_release: a CLONE_VFORK parent runs again.
        if let Some(me) = p.forked.as_mut() {
            me.exec();
        }
        t.sigpending = super::signal::deliver::recalc_sigpending(p, &t);
        self.threads.push(t);
    }
}
