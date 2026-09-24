//! Linux processes: `execve` setup and thread execution.
//!
//! [`LinuxProcess::spawn`] performs the work of `execve` for the initial
//! program — map the stack, load the ELF image and its interpreter, write
//! the argument/environment/auxiliary vectors, and set the entry registers
//! — and [`LinuxProcess::run`] executes the process's threads until the
//! process exits, routing each CPU event to the system-call layer or to
//! signal handling.

use std::path::PathBuf;
use std::sync::Arc;

use super::abi::errno::Errno;
use super::abi::{DEFAULT_STACK_LIMIT, LinuxAbi};
use super::arch::{CpuEvent, CpuOptions, GuestCpu};
use super::fs::Vfs;
use super::fs::fd::{FdTable, FileObject, FileType, NOFILE_HARD, NOFILE_SOFT, OpenFile};
use super::loader::{ImageFile, LoadError, LoadedProgram, load_program};
use super::signal::deliver::SyscallEntry;
use super::signal::frame::FaultState;
use super::signal::{AltStack, SigInfo, SigPending, signal_name};
use super::stack::{AuxInfo, InitialStack, StackError, map_stack, write_initial_stack};
use super::syscall;
use crate::user::cpu::x86_64::RESERVED_PHYS;
use crate::user::image::elf::identify;
use crate::user::mm::{AddressSpace, SpaceConfig};

/// Instructions per scheduling slice for cores whose run budget RAX sets
/// (AArch64, RV64); the x86-64 core yields on its own ~1 ms timer.
pub const DEFAULT_SLICE_INSNS: u64 = 1 << 20;

/// Default guest-memory arena: 16 GiB of address space, committed by the
/// host only as pages are touched.
pub const DEFAULT_ARENA_BYTES: u64 = 16 << 30;

/// Kernel release reported by `uname`: the UAPI revision RAX implements.
pub const DEFAULT_KERNEL_RELEASE: &str = "6.19.0";

/// How to start a process.
#[derive(Clone, Debug)]
pub struct LinuxConfig {
    /// `argv`, including `argv[0]`.
    pub argv: Vec<Vec<u8>>,
    /// `envp`.
    pub envp: Vec<Vec<u8>>,
    /// Guest path of the executable (`AT_EXECFN`, `/proc/self/exe`).
    pub exec_path: String,
    /// Guest root overlay (QEMU `-L`).
    pub sysroot: Option<PathBuf>,
    /// Absolute guest working directory.
    pub cwd: String,
    /// `RLIMIT_STACK` soft limit in bytes.
    pub stack_limit: u64,
    /// Guest-memory arena size in bytes.
    pub arena_bytes: u64,
    /// CPU options.
    pub cpu: CpuOptions,
    /// Log every system call to standard error (`strace` format).
    pub strace: bool,
    /// Seed for `AT_RANDOM` and `getrandom`; `None` reads the host's
    /// entropy source.
    pub seed: Option<u64>,
    /// `uname -r`.
    pub kernel_release: String,
    /// Instructions per scheduling slice (AArch64, RV64).
    pub slice_insns: u64,
}

impl LinuxConfig {
    /// A configuration for `exec_path` with `argv` and the defaults.
    pub fn new(exec_path: impl Into<String>, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".into());
        LinuxConfig {
            argv,
            envp,
            exec_path: exec_path.into(),
            sysroot: None,
            cwd,
            stack_limit: DEFAULT_STACK_LIMIT,
            arena_bytes: DEFAULT_ARENA_BYTES,
            cpu: CpuOptions::default(),
            strace: false,
            seed: None,
            kernel_release: DEFAULT_KERNEL_RELEASE.into(),
            slice_insns: DEFAULT_SLICE_INSNS,
        }
    }
}

/// How a process ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// `exit_group(code)`; only the low 8 bits are reported to a parent.
    Exited(i32),
    /// Killed by a signal.
    Signaled {
        /// The signal.
        info: SigInfo,
        /// PC of the thread that received it.
        pc: u64,
        /// Whether the signal's default action is to dump core
        /// (`sig_kernel_coredump`). No core file is written: the default
        /// `RLIMIT_CORE` soft limit is zero.
        core: bool,
    },
    /// The emulator could not continue.
    Internal(String),
}

impl ExitStatus {
    /// The status a shell reports: `code & 0xff`, or `128 + signal`.
    pub fn shell_code(&self) -> i32 {
        match self {
            ExitStatus::Exited(code) => code & 0xff,
            ExitStatus::Signaled { info, .. } => 128 + info.signo,
            ExitStatus::Internal(_) => 125,
        }
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitStatus::Exited(code) => write!(f, "exited with status {}", code & 0xff),
            ExitStatus::Signaled { info, pc, core } => {
                write!(
                    f,
                    "killed by {} (si_code {}",
                    signal_name(info.signo),
                    info.code
                )?;
                // Faults carry si_addr; signals sent by a process carry its
                // PID (SI_USER, SI_TKILL, SI_QUEUE, ...).
                if info.code > 0 && info.code != super::signal::code::SI_KERNEL {
                    write!(f, ", address {:#x}", info.addr())?;
                } else if info.code <= 0 {
                    write!(f, ", sent by pid {}", info.pid())?;
                }
                write!(
                    f,
                    ") at pc {pc:#x}{}",
                    if *core { "; core not dumped" } else { "" }
                )
            }
            ExitStatus::Internal(why) => write!(f, "emulator error: {why}"),
        }
    }
}

/// Why a process could not be started.
#[derive(Debug)]
pub enum SpawnError {
    /// The image is not an executable for a supported ABI.
    Unsupported(String),
    /// Loading the image failed.
    Load(LoadError),
    /// Building the initial stack failed.
    Stack(StackError),
    /// The guest address space could not be created.
    Memory(crate::user::mm::MmError),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Unsupported(why) => write!(f, "{why}"),
            SpawnError::Load(e) => write!(f, "{e}"),
            SpawnError::Stack(e) => write!(f, "{e}"),
            SpawnError::Memory(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// A `struct k_sigaction`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    /// `SIG_DFL` (0), `SIG_IGN` (1), or a handler address.
    pub handler: u64,
    /// `SA_*` flags.
    pub flags: u64,
    /// `sa_restorer`.
    pub restorer: u64,
    /// Signals blocked while the handler runs.
    pub mask: u64,
}

/// Resource limits (`RLIMIT_*`), as `(soft, hard)`.
pub type Rlimits = [(u64, u64); 16];

/// `RLIM_INFINITY`.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Linux's initial limits (`include/asm-generic/resource.h` `INIT_RLIMITS`
/// with the usual distribution `RLIMIT_NOFILE` and `RLIMIT_STACK` values).
pub fn default_rlimits(stack_limit: u64) -> Rlimits {
    let inf = (RLIM_INFINITY, RLIM_INFINITY);
    [
        inf,                          // RLIMIT_CPU
        inf,                          // RLIMIT_FSIZE
        inf,                          // RLIMIT_DATA
        (stack_limit, RLIM_INFINITY), // RLIMIT_STACK
        (0, RLIM_INFINITY),           // RLIMIT_CORE
        inf,                          // RLIMIT_RSS
        (63_000, 63_000),             // RLIMIT_NPROC
        (NOFILE_SOFT, NOFILE_HARD),   // RLIMIT_NOFILE
        (8 << 20, 8 << 20),           // RLIMIT_MEMLOCK
        inf,                          // RLIMIT_AS
        inf,                          // RLIMIT_LOCKS
        (63_000, 63_000),             // RLIMIT_SIGPENDING
        (819_200, 819_200),           // RLIMIT_MSGQUEUE
        (0, 0),                       // RLIMIT_NICE
        (0, 0),                       // RLIMIT_RTPRIO
        inf,                          // RLIMIT_RTTIME
    ]
}

/// A deterministic or host-seeded byte source for `AT_RANDOM`/`getrandom`.
#[derive(Clone, Debug)]
pub struct Entropy {
    state: Option<u64>,
}

impl Entropy {
    fn new(seed: Option<u64>) -> Self {
        Entropy { state: seed }
    }

    /// Fills `buf`: SplitMix64 output when seeded, host entropy otherwise.
    pub fn fill(&mut self, buf: &mut [u8]) -> Result<(), Errno> {
        match &mut self.state {
            Some(s) => {
                for chunk in buf.chunks_mut(8) {
                    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
                    let mut z = *s;
                    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                    z ^= z >> 31;
                    chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
                }
                Ok(())
            }
            None => {
                use std::io::Read;
                std::fs::File::open("/dev/urandom")?.read_exact(buf)?;
                Ok(())
            }
        }
    }
}

/// Memory-management bookkeeping (`struct mm_struct` fields RAX needs).
#[derive(Clone, Debug)]
pub struct MmState {
    /// `start_brk`.
    pub start_brk: u64,
    /// Current break.
    pub brk: u64,
    /// Top of the top-down mmap area.
    pub mmap_base: u64,
    /// The loaded program.
    pub program: LoadedProgram,
    /// The initial stack layout.
    pub stack: InitialStack,
}

/// Process-wide state shared by all threads.
pub struct ProcState {
    /// The ABI.
    pub abi: LinuxAbi,
    /// The address space.
    pub space: AddressSpace,
    /// Path resolution.
    pub vfs: Vfs,
    /// Descriptors.
    pub fds: FdTable,
    /// Process ID (the host process ID).
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// `(uid, euid, gid, egid)`.
    pub creds: (u32, u32, u32, u32),
    /// Memory bookkeeping.
    pub mm: MmState,
    /// Resource limits.
    pub rlimits: Rlimits,
    /// File-creation mask.
    pub umask: u32,
    /// Signal dispositions, indexed by signal number minus one.
    pub sigactions: [SigAction; 64],
    /// `prctl(PR_SET_NAME)` value.
    pub comm: Vec<u8>,
    /// Guest path of the executable.
    pub exe_path: String,
    /// Host path of the executable, when it came from the host.
    pub exe_host_path: Option<PathBuf>,
    /// The auxiliary vector as written, for `/proc/self/auxv`.
    pub auxv: Vec<(u64, u64)>,
    /// `/proc/self/cmdline` contents.
    pub cmdline: Vec<u8>,
    /// `/proc/self/environ` contents.
    pub environ: Vec<u8>,
    /// Entropy source.
    pub entropy: Entropy,
    /// The configuration the process was started with.
    pub config: LinuxConfig,
    /// Exit status once the process has exited.
    pub exit: Option<ExitStatus>,
    /// Next thread ID to assign.
    pub next_tid: i32,
    /// `personality(2)` value.
    pub persona: u32,
    /// `prctl(PR_SET_DUMPABLE)` value.
    pub dumpable: u64,
    /// `prctl(PR_SET_NO_NEW_PRIVS)` value.
    pub no_new_privs: bool,
    /// `prctl(PR_SET_PDEATHSIG)` value.
    pub pdeathsig: i32,
    /// `prctl(PR_SET_TIMERSLACK)` value in nanoseconds.
    pub timerslack: u64,
    /// Signals pending for the process (`signal->shared_pending`).
    pub shared_pending: SigPending,
    /// Address of the signal-return trampoline in the `[vdso]` page (arm64
    /// `__kernel_rt_sigreturn`, riscv `__vdso_rt_sigreturn`); zero on x86-64,
    /// whose handlers must supply `SA_RESTORER`.
    pub sigtramp: u64,
    /// `SIGNAL_UNKILLABLE`: the process is its PID namespace's init (PID 1)
    /// and default-action signals do not kill it.
    pub unkillable: bool,
}

/// A Linux thread.
pub struct Thread {
    /// Thread ID.
    pub tid: i32,
    /// The CPU.
    pub cpu: GuestCpu,
    /// `set_tid_address` pointer, cleared and woken at exit.
    pub clear_child_tid: u64,
    /// `set_robust_list` head and length.
    pub robust_list: (u64, u64),
    /// Blocked signals.
    pub sigmask: u64,
    /// Signals pending for this thread (`task->pending`).
    pub pending: SigPending,
    /// The alternate signal stack.
    pub altstack: AltStack,
    /// The mask a signal-waiting call replaced, restored on the return to
    /// user mode unless a handler frame saved it (`saved_sigmask` with
    /// `TIF_RESTORE_SIGMASK`).
    pub saved_sigmask: Option<u64>,
    /// The system call being returned from, for restart processing.
    pub syscall: Option<SyscallEntry>,
    /// Architectural fault record for signal frames.
    pub fault: FaultState,
}

impl Thread {
    /// A thread with `cpu` in its initial signal state: nothing blocked or
    /// pending and no alternate stack.
    pub fn new(tid: i32, cpu: GuestCpu) -> Self {
        Thread {
            tid,
            cpu,
            clear_child_tid: 0,
            robust_list: (0, 0),
            sigmask: 0,
            pending: SigPending::new(),
            altstack: AltStack::DISABLED,
            saved_sigmask: None,
            syscall: None,
            fault: FaultState::default(),
        }
    }
}

/// A running Linux process.
pub struct LinuxProcess {
    /// Process-wide state.
    pub state: ProcState,
    /// Live threads.
    pub threads: Vec<Thread>,
}

/// Wraps an inherited host descriptor as a guest standard stream with the
/// host descriptor's access mode.
fn stdio(fd: i32, host: std::io::Result<std::os::fd::OwnedFd>) -> Option<Arc<OpenFile>> {
    let owned = host.ok()?;
    let mode = super::host::access_mode(&owned).ok()?;
    let file = std::fs::File::from(owned);
    let ftype = file
        .metadata()
        .map(|m| super::fs::file_type_of(&m))
        .unwrap_or(FileType::CharDevice);
    Some(OpenFile::new(
        FileObject::Host(file),
        ftype,
        format!("/dev/fd/{fd}"),
        None,
        mode,
    ))
}

impl LinuxProcess {
    /// Performs `execve` of `image` as the process's initial program.
    pub fn spawn(config: LinuxConfig, image: ImageFile) -> Result<Self, SpawnError> {
        let ident = identify(&image.bytes)
            .map_err(|e| SpawnError::Unsupported(format!("{}: {e}", config.exec_path)))?;
        let abi = LinuxAbi::from_elf(ident.e_machine, ident.elf_class()).ok_or_else(|| {
            SpawnError::Unsupported(format!(
                "{}: ELF machine {} (class {}) is not a supported Linux ABI",
                config.exec_path, ident.e_machine, ident.class
            ))
        })?;
        let reserved = if abi == LinuxAbi::X86_64 {
            RESERVED_PHYS.to_vec()
        } else {
            Vec::new()
        };
        let space = AddressSpace::new(SpaceConfig {
            va_limit: abi.task_size(),
            arena_bytes: config.arena_bytes,
            reserved_phys: reserved,
        })
        .map_err(SpawnError::Memory)?;
        let mut cpu = GuestCpu::new(abi, &space, &config.cpu);
        let vfs = Vfs::new(config.sysroot.clone(), config.cwd.clone());
        // /proc/self/exe and the mapping names carry the absolute, symlink-
        // resolved path (d_path of the executable), whatever path execve got.
        let exe_guest = super::fs::join_guest(&config.cwd, &config.exec_path);
        let exe_host = vfs.host_path(&exe_guest, true);
        let exe_path = std::fs::canonicalize(&exe_host)
            .map(|p| vfs.guest_path_of(&p))
            .unwrap_or(exe_guest);
        let image = ImageFile::new(image.bytes.clone(), exe_path.clone());

        // setup_arg_pages() precedes the segment mappings.
        let exec_stack = {
            let (class, data) = abi.elf_encoding();
            crate::user::image::elf::ElfImage::parse(&image.bytes, class, data)
                .map_err(|e| SpawnError::Load(LoadError::Elf(e)))?
                .gnu_stack_executable()
                .unwrap_or(false)
        };
        map_stack(abi, &space, config.stack_limit, exec_stack).map_err(SpawnError::Stack)?;

        let mut resolver = |path: &[u8]| -> std::io::Result<ImageFile> {
            let guest = String::from_utf8_lossy(path).into_owned();
            let host = vfs.host_path(&guest, true);
            Ok(ImageFile::new(std::fs::read(&host)?, guest))
        };
        let program = load_program(abi, &space, &image, &mut resolver, config.stack_limit)
            .map_err(SpawnError::Load)?;
        // ARCH_SETUP_ADDITIONAL_PAGES follows the image and interpreter.
        let sigtramp =
            super::signal::frame::map_sigtramp(abi, &space, abi.mmap_base(config.stack_limit))
                .map_err(SpawnError::Memory)?;

        let caps = cpu.caps();
        let creds = super::host::credentials();
        let mut entropy = Entropy::new(config.seed);
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
            config.stack_limit,
            &config.argv,
            &config.envp,
            config.exec_path.as_bytes(),
            &aux,
            random,
        )
        .map_err(SpawnError::Stack)?;
        cpu.start(program.entry, stack.sp);

        let mut fds = FdTable::new();
        use std::os::fd::AsFd;
        for (fd, host) in [
            (0, std::io::stdin().as_fd().try_clone_to_owned()),
            (1, std::io::stdout().as_fd().try_clone_to_owned()),
            (2, std::io::stderr().as_fd().try_clone_to_owned()),
        ] {
            if let Some(file) = stdio(fd, host) {
                fds.install_at(fd, file, false, NOFILE_HARD)
                    .expect("standard descriptors are below the limit");
            }
        }

        let pid = super::host::pid();
        let join0 = |v: &[Vec<u8>]| -> Vec<u8> {
            let mut out = Vec::new();
            for s in v {
                out.extend_from_slice(s);
                out.push(0);
            }
            out
        };
        let comm = config
            .exec_path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .as_bytes()
            .iter()
            .take(15)
            .copied()
            .collect();
        let exe_host_path = Some(exe_host);
        let state = ProcState {
            abi,
            space: space.clone(),
            vfs,
            fds,
            pid,
            ppid: super::host::ppid(),
            creds,
            mm: MmState {
                start_brk: program.brk,
                brk: program.brk,
                mmap_base: abi.mmap_base(config.stack_limit),
                program,
                stack: stack.clone(),
            },
            rlimits: default_rlimits(config.stack_limit),
            umask: 0o022,
            sigactions: [SigAction::default(); 64],
            comm,
            exe_path,
            exe_host_path,
            auxv: stack.auxv.clone(),
            cmdline: join0(&config.argv),
            environ: join0(&config.envp),
            entropy,
            config,
            exit: None,
            next_tid: pid + 1,
            persona: 0,
            dumpable: 1,
            no_new_privs: false,
            pdeathsig: 0,
            timerslack: 50_000,
            shared_pending: SigPending::new(),
            sigtramp,
            unkillable: pid == 1,
        };
        Ok(LinuxProcess {
            state,
            threads: vec![Thread::new(pid, cpu)],
        })
    }

    /// The ABI.
    pub fn abi(&self) -> LinuxAbi {
        self.state.abi
    }

    /// The address space.
    pub fn space(&self) -> &AddressSpace {
        &self.state.space
    }

    /// Runs until the process exits.
    pub fn run(&mut self) -> ExitStatus {
        let slice = self.state.config.slice_insns;
        let mut current = 0usize;
        loop {
            if let Some(status) = &self.state.exit {
                return status.clone();
            }
            if self.threads.is_empty() {
                return ExitStatus::Exited(0);
            }
            current %= self.threads.len();
            // The return to user mode: restart processing and signals.
            self.deliver_signals(current);
            if self.state.exit.is_some() {
                continue;
            }
            let event = self.threads[current].cpu.run(slice);
            match event {
                CpuEvent::Syscall { nr, args } => {
                    self.threads[current].syscall = Some(SyscallEntry { nr, arg0: args[0] });
                    let outcome =
                        syscall::dispatch(&mut self.state, &mut self.threads[current], nr, args);
                    self.apply(current, outcome);
                }
                CpuEvent::CompatSyscall { nr, args } => {
                    let outcome = syscall::dispatch_compat(
                        &mut self.state,
                        &mut self.threads[current],
                        nr,
                        args,
                    );
                    self.apply(current, outcome);
                }
                CpuEvent::Signal(info, update) => self.trap_signal(current, info, update),
                CpuEvent::Yield => current += 1,
                CpuEvent::Internal(why) => {
                    let pc = self.threads[current].cpu.pc();
                    self.state.exit = Some(ExitStatus::Internal(format!("{why} (pc {pc:#x})")));
                }
            }
        }
    }

    /// Applies a system call's outcome to the calling thread.
    fn apply(&mut self, current: usize, outcome: syscall::Outcome) {
        match outcome {
            syscall::Outcome::Return(value) => self.threads[current].cpu.set_syscall_result(value),
            syscall::Outcome::Unchanged => {
                // The call replaced the register state (rt_sigreturn):
                // nothing is left to restart.
                self.threads[current].syscall = None;
            }
            syscall::Outcome::ExitThread(code) => {
                // The last thread's exit ends the process with its code.
                if self.threads.len() == 1 {
                    self.state.exit = Some(ExitStatus::Exited(code));
                }
                self.threads.remove(current);
            }
            syscall::Outcome::ExitGroup(code) => {
                self.state.exit = Some(ExitStatus::Exited(code));
            }
            syscall::Outcome::Fatal(why) => {
                self.state.exit = Some(ExitStatus::Internal(why));
            }
        }
    }
}
