//! Darwin processes: `exec` setup and thread execution.
//!
//! [`DarwinProcess::spawn`] does what `execve` does for the first program —
//! create the task's address space and port name space, load the image and
//! `dyld`, and start the main thread — and [`DarwinProcess::run`] executes
//! the process's threads until it exits, routing each kernel entry to the
//! system-call layer.
//!
//! Every thread of a process runs on one host thread; the scheduler takes
//! the thread to run out of the process, runs it for a slice, handles the
//! trap that ended the slice, and puts it back. A call that must sleep
//! parks its thread ([`super::wait`]); when every thread sleeps the host
//! blocks in `poll` until one can continue.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use super::abi::DarwinAbi;
use super::arch::{DarwinCpu, Trap};
use super::commpage::MachineInfo;
use super::fd::{FdTable, NOFILE_HARD, NOFILE_SOFT};
use super::loader::{self, ExecParams, ImageFile, LoadError, LoadedProgram};
use super::mach::ipc::{IpcSpace, KObject, Port, PortName, Right};
use super::mach::task::{TaskState, ThreadMach};
use super::signal;
use super::syscall;
use super::vfs::Vfs;
use super::vm::VmLayout;
use super::wait::{self, Resume, Wait, WaitKey};
use crate::user::mm::{AddressSpace, MmError, SpaceConfig};

/// Instructions per scheduling slice for arm64 threads (x86-64 threads
/// yield on the core's own ~1 ms timer).
pub const DEFAULT_SLICE_INSNS: u64 = 1 << 20;

/// Default guest-memory arena: 16 GiB, committed as pages are touched.
pub const DEFAULT_ARENA_BYTES: u64 = 16 << 30;

/// The user address space's upper bound as the page table sees it (the
/// x86-64 commpage lies just below 2^47).
const VA_LIMIT: u64 = 1 << 47;

/// How to start a process.
#[derive(Clone, Debug)]
pub struct DarwinConfig {
    /// `argv`, including `argv[0]`.
    pub argv: Vec<Vec<u8>>,
    /// `envp`.
    pub envp: Vec<Vec<u8>>,
    /// Guest path of the executable (`executable_path=`).
    pub exec_path: String,
    /// Guest root overlay.
    pub root: Option<PathBuf>,
    /// Absolute guest working directory.
    pub cwd: String,
    /// The architecture to run a fat file as (`None`: the host's first).
    pub abi: Option<DarwinAbi>,
    /// Log every system call and trap to standard error.
    pub strace: bool,
    /// Seed for the `apple[]` entropy and `getentropy` (default: host).
    pub seed: Option<u64>,
    /// `RLIMIT_STACK` soft limit (default `DFLSSIZ`).
    pub stack_limit: Option<u64>,
    /// Guest-memory arena size in bytes.
    pub arena_bytes: u64,
    /// Instructions per slice (arm64).
    pub slice_insns: u64,
}

impl DarwinConfig {
    /// A configuration for `exec_path` with `argv`, `envp`, and defaults.
    pub fn new(exec_path: impl Into<String>, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".into());
        DarwinConfig {
            argv,
            envp,
            exec_path: exec_path.into(),
            root: None,
            cwd,
            abi: None,
            strace: false,
            seed: None,
            stack_limit: None,
            arena_bytes: DEFAULT_ARENA_BYTES,
            slice_insns: DEFAULT_SLICE_INSNS,
        }
    }
}

/// How a process ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// `exit(code)`; a parent sees the low 8 bits.
    Exited(i32),
    /// Killed by a signal.
    Signaled {
        /// The signal.
        signo: i32,
        /// Whether its default action dumps core.
        core: bool,
        /// PC of the thread that took it.
        pc: u64,
    },
    /// The emulator could not continue.
    Internal(String),
}

impl ExitStatus {
    /// The status a shell reports: `code & 0xff`, or `128 + signal`.
    pub fn shell_code(&self) -> i32 {
        match self {
            ExitStatus::Exited(c) => c & 0xff,
            ExitStatus::Signaled { signo, .. } => 128 + signo,
            ExitStatus::Internal(_) => 125,
        }
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitStatus::Exited(c) => write!(f, "exited with status {}", c & 0xff),
            ExitStatus::Signaled { signo, core, pc } => write!(
                f,
                "killed by {} at pc {pc:#x}{}",
                signal::name(*signo),
                if *core { " (core not dumped)" } else { "" }
            ),
            ExitStatus::Internal(why) => write!(f, "emulator error: {why}"),
        }
    }
}

/// Why a process could not be started.
#[derive(Debug)]
pub enum SpawnError {
    /// Loading failed.
    Load(LoadError),
    /// The address space could not be created.
    Memory(MmError),
    /// The executable or dynamic linker could not be read.
    Io(String, std::io::Error),
}

impl SpawnError {
    /// The `errno` `execve` would report.
    pub fn errno(&self) -> i32 {
        match self {
            SpawnError::Load(e) => e.errno(),
            SpawnError::Memory(_) => 12,
            SpawnError::Io(_, e) => e.raw_os_error().unwrap_or(5),
        }
    }
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Load(e) => write!(f, "{e}"),
            SpawnError::Memory(e) => write!(f, "{e}"),
            SpawnError::Io(p, e) => write!(f, "{p}: {e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// A deterministic or host-seeded byte source.
#[derive(Clone, Debug)]
pub struct Entropy {
    state: Option<u64>,
}

impl Entropy {
    /// SplitMix64 from `seed`, or the host's entropy.
    pub fn new(seed: Option<u64>) -> Self {
        Entropy { state: seed }
    }

    /// Fills `buf`.
    pub fn fill(&mut self, buf: &mut [u8]) {
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
            }
            None => {
                use std::io::Read;
                if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                    let _ = f.read_exact(buf);
                }
            }
        }
    }
}

/// Resource limits (`RLIMIT_*`, 0-8) as `(soft, hard)`.
pub type Rlimits = [(u64, u64); 9];

/// `RLIM_INFINITY`.
pub const RLIM_INFINITY: u64 = 0x7fff_ffff_ffff_ffff;

/// A guest thread.
pub struct Thread {
    /// The 64-bit thread ID (`thread_selfid`).
    pub tid: u64,
    /// The thread's control port name in the task's space.
    pub port: PortName,
    /// The thread's control port.
    pub kport: Arc<Port>,
    /// The CPU.
    pub cpu: DarwinCpu,
    /// Blocked signals.
    pub sigmask: u32,
    /// Signals pending for this thread.
    pub pending: u32,
    /// The wait a sleeping call registered.
    pub wait: Option<Wait>,
    /// Progress of a restarted call.
    pub resume: Option<Resume>,
    /// The thread's `pthread_t` (its user stack's top), zero for the main
    /// thread until libpthread registers.
    pub pthread: u64,
    /// The thread has exited.
    pub exited: bool,
    /// Something ended the thread's wait (it runs again).
    pub woken: bool,
    /// A targeted wake (`ulock_wake`, a semaphore signal) ended the wait:
    /// the restarted call returns success.
    pub wake_event: bool,
    /// The alternate signal stack: `(ss_sp, ss_size, ss_flags)`.
    pub altstack: (u64, u64, u32),
    /// Mach thread state.
    pub mach: ThreadMach,
    /// The thread's name (`PROC_SELFSET_THREADNAME`).
    pub name: Vec<u8>,
}

impl Thread {
    /// Whether the thread can run now.
    pub fn runnable(&self) -> bool {
        !self.exited && (self.wait.is_none() || self.woken)
    }
}

/// `bsdthread_register`'s record.
#[derive(Clone, Copy, Debug, Default)]
pub struct PthreadRegistration {
    /// `thread_start`.
    pub thread_start: u64,
    /// `start_wqthread`.
    pub wqthread_start: u64,
    /// `sizeof(struct _pthread)`.
    pub pthread_size: u32,
    /// The `pthread_registration_data` fields.
    pub tsd_offset: u32,
    /// Offset of the return-to-kernel field.
    pub return_to_kernel_offset: u32,
    /// Offset of the mach thread self field.
    pub mach_thread_self_offset: u32,
    /// Offset of the dispatch queue pointer from a thread's TSD base
    /// (`dispatch_queue_offset`).
    pub dispatch_queue_offset: u64,
    /// Whether registration happened.
    pub registered: bool,
}

/// Process-wide state shared by all threads.
pub struct Proc {
    /// The ABI.
    pub abi: DarwinAbi,
    /// The address space.
    pub space: AddressSpace,
    /// Where the process may map memory.
    pub vm: VmLayout,
    /// Path resolution.
    pub vfs: Vfs,
    /// Absolute guest working directory.
    pub cwd: Vec<u8>,
    /// Descriptors.
    pub fds: FdTable,
    /// Process ID (the host's).
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// `(ruid, euid, rgid, egid)`.
    pub creds: (u32, u32, u32, u32),
    /// The loaded program.
    pub program: LoadedProgram,
    /// The configuration the process started with.
    pub config: DarwinConfig,
    /// Set once the process has exited.
    pub exit: Option<ExitStatus>,
    /// The port name space.
    pub ipc: IpcSpace,
    /// The task's control port.
    pub task_port: Arc<Port>,
    /// The host port.
    pub host_port: Arc<Port>,
    /// Threads not running now, by thread ID.
    pub threads: BTreeMap<u64, Thread>,
    /// The next thread ID.
    pub next_tid: u64,
    /// Entropy source.
    pub entropy: Entropy,
    /// Resource limits.
    pub rlimits: Rlimits,
    /// File-creation mask.
    pub umask: u32,
    /// Signal dispositions, indexed by signal number minus one.
    pub sigactions: [signal::SigAction; 32],
    /// Signals pending for the process.
    pub pending: u32,
    /// libpthread's registration.
    pub pthread: PthreadRegistration,
    /// Machine facts.
    pub machine: MachineInfo,
    /// The shared region, once mapped.
    pub shared_region: Option<super::shared_region::SharedRegion>,
    /// When the process started (for `proc_pidinfo` start times).
    pub started: Instant,
    /// Events posted by the running thread for sleeping ones.
    pub posted: Vec<WaitKey>,
    /// Mach task state.
    pub task: TaskState,
    /// The task's audit token: auid, euid, egid, ruid, rgid, pid, asid,
    /// pidversion (the host process's, as the emulated process is it).
    pub audit: [u32; 8],
}

impl Proc {
    /// Where a thread's dispatch queue pointer lies after its TSD base
    /// (`thread_dispatchqaddr`).
    pub fn pthread_dispatch_offset(&self) -> u64 {
        self.pthread.dispatch_queue_offset
    }

    /// The name the task's space gives a new send right to `port`.
    pub fn insert_send(&mut self, port: &Arc<Port>) -> PortName {
        port.state.lock().unwrap().srights += 1;
        self.ipc
            .insert(Right::Send(port.clone()))
            .unwrap_or(super::mach::ipc::MACH_PORT_NULL)
    }

    /// Wakes threads sleeping on `key`.
    pub fn post(&mut self, key: WaitKey) {
        self.posted.push(key);
    }

    /// Wakes up to `n` threads sleeping on `key` (in thread order),
    /// marking the wake as the event they waited for. Returns how many.
    pub fn wake(&mut self, key: WaitKey, n: usize) -> usize {
        // The oldest waiters first (FIFO wait queues).
        let mut waiting: Vec<(u64, u64)> = self
            .threads
            .values()
            .filter(|t| !t.woken)
            .filter_map(|t| {
                t.wait
                    .as_ref()
                    .filter(|w| w.keys.contains(&key))
                    .map(|w| (w.seq, t.tid))
            })
            .collect();
        waiting.sort_unstable();
        let mut woken = 0;
        for (_, tid) in waiting.into_iter().take(n) {
            let t = self.threads.get_mut(&tid).expect("listed thread");
            t.woken = true;
            t.wake_event = true;
            woken += 1;
        }
        woken
    }

    /// Wakes the thread with control port `port` if it sleeps on `key`.
    pub fn wake_thread_port(&mut self, key: WaitKey, port: PortName) -> usize {
        for t in self.threads.values_mut() {
            if t.port == port && !t.woken && t.wait.as_ref().is_some_and(|w| w.keys.contains(&key))
            {
                t.woken = true;
                t.wake_event = true;
                return 1;
            }
        }
        0
    }

    /// Ends the process with `status` (the first exit wins).
    pub fn exit_with(&mut self, status: ExitStatus) {
        if self.exit.is_none() {
            self.exit = Some(status);
        }
    }
}

/// A running Darwin process.
pub struct DarwinProcess {
    /// Process-wide state.
    pub proc: Proc,
    /// The thread that ran last (the scheduler continues after it).
    last: u64,
}

/// Physical memory the emulated Mac reports (`hw.memsize`,
/// `max_mem_actual`).
pub const MEMSIZE: u64 = 16 << 30;

/// Memory the kernel manages (`max_mem`, `mem_size`;
/// `hw.memsize_usable`): on Apple silicon the physical memory less the
/// firmware carve-outs, modelled as 1/64 of it; on Intel all of it.
pub fn memsize_usable(abi: DarwinAbi) -> u64 {
    match abi {
        DarwinAbi::X86_64 => MEMSIZE,
        DarwinAbi::Arm64 => MEMSIZE - MEMSIZE / 64,
    }
}

impl DarwinProcess {
    /// Loads `image` and prepares its main thread, as `execve` does for the
    /// first program.
    pub fn spawn(config: DarwinConfig, image: ImageFile) -> Result<Self, SpawnError> {
        let abi = loader::choose_abi(&image.bytes, config.abi)
            .map_err(|e| SpawnError::Load(LoadError::Image(e)))?;
        let reserved = match abi {
            DarwinAbi::X86_64 => crate::user::cpu::x86_64::RESERVED_PHYS.to_vec(),
            DarwinAbi::Arm64 => Vec::new(),
        };
        let space = AddressSpace::new(SpaceConfig {
            va_limit: VA_LIMIT,
            arena_bytes: config.arena_bytes,
            reserved_phys: reserved,
        })
        .map_err(SpawnError::Memory)?;
        let vfs = Vfs::new(config.root.clone());

        // The task's name space: the main thread's port first (th_port,
        // 0x103), then the task's (0x203), as on macOS.
        let mut ipc = IpcSpace::new();
        let pid = std::process::id() as i32;
        let tid = ((pid as u64) << 20) | 1;
        let kport = Port::new(KObject::Thread(tid));
        kport.state.lock().unwrap().srights += 1;
        let thread_port = ipc
            .insert(Right::Send(kport.clone()))
            .expect("a fresh space has room");
        let task_port = Port::new(KObject::Task);
        task_port.state.lock().unwrap().srights += 1;
        ipc.insert(Right::Send(task_port.clone()))
            .expect("a fresh space has room");

        let dyld_file = match loader::parse_executable(&image, abi) {
            Ok((_, main)) if main.dylinker.is_some() => {
                let host = vfs.system_path(loader::DYLD_PATH);
                Some(ImageFile::read(loader::DYLD_PATH, &host).map_err(|e| {
                    SpawnError::Load(LoadError::Dylinker(loader::DYLD_PATH.into(), e))
                })?)
            }
            _ => None,
        };
        let mut entropy = Entropy::new(config.seed);
        let mut rand = [0u8; 32];
        entropy.fill(&mut rand);
        let stack_limit = config
            .stack_limit
            .unwrap_or_else(|| loader::default_stack_limit(abi));
        let machine = MachineInfo {
            memory_size: MEMSIZE,
            boottime_usec: boottime_usec(),
        };
        let params = ExecParams {
            argv: &config.argv,
            envp: &config.envp,
            dyld: dyld_file.as_ref(),
            stack_limit,
            entropy: rand,
            thread_port,
            machine,
        };
        let program = loader::load(&space, abi, &image, &params).map_err(SpawnError::Load)?;

        let mut cpu = DarwinCpu::new(abi, &space);
        if let Some(state) = &program.thread_state {
            cpu.set_thread_state(state);
        }
        cpu.set_pc(program.entry);
        cpu.set_sp(program.sp);

        let vm = VmLayout {
            min: program.vm_min.max(abi.user_page_size()),
            hint: program.mmap_base,
            max: abi.max_address(),
            page: abi.user_page_size(),
        };
        let mut rlimits: Rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 9];
        rlimits[3] = (stack_limit, 64 << 20); // RLIMIT_STACK
        rlimits[4] = (0, RLIM_INFINITY); // RLIMIT_CORE
        rlimits[7] = (1_392, 1_392); // RLIMIT_NPROC
        rlimits[8] = (NOFILE_SOFT, NOFILE_HARD); // RLIMIT_NOFILE
        // SAFETY: the credential getters take no arguments.
        let creds = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        // SAFETY: umask(2) takes no pointers; the mask is put back at once.
        let umask = unsafe {
            let m = libc::umask(0o022);
            libc::umask(m);
            m as u32
        };
        let main = Thread {
            tid,
            port: thread_port,
            kport,
            cpu,
            sigmask: 0,
            pending: 0,
            wait: None,
            resume: None,
            pthread: 0,
            exited: false,
            woken: false,
            wake_event: false,
            altstack: (0, 0, 4),
            mach: ThreadMach::default(),
            name: Vec::new(),
        };
        let mut threads = BTreeMap::new();
        threads.insert(tid, main);
        Ok(DarwinProcess {
            proc: Proc {
                abi,
                space,
                vm,
                vfs,
                cwd: config.cwd.clone().into_bytes(),
                fds: FdTable::with_stdio(),
                pid,
                // SAFETY: getppid takes no arguments.
                ppid: unsafe { libc::getppid() },
                creds,
                program,
                config,
                exit: None,
                ipc,
                task_port,
                host_port: Port::new(KObject::Host),
                threads,
                next_tid: tid + 1,
                entropy,
                rlimits,
                umask,
                sigactions: [signal::SigAction::default(); 32],
                pending: 0,
                pthread: PthreadRegistration::default(),
                machine,
                shared_region: None,
                started: Instant::now(),
                posted: Vec::new(),
                task: TaskState::default(),
                audit: host_audit_token(pid, creds),
            },
            last: 0,
        })
    }

    /// Runs the process until it exits.
    pub fn run(&mut self) -> ExitStatus {
        loop {
            if let Some(status) = self.proc.exit.clone() {
                return status;
            }
            self.deliver_posted();
            let Some(tid) = self.next_runnable() else {
                if self.proc.threads.values().all(|t| t.exited) {
                    self.proc.exit_with(ExitStatus::Exited(0));
                    continue;
                }
                self.idle();
                continue;
            };
            self.last = tid;
            let mut thread = self
                .proc
                .threads
                .remove(&tid)
                .expect("runnable thread exists");
            thread.woken = false;
            thread.wait = None;
            thread.mach.csw += 1;
            let t0 = thread_cpu_ns();
            let trap = thread.cpu.run(self.proc.config.slice_insns);
            let t1 = thread_cpu_ns();
            self.handle(&mut thread, trap);
            let t2 = thread_cpu_ns();
            thread.mach.user_ns += t1.saturating_sub(t0);
            thread.mach.system_ns += t2.saturating_sub(t1);
            if thread.exited {
                self.proc.task.dead_times.0 += thread.mach.user_ns;
                self.proc.task.dead_times.1 += thread.mach.system_ns;
            }
            if !thread.exited {
                self.proc.threads.insert(tid, thread);
            }
        }
    }

    /// The next runnable thread after the one that ran last.
    fn next_runnable(&self) -> Option<u64> {
        let after = self
            .proc
            .threads
            .range(self.last + 1..)
            .find(|(_, t)| t.runnable())
            .map(|(&id, _)| id);
        after.or_else(|| {
            self.proc
                .threads
                .range(..=self.last)
                .find(|(_, t)| t.runnable())
                .map(|(&id, _)| id)
        })
    }

    /// Marks threads whose waits the posted events end as woken.
    fn deliver_posted(&mut self) {
        if self.proc.posted.is_empty() {
            return;
        }
        let posted = std::mem::take(&mut self.proc.posted);
        for t in self.proc.threads.values_mut() {
            if let Some(w) = &t.wait
                && w.keys.iter().any(|k| posted.contains(k))
            {
                t.woken = true;
            }
        }
    }

    /// Sleeps until some thread's wait may be over.
    fn idle(&mut self) {
        let mut fds = Vec::new();
        let mut deadline: Option<Instant> = None;
        for t in self.proc.threads.values() {
            if let Some(w) = &t.wait {
                fds.extend_from_slice(&w.fds);
                if let Some(d) = w.deadline {
                    deadline = Some(deadline.map_or(d, |c| c.min(d)));
                }
            }
        }
        if fds.is_empty() && deadline.is_none() {
            // Nothing can ever wake a thread: every thread waits for an
            // event only another thread of this process could post.
            self.proc.exit_with(ExitStatus::Internal(
                "deadlock: every thread waits for an event no thread can post".into(),
            ));
            return;
        }
        let ready = wait::sleep(&fds, deadline);
        let now = Instant::now();
        for t in self.proc.threads.values_mut() {
            if let Some(w) = &t.wait {
                let fd_ready = w
                    .fds
                    .iter()
                    .any(|f| fds.iter().position(|g| g == f).is_some_and(|i| ready[i]));
                if fd_ready || w.deadline.is_some_and(|d| d <= now) {
                    t.woken = true;
                }
            }
        }
    }

    /// Handles the trap that ended a slice.
    fn handle(&mut self, thread: &mut Thread, trap: Trap) {
        match trap {
            Trap::Yield => {}
            Trap::Internal(why) => self.proc.exit_with(ExitStatus::Internal(why)),
            Trap::Exception(exc) => {
                if self.proc.config.strace {
                    eprintln!("[{:#x}] exception {exc:?}", thread.tid);
                }
                signal::raise_exception(&mut self.proc, thread, &exc);
            }
            Trap::BadSyscall { number } => {
                if self.proc.config.strace {
                    eprintln!("[{:#x}] invalid system call {number:#x}", thread.tid);
                }
                signal::raise_exception(
                    &mut self.proc,
                    thread,
                    &super::arch::Exception::Undefined {
                        pc: thread.cpu.pc(),
                        reason: format!("EXC_SYSCALL {number:#x}"),
                    },
                );
            }
            other => syscall::dispatch(&mut self.proc, thread, other),
        }
    }
}

/// The audit token of the host process the emulated process runs in
/// (`TASK_AUDIT_TOKEN`), with the emulated credentials; elsewhere a
/// token with the default audit user and session and pidversion 1 (the
/// kernel's version numbers are never zero).
fn host_audit_token(pid: i32, creds: (u32, u32, u32, u32)) -> [u32; 8] {
    let (ruid, euid, rgid, egid) = creds;
    let mut t = [u32::MAX, euid, egid, ruid, rgid, pid as u32, 0, 1];
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u32; 8];
        let mut count: libc::mach_msg_type_number_t = 8;
        // SAFETY: `buf` holds TASK_AUDIT_TOKEN_COUNT (8) integers and
        // `count` says so; the task port is this process's own.
        let kr = unsafe {
            libc::task_info(
                libc::mach_task_self(),
                15,
                buf.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if kr == 0 && count == 8 {
            t[0] = buf[0];
            t[6] = buf[6];
            t[7] = buf[7];
        }
    }
    t
}

/// CPU time the host thread has used, in nanoseconds
/// (`CLOCK_THREAD_CPUTIME_ID`): every guest thread runs on it, so the
/// difference across a slice is that guest thread's time.
fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live timespec for the call's duration.
    let r = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if r != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The emulated machine's boot time in microseconds since the epoch
/// (`kern.boottime`, the commpage's boot time): the wall-clock time at
/// which the emulator's clock read zero, so that uptime, the Mach
/// absolute time, and the boot time agree.
fn boottime_usec() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let up = std::time::Duration::from_nanos(crate::vm::timing::elapsed_nanos());
    now.saturating_sub(up).as_micros() as u64
}
