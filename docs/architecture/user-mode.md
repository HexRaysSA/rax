[← Documentation home](../../README.md)

# User-mode (process-level) emulation

The `rax::user` subsystem runs one guest *program* instead of a machine. It
is independent of `machine/`, `devices/`, and the VM runtime: there is no
board or firmware, only a guest address space, guest threads, and an
operating-system personality that implements the system calls. The
`rax-user` binary ([usage](../getting-started/linux-programs.md)) is its
command-line front end.

```text
rax-user ─> user::linux ─┬─> user::image::elf     (parse)
                         ├─> user::mm             (address space)
                         └─> user::cpu ─> isa::{x86_64, arm::aarch64, riscv}
```

| Module | Owns |
|---|---|
| `user::image::elf` | ELF parsing with Linux `binfmt_elf` acceptance rules |
| `user::mm` | Guest address spaces: VMAs, demand-populated frames, faults, code invalidation |
| `user::cpu` | OS-neutral adapters running each ISA core unprivileged |
| `user::linux` | The Linux personality: ABI tables, loader, stack, files, system calls, process loop |

## Address spaces

An `AddressSpace` holds:

- a **VMA map** (ordered, non-overlapping page ranges with permissions and a
  backing) that is the source of truth for what is mapped;
- a **lock-free page table** — a three-level radix tree of atomic entries
  (36-bit page numbers, 48-bit addresses) — caching the frames of pages
  that have been touched;
- a **frame arena**: one anonymous host mapping created with
  `MAP_NORESERVE`, exposed as guest-physical memory at address zero, so the
  host commits memory only as the guest touches it.

A translation is a few atomic loads when the page is populated. On first
touch the slow path consults the VMA map, allocates a zeroed frame, and
fills it from the backing (anonymous zero, or a page of a file or byte
source). Faults are classified as Linux classifies them: no VMA
(`SEGV_MAPERR`), a VMA forbidding the access (`SEGV_ACCERR`), or a file page
past end of file (`SIGBUS`, `BUS_ADRERR`). Huge `PROT_NONE` reservations cost
one VMA and no page-table memory.

**Shared memory.** A page of a shared mapping is not a copy: it is the
object's own page. The object — the mapped file, or for anonymous shared
memory (`MAP_SHARED | MAP_ANONYMOUS`, a shared mapping of `/dev/zero`) a
Linux `memfd` or an unlinked temporary file standing for the `shmem`
object — is attached to the arena in 256 KiB *extents*, each a host
`MAP_SHARED` mapping laid over an extent of the arena taken from its top
(so every host page size divides it), and the page-table entry points
into it. The guest's stores therefore reach the host page cache: the file
sees them, `read`, `write`, and other mappings (of this or another
process) agree with the mapping, `msync(MS_SYNC)` writes them out, and a
host `fork` leaves the pages shared with the child, as Linux does. An
extent is shared by every page, of any mapping, that lies in it, is
attached read-only for a file not open for writing (and attached again
for writing when a writable mapping needs it), and is detached when no
page points into it. `mremap` duplicates a shared mapping (an old length
of 0) by mapping the same object again. A file the guest truncates loses
its pages past the new end in every mapping, so the next access is
`SIGBUS`, as after `truncate_pagecache`.

**`memfd`** (`fs::memfd`, `syscall::memfd`). A `memfd` is such a nameless
host object wrapped as a regular file, its seals a word of memory shared
with forked processes (so `dup`s, children, and descriptions passed within
the process all see them), enforced where `mm/shmem.c` enforces them:
writes (a grow seal stops a write at the first page-sized chunk that
would extend the file), `ftruncate`, `fallocate`, `fchmod`, `mmap`
(`memfd_check_seals_mmap`), and `MADV_REMOVE`; `F_SEAL_WRITE` is refused
while a shared mapping in this process may write.

Mapping, unmapping, protection changes, `mremap` moves (which move frames
without copying), and population all take the VMA lock; reads of the page
table do not. Every guest thread of a process runs on one host thread, so
no guest access can race a mapping change, and a guest atomic instruction
is atomic with respect to every other guest thread.

**Code invalidation.** CPU cores cache decoded instructions and compiled
regions. The address space logs, with an epoch, every event that can make
such a cache stale — removing execute permission, unmapping or replacing
executable pages, and any write (by a CPU or by the host) to an executable
page. Each adapter applies the log before it resumes guest code.

## CPU adapters

| ISA | Core | Privilege | Syscall exit | Memory path |
|---|---|---|---|---|
| x86-64 | `X86_64Vcpu` in user mode | CPL 3 (`__USER_CS` 0x33) | `SYSCALL` retires with RCX/R11 set and exits `VcpuExit::SystemCall` | `Mmu` flat translation through the address space; fetches checked as executes |
| AArch64 | `AArch64Cpu` via `ArmCpu::step` | EL0t | `SVC` returns `CpuExit::Svc` | `ArmMemory` over the address space; no alignment requirement (SCTLR.A clear) |
| RV64 | `RiscVCpu` | U-mode | `ECALL` returns `RiscVExit::Ecall` | `riscv::Memory` over the address space, with the `fetch_u16` hook for execute permission |

The x86-64 user mode (`src/isa/x86_64/user_mode.rs`) is a default-off
engine mode: paging is replaced by the installed `FlatTranslation`, the IDT
is bypassed and every exception or software interrupt is reported as an
`X86UserEvent` with its vector, error code, and the return RIP the
architectural frame would have held, and `HLT` raises #GP at CPL 3 as the
SDM specifies. System emulation is unchanged when user mode is not enabled.

Adapters clear LL/SC reservations (AArch64 exclusive monitor, RISC-V `LR`
reservation) whenever they leave guest code, as exception entry and return
do on hardware, so an interrupted `LDXR`/`STXR` or `LR`/`SC` sequence fails
and retries. The AArch64 generic timer and the RISC-V `time` CSR follow
host time (62.5 MHz and 10 MHz).

## Linux personality

Behavior follows the Linux 6.19 sources vendored in
`docs/specifications/linux/kernel-6.19/` ([provenance](../specifications/linux/kernel-6.19.provenance.md));
code comments name the kernel function each rule comes from.

- **ABI tables.** System-call numbers and `errno` values are generated by
  `tools/linux/gen_syscalls.py` from the Linux 6.19 UAPI headers vendored in
  `docs/specifications/linux/uapi-6.19/`; the `user_linux` test re-derives
  them from the headers. Per-ABI constants cover the address-space layout
  (`TASK_SIZE`, `STACK_TOP`, `ELF_ET_DYN_BASE`, `mmap_base`), the arm64
  `O_DIRECTORY`/`O_NOFOLLOW`/`O_DIRECT`/`O_LARGEFILE` encodings, and
  structure layouts (`struct stat` differs between x86-64 and asm-generic).
- **Loader.** `load_elf_binary`, `elf_load`, and `load_elf_interp` with
  randomization disabled: `ET_EXEC` at link addresses with
  `MAP_FIXED_NOREPLACE` over the span, PIEs at `ELF_ET_DYN_BASE` rounded to
  `maximum_alignment()`, static PIEs and interpreters top-down below the
  mmap base, `padzero` only for writable segments, `vm_brk_flags` pages
  read-write (executable only if the segment is), `AT_PHDR` from the
  `PT_LOAD` containing `e_phoff`, and the kernel's rejection errors.
- **Initial stack.** `copy_strings` and `create_elf_tables` byte for byte,
  including `ARCH_DLINFO`, `AT_PLATFORM`, `AT_RSEQ_*`, and `AT_MINSIGSTKSZ`
  sized for the signal frame of the emulated CPU state.
- **Exceptions to signals.** x86-64 follows `arch/x86/kernel/traps.c`
  (`INT3`/`INTO` DPL-3 gates, other `INT n` as #GP, #DE → `FPE_INTDIV`, #XM
  code from MXCSR), AArch64 `traps.c`/`fault.c` (`BRK` → `TRAP_BRKPT`,
  undefined and EL1-only accesses → `ILL_ILLOPC`), and RISC-V `traps.c`.
- **Signals.** Generation, queueing, and delivery follow `kernel/signal.c`:
  per-thread and process pending sets with the kernel's dequeue order
  (faults first, then the lowest number), coalesced standard signals and
  queued real-time signals, ignore-at-generation, `SIGCONT`/stop
  cancellation, forced synchronous signals, and default actions. Delivery
  runs on every return to user mode and nests a frame for each deliverable
  signal. Frames are each architecture's `rt_sigframe`, byte for byte:
  x86-64 with the 64-byte-aligned XSAVE area, `_fpx_sw_bytes`, and
  `FP_XSTATE_MAGIC2`, and handlers starting in the initial FPU state;
  AArch64 with the FP/SIMD record, the ESR record after a fault, and the
  frame record; RV64 with the D registers and, on a core with V, the vector
  record. `rt_sigreturn` validates as the kernel does (x86 `XRSTOR` header
  and MXCSR checks, arm64 `valid_user_regs` and record parsing, riscv
  extension headers). Interrupted system calls return the internal restart
  codes, resolved per `SA_RESTART` as `arch_do_signal_or_restart` does.
  Handlers without `SA_RESTORER` (all RV64 handlers, AArch64 handlers that
  omit it) return through a `[vdso]` page holding the vDSO's trampoline
  instructions.
- **Host signals** (`host::forward_host_signals`). An async-signal-safe
  host handler records each forwardable signal and its `kill` sender in
  atomics and writes a byte to a non-blocking close-on-exec wake pipe; the
  personality turns them into process-directed Linux signals
  (`SI_USER` with the sender, else `SI_KERNEL`) before every delivery and
  every wait. Between `rax-user` processes the sender does not come from
  the host (`sigmail`): XNU keeps a signal's `siginfo` in per-process
  fields that a child's exit overwrites (a signal whose sender exits at
  once arrives as `CLD_EXITED`), and one that arrives while the target is
  forking has none. So before its host `kill`, a `rax-user` sender posts
  the target, signal, its PID, and its guest UID in a table shared by every
  process forked from the first, and the target's handler claims the
  record; records older than the target (a reused PID) or than two seconds
  (a duplicate a pending signal absorbed) are ignored. A signal from
  another process keeps the host's report.
  Signals that report an emulator failure (`SIGSEGV`, `SIGBUS`,
  `SIGILL`, `SIGFPE`, `SIGTRAP`, `SIGABRT`) keep their host dispositions.
  A guest killed by a signal without a core dump ends `rax-user` with the
  same host signal.
- **Threads and scheduling** (`sched`). The process's threads run
  round-robin on the one emulated CPU: a thread keeps the CPU until its
  slice ends, it sleeps in a system call, it yields, or it exits.
  `clone`/`clone3` follow `copy_process` and each architecture's
  `copy_thread` (return value 0, stack, `CLONE_SETTLS`, a cleared
  alternate stack, RV64 vector state cleared, `CLONE_*_SETTID` and
  `CLONE_CHILD_CLEARTID` words, the arm64/riscv `CONFIG_CLONE_BACKWARDS`
  argument order). Thread exit follows `do_exit`: process signals meant
  for the thread go to others (`exit_signals`), the robust list is walked
  and PI futexes handed on (`futex_exit_release`), and the
  `clear_child_tid` word is cleared and woken (`mm_release`); the last
  thread's code becomes the process's (`synchronize_group_exit`).
- **Sleeping in system calls** (`wait`). A call that must sleep records
  what ends the wait (descriptors, a deadline, another thread's event such
  as `FUTEX_WAKE`) and its progress, and its thread is parked instead of
  blocking the host. When the wait can end — or, for an interruptible
  wait, a signal is sent to the thread (`TIF_SIGPENDING`) — the call is
  dispatched again with its record and re-evaluates its condition in the
  kernel's order: as in `do_poll` and `pipe_read`, a ready descriptor
  before a pending signal, a signal before the deadline. When every thread
  sleeps the host waits in `poll` on their descriptors, the host-signal
  wake pipe, and the nearest deadline; a wait nothing can end ends the
  process with a diagnostic. Pipes the guest creates are non-blocking on
  the host, so one thread's transfer never stops the others.
- **Processes** (`children`, `exec`). A new process forks the host
  process: the child continues the guest child with a copy of the
  address space and descriptor table, one thread, and no pending signals
  or interval timers (`copy_process`). It reports to its parent through a
  status pipe — `E` when a `CLONE_VFORK` child calls `execve`, `X` with
  the Linux wait status when it ends, which the host's exit status cannot
  express — and ends the host process itself, so a forked child never
  returns to the embedder. The parent watches its children through the
  host `SIGCHLD`, keeps exited ones as zombies for `wait4`/`waitid`
  (`wait_task_zombie`, `wait_task_stopped`, `wait_task_continued`), and
  generates the guest's `SIGCHLD` as `do_notify_parent` does. The
  forwarded host signals stay blocked across the host `fork` until each
  process has set up its own records, so a signal sent to a child the
  moment it exists is not lost, and the child discards the compiled
  native code it inherited and compiles it again (on Apple-Silicon macOS
  hosts, JIT code inherited across the host `fork` intermittently faults
  on its first execution). `execve` builds a complete new image
  (`exec::load_image`, shared with the initial program) before replacing
  anything, so an error leaves the caller intact, then does what the point
  of no return does (`commit_exec`).
- **POSIX timers** (`posix_timers`). The state machine of
  `kernel/time/posix-timers.c` and `posix-cpu-timers.c` over expiries in
  nanoseconds on a base clock (host wall-clock or monotonic time, or the
  emulator's CPU time); relative `CLOCK_REALTIME` settings count on
  monotonic time, as `common_hrtimer_arm` makes them. Expiry is found
  lazily: the scheduler passes the time between slices (and sleeps no
  longer than the next wall-clock or monotonic expiry), and an expired
  timer queues its one preallocated signal record, tagged with the timer
  in the pending queue (`SIGQUEUE_PREALLOC`). A periodic timer stays
  stopped until that record is dequeued (`__posixtimer_deliver_signal`),
  then moves forward past now by whole periods (`hrtimer_forward`), which
  become the signal's overrun count; a setting or deletion since the
  signal was queued makes the dequeue drop it and take the next signal.
  An ignored periodic signal is parked and queued again when a handler
  replaces `SIG_IGN` (`posixtimer_sig_unignore`). `execve` deletes the
  timers and every queued `SI_TIMER` record (`exit_itimers`,
  `flush_itimer_signals`); a forked child has none.
- **Event, timer, and signal descriptors** (`fs::anon`). `eventfd`,
  `timerfd`, and `signalfd` are anonymous-inode files (mode `0600` without
  a file type, `anon_inode:[name]` in `/proc/<pid>/fd`, `O_RDWR` without
  `O_LARGEFILE`, `lseek` 0, no `pread`). Their state lives in anonymous
  memory shared with forked processes, so a description held by a parent
  and a child is one counter or timer, as on Linux; a lock word orders
  changes. A condition a sleeper waits for is mirrored as a *level*: one
  direction of a host socket pair holds exactly one byte while it is true
  (an `eventfd` readable or writable, a `timerfd` with ticks), so the
  scheduler's host `poll`, in any process, wakes on it without consuming
  it. A `timerfd` fires lazily too: one tick at its expiry, the missed
  periods counted when it is read or queried. A `signalfd` reports the
  reading thread's pending signals; queueing a signal wakes threads
  sleeping on a `signalfd` of it, even while the signal is blocked
  (`signalfd_notify`).
- **pidfds** (`fs::pidfd`, `syscall::pidfd`). A pidfd is an
  anonymous-inode file of `pidfs` (mode `0700` without a file type, owned
  by root, one inode per task, `anon_inode:[pidfd]` in `/proc/<pid>/fd`)
  naming a task by its process's host PID and its thread ID. What it
  reports depends on where the task lives. A thread of the calling
  process and a child of it are known exactly from the process's own
  records; a thread's exit and a child's reaping reach every pidfd of it
  through the process's registry of its pidfds' tasks (as `pidfs_exit`
  does), with the wait status, and wake threads sleeping in `poll`,
  `select`, or `epoll`. Any other process is watched through the host
  from the moment the pidfd is made (a host pidfd on Linux, a kqueue with
  an `EVFILT_PROC` filter on macOS), so a PID the host reuses is never
  taken for it; it is gone once it exits, since only its parent's records
  know its zombie. A forked child watches the tasks of the pidfds it
  inherits the same way from the fork on (a kqueue does not survive
  `fork`), and a task that had the child's new PID is gone.
  `pidfd_send_signal` finds the task by its ID and directs the signal at
  it or at its thread group through the paths of `tgkill` and `kill`;
  `waitid(P_PIDFD)` selects the child a pidfd names, `WNOHANG` and then
  `EAGAIN` for a non-blocking pidfd; `CLONE_PIDFD` checks the free
  descriptor and the result word before the task exists, so neither
  failure leaves a task behind.
- **Readiness and `epoll`** (`syscall::ready`, `fs::epoll`). Each file
  reports the mask its `f_op->poll` computes (`pipe_poll` for pipes, with
  the queued bytes read by `FIONREAD`, since the host's `poll` reports
  pipes differently), a level (bytes queued, a counter, ticks, signals),
  and what a sleeper waits on; `poll`, `select`, and `epoll` share it. An
  `epoll` item is keyed by the open file description, held weakly, and
  the descriptor number. Wake-ups the emulator causes itself (a pipe
  written, read, or closed through the guest, an `eventfd` changed, a
  nested instance becoming ready) link the watching items at once, in
  order, as `ep_poll_callback` does; readiness from outside (terminal
  input, other processes, timer expiries, signals) is found when an
  instance is polled, an edge-triggered item counting a growth of its
  file's level as a wake-up. Reporting follows `ep_send_events`: items
  re-polled at the head of the ready list, level-triggered ones queued
  again at the tail after those there was no room for.
- **Sockets** (`net`, `syscall::net`). `AF_UNIX`, `AF_INET`, and
  `AF_INET6` sockets are host sockets, always non-blocking on the host;
  the personality keeps what Linux has and the host lacks (the name a
  Unix socket was bound to, the timeouts, Linux's reported buffer sizes,
  the listening state, its own shutdowns) and translates addresses,
  flags, options, and errors. A call that would block sleeps on the
  socket (`Resume::Socket` records the bytes transferred, the timeout's
  end, and a batch position), so `SO_RCVTIMEO`/`SO_SNDTIMEO` end it with
  `EAGAIN` and a signal with `-ERESTARTSYS`, or `EINTR` once a timeout is
  set (`sock_intr_errno`). Unix paths resolve through the VFS to
  absolute host paths; a host path longer than the host's `sun_path` is
  reached through its directory (a `/proc/self/fd` link on Linux, a
  short-lived symbolic link on macOS). The abstract namespace is the
  host's on Linux; on macOS an abstract name is a socket file in a
  per-user directory named by a hash, with the name recorded beside it
  and a lock file the binding socket holds, so a name is taken exactly
  while its socket lives. `SCM_RIGHTS` descriptors travel as host
  descriptors, so they reach other processes; each send also records the
  description by its host object's identity, so a receiver in the same
  process gets the same description (shared status flags), and a
  description without a host descriptor travels as a stand-in socket
  only that record resolves. Readiness is `sock_poll`'s: the host's mask
  on Linux; on macOS, whose masks differ (no `POLLRDHUP`, `POLLHUP` after
  one shutdown, no `POLLOUT` after a shutdown, nothing for a new stream
  socket), it is derived from the `unix_poll`/`tcp_poll`/`datagram_poll`
  rules and the socket's state (`net::poll`).
- **Netlink** (`net::netlink`). On Linux hosts `AF_NETLINK` sockets are
  the host's, every protocol, with `struct sockaddr_nl` and the
  `SOL_NETLINK` options and control messages passed through. Elsewhere
  `NETLINK_ROUTE` is emulated: the socket's host descriptor is a readiness
  level over a queue of datagrams the kernel side fills when the guest
  sends requests. `route` answers them as `rtnetlink_rcv_msg` dispatches
  (link dumps and lookups, address dumps by family, one IPv6 address,
  `-EPERM` for changes without `CAP_NET_ADMIN`, `-EOPNOTSUPP` otherwise),
  from a snapshot of the host's interfaces (`ifaces`: `getifaddrs` and
  the media status, translated to Linux types, flags, operational states,
  and scopes). The socket side follows `af_netlink.c`: port IDs (the
  process's, then negative ones), groups, acknowledgements carrying the
  request unless capped, a dump paced a datagram per receive by the
  largest buffer seen with `NLMSG_DONE` alone where rtnetlink splits it,
  one dump at a time, `MSG_TRUNC`, and `NETLINK_PKTINFO`. A forked child
  gets its own readiness level over its copy of the queue.
- **System V IPC** (`ipc`, `syscall::ipc`). The objects of every
  `rax-user` process of a host user share one namespace: a directory
  (per user under the temporary directory, or `LinuxConfig::ipc_dir`)
  holding each type's table as text, read and replaced whole under an
  exclusive `flock`, with identifiers allocated as `ipc_idr_alloc`
  allocates them. A shared memory segment's pages are a host file there,
  which `shmat` maps shared (named `/SYSV<key> (deleted)`, its identifier
  the inode `/proc/<pid>/maps` shows), so every process sees every store.
  Attaches are counted by mapping as the kernel counts them (a split
  mapping counts twice and is not merged back): after the calls that
  change its mappings, and at `fork`, `execve`, and exit, a process
  publishes how many mappings of each segment it has, and `shm_nattch` is
  the sum over processes still alive, so a segment marked for removal
  goes with its last attach even when its last process was killed. A
  semaphore operation list is applied all or none, in order, under the
  table's lock; a caller that must wait records its blocking operation
  (for `GETNCNT` and `GETZCNT`) and tries again every 2 ms until it can,
  its timeout passes, the set is removed (`EIDRM`), or a signal ends it
  (`EINTR`). Each thread holds a reference to an undo list, made at its
  first `SEM_UNDO` and shared by the threads `CLONE_SYSVSEM` makes; the
  adjustments, recorded per process, apply when the last holder leaves
  its list (exit, `unshare(CLONE_SYSVSEM)`) and no other thread holds
  one, at the process's exit otherwise, or, for a killed process, when
  the table is next read after it is gone. A message queue
  keeps its messages in the table; a send that does not fit and a receive
  that finds nothing wait the same way, a signal ending them with
  `-ERESTARTNOHAND`.
- **Seccomp** (`seccomp`, `syscall::seccomp`). Each thread has a mode and
  a chain of classic BPF filters, newest first, shared with the threads
  and processes that inherited it (`clone` and `fork` copy it, `execve`
  keeps it, `SECCOMP_FILTER_FLAG_TSYNC` gives the caller's chain to every
  thread whose own chain it extends). A filter must pass
  `bpf_check_classic` and `seccomp_check_filter`, and a chain is bounded
  by its length as `bpf_convert_filter` converts it to eBPF (each return
  of a constant two instructions, a division by `X` five, a conditional
  jump one or two, and a three-instruction prologue), as the kernel
  bounds it. A call is checked when it enters (a call that slept is not
  checked again when it runs on), before its handler: the filters run
  over its `struct seccomp_data` (number, `AUDIT_ARCH_*`, the address
  after the calling instruction, arguments), the action ranking lowest
  wins (the newest filter's on a tie), and it is decided as
  `__seccomp_filter` decides it: an errno (capped at 4095), `SIGSYS` with
  `SYS_SECCOMP` and the registers untouched, the thread's death (alone
  while others live) or the process's by `SIGSYS`, or `ENOSYS` for a
  tracer or listener that cannot exist. Strict mode allows `read`,
  `write`, `exit`, and `rt_sigreturn` and kills the thread alone with
  `SIGKILL`; on x86-64 it also sets `TIF_NOTSC`, as `PR_SET_TSC` does,
  which is the thread's CR4.TSD, so `RDTSC` and `RDTSCP` fault with
  `SIGSEGV` on every execution path. x86-64 `INT 0x80` calls are checked
  as `AUDIT_ARCH_I386` ones. `no_new_privs` is a thread's, as in Linux.
- **File-system notification** (`fsnotify`, `syscall::inotify`,
  `syscall::notify`). An inotify instance is the host's on Linux hosts
  (`fsnotify::Backend::Host`): the host kernel reports what any process
  does to the files, `rax-user`'s own host calls included, which follow
  the guest's (a vectored read that finds nothing makes a zero-length
  host `readv`, `truncate` truncates by path). Elsewhere it is emulated
  (`Backend::Emulated`): the file calls report what they did, in the
  order of `include/linux/fsnotify.h`'s hooks, to a namespace every
  `rax-user` process of the host user shares — a directory holding the
  watches (the marks) in a mapped index with a hash of the watched inodes,
  each instance's queue in a mapped file, and a FIFO per instance that
  holds a byte while its queue is not empty — so that a child's writes
  reach its parent's instance. Delivery follows `fsnotify`,
  `send_to_group`, and `inotify_handle_inode_event` (a directory hears
  of a child before the child itself; names only for entry changes;
  `IN_ISDIR`; the special-file and `IN_EXCL_UNLINK` exclusions; one-shot
  watches), and the queue `fsnotify_insert_event` (merging with the last
  event, one `IN_Q_OVERFLOW` past `max_queued_events`). An open file
  carries a token whose last reference reports its close: its mappings
  hold it (`vm_file`), a forked process shares it through a count in the
  namespace, exit releases it, and an inode whose last link went while it
  was open ends (`IN_DELETE_SELF`) at its last close. `execve` opens the
  executable and interpreter (`IN_OPEN`, `IN_ACCESS`) for as long as the
  image runs. Nothing costs more than two loads while nothing is watched.
- **POSIX message queues** (`ipc::mqueue`, `syscall::mqueue`). A queue
  is a host file in the IPC namespace directory holding its attributes,
  owner, notification, messages, and waiting tasks, with a table of names
  beside it; a description holds the file open, so an unlinked queue
  lives until its last description closes in any process, and every
  change happens under the namespace's lock. Messages go highest priority
  first, first in first out within one (`msg_insert`, `msg_get`). A task
  that must wait registers in the queue and renews its registration as it
  retries every 2 ms: a send hands its message to the first waiting
  receiver (`pipelined_send`), and a receive that frees a slot queues the
  first waiting sender's message (`pipelined_receive`); a registration
  not renewed for a second is a task that is gone. A notification goes to
  its registering process when a message arrives in an empty queue
  without a waiting receiver: `SI_MESGQ` with the sender's IDs and the
  value, sent to another process through the host with the record
  `sigmail` carries, and dropped by that process's close of any
  descriptor of the queue. The queue file reads as its status line,
  seeks against its size, polls readable while messages wait and
  writable while there is room, and stats as the kernel's inode;
  `/proc/<pid>/fd` shows `/<name>`, and ` (deleted)` once unlinked.
- **Scheduling attributes** (`priority`, `syscall::priority`). Each
  thread carries the kernel's scheduling state: policy, static, normal,
  and effective priorities, real-time priority, `reset_on_fork`, the fair
  slice, deadline parameters, timer slack, and its I/O context, which
  the threads that `CLONE_IO` made share (a priority set through one is
  all of theirs; a `CLONE_IO` child process gets its own copy). The calls
  change and report it with `__sched_setscheduler`'s checks and
  permission rules (`RLIMIT_NICE`, `RLIMIT_RTPRIO`, `CAP_SYS_NICE` being
  root), `sched_fork` applies it to new threads and processes, and
  `/proc/<pid>/stat` shows it; nothing is scheduled by it, the threads
  sharing one emulated CPU. The kernel modelled has one CPU (a 700 µs
  base slice), `CONFIG_HZ=250`, no utilization clamping, and no
  `SCHED_EXT`; deadline tasks are admitted within 95% of the CPU less the
  fair server's 5%. A task is named by a thread of the calling process;
  another process's tasks are not reachable, except that root always has
  some (`init`), which another user's `ioprio_set` may not change.
- **Process memory and kernel objects** (`syscall::task`,
  `syscall::procmem`, `syscall::kcmp`, `syscall::iov`). A call naming a
  task by ID or pidfd finds the caller's threads, and its leader after
  that has exited while others run (without memory, tables, I/O context,
  or undo list; its signal handlers stay). Another process lives in
  another host process whose memory and tables this one cannot reach, so
  the right to inspect it fails as a denied `ptrace_may_access` does, for
  root too: `process_vm_readv` and `process_vm_writev` return `EPERM`,
  `process_madvise` `mm_access`'s `EACCES`, `kcmp` `EPERM`. Transfers
  reach the caller's memory as `get_user_pages` does: page by page from
  the start of each remote vector, a read needing `VM_READ` and a write
  `VM_WRITE`, so a transfer ends at the first page it cannot reach or at a
  local fault, exactly, with the bytes moved so far. Every vectored call
  (`readv`, `writev`, the positioned forms, `sendmsg`, `recvmsg`, and
  these) imports its vectors as `__import_iovec` does before anything
  moves: the count an `unsigned int`, a single vector capped at
  `MAX_RW_COUNT` before `access_ok`, several each checked at full length
  and then capped to `MAX_RW_COUNT` in total. `kcmp` compares the objects modelled per task: the
  address space, descriptor table, and file-system context shared by
  every thread, the signal handlers, each thread's I/O context and undo
  list, and open file descriptions (with epoll items found by descriptor
  and offset), ordered by their identities under fixed per-type cookies.
- **Machine administration and mounts** (`syscall::admin`,
  `syscall::mount`, and the clock-setting calls in `syscall::time`). The
  calls that act on the machine rather than on the caller's objects —
  swap, `reboot`, `acct`, the host and domain names, `vhangup`, I/O ports,
  modules, the kernel log, `chroot`, setting and adjusting the clocks,
  and the mount calls — make the kernel's checks in its order. An
  unprivileged caller fails at the capability check with `EPERM`. Root
  holds every capability, as `capget` reports, so it passes; the checks
  that follow still apply, and the change itself is refused with
  `EOPNOTSUPP` (the host's machine, clock, and mounts are not the guest's
  to change), as interface changes are. What needs no privilege works:
  reading the NTP state (`adjtimex` without modes: the kernel's boot
  state, an unsynchronized clock), `open_tree` without a clone (an
  `O_PATH` open), revoking I/O ports or `iopl` 0, and turning accounting
  off. The kernel log is empty and `dmesg_restrict` is set, so every
  `syslog` action needs `CAP_SYSLOG`; for root, reading waits for a
  message until a signal. kexec is absent (`ENOSYS`), as in a kernel
  built without it; no file-system context is ever opened, so `fsconfig`
  and `fsmount` find none. Linux 7.0 changed three orders the reference
  6.19 has: it checks `settimeofday`'s microseconds against a whole
  second before reading the time zone, looks up `pivot_root`'s paths
  before `may_mount`, and accepts `OPEN_TREE_NAMESPACE`; `rax-user`
  answers as 6.19 does.
- **Interface requests** (`net::ifreq`). The socket `ioctl`s about
  interfaces (`SIOCGIFCONF`, `SIOCGIFINDEX`, `SIOCGIFNAME`,
  `SIOCGIFFLAGS`, `SIOCGIFHWADDR`, `SIOCGIFADDR`, and the rest) pass
  through to a Linux host with their `struct ifreq` bytes (every guest ABI
  is LP64, so the layout is the host's; `SIOCGIFCONF`'s buffer goes
  through a host copy). Elsewhere they are answered from the same view of
  the host's interfaces as netlink, routed by the socket's family as
  `sock_ioctl` routes them (`inet_ioctl` takes the IPv4 address requests,
  other families reach `dev_ioctl`, which does not know them), with the
  kernel's name handling (an alias's `:` suffix, the 16th byte cleared) and
  the argument's untouched bytes kept.
- **Signal targeting.** A signal is queued for a thread or for the process;
  `complete_signal` then wakes the thread that should take it — the
  suggested thread if it wants it (unblocked, and running or without a
  signal pending), else the next such thread from `curr_target` — and a
  fatal signal without a core dump ends the process at once. A thread
  that blocks a signal meant for it passes it on
  (`retarget_shared_pending`).
- **Futexes** (`futex`). FIFO wait queues keyed as `get_futex_key` keys
  them (private and shared keys never match), with `futex_wake`'s count
  rule, requeue and wake-op counting, PI ownership words (`FUTEX_WAITERS`,
  `FUTEX_OWNER_DIED`, hand-over to the first waiter on unlock or owner
  exit), `futex_waitv`, and the `futex2` calls; a woken wait returns 0
  whatever else happened, as `futex_unqueue` reports.
- **Timers and restarts** (`timers`). `ITIMER_REAL` follows
  `kernel/time/itimer.c`: it re-arms only when its `SIGALRM` is dequeued,
  at the next interval multiple after the last expiry, so a blocked
  `SIGALRM` accumulates no expiries; the CPU-time timers add `TICK_NSEC`
  and re-arm at expiry (`posix-cpu-timers.c`). Interrupted sleeps and
  `poll` save a `restart_block` so `restart_syscall` resumes them with the
  remaining time; `select` and `poll` write back the time left and
  `revents` as `poll_select_finish` and `do_sys_poll` do.
- **System calls.** 310 calls across descriptors and I/O, paths and
  metadata (with device and FIFO nodes, file times, and extended
  attributes), memory management (with `memfd_create`, locking, sealing,
  and access through a task's ID), identity (with
  supplementary groups) and limits, scheduling attributes, clocks,
  signals, threads, futexes,
  processes (with pidfds), POSIX timers, event, timer, and signal
  descriptors, `epoll`, sockets, System V and POSIX IPC, seccomp,
  inotify, and machine administration and mounts, each validated in the kernel's order so the first failing
  check determines the `errno`. Host `errno` values are translated by name.
  Memory calls act VMA by VMA as `mm/mprotect.c` and `mm/madvise.c` do,
  including partial application before a failing VMA or hole; the Linux VMA
  properties that change results (`VM_GROWSDOWN` on `[stack]`, `VM_MAYWRITE`
  clear on shared mappings of read-only files, `VM_READ` apart from
  readable pages, `VM_LOCKED` and `VM_LOCKONFAULT`, the special `[vdso]`
  mapping, `VM_SEALED`) live in `Vma::flags` (`abi::vma_flags`). A sealed
  VMA (`syscall::mseal`) refuses what `vma_is_sealed` refuses where the
  kernel checks it: every unmapping (`munmap`, and `mmap`, `shmat`, or
  `mremap` over it) with nothing changed, `mremap` of it, `mprotect` VMA
  by VMA, and discarding advice on private anonymous memory that could
  not be written; `brk` and `shmdt` leave it mapped. Memory locking
  (`syscall::mlock`) keeps `mm->locked_vm` as the kernel keeps it, a count
  the calls raise and lower (so a `MREMAP_DONTUNMAP` move of locked memory
  leaves its old pages counted, as on Linux), checks `RLIMIT_MEMLOCK`
  wherever the kernel does (`mlock`, `mlockall`, `MAP_LOCKED`, and
  `MCL_FUTURE` growth by `mmap`, `brk`, `mremap`, and `shmat`), brings
  locked pages in, and makes `madvise` refuse to discard them; a new
  process starts with nothing locked. One deliberate deviation: `MADV_GUARD_INSTALL` and
  `MADV_GUARD_REMOVE` are refused with `EINVAL`, as on a kernel without
  guard regions, instead of being accepted without effect. `MADV_REMOVE`
  zeroes the object's bytes (its size kept), which is what a punched hole
  reads as.
- **Files.** Guest paths resolve through the sysroot overlay; host files are
  opened with `std` and wrapped as Linux open file descriptions (shared by
  `dup`, with per-descriptor close-on-exec). `/proc` entries about the
  process are synthesized from personality state; `/proc/<pid>/fdinfo`
  (`fdinfo`) prints what `seq_show` does (position, status flags with
  `O_CLOEXEC`, a mount ID per file system, the inode number) and the
  lines of the pidfd, `eventfd`, `timerfd`, `signalfd`, and `epoll`
  `show_fdinfo` operations.
- **Nodes, times, and the umask** (`nodes`). `mknod` and `mknodat` follow
  `do_mknodat`: the type, then the name, then the privilege (device nodes
  need a privileged guest); FIFOs and device nodes are host nodes, and a
  socket node is a bound Unix socket where the host refuses to make one
  (macOS, for other users than root). `utimensat` looks the path up before
  it checks the times, and `utime`, `utimes`, and `futimesat` convert to it
  as `fs/utimes.c` does. The guest has its own umask, inherited from the
  host at start; a new file or directory gets the mode that umask leaves
  even where the host's stripped more bits.
- **Extended attributes** (`xattr`). The `*xattr` calls and the
  `*xattrat` calls check in `fs/xattr.c`'s order (flags, name, value,
  object, then the namespace's permission) and give host files the
  handlers of a disk file system mounted without POSIX ACLs: `user.*` on
  regular files and directories only, `trusted.*` for a privileged guest,
  `security.*` set only by one, and `EOPNOTSUPP` for other names,
  `system.posix_acl_*` included. The attributes are the host file's; a
  macOS host stores a name it cannot hold (not UTF-8, or longer than 127
  bytes) under a hashed `rax.x.` name whose value begins with the full
  name, and its own names are not shown. Sockets have `sockfs`'s
  `system.sockprotoname`; pipes, anonymous inodes, and synthesized `/proc`
  files have none.
- **File locks** (`locks`). Guest processes are host processes and each
  open file description owns one host descriptor, so guest locks are host
  locks with Linux's owners: `flock` locks and OFD record locks belong to
  the description (shared by `dup` and `fork`), POSIX record locks to the
  process; they also exclude other host programs. `fs/locks.c`'s checks
  come first (the command, the descriptor, then `flock64_to_posix_lock`'s
  range, the type, and the access mode). Closing any descriptor of a file
  releases the process's POSIX locks on it (`locks_remove_posix`), also
  when the description stays open through another descriptor; the
  descriptors the emulator keeps for mappings of such a file are kept
  open until then, since closing one would release the locks on the host
  while `munmap` releases none on Linux. A conversion that would wait
  loses the old `flock` lock, as `flock_lock_inode` removes it first (a
  macOS host keeps it; it is removed there). A waiting call (`flock`
  without `LOCK_NB`, `F_SETLKW`, `F_OFD_SETLKW`) tries again every 2 ms
  while other guest threads run, and a signal ends it with
  `-ERESTARTSYS`.
- **Groups, read-ahead, and range sync** (`misc`). Supplementary groups
  start as the host's; `setgroups` needs a privileged guest and sorts
  them as `groups_sort` does, and `/proc/<pid>/status` lists them.
  `readahead` checks the descriptor and the file's type as
  `ksys_readahead` does; `sync_file_range` checks its flags, then the
  range, then the file as `fs/sync.c` does, and writing a range
  (`SYNC_FILE_RANGE_WRITE`) writes the host file's data.

## Evidence

| Claim | Evidence |
|---|---|
| ELF acceptance matches `binfmt_elf` | Unit tests in `src/user/image/elf/tests.rs`, including a 20,000-image corruption sweep |
| Address-space semantics | Unit tests in `src/user/mm/tests.rs`, including a randomized model-based differential (8 seeds × 3,000 operations), and shared objects: stores reaching the file and the file's changes reaching the mapping, pages shared between mappings and moves, bus errors past the end, read-only objects refusing forced stores, re-attachment for writing, detaching, and the frame and extent allocators never overlapping |
| x86-64 user-mode contract | `src/isa/x86_64/user_mode_tests.rs` (28 tests; the JIT-invalidation test is discriminating on x86-64 hosts; the XSAVE-image tests compare with the `XSAVE`/`XRSTOR` instructions, which also keep x87 tags across `FXRSTOR`/`XRSTOR`) |
| Adapter contracts | `src/user/cpu/tests.rs` (21 tests across the three ISAs, including JIT/interpreter agreement on RISC-V) |
| Loader and stack layout | `src/user/linux/tests/{loader,stack}.rs` with addresses derived by hand from the kernel algorithms |
| Signals | `src/user/linux/signal/tests.rs` (records, queues, alternate stacks) and `src/user/linux/tests/signals.rs` (frames, `rt_sigreturn`, restart, and the signal calls on every ABI, with offsets from the UAPI structures) |
| Threads, futexes, and signal targeting | `src/user/linux/tests/threads.rs` (14 tests): `clone`/`clone3` register state and validation on every ABI, `unshare`'s implied flags and checks alone and with another thread, futex wait/wake/bitset/requeue/wake-op/PI and interrupted waits, robust-list and `clear_child_tid` handling at exit, `complete_signal` choice and retargeting, thread and process exit status, `CLONE_VFORK`, and the `/proc` thread views |
| `execve` and waits | `src/user/linux/tests/exec.rs`: `#!` parsing edge cases of `load_script`, `execve`/`execveat` error order on every ABI, the argument space charged to the byte (pointers, an empty `argv`, a script's rewritten arguments), a script named by a close-on-exec descriptor, the image replacement with a script and what survives it, `wait4`/`waitid` argument checks and `siginfo_t` writes on errors, children passing to a live thread (`__WNOTHREAD`) on thread exit and `execve`, and processes unavailable without host processes |
| `epoll` and readiness | `src/user/linux/tests/epoll.rs`: `do_epoll_ctl` and `do_epoll_wait` checks in order on every ABI, each ABI's `struct epoll_event`, level-triggered, edge-triggered (including a write from outside the emulator), and one-shot items, hang-up and error, the ready-list order, `maxevents` rotation, and a faulting buffer, items keyed by description, nesting and loop depth, and sleeping, `EINTR`, and `epoll_pwait`'s mask. `src/user/linux/tests/waits.rs`: pipes in `ppoll` as `pipe_poll` reports them |
| Sockets | `src/user/linux/tests/sockets.rs` (15 tests on every ABI): `__sock_create` and `inet_create` checks in order, `socketpair` writing its reserved descriptors first, Unix names (relative and over-long paths, node permissions, rebinding, abstract names in use and freed, autobind), `move_addr_to_user` copies, IP `bind`/`connect` address checks, `copy_msghdr_from_user` checks, `scm_detach_fds` installation and `MSG_CTRUNC`, descriptions shared within the process, `SCM_CREDENTIALS` checks and `SO_PASSCRED` delivery, timeouts and signal interruption, `sk_setsockopt`/`sk_getsockopt` rules, `SIGPIPE` by protocol, `sendmmsg`/`recvmmsg`, readiness and the socket `ioctl`s, IPv6; unit tests of the address codec, control-message framing, name mapping, and timeouts in `src/user/linux/net/` |
| POSIX timers | `src/user/linux/tests/posix_timers.rs`: the state machine driven by explicit times against `hrtimer_forward` arithmetic (overrun counts, one-shot and `SIGEV_NONE` `gettime`, the 1 ns of a fired but unqueued timer, stale signals, CPU timers set in the past, parked ignored signals), `timer_create` error order and ID use on every ABI, the other calls' checks, one queued record per timer, stale-record drops, re-queueing when `SIG_IGN` is replaced, thread targets, and `execve`'s flush |
| Event, timer, and signal descriptors | `src/user/linux/tests/events.rs`: `eventfd` limits, semaphores, zero-length and faulting transfers, `readv`/`writev` segments, and levels; `timerfd` ticks driven by explicit times, `TFD_IOC_SET_TICKS`, and argument order on every ABI; anonymous-inode `fstat` and `/proc` names; `signalfd` checks, reads in order, lost records at a fault, every `siginfo_t` layout's `struct signalfd_siginfo`, and wake-ups of blocked readers and pollers. `src/user/linux/tests/files.rs`: `F_GETFL` of regular, `O_PATH`, directory, pipe, and `eventfd` descriptions |
| Nodes, file times, and the umask | `src/user/linux/tests/nodes.rs`: `do_mknodat`'s type, name, and privilege checks in order; `utimensat` looking the path up before checking the times; the older calls converted as `fs/utimes.c` converts them; the guest's umask alone masking new files |
| Netlink | `src/user/linux/tests/netlink.rs` (10 tests on every ABI; the host's sockets on Linux, the emulation elsewhere): `netlink_create`'s checks, port IDs and `netlink_bind`, acknowledgements and errors (capped, several messages per send, privilege), link dumps and lookups by index and name, address dumps by family, `MSG_PEEK`/`MSG_TRUNC`/timeouts, membership and options, `NETLINK_PKTINFO`, the calls netlink lacks, readiness, a socket passed within the process; unit tests of `rtnetlink_rcv_msg` dispatch, message layouts, dump pacing and `NLMSG_DONE` placement, send checks, and the host interface translation in `src/user/linux/net/netlink/` |
| System V message queues | `src/user/linux/tests/sysvmsg.rs` (2 tests on every ABI): `msgsnd`'s and `msgrcv`'s checks in order, message types (`MSG_EXCEPT`, the least type up to a bound), `E2BIG` and `MSG_NOERROR`, `MSG_COPY`, a full queue, `msgctl`'s commands, and a receiver waiting for its type, ended by a removal or a signal; unit tests of `find_msg` and `msg_fits_inqueue` in `src/user/linux/ipc/msg.rs` |
| Memory locking | `src/user/linux/tests/mlock.rs` (6 tests, on every ABI): `mlock`, `mlock2`, and `munlock` (the right, the limit less what is already locked, whole pages, the kernel's length arithmetic, holes, `PROT_NONE`), populating or not, `madvise`'s refusals, `mlockall` with `MCL_FUTURE` through `mmap`, `brk`, and `mremap` (`MREMAP_DONTUNMAP`'s count), the special `[vdso]` mapping, `VmLck`, and a new process |
| Memory sealing | `src/user/linux/tests/mseal.rs` (4 tests, on every ABI): `mseal`'s checks in order, the unmapping, remapping, and reprotecting a seal refuses (partial `mprotect` included), discarding advice by writability and backing, `brk` and `shmdt` keeping sealed pages, `SHM_REMAP` |
| Vector import | `src/user/linux/tests/vectored.rs`: vectors imported before anything moves (a far vector refuses the whole transfer and leaves a file's position), the count as an `unsigned int`, a single vector capped before `access_ok`, a length beyond memory, `sendmsg` and `recvmsg`; `src/user/mm/tests.rs`: a probe of any length ends at the first fault |
| Process memory and kernel objects | `src/user/linux/tests/procmem.rs` (4 tests, on every ABI): `process_vm_readv` and `process_vm_writev`'s checks in order and vector import, transfers by page with `VM_READ` and `VM_WRITE`, partial transfers at a remote or local fault, a thread's ID, an exited leader, another process; `process_madvise`'s checks, advice by vector with empty and misaligned vectors, pidfds. `src/user/linux/tests/kcmp.rs` (3 tests, on every ABI): `kcmp`'s checks in order, open file descriptions and their total order, what threads share by `CLONE_IO` and `CLONE_SYSVSEM`, an exited leader, epoll items by descriptor and offset; the order's unit test in `src/user/linux/syscall/kcmp.rs`. `VM_READ`: `src/user/linux/tests/syscall_mm.rs` (`/proc/self/maps`, `MADV_POPULATE_READ`) and `src/user/linux/tests/loader.rs` (a segment without `PF_R`) |
| Scheduling attributes | `src/user/linux/tests/priority.rs` (9 tests, on every ABI) and the unit tests of `src/user/linux/priority.rs`: defaults, the priority ranges, `sched_setscheduler`'s checks in order and the permission rules, `sched_setattr`'s sizes, flags, slices, `SCHED_IDLE`, and kept policy or parameters, `sched_getattr`, deadline admission and `EAGAIN` at `clone`, time slices, nice values (a thread, the group, the user, a partial failure), inheritance, `reset_on_fork`, timer slack, `/proc/<pid>/task/<tid>/stat`, and I/O priorities and their sharing by `CLONE_IO` threads |
| POSIX message queues | `src/user/linux/tests/mqueue.rs` (9 tests, on every ABI): `mq_open`'s checks in order, the attributes, limits, `RLIMIT_MSGQUEUE` charge, and permissions, priorities, the status line and position, sizes, access, timeouts, a message taken although its copy faults, waiting receivers handed messages and waiting senders given slots, a signal ending a wait, notifications (`SI_MESGQ`, once, `EBUSY`, removal by closing, none while a receiver waits, `SIGEV_THREAD`'s checks), `mq_getsetattr`, unlinked queues, and `poll`; the `sigmail` unit test of records with a code and value |
| Machine administration and mounts | `src/user/linux/tests/admin.rs` (10 tests) and `src/user/linux/tests/mounts.rs` (7 tests), on every ABI (the I/O port calls on x86-64): each call's checks in order for an unprivileged caller and for root, the refusals, the empty kernel log and its wait, reading the NTP state and the `timex` bytes written back or not, the CPU-time and device clocks, `mount`'s string and option copies, `copy_struct_from_user` zero checks up to a fault, `build_mount_kattr`, `open_tree` as an `O_PATH` open and its descriptor taken first, and `open_tree_attr` publishing its descriptor only on success |
| inotify | `src/user/linux/tests/inotify.rs` (9 tests, on every ABI and, on Linux hosts, with both backends, so that the host kernel checks the expectations): the calls' checks in order, descriptors, the events of each file call and their order, a file watching itself through removal and renames, merging, overflow, `read`'s records, `FIONREAD`, waiting readers, one-shot and `IN_EXCL_UNLINK` watches, closes at the last reference (a duplicate, a mapping), `fdinfo`, `poll`, and the limits; unit tests of delivery in `src/user/linux/fsnotify/mod.rs` and of the queue in `src/user/linux/fsnotify/queue.rs` |
| Seccomp | `src/user/linux/tests/seccomp.rs` (10 tests, most on every ABI): installing in `seccomp_set_mode_filter`'s order, the eBPF-length bound, what filters see and decide, `SECCOMP_RET_TRAP`'s `SIGSYS`, the kill actions against the number of threads, strict mode, TSYNC, calls checked once as they enter, x86-64 `INT 0x80` calls as i386 ones, and `TIF_NOTSC` faulting `RDTSC`; unit tests of the checks, the conversion length, and running in `src/user/linux/seccomp/bpf.rs`, and of verdicts and chains in `src/user/linux/seccomp/mod.rs` |
| System V semaphores | `src/user/linux/tests/sysvsem.rs` (5 tests on every ABI): values and `semctl`'s commands with each ABI's `semid64_ds`, operation lists all or none and in order, `semtimedop`'s checks in order and its timeout, waits counted by `GETNCNT` and `GETZCNT` and ended by a value, a removal, or a signal, `SEM_UNDO` at exit, undo lists shared by `CLONE_SYSVSEM` or a thread's own, left by `unshare(CLONE_SYSVSEM)` or a thread's exit; unit tests of `perform_atomic_semop`'s rules and `exit_sem` in `src/user/linux/ipc/sem.rs` |
| System V shared memory | `src/user/linux/tests/sysvshm.rs` (3 tests on every ABI): attaches seeing each other's stores, attach counting by mapping (split, not merged back), `shmdt` and `munmap`, `/proc/self/maps`, read-only attaches, `SHM_RND` and `SHM_REMAP`, keys, `SHM_STAT`, `IPC_INFO`, `SHM_INFO`, `IPC_SET`, `SHM_LOCK`, and removal while attached; unit tests of identifier allocation, `ipcperms`, the tables, and publication in `src/user/linux/ipc/` |
| Interface requests | `src/user/linux/tests/ifreq.rs` (every ABI; the host's answers on Linux, the emulation elsewhere): `SIOCGIFCONF`'s length and entries, the device requests by name and index on IPv4, Unix, and netlink sockets, the hardware address's untouched bytes, IPv4 addresses on an IPv4 socket only, unknown devices, faults, privilege, driver requests; unit tests of `dev_ioctl`, `devinet_ioctl`, `dev_ifconf`, and IPv6's address changes in `src/user/linux/net/ifreq.rs` |
| Extended attributes | `src/user/linux/tests/xattr.rs`: `setxattr`'s checks in order (flags, name, size, value, path), the name-length limit, listing and its sizes, the namespaces' permissions and handlers (no POSIX ACLs), host names hidden on macOS, descriptors (`O_PATH` refused), pipes and sockets (`system.sockprotoname`), and `struct xattr_args` of the `*xattrat` calls |
| File locks | `src/user/linux/tests/locks.rs`: `flock`'s and the record-lock commands' checks in order, `flock` locks per description (duplicates, other descriptions, a conversion losing its lock, closing), a wait for another description's lock, the POSIX locks released by closing a duplicate, another description, or a descriptor replaced by `dup3`, the mapping descriptors kept until then, and (on Linux hosts) OFD locks per description |
| Groups, read-ahead, and syncing | `src/user/linux/tests/misc.rs`: groups inherited and sorted, `setgroups`'s privilege and limits, the `Groups:` line of `/proc/self/status`, the file checks of `readahead` and `sync_file_range`, and the files `fsync` and `syncfs` take on every ABI |
| `/proc/<pid>/fdinfo` | `src/user/linux/tests/fdinfo.rs`: the generic lines of a file (position, flags with `O_CLOEXEC`, mount, inode) on every ABI and of a pipe, the directory's listing, and the `eventfd` (16-column count, ID, semaphore), `signalfd` (mask without `SIGKILL`), `timerfd`, `epoll` (events with `EPOLLERR \| EPOLLHUP`, data, position, inode, device), and pidfd lines (`-1` once gone); `src/user/linux/fs/anon.rs`: `eventfd` IDs as `ida_alloc` gives them |
| pidfds | `src/user/linux/tests/pidfd.rs` (9 tests): `pidfd_open`'s checks and file on every ABI, the operations a pidfd refuses and its `fstat`/`fstatfs`, the `ioctl`s (`PIDFD_GET_INFO` fields, sizes, and request checks; `FS_IOC_GETVERSION`; the namespace requests), a thread's pidfd through its exit (a sleeping `ppoll` woken by it, the exit status kept), `CLONE_PIDFD` for threads (the result word, `EFAULT` and `EMFILE` leaving no thread), `pidfd_send_signal`'s scope, record, and descriptor rules, `pidfd_getfd`, `waitid(P_PIDFD)` checks, and a host process watched to its end. `src/user/linux/fs/pidfd.rs`: inode numbers and the registry |
| Timers and blocking | `src/user/linux/tests/waits.rs`: interval timers, `alarm` rounding, interrupted sleeps and `restart_syscall`, `clock_nanosleep` clocks, `poll`/`select`/`ppoll`/`pselect6` interruption, write-back, clamping, and temporary masks, interruptible pipe reads, `sigtimedwait` woken by a timer, and the deadlock diagnostic |
| Host signals | `user_linux` `host_signals`: `kill` from the test process reaches the `hostsig` guest with `SI_USER` and the sender on every ISA, interrupts a blocking `read` of a pipe with `EINTR`, and a default-action `SIGTERM` ends `rax-user` with `SIGTERM`; with `--no-signal-forwarding` the host default applies. `src/user/linux/sigmail.rs`: sender records claimed oldest first, only by their target, withdrawn when unsent, and ignored below the target's floor |
| Memory-management system calls | `src/user/linux/tests/syscall_mm.rs`: `mprotect`, `madvise`, and `personality` driven through `dispatch` on every ABI, expectations from the named kernel functions; shared anonymous memory as a `shmem` object (its `/proc/self/maps` line, `mremap` duplication and its checks, growth past the object), and shared file mappings (write-back through `pread`/`pwrite`, `msync`, `MREMAP_DONTUNMAP`, pages dropped by `ftruncate`, `truncate`, and `O_TRUNC`); `memfd_create`'s flag and name checks, `MFD_HUGETLB`'s empty pool, and seals on `ftruncate` and `mmap`/`mprotect`. `src/user/linux/fs/memfd.rs`: the seal rules of `shmem_write_begin` and `shmem_setattr` |
| Syscall and errno numbering | `user_linux` `abi_tables` against the vendored UAPI headers |
| End-to-end behavior | `user_linux` `fixtures`: 45 cases × 3 ISAs match stdout and exit status recorded on Linux (RV64 `mman` uses the AArch64 kernel's result because QEMU user mode, the RV64 translator, emulates `madvise`; x86-64 `signals` runs under QEMU user mode because Rosetta, the x86-64 translator, mishandles `SA_RESETHAND`; x86-64 and RV64 `threads` use the AArch64 kernel's result because Rosetta and QEMU lack `clone3` and `futex_waitv` and QEMU robust lists, as do their `exec` results because both run executed programs through `binfmt_misc`, RV64 `fork` because QEMU ignores `clone` exit signals and `SA_NOCLDSTOP`, RV64 `events` because QEMU lacks `TFD_IOC_SET_TICKS`, the `signalfd4` size check, and the kernel's timer IDs, x86-64 and RV64 `epoll` because Rosetta faults converting `struct epoll_event` and QEMU does not apply `epoll_pwait`'s mask, RV64 `sockets` and `sockmsg` because QEMU drops unknown socket type flags, writes `socketpair`'s descriptors only on success, and ignores `recvmmsg`'s timeout, x86-64 and RV64 `shmem` because Rosetta traps duplicating a mapping with `mremap` and QEMU checks the zero length first and lacks `MADV_REMOVE`, RV64 `memfd` because QEMU lacks `MADV_REMOVE`, x86-64 and RV64 `pidfd` because Rosetta lacks `pidfd_getfd` and `clone3` and QEMU the pidfd `ioctl`s, x86-64 and RV64 `fdinfo` because both translators leave the AArch64 kernel's status-flag encoding in `fdinfo`, x86-64 `nodes` because Rosetta faults on `utime` with an unmapped buffer, x86-64 and RV64 `xattr` because Rosetta faults on `getxattr` with an unmapped path and QEMU lacks the `*xattrat` calls, RV64 `netlink` because QEMU translates netlink messages itself, x86-64 and RV64 `sysvshm` because Rosetta returns 1 from a failed `shmat` and QEMU converts the IPC structures itself, RV64 `sysvmsg` because QEMU converts `struct msqid64_ds` itself, x86-64 and RV64 `seccomp` because Rosetta and QEMU refuse seccomp, RV64 `inotify` because QEMU does not translate `INOTIFY_IOC_SETNEXTWD`, x86-64 and RV64 `admin` because Rosetta lacks `mount_setattr` and `open_tree_attr` and QEMU reads arguments before the kernel's checks and makes `settimeofday` succeed, RV64 `mqueue` because QEMU mishandles queue names and lacks `mq_notify`, RV64 `sched` because QEMU converts `struct sched_attr` itself and its threads join the process, x86-64 and RV64 `procmem` because Rosetta lacks `process_madvise` and QEMU lacks `process_vm_readv` and `process_vm_writev` and populates a mapping without `PROT_READ` for reading, RV64 `kcmp` because QEMU cannot run a bare `CLONE_THREAD` clone, RV64 `iovec` because QEMU converts vector arrays itself, and x86-64 and RV64 `mlock` because Rosetta cannot run under a small `RLIMIT_MEMLOCK` with `MCL_FUTURE` and QEMU lacks `mlock2`, translates the lock errors, and ignores advice on locked memory, and x86-64 and RV64 `mseal` because both lack `mseal`; see `oracle-overrides.txt`) (also with the x86-64 JIT disabled, the RISC-V JIT enabled, and 64-instruction scheduling slices); an opt-in live Docker differential (`RAX_USER_DOCKER_ORACLE=1`) |
| Whole programs | `user_linux` `programs`: the morok corpus (`tests/fixtures/user/linux/programs`), 97 C and C++ programs × 3 ISAs, each run with the x86-64 JIT on and off and the RISC-V JIT off and on, match stdout and exit status recorded on Linux after masking run-to-run noise (times, ASLR addresses); the programs rax does not reproduce yet are listed per mode in `known-divergences.txt`, which the test requires to be exact |

**Differential-tested** here means that, for the fixture programs and
inputs in `tests/fixtures/user/linux` (including its `programs` corpus),
output and exit status equal what the recorded Linux kernel produced; it is
not a claim about programs outside that corpus.
