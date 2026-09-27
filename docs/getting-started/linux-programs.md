[← Documentation home](../../README.md)

# Running Linux programs with `rax-user`

`rax-user` runs a single Linux user-space program — not a whole machine —
on RAX's software CPUs. It loads an ELF executable the way the Linux
kernel's `binfmt_elf` does, executes it in the CPU's unprivileged mode, and
services its system calls on the host. It is the process-level counterpart
of the `rax` machine emulator, comparable in scope to QEMU's user-mode
emulators (`qemu-x86_64`, `qemu-aarch64`, `qemu-riscv64`).

| Guest ABI | ELF `e_machine` | CPU core |
|---|---|---|
| i386 Linux compatibility (partial) | `EM_386` (3) or `EM_486` (6), ELFCLASS32 | RAX x86 core in IA-32e compatibility mode; interpreter only |
| ARM EABI Linux compatibility (partial) | `EM_ARM` (40), ELFCLASS32, an EABI version in `e_flags` | RAX AArch32 core in User mode (A32 and T32); interpreter only |
| x86-64 Linux | `EM_X86_64` (62) | RAX x86-64 interpreter with the SMIR JIT on x86-64 hosts |
| AArch64 Linux | `EM_AARCH64` (183) | RAX AArch64 interpreter at EL0 |
| RV64 Linux | `EM_RISCV` (243), ELFCLASS64 | RAX RISC-V interpreter in U-mode (optional SMIR JIT) |

The host must be Unix (Linux or macOS). On other hosts the binary builds but
reports that the host is unsupported.

## Build and run

```sh
cargo build --release --locked --no-default-features --features smir-jit --bin rax-user

./target/release/rax-user tests/fixtures/user/linux/bin/aarch64/hello arg1 arg2
echo $?
```

The checked-in `hello` fixture prints its arguments/environment and returns
`40 + argc`: this invocation reports status 43. With no extra arguments it
returns 41. These nonzero values test exit-status propagation.

The guest ABI comes from the ELF header, so the same command selects x86-64,
AArch64, RV64, or the partial i386 or ARM EABI compatibility path. Standard input, output,
and error are the host's. The exit status is the guest's:

| Status | Meaning |
|---|---|
| `0`–`255` | The program called `exit`/`exit_group` with this value (mod 256). |
| `128 + N` | Signal `N` killed the program with a core-dumping default action (for example 139 for `SIGSEGV`, 134 for `SIGABRT`), or any signal with `--no-signal-forwarding`. A diagnostic line with the signal, `si_code`, the fault address or sending PID, and the PC goes to standard error. `rax-user` exits instead of re-raising the signal, so the host records no crash of the emulator. |
| killed by `N` | Any other signal `N` killed the program: after the same diagnostic line, `rax-user` dies of the host's `N`, so its parent sees a signal death. A shell reports `128` plus the host's signal number, which on macOS differs from Linux's for some signals (`SIGUSR1` is 30, `SIGTSTP` 18). A signal the host lacks (for example `SIGPWR` on macOS, or a real-time signal) exits with `128 + N`. |
| `125` | The emulator could not continue (for example a deadlock with no runnable thread). |
| `126` | The file is not an executable for a supported ABI, or loading it failed. |
| `127` | The file does not exist. |

## Options

| Option | Effect |
|---|---|
| `-L`, `--sysroot DIR` | Guest root overlay: an absolute guest path that exists under `DIR` resolves there, anything else resolves on the host (QEMU `-L` semantics). Symbolic links inside `DIR` resolve inside `DIR`. `/dev`, `/proc`, and `/sys` always resolve on the host or are synthesized. |
| `-E`, `--env VAR=VALUE` | Set a guest environment variable (repeatable). |
| `-U`, `--unset-env VAR` | Remove a guest environment variable (repeatable). |
| `--clear-env` | Start from an empty environment instead of `rax-user`'s own. |
| `-0`, `--argv0 NAME` | Pass `NAME` as `argv[0]`. |
| `-C`, `--cwd DIR` | Guest working directory (default: the current directory). |
| `--strace` | Log every system call as `[tid] name(args) = result` on standard error. |
| `--seed N` | Deterministic `AT_RANDOM` bytes and `getrandom` output. |
| `-s`, `--stack-size SIZE` | `RLIMIT_STACK` soft limit and `[stack]` mapping size (default `8M`). |
| `--memory SIZE` | Guest memory arena (default `16G`, committed by the host only as touched). |
| `--riscv-jit` | Execute RISC-V guests through the SMIR JIT where the host supports it. |
| `--kernel-release R` | `uname -r` value (default `6.19.0`). |
| `--slice N` | Instructions per scheduling slice for AArch64 and RV64 guests. |
| `--no-signal-forwarding` | Leave host signals at their host dispositions (Ctrl-C then ends `rax-user` directly) and report every signal death as `128 + N`. |

Sizes accept `K`, `M`, `G`, and `T` suffixes (powers of 1024); `8M` is
8 MiB and `16G` is 16 GiB. `--seed` fixes `AT_RANDOM` and `getrandom`
bytes, not host timing, I/O, or the complete thread interleaving.

## What the 64-bit guest sees

The following describes the x86-64, AArch64, and RV64 ABIs. The narrower
i386 and ARM EABI paths are described separately below. The behavioral reference is the
vendored Linux 6.19 source; supported operations and deviations are enumerated
in the [user-mode topic references](../architecture/user-mode.md#runtime-topics).

- **Address space.** Linux 6.19's layout with randomization disabled
  (`setarch -R`): x86-64 PIEs load at `0x555555554000` and their
  interpreter just below `0x7ffff7fff000`; AArch64 PIEs at `0xaaaaaaaa0000`
  (64 KiB alignment); the stack ends at `STACK_TOP` (`0x7ffffffff000` on
  x86-64). Page permissions are enforced exactly; an access to an unmapped
  page raises `SIGSEGV`/`SEGV_MAPERR`, to a protected page
  `SIGSEGV`/`SEGV_ACCERR`, and past the end of a mapped file `SIGBUS`.
- **Initial stack and auxiliary vector.** Byte-for-byte the layout of
  `create_elf_tables` for the vector RAX produces (no `AT_SYSINFO_EHDR`,
  because no vDSO is mapped; C libraries then use system calls for time).
- **CPU and threads.** One CPU executes every guest thread, in time slices
  (`--slice` on AArch64 and RV64, about 1 ms on x86-64), so guest atomic
  instructions stay atomic among that process's guest threads. Interleaving
  depends on scheduler boundaries and guest/host events. `sched_getaffinity`
  reports CPU 0 only, and
  `/proc/cpuinfo` describes that CPU. Threads come from `clone` and `clone3`
  with the flags threads libraries pass (musl and glibc `pthread_create`),
  with Linux's register state, TLS, and TID words; futexes (every `futex`
  operation except the requeue-PI pair, `futex_waitv`, and the `futex2`
  calls), robust and priority-inheritance mutexes, thread-directed and
  process-directed signals (a process signal goes to a thread that does not
  block it, as `complete_signal` chooses), thread exit with its
  `clear_child_tid` wake, and the `/proc/self/task/<tid>` views (with
  per-thread names) behave as on Linux. A system call that must sleep
  parks its thread while the others run.
- **Files.** Host files, directories, pipes, and terminals, with Linux
  `errno` values. `/proc/self` (`exe`, `maps`, `auxv`, `cmdline`, `environ`,
  `stat`, `status`, `comm`, `fd/`, `fdinfo/`, `task/<tid>/`),
  `/proc/thread-self`,
  `/proc/<tid>`, `/proc/cpuinfo`, `/proc/meminfo`,
  `/proc/uptime`, `/proc/version`, and the CPU-topology files under
  `/sys/devices/system/cpu` are synthesized.
- **Identity.** The host process ID, user, and group IDs.
- **Processes.** `fork`, `vfork`, and `clone`/`clone3` without
  `CLONE_THREAD` fork `rax-user`: each guest process is a host process,
  so guest PIDs, parent PIDs, process groups, and sessions are the host's.
  `wait4` and `waitid` report exits, signal deaths, stops, and
  continuations with Linux statuses; `SIGCHLD` carries the child's
  `siginfo`, honors `SA_NOCLDSTOP`, and an ignored `SIGCHLD` or
  `SA_NOCLDWAIT` reaps children automatically. `execve` and `execveat`
  load ELF programs for the supported ABIs, including the partial i386 and
  ARM EABI compatibility ones, and `#!` scripts, and
  keep, reset, and close what Linux does. A forked child that dies prints
  no diagnostic; its parent sees its status.
- **Host signals.** `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1`, `SIGUSR2`,
  `SIGALRM`, `SIGTERM`, `SIGCONT`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`,
  `SIGURG`, `SIGXCPU`, `SIGXFSZ`, `SIGVTALRM`, `SIGPROF`, `SIGWINCH`, and
  `SIGIO` sent to `rax-user` (Ctrl-C, Ctrl-Z, `kill`, a terminal resize)
  are delivered to the guest as Linux would deliver them: `si_code`
  `SI_USER` with the sender's PID and UID for `kill`, `SI_KERNEL`
  otherwise. The synchronous error signals (`SIGSEGV`, `SIGBUS`, `SIGILL`,
  `SIGFPE`, `SIGTRAP`) and `SIGABRT` keep their host dispositions, because
  on the host they report a failure of the emulator; `SIGPIPE` stays
  ignored on the host and is raised in the guest on `EPIPE`.
- **Timers and blocking calls.** `alarm` and `setitimer`/`getitimer`:
  `ITIMER_REAL` runs on the monotonic clock; `ITIMER_VIRTUAL` and
  `ITIMER_PROF` count `rax-user`'s host CPU time, which includes emulation
  overhead. Reads and writes of pipes, terminals, and sockets without
  `O_NONBLOCK`, `poll`, `ppoll`, `select`, `pselect6`, `nanosleep`,
  `clock_nanosleep`, `pause`, `sigsuspend`, and `sigtimedwait` sleep until
  their condition or a signal, and an interrupted call returns `EINTR` or
  restarts exactly as on Linux (`SA_RESTART`; `restart_syscall` for
  `nanosleep` and `poll`; `poll` and `select` never restart after a
  handler).
- **POSIX timers and event descriptors.** `timer_create` on the
  realtime, monotonic, boot-time, TAI, and CPU-time clocks, with
  `SIGEV_SIGNAL`, `SIGEV_NONE`, and `SIGEV_THREAD_ID` notification: one
  queued signal per timer, the periods missed meanwhile reported as its
  overrun count, and the queued signal of a changed or deleted timer
  dropped, as on Linux. `eventfd` counters and semaphores, `timerfd`
  one-shot and periodic timers (with `TFD_IOC_SET_TICKS`), and `signalfd`
  readers of blocked signals behave as Linux's do, including their size
  and limit checks, `poll`/`select` readiness, and blocking reads and
  writes; an `eventfd` or `timerfd` stays one object across `fork`, as an
  open file description does.
- **`epoll`.** `epoll_create`, `epoll_ctl`, and `epoll_wait` with its
  `pwait` variants over pipes, terminals, and event, timer, and signal
  descriptors, and nested instances: level-triggered, edge-triggered, and
  one-shot items, the kernel's reporting order and `maxevents` rotation,
  items that follow the open file description rather than the
  descriptor, `EINTR` without restart, and every argument check in the
  kernel's order.
- **Shared memory.** A shared file mapping is the file's own pages: stores
  reach the file at once, and `read`, `write`, and other mappings, in this
  process or another, see the same bytes; `msync` flushes them.
  Anonymous shared memory and shared `/dev/zero` mappings stay shared
  with forked children. `mremap` can duplicate a shared mapping, and
  `MADV_REMOVE` punches its object. `memfd_create` makes such an object
  as a file, with Linux's seals (`F_ADD_SEALS`, `F_GET_SEALS`) enforced
  on writes, size changes, mappings, and mode changes.
- **pidfds.** `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`,
  `CLONE_PIDFD` (`clone`, `clone3`), and `waitid(P_PIDFD)` work on the
  process's own threads, its children, and other processes; a pidfd
  polls readable when its task exits and hung up when it is gone, so
  `poll`, `select`, and `epoll` can wait for a process to end, and it
  names that process even after the host reuses its PID.
  `PIDFD_GET_INFO` reports identifiers, credentials, and available exit status.
  `pidfd_getfd` reaches only the caller's own descriptors; other-process and
  namespace queries have the limits listed below.
- **Sockets.** `AF_UNIX` (stream and datagram, and sequenced-packet
  where the host has it), `AF_INET`, and `AF_INET6` sockets are host
  sockets, so the loopback and real networks work: `socket`,
  `socketpair`, `bind`, `listen`, `accept`/`accept4`, `connect`, the name
  and option calls, `shutdown`, and every send and receive call,
  `sendmmsg` and `recvmmsg` included. Unix paths resolve through the
  sysroot and the working directory; the abstract namespace and autobind
  work on every host. Blocking, `SO_RCVTIMEO`/`SO_SNDTIMEO`,
  `MSG_WAITALL`, `MSG_PEEK`, `MSG_TRUNC`, and signal interruption behave
  as on Linux; `SCM_RIGHTS` passes descriptors, also to other processes;
  `SO_PASSCRED` delivers the peer's credentials; `SIGPIPE` follows the
  protocol; `poll`, `select`, and `epoll` report sockets as `sock_poll`
  does, including `POLLRDHUP`.

- **Netlink and interfaces.** `AF_NETLINK` uses host netlink on Linux;
  macOS emulates `NETLINK_ROUTE` link/address queries over host interfaces.
  Interface lookup calls include `SIOCGIFCONF` and device/address queries.
  Routing changes and notifications are not implemented by the macOS model.
- **File metadata and locks.** Device/FIFO nodes, file times, extended
  attributes, supplementary groups, `flock`, and POSIX record locks are
  implemented. OFD locks require Linux host support; POSIX ACL attributes
  are unsupported. File locks interact with other host programs.
- **IPC and notifications.** System V shared memory, semaphores, and message
  queues, plus POSIX message queues, use a namespace shared by `rax-user`
  processes of the host user. Inotify uses the host kernel on Linux and an
  emulated event hub elsewhere. The emulated hub observes `rax-user` file
  operations rather than arbitrary host changes.
- **Memory and scheduling controls.** `mlock`/`mlock2`/`mlockall`, `mseal`,
  and `rseq` track guest memory and critical-section state. Scheduling and
  I/O-priority attributes are stored and reported; guest threads still share
  one emulated CPU. `process_vm_readv`, `process_vm_writev`,
  `process_madvise`, and `kcmp` inspect the caller's process or its threads,
  with explicit refusals for other processes.
- **Seccomp and tracing.** Strict seccomp and classic BPF filters apply to
  guest syscall entry. Guest `ptrace` implements attach/seize, register and
  memory access, syscall stops and editing, job-control and process events,
  and seccomp events/queries. It reaches linked parent/child processes and
  descendants passed to the tracer. Single-step is implemented for x86-64
  and AArch64; block-step is x86-64 only. RISC-V step requests are refused.
- **Splicing and asynchronous I/O.** `splice`, `vmsplice`, and Linux-host
  `tee` are implemented. Linux AIO (`io_setup`, `io_submit`, `io_getevents`,
  `io_pgetevents`, `io_cancel`, `io_destroy`) provides completion rings,
  file/vector transfers, syncs, poll requests, and eventfd notifications.
  This is the Linux AIO interface; it does not imply `io_uring` support.
- **Administration.** Machine, clock, module, and mount calls perform guest
  argument/permission checks and refuse unsupported changes. They do not
  create a separate guest kernel, mount tree, or network namespace.

## i386 compatibility tasks

ELF32 `EM_386`/`EM_486` programs use the x86 core with `CS=0x23`, 32-bit
stack words, `AT_PLATFORM=i686`, and `INT 0x80` syscall numbering. The user
address limit and stack top are `0xFFFFE000`; a PIE starts at `0x56555000`.
`set_thread_area` and `get_thread_area` manage Linux-style GDT TLS entries.

The compatibility dispatcher implements matching-layout calls and explicit
32-bit conversions. Current conversions include `mmap`/`mmap2`, iovecs,
`execve` argument/environment pointers, split 64-bit file offsets, `_llseek`,
file status/statistics, directory entries, `fcntl` record locks, and
`time32`/`time64` clock, sleep, and timer layouts. File and path operations,
32-bit ID calls, and selected event-descriptor and memory controls are reachable through that table. The owning table is
[`syscall::compat`](../../src/user/linux/syscall/compat/mod.rs); support
must be checked there for the exact syscall and layout.

Signals use the i386 frames and their returns, threads get GDT TLS through
`CLONE_SETTLS`, sockets have the `socketcall` multiplexer and the 32-bit
message and control structures, System V IPC the `ipc` multiplexer, and a
32-bit tracer the compatibility `ptrace` requests and the i386 register sets.
This is still a partial ABI: calls without a conversion return `ENOSYS`;
unsupported compatibility `ioctl`s return `ENOTTY`. `SYSENTER` raises
`SIGILL`, no 32-bit vDSO is provided, and compatibility code does not use the
JIT. A 64-bit process's `INT 0x80` is still refused with `ENOSYS` after
seccomp checks. An i386 subset of the fixture programs (and some i386-only
ones) is recorded on a Linux 6.19 kernel; the whole-program corpus does not
exercise i386.

## ARM EABI compatibility tasks

ELF32 `EM_ARM` programs with an EABI version run as an arm64 kernel runs
AArch32 tasks (`CONFIG_COMPAT`): the AArch32 core in User mode, `SVC` with
the number in R7 and arm64's `syscall_32.tbl` numbering, 32-bit stack words
with `AT_PLATFORM=v8l` and the compat hardware capabilities (no
`AT_MINSIGSTKSZ` and no vDSO). User addresses end at `0xFFFFF000`; the stack
top and the `[vectors]` page of kuser helpers are at `0xFFFF0000`, a
`[sigpage]` holds the signal return code, and a PIE starts at `0x400000`.
The thread pointer is TPIDRURO (`set_tls`, `CLONE_SETTLS`). The kernel
modelled is a distribution's: kuser helpers, no compat vDSO, and the A32 CP15
barriers emulated (`CONFIG_CP15_BARRIER_EMULATION`).

The ARM dispatcher ([`syscall::compat::arm`](../../src/user/linux/syscall/compat/arm.rs))
applies arm64's `aarch32_*` wrappers (64-bit arguments in register pairs,
the reordered `arm_fadvise64_64` and `arm_sync_file_range`, `statfs64`'s
size fixup), the direct System V IPC calls with `IPC_64` in the command and
the 16 KiB `COMPAT_SHMLBA`, and the private calls `cacheflush` and
`set_tls`; the rest of the compatibility table is i386's where the layouts
agree, and the EABI `struct stat64` and `struct compat_flock64` otherwise.
Signals use the AArch32 frames with their VFP record.

Limitations: register requests of `ptrace` on or by an AArch32 thread are
`EIO`; `SWP` and `SETEND` raise `SIGILL`, as on an arm64 CPU without
mixed-endian EL0. The AArch32 core's Thumb-2 decoder lacks the coprocessor
and exclusive-access encodings, ARMv8's load-acquire and store-release ones
among them (so T32 code that reads TLS with `MRC` does not run; A32 code
has them all), and its NEON coverage has gaps. No
recorded fixtures cover ARM EABI yet.

## Current limitations

The [status page](../reference/status-and-limitations.md#required-user-mode-qualifications)
owns the subsystem qualifications. The
[architecture topics](../architecture/user-mode.md#runtime-topics) explain the
corresponding mechanisms. The operational boundaries are:

- `--sysroot` is an overlay: paths absent from it fall back to the host.
  Files, pipes, locks, sockets, and guest child processes use host resources.
- `CLONE_VM` child processes use copied private memory; `vfork` sleeps the
  parent but does not expose child stores. Non-thread sharing of descriptor,
  file-system, or signal-handler tables, namespaces, and requeue-PI futexes
  are unsupported. Guest threads require `CLONE_FILES | CLONE_FS`.
- CPU-time timers measure emulator host CPU time, including emulation overhead.
  `TFD_TIMER_CANCEL_ON_SET` does not observe host-clock changes. Epoll instances
  are copied by fork, and externally generated readiness has emulation-specific
  edge/order limits. Scheduling attributes do not change scheduling policy.
- Process-memory access and `kcmp` do not reach another process. Pidfds have
  restricted cross-process descriptor, thread, credential, and exit-state
  visibility; `PR_SET_PDEATHSIG` is recorded but not delivered.
- Guest ptrace has no arbitrary same-user host-process attach, hardware
  breakpoints, or SVE/vector regsets. Seccomp user notification is unsupported;
  logging actions do not produce logs, and capability checks use the guest's
  root/non-root model.
- IPC namespaces are visible to `rax-user` processes, with resource-counting,
  wake-up-order, and killed-process cleanup limits. The macOS inotify and
  netlink models have narrower event/query coverage than their Linux backends.
- A private file page is copied on first touch; external file changes do not
  reach that copy. External truncation of an already touched shared file page
  can fault the emulator itself. A memfd transferred to another process or
  reopened through `/proc` loses seal tracking there.
- Splicing copies bytes through host pipes; it does not gift kernel pages.
  Linux AIO poll completion is detected at scheduler/syscall boundaries.
  OFD locks and `tee` are unavailable on macOS. Terminal attribute changes
  are accepted without applying them to the host terminal.
- With `--no-signal-forwarding`, a signal wait that nothing can wake ends with
  a diagnostic. Inherited blocking output can hold all guest threads while
  the host write completes. A default stop signal stops the host process.

## Validation scope

The registered `user_linux` target compares decoded stdout text and exit status with
checked-in Linux recordings for syscall fixtures and the morok whole-program
corpus. Some expectations use an explicit architecture override when Rosetta
or QEMU cannot exercise the kernel interface; `oracle-overrides.txt` records
those cases. Whole-program output passes through declared noise filters, and
`known-divergences.txt` is enforced exactly. Neither corpus is exhaustive
Linux or ISA conformance; the whole-program corpus does not cover i386, and
neither covers ARM EABI compatibility tasks.
Both runners use UTF-8 lossy decoding, so this evidence does not establish
equality of arbitrary binary output.

```sh
cargo test --release --locked --no-default-features --features smir-jit --test user_linux
cargo test --locked --no-default-features --features smir-jit --lib user::
```

The ignored live Docker comparison requires Docker and explicit opt-in:

```sh
RAX_USER_DOCKER_ORACLE=1 cargo test --release --locked --no-default-features \
    --features smir-jit --test user_linux -- --ignored --nocapture
```

See [Verification model](../development/verification.md) for the recorded
oracle, output projection, host gates, and execution-mode distinctions.
