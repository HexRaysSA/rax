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
| x86-64 Linux | `EM_X86_64` (62) | RAX x86-64 interpreter with the SMIR JIT on x86-64 hosts |
| AArch64 Linux | `EM_AARCH64` (183) | RAX AArch64 interpreter at EL0 |
| RV64 Linux | `EM_RISCV` (243), ELFCLASS64 | RAX RISC-V interpreter in U-mode (optional SMIR JIT) |

The host must be Unix (Linux or macOS). On other hosts the binary builds but
reports that the host is unsupported.

## Build and run

```sh
cargo build --release --no-default-features --features smir-jit --bin rax-user

./target/release/rax-user ./hello-aarch64 arg1 arg2
echo $?
```

The guest ABI comes from the ELF header, so the same command runs x86-64,
AArch64, and RV64 programs. Standard input, output, and error are the
host's. The exit status is the guest's:

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

Sizes accept `K`, `M`, `G`, and `T` suffixes (powers of 1024).

## What the guest sees

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
  instructions stay atomic and a program's interleaving depends only on
  where slices end. `sched_getaffinity` reports CPU 0 only, and
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
  `stat`, `status`, `comm`, `fd/`, `task/<tid>/`), `/proc/thread-self`,
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
  run ELF programs of any of the three ABIs (as a kernel with
  `binfmt_misc` handlers for the other two would) and `#!` scripts, and
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

## Current limitations

These are tracked in [Status and limitations](../reference/status-and-limitations.md)
and in the [user-mode architecture page](../architecture/user-mode.md):

- With `--no-signal-forwarding`, a wait for a signal with no timeout
  (`pause`, `sigsuspend`) that no timer can end stops the process with a
  diagnostic. A stop signal's default action stops the `rax-user` process
  itself.
- CPU-time timers (`CLOCK_PROCESS_CPUTIME_ID`, `CLOCK_THREAD_CPUTIME_ID`,
  and the CPU clocks of the process and its threads) count `rax-user`'s
  CPU time, as `clock_gettime` reports it; other processes' CPU clocks are
  refused (`EINVAL`). The alarm clocks need root (`CAP_WAKE_ALARM`), and a
  real-time clock is assumed. `TFD_TIMER_CANCEL_ON_SET` is accepted, but
  changes of the host clock are not observed, so no `timerfd` is
  canceled. `/proc/<pid>/fdinfo` is not provided.
- An `epoll` instance is copied, not shared, by `fork`. Readiness the
  emulator does not cause itself (input from a terminal or another
  process, a timer's expiry, a signal) is found when a wait looks, so an
  edge-triggered item reports it once per growth of the data waiting and
  items that became ready that way are reported in the order they were
  added; `EPOLLWAKEUP` needs root, and the limits on watches and wake-up
  paths are not enforced.
- A process sharing memory with its parent (`CLONE_VM`) is a copy: with
  `CLONE_VFORK` (`vfork`, `posix_spawn`) the parent still sleeps until the
  child calls `execve` or exits, but does not see the child's stores (a
  glibc `posix_spawn` whose `execve` fails therefore reports success and
  the child exits with 127). Without `CLONE_VFORK` such a process, and one
  sharing descriptors, file-system context, or handlers (`CLONE_FILES`,
  `CLONE_FS`, `CLONE_SIGHAND` without `CLONE_THREAD`), `CLONE_PARENT`, and
  pidfds are not supported.
- Signals to other processes are host signals: they arrive as `SI_USER`
  from the sender, without a `sigqueue` value; a real-time signal the host
  lacks reaches only the sending process; a thread of another process
  other than its leader cannot be named; `kill(-1)` reaches the caller's
  children. Between `rax-user` processes the sender is exact (its UID the
  guest's); a signal from a process outside `rax-user` carries the host's
  report, which on macOS hosts is lost (`SI_KERNEL`) when the signal
  arrives while the target forks or a child of the target exits.
- `/proc` describes only the calling process. `PR_SET_PDEATHSIG` is
  recorded but never delivered.
- A thread must share the descriptor table and file-system context
  (`CLONE_FILES | CLONE_FS`, otherwise `EINVAL`); `CLONE_PIDFD` and
  `CLONE_INTO_CGROUP` are `EINVAL` and namespace flags `EPERM`.
  `FUTEX_WAIT_REQUEUE_PI` and `FUTEX_CMP_REQUEUE_PI` return `ENOSYS`; an
  absolute `CLOCK_REALTIME` futex timeout does not follow later changes of
  the host clock.
- Pipes the guest creates never block the host (their blocking is
  emulated), but a write to an inherited pipe or terminal whose reader is
  slow (standard output into a pager) holds every guest thread until it
  completes. On macOS hosts, whose `PIPE_BUF` is 512 bytes, a pipe write of
  513 to 4,096 bytes into a nearly full pipe can be split, which another
  writer to the same pipe could observe.
- The 32-bit `INT 0x80` system-call ABI on x86-64 returns `-ENOSYS`.
- A `memfd` is one object for this process, its children, and
  descriptors passed within the process; one passed to another process
  with `SCM_RIGHTS`, or opened again through `/proc/self/fd`, is an
  ordinary file there, without seals. `F_SEAL_WRITE` is refused only for
  writable shared mappings in the calling process. An `MFD_HUGETLB`
  `memfd` cannot be mapped (the huge-page pool is empty).
- A private file mapping copies a page from the file at its first touch,
  so later changes to the file never reach that page (Linux shows them
  until the page is written). A shared mapping of a block device is a
  copy. When another process truncates a file this process maps shared,
  past a page this process has touched, the next access faults
  `rax-user` itself rather than raising `SIGBUS` in the guest (the guest's
  own truncations are handled).
- Socket families other than `AF_UNIX`, `AF_INET`, and `AF_INET6`
  (netlink, packet, ...) are `EAFNOSUPPORT`, so interface lists through
  netlink are unavailable, and the interface `ioctl`s report no device.
  Options without a host counterpart (`SO_TIMESTAMP`, `IP_PKTINFO`,
  `TCP_QUICKACK`, ...) and IP-level control messages are accepted but
  have no effect. A description without a host descriptor (`eventfd`,
  `timerfd`, `signalfd`, `epoll`, a `/proc` file) passed with
  `SCM_RIGHTS` reaches only its own process, and one passed to another
  process arrives with its access mode and `O_APPEND` but not its other
  status flags. `SO_PASSCRED` reports the connected peer's credentials,
  not each sender's. Peers see a socket bound by a relative path under
  its absolute path. The timeouts count whole milliseconds (a 1000 Hz
  kernel), and `MSG_CMSG_COMPAT` is an ordinary bit, as in a kernel
  without 32-bit system calls.
- On macOS hosts an abstract socket name is a file in a per-user temporary
  directory, a path longer than 103 bytes is bound through a temporary
  link that peers see, sequenced-packet Unix sockets are unavailable, the
  peer's `SHUT_RD` does not show in `poll`, and a datagram to a full
  receiver is retried every millisecond until it fits.
- Terminal attribute changes (`TCSETS*`) are accepted but not applied to the
  host terminal; `TCGETS` reports Linux's default terminal settings.
