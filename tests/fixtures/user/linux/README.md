# rax-user Linux fixtures

Static Linux programs that exercise the `rax-user` Linux personality, with
the output a real Linux kernel produced for each of them. The
`user_linux` test target (`tests/suites/user/linux/`) runs every case on
every architecture and requires a byte-for-byte match.

| Path | Content |
|---|---|
| `src/*.c` | Self-checking C sources. Each check prints `ok <name>` or `FAIL <name>: ...`. |
| `build.sh` | Rebuilds `bin/` and `manifest.toml`. |
| `bin/<arch>/<program>` | Static, stripped executables for `x86_64`, `aarch64`, and `riscv64`. |
| `manifest.toml` | Toolchain, flags, and SHA-256 of every binary (checked by the test). |
| `cases.txt` | Case table: program, standard-input file, and arguments. |
| `input/` | Standard-input files referenced by `cases.txt`. |
| `record-expected.sh` | Records `expected/` on Linux through Docker. |
| `oracle-overrides.txt` | Cases whose expectation for one architecture is another architecture's real-kernel result, with the reason. |
| `expected/<arch>/<case>.{stdout,status}` | Recorded results. |
| `expected/ORACLE` | Kernel, Docker server, binfmt handlers, overrides, and recording time of the oracle run. |
| `programs/` | The morok program corpus: 97 whole C and C++ programs with their own build, recordings, and README. |

## Programs

| Program | Covers |
|---|---|
| `hello` | `argc`/`argv`/`envp`, exit status |
| `fileio` | `open` flags and errors, `read`/`write`/`pread`/`lseek`, `O_APPEND`, `ftruncate`, `stat` family, `rename`/`link`/`symlink`/`readlink`, directories and `getdents64`, `*at` calls with a directory descriptor, pipes, `dup2`/`dup3`, `fcntl` descriptor and status flags, non-blocking pipes |
| `memory` | `malloc` across the mmap threshold, `brk`, anonymous and private file mappings, `mprotect`, `madvise(MADV_DONTNEED)`, `munmap` holes, `mincore`, `MAP_FIXED`/`MAP_FIXED_NOREPLACE`, `mremap` with move, argument errors |
| `mman` | Per-VMA `madvise` (`DONTNEED` on private and shared memory, `FREE`, `REMOVE`, `POPULATE_READ`/`WRITE`, holes, a refusing VMA ending the walk), `mprotect` validation order, partial application up to a hole, `PROT_GROWSDOWN` on the stack, shared mappings of read-only files, `personality` |
| `process` | IDs, `uname`, auxiliary vector, clocks and `nanosleep`, resource limits, affinity, `getrandom`, `prctl`, `umask`, `/proc/self/exe`, `/proc/self/maps`, `ENOSYS`/`EBADF`/`EFAULT` |
| `timers` | `alarm` and `pause`, a periodic `ITIMER_REAL`, `getitimer`, `nanosleep` interrupted with the time left, a pipe `read` interrupted (`EINTR`) and restarted (`SA_RESTART`), `poll` not restarted, `pselect6` writing back the time left, `sigtimedwait` taking a timer's `SIGALRM`, `clock_nanosleep` on the thread CPU clock (`EOPNOTSUPP`) and the monotonic clock |
| `threads` | `pthread_create`/`join` and thread IDs, mutex/condition-variable/barrier/rwlock correctness under contention, thread-local storage, detached threads, timed waits (`sem_timedwait`, `pthread_cond_timedwait`, `pthread_mutex_timedlock`), `pthread_kill`, a process signal taken by the only thread not blocking it, `sigwait` in a dedicated thread, robust mutexes (`EOWNERDEAD`), priority-inheritance mutexes, cancellation of threads blocked in `read`, `pthread_cond_wait`, and `sleep`, `/proc/self/task` and per-thread names, `clone`/`clone3` validation, and `futex`/`futex_waitv` operations directly (value checks, timeouts, requeue and wake-op counts, PI ownership words) |
| `threadexit` | How a multithreaded process ends (argument): the last thread's code after the leader exits (`leader`, 9), `exit_group` from a thread (`group`, 5), a fault in a thread (`segv`, 139), and `SIGTERM` taken by a thread (`kill`, 143) |
| `exec` | A chain of `execve` stages: kept descriptors, closed close-on-exec ones, reset handlers, kept ignored signals, mask, pending signals, and interval timers, a cleared alternate stack, `AT_EXECFN` and `comm`; the error order (missing file, directory, no execute permission, unknown format, bad `#!` lines, a missing interpreter, a script loop, a bad `argv`, an over-long argument, bad `execveat` flags); a `#!` script run with its interpreter's arguments; `execveat` through a descriptor; `execve` from a second thread |
| `fork` | `fork`, `vfork` (resuming at `execve`), `posix_spawn`, `clone` with a non-`SIGCHLD` exit signal, and `fork` in a second thread (whose child, once the thread exits, the main thread waits for with `__WNOTHREAD`); `waitpid`/`waitid` for exits, signal deaths, faults, stops, and continuations (each reported once), `WNOHANG`, `WNOWAIT`, `__WCLONE`, and `ECHILD`; `SIGCHLD` `siginfo`, `SA_NOCLDSTOP`, and automatic reaping; pipes between processes; `kill(0)` to the process group; 100 children killed the moment they exist |
| `events` | `eventfd` counters and semaphores (limits, sizes, `lseek`/`pread`, readiness, a blocking read ended by another thread, one counter shared with a child process); `timerfd` one-shot and periodic ticks, `gettime`/`settime` old values, absolute times, `TFD_IOC_SET_TICKS`, blocking reads, and `TFD_TIMER_CANCEL_ON_SET`; `signalfd` reads of blocked signals with their `siginfo`, mask updates, `SIGKILL`/`SIGSTOP` in a mask, and a blocking read ended by another process's signal; POSIX timers with each notification kind, one queued signal and its overrun count, a stale signal dropped after `timer_settime`, `SIGEV_THREAD_ID`, and timers not inherited by a child; the error cases of each call |
| `epoll` | Instances and their checks; level-triggered, edge-triggered, and one-shot items over pipes, `eventfd`, `timerfd`, and `signalfd`; hang-up and error; the ready-list order and `maxevents` rotation; items that outlive a `dup`'d descriptor's close; nested instances, loops, and the depth limit; a wait ended by another thread, by a timeout, and by a handler (`EINTR` despite `SA_RESTART`); `epoll_pwait`'s mask and `epoll_pwait2`'s timeout; an instance in `poll` |
| `sockets` | Socket creation and its checks (families, types, flags, protocols), `SO_TYPE`/`SO_DOMAIN`/`SO_PROTOCOL`, a socket's `fstat` and `/proc` name; Unix streams on paths (the socket node, names in use, refused and repeated connections, peer names and credentials, end of file) and in the abstract namespace, autobind; Unix datagrams (boundaries, truncation, `MSG_TRUNC`, `MSG_PEEK`); `socketpair` (descriptors written before a refusal), `shutdown`, `POLLRDHUP`, `SIGPIPE` and `MSG_NOSIGNAL`; TCP on the loopback (a non-blocking connect, `accept4`, `MSG_PEEK`/`MSG_WAITALL`/`MSG_DONTWAIT`, `TCP_NODELAY`, `SO_RCVTIMEO`, `SO_RCVBUF` doubling, a port in use, a refused connection, sending unconnected); UDP (`EDESTADDRREQ`, `sendto`/`recvfrom` names, `connect`); `SCM_RIGHTS` with `MSG_CMSG_CLOEXEC` |
| `sockmsg` | Readiness through each shutdown and close (Unix, TCP, datagram, a listener); message headers (truncation flags, name and vector checks, a truncated name, a vanished destination); a descriptor passed from a forked child; `SO_PASSCRED` credentials and a refused foreign claim; `sendmmsg`/`recvmmsg` (`MSG_WAITFORONE`, an invalid timeout); IPv6 on the loopback where the host has it; a blocking `accept` woken by another thread; a receive ended by a signal (`EINTR` with a timeout set despite `SA_RESTART`) and one restarted without |
| `shmem` | Shared memory: anonymous and `/dev/zero` shared mappings shared with forked children (a private one copied); a shared file mapping's stores reaching the file and the file's changes reaching the mapping (`pwrite`, another process's mapping, a second mapping), kept after `munmap`, `msync`; read-only files mapped shared for reading only; `mremap` duplicating a shared mapping (not a private one, not without `MREMAP_MAYMOVE`) and growing one past its object (`SIGBUS`); `MADV_DONTNEED` and `MADV_REMOVE` on shared pages; the `/proc/self/maps` line of shared anonymous memory; a page past a truncated end (`SIGBUS`) and the zeroed tail of a partial page |
| `memfd` | `memfd_create`'s flag and name checks; the file's status flags, mode, links, size, and `/proc` names; data through `write`, `pread`, and a shared mapping; the initial seals of each creation mode; `F_SEAL_SHRINK`/`F_SEAL_GROW` at `ftruncate`, `pwrite` (a write stopped at the chunk that would grow the file), and `fallocate`; `F_SEAL_WRITE` refused while a shared mapping may write and then refusing writes, writable shared mappings, and `mprotect`; `F_SEAL_FUTURE_WRITE` leaving a writable mapping; `MADV_REMOVE` refused by access and by seal; `F_SEAL_EXEC` implying the write seals and guarding the execute bits; the seal commands on another file; seals and pages shared with a forked child |
| `pidfd` | `pidfd_open`'s checks and the file it makes (status flags, close-on-exec, mode and owner, name, one inode per task, `F_SETFL` keeping `PIDFD_THREAD`, `PID_FS_MAGIC`); the operations a pidfd refuses (`read`, `write`, `pread`, `lseek`, `fchmod`, `fchown`, `ftruncate`, `fallocate`, `fsync`, `mmap`, `FIONREAD`) and an `eventfd`'s `fchmod`; `FS_IOC_GETVERSION` and `PIDFD_GET_INFO` (identifiers, credentials, dumpability, structure sizes, request checks); a thread's pidfd (`ENOENT` without `PIDFD_THREAD`, a thread-group signal through it, a sleeping `poll` woken by its exit, its exit information); a child's pidfd through exit, zombie, and reaping, with `waitid(P_PIDFD)` non-blocking (`EAGAIN`), with `WNOWAIT`, and blocking; `pidfd_send_signal`'s flag, signal, record, and descriptor checks, the `siginfo` of each scope, `PIDFD_SELF_*`, a `/proc/self` directory, and a signal's sender seen by a child; `pidfd_getfd`; `CLONE_PIDFD` from `clone3` (the child without the pidfd, an unwritable word refused before any child exists) and `clone`; an `epoll` on a pidfd; a pidfd of a sibling inherited by a forked child |
| `fdinfo` | `/proc/self/fdinfo`: position, status flags with `O_CLOEXEC`, a mount ID, and the inode number of a file (after `lseek`), a close-on-exec file, a directory, both ends of a non-blocking pipe, and a socket; the directory listing and a closed descriptor; a pidfd's `Pid`/`NSpid` (its own, a child's, `-1` once reaped); an `eventfd`'s count, ID, and semaphore flag; a `timerfd` disarmed, armed (remaining time, interval), and fired (`TFD_TIMER_ABSTIME`); a `signalfd`'s mask; an `epoll` item's line and its removal with its file |
| `nodes` | `mknod`: a directory (`EPERM`) and an unknown type (`EINVAL`) refused, a type-less mode making a regular file, a FIFO that works, a socket node, `mknodat`, the umask, a device node only with `CAP_MKNOD`, and the name checks (existing names and links, trailing slashes, a missing or non-directory parent, a bad pointer); `utimensat` setting and omitting times, doing nothing for two `UTIME_OMIT`, looking the path up before checking the times, the flag and null-path checks, descriptors (an `O_PATH` one refused, through `AT_EMPTY_PATH`, a pipe, an `eventfd` refused), `AT_SYMLINK_NOFOLLOW`, a file the owner cannot read, a `/proc/self/fd` link, and the current time; the C library's `utimes` and `utime`, and on x86-64 the raw `utimes`, `futimesat` (by directory and by descriptor), and `utime`; the modes of new files, directories, and FIFOs under umask 0, and an existing file's kept |
| `xattr` | `user.*` names set, got, listed, and removed on a file and a directory (`XATTR_CREATE`/`XATTR_REPLACE`, an empty value, size queries, too small a buffer, a missing name, the longest name); the name checks (empty, over-long, a bare prefix, unknown and `system.*` namespaces) and a value over `XATTR_SIZE_MAX`; `trusted.*`, `security.*`, and a sticky directory without privilege; symbolic links (the `l` forms, and following one), a FIFO, a pipe, an `eventfd`, and sockets (`system.sockprotoname` for Unix stream and datagram, TCP, and UDP sockets, and the list it is in); the `f` forms, an `O_PATH` descriptor, bad pointers, and a missing path; `setxattrat`, `getxattrat`, `listxattrat`, and `removexattrat` with their `struct xattr_args` checks and null or empty paths |
| `misc` | `getgroups` (the count, a small or bad buffer, a negative size) and the `Groups:` line of `/proc/self/status`; `setgroups` for root (sorting, the invalid gid, `NGROUPS_MAX`, a bad buffer, clearing) and refused without `CAP_SETGID`; `readahead` on a file, a `/proc` file, and refused files (write-only, `O_PATH`, closed, a directory, a pipe, a socket); `sync_file_range`'s flag, range, and file checks; `fsync` and `fdatasync` (a file and a directory; `EINVAL` for a pipe, a socket, an `eventfd`, `/dev/null`, and a `/proc` file; `EBADF` for `O_PATH`) and `syncfs` (every kind of file; `EBADF` for `O_PATH` and a closed descriptor) |
| `locks` | `flock`: conflicts between descriptions, a duplicate and a forked child sharing a description's lock, release with the last descriptor, a conversion that would wait losing the old lock; POSIX record locks: `F_GETLK` reporting the owner's PID and range, a partial unlock splitting a lock, locks to the end of the file, shared read locks, a child inheriting none and conflicting with its parent's, release by closing a duplicate or another description of the file but not by `munmap`; `F_SETLKW` and `flock` waiting for another process, and ended by a signal (`EINTR`) |
| `netlink` | Route sockets: creation checks, port IDs (the process's, then negative ones) and binding; acknowledgements, errors carrying the request or capped, requests that are not requests, several messages in one send, privilege; a link dump with a loopback (`NLMSG_DONE` alone, one dump at a time), the loopback by index and by name; IPv4 addresses with 127.0.0.1/8 at host scope, dumps by family; `MSG_PEEK`, `MSG_TRUNC`, timeouts; group membership and the `SOL_NETLINK` options; `NETLINK_PKTINFO`; the calls netlink lacks; readiness; a forked child's requests; musl's `getifaddrs` and `if_nameindex` |
| `ifreq` | Interface requests on IPv4, Unix, and netlink sockets: `SIOCGIFCONF` (the length alone, entries with the loopback's 127.0.0.1, whole entries only, a negative length); a device by name and by index, flags, MTU, metric, map, hardware address (the bytes past it untouched), an alias's `:` kept and the name's 16th byte cleared; IPv4 address, netmask, destination, and broadcast on an IPv4 socket (`ENOTTY` elsewhere), an alias without an address; unknown devices, `SIOCGIFSLAVE`, `SIOCGIFMEM`, `SIOCGIFPFLAGS`, a bad pointer; changes without `CAP_NET_ADMIN`; musl's `if_nametoindex` and `if_indextoname` |
| `hostsig` | Not a recorded case: the `user_linux` `host_signals` tests send it host signals and follow its output (`siginfo` of a `kill`, a blocking `read` of standard input interrupted by a handler, death by `SIGTERM`) |
| `signals` | Handlers with `siginfo` from `raise`/`kill`/`sigqueue`, the mask during and after a handler, `SA_NODEFER`, `SA_RESETHAND`, delivery order of several unblocked signals, real-time queueing with `sigtimedwait`, `sigsuspend`, ignored signals, `SA_ONSTACK` alternate stacks, recovering from `SIGSEGV` (MAPERR, ACCERR), `SIGBUS`, and traps with `siglongjmp`, a handler editing the saved PC to skip a faulting store, `SIGPIPE`, and `abort()` after its handler returns (status 134) |
| `stdin` | Reading standard input to end of file |
| `segv` | Fatal `SIGSEGV` (status 139) |
| `abort` | `abort()` → `tgkill(SIGABRT)` (status 134) |
| `trap` | `__builtin_trap()`: `SIGILL` on x86-64 and RISC-V (132), `SIGTRAP` on AArch64 (`BRK`, 133) |

## Provenance

- Toolchain: Zig 0.16.0 (`zig cc`, bundled clang and musl 1.2.5), Homebrew
  bottle `zig 0.16.0_1` on macOS 27 arm64.
- Flags: `-static -Os -s -fno-sanitize=all -fno-stack-protector
  -ffile-prefix-map=<dir>=.`, targets `x86_64-linux-musl`,
  `aarch64-linux-musl`, `riscv64-linux-musl`.
- The build is reproducible: running `build.sh` twice produces identical
  `manifest.toml` hashes, and adding a program leaves the others' hashes
  unchanged.
- Size: 84 binaries (28 programs × 3 architectures), 2,868 KiB in total; each
  is stripped and statically linked so that no guest sysroot is needed.
- The expected results were recorded with `record-expected.sh` on the
  Linux kernel named in `expected/ORACLE` (OrbStack Linux 7.0.14, arm64).
  AArch64 binaries ran natively on that kernel. x86-64 binaries ran through
  a `binfmt_misc` translator (both Rosetta and `qemu-x86_64` are registered;
  `expected/ORACLE` lists them); their `mman` results are identical to the
  native AArch64 run, so their system calls reached the kernel. RV64
  binaries ran through `qemu-riscv64` user mode, which emulates some system
  calls itself (for example, it ignores most `madvise` advice). Where that
  emulation diverges from Linux in architecture-independent kernel code,
  `oracle-overrides.txt` substitutes the native result and says why.
  Where the x86-64 translator (Rosetta) diverges, the case runs under
  `qemu-x86_64` user mode installed in the container instead (its version
  is in `expected/ORACLE`): Rosetta resets an `SA_RESETHAND` disposition
  before running the handler. Where both translators lack a call the
  fixture checks (`clone3` and `futex_waitv` in Rosetta and QEMU, robust
  futex lists in QEMU, whose `/proc/self/task` also lists its own
  threads), or runs executed programs through `binfmt_misc` (`exec`), or
  mishandles process exit signals and `SA_NOCLDSTOP` (QEMU, `fork`), or
  lacks `TFD_IOC_SET_TICKS`, `signalfd4`'s mask-size check, and the
  kernel's POSIX timer IDs (QEMU, `events`), or converts
  `struct epoll_event` itself and faults on a bad pointer (Rosetta,
  `epoll`), or does not apply `epoll_pwait`'s mask during the wait (QEMU,
  `epoll`), or drops unknown socket type flags, writes `socketpair`'s
  descriptors only on success, and ignores `recvmmsg`'s timeout (QEMU,
  `sockets` and `sockmsg`), or cannot duplicate a mapping with `mremap`
  (Rosetta traps; QEMU checks the zero length first) and lacks
  `MADV_REMOVE` (QEMU, `shmem` and `memfd`), or lacks `pidfd_getfd`
  (Rosetta) or the pidfd `ioctl`s (QEMU) (`pidfd`), or leaves the host
  kernel's AArch64 status-flag encoding in `fdinfo` (both, `fdinfo`), or
  faults on `utime` with an unmapped buffer (Rosetta, `nodes`) or on
  `getxattr` with an unmapped path (Rosetta, `xattr`), or lacks the
  `*xattrat` calls (QEMU, `xattr`), or translates netlink messages itself
  (QEMU, `netlink`), the native AArch64 result is used for
  architecture-independent kernel code. Rosetta has once, in
  about ten recordings, lost a stopped child continued by `SIGCONT`
  (`fork`); a recording is kept only when it matches the native AArch64
  result.
- Containers ran with `--init` so the fixture was not the PID-namespace
  init (the kernel ignores default-action signals sent to an init, which
  would make `abort()` loop), and with `--security-opt seccomp=unconfined`
  so Docker's default seccomp profile did not refuse valid arguments (it
  returns `EPERM` for `personality(READ_IMPLIES_EXEC)`).
- License: the binaries statically link musl libc (MIT) and Zig's
  compiler-rt (MIT); the sources in `src/` are part of RAX (MIT).

## Updating

1. Edit `src/`, then run `./build.sh` (requires Zig 0.16.0).
2. Run `./record-expected.sh` on a host with Docker able to execute all
   three architectures, and review the diff under `expected/`.
3. Run `cargo test --no-default-features --features x86_64-suite,smir-jit
   --test user_linux`.

A case added to `cases.txt` is picked up by the test automatically; a new
program must also be added to `build.sh`. An override must name its source
architecture and a reason; the test checks that the overridden files equal
the source architecture's recording.
