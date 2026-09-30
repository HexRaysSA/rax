[← Documentation home](../../../README.md) · [User-mode overview](../../architecture/user-mode.md)

# User-mode validation evidence

This inventory records which source tests and external recordings exercise
the process-emulation contracts. Test presence is distinct from execution on
a particular host. The runtime mechanisms are in the
[user-mode topic pages](../../architecture/user-mode.md#runtime-topics).

## Evidence by subsystem

- [Memory and CPU contracts](#memory-and-cpu-contracts)
- [ABI and loading](#abi-and-loading)
- [Processes and scheduling](#processes-and-scheduling)
- [Signals and timers](#signals-and-timers)
- [Files and notifications](#files-and-notifications)
- [Descriptor I/O](#descriptor-io)
- [Networking and IPC](#networking-and-ipc)
- [Tracing and seccomp](#tracing-and-seccomp)
- [Recorded execution](#recorded-execution)

## Running the checks

```sh
cargo test --locked --no-default-features --features smir-jit --lib user::
cargo test --release --locked --no-default-features --features smir-jit --test user_linux -- --test-threads=1
cargo test --locked --no-default-features --features x86_64-suite,smir-jit --test user_darwin
```

The library filter selects `user::`; it does not run every ISA or backend
test. The integration target uses recorded Linux results. The ignored live
Docker comparison requires `RAX_USER_DOCKER_ORACLE=1`. Record test, ignored,
filtered, and self-skip counts separately. See
[Verification](../verification.md#linux-process-and-whole-program-comparisons)
for the output projection and oracle substitutions.

Linux integration fixture processes share the host filesystem. Some recorded
programs, including `uringio`, use fixed absolute `/tmp` names; `TMPDIR`
isolation separates IPC namespaces but does not rewrite those guest paths.
Run this target serially to keep architecture/mode comparisons from modifying
the same fixture files concurrently.

Compatibility filesystem tests do not assume host inode numbers fit in 32
bits. `stat64` checks preserve the complete host identity; `compat_stat` checks
expect `EOVERFLOW` and unchanged guest output when the inode or link count does
not fit (`fs/stat.c`, `cp_compat_stat`). Synthesized proc inodes also exercise
successful 64-byte conversion on every host. Controlled directory snapshots
exercise both compatibility dirent layouts, the exact 32-bit inode boundary,
valid-prefix output, unchanged output/cursor on overflow, and subsequent
64-bit retrieval (`fs/readdir.c`, `compat_filldir`, `compat_fillonedir`).

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- | --- |
| F1 | Host temporary-file inode numbers fit in 32 bits. | The original success-only tests used host temporary volumes. | Unconditional successful `compat_stat` and compatibility dirent conversion. | Intel macOS CI returned `EOVERFLOW`; inspect the host inode and compare against `0xffffffff`. New tests cover both narrowing outcomes and controlled boundary identities. | Falsified; no test now relies on it. |

Host metadata controls the expected narrowing outcome, and fixed guest
identities guarantee successful-layout coverage. This changes tests and their
execution guidance only; filesystem translation and error behavior are
unchanged. Medium-impact finding: parallel recorded fixtures may interfere
through absolute paths; serial execution is required until those fixtures or
their filesystem namespaces are isolated.

The Darwin target has no recordings: on a macOS host it compares each run
with the same program's native run (x86_64 through Rosetta, which exercises
the host's x86-64 user space but is not a physical-x86 oracle), and
elsewhere its comparisons report themselves skipped. See
[Darwin evidence](../../architecture/user-mode/darwin.md#evidence).

## Memory and CPU contracts

### ELF acceptance matches `binfmt_elf`

Unit tests in `src/user/image/elf/tests.rs`, including a 20,000-image corruption
sweep

### Address-space semantics

Unit tests in `src/user/mm/tests.rs`, including a randomized model-based
differential (8 seeds × 3,000 operations), and shared objects: stores reaching the
file and the file's changes reaching the mapping, pages shared between mappings and
moves, bus errors past the end, read-only objects refusing forced stores,
re-attachment for writing, detaching, and the frame and extent allocators never
overlapping

### x86-64 user-mode contract

`src/isa/x86_64/user_mode_tests.rs` (28 tests; the JIT-invalidation test is
discriminating on x86-64 hosts; the XSAVE-image tests compare with the
`XSAVE`/`XRSTOR` instructions, which also keep x87 tags across `FXRSTOR`/`XRSTOR`)

### Adapter contracts

`src/user/cpu/tests.rs` (23 declared tests across the three ISAs, including
JIT/interpreter agreement on RISC-V and single-instruction adapter exits)

### Memory locking

`src/user/linux/tests/mlock.rs` (6 tests, on every 64-bit ABI): `mlock`, `mlock2`,
and `munlock` (the right, the limit less what is already locked, whole pages, the
kernel's length arithmetic, holes, `PROT_NONE`), populating or not, `madvise`'s
refusals, `mlockall` with `MCL_FUTURE` through `mmap`, `brk`, and `mremap`
(`MREMAP_DONTUNMAP`'s count), the special `[vdso]` mapping, `VmLck`, and a new
process

### Memory sealing

`src/user/linux/tests/mseal.rs` (4 tests, on every 64-bit ABI): `mseal`'s checks in
order, the unmapping, remapping, and reprotecting a seal refuses (partial `mprotect`
included), discarding advice by writability and backing, `brk` and `shmdt` keeping
sealed pages, `SHM_REMAP`

### Vector import

`src/user/linux/tests/vectored.rs`: vectors imported before anything moves (a far
vector refuses the whole transfer and leaves a file's position), the count as an
`unsigned int`, a single vector capped before `access_ok`, a length beyond memory,
`sendmsg` and `recvmsg`, the `RWF_*` flags `kiocb_set_rw_flags` refuses and
`RWF_NOSIGNAL`; `src/user/mm/tests.rs`: a probe of any length ends at the first
fault

### Process memory and kernel objects

`src/user/linux/tests/procmem.rs` (4 tests, on every 64-bit ABI): `process_vm_readv`
and `process_vm_writev`'s checks in order and vector import, transfers by page with
`VM_READ` and `VM_WRITE`, partial transfers at a remote or local fault, a thread's
ID, an exited leader, another process; `process_madvise`'s checks, advice by vector
with empty and misaligned vectors, pidfds. `src/user/linux/tests/kcmp.rs` (3 tests,
on every 64-bit ABI): `kcmp`'s checks in order, open file descriptions and their
total order, what threads share by `CLONE_IO` and `CLONE_SYSVSEM`, an exited leader,
epoll items by descriptor and offset; the order's unit test in
`src/user/linux/syscall/kcmp.rs`. `VM_READ`: `src/user/linux/tests/syscall_mm.rs`
(`/proc/self/maps`, `MADV_POPULATE_READ`) and `src/user/linux/tests/loader.rs` (a
segment without `PF_R`)

### Memory-management system calls

`src/user/linux/tests/syscall_mm.rs`: `mprotect`, `madvise`, and `personality`
driven through `dispatch` on every 64-bit ABI, expectations from the named kernel
functions; shared anonymous memory as a `shmem` object (its `/proc/self/maps` line,
`mremap` duplication and its checks, growth past the object), and shared file
mappings (write-back through `pread`/`pwrite`, `msync`, `MREMAP_DONTUNMAP`, pages
dropped by `ftruncate`, `truncate`, and `O_TRUNC`); `memfd_create`'s flag and name
checks, `MFD_HUGETLB`'s empty pool, and seals on `ftruncate` and `mmap`/`mprotect`.
`src/user/linux/fs/memfd.rs`: the seal rules of `shmem_write_begin` and
`shmem_setattr`

## ABI and loading

### Loader and stack layout

`src/user/linux/tests/{loader,stack}.rs` with addresses derived by hand from the
kernel algorithms

### i386 compatibility tasks

`src/user/linux/tests/i386/`: ELF32 acceptance, layout and numbering,
compatibility-mode entry and stack, `INT 0x80`, TLS descriptors/reloads,
mapping/iovec conversions, file opens and offsets, status/statistics layouts,
directories, record locks, exec vectors, time32/time64 layouts, process and
resource layouts, the i386 signal frames and returns (layouts derived from the
UAPI structures, FSAVE conversions from the SDM tag rules, selector reloads and
`IRET` faults, bad frames, the `[vdso]` trampolines), the 32-bit signal calls and
`struct compat_siginfo`, threads (`CLONE_SETTLS` descriptors checked before a TID is
taken, the separate 32-bit robust list, `futex_time32`/`futex_time64` timeouts),
`compat_sys_ioctl`'s routing and `epoll_pwait2`, sockets (`struct compat_msghdr`,
32-bit control messages and their checks, `mmsghdr` strides, `socketcall`, old
timeouts, interface requests), System V IPC (the `ipc` multiplexer, the old and
`*64` structures, whole commands, 32-bit message types, `old_timespec32`
timeouts), POSIX message queues (`struct compat_mq_attr`, `struct
compat_sigevent`, the `*_time32` calls), asynchronous I/O (32-bit contexts and iocb
pointers, `io_getevents_time32`, `struct __compat_aio_sigset`), `select`,
`pselect6`, and `ppoll` (32-bit fd set words, `struct old_timeval32`, the old
`select`, `struct compat_sigset_argpack`), seccomp filters (`struct
compat_sock_fprog`, the 32-bit `struct seccomp_data`), tracing (a 32-bit tracer's
forms, the i386 register sets, the x86-64 view's selectors), and rejection of
unconverted calls;
`src/user/linux/abi/compat_tests.rs`: 32-bit layout and overflow checks;
`src/isa/x86_64/user_gdt_tests.rs`: GDT selector/TLS behavior; `user_linux`
`abi_tables`: numbering against `unistd_32.h`. `user_linux` `fixtures` runs an i386
subset of the fixture programs, and the i386-only `sigframes`, `futex32`, `ipc32`,
`mq32`, `aio32`, `select32`, `seccomp32`, and `ptrace32` (`cases-i386.txt`),
against results recorded on Linux 6.19 for x86-64 under `qemu-system-x86_64`
(`tests/fixtures/user/linux/oracle/`); the morok program corpus has no i386
builds.

### ARM EABI compatibility tasks

`src/user/linux/tests/arm/`: EABI admission, the arm64 compat layout
(`TASK_SIZE_32`, `STACK_TOP` at the vectors page, `mmap_base`) and numbering,
`compat_start_thread` and the initial stack with the compat capabilities and
`AT_PLATFORM`, the `[vectors]` kuser helpers and `[sigpage]` return code (their
bytes from `kuser32.S` and `sigreturn32.S`), `SVC` with R7, the AArch32
exceptions' signals and fault records (`BKPT`'s and the aborts' ESR values from
the Arm ARM's exception classes, the `AARCH32_BREAK_*` encodings, the emulated A32
CP15 barriers, PC alignment), the private calls past the table, the `aarch32_*`
wrappers' register pairs, the EABI `struct stat64` and `struct compat_flock64`,
`statfs64`'s size fixup, the direct System V IPC calls with `IPC_64` and the
16 KiB `COMPAT_SHMLBA`, `accept`/`send`/`recv`, `uname` under `PER_LINUX32`,
`CLONE_SETTLS`, and the AArch32 signal frames and returns (layouts from
`asm/signal32.h`, the handler's entry state from `compat_setup_return`, bad
frames from `valid_compat_regs`), and tracing an AArch32 thread (a 32-bit
tracer's `compat_arch_ptrace` requests, the AArch32 views' sets for a 32-bit
and a 64-bit tracer, `valid_compat_regs` on writing, a 32-bit tracer's view of
an AArch64 thread); `src/user/cpu/tests.rs`: the AArch32 adapter
(User mode, `SVC`/`BKPT`/UNDEFINED reporting, precise faults, PL0 CP15 and FP
system-register access, the exclusive monitor, interworking and IT blocks, and
the PC's low bits, which the kernel keeps until the return to the thread);
`src/user/linux/tests/stack.rs`: the compat auxiliary vector's order;
`user_linux` `abi_tables`: numbering against `unistd-eabi.h` and arm64's
`syscall_32.tbl`. `user_linux` `fixtures` runs an ARM subset of the fixture
programs (49 of 55, built for ARMv7-A with VFPv3-D16), the same programs
built as Thumb-2 code (`thumb`), and the ARM-only `armframes` (the AArch32
signal frames and signal calls, `cases-arm.txt`) against results recorded on
Linux 6.19 for arm64, configured as the modelled compatibility task, under
`qemu-system-aarch64` (`tests/fixtures/user/linux/oracle/`); the morok
program corpus has no ARM builds.

### io_uring

`src/user/linux/tests/uring.rs`: `io_uring_setup`'s checks, rounding, ring
offsets, and descriptor; the ring and SQE mappings and what they refuse;
submission order and the SQ head; the NOP flags; links, hard links,
`IOSQE_CQE_SKIP_SUCCESS`, and the failure of a link's request; requests
failing `io_init_req`'s checks (with and without `IORING_SETUP_SUBMIT_ALL`);
a dropped SQ index; CQ overflow and its flush; the task work of deferring and
ordinary rings; drains and async requests; waits (timeouts, a signal);
`poll` of the ring; registration (probe, personalities, eventfds, enabling a
disabled ring, registered ring descriptors); and `/proc/<pid>/fdinfo`, each
following the Linux 6.19 function it names. `src/user/linux/tests/uring/rsrc.rs`:
registered files and buffers (`io_uring/rsrc.c`, `io_uring/filetable.c`):
registration and its refusals, sparse tables, updates, tags posted as nodes
are released (a node a request uses once that request is freed), a
registered file holding its file open, NOP's lookups,
`IORING_OP_FILES_UPDATE` and slot allocation within the allocation range,
pinning checks, `VmPin`, the `RLIMIT_MEMLOCK` charge of a user without
`CAP_IPC_LOCK`, cloning buffers between rings, the compatibility vector
layout, and the fdinfo listings. `src/user/linux/tests/uring/rw.rs`: reads
and writes (`io_uring/rw.c`) on a regular file at an offset and at the file
position, short transfers failing their links, vectored and
registered-buffer transfers and their refusals, the checks of the request
and the file (in preparation and at issue), requests waiting for pipes (a
write's wake-up, `RWF_NOWAIT`, links, room to write, deferring rings), a
sleeping call also waking for them, a write without readers (task work,
`SIGPIPE`, `RWF_NOSIGNAL`), registered files holding their nodes, the
operations that run on the workers (`FSYNC`, `SYNC_FILE_RANGE`,
`FALLOCATE`, `FADVISE`, `MADVISE`, `FTRUNCATE`: their preparation and which
of their failures fail a link), and cancellation at exec and fork.
`src/user/linux/tests/uring/files.rs`: opens (`io_uring/openclose.c`) into
descriptors (the lowest free one, taken before the lookup, `O_LARGEFILE`,
the `O_NONBLOCK` try, `EMFILE` by the limit, `ENXIO` for a FIFO without a
reader, the name read at preparation), `OPENAT2`'s structure and flags,
direct descriptors, `FIXED_FD_INSTALL`, `CLOSE`, `PIPE` (into slots too),
the path operations (`io_uring/fs.c`, `statx.c`), whose failures keep
their links, and extended attributes (`io_uring/xattr.c`: of a file and a
path, their preparation, the value read at preparation).
`src/user/linux/tests/uring/poll.rs`: poll requests (`io_uring/poll.c`):
one-shot ones woken by a write or ready at once (with `IO_POLL_UNMASK`'s
events), files without a wait queue, preparation, multishot ones woken by
each write and not by reads, removals (none, a waiting request, the newest
of two) and their event and user-data updates, `EALREADY` for a poll whose
task work a deferring ring holds, links, the async workers, exec and fork,
fdinfo's `PollList` by hash bucket, and a wake-up of io_uring's own ending a
multishot poll. `src/user/linux/tests/uring/timeout.rs`: timeouts
(`io_uring/timeout.c`): expiry, the count of completions (a timeout's own
CQE left out, the list's order), a wait an expiry ends, links and
`IORING_TIMEOUT_ETIME_SUCCESS`, multishot ones, preparation, removals and
updates (a count dropped, an absolute time past, the link-timeout flag
alone), linked timeouts (expiring or cancelled first, the rest of the
link, their update); cancellation (`io_uring/cancel.c`) of polls, waiting
requests, timeouts, and requests queued for the workers, by user data,
all, any (the table's order, then the timeouts), file, and operation, its
preparation, `IORING_REGISTER_SYNC_CANCEL`; exec and fork, and a sleeping
call's wake-up for a timer. `src/user/linux/tests/uring/net.rs`: socket
requests (`io_uring/net.c`): sends and receives on a pair (data left,
waiting, `MSG_DONTWAIT`), `MSG_WAITALL` in parts and cancelled, messages
(vectors, `MSG_TRUNC`, the header read at preparation), preparation,
`ENOTSOCK`, buffer selection, `IORING_RECVSEND_POLL_FIRST`, `SHUTDOWN`'s
link, Unix sockets made, bound, listened, connected, and accepted, accepts
into slots and multishot ones, and TCP connecting in the background and
accepting with a queue. `src/user/linux/tests/uring/kbuf.rs`: provided
buffers (`io_uring/kbuf.c`): `PROVIDE_BUFFERS` and `REMOVE_BUFFERS` (their
checks, the 65535-buffer limit), selection by reads (a read keeping its
buffer while it waits, reporting it as it fails), receives (handing it
back) and sends (keeping it), buffer rings (registration and its checks,
mappings, status, the memlock charge, the head moving as requests
complete or at once for files without a wait queue, incremental rings),
bundles (the message state a ring caches sizing the next), multishot
`RECV` and `RECVMSG` (their ends: no buffer, a full CQ, a header that
does not fit), and `READ_MULTISHOT`. `user_linux` `fixtures` runs the
`uring`, `uringio`, `uringpoll`, `uringtimeout`, `uringnet`, and `uringbuf` programs on every architecture against results recorded on the Linux
6.19 kernel oracles (native AArch64 and x86-64 in their `compare` runs,
i386, ARM, and Thumb-2).

### Syscall and errno numbering

`user_linux` `abi_tables` against the vendored UAPI headers

### Machine administration and mounts

`src/user/linux/tests/admin.rs` (10 tests) and `src/user/linux/tests/mounts.rs` (7
tests), on every 64-bit ABI (the I/O port calls on x86-64): each call's checks in
order for an unprivileged caller and for root, the refusals, the empty kernel log
and its wait, reading the NTP state and the `timex` bytes written back or not, the
CPU-time and device clocks, `mount`'s string and option copies,
`copy_struct_from_user` zero checks up to a fault, `build_mount_kattr`, `open_tree`
as an `O_PATH` open and its descriptor taken first, and `open_tree_attr` publishing
its descriptor only on success

## Processes and scheduling

### Threads, futexes, and signal targeting

`src/user/linux/tests/threads.rs` (15 tests): `clone`/`clone3` register state and
validation on every 64-bit ABI, `unshare`'s implied flags and checks alone and with
another thread, futex wait/wake/bitset/requeue/wake-op/PI and interrupted waits,
robust-list and `clear_child_tid` handling at exit, every thread's robust futexes
released when the process ends, `complete_signal` choice and
retargeting, thread and process exit status, `CLONE_VFORK`, and the `/proc` thread
views

### `execve` and waits

`src/user/linux/tests/exec.rs`: `#!` parsing edge cases of `load_script`,
`execve`/`execveat` error order on every 64-bit ABI, the argument space charged to
the byte (pointers, an empty `argv`, a script's rewritten arguments), a script named
by a close-on-exec descriptor, the image replacement with a script and what survives
it, the caller's robust futexes released against the old address space,
`READ_IMPLIES_EXEC` from a 32-bit program's missing `PT_GNU_STACK` and kept or
dropped across `execve` (readable segments, the zero-filled tail, the stack, and
the heap executable where `VM_DATA_DEFAULT_FLAGS` follows it),
`wait4`/`waitid` argument checks and `siginfo_t` writes on errors, children
passing to a live thread (`__WNOTHREAD`) on thread exit and `execve`, and processes
unavailable without host processes

### pidfds

`src/user/linux/tests/pidfd.rs` (9 tests): `pidfd_open`'s checks and file on every
64-bit ABI, the operations a pidfd refuses and its `fstat`/`fstatfs`, the `ioctl`s
(`PIDFD_GET_INFO` fields, sizes, and request checks; `FS_IOC_GETVERSION`; the
namespace requests), a thread's pidfd through its exit (a sleeping `ppoll` woken by
it, the exit status kept), `CLONE_PIDFD` for threads (the result word, `EFAULT` and
`EMFILE` leaving no thread), `pidfd_send_signal`'s scope, record, and descriptor
rules, `pidfd_getfd`, `waitid(P_PIDFD)` checks, and a host process watched to its
end. `src/user/linux/fs/pidfd.rs`: inode numbers and the registry

### Scheduling attributes

`src/user/linux/tests/priority.rs` (9 tests, on every 64-bit ABI) and the unit tests
of `src/user/linux/priority.rs`: defaults, the priority ranges,
`sched_setscheduler`'s checks in order and the permission rules, `sched_setattr`'s
sizes, flags, slices, `SCHED_IDLE`, and kept policy or parameters, `sched_getattr`,
deadline admission and `EAGAIN` at `clone`, time slices, nice values (a thread, the
group, the user, a partial failure), inheritance, `reset_on_fork`, timer slack,
`/proc/<pid>/task/<tid>/stat`, and I/O priorities and their sharing by `CLONE_IO`
threads

### Restartable sequences

`src/user/linux/tests/rseq.rs` (3 tests, on every 64-bit ABI): `rseq`'s checks in
order and the fields it writes, and the return to user mode driven directly (IDs
after registration, a preempted or signalled section aborting, a section cleared
outside it or left alone after a system call, the failures that force `SIGSEGV`);
end to end, the `rseq` fixture's inline-assembly critical sections on every 64-bit
guest ISA

## Signals and timers

### Signals

`src/user/linux/signal/tests.rs` (records, queues, alternate stacks) and
`src/user/linux/tests/signals.rs` (frames, `rt_sigreturn`, restart, and the signal
calls on every 64-bit ABI, with offsets from the UAPI structures)

### Host signals

`user_linux` `host_signals`: `kill` from the test process reaches the `hostsig`
guest with `SI_USER` and the sender on every 64-bit guest ISA, interrupts a blocking
`read` of a pipe with `EINTR`, and a default-action `SIGTERM` ends `rax-user` with
`SIGTERM`; with `--no-signal-forwarding` the host default applies.
`src/user/linux/sigmail.rs`: sender records claimed oldest first, only by their
target, withdrawn when unsent, and ignored below the target's floor

### POSIX timers

`src/user/linux/tests/posix_timers.rs`: the state machine driven by explicit times
against `hrtimer_forward` arithmetic (overrun counts, one-shot and `SIGEV_NONE`
`gettime`, the 1 ns of a fired but unqueued timer, stale signals, CPU timers set in
the past, parked ignored signals), `timer_create` error order and ID use on every
64-bit ABI, the other calls' checks, one queued record per timer, stale-record
drops, re-queueing when `SIG_IGN` is replaced, thread targets, and `execve`'s flush

### Timers and blocking

`src/user/linux/tests/waits.rs`: interval timers, `alarm` rounding, interrupted
sleeps and `restart_syscall`, `clock_nanosleep` clocks,
`poll`/`select`/`ppoll`/`pselect6` interruption, write-back, clamping, and temporary
masks, interruptible pipe reads, `sigtimedwait` woken by a timer, and the deadlock
diagnostic

## Files and notifications

### Nodes, file times, and the umask

`src/user/linux/tests/nodes.rs`: `do_mknodat`'s type, name, and privilege checks in
order; `utimensat` looking the path up before checking the times; the older calls
converted as `fs/utimes.c` converts them; the guest's umask alone masking new files

### Extended attributes

`src/user/linux/tests/xattr.rs`: `setxattr`'s checks in order (flags, name, size,
value, path), the name-length limit, listing and its sizes, the namespaces'
permissions and handlers (no POSIX ACLs), host names hidden on macOS, descriptors
(`O_PATH` refused), pipes and sockets (`system.sockprotoname`), and `struct
xattr_args` of the `*xattrat` calls

### File locks

`src/user/linux/tests/locks.rs`: `flock`'s and the record-lock commands' checks in
order, `flock` locks per description (duplicates, other descriptions, a conversion
losing its lock, closing), a wait for another description's lock, the POSIX locks
released by closing a duplicate, another description, or a descriptor replaced by
`dup3`, the mapping descriptors kept until then, and (on Linux hosts) OFD locks per
description

### Groups, read-ahead, and syncing

`src/user/linux/tests/misc.rs`: groups inherited and sorted, `setgroups`'s privilege
and limits, the `Groups:` line of `/proc/self/status`, the file checks of
`readahead` and `sync_file_range`, and the files `fsync` and `syncfs` take on every
64-bit ABI

### inotify

`src/user/linux/tests/inotify.rs` (9 tests, on every 64-bit ABI and, on Linux hosts,
with both backends, so that the host kernel checks the expectations): the calls'
checks in order, descriptors, the events of each file call and their order, a file
watching itself through removal and renames, merging, overflow, `read`'s records,
`FIONREAD`, waiting readers, one-shot and `IN_EXCL_UNLINK` watches, closes at the
last reference (a duplicate, a mapping), `fdinfo`, `poll`, and the limits; unit
tests of delivery in `src/user/linux/fsnotify/mod.rs` and of the queue in
`src/user/linux/fsnotify/queue.rs`

### `/proc/<pid>/fdinfo`

`src/user/linux/tests/fdinfo.rs`: the generic lines of a file (position, flags with
`O_CLOEXEC`, mount, inode) on every 64-bit ABI and of a pipe, the directory's
listing, and the `eventfd` (16-column count, ID, semaphore), `signalfd` (mask
without `SIGKILL`), `timerfd`, `epoll` (events with `EPOLLERR | EPOLLHUP`, data,
position, inode, device), and pidfd lines (`-1` once gone);
`src/user/linux/fs/anon.rs`: `eventfd` IDs as `ida_alloc` gives them

## Descriptor I/O

### `epoll` and readiness

`src/user/linux/tests/epoll.rs`: `do_epoll_ctl` and `do_epoll_wait` checks in order
on every 64-bit ABI, each ABI's `struct epoll_event`, level-triggered,
edge-triggered (including a write from outside the emulator), and one-shot items,
hang-up and error, the ready-list order, `maxevents` rotation, and a faulting
buffer, items keyed by description, nesting and loop depth, and sleeping, `EINTR`,
and `epoll_pwait`'s mask. `src/user/linux/tests/waits.rs`: pipes in `ppoll` as
`pipe_poll` reports them

### Event, timer, and signal descriptors

`src/user/linux/tests/events.rs`: `eventfd` limits, semaphores, zero-length and
faulting transfers, `readv`/`writev` segments, and levels; `timerfd` ticks driven by
explicit times, `TFD_IOC_SET_TICKS`, and argument order on every 64-bit ABI;
anonymous-inode `fstat` and `/proc` names; `signalfd` checks, reads in order, lost
records at a fault, every `siginfo_t` layout's `struct signalfd_siginfo`, and
wake-ups of blocked readers and pollers. `src/user/linux/tests/files.rs`: `F_GETFL`
of regular, `O_PATH`, directory, pipe, and `eventfd` descriptions

### Splicing

`src/user/linux/tests/splice.rs` (7 tests, 6 on each host, on every 64-bit ABI):
`splice`'s and `vmsplice`'s checks in order (`tee`'s flags before its length),
file-to-pipe and pipe-to-file transfers at an offset and at the file's position,
pipe to pipe, sockets and the memory devices, the end of a pipe's data,
`SPLICE_F_NONBLOCK` and `O_NONBLOCK`, a sleep and a signal ending it, `EPIPE` with
`SIGPIPE`, `vmsplice` both ways with faults and its deafness to `O_NONBLOCK`, and
`tee` copying without consuming (Linux hosts) or refused (others); end to end, the
`splice` fixture

### Asynchronous I/O

`src/user/linux/tests/aio.rs` (13 tests, 12 on every 64-bit ABI): `io_setup`'s
checks in order and the ring it maps (header, slots, `aio-max-nr`, a `*ctxp` that
cannot be written), `io_submit`'s checks in order and the slots refused requests
give back, reads, writes, vectors, syncs, and `IOCB_FLAG_RESFD`, pipes (`-EAGAIN`,
`-EINTR`, a request sleeping and resuming where it slept) and `-EPIPE` with and
without `SIGPIPE`, `IOCB_CMD_POLL` completing with a wake-up's key or the events
polled (and waking a thread asleep in another call, which reads its eventfd),
`eventfd_signal` reaching `UINT64_MAX`, `io_cancel` and `io_destroy` of waiting
polls, `io_getevents` (timeouts, `KTIME_MAX`, a fault leaving the events in the
ring, the process's head clamped), `io_pgetevents`' mask, slots reaped by the
process, and the ring under `mlock`, `mremap`, and `mseal`; the slot batching and
ring geometry in `src/user/linux/aio.rs`; end to end, the `aio` fixture

## Networking and IPC

### Sockets

`src/user/linux/tests/sockets.rs` (15 tests on every 64-bit ABI): `__sock_create`
and `inet_create` checks in order, `socketpair` writing its reserved descriptors
first, Unix names (relative and over-long paths, node permissions, rebinding,
abstract names in use and freed, autobind), `move_addr_to_user` copies, IP
`bind`/`connect` address checks, `copy_msghdr_from_user` checks, `scm_detach_fds`
installation and `MSG_CTRUNC`, descriptions shared within the process,
`SCM_CREDENTIALS` checks and `SO_PASSCRED` delivery, timeouts and signal
interruption, `sk_setsockopt`/`sk_getsockopt` rules, `SIGPIPE` by protocol,
`sendmmsg`/`recvmmsg`, readiness and the socket `ioctl`s, IPv6; unit tests of the
address codec, control-message framing, name mapping, and timeouts in
`src/user/linux/net/`

### Netlink

`src/user/linux/tests/netlink.rs` (10 tests on every 64-bit ABI; the host's sockets
on Linux, the emulation elsewhere): `netlink_create`'s checks, port IDs and
`netlink_bind`, acknowledgements and errors (capped, several messages per send,
privilege), link dumps and lookups by index and name, address dumps by family,
`MSG_PEEK`/`MSG_TRUNC`/timeouts, membership and options, `NETLINK_PKTINFO`, the
calls netlink lacks, readiness, a socket passed within the process; unit tests of
`rtnetlink_rcv_msg` dispatch, message layouts, dump pacing and `NLMSG_DONE`
placement, send checks, and the host interface translation in
`src/user/linux/net/netlink/`

### Interface requests

`src/user/linux/tests/ifreq.rs` (every 64-bit ABI; the host's answers on Linux, the
emulation elsewhere): `SIOCGIFCONF`'s length and entries, the device requests by
name and index on IPv4, Unix, and netlink sockets, the hardware address's untouched
bytes, IPv4 addresses on an IPv4 socket only, unknown devices, faults, privilege,
driver requests; unit tests of `dev_ioctl`, `devinet_ioctl`, `dev_ifconf`, and
IPv6's address changes in `src/user/linux/net/ifreq.rs`

### System V message queues

`src/user/linux/tests/sysvmsg.rs` (2 tests on every 64-bit ABI): `msgsnd`'s and
`msgrcv`'s checks in order, message types (`MSG_EXCEPT`, the least type up to a
bound), `E2BIG` and `MSG_NOERROR`, `MSG_COPY`, a full queue, `msgctl`'s commands,
and a receiver waiting for its type, ended by a removal or a signal; unit tests of
`find_msg` and `msg_fits_inqueue` in `src/user/linux/ipc/msg.rs`

### System V semaphores

`src/user/linux/tests/sysvsem.rs` (5 tests on every 64-bit ABI): values and
`semctl`'s commands with each ABI's `semid64_ds`, operation lists all or none and in
order, `semtimedop`'s checks in order and its timeout, waits counted by `GETNCNT`
and `GETZCNT` and ended by a value, a removal, or a signal, `SEM_UNDO` at exit, undo
lists shared by `CLONE_SYSVSEM` or a thread's own, left by `unshare(CLONE_SYSVSEM)`
or a thread's exit; unit tests of `perform_atomic_semop`'s rules and `exit_sem` in
`src/user/linux/ipc/sem.rs`

### System V shared memory

`src/user/linux/tests/sysvshm.rs` (3 tests on every 64-bit ABI): attaches seeing
each other's stores, attach counting by mapping (split, not merged back), `shmdt`
and `munmap`, `/proc/self/maps`, read-only attaches, `SHM_RND` and `SHM_REMAP`,
keys, `SHM_STAT`, `IPC_INFO`, `SHM_INFO`, `IPC_SET`, `SHM_LOCK`, and removal while
attached; unit tests of identifier allocation, `ipcperms`, the tables, and
publication in `src/user/linux/ipc/`

### POSIX message queues

`src/user/linux/tests/mqueue.rs` (9 tests, on every 64-bit ABI): `mq_open`'s checks
in order, the attributes, limits, `RLIMIT_MSGQUEUE` charge, and permissions,
priorities, the status line and position, sizes, access, timeouts, a message taken
although its copy faults, waiting receivers handed messages and waiting senders
given slots, a signal ending a wait, notifications (`SI_MESGQ`, once, `EBUSY`,
removal by closing, none while a receiver waits, `SIGEV_THREAD`'s checks),
`mq_getsetattr`, unlinked queues, and `poll`; the `sigmail` unit test of records
with a code and value

## Tracing and seccomp

### Process tracing

`src/user/linux/tests/ptrace.rs` (9 tests, 8 on every 64-bit ABI): `ptrace`'s checks
in order, `PTRACE_TRACEME` and `TracerPid`, each architecture's general registers
(layout, writing back, PSTATE's check), x86-64's `struct user` (`putreg`'s selector,
base, flag, and debug-register rules), the signal-delivery-stop and the tracer's
verdicts (cancelled, changed, requeued when blocked, never for `SIGKILL`), ignored
signals queued and group stops trapped, `execve`'s `SIGTRAP` and event stop, a
tracer's link ending (detach, `PTRACE_O_EXITKILL`), answers read together with the
stop or end that follows them;

`src/user/linux/tests/ptrace_stops.rs` (12 tests, 5 on every 64-bit ABI):
system-call stops in each architecture's entry and exit view,
`PTRACE_O_TRACESYSGOOD` and the messages, `PTRACE_GET_SYSCALL_INFO` and
`PTRACE_SET_SYSCALL_INFO` (sizes, checks, a number changed or skipped, a result
set), `PTRACE_SYSEMU` by the flags read before the stop, a system-call stop's signal
sent from the kernel, a tracer's end at a system-call stop, `NT_ARM_SYSTEM_CALL`,
single steps and their traps, a stepped system call's report, entering a handler,
RISC-V refusing to step, block steps through the scheduler (a tracer thread serving
each stop), and the others refusing them;

`src/user/linux/tests/ptrace_events.rs` (8 tests, 6 on every 64-bit ABI): clone
events for seized and attached threads (`CLONE_PTRACE`, `CLONE_UNTRACED`), exit
events for `exit`, `exit_group`, and fatal signals (none for `SIGKILL`), seccomp
events (after the entry stop, rechecked, skipped), `SECCOMP_RET_TRAP` rolling a
traced call back, and a tracer reaping exited threads (the group's status after a
group exit);

`src/user/linux/tests/ptrace_fork.rs` (5 tests, 3 on every 64-bit ABI): which fork
is traced and reported (`CLONE_VFORK`, the exit signal, `CLONE_PTRACE`,
`CLONE_UNTRACED`, the options), the forker passing its tracer a link and stopping
for its event, the new process traced along its own link (its first stop, the
tracer's end detaching it), `vfork`'s events around its sleep (a stopped sleeper not
woken), and a tracer adopting, waiting for, and reaping the new tracee;

`src/user/linux/tests/ptrace_seccomp.rs` (4 tests, 2 on every 64-bit ABI):
`PTRACE_O_SUSPEND_SECCOMP`'s checks (`CAP_SYS_ADMIN`, the tracer's own seccomp and
suspension, `PTRACE_SEIZE`) and a suspended tracee skipping filter and strict mode,
the tracee's filters oldest first with their metadata, and the tracer's checks and
copies (`EACCES`, sizes, `EFAULT`, partial metadata);

`src/user/linux/tests/ptrace_jobctl.rs` (8 tests, 6 on every 64-bit ABI): group
stops as seized and attached threads report them and the tracer's `SIGCHLD` codes,
other traced threads joining, `PTRACE_INTERRUPT` for running, sleeping (the call
restarted), stopped, and attached threads, `PTRACE_LISTEN` and what traps it again,
`SIGCONT` telling seized threads, the tracer's records of stops and listening, and
`SIGSTOP` along a link;

`src/user/linux/tests/ptrace_regsets.rs` (8 tests, 3 on every 64-bit ABI): the
floating-point sets of each architecture (layouts, reserved tails, whole-area and
MXCSR rules, prefixes, `PTRACE_GETFPREGS`), x86-64's XSAVE area (software bytes,
header, `EFAULT`, compacted `EINVAL`), `NT_ARM_TLS`, `PTRACE_ARCH_PRCTL` on both
sides, `PTRACE_PEEKSIGINFO` (either queue, order, offsets; the tracer's checks and
partial copies), `PTRACE_GET_RSEQ_CONFIGURATION`, and x86-64's `NT_386_IOPERM` and
`NT_X86_SHSTK` with the order of each side's refusals and copies; the classic branch
classifier in `src/user/cpu/x86_64/branch.rs` (4 tests: unconditional transfers,
other instructions, every condition code, `LOOP*` and `JRCXZ` counts); the message
codec in `src/user/linux/ptrace/mod.rs`; end to end, the `ptrace` fixture traces
between parent and child in both directions, the `ptracestops` fixture covers
system-call stops and steps, the `ptraceregs` fixture the other register sets and
the queues, the `ptracejobs` fixture a seized tracee's job control, the
`ptraceevents` fixture the clone, exit, and seccomp events, and the `ptracefork`
fixture the fork, vfork, and process-clone events and the new tracee, the
`ptraceseccomp` fixture an unprivileged tracer's seccomp refusals, and the
`ptraceblock` fixture block steps and the x86-64 sets without contents

### Seccomp

`src/user/linux/tests/seccomp.rs` (10 tests, most on every 64-bit ABI): installing
in `seccomp_set_mode_filter`'s order, the eBPF-length bound, what filters see and
decide, `SECCOMP_RET_TRAP`'s `SIGSYS`, the kill actions against the number of
threads, strict mode, TSYNC, calls checked once as they enter, x86-64 `INT 0x80`
calls as i386 ones, and `TIF_NOTSC` faulting `RDTSC`; unit tests of the checks, the
conversion length, and running in `src/user/linux/seccomp/bpf.rs`, and of verdicts
and chains in `src/user/linux/seccomp/mod.rs`

## Recorded execution

### End-to-end behavior

`user_linux` `fixtures`: cases in `tests/fixtures/user/linux/cases.txt` run for
x86-64, AArch64, and RV64 against recorded stdout/exit status; additional
interpreter/JIT and short-slice runs exercise execution modes.
`oracle-overrides.txt` names translator limitations and borrowed expectations;
`expected/ORACLE` identifies the recording kernel and tools. The ignored live Docker
comparison requires `RAX_USER_DOCKER_ORACLE=1`.

### Whole programs

`user_linux` `programs`: morok cases run in five modes (x86-64 default/no-JIT,
AArch64, RV64 default/JIT) against recorded stdout/exit status. `noise.txt` defines
masked or dropped output; `known-divergences.txt` must exactly match observed
divergences. See the [corpus
reference](../../../tests/fixtures/user/linux/programs/README.md). These matrices
exclude i386; a mode name alone does not prove native admission on the current host.

## Interpretation boundary

**Differential-tested** here means that, for the fixture programs and
inputs in `tests/fixtures/user/linux` (including its `programs` corpus),
output and exit status equal what the recorded Linux kernel produced; it is
scoped to decoded stdout text and the whole-program runner's declared noise
filters, and for i386 to the fixture subset built for it. It is not a claim
about programs outside that corpus, arbitrary binary stdout, or other i386
compatibility programs.
