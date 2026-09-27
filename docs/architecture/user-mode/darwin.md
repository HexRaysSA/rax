[← User-mode emulation](../user-mode.md)

# Darwin (macOS) personality

`user::darwin` runs macOS user-space programs for x86-64 and arm64 on RAX's
software CPUs. `rax-user` selects it for a Mach-O or fat executable; the
program runs against the host's `dyld`, dyld shared cache, and system
libraries (or a guest root given with `--sysroot`), so its user space is
the host's macOS release.

```text
rax-user --arch arm64 /bin/echo hello
rax-user --arch x86_64 ./program args...
```

## Behavior references

The kernel behavior reproduced is XNU 12377.121.6
([provenance](../../specifications/darwin/xnu-12377.121.6.provenance.md)),
with dyld 1378, libpthread 539.100.4, and Libc 1752.120.2 for the user-side
contracts the kernel serves. The user space the programs run is newer
(macOS 27, kernel `xnu-13432`, unpublished). Where that kernel's published
interface extends an XNU 12377 structure, the personality follows the SDK
([macOS 27.0 SDK headers](../../specifications/darwin/MacOSX27.0.sdk.provenance.md))
and says so next to the implementation. The native kernel is the test
oracle (see [Evidence](#evidence)).

## Process construction

`DarwinProcess::spawn` does what `exec_mach_imgact` and `load_machfile` do
for a first program:

| Step | Module | XNU counterpart |
|---|---|---|
| Fat slice choice and grading (arm64e host grades on Apple silicon, x86_64h on Intel) | `user::image::macho` | `exec_fat_imgact`, `fatfile_getbestarch` |
| Segment mapping, page zero, entry point, `LC_UNIXTHREAD`/`LC_MAIN` | `user::image::macho`, `loader` | `parse_machfile`, `load_segment` |
| `dyld` mapping above the image | `loader` | `load_dylinker` |
| Stack (64 MiB `MAXSSIZ` reservation, `DFLSSIZ` limit, guard) and strings | `stack`, `loader` | `create_unix_stack`, `exec_copyout_strings` |
| `apple[]` strings (`executable_path`, entropy, `ptr_munge`, `th_port`, ...) | `loader` | `exec_add_apple_strings` |
| Commpage (x86-64 at `0x7fffffe00000`; arm64 read-only and read-write pages) | `commpage` | `commpage_populate` |
| Task and thread ports: thread `0x103`, task `0x203` | `process` | `ipc_task_enable`, `thread_self` |

Address-space layout randomization is disabled: slides are zero and `dyld`
maps the shared cache at its unslid address.

## Kernel entry

| ISA | Entry | Selector | Arguments | Error |
|---|---|---|---|---|
| x86-64 | `SYSCALL` | class in `RAX[31:24]` (1 Mach, 2 BSD, 3 machine-dependent, 4 diagnostics), number below | `RDI RSI RDX R10 R8 R9`, then the stack | `CF` set, `RAX` = errno |
| arm64 | `SVC #0x80` | `X16`: positive BSD, negative Mach trap, `0x80000000` platform call | `X0`-`X7` | `C` set, `X0` = errno |

`syscall::dispatch` routes BSD calls by number through the table generated
from `bsd/kern/syscalls.master` (`abi::tables`, `tools/darwin/gen_abi.py`),
Mach traps through the table generated from `osfmk/kern/syscall_sw.c`, and
the machine-dependent calls (thread pointers: `thread_fast_set_cthread_self64`
on x86-64, `TPIDRRO_EL0` on arm64). Results follow each call's
`sy_return_type`. A call that must sleep records a `Wait` and returns
`ERESTART`, which backs the PC up over the trap so the call runs again when
its thread wakes; all guest threads run on one host thread (one emulated
CPU, `hw.ncpu` = 1).

## Mach IPC

| Area | Module | XNU counterpart |
|---|---|---|
| Name space: names `(index << 8) \| generation`, rights and user references, dead names, port sets, dead-name and port-deleted requests | `mach::ipc` | `ipc_entry.c`, `ipc_right.c`, `ipc_object.c` |
| Messages in transit, descriptors, trailers | `mach::msg` | `ipc_kmsg.c` |
| `mach_msg2_trap` and the legacy traps: vectors, send and receive options, queue limits, timeouts, `MACH_RCV_LARGE`, pseudo-receive of failed sends | `syscall::mach::msg` | `mach_msg.c`, `ipc_mqueue.c` |
| Copy-in and copy-out of header and body rights, out-of-line memory and port arrays, guarded descriptors; no-senders, send-once, dead-name, port-destroyed, and send-possible notifications | `syscall::mach::kmsg` | `ipc_kmsg.c`, `ipc_notify.c`, `ipc_port.c` |
| `_kernelrpc_mach_port_*` traps and the `mach_port` routines | `syscall::mach::port`, `mig::port` | `mach_port.c`, `mach_kernelrpc.c` |
| Port guards: the guard is the port's context; misuse of a guarded or immovable port is a fatal `EXC_GUARD` (`SIGKILL`) | `syscall::mach::guard` | `mach_port_guard_exception` |
| Semaphores and `__semwait_signal` | `syscall::mach::sync` | `sync_sema.c`, `kern_sig.c` |

Kernel objects (task, thread, host, clock, semaphore ports) answer messages
through MIG servers (`mig`), dispatched by message ID from the table
`tools/darwin/gen_mig.py` generates from the vendored `.defs` files. The
servers check request layouts as MIG's generated code does and build the
same replies: `host` (`host_info`, statistics, clock services, kernel
version, page size), `task` (`task_info`, special and exception ports,
threads, semaphores, policies, restartable ranges, dyld registration),
`thread_act` (`thread_info`, policies, exception ports, suspension),
`mach_vm`/`vm_map` (allocation, protection, regions, reads and writes), and
`clock`.

## Threads

| Area | Module | Counterpart |
|---|---|---|
| `bsdthread_create`: a thread with its own control port, the TSD base, and libpthread's `thread_start(pthread, kport, func, arg, stack, flags)` state; QoS requests validated; `PTHREAD_START_SUSPENDED` | `syscall::bsd::pthread` | libpthread `kern_support.c` |
| `bsdthread_terminate`: the stack freed (the main thread's made inaccessible), the joiner's semaphore signalled or its ulock woken once the thread is gone, the control port dead | `syscall::bsd::pthread` | `pthread_shims.c`, `uthread_joiner_wake` |
| Cancellation: `__pthread_markcancel`, `__pthread_canceled`, `__disable_threadsignal`, and the calls that are cancellation points (`EINTR` when a cancellation is pending) | `syscall::bsd::pthread` | `kern_sig.c` |
| psynch: kernel wait queues per object address for contended mutexes (first-fit and fair-share), condition variables (signals, broadcasts, directed signals, timed waits, preposts), and read-write locks (overlapping readers, writer hand-off) | `psynch` | libpthread `kern_synch.c` |

A new thread inherits its creator's signal mask. Threads share the one
emulated CPU in round-robin time slices; a thread parked in a psynch wait
finishes its call in the operation's continuation when a waker grants it,
its timeout passes, or a signal or cancellation interrupts it, as
`ksyn_wait` and the `psynch_*continue` functions do. Queues of
`PTHREAD_PROCESS_SHARED` objects are keyed by address: sharing them with
another process is not supported.

## kqueues

| Area | Module | Counterpart |
|---|---|---|
| `kqueue`, `kevent`, `kevent64`, `kevent_qos` on kqueue descriptors: registration with receipts and errors as events, activation-order delivery, `EV_ONESHOT`, `EV_CLEAR`, `EV_DISPATCH`, deferred deletes, `EV_UDATA_SPECIFIC`, `EV_VANISHED`, timeouts, interrupted waits, one interface per kqueue | `kevent` | `kern_event.c` |
| `EVFILT_TIMER` (units, absolute, repeating counts), `EVFILT_USER` (triggers, filter-flag operations), `EVFILT_SIGNAL` (counts of process-directed signals, ignored ones included), `EVFILT_READ` on a kqueue | `kevent::filters` | `kern_event.c`, `kern_sig.c` |
| `EVFILT_MACHPORT` on receive rights and port sets, reporting the port or receiving the message into the knote's buffer or the call's data area (`MACH_RCV_MSG`) | `kevent::filters`, `syscall::mach::msg` | `ipc_pset.c` |
| Descriptor filters (`EVFILT_READ`, `EVFILT_WRITE`, `EVFILT_VNODE`, `EVFILT_EXCEPT`, ...) and `EVFILT_PROC`: carried by a host kqueue per guest kqueue on a macOS host, whose events give the data, flags, and `EV_EOF`; elsewhere reads and writes are emulated with `poll` | `kevent::host` | `kern_event.c` |

Closing a descriptor drops its knotes (or reports `EV_VANISHED` for those
that asked); closing a kqueue's last descriptor drops the kqueue.

## Signals

| Area | Module | XNU counterpart |
|---|---|---|
| Actions (`sigaction`), process-wide `sigprocmask`, per-thread `__pthread_sigmask`, `sigpending`, `sigsuspend`, `__sigwait`, `sigaltstack`, `kill`, `__pthread_kill`, `setitimer`/`getitimer` | `syscall::bsd::sig` | `kern_sig.c`, `kern_time.c` |
| Posting to a thread (the first in creation order that does not block the signal), `sigwait` hand-off, discarding ignored signals, delivery on the way back to user mode (`issignal`, `postsig`), `SA_RESETHAND`, `SA_NODEFER` | `signal` | `psignal_internal`, `bsd_ast` |
| Machine exceptions: Mach exception type, code, and subcode, then the signal (`SIGSEGV` for `KERN_INVALID_ADDRESS`, `SIGBUS` for protection failures, `SIGSEGV` on the stack guard) | `signal` | `user_trap`, `sleh.c`, `ux_exception.c` |
| Signal frames: `siginfo_t`, `ucontext_t`, and the machine context (arm64 `mcontext64`, 816 bytes; x86-64 `mcontext_avx64`, 1032 bytes), alternate stacks, and `sigreturn` with its token | `signal::frame`, `thread_state` | `unix_signal.c`, `status.c`, `fpu.c`, `pcb.c` |
| Interrupted sleeps: `EINTR`, or a restart after the handler for `SA_RESTART` (never for `select`, `poll`, `sigsuspend`, `__semwait_signal`); `MACH_RCV_INTERRUPTED`, `MACH_SEND_INTERRUPTED`, `KERN_ABORTED` | `syscall`, `syscall::mach` | `kern_synch.c`, `sys_generic.c`, `ipc_mqueue.c` |
| `SIGPIPE` for a write to a broken pipe (unless `F_SETNOSIGPIPE`) | `syscall::bsd::file` | `dofilewrite` |
| Interval timers: `ITIMER_REAL` deadlines, `ITIMER_VIRTUAL` and `ITIMER_PROF` charged per time slice | `signal::timer` | `realitexpire`, `itimerdecr`, `bsd_ast` |
| Host signals: asynchronous host signals are the guest's (`rax-user` forwards them), a stop signal's default action stops the host process, and the state inherited across `exec` (ignored signals, action flags, mask) is the host process's | `signal::host` | `execsigs` |

Pointer authentication uses RAX's identity algorithm, so the arm64 thread
state of a process with the pointer-authentication ABI carries the
kernel-signed flags, the thread's diversifier, and `sigreturn` tokens
derived from the thread's secret without a key. Rosetta, the x86-64 test
oracle, keeps an `SA_RESETHAND` action installed after the handler runs;
the personality resets it, as XNU does on an Intel Mac.

## Memory

Mach VM calls and `mmap` share one VMA map with the Mach attributes (maximum
protection, inheritance, user tag) in each VMA's personality flags
(`vm::VmFlags`). `shared_region_map_and_slide_2_np` maps the dyld shared
cache from the host's cache files; slid mappings (slide info v2 and v5) are
rebased page by page on first touch, as XNU's shared-region pager does.

## Emulated machine

One CPU of the program's architecture: a Haswell-class Intel Mac for x86-64
(`CPU_SUBTYPE_X86_64_H`; `XCR0` enables x87, SSE, and AVX state), an
Apple-silicon Mac for arm64 (`CPU_SUBTYPE_ARM64E`, `PSTATE.SSBS` set for new
threads; the implementation's pointer-authentication algorithm is the
identity), with 16 GiB of memory. Mach absolute time, uptime, and `kern.boottime` share one
clock that starts with the emulator. Process identity (pid, credentials,
audit token) is the host process's.

## Status

Single-threaded programs linked against libSystem run on both
architectures: `dyld` and libSystem initialization, file and path calls,
memory calls, `sysctl`, Mach messaging with the kernel servers above,
semaphores and sleeping, signals, POSIX threads with their mutexes,
condition variables, and read-write locks, and kqueues. Not yet implemented, and answered
with `ENOSYS` (or `KERN_FAILURE` / `MIG_BAD_ID` for Mach) with a warning
under `--strace` or `RAX_DARWIN_WARN`: work queues (`workq_open`,
`workq_kernreturn`, the work-queue kqueue of `kevent_qos`, workloops and
`kevent_id`: so `libdispatch`'s queues), `fork`/`execve`/`posix_spawn`,
sockets, `proc_info`, and exception delivery
to Mach exception ports (a machine exception becomes its signal
directly). `kill` of the process group reaches this process only through
host-signal forwarding, and `kill(-1, sig)` signals only this process.

## Evidence

`cargo test --no-default-features --features x86_64-suite,smir-jit --test user_darwin`

- `fixtures`: the C programs in `tests/fixtures/user/darwin/src` are built
  for arm64 and x86_64 and must produce the standard output and exit status
  of their native runs (x86_64 through Rosetta), including the fatal
  `EXC_GUARD` of `guard_fatal`, the handlers, frames, masks, timers,
  faults, and final `SIGTERM` of `signals`, and the thread creation,
  joins, cancellation, and contended synchronization of `threads` and
  `threads_sync`, and the filters and delivery protocol of `kqueue`.
- `programs`: `/bin/echo`, `/usr/bin/true`, `/usr/bin/false`, and `/bin/cat`
  likewise.
- `generators`: the checked-in tables equal what the generators produce
  from the vendored sources (`--check`).
- `layouts`: the signal-frame and thread-state sizes the personality uses
  equal the SDK's, measured by a probe compiled against it.

Without a macOS host (or without Rosetta, for x86_64) the comparisons have
no oracle and report themselves skipped. Library tests under
`src/user/darwin/` cover the name space, message trailers, commpage and
stack layout, slide info, sysctl nodes, the host-information flavors,
exception-to-signal translation, signal actions, interval-timer
arithmetic, the thread-state flavors, psynch sequence arithmetic and queue
order, and thread QoS requests.
