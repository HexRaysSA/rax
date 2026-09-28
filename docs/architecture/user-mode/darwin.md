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
with dyld 1378, libpthread 539.100.4, Libc 1752.120.2, libdispatch
1542.100.32, and libmalloc 812.100.31 for the user-side contracts the kernel
serves. The user space the programs run is newer
(macOS 27, kernel `xnu-13432`, unpublished). Where that kernel's published
interface extends an XNU 12377 structure, the personality follows the SDK
([macOS 27.0 SDK headers](../../specifications/darwin/MacOSX27.0.sdk.provenance.md))
and says so next to the implementation. The system calls macOS 27 adds
where XNU 12377 has none (`pipe2`, `dup3`) take the SDK's numbers and
manual pages as their contract, and the host kernel's observed behavior
where those are silent. The native kernel is the test oracle (see
[Evidence](#evidence)).

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
| Port guards: the guard is the port's context; a violation is noted on the thread (a sticky one is not replaced) and raised on its way back to user mode as `EXC_GUARD` with XNU's code (type, reason, port name) and payload. Misusing a guarded or immovable port is fatal: the exception goes to the handlers, then the task dies of `SIGKILL`. Invalid names, rights, and values are delivered only with `TASK_EXC_GUARD_MP_DELIVER` (once with `_MP_ONCE`) and kill after delivery with `_MP_FATAL`. A deferred-reclamation violation is delivered, then kills | `syscall::mach::guard`, `exception` | `mach_port_guard_exception`, `mach_port_guard_ast`, `thread_ast_mach_exception`, `exit_with_fatal_exception_and_notify` |
| Semaphores and `__semwait_signal` | `syscall::mach::sync` | `sync_sema.c`, `kern_sig.c` |
| Exception ports (`task_`, `thread_`, and `host_set`/`get`/`swap_exception_ports`, `task_`/`thread_get_exception_ports_info`): XNU's checks in order (mask, behavior, a plain port as handler, flavor of the kernel's architecture, 64-bit codes for the protected and backtrace behaviors), dead names kept, `get` merging equal actions in exception order, a thread's actions from its first `set`, the control port as target (the read port for the info variants), and the host's refused without `host_priv`; behavior 5 without `MACH_EXCEPTION_CODES` is refused (XNU takes it, then panics delivering to it) | `mach::exception`, `mig::exception` | `ipc_tt.c` (`set_exception_ports_validation`), `exception_policy.c`, `ipc_host.c`, `exception_types.h`, `thread_status.h` |
| Vouchers: `host_create_mach_voucher` (trap and routine) running recipe arrays in XNU's check order; vouchers with the same values are one port (one name in a space) while anything holds them; the managers a macOS kernel registers for one task alone (importance: the task's own element; bank: the default task value and the task's context; pthread priority, normalized; user data), extraction (`mach_voucher_extract_attr_recipe` trap and routine, `_content`, `_all_attr_recipes`) and `mach_voucher_attr_command`; a thread's voucher (`thread_get`/`_set_mach_voucher`, `bsdthread_ctl` `SET_SELF`, cleared for workqueue threads); send preprocessing and receive processing of message vouchers; the task voucher placeholders; `mach_generate_activity_id` (the host's counter on a macOS host) | `mach::voucher`, `syscall::mach::voucher`, `mig::voucher` | `ipc_voucher.c`, `ipc_importance.c`, `bank.c`, `ipc_pthread_priority.c`, `mach_kernelrpc.c`, `thread.c`, `task.c` |
| Mach timers (`mk_timer_create`, `_destroy`, `_arm`, `_arm_leeway`, `_cancel`): a receive right to a user port the kernel holds a send right to; at the deadline one 48-byte expiration message (id 0) is queued unless the last is still queued; the deadline a cancel reports carries the kernel's coalescing slop (none for a critical timer; the leeway where larger; otherwise the share of the time left the process's latency tier allows, which on a macOS host is what the host kernel gives a timer armed the same way, the process being a host process, and elsewhere tier 1's quarter, at most 5 ms) | `syscall::mach::timer` | `mk_timer.c`, `thread_call.c` (`thread_call_enter_delayed_internal`), `timer_call.c` (`timer_call_slop`), `arm_timer.c`, `i386_timer.c` |

Kernel objects (task, thread, host, clock, semaphore ports) answer messages
through MIG servers (`mig`), dispatched by message ID from the table
`tools/darwin/gen_mig.py` generates from the vendored `.defs` files. The
servers check request layouts as MIG's generated code does and build the
same replies: `host` (`host_info`, statistics, clock services, kernel
version, page size), `task` (`task_info`, special and exception ports,
threads, semaphores, policies, restartable ranges, dyld registration,
identity tokens and the task ports of each flavor they give; the read
and inspect ports, like the name port, are one port per task, made on
first use; the three registered ports of `mach_ports_register` and
`mach_ports_lookup`, send rights or dead names the kernel holds and a new
task inherits; the read and inspect ports, whose send rights may not
move, may be neither registered nor made special ports,
`KERN_INVALID_RIGHT`),
`thread_act` (`thread_info`, policies, exception ports, suspension),
`host_priv`'s special ports (refused, `KERN_INVALID_ARGUMENT`, to a caller
without the privileged host port, the right a set carries released),
`mach_vm`/`vm_map` (allocation, protection, regions, reads and writes), and
`clock`.

## Host services

The emulated process is a host process, which the system's services
(`launchd`, and the directory, preference, keychain, and notification
services it names) know by its pid, credentials, and audit token as they
would know the native program. The bridge (`bridge`) lets the guest reach
them over Mach:

| Area | Module | Counterpart |
|---|---|---|
| The bootstrap port: the host's, the task's bootstrap special port and first registered port (as `launchd` registers it); a forked or spawned child (a host fork) has the host's again, and no other proxy of its parent's | `bridge` | `ipc_task_init`, `launchd` |
| Proxies: a host send or send-once right the process holds appears in the guest as a port of its own (one per host right, so that names compare); a message the guest sends to one is sent on the host, its rights and out-of-line memory translated, the send's result the guest's (`MACH_SEND_INVALID_DEST` when the host port died); `mach_port_kobject` reports the host port's type. The host's dead-name notification kills a proxy: the guest's rights become dead names, with their notifications | `bridge::translate` | `ipc_kmsg_copyin_body`, `ipc_right_copyin` |
| Exports: a guest port whose right the guest gives a host service is a host receive right of the process's, whose messages the scheduler receives (without blocking, and in its `poll` when every thread sleeps) and queues on the guest port with their rights, memory, and sender's audit token; a send-once right in a message's reply field is made from a host reply port (`MPO_REPLY_PORT`), as services enforcing reply-port semantics require (a violation is a fatal guard exception on the host). While the host holds send rights to an export, the guest port keeps one that stands for them, released at the host's no-senders notification | `bridge`, `bridge::translate` | `ipc_validate_local_port`, `mach_port_construct` |
| Moved receive rights: a receive right the guest sends a host service is the export's (or a new host receive right), and the guest port then sends on to the host what the guest sends it or had queued on it; the right coming back makes it the guest port's again | `bridge::translate` | `ipc_right_copyin` (`MACH_MSG_TYPE_MOVE_RECEIVE`) |
| Memory entries: an entry of the guest's memory (`mach_make_memory_entry`) is a host memory entry over a host file the range becomes a shared mapping of (its contents kept; `MAP_MEM_VM_COPY` makes one of a copy, `MAP_MEM_NAMED_CREATE` one of new memory), so a service that maps it shares it; `vm_map` of such an entry maps the file shared (or a copy), and of an entry a service made maps a copy of its contents | `syscall::mach::entry`, `mig::vm` | `mach_make_memory_entry_internal`, `vm_map_enter_mem_object` |
| Policy calls (`__mac_syscall`): AMFI's dyld policy for an unrestricted process; the Sandbox policy's checks (`sandbox_check` and its variants) and container queries, the host's answers with the guest's strings, buffers, and filter blocks copied through; other calls of a registered policy `ENOTSUP`, an unregistered policy `ENOPOLICY` | `syscall::bsd::mac` | `mac_syscall` (`security/mac_base.c`) |
| `gethostuuid`: the host's UUID (`EFAULT` for the timeout, `EWOULDBLOCK` without one) | `syscall::bsd::misc` | `gethostuuid` (`sys_generic.c`) |

The Sandbox policy's argument blocks are private: their layout (the
result, the operation's name, the filter's kernel type and value, and
which types carry a string or a 16-byte block) is the host's
`libsystem_sandbox` as macOS 27.2 builds them (`sandbox_check_common`).
Not bridged: vouchers (dropped), guarded descriptors (receive rights the
guest would guard), thread ports, and other kernel objects but the task
(and its flavors) and the host, whose sends fail
`MACH_SEND_INVALID_RIGHT`. A send-once right to a moved port travels as a
send right, and a send the host must wait to queue holds the whole
process. `RAX_DARWIN_NO_HOST_SERVICES` turns the bridge off: the process
then has no bootstrap port and its registered ports are null.

## Threads

| Area | Module | Counterpart |
|---|---|---|
| `bsdthread_create`: a thread with its own control port, the TSD base, and libpthread's `thread_start(pthread, kport, func, arg, stack, flags)` state; QoS requests validated; `PTHREAD_START_SUSPENDED` | `syscall::bsd::pthread` | libpthread `kern_support.c` |
| `bsdthread_terminate`: the stack freed (the main thread's made inaccessible), the joiner's semaphore signalled or its ulock woken once the thread is gone, the control port dead | `syscall::bsd::pthread` | `pthread_shims.c`, `uthread_joiner_wake` |
| Thread state by flavor (`thread_get_state`, `thread_set_state`): the flavors a 64-bit thread has and their counts, the flavor lists, the unified states with their headers, the exception state (set: accepted and ignored on arm64, refused on x86-64), NEON, VFP, float, and AVX state (a float state clears the upper YMM halves; no AVX-512 on the emulated Haswell); the debug registers are checked, masked, and kept but not applied (the CPUs have no hardware breakpoints); the saved-state, full-state, SME, and SVE flavors are refused | `thread_status`, `mig::thread` | `status.c`, `pcb.c`, `fpu.c`, `thread_act.c` |
| Cancellation: `__pthread_markcancel`, `__pthread_canceled`, `__disable_threadsignal`, and the calls that are cancellation points (`EINTR` when a cancellation is pending) | `syscall::bsd::pthread` | `kern_sig.c` |
| psynch: kernel wait queues per object address for contended mutexes (first-fit and fair-share), condition variables (signals, broadcasts, directed signals, timed waits, preposts), and read-write locks (overlapping readers, writer hand-off) | `psynch` | libpthread `kern_synch.c` |

A new thread inherits its creator's signal mask. Threads share the one
emulated CPU in round-robin time slices; between slices the scheduler ends
the waits whose timeouts have passed or whose descriptors are ready (a
poll that does not block), so a thread that never sleeps does not keep the
others asleep. A thread parked in a psynch wait
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
| `EVFILT_MACHPORT` on receive rights and port sets, reporting the port or receiving the message into the knote's buffer or the call's data area (`MACH_RCV_MSG`): message, trailer, and auxiliary data in one piece (a message they do not fit left queued with its size, trailer excluded), from the area's start or, for `KEVENT_FLAG_STACK_DATA`, down from its end | `kevent::filters`, `syscall::mach::msg` | `ipc_pset.c` (`filt_machportprocess`), `ipc_kmsg.c` (`ipc_kmsg_put_to_user`), `ipc_mqueue.c` (`ipc_mqueue_msg_too_large`), `mach_msg.c` |
| Descriptor filters (`EVFILT_READ`, `EVFILT_WRITE`, `EVFILT_VNODE`, `EVFILT_EXCEPT`, ...) and `EVFILT_PROC`: carried by a host kqueue per guest kqueue on a macOS host, whose events give the data, flags, and `EV_EOF`; elsewhere reads and writes are emulated with `poll` | `kevent::host` | `kern_event.c` |

Closing a descriptor drops its knotes (or reports `EV_VANISHED` for those
that asked); closing a kqueue's last descriptor drops the kqueue.

## Processes

| Area | Module | Counterpart |
|---|---|---|
| `fork`: the host process forks (the child is a copy of the emulator with its guest; private memory copied on write, shared mappings shared), and the child becomes XNU's forked process: the caller's thread only, with a new thread ID and the caller's signal mask; a new task whose space holds its control port then the thread's, keeping the bootstrap, access, and host special ports, the registered ports, and the exception actions; descriptors without kqueues (`FG_CONFINED`) or close-on-fork descriptors; no pending signals, interval timers, alternate stack, work queue, psynch, or kqueue state, and not `SA_NOCLDSTOP` or `SA_NOCLDWAIT` (process flags; the actions stay); `VM_INHERIT_NONE` regions unmapped. The child's call returns its own pid with 1 in the second return register | `fork` | `kern_fork.c`, `ipc_task_init`, `fdt_fork`, `thread_set_child` |
| `execve`: the path saved and looked up (following links; `ENAMETOOLONG`, `EFAULT`, `ENOENT`, `ENOTDIR`), the permission checks (a regular file with an execute bit, `EACCES`; not empty, `ENOEXEC`), then the activators in XNU's order at most three times: a thin Mach-O executable graded for the machine (`EBADARCH` for another CPU, a 32-bit or reverse-endian image; another file type is not claimed), a fat file's slice (`EBADMACHO` for a bad table), a `#!` script (the first 512 bytes: the interpreter and its words, `ENOEXEC` without one or without an end of line, and no script as interpreter); nothing claimed is `ENOEXEC`. The arguments and environment are then copied within `NCARGS` (`E2BIG`, `EFAULT`; a NULL vector is empty; a script's `argv` is the interpreter's words, the path, and the caller's `argv` less its first) | `exec`, `exec::image`, `exec::args` | `exec_activate_image`, `exec_mach_imgact`, `exec_fat_imgact`, `exec_shell_imgact`, `exec_extract_strings` |
| The new image: past the point of no return a new process image is built (a failure to load it kills the process with `SIGKILL`) and replaces the old when the call returns. It keeps the pid, parent, credentials, working directory, file-creation mask, limits, children, start time, interval timers, the descriptors less close-on-exec ones and kqueues, the caller's signal mask and pending signals, ignored signals, and the task's inherited special ports and exception actions; caught signals return to their defaults, and the alternate stack, `SA_ONSTACK`, `sigreturn` validation, `SA_NOCLDSTOP`/`SA_NOCLDWAIT`, other threads, the address space, port names, and the guard-exception behavior are new. Thread and task ports are again `0x103` and `0x203` | `exec`, `process` | `proc_exec_switch_task`, `execsigs`, `fdt_exec`, `ipc_task_init`, `proc_inherit_itimers` |
| `posix_spawn`: the argument descriptor and attribute layouts (`EINVAL` for file- or port-action sizes that disagree with their counts), file actions in order on the child's descriptor table (`OPEN` at the lowest descriptor then moved, `CLOSE`, `DUP2` clearing close-on-exec, `INHERIT`, `CHDIR`, and `FCHDIR` of the caller's descriptor; the first failure fails the spawn), `POSIX_SPAWN_CLOEXEC_DEFAULT`, port actions (special ports, exception handlers, and registered ports of the new task, a dead name kept dead; `EINVAL` for bad names or kinds, and for a right that may not be stashed), `RESETIDS`, binary preferences (`EBADARCH`, and `EBADEXEC` when four preferences all miss a fat file), then the child's process group and session, signal mask, and default actions; the child, as a forked one, has no close-on-fork descriptors; `POSIX_SPAWN_SETEXEC` runs the image in the caller (keeping them); `POSIX_SPAWN_START_SUSPENDED` stops the child before it runs. A failed spawn writes no pid, leaves no child, and sends no `SIGCHLD` | `exec::spawn` | `posix_spawn`, `exec_handle_file_actions`, `exec_handle_port_actions` |
| `task_read_for_pid` and `task_inspect_for_pid`: the caller's own task port of that flavor; another process's refused (`EPERM`, as for pid 0; `ESRCH` for none) and a target that is not the caller's task control port refused (`EINVAL`), with a null name written back | `syscall::bsd::proc` | `task_read_for_pid`, `task_inspect_for_pid` (`kern_proc.c`) |
| `waitid`: options (`EINVAL` for none or unknown ones) and id types, `WNOWAIT`, `WNOHANG` leaving the `siginfo_t` untouched, and the `siginfo_t` of an exit (the status), a signal death, a stop (the signal), and a continue (`SIGCONT`, the child's pid) | `syscall::bsd::wait` | `waitid_nocancel` |
| `wait4`: the host's wait for the guest's children (host processes), XNU's status encoding (a continue is `W_STOPCODE(SIGCONT)`), `struct rusage`, `WNOHANG`, sleeping until a child changes state with signal interruption, and the pending `SIGCHLD` cleared when the last child is reaped with `SIGCHLD` blocked | `syscall::bsd::wait` | `wait4_nocancel` |
| `SIGCHLD`: the host's `SIGCHLD` wakes waiters and becomes the guest's with the child's pid, user, code, and status; `SA_NOCLDSTOP` suppresses it for stops, a process that ignores `SIGCHLD` or sets `SA_NOCLDWAIT` leaves no zombies and gets no signal for exits, and continues send none | `signal`, `signal::host` | `proc_exit`, `psignal_internal` |

A guest killed by a signal whose default action dumps core makes
`rax-user` exit with status 128 + N rather than die by the signal (so the
host records no crash of the emulator); a parent waiting for such a child
sees an exit.

An exec happens inside the emulator: the host process keeps running
`rax-user`, which swaps in the new guest image. Everything that can fail
before XNU's point of no return is checked first, including a spawn's
file actions, which work on a copy of the caller's descriptor table with a
directory descriptor for a changed working directory, and the new image
is built in the caller. So a failed spawn (`posix_spawnp` tries each
`PATH` entry) forks nothing, and the host fork carries a finished image
into the child. In a spawned child, the old image's host-service bridge
is transferred to the new image before rebinding: the inherited kqueue
descriptor is not valid after the host fork, so rebinding forgets it
before the old image is dropped. Setting a spawned child's process group
or session can still fail in the child; the child then reports the error
through a pipe, the caller reaps it, and the host's `SIGCHLD` for it is
dropped. The machine an image runs on follows the caller: an arm64 process
may exec x86-64 images as well as arm64 ones (translated, as by Rosetta,
which runs x86_64 slices but refuses x86_64h ones with `EBADARCH`; a fat file
without an arm64 slice runs its x86_64 one), and an x86-64 process only
x86-64 ones (preferring x86_64h). The slice activation chooses is the one
loaded.

Host-level effects of a native exec are not reproduced. The host sees
`rax-user` throughout, so a watcher of the host process gets no
`NOTE_EXEC`, and `setpgid` on a child that has exec'd is not refused. A
start-suspended child is stopped with `SIGSTOP` (as any stop is, with host
job control), so its parent may get a `CLD_STOPPED` `SIGCHLD` and a stop
status that XNU's suspended child does not produce. A child stopped by `SIGTSTP`, `SIGTTIN`, or `SIGTTOU` stops
the host with `SIGSTOP` and is reported so. An exit status keeps only its
low eight bits. Port actions set the new task's ports, but no Mach message
crosses to another emulated process. Persona and credential attributes
(`EPERM`), coalitions (`EPERM`), and fileports (`EINVAL`) are refused as
for an unprivileged, unentitled caller.

## Work queues

| Area | Module | Counterpart |
|---|---|---|
| `workq_open` and `workq_kernreturn`: dispatch configuration (`WQOPS_SETUP_DISPATCH`, `WQOPS_QUEUE_NEWSPISUPP`), thread requests (`WQOPS_QUEUE_REQTHREADS`, the cooperative `WQOPS_QUEUE_REQTHREADS2`), the event manager's priority, `WQOPS_SHOULD_NARROW`, and a thread's return (`WQOPS_THREAD_RETURN`, and the kevent and workloop returns that first hand back pending changes) | `workq` | `pthread_workqueue.c` |
| Admission by pool: overcommit requests always, the event manager one thread at a time, constrained requests while fewer active threads than CPUs run at or above their QoS (at most 64 scheduled), the cooperative pool while it has room; the manager's request first, then QoS | `workq` | `workq_threadreq_select`, `workq_constrained_allowance`, `workq_cooperative_allowance` |
| Workqueue threads: a kernel-allocated stack (guard page, 512 KiB, the `pthread_t` above, 12 KiB into its last page on arm64), a pinned thread port, the TSD base, the `workq_threadmask` signal mask (reset on return), and `_pthread_wqthread(self, kport, stacklowaddr, keventlist, flags, nkevents)` with the upcall flags; idle threads park and are reused | `workq` | `workq_setup_thread`, `workq_set_register_state`, `workq_thread_return` |
| The workqueue kqueue (`kevent_qos` with `KEVENT_FLAG_WORKQ`): knotes queued by QoS in seven buckets (the last the event manager's, for knotes without a QoS), each bucket's thread request, and its servicer receiving that bucket's events and data on its stack | `kevent::workq`, `kevent::call` | `kqworkq_*`, `kevent_workq_internal` |
| Workloops (`kevent_id`): made by ID on first use and freed with their last reference, one thread request made when an event arrives with neither a servicer nor an owner, the servicer's events with the workloop's ID below them, rebinding or unbinding as the servicer parks | `kevent::workq`, `kevent::call` | `kqworkloop_*`, `kevent_id` |
| `EVFILT_WORKLOOP`: the thread request, synchronous waiters (`NOTE_WL_SYNC_WAIT` sleeps in `kevent_id` until a `NOTE_WL_SYNC_WAKE` or a delete, or a signal: `EINTR` in the event), ownership (`NOTE_WL_DISCOVER_OWNER`, `NOTE_WL_END_OWNERSHIP`), and the debounce check (`ESTALE`, `NOTE_WL_IGNORE_ESTALE`) | `kevent::workloop` | `filt_wl*` |
| `bsdthread_ctl`: `BSDTHREAD_CTL_SET_SELF` (kevent unbind, QoS with pool moves for workqueue threads, voucher, scheduling policy), QoS overrides, `BSDTHREAD_CTL_QOS_MAX_PARALLELISM`, `BSDTHREAD_CTL_WORKQ_ALLOW_KILL` and `_ALLOW_SIGMASK` (and `__pthread_kill`'s `ENOTSUP` for workqueue threads without them), `BSDTHREAD_CTL_DISPATCH_APPLY_ATTR` | `syscall::bsd::workq` | `bsdthread_ctl` |
| Priority encoding: QoS classes, relative priorities, normalization and combination of `pthread_priority_t` | `workq::priority` | `priority_private.h`, `pthread_priority.c` |

One host thread runs every guest thread, so the kernel's creator thread,
thread calls, and scheduler callbacks become the scheduler's work between
time slices: it fires the timers and takes the host events of the
workqueue kqueue and the workloops (which no thread waits in), binds
admitted requests to idle or new threads, and a bound thread performs its
unpark continuation (`workq_setup_and_run`, collecting its kqueue's
events) in its own context when it next runs. A thread counts as active
unless it sleeps; the kernel's 200 µs stall window, turnstile priority
pushes, QoS overrides of servicers, and the return-to-kernel notification
are not modeled (they change timing, not results). Idle threads are kept
rather than reaped after five seconds. `kqueue_workloop_ctl` (workloops
with scheduling parameters or bound threads) and sync IPC links to special
reply ports (`NOTE_WL_SYNC_IPC` attaches fail with `ENOENT`, as they do for
ports outside an IPC chain) are not provided.

On an x86_64 kernel `PTHREAD_T_OFFSET` is 0; Rosetta's x86_64 processes run
on an arm64 kernel, whose workqueue stacks carry the 12 KiB offset.

## Signals

| Area | Module | XNU counterpart |
|---|---|---|
| Actions (`sigaction`), process-wide `sigprocmask`, per-thread `__pthread_sigmask`, `sigpending`, `sigsuspend`, `__sigwait`, `sigaltstack`, `kill`, `__pthread_kill`, `setitimer`/`getitimer` | `syscall::bsd::sig` | `kern_sig.c`, `kern_time.c` |
| Posting to a thread (the first in creation order that does not block the signal), `sigwait` hand-off, discarding ignored signals, delivery on the way back to user mode (`issignal`, `postsig`), `SA_RESETHAND`, `SA_NODEFER` | `signal` | `psignal_internal`, `bsd_ast` |
| Machine exceptions: Mach exception type and codes (arm64: a breakpoint's PC, an undefined instruction's word; x86-64: `INT3` a trap, `EXC_I386_BPT` with the state past it), and an invalid Mach trap's `EXC_SYSCALL` (the trap number alone on arm64, `RAX` and 1 on x86-64); a `BRK` of 0xB000-0xBFFF kills the process with no message or signal | `exception`, `signal` | `user_trap`, `sleh.c`, `mach_syscall`, `mach_call_munger64` |
| Exception delivery: the thread's handler, then the task's, then the host's (`ux_handler`: the signal, with `SIGSEGV` for `KERN_INVALID_ADDRESS`, `SIGBUS` for protection failures, `SIGSEGV` on the stack guard). A handler gets its behavior's request (`exception_raise`, `_state`, `_state_identity`, and their 64-bit-code `mach_exc` forms, with the thread's and task's control ports and the flavor's full state; the protected behaviors' `mach_exception_raise_identity_protected` and `_state_identity_protected`, with the thread's ID and a new task identity token), and the thread waits for the reply, which neither a signal nor `thread_abort_safely` ends, on a port of its own; the reply is checked as MIG checks it, and one that takes the exception resumes the thread with the state it returns. A refusal, a reply that fails its checks or whose state cannot be installed, a destroyed reply right, a dead handler, or a flavor the thread cannot report passes the exception to the next level. Guard violations are delivered the same way, before the kill a fatal one ends in | `exception` | `exception_triage`, `exception_deliver`, `mach_msg_rpc_from_kernel`, `exc.defs`, `mach_exc.defs`, `ux_exception.c` |
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

POSIX shared memory objects (`shm_open`, `shm_unlink`) are the host's, shared
by name with every other process: the host checks names, flags, and
permissions and fixes an object's size at its first `ftruncate`. Their
descriptors are close-on-exec, and whether undocumented `shm_open` flags are
refused follows the guest program's SDK (26.4 or later refuses them), not the
emulator's. A mapping must be shared and lie within the object's size
(`EINVAL`), and may write only through a writable descriptor (`EPERM`); the
host maps the object no further than its end, and each mapping's object has
an identity of its own, since the host reports none for these objects.

Deferred reclamation (`mach_vm_deferred_reclamation_buffer_allocate`,
`_flush`, `_resize`, `_query`, and the accounting trap): libmalloc's xzone
allocator (arm64) keeps a ring of freed regions shared with the kernel, which
the emulator reclaims as XNU does. The ring is guest memory (tag
`VM_MEMORY_VM_RECLAIM`, read-write, inherited by a forked child, gone after an
exec, one per task); userspace enters regions and moves `tail`, the kernel
reclaims from the head in chunks of 16, advancing `head` and `busy` in the
ring and taking slots modulo its own copy of the length. A deallocated
region is unmapped (a hole anywhere in it reclaims nothing, the ring stays
where it was, and the task dies only with `TASK_EXC_GUARD_VM_FATAL`); a freed
one keeps its mapping and contents. A fault on the ring, a corrupted index,
or an unknown action kills the task (`SIGKILL`, a virtual-memory guard
exception). The accounting trap samples the ring at most every 10 s of the
guest clock and trims its oldest entries when an idle minimum persists, as
the kernel does without memory pressure, against the task's peak resident
size as seen at the samples. The ring's mapping is not permanent: a program
that unmaps it frees the addresses, where XNU keeps an inaccessible region.

## Files and volumes

Paths resolve through the root overlay (`vfs`) and the host performs the
calls; results in guest layouts come from the host's.

| Area | Module | Counterpart |
|---|---|---|
| Descriptor flags: close-on-exec and close-on-fork (`O_CLOFORK`, `FD_CLOFORK`, `F_DUPFD_CLOFORK`) as `open`, `fcntl`, `kqueue` (both), and macOS 27's `pipe2` and `dup3` set them and `proc_pidfdinfo` reports them; a new process drops close-on-fork descriptors, a new image close-on-exec ones. `pipe2` takes `O_CLOEXEC`, `O_CLOFORK`, and `O_NONBLOCK` for both ends and `dup3` the first two (`EINVAL` for others, checked first; `dup3` then refuses one descriptor for both, `EINVAL`, before `EBADF`). A kqueue's status flags are kept, and setting them fails (`ENOTTY`, the kqueue refusing `FIONBIO`) once they are set | `syscall::bsd::file`, `fd`, `exec` | `fdt_fork`, `fdt_exec`, `fcntl_nocancel` (`F_SETFL`), `pipe(2)`, `dup(2)`, `fcntl(2)` |
| Opens check their flags before the path: where the guest's path or directory cannot be resolved, the host is handed a path that faults, so the error it reports first (`EINVAL` for both access modes or `O_EXEC` with one) is the call's | `syscall::bsd::path` | `open1`, `openat_internal` |
| Data-protection opens: `open_dprotected_np` and `openat_dprotected_np` (and `openat_authenticated_np` through it), the host's, which keeps the class a file is created in and makes the checks: authentication only by `openat_dprotected_np` and never with `O_CREAT`, raw and authenticated opens read-only, and the authenticating descriptor a file's (`EBADF`, `ENOTSUP`) before the path is read | `syscall::bsd::path` | `open_dprotected_np`, `openat_dprotected_np`, `openat_dprotected_internal`, `vnode_getfromfd` |
| Volume statistics: `statfs64`, `fstatfs64`, and `getfsstat64` (the count of mounted volumes with a NULL buffer, of those copied with a buffer too small for them all) | `syscall::bsd::path`, `syscall::bsd::file` | `statfs64`, `getfsstat64` |
| `fsgetpath` and `fsgetpath_ext`: the path of an object by volume and object ID, the root overlay's prefix removed (`EINVAL` for unknown options or a size of 0 or over `MAXLONGPATHLEN`, `EFAULT` for the volume ID) | `syscall::bsd::path` | `fsgetpath_extended` |
| Extended attributes: `getxattr`, `setxattr`, `removexattr`, `listxattr` and their descriptor forms, the host's attributes with the guest's memory copied in XNU's order (an option the call does not take, then the path before `getxattr`'s and `listxattr`'s name or buffer; the name, its protection, and the value's size before `setxattr`'s and `removexattr`'s path), lengths for a NULL buffer (and for a size of 0 except through `getxattr`), resource forks read at an offset | `syscall::bsd::xattr` | `getxattr`, `fgetxattr`, `setxattr`, `listxattr`, `xattr_protected` |
| Access control lists: the `*_extended` calls set a list (`chmod_extended`, `fchmod_extended`, and at creation `open_extended`, `mkdir_extended`, `mkfifo_extended`; 1 removes it) or read it with the status (`stat64_extended`, `lstat64_extended`, `fstat64_extended`: the list's size written back, the list copied only into a buffer that holds it); a list is copied in before the path is looked up (`EINVAL` for a bad magic number or more than 128 entries); `umask_extended` is `umask` | `syscall::bsd::acl` | `kauth_copyinfilesec`, `fstatat_internal`, `chmod_extended_init` |
| Attribute lists and clones: `getattrlistbulk` (records copied out up to the last one the host wrote, the directory offset the host's), `setattrlist`, `fsetattrlist`, `setattrlistat`, `clonefileat`, `fclonefileat`, `exchangedata`, and `access_extended`, the host's, with the guest's memory given to it in XNU's order: a path or buffer the guest cannot supply is given as memory the host cannot read (or a path too long), so a failed lookup is still reported before a bad attribute list | `syscall::bsd::attr` | `getattrlistbulk`, `setattrlist_internal`, `clonefileat`, `access_extended` |

## Sockets

| Area | Module | Counterpart |
|---|---|---|
| Making sockets: `socket` (a descriptor first, so a full table is `EMFILE` before the protocol is looked up), `socketpair` (the protocol first; a fault storing the pair frees both), `socket_delegate`; lookup (`EBADF` without a descriptor, `ENOTSOCK` for another file) | `syscall::bsd::socket` | `socket_common`, `socketpair`, `file_socket` |
| Addresses: `bind` (`EDESTADDRREQ` without one), `connect`, `connectx` and the send calls copy an address as XNU does (`ENAMETOOLONG` past 255 bytes; up to `sockaddr_storage`, `EINVAL` for none or one shorter than its family, then `EFAULT`); `getsockname` reads the length first, `getpeername` after its `EINVAL` and `ENOTCONN` checks; `accept`, `recvfrom`, `recvmsg`, and `recvmsg_x` copy an address cut to the caller's length and report the whole length, each with XNU's rule for a fault | `socket::conn`, `socket::io` | `getsockaddr`, `getsockaddr_s`, `copyout_sa`, `accept_nocancel` |
| Connections: `listen`, `accept` (a blocking socket sleeps until a connection is queued; the new socket has the listening one's non-blocking and asynchronous modes; a fault writing the length leaves the descriptor open), `connect` and `connectx` (a blocking socket waits for the outcome; a signal ends the wait with `EINTR`, never a restart; the connection goes on, and another `connect` reports `EISCONN`, or `EALREADY` without blocking), `disconnectx`, `peeloff` (nothing, 0), `shutdown` | `socket::conn` | `accept_nocancel`, `connectit`, `connectitx`, `soshutdown` |
| Data: `sendto`, `sendmsg`, `recvfrom`, `recvmsg`, and `read`, `write`, `readv`, `writev` on a socket, with the checks made before the descriptor (`MSG_SKIPCFIL`, the header and its scatter-gather list); a blocking socket sends in pieces as room appears and receives when data arrives, each wait bounded by `SO_SNDTIMEO` or `SO_RCVTIMEO` (what was moved, or `EAGAIN`, when one passes; `MSG_DONTWAIT` does not stop a send from waiting), `MSG_WAITALL` gathering a stream's whole request; the flags a receive was given come back in `msg_flags` | `socket::io` | `sendit`, `recvit`, `sosend`, `soreceive` |
| `sendmsg_x` and `recvmsg_x`: arrays of `msghdr_x`, the host's, with the guest's memory given to it so that faults and bad counts stop the call at the same message | `socket::msgx` | `sendmsg_x`, `recvmsg_x` |
| `SIGPIPE` for `EPIPE` from a send or a write, to the process, unless the socket has `SO_NOSIGPIPE` (or `F_SETNOSIGPIPE`) or the send `MSG_NOSIGNAL` | `socket` | `sendit`, `soo_write` |
| Descriptors in `SCM_RIGHTS`: sent, the guest's become the host's (in the host's order of checks: `EBADF` for one not open, `EINVAL` for one that cannot be sent, such as a kqueue); received, each is installed at the lowest free descriptor without close-on-exec, whether or not the caller's buffer can report it (as XNU leaves them), control data cut at the caller's buffer with `MSG_CTRUNC`, and `EMSGSIZE` when the table cannot hold them | `socket::control` | `unp_internalize`, `unp_externalize`, `copyout_control` |
| Options (`setsockopt`: a NULL value with a size faults first; `getsockopt`: the size read only with a value buffer, the value cut to it) and `ioctl`: those whose argument points at more memory (`SIOCGIFCONF`, `SIOCGIFMEDIA`, `SIOCGIFXMEDIA`, `SIOCGDRVSPEC`, `SIOCSDRVSPEC`, `SIOCIFGCLONERS`) get the emulator's buffers; `FIOGETOWN` copies nothing out | `socket::opt`, `socket::ioctl` | `sosetoptlock`, `sogetoptlock`, `ioctl`, `ifconf` |

A guest socket is a host socket, so the host kernel implements the
protocols and the state other processes share (on a macOS host; elsewhere
the socket calls are `ENOSYS`). A call that would block is made to the
host without blocking (`MSG_NBIO`; for `accept`, `connect`, and
`connectx`, whose calls have no such flag, the socket is made
non-blocking for the call, which another process sharing it could see),
and the calling thread sleeps on the socket's readiness while other guest
threads run. What the host says of a peer process (`LOCAL_PEERPID`,
`LOCAL_PEERCRED`, `LOCAL_PEERTOKEN`) is of the host process, which for an
emulated peer is its own identity; its executable's UUID
(`LOCAL_PEERUUID`) is the emulator's. A receive whose buffer cannot be
written fails before the data is taken (XNU takes a datagram's sender
first). When the descriptors a message carries do not fit the table, the
message's data is lost with them, where XNU keeps the data queued.
`AF_UNIX` addresses are host paths (the root overlay does not apply to
them). The private socket `ioctl` requests whose arguments hold pointers
(the association, connection, agent, and protocol lists, `SIOCRSLVMULTI`,
the old `OSIOCGIFCONF`) are refused with `EOPNOTSUPP`, and
`SIOCIFCREATE2` (whose parameters are the interface cloner's) with
`EPERM`, or `EOPNOTSUPP` for the superuser.

## Process information

| Area | Module | Counterpart |
|---|---|---|
| `proc_info` and `proc_info_extended_id` about another process: the host kernel's answer (the guest's processes are host processes), with its checks in XNU's order; the host writes into a copy of the guest's buffer, so bytes it leaves alone stay as they were | `syscall::bsd::procinfo` | `proc_info_internal` |
| `PROC_INFO_CALL_PIDINFO` about the calling process: the flavor and size checks (`EINVAL`, `ENOMEM`, `EOVERFLOW` for a path buffer over 4096 bytes) and the identifier checks of `proc_info_extended_id` (`ESRCH`), then the emulated process: its names (the executed path's last component), `PROC_FLAG_EXEC`, and descriptor-table size in the process record (the session, terminal, start time, and unique identifiers the host's); the executable's UUID, CPU type, and platform; the task's memory, CPU times in Mach units, counters, and threads; thread records by TSD base or identifier with the thread's name and run state, and the thread lists; memory regions and the files mapped; the working directory; the executable's path (the whole buffer written, 0 returned); descriptors and their types; knote user data; workloop identifiers; the work queue's threads (`ESRCH` before it exists) | `procinfo::pidinfo` | `proc_pidinfo` |
| `PROC_INFO_CALL_PIDFDINFO` about the calling process's descriptors (`EBADF` for none, the flavor's error for another type): a file, pipe, or shared memory object is the host's record of the host descriptor with the descriptor's status the guest's (close-on-exec; shared when another guest descriptor, or as the host says another process, holds the open file); a kqueue is the emulated kqueue's state, pending events, event size, and knotes; descriptor -1 names the work queue's kqueue | `procinfo::fdinfo` | `proc_pidfdinfo`, `fill_kqueueinfo`, `pid_kqueue_extinfo` |
| The calling process's controls: a thread's name (`PROC_SELFSET_THREADNAME`, at most 63 characters, `ENAMETOOLONG`; the name Mach `thread_info` reports too), the other controls the host's; dyld's image-information registration (`TASK_DYLD_INFO`: final once a registration replaces another, `EINVAL` after); resource usage the host's with the executable's UUID (a whole record whatever the buffer size); its fileports (none) and workloops (`PIDDYNKQUEUEINFO`) | `procinfo::selfctl` | `proc_setcontrol`, `proc_set_dyld_images`, `task_set_dyld_info` |

Paths are the kernel's names for the files (`vn_getpath`): symbolic
links resolved, the root overlay's prefix removed, and laid out as
`vn_getpath` leaves them, the path at the start of its field and the copy
it was built as at the end. An image and a mapped file are named when
they are mapped.

Another emulated process is a host process running `rax-user`, so what
the host says of it beyond its identity, credentials, status, and
resource usage (its name and path, descriptors, memory, and threads) is
the emulator's. A region's share mode and shared flag follow the kind of
mapping rather than the reference counts of its memory objects: two parts
of one private mapping split by `munmap`, or a region copied by `fork`, are
reported as private, and a shared mapping is shared before any fork. A
descriptor whose file the guest has mapped is reported as shared (the
mapping holds a duplicate of the host descriptor). dyld does not move to
its copy in the shared cache (the kernel maps the shared region at exec,
the emulator when dyld asks, so dyld finds none), so it makes no
registration of its own and the registration the loader records stays
open, where a native arm64 process's is final. A thread's CPU usage,
flags, and sleep time are 0 and its priority the default (31);
`kqueue_dyninfo`'s servicing state is 0.

## Emulated machine

One CPU of the program's architecture: a Haswell-class Intel Mac for x86-64
(`CPU_SUBTYPE_X86_64_H`; `XCR0` enables x87, SSE, and AVX state), an
Apple-silicon Mac for arm64 (`CPU_SUBTYPE_ARM64E`, `PSTATE.SSBS` set for new
threads; the implementation's pointer-authentication algorithm is the
identity; data addresses ignore their top byte, instruction addresses do
not, as XNU's `TCR_EL1` sets `TBI0` and `TBID0`, so a fault reports the
tagged address and a branch to one faults), with 16 GiB of memory.

`sysctl` (`syscall::bsd::sysctl`, after `kern_newsysctl.c` and
`kern_mib.c`): the `hw` and `machdep` subtrees describe the emulated
machine (one CPU at one performance level, its caches and no L3 cache, its
`hw.optional` features and capability bits, its memory and page size)
under the OIDs, kinds, formats, and descriptions of the arm64 kernel the
host runs (`docs/specifications/darwin/macos-27.2-26B5091g/`, turned into
a table by `tools/darwin/gen_sysctl.py`); an x86-64 guest sees the Intel
kernel's `hw` nodes (the arm64-only ones removed, the frequencies and x86
capabilities present) and its `machdep` subtree (`bsd/dev/i386/sysctl.c`,
numbered in declaration order): the CPU description `cpuid.c` derives from
the emulated CPU's `CPUID` (the cache nodes, which that `CPUID` does not
describe, report the machine's cache profile), the TSC and nanotime
parameters of the commpage, and the interrupt vectors; the kernel's own
statistics and controls there are not modeled. Each value is copied out
as its kernel handler does it (an exact copy, or `sysctl_io_number`, which
gives a 32-bit buffer a 64-bit value that fits); the platform's identity
and configuration (model, target, brand string) are the host's on arm64.
The other subtrees are the host's, answered with the guest's buffer, except
the boot time, the stack top, the argument limit, the process name, and a
few constants the emulation decides. The metadata nodes (`sysctl.name`,
`.next`, `.name2oid`, `.oidfmt`, `.oiddescr`) cover both, `next` merging
the two walks. Writes are refused (`EPERM`) once the node is found.

Mach absolute time, uptime, and `kern.boottime` share one
clock that starts with the emulator. Process identity (pid, credentials,
audit token) is the host process's, and so are its persona (`persona`,
the host's operations with the guest's buffers copied through: none for a
process started without one, `ESRCH`) and its audit state: `getauid`,
`getaudit_addr`, `auditon`, and the privileged `setauid`,
`setaudit_addr`, `audit`, and `auditctl` are the host's, with the guest's
memory given to them in XNU's order (lengths and privilege before a
buffer is read, a buffer the guest cannot supply as memory the host
cannot read, and a query whose result cannot be written back failing
with `ENOSYS`, as `auditon`'s copy-out does). A thread's assumed identity
(`settid`, `settid_with_pid`: privileged, `EPERM` otherwise) is what
`gettid` reports (`ESRCH` without one); the host still checks access with
the process's. The System Integrity Protection configuration `csrctl` reports and checks against is the host's on a macOS
host (none of its exceptions elsewhere), with the Intel rule that device
configuration needs a configuration boot on x86-64; `crossarch_trap`
offers no service (`ENOTSUP`, `EINVAL` for an unknown namespace).

## Status

Single-threaded programs linked against libSystem run on both
architectures: `dyld` and libSystem initialization, file and path calls,
memory calls, `sysctl`, Mach messaging with the kernel servers above,
semaphores and sleeping, signals, POSIX threads with their mutexes,
condition variables, and read-write locks, kqueues, and work queues with
their kqueue and workloops (so `libdispatch`: global and serial queues,
groups, semaphores, `dispatch_apply`, `dispatch_after`, barriers, and
timer, read, and signal sources), `fork` with `wait4`, `waitid`, and
`SIGCHLD`, `execve` and `posix_spawn` (scripts, fat files, file and
port actions, spawn attributes), process information (`proc_info`),
sockets, and the host's services over the bootstrap port (so user and
group lookups, preferences, the keychain list, and notifications: `id`,
`whoami`, `defaults`, and `security` behave as natively).
Not yet implemented, and answered
with `ENOSYS` (or `KERN_FAILURE` / `MIG_BAD_ID` for Mach) with a warning
under `--strace` or `RAX_DARWIN_WARN`: `kqueue_workloop_ctl`. `kill` of the process group reaches this process only through
host-signal forwarding, and `kill(-1, sig)` signals only this process.

## Evidence

`cargo test --no-default-features --features x86_64-suite,smir-jit --test user_darwin`

- `fixtures`: the C programs in `tests/fixtures/user/darwin/src` are built
  for arm64 and x86_64 and must produce the standard output and exit status
  of their native runs (x86_64 through Rosetta), including the fatal
  `EXC_GUARD` of `guard_fatal`, the handlers, frames, masks, timers,
  faults, and final `SIGTERM` of `signals`, and the thread creation,
  joins, cancellation, and contended synchronization of `threads` and
  `threads_sync`, the filters and delivery protocol of `kqueue`, the
  workqueue and workloop calls, errors, servicers, synchronous waiters,
  and ownership of `workq` (driven through libpthread's SPI and the raw
  calls), libdispatch's queues and sources in `dispatch`, the
  inheritance, statuses, and `SIGCHLD` of `fork`, every `execve`
  refusal, the `SIGKILL` past the point of no return, scripts, and the
  state a new image keeps in `exec`, an arm64 process running the x86_64
  build (thin, and fat beside x86_64h slices) in `exec_translated`, the
  file actions, attributes, port
  actions, failures, and `waitid` views of `spawn` (with a short
  single-child bridge-ownership regression), the SIP queries of
  `csr`, the volume statistics and object paths of `volumes`, the
  per-thread identity and persona calls of `identity`, the POSIX shared memory
  objects of `shm` (shared between mappings and with a forked child), the
  extended attributes of `xattr`, the access control lists of `acl`, the
  process, task, thread, descriptor, region, and control queries of
  `procinfo`, and the calls, errors, blocking, signals, and passed
  descriptors of `sockets`, the attribute lists, clones, and access tables
  of `attrs`, the deferred-reclamation ring of `reclaim`
  (libmalloc's, and a ring of the fixture's own in a process libmalloc gives
  none), the identity tokens, requests, replies, levels, codes, and
  fallen-through signals of `mach_exc` (the failure paths, protected
  behaviors, and guard exceptions, which Rosetta handles differently, on
  arm64 only), and the metadata, copy-out rules, lookups, and walks of
  `sysctl` (the `machdep` subtree, which Rosetta shows as the arm64
  kernel's, on arm64 only), the flavored task ports, `task_read_for_pid`
  and `task_inspect_for_pid`, and the host's special ports in
  `mach_info`, the audit identity, copy rules, and refusals of `audit`,
  the protection classes, checks, and authentication of
  `protected_open`, the stash, rights, refusals, and inheritance of
  `registered_ports`, the descriptor flags and their inheritance in
  `fd_flags`, and the bootstrap lookups, directory service, notifications,
  Sandbox checks, memory entries, and host UUID of `host_services` (in the
  parent and its forked and spawned children).
- `programs`: `/bin/echo`, `/usr/bin/true`, `/usr/bin/false`, and `/bin/cat`
  likewise, `/usr/bin/env` running a program (and failing to), and
  `/bin/sh -c` with external commands, a command substitution, and an exit
  status (`/bin/sh` itself execs the shell it stands for).
- `generators`: the checked-in tables equal what the generators produce
  from the vendored sources (`--check`).
- `layouts`: the signal-frame and thread-state sizes the personality uses
  equal the SDK's, measured by a probe compiled against it.

Without a macOS host (or without Rosetta, for x86_64) the comparisons have
no oracle and report themselves skipped. Library tests under
`src/user/darwin/` cover the name space, message trailers, commpage and
stack layout, slide info, sysctl walks, values, and copy-out, the
host-information flavors,
exception-to-signal translation, exception requests and reply checks,
signal actions, interval-timer
arithmetic, the thread-state flavors, psynch sequence arithmetic and queue
order, thread QoS requests, the pthread priority encoding, work-queue
admission and request selection, interpreter-line parsing, fat and thin
grading with binary preferences, `NCARGS` accounting, `execsigs`,
`fdt_exec`, and the spawn layouts.
