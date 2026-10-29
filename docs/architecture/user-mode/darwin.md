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
`sy_return_type`. An ARM64 BSD entry owns its effective call number, at most
eight decoded scalar arguments and original post-SVC context PC. A parked
service records a `Wait` and keeps that entry without rewinding saved user
state. On wake the scheduler continues the service without fetching another
guest instruction or decoding registers again. Mach state writes independently
select user registers and the eventual return PC. Existing `Resume` records
retain per-service deadlines and progress; this does not snapshot every
pointed-to user payload. Final return clears the entry. A final signal-induced
`ERESTART` still rewinds the current saved PC by 4 bytes before user signal
delivery. x86-64 and Mach traps retain their existing instruction-restart
paths; their saved-state behavior is not inferred from ARM64 BSD controls.
Apple's [ARM entry and return implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/arm/systemcalls.c)
provides the reference separation between copied arguments, retained syscall
identity and saved user state. That source revision is not the installed
macOS 27 kernel's exact source; the native read controls establish the covered
runtime behavior independently. Descriptor close/reuse during pending I/O
remains separately unqualified: scalar entry retention alone does not retain
every referenced kernel object across service attempts.
All guest threads run on one host thread (one emulated CPU, `hw.ncpu` = 1).
The host descriptors the sleeping threads wait on are
polled together, each once for every readiness asked of it (the host
answers a descriptor listed twice in only one entry), and each waiter is
woken for the direction it waits for.

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
`KERN_INVALID_RIGHT`; a task's own movable control port, its
`TASK_KERNEL_PORT`, as the host's MAC policy decides for the emulator's
task, `KERN_DENIED` unless a relaxed host gives it),
`thread_act` (`thread_info`, policies, exception ports, suspension),
`host_priv`'s special ports (refused, `KERN_INVALID_ARGUMENT`, to a caller
without the privileged host port, the right a set carries released),
`mach_vm`/`vm_map` (allocation, protection, regions, reads and writes), and
`clock`.

### Host timer probe ownership

The macOS coalescing probe creates and destroys a private Mach timer for each
arm/cancel query. Independent emulated processes may run on different owner
threads; they cannot share the mutable host timer between those two calls.
Only the immutable host timebase is cached. Conversion uses 128-bit arithmetic
and saturates at the 64-bit absolute-time bound.

The concurrent regression issues 1,024 independent queries in eight threads,
using both guest timebases and distinct deadlines/leeways. It fails with the
former shared host timer. Critical-timer queries assert exact zero slop and
exact explicit leeway. An ordinary query does not assume a foreground QoS tier:
XNU's `osfmk/i386/i386_timer.c` and `osfmk/arm/arm_timer.c` define different
coalescing bounds across tiers. The arm/cancel/destroy contract is specified
by `osfmk/kern/mk_timer.c` and `osfmk/mach/mk_timer.h`; explicit leeway is applied
after critical-timer slop in `thread_call_enter_delayed_internal`.

| ID | Assumption / basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| T1 | A Mach timer's arm/cancel state belongs to its receive right (`mk_timer.c`). | A query must own that right until cancellation and destruction complete. | Concurrent distinct-deadline queries on the real macOS kernel; the shared-right implementation produces missing or mixed results. | Confirmed. |
| T2 | Host QoS is selected externally and may exceed foreground coalescing tiers. | Ordinary slop has no fixed foreground-only bound in native tests. | Intel macOS CI reported 150 ms, exceeding the former 10 ms assumption; critical plus explicit-leeway queries remain exact across tiers. | Revised. |

The change affects the macOS host timer adapter and its tests; Linux continues
to use the existing modeled coalescing rule. It adds no Windows personality,
C ABI, ISA, CPU-state, or guest syscall-layout changes. Each query uses O(1)
space and one temporary native timer; no timer port remains cached for the
host process's lifetime. High-impact resolved finding: a shared probe could
return another emulated process's coalescing result under concurrent execution.

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
| Kernel objects of the host: IOKit's main port (`host_get_io_main`) is the host's, and the guest's sends to a proxy travel in the guest's own call class (`MACH64_SEND_KOBJECT_CALL` or `MACH64_SEND_MQ_CALL`), which the host kernel checks; a kernel object's call is sent and its reply received in one call, as the host requires of a call that names a reply port. The calls that name memory of the calling task (IOKit's property reads into a buffer, and `io_connect_method`'s out-of-line input and output) are given host buffers, copied from the guest's memory before the call and into it after as the reply says; mapping memory into a task or unmapping it is answered `kIOReturnUnsupported` without reaching the host. Rights to the emulator's own task or to the host that a service hands the guest are the guest's own | `bridge::kernel`, `bridge::translate`, `mig::host` | `ipc_validate_kmsg_dest_from_user`, `device.defs` |
| Moved receive rights: a receive right the guest sends a host service is the export's (or a new host receive right), and the guest port then sends on to the host what the guest sends it or had queued on it; the right coming back makes it the guest port's again | `bridge::translate` | `ipc_right_copyin` (`MACH_MSG_TYPE_MOVE_RECEIVE`) |
| Memory entries: an entry of the guest's memory (`mach_make_memory_entry`) is a host memory entry over a host file the range becomes a shared mapping of (its contents kept; `MAP_MEM_VM_COPY` makes one of a copy, `MAP_MEM_NAMED_CREATE` one of new memory), so a service that maps it shares it; `vm_map` of such an entry maps the file shared (or a copy), and of an entry a service made maps the service's memory itself (or, with `copy`, a copy of its contents): the guest's pages are the host memory, which the emulator maps too (a host child makes its own entry of that mapping); `VM_PROT_IS_MASK` asks for the protections the entry allows | `syscall::mach::entry`, `mig::vm`, `bridge::mirror` | `mach_make_memory_entry_internal`, `vm_map_enter_mem_object` |
| Memory a service maps into the task: a service the guest hands its task control port or identity token may map memory into the task (`coreservicesd` maps the session's file-ID universe into a client "via identity-token", returns its address, and later maps segments whose addresses it publishes in that memory). The guest's task is the emulator's, so the memory lands in the emulator's address space: from the first such hand-over, what the guest maps is reserved on the host (inaccessible mappings) before each send, so the host picks addresses the guest leaves free, and after each message from the host a region that is new, accessible, shared with another task, and outside the frame arena is mapped at the same address in the guest as the same memory (through an entry of it, `MAP_MEM_VM_SHARE`, allowing what the region allows now) | `bridge::mirror` | `mach_make_memory_entry_share`, `vm_map_region_walk` (share modes) |
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

What a service maps into the task is found by looking at the emulator's
regions, so a shared mapping the emulator's own libraries make meanwhile
(a notification page, say) appears in the guest too, and a region the host
places where the guest has memory is not mirrored (`--strace` reports it):
memory another guest thread mapped after the send, or a range that was the
emulator's own when the guest's was reserved and that the emulator has
freed since. A region mirrored at its first touch in
the parent is shared with a forked child; one touched first in the child
is the child's copy of the host region, as the host fork gives it.

## Threads

| Area | Module | Counterpart |
|---|---|---|
| `bsdthread_register`: the main thread's QoS is the one the host kernel gave the emulator's own primordial thread at its exec (from the task's application type and QoS clamp, which fork and exec keep; a host fork's thread is not given it again), legacy when it has none | `syscall::bsd::thread` | libpthread `kern_support.c` (`_bsdthread_register`), `task_set_main_thread_qos` |
| `bsdthread_create`: a thread with its own control port, the TSD base, and libpthread's `thread_start(pthread, kport, func, arg, stack, flags)` state; QoS requests validated; `PTHREAD_START_SUSPENDED` | `syscall::bsd::pthread` | libpthread `kern_support.c` |
| `bsdthread_terminate`: the stack freed (the main thread's made inaccessible), the joiner's semaphore signalled or its ulock woken once the thread is gone, the control port dead | `syscall::bsd::pthread` | `pthread_shims.c`, `uthread_joiner_wake` |
| Thread state by flavor (`thread_get_state`, `thread_set_state`): the flavors a 64-bit thread has and their counts, the flavor lists, the unified states with their headers, the exception state (set: accepted and ignored on arm64, refused on x86-64), NEON, VFP, float, and AVX state (a float state clears the upper YMM halves; no AVX-512 on the emulated Haswell); the debug registers are checked, masked, and kept, Arm SS controls stepping, and hardware breakpoint/watchpoint event generation remains unsupported; the saved-state, full-state, SME, and SVE flavors are refused | `thread_status`, `mig::thread` | `status.c`, `pcb.c`, `fpu.c`, `thread_act.c` |
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

`ptrace` (BSD call 26) is incomplete in the host-services profile and is
not admitted in the embedded profile. Self-directed `PT_DENY_ATTACH` and
`PT_FORCEQUOTA` maintain process flags and perform their local checks. A
connected child's no-attach flag rejects its parent's attach request. A
connected, non-root tracer can use `PT_ATTACH` or `PT_ATTACHEXC` when its
real and effective UIDs match the target's and the target's observed signature
has `get-task-allow`. Independently launched host-backed RAX instances discover
each other through a per-user registry; the tracer need not be a guest ancestor. This policy extrapolates the tested macOS 27.2 case;
it does not evaluate all MAC hooks, set-ID state, sandbox restrictions, or
task-access policy. Other unmodeled cases return `ENOSYS` after the local
rejection checks. The quota
flag is not enforced against filesystem operations. For processes connected at fork, spawn, or through the per-user registry,
the implementation has a tracing path for
`PT_TRACE_ME`, signal
stops, `wait4`/`waitid`, `PT_CONTINUE`, `PT_KILL`, `PT_STEP`, `PT_DETACH`,
task-level `PT_SIGEXC`, and traced exec. That path is incomplete: its
security checks, signal edge cases, code-signing flag transitions, remote
exception-port control, and failure handling do not yet establish full XNU
behavior. x86-64 `RFLAGS.TF` is preserved on detach and now generates
architectural trace events through the ordinary direct user CPU. The shared
x86 segment-load helper still sets interrupt inhibition for `LSS`, although
the [pinned Intel SDM](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
Vol. 3A section 7.8.3 specifies no such inhibition. That separate interrupt
shadow discrepancy remains; TF suppression now uses its own MOV/POP SS marker. A signal sent to a connected traced
child by positive pid uses the guest link. A `SIGKILL` sent to a traced stop
stays pending until continuation or the exception handler's reply. In the
observed soft-exception case, the pending kill took effect after the suspended
handler resumed and replied. In the hard-stop mode, `SIGKILL` sent while a
traced child is running produces a trace stop and is delivered when that stop
is released. If all guest threads have explicit thread suspensions, a running
hard-stop tracee instead exits for `SIGKILL`; `PT_KILL` and a continuation
carrying `SIGKILL` also terminate a suspended tracee. On macOS 27.2 arm64, the
running case either terminated directly or first reported a `SIGKILL` trace
stop; a Rosetta run also reported a stop. Physical Intel behavior is unknown.
Process-group signals and signals from external
host processes still use host delivery, including host `SIGSTOP`. Discovery
can wake a host-stopped RAX target while retaining its guest stop. An ancestral
parent retains ordinary POSIX signal permission after a different tracer
becomes the guest parent; its ptrace controls and waits remain excluded.
For a connected target, `task_for_pid` requests an authenticated target-side grant independently of BSD attach and stop state. The target checks the
represented credentials, image epoch, and host-observed get-task-allow
signing state before retaining a task send and replying. The caller then
receives a proxy control port; `task_info`, `task_threads`, `thread_info`,
`thread_get_state`, `thread_set_state`, `thread_suspend`, and `thread_resume`
run in the target process. Remote
`mach_vm` allocation, deallocation,
protection, read, read-overwrite, write, copy, page query, region, and
recursive-region calls operate on the target's map. The corresponding
`vm_map` read, read-overwrite, write, copy, page-query, and 64-bit region
calls use the same path. `task_set_exception_ports` and
`task_swap_exception_ports` can install a connected tracer's live handler for
`EXCEPTION_DEFAULT`, `EXCEPTION_STATE`, and
`EXCEPTION_STATE_IDENTITY`, with 32-bit or 64-bit exception codes. The target
runs the shared MIG validation before changing its actions. Protected-identity
layouts remain unsupported and are rejected before mutation. Kernel exception
requests travel back to the tracer with task/thread capability descriptors and
a single-use reply token; replies return to the target's waiting thread.
Handler death, last-send release, abandoned replies, disconnect, and exec have
explicit lifecycle controls. Target actions retain their handler across exec,
while the old image's pending replies and guest IPC names are retired.
Inherited state-only RPCs can relay through their parent's connection after
fork or spawn; relayed replies and handler sends also survive an intermediary
exec. This requires the ancestry connections to remain live. Inherited
identity-bearing exceptions and loss of an intermediary still need broader
capability routing. `ptrace_inherited_state` compares the arm64 fork case
with native behavior. The corresponding Rosetta probe cleared the inherited
action; physical Intel behavior remains unknown.
`task_set_exception_ports` and `task_swap_exception_ports` can also install a
null or dead-name handler. The swap path rejects a live previous handler
whose receiver is outside the represented connected-tracer capability set
before changing the action.
`task_get_exception_ports_info` can inspect target actions,
and `task_get_exception_ports` and swap can return null, dead-name, and
connected-tracer-owned live handlers. Live sends return to the original port
identity in the tracer. Return frames precede the last-send release of a
replaced handler; a receive right destroyed while its send is in transit
becomes a dead name.
The info identities use the emulator's synthetic port and receiver values, not
XNU's hashes, and receiver identities can collide. On macOS 27.2 arm64,
`tools/darwin/ptrace_remote_exception_probe.c` installed a handler in the tracer,
received a child's software exception, replied successfully, and observed its
normal exit; the x86-64 probe under Rosetta did the same. The
`ptrace_attach_exception_live` fixture exercises that cross-process handler
installation and reply path. `ptrace_attach_exception_live_ports` adds get,
live-to-live swap, swap back, and clear, checking that each returned live
right has the original port name. A separate
macOS 27.2 arm64 probe confirmed that the child's
software action is cleared. An x86-64 probe under Rosetta reported success
but the child still observed a non-null handler; physical Intel behavior is
unknown. The dead-name set/get fixture agrees with native macOS 27.2 arm64 and
x86-64 under Rosetta, including invalid flavor and `MACH_PORT_DEAD` inputs.
Large out-of-line transfers
use an anonymous host file passed over the family link; they retain a complete
memory snapshot and consume a host descriptor, and snapshot creation or
allocation can return `KERN_RESOURCE_SHORTAGE`. Other remote operations return
`KERN_NOT_SUPPORTED`. Legacy `task_suspend` and `task_resume` use the task's
user and legacy hold counters (`osfmk/kern/task.c`: `place_task_hold`,
`release_task_hold`, `task_suspend`, `task_resume`). A suspend installs one
hidden resume-port send uref in the caller's IPC space; repeated calls coalesce
the physical send. Deallocating its last uref releases all remaining legacy
holds, while resuming consumes one uref on success and destroys stale urefs on
failure. The family transport carries this caller-space effect separately
from the RPC result, including for a message without a reply right. Caller
exec releases sends owned only by its old IPC namespace; registered ports and
inherited task special ports retain their sends. A disconnect releases the
connection's exported send; target exec invalidates its proxy. A canceled
suspend reply refreshes an existing retained send's generation without
releasing its shared physical export. Generation checks protect a reacquired
send from a stale release, and
last-send controls share the callback FIFO so a new RPC cannot overtake them.
Hard ptrace stops and cooperative job stops take normal holds. A hard ptrace
resume uses the legacy release rule and consumes the tracer's hidden uref
before returning its BSD reply; `SIGCONT` uses the normal release rule.
Task-info suspend counts include these user holds, and a held task remains
able to service kernel requests while guest execution is blocked.
`task_suspend2` returns an independent send-once suspension token. Both
`task_resume2` and token abandonment release a normal hold; using its
send-once destination for a malformed RPC consumes the right without
releasing that hold, as XNU does. Token calls remain valid after releasing
the separate task-control name. This link retains trace stops and replies in order under output backpressure. A
process with a `PT_TRACE_ME` announcement or synchronous tracing or remote Mach
reply still queued waits for the ordered backlog to enter the socket before
host-process teardown, including when the guest has already exited. If the
tracer holds the socket open without reading, this can delay host-process exit;
bounded execution reports a blocked state. In the opposite direction, a full
tracer-to-tracee output queue can still cause a tracing request to return
`EAGAIN` or a remote Mach call to receive `KERN_RESOURCE_SHORTAGE` instead of
waiting for capacity.

### Independent instances, parentage, and exit waits

The host-services profile publishes an endpoint under
`/tmp/rax-darwin-<effective-host-uid>/`, independently of the launcher's
`TMPDIR`. The directory must be account-owned with mode `0700`; records and
leases must be account-owned, single-link regular files with mode `0600`.
Symlinks, unexpected file types, writable ancestors, and replacement of the
registry directory are rejected. A per-PID `flock` lease serializes publication;
a 128-bit random process-instance identifier names the socket and binds the
handshake. Current discovery uses `RAXREG02`, a fixed 32-byte identity record
and a 33-byte framed hello. A prior protocol version is rejected before a
tracing relationship can be created. Under its own exclusive PID lease, a new
publisher may replace a valid stale version-1 record. Lease files remain in
place to preserve lock-inode identity. Abnormal host termination can leave
stale record/socket files; there is no directory-wide garbage collector.

On macOS, `getpeereid`, `LOCAL_PEERPID`, and `LOCAL_PEERTOKEN` establish the
socket peer's kernel identity. Discovering a stopped peer sends `SIGCONT`
through `proc_signal_with_audittoken`, which checks the audit token's PID
version. It does not signal a running peer. The validated hello identifies this
internal wake so the target retains its guest `SIGSTOP` without invoking a
caught guest `SIGCONT` handler. Losing the last controller returns an untraced
cooperative stop to host job control. Setup is nonblocking: at most 32 pending
setups and 32 incoming established peers, with a 5 s setup deadline. Each
scheduler pass accepts at most eight peers. The underlying tracing transport
bounds an ordinary frame to 1 MiB and its queued payload to 4 MiB; the existing
Mach out-of-line path has separate resource accounting.

Registry discovery grants no ptrace or Mach authority. Connection identities
select independent target export, suspension-token, callback, reply, and
backpressure namespaces. Tracer PID, original parent (`p_oppid`), and physical
host ancestry are distinct. An original guest parent can observe another
tracer's ownership without acquiring its controls. It cannot consume that
tracer's stop, continuation, or exit waits. Target exec retires prior-image
rights, advances an image epoch, and republishes signing state; status replies
from an earlier epoch cannot replace the new projection. A successful attach
publishes its guest signing transition before its acknowledgement.

A guest exit can precede physical engine exit. The cooperative zombie reports
its status and a 144-byte `user64_rusage` while the engine pins the host PID.
`wait4` and `waitid` copy requested output before committing the reap; an
`EFAULT` leaves the zombie waitable. A reap acknowledgement changes parentage
before the caller returns. As in `reap_child_locked`, a nonzero `p_oppid`
returns the zombie to its original parent even when that parent is also the
tracer: `PT_TRACE_ME` can therefore require two successful exit waits for the
same PID. The final guest reap permits host exit, and a physical RAX parent
collects its host child. `SA_NOCLDWAIT` performs the same handoff and host
collection automatically. Ordinary untraced child exits retain host
`SIGCHLD`; only foreign-owned children and cooperative exit/reap exchanges
suppress that internal host notification.

Debugger memory writes support both `mach_vm_machine_attribute` (4812) and
`vm_machine_attribute` (3813). For `MATTR_CACHE`, the RPC preserves the input
value and publishes the page-rounded range to the address-space code-change
log. CPU adapters consume that log before entering guest code. Zero size
returns success before address/attribute validation; range overflow, invalid
map bounds, unsupported attributes, and unmapped pages retain distinct error
paths. The SDK debugserver uses this RPC after `vm_write`; an unsupported RPC
previously reported a failed breakpoint or memory write after modifying bytes.
The implementation follows pinned XNU
[`vm_user.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/vm/vm_user.c)
and
[`vm_map.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/vm/vm_map.c),
with native macOS 27.2 cache-value and error-precedence comparisons. This is
instruction-cache synchronization of the flat guest map; physical cache
placement and migration attributes are not represented.

Task, thread, legacy-resume and send-once suspension-token rights are retired
at guest exit while the PID and
BSD reap transport remain live. Native teardown can make a task send become a
dead name shortly after the process event, before any `waitpid` call; the
fixture polls for this transition with a 5 s observation bound. The primary
source is `ipc_task_terminate` / `ipc_thread_terminate` in pinned XNU
[`ipc_tt.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/kern/ipc_tt.c).

New task acquisition on the zombie returns `KERN_FAILURE` with a null name.
The dying server completes queued grants and rejects Mach/callback, token and
ptrace requests without executing guest work; the connection remains open for
the BSD reap acknowledgement.

The cooperative exit report also activates matching `EVFILT_PROC` knotes in
the current guest parent before it can reap the target. `NOTE_EXITSTATUS`
contains the guest wait status; `NOTE_EXIT` forces `EV_EOF | EV_ONESHOT`
unless the knote retains `NOTE_REAP`. Disabled knotes keep their event until
enabled. The eventual physical engine exit does not produce a second
`NOTE_EXIT`; retained `NOTE_REAP` and unrelated host process events remain
available. New process-knote registration on a known guest zombie returns
`ESRCH`, as `proc_find` excludes zombies. This follows `filt_procevent` in
pinned XNU `kern_event.c`, including
its suppression of exit notifications to an original parent while a foreign
tracer owns the zombie. Publishing an exit scans K knotes in O(K) time and
uses O(K) temporary space. This notification is required by SDK debugserver,
which waits on a process knote before issuing its exit wait.

Architectural basis: pinned XNU `bsd/kern/kern_exit.c`
(`reap_child_locked`, `wait4`, `waitid`), `bsd/kern/mach_process.c`
(`PT_TRACE_ME`, `proc_reparentlocked`), and
[`uipc_usrreq.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/uipc_usrreq.c)
(peer socket identity); SDK `sys/un.h` and `libproc.h` define the audit-token
interfaces. The observed host is macOS 27.2; the pinned XNU revision is a
source baseline rather than a claim about that host's exact kernel binary.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| REG1 | The host-backed Darwin process profile uses one guest PID equal to its host PID; closed embeddings do not publish. | process::start/fork PID assignment and existing host-backed profile. | Per-PID lookup, kernel peer authentication, and fork/exec publication ownership. | Fork, failed spawn construction, exec, multiple embedded Proc objects, PID reuse. | An active host-backed Proc intentionally has a different PID or an uncommitted image becomes discoverable. | Retained host-services identity contract; closed embeddings do not publish. |
| REG2 | A per-user host registry is the selected process-isolation boundary; guest credentials remain separate policy inputs. | Explicit user choice: Per-user registry for independent RAX instances; verified XNU uipc_usrreq.c and SDK LOCAL_PEERPID/getpeereid interface. | Private account-owned directory, authenticated PID/UID, generation handshake. | Foreign/mismatching PID or UID, insecure/symlink/hardlink/FIFO records, stale generations and directory replacement. | A direct foreign-account socket is admitted, a mismatched kernel identity is accepted, or stale setup promotes a replacement process. | User-selected per-user contract; private-path, peer-identity, stale-generation, malformed-handshake and bounded-setup tests pass. |
| REG3 | The same-credential, entitled-target attach profile works for an unrelated unentitled tracer on the observed host. | Independent sibling native PT_ATTACH/stop/PT_KILL probes pass on macOS 27.2 arm64 and Rosetta with a get-task-allow target and unentitled tracer. | An evidence-backed initial independent-attach authorization path. | Deny attach, already traced, UID change, image change, unsigned/restricted target and tracer death. | A bounded native probe disagrees for an admitted credential/signing combination. | Confirmed for the observed same-credential, non-platform get-task-allow profile; complete native MAC/taskgated policy remains unknown. |
| REG4 | Observation of traced state and ownership of ptrace controls must be separate. | XNU mach_process.c cantrace/proc_reparentlocked/PT_TRACE_ME; PT_TRACE_ME can overwrite p_oppid with the current tracer-parent. | Atomic tracer+original-parent snapshot and explicit Child.owner_pid. | Ancestral parent observes an external tracer, p_oppid overwritten by trace-me, clear on exit, output backpressure. | The original parent gains a foreign tracer control or observes a torn owner/parent pair. | Ownership, sibling signalling, parent metadata and exit/wait tests pass; v4 full Darwin campaign passed 375 tests. |
| REG5 | An unrelated emulated tracer needs a cooperative exit report and reap acknowledgment rather than host wait4. | Host wait4 requires a real host child; native attach reparents the target, while a guest registry connection does not change host ancestry. | Virtual wait4/waitid exit/rusage delivery and target zombie lifetime. | WNOHANG/WNOWAIT, tracer exits without reaping, original parent waits concurrently, guest SIGKILL. | Independent RAX wait falls through to ECHILD or exposes/reuses a target PID before the emulated tracer reaps it. | Revised to cover family and registered tracing; native/RAX copyout, double-wait, waitid and reparent fixtures pass. |
| REG6 | Independently launched Rosetta tasks are not a native oracle for x86 architectural thread state on this Apple Silicon host. | /tmp/rax-registry-state-diagnostic.json: two threads reject flavor 4 with KERN_INVALID_ARGUMENT and accept ARM64 flavor 6; arm64 native and RAX x86 state queries are tested separately. | The independent x86 Mach comparison excludes that host-only state observation; RAX must independently return its x86 state. | Physical Intel macOS, translated helper thread ordering and count, wrong guest flavor. | An independent native Rosetta target exposes x86_THREAD_STATE64 successfully under the same stopped profile. | Confirmed for the observed Rosetta profile; physical Intel execution remains unknown. |
| REG7 | A host wait result is terminal only for WIFEXITED or WIFSIGNALED. | Frozen detach campaign iteration 2 reports native status 4991 (0x137f, continued), not a death; the original harness incorrectly treated it as terminal. | Native orchestration must ignore continued transitions and retain PID ownership until a terminal reap. | SIGCONT races with retained PT_DETACH SIGSTOP; WNOHANG and WUNTRACED statuses arrive in either order. | A nonterminal status is cached as a completed Child or an owned live target is leaked. | Native harness ignores nonterminal statuses; both-architecture independent detach/continue fixtures pass. |
| REG8 | A caught debugger-supplied signal completes the interrupted kernel continuation before its user handler frame is saved. | Pinned XNU kern_sig.c sigsuspend_nocancel returns EINTR; the ARM syscall source retains entry arguments and identity separately from user state. | ARM64 BSD uses its owned entry despite saved-PC changes; x86/Mach paths keep the exact restart-PC guard. | Indirect arguments, edited return PC, mismatched owner, zero/fatal/masked verdicts, Mach traps and EINTR/ERESTART. | An unrelated owner is admitted or a caught handler is saved before its pending service reaches kernel return. | Covered by focused continuation/verdict units; complete platform and native campaigns qualify each implementation. |
| REG9 | A stopped peer can be awakened without targeting a reused host PID by using the socket audit token. | /tmp/rax-registry-wake-audit-current.json and /tmp/rax-registry-wake-stage-current.json; SDK LOCAL_PEERTOKEN/proc_signal_with_audittoken and pinned XNU proc_info.c validate exact process identity. | Discovery of independently launched targets that were stopped before connecting. | Stale pidversion, running peer, false hello claim, peer death before wake and ordinary native SIGCONT. | A stale audit token wakes a replacement process, a running target receives an unsolicited SIGCONT, or an unauthenticated hello claims an internal wake. | Stale audit-token API probe and native/RAX self-stopped, externally stopped and caught-CONT fixtures pass. |
| REG10 | Guest exit ownership follows p_oppid before physical host reaping, including when tracer and original parent coincide. | Pinned XNU kern_exit.c:2849-2918 and native double-wait/EFAULT probes on macOS 27.2 arm64 and Rosetta. | Reap acknowledgement protocol, current-parent shared snapshot, wait eligibility and zombie metadata. | Two successive WNOHANG waits, status/rusage EFAULT, foreign controller ack, original parent waits concurrently, tracer EOF, SA_NOCLDWAIT. | Native/RAX ptrace_reap or ptrace_reparent fixture differs, or a nonowner controller can advance a zombie. | Native/RAX EFAULT, WNOWAIT, double-wait, reparent and parent-ownership fixtures pass; new process-event assertions also pass on both architectures. |
| REG11 | On the observed macOS 27.2 profile, MATTR_CACHE preserves tested input values; code-range invalidation supplies the flat guest map cache synchronization effect. | Pinned XNU vm_user.c/vm_map.c; native /tmp/rax-vm-attribute-native-arm64.log; LLVM MachVMMemory.cpp explains SDK post-write RPC. | Local and remote RPC 4812/3813 and successful debugger breakpoint/memory write acknowledgement. | Zero size with invalid attributes/address, integer overflow, unmapped/cross-page ranges, arbitrary signed values, read-only maps, both RPC variants and guest architectures. | Native/RAX vm_attribute output differs, code log lacks affected pages, or actual SDK breakpoint insertion still reports E09 after memory write. | Both cache RPC variants, range/error and code-log units, native/RAX cache fixtures, and actual SDK breakpoint/memory writes pass. |
| REG12 | A cooperative guest zombie must publish its process knote exit before physical engine exit; proc_find excludes that zombie from new registrations. | Pinned XNU kern_event.c:filt_procattach/filt_procevent; native arm64 and Rosetta ptrace_registry_event comparisons; v4 SDK timeout at final continuation. | EVFILT_PROC guest exit/status, NOTE_REAP retention, physical-event suppression, and zombie registration ESRCH. | Disabled knote, wrong PID/filter, missing NOTE_EXITSTATUS, NOTE_REAP retained, p_oppid handoff, duplicate host exit, and new registration after guest exit. | The native/RAX event fixture differs, or SDK debugserver cannot observe target exit42 after successful continue. | Confirmed for covered units and both native/RAX guest architectures; final debug and optimized SDK workflows complete attach, software breakpoint, PC+4 step, memory write and exit42. |
| REG13 | Native task/thread and resume rights become dead independently of BSD zombie reaping; task-port death can follow the process knote asynchronously. | Pinned XNU ipc_task_terminate/ipc_thread_terminate and task_deallocate; native macOS 27.2 probe /tmp/rax-process-exit-rights-poll-current.json observes a live initial send then a dead name before waitpid. | Retire all controller exports at cooperative guest exit while retaining PID lease and BSD reap transport. | Family and independent registry links, task and thread exports, multiple controllers, queued calls, task death observed before a reap acknowledgement. | cooperative_zombie_retires_task_and_thread_rights_before_any_reap_ack fails, or native/RAX event fixture cannot observe a dead task name without reaping. | Task/thread and resume-token baseline defects reproduced; final units and native/RAX pre-reap port-death fixtures pass on both guest architectures. |
| REG14 | A request delivered after guest exit must complete with a terminal failure rather than wait for BSD zombie reaping. | Native macOS 27.2 probe returns KERN_FAILURE and MACH_PORT_NULL when reacquiring an unreaped zombie task; baseline unit retained Mach RESTART indefinitely. | Dying-frontier grant, Mach/callback, token and ptrace replies; resume-right retirement without closing the reap transport. | Request queued before exit but received afterwards, retained send-once token, fresh task acquisition after port death, no reap acknowledgement. | cooperative_zombie_rejects_an_inflight_task_grant_without_waiting_for_reap returns Mach RESTART, or ptrace_registry_event reacquisition differs from native. | Final 417-test Darwin unit gate and both-architecture native/RAX lifecycle comparisons pass, including token death and task reacquisition failure before reap. |

The additional registry change affects the Darwin process/syscall scheduler,
IPC routing, metadata, explicit address-space code synchronization, and tests.
It adds no ISA decode or execute operation,
SMIR operation, optimizer/native-lowering admission, device behavior, or public
C ABI layout. Its remaining bounded limitations include unmodeled MAC policy
(high impact for unsupported authorization profiles), host `SIGCONT`
coalescing with an internal wake (medium impact under simultaneous external
continues), and stale registry files after abnormal termination (low impact).
These limits do not extend the admitted policy profile.

Registry validation on macOS 27.2 arm64 (28 October 2026) passed 417 Darwin
library tests and all 377 Darwin integration tests, with no ignored or filtered
integration cases. The integration campaign required native oracles with
`RAX_USER_DARWIN_REQUIRE_ORACLE=1`, used a frozen optimized runner through
`RAX_USER_DARWIN_RUNNER`, and ran serially. The runner was built with
`--no-default-features --features x86_64-suite,smir-jit`; its SHA-256 was
`d525691e54172b2128f345704d05bf910231c124879e51502923948fc2dca0e6`.

The actual SDK arm64 debugserver, launched independently from its RAX target,
completed attach, a software breakpoint, single-step with a 4-byte PC advance,
a debugger memory write, and target exit status 42. Native and RAX controls
both finished with LLDB/debugserver status 0. This is separate from the C
fixtures. Native x86-64 controls used Rosetta; physical Intel execution remains
unknown. Clippy passed for all targets with the runner's features, and the
portable AArch64 Linux/musl library and `rax-user` compiled; the latter is not
Linux runtime validation. The build and runtime results cover the combined
dirty checkout. No installed executable, Git index, commit, or remote was
changed.

Final platform review added a Unix conditional to the private zombie-RPC
module declaration, matching its transport dependencies. This changes only
non-Unix admission of that module. Current-source all-target Clippy and
Windows/GNU and Windows/MSVC Rust checks pass. The GNU check used cross-compiled
C dependencies; the MSVC check used host zstd metadata. Neither establishes
Windows linking or runtime behavior.

The native `ptrace_task_suspend_probe.c` observes two hidden urefs after two
suspends, two holds after dropping one uref, and zero holds after dropping the
last; an extra resume returns `KERN_FAILURE`. The exec fixtures check that
the hidden right disappears, then use `SIGKILL` to bound child cleanup. Unit
tests separately verify that caller exec releases the target's legacy holds.
The diagnostic tool also attempts normal child completion after exec. Native
stress runs sometimes left the child in `read` even with task user holds at
zero; an extra pipe byte did not release one such stall. Its cause is unknown.
Consequently, ordinary read completion is not used as the hold-count oracle.
`ptrace_task_resume_registered_probe.c` independently obtains a child task port,
registers the resume send, and execs. Native macOS 27.2 arm64 retains both holds
until the new image drops its lookup rights and clears the registration; the
child then exits with status 42. The engine preserves these sends across the
same connection. Inheritance of a remote resume send through another fork or
spawn connection still needs capability routing.
The fixtures wait for child readiness before attachment, detach from an ignored
`SIGUSR1` stop to avoid re-delivering the initial `SIGSTOP`, and retain a bounded
watchdog across exec. The counter/namespace fixtures passed 160 native runs
across arm64 and x86-64 under Rosetta after these controls and bounded cleanup.
`ptrace_task_suspend_trace_probe.c` observes
the following sequence on macOS 27.2 arm64 and x86-64 under Rosetta; this is
not physical Intel runtime evidence:

| Event | Task user holds | Hidden send urefs |
| --- | ---: | ---: |
| Hard ptrace stop | 1 | 0 |
| Legacy suspend | 2 | 1 |
| `PT_CONTINUE` | 1 | 0 |
| Out-of-band `task_resume` | 0 | 0 |

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| S1 | Nonnegative signed 32-bit hold counts bound the modeled state. | Pinned XNU [`task.h`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/osfmk/kern/task.h) declares `integer_t` user and legacy counters; native overflow behavior is unknown. | Before either counter exceeds `i32::MAX`, the engine returns `KERN_RESOURCE_SHORTAGE` without mutation. | Either counter already at capacity; stale legacy credits exceeding the total. | Unit boundary cases disprove atomic accounting; an independent native overflow oracle would determine whether the engine bound matches XNU. | Retained engine bound. |
| S2 | One family connection represents the immediate caller's physical resume send. | Remote task calls currently route only over connected parent-child links. | Hidden urefs coalesce per caller and target resume-port identity. | Multiple calls, last-send then reacquisition, queued reply at exec, full socket, disconnect. | Lifecycle tests or native comparison report a stranded hold, premature release, or a hidden uref in the target IPC space. | Retained scope restriction. |
| S3 | The exec task projection and connection-held exports enumerate the surviving resume sends. | `exec::carry` uses `exec_task`; pending old-image reply rights are released before resume counts are rebased. | Registered and special-port sends survive caller exec without retaining old IPC urefs. | A registered send with a late suspend reply or a borrowed invalid-handler send; owned versus borrowed kernel receive rights. | The registered-exec unit/native probes report a premature hold release, a dead retained port, or a count remaining after the final retained send is cleared. | Confirmed for the covered holders; adding another holder requires an ownership audit. |

High-impact remaining scope includes capability routing outside the immediate
family connection, complete task/tracing policy, and hardware
breakpoint/watchpoint event generation. The hard-sigwait and job-stop interactions below are implemented;
their covered additional-hold combinations are characterized independently.
These limits prevent a claim of complete Mach debugging support.
`tools/darwin/ptrace_oob_resume_probe.c` isolates the corrected hard-sigwait case:
a shared counter is visible before the stop, and its worker increment gate
opens only after `task_resume` returns. On macOS 27.2 arm64 and x86-64 under
Rosetta, resuming the single task hold lets the worker increment while the
thread that raised `SIGSTOP` remains blocked in BSD sigwait. The previous frozen
resume-port runner reported the same hold count transition (1 to 0), but no
worker progress. The new scheduler now matches both guest architectures in
all six normal, queued-signal, and signal-mode-switch comparisons. Both native
and engine children exit with status 42 after `PT_CONTINUE`. Forty native normal-mode repetitions per architecture completed
(80 runs). A native `signal` mode instead makes the worker raise
`SIGUSR1`: it remains blocked until the first stop is continued, then the
parent observes a separate `SIGUSR1` stop; ten repetitions per architecture
completed (20 runs). Pinned
[`kern_sig.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/bsd/kern/kern_sig.c)
blocks other signal-processing threads in `sig_try_locked` while the original
`p->sigwait` is set. This requires per-thread scheduling and signal-wait
serialization; simply removing the scheduler's global tracing-stop check
would permit another thread to overwrite the active stop.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| OOB1 | The gated shared counter distinguishes worker execution from pre-stop stores or failed interprocess visibility. | The parent verifies the worker's ready value before releasing the child to stop; an acquire/release gate opens only after the resume call. | The diagnostic's worker-progress result. | Native/engine shared visibility, two guest architectures, and a worker entering signal processing during sigwait. | `shared-visible=0`, a worker increment before the post-resume gate, or disagreement after normal `PT_CONTINUE` falsifies this measurement. | Confirmed for the covered diagnostic paths and the corrected hard-sigwait scheduler. |
| OOB2 | The active BSD sigwait lifetime is separate from retained SSTOP/p_xstat metadata and from the task's global user hold. | Pinned `kern_sig.c` sets/clears `p->sigwait` around blocking or `do_bsdexception`, and `sig_try_locked` serializes other signal-processing threads. | Per-thread scheduling, pending-signal preservation, and verdict processing before user execution. | Out-of-band resume; a second pending signal; missing/dead exception handler; thread termination and exec. | Native/engine probes disagree about worker progress or stop order, or unit tests expose an overwritten stop, consumed pending bit, or orphan active wait. | Confirmed for the ten local tests and six hard-sigwait native comparisons; broader combinations remain bounded separately. |

The implementation keeps the active wait owner/kind and entered signal
waiters in private ptrace state. A task hold still blocks every guest thread;
a hard BSD sigwait blocks its selected thread independently. Other threads
can run after an out-of-band task resume, then park before consuming a
pending signal if another thread still owns sigwait. A pending signal alone
does not mark the thread as having entered that wait. The selected thread
consumes its continuation verdict before returning to guest instructions;
failed/returned signal exceptions and terminated wait owners release the
serialization state. Exec starts with neither an active wait nor waiters.
`THREAD_BASIC_INFO`, extended thread information, proc thread records, and
proc task running counts share the resulting wait-state projection. The
native probe reports the selected thread as `TH_STATE_WAITING` (3) with the
original task hold and after that hold drains.

A third native probe mode, `sigexc`, lets the worker enable `PT_SIGEXC`
after the task hold drains. The already-active hard sigwait still wakes on
`PT_CONTINUE`. Pinned
[`mach_process.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/bsd/kern/mach_process.c)
wakes `p->sigwait` independently of the current `P_LSIGEXC` flag; that flag
controls whether it also calls `task_resume`. The engine retains the wait's
original kind when creating its continuation verdict. Ten native repetitions
of this mode per architecture completed; the three modes total 120 native
runs. The selected thread remains `TH_STATE_WAITING` before and after the
resume in all three modes.

A separate job-stop correction is characterized by
`tools/darwin/ptrace_oob_job_probe.c`. This process does not call
`PT_TRACE_ME`; its shared counter and post-stop gate otherwise provide the
same observations. Native arm64 and Rosetta report `TH_STATE_WAITING` before
resume, then a zero task hold count, progress in both threads, and a running
main thread. The previous frozen hard-sigwait runner reported `TH_STATE_STOPPED`
before resume and no progress in either thread after the count reaches zero,
even though its thread-info projection reported running. Job-stop metadata
now remains independent of execution: task holds block the scheduler, and
signal processing resumes when the last hold drains. The probe gates normal completion;
it kills and reaps a stalled emulated child through the untraced host
`SIGKILL` path. An extra independent hold still blocks both threads until
the final release. Both the child's own BSD record and its parent's query
retain `SSTOP` (4) after out-of-band resume, while the threads execute and
a caught `SIGUSR1` is delivered. `SIGCONT` changes both records to `SRUN`
(2). Another `SIGSTOP` before `SIGCONT` does not add a new task hold.

The quiescent APC-state correction applies independently of job
control. `tools/darwin/task_suspend_state_probe.c` publishes main-thread
readiness before a legacy `task_suspend`, then permits a bounded poll for
the asynchronous APC to park. Native arm64 and Rosetta report state 3 while
the task hold is 1; the previous frozen hard-sigwait runner reported state 2. Both
resume and complete normally. `tools/darwin/thread_suspend_state_probe.c`
observes state 3 for a per-thread suspension while the task hold remains
zero. The pinned
[`thread_act.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/osfmk/kern/thread_act.c)
uses `thread_hold`/`thread_apc_ast` to park suspended threads with
`assert_wait`; `thread.c::retrieve_thread_basic_info` maps the resulting
`TH_WAIT` to `TH_STATE_WAITING`. The canonical thread-info projection now
reports this wait for task and thread user holds, including a temporarily
borrowed running thread; it preserves the independent suspend-count field.
This describes settled user-suspension APC waits, not every asynchronous
native transition or debugger-specific `TH_SUSP` state.

The job probe's normal-completion output passed 40 native repetitions per
architecture (80 runs); status/signal, extra-hold, and repeated-stop variants
each passed 20 repetitions per architecture (120 more runs).
The independent task and thread suspension probes
passed 40 repetitions per architecture and API (160 runs). The latter
probes use a pipe acknowledgment before suspension, so pre-hold user
progress is not inferred from a scheduling delay. These six probe variants
total 360 native runs. The job probe bounds each progress observation at
60 s and the entire process at 180 s. Its former 2 s bounds failed on the
debug interpreter's default 2^20-instruction slice; the same ARM64 binary
passed at a 4096-instruction slice and at the default slice with the longer
observation bound. The comparison asserts progress and status, not a native
wall-clock scheduling guarantee.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| JOB1 | Draining the task user hold permits both untraced job-stopped threads to execute without a BSD tracing verdict. | Arm64/Rosetta job-resume probe; `kern_sig.c::stop` and normal task holds. | Job-stop scheduling and signal delivery; BSD status remains a separate projection. | Extra independent holds, repeated stops, SIGCONT, and pending signals. | The gated native probe reports either thread blocked after the final hold drains, or broader probes require metadata alone to prevent execution. | Confirmed for 200 covered native runs and the implemented correction; arbitrary external stop sources remain outside the connection scope. |
| APC1 | A quiescent user suspension is represented by an APC wait in the covered task/thread probes. | `thread_hold`/`thread_apc_ast`, `retrieve_thread_basic_info`, and 160 native repetitions. | General held-thread state projection. | An already sleeping thread; nested holds; release to zero followed by a new hold. | A settled native query of these cases consistently reports another scheduler state or the projection changes suspend counts. | Confirmed for the covered probes and local state/count tests; asynchronous transitions and broader combinations remain bounded separately. |
| JOB2 | A bounded wall-clock poll observes eventual progress rather than imposing native scheduling latency on the interpreter. | The former 2 s probe failed at the default 2^20-instruction slice and passed at 4096 instructions; a 60 s bound passes at the default slice. | Probe progress and signal-delivery measurements. | Concurrent test load, long interpreter slices, and a genuinely held thread. | Progress still fails within 60 s under the recorded campaign, or an unreleased hold spuriously crosses the gate. | Revised to 60 s per observation with an independent 180 s watchdog; no real-time guarantee is inferred. |

Attachment also preserves the distinction between stop metadata and an active
BSD signal wait. `PT_ATTACH` clears `p_xstat`, posts `SIGSTOP`, and releases
one existing task user hold. It does not itself enter `sigwait`. The engine
retains the old `SSTOP` metadata with status 0 until the pending signal reaches
`issignal`; that path creates and announces the new trace stop. Creating a
synthetic wait at attachment previously prevented this AST after a job-stopped
thread had resumed user instructions. The arm64 and x86-64 diagnostic children
both remained blocked after successful attach in the frozen job-stop runner.
The parent separately tracks the expected attach-generated stop so its new
notification replaces an older job-stop record, whether that record has been
waited or not. Consuming this transition clears the marker; ordinary duplicate
hard-stop messages retain their previous handling.
`PT_CONTINUE`, `PT_STEP`, `PT_DETACH`, and `PT_KILL` now distinguish this metadata
from an active wait: metadata alone neither consumes an independent task hold
nor supplies a signal-wait verdict. Posted signals still enter signal processing.

`ptrace_oob_job_attach_probe.c` checks attachment after a post-resume user gate.
Its `JOB_ATTACH_HELD` variant instead adds a second hold before attachment.
Native attachment leaves one hold, `SSTOP` (4), and status 0; an early
`PT_CONTINUE` changes the BSD state to `SRUN` (2) while leaving that hold at 1.
Only the later Mach resume permits the queued `SIGSTOP` to create its own
hard trace stop. Both variants continue the new stop and exit with status 42.

The native stop notifications have two relevant timing windows. In the pinned
`kern_sig.c`, `stop` wakes the parent before installing the job task hold, and
hard tracing notifies the parent before `assert_wait(p->sigwait)`. A native
self-stop/attach diagnostic stalled with two task holds; another continuation
stalled with zero holds and a waiting main thread. These observations are
consistent with those source orderings; they do not establish every native
stall's cause. The fixtures now wait for the initial job hold and selected
thread's wait before attaching, and for the new hard-stop hold and selected
thread's wait before continuing. They identify the thread by its published
`pthread_threadid_np` value, including under Rosetta. The two attach probes and
the settled self-stop fixture passed 80 repetitions per architecture and case
(480 native runs), with 60 s observation bounds and 180 s watchdogs.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| JOB3 | Retained SSTOP metadata does not imply an active BSD sigwait. | `mach_process.c` tests `t->sigwait` before waking or resuming; the native held-attach probe leaves a hold at 1 across an early continuation. | Attach status 0, deferred stop publication, and continuation hold/verdict accounting. | Attach after user progress; an independent hold; continue, step, detach, and kill before signal-wait entry. | A native held-attach continuation drains the remaining hold, or the metadata-only unit cases create a verdict, consume a hold, or terminate before processing the posted signal. | Confirmed for the covered native accounting and local continuation cases; general concurrent-controller policy remains outside the family scope. |
| JOB4 | The probe's one-hold and selected-thread WAITING observations delimit the settled stop needed for its continuation oracle. | Pinned notification order, native stalled-state inspection, and 480 runs with the two observation gates. | Stable native attach/self-stop comparisons. | Initial job notification before hold installation; hard-stop notification before parking; translated x86-64 threads. | A gated native run still stalls or observes an unexpected hold/state transition. | Confirmed for the recorded runs; this is a bounded oracle synchronization condition, not a general kernel scheduling guarantee. |

For T threads and W entered signal waiters, the private wait set uses O(W)
space, lookups take O(log(W + 2)), and scheduler scans take O(T log(W + 2)).
Waiter cleanup takes O(W log(T + 2)); no public Rust signal-state field or
C ABI layout changes are needed. This change affects Darwin scheduling,
signal delivery, ptrace lifecycle, and thread/process-info projection.
ISA decode/execute, architectural register state, MMU/SMIR, native lowering,
JIT admission, VM backends/devices, and oracle layouts are unaffected.


`tools/darwin/ptrace_resume_port_probe.c` also tests shared-port dispatch:
native arm64 and x86-64 under Rosetta accept a raw `task_resume2` kobject
call with either `COPY_SEND` or `MOVE_SEND` on the legacy resume send,
returning success and reducing the hold count from 1 to 0. The previous
foreign legacy-send proxy dispatched locally and returned
`KERN_INVALID_ARGUMENT` with count 1. The family-link path now dispatches
both right kinds on the target's actual resume port. It queues the call
before consuming its destination so a final `MOVE_SEND` cannot release
the legacy hold through no-senders before the method runs. All four
architecture/disposition comparisons match native output; 40 native repetitions
of each combination completed (160 runs), with child exit status 42. The typed
`task_resume2` client uses `MOVE_SEND_ONCE`, covered separately below.
`tools/darwin/ptrace_task_suspend2_probe.c` characterizes the token path
without BSD tracing: on macOS 27.2 arm64 and x86-64 under Rosetta, two
`task_suspend2` calls returned distinct send-once names and a user hold count
of 2; abandoning one reduced the count to 1, and `task_resume2` consumed the
other and reduced it to 0. An out-of-band legacy resume drained another
normal hold; subsequently consuming its still-live token returned
`KERN_FAILURE` with count 0. This agrees with the pinned
[`task.defs`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/osfmk/mach/task.defs),
[`ipc_tt.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/osfmk/kern/ipc_tt.c),
and [`task.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/osfmk/kern/task.c):
tokens use `MOVE_SEND_ONCE`, while legacy suspensions use send rights on the
same task resume port. The previous engine returned `KERN_NOT_SUPPORTED`.
The implemented local and family-link paths now match the normal and caller-exec
fixtures on both architectures. Forty native repetitions of each mode per
architecture completed (160 runs); the children exited normally with status
42 after their gates were opened. Caller exec discarded both token rights
and released their holds before the new image queried the child.

The extended native probe sends correctly classified kobject calls through
`mach_msg2_internal`: the public `mach_msg` wrapper classifies queue calls
and triggered `EXC_GUARD/INVALID_OPTIONS` in the initial malformed-message
probe. With the kobject-call flag, an unknown RPC ID returned `MIG_BAD_ID`
and a bad `task_resume2` request size returned `MIG_BAD_ARGUMENTS`. Both
consumed the token but left the hold at 1. A 2 MiB malformed request also
returned `MIG_BAD_ARGUMENTS` with count 1. The old transport instead returned
`KERN_RESOURCE_SHORTAGE` and abandoned the hold at its 1 MiB frame limit.
The token path now represents nonempty `task_resume2` bodies by a bounded
bad-size request; that routine checks exact size before any field access,
so the MIG result and hold ownership are preserved without transmitting
unused bytes. The kernel server's destination
consumption in pinned
[`ipc_kobject.c`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-12377.121.6/osfmk/kern/ipc_kobject.c)
explicitly suppresses send-once notification. The engine follows that
distinction, including when a token is used as a kernel RPC's reply right.
Reply IDs wrap in their 32-bit field rather than panicking on an unknown high
request ID.

The target retains one actual send-once per exported token, using a distinct
connection-scoped cookie. The caller inserts a send-once proxy, not a hidden
send uref. Abandonment and calls use separate ordered controls; there is no
per-token copy of the global user-hold count. A discarded or canceled token
reply releases its actual send-once. Caller exec/disconnect releases owned
tokens; target exec invalidates them. Resume replies remain pending across
backpressure and are retired on caller exec or peer death. The protocol
uses 25-byte offers, 9-byte drop/death controls, 13-byte results, and a
30-byte call header plus its bounded body, with distinct call tags for
send and send-once destinations. Token lookup is O(log N) for N token
records; legacy-send routing scans O(P) retained resume ports; offer duplicate checks and lifecycle scans are O(N), in addition
to ordinary IPC release and transport costs. Codec work and temporary
space are O(B) for B payload bytes; retained capability state is O(N).
The affected planes are MIG dispatch, IPC ownership and family-link
lifecycle. Architectural decoders/executors, CPU register state, MMU/SMIR,
optimizers/lowerers/JIT, VM backends/devices, oracle output and public C ABI
layouts are unaffected.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| TK1 | A token handoff represents one independently owned send-once reference, while its normal hold remains part of the task's global count. | Pinned `mach_types.defs`, `ipc_tt.c`, `task.c`, and `ipc_kobject.c`; arm64/Rosetta probes. | Separate use and abandonment paths; out-of-band resume may drain a hold before token use. | Independent tokens, stale token after legacy resume, malformed RPC, ignored reply, and mixed legacy holds. | Native or transport tests show double release, a leaked abandoned hold, or a malformed call releasing a hold. | Confirmed for the covered local and family-link operations. |
| TK2 | The immediate family connection owns each represented foreign token until use, abandonment, or namespace teardown. | Existing ordered transport; send-once rights cannot be copied into registered send arrays. | Per-cookie exports and exec/disconnect cleanup, independent of the task-control name. | Full output queue, late offer at caller exec, token used as a reply right, shared-port send calls, final-send ordering, and target exec/death. | Lifecycle tests reveal an orphan export, premature release, a live stale name, or a stranded reply. | Retained routing bound; arbitrary interprocess right transfers require broader capability routing. |

Task holds require O(1)
accounting; proxy last-send and lifecycle scans take O(P) time for P retained
ports, with O(P) proxy state. No ISA decoder, CPU state layout, SMIR,
native lowerer, VM backend, or C ABI changes are required for this accounting.
The task-port policy extrapolates the same observed case and does not implement
the complete saved-credential, group, MAC, or taskgated checks.
LLVM debugserver's
[`AttachForDebug`](https://raw.githubusercontent.com/llvm/llvm-project/main/lldb/tools/debugserver/source/MacOSX/MachProcess.mm)
starts its exception thread before `PT_ATTACHEXC`; its
[`StartExceptionThread`](https://raw.githubusercontent.com/llvm/llvm-project/main/lldb/tools/debugserver/source/MacOSX/MachTask.mm)
first obtains and validates the task port and installs its exception handler
(source inspected on 27 October 2026):

```text
task_for_pid -> exception-port setup -> PT_ATTACHEXC -> initial SIGSTOP exception
```

`tools/darwin/ptrace_pre_attach_probe.c` completes this sequence on macOS 27.2
arm64 and x86-64 under Rosetta, including 40 native repetitions per
architecture. The prior engine returned `KERN_FAILURE` at the first call.
The new target-side grant path removes the attach-state prerequisite;
`ptrace_pre_attach` exercises this ordering as a native comparison. This
fixture passed both native comparisons after the grant change (302-case
driver; two selected cases). It does not run the debugserver executable. An ad hoc
arm64 build of this same parent/child probe without the fixture entitlement
also fails at the first call natively; because both processes use that image,
this paired case does not isolate caller policy from target policy.
The grant request and reply carry 41 bytes and 29 bytes, respectively,
with strict framing and a nonzero image/instance identity. Caller-issued
export generations use bit 63 clear; target-issued exception-capability
generations use bit 63 set. A queued last-send notice from one endpoint
therefore cannot consume a newer handoff from the other endpoint when their
sequence counters coincide. A regression reproduced that premature release
before the namespaces were separated. The target retains
a physical send before acknowledging. Each successful pending reply owns a
local send until IPC copyout or cancellation, so concurrent callers coalesce
their port names without losing a grant when one caller releases its name.
Caller exec and terminated threads retire outstanding grants; late replies
retain an existing live send or release an orphan by its generation. Target
exec rejects requests for its previous image. Link death wakes pending traps
with failure. Grant lookup takes O(G + P) time and O(G + P) retained state
for G outstanding grants and P peer capabilities. A live-waiter scheduler
scan takes O(G log T) time for T guest threads; retirement additionally
performs IPC right release and connection cleanup. These changes affect Mach traps, IPC
ownership, and family-link scheduling; ISA decoding/execution, SMIR, native
lowering, VM backends, and public ABI layouts are unaffected.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| G1 | Equal represented user/group IDs and a host-observed non-platform get-task-allow image describe the admitted ordinary family case. | Native pre-attach probe; pinned XNU `task_for_pid_posix_check` and `task_for_pid` in `bsd/kern/kern_proc.c`. Saved IDs, supplementary groups, prior credential transitions, and general MAC/taskgated state are not represented completely. | The target grants this bounded case and rejects mismatches or unobserved signing. | Target credential change in flight, stale parent identity, missing entitlement, platform binary, or assumed thread identity. | The native comparison disagrees, or policy unit cases export a send after denial. | Retained policy approximation; complete native authorization remains unknown. |
| G2 | The immediate private family connection identifies the caller and preserves control-frame order. | Existing transport and callback FIFO; grant requests validate the shared parent credentials and target image epoch. | A grant cannot be redirected to another peer/image; canceled generations do not release another live owner. | Caller/target exec, delayed replies, concurrent copyout, and disconnect. | Lifecycle tests expose a leaked export, dead retained send, reused pending instance, or unawakened waiter. | Originally limited to the family connection; the independent-instance registry described above now supplies authenticated connection-specific acquisition for the admitted profile. |

The link holds
target send rights while their proxies have send rights, and forwards target
thread death. At target exec it invalidates old proxies before serving the new
image and permits a fresh task proxy at the traced exec stop. On native macOS
27.2 arm64, old task and thread operations failed at that stop, but the port
type sometimes still reported a send right before becoming a dead name; the
emulator invalidates those rights earlier and does not reproduce that timing.
Other cross-process right transfers are not yet fully modeled. A native macOS
27.2 arm64 probe read and changed a
stopped child's callee-saved register. The x86-64 run under Rosetta returned
`KERN_INVALID_ARGUMENT` for the x86 thread-state flavor on both reported
threads; its fixture checks the emulated register result, leaving native
Intel behavior unverified. Connected guest children use a cooperative job stop
for their own default stop actions and for positive-PID `SIGSTOP` from their
parent. Their parent can wait for the stop, attach, and continue. The emulator
reports the pending attach-generated stop separately. Self-stopped fixtures
settle the initial job hold before attaching and the new hard-stop wait before
continuing; ungated native probes also observed direct exit, a stop with signal
0, or a stalled child, so that notification timing is not an oracle for the
new stop's precise readiness. A child stopped directly
by the host cannot process an attach request until the host resumes it. The tracing and
no-attach flags are retained by exec; all of these flags are cleared for a new
process, and the quota flag is cleared on exec.

`PT_THUPDATE` validates the signal and the caller's thread-port name. For a
hard-stopped connected child, it accepts a live thread right in the tracer's
own task, queues the requested signal on that thread, and marks the child
running without releasing its task suspension. It also accepts that right
for `PT_SIGEXC` stops, including while a task exception handler is waiting
on an `EXC_SOFT_SIGNAL` reply. It also accepts a thread right returned by
`task_threads` for that connected child. Connected processes reserve the stop,
record the signal on the selected thread, and then commit the tracee's state
change, preserving XNU's order between those two effects. The remote path
rechecks the exported right at commit, so concurrent deallocation can fail
where XNU has already acquired a reference. The reservation serializes competing
tracing requests and can return `EBUSY` where concurrent XNU calls race.

The traced flag in `proc_pidinfo` BSD records and `kern.proc` sysctl records
is projected from guest state for the current process and connected children.
Trace stops and their `p_xstat` are projected into these records when known.
The `kern.proc` projection also carries the saved original parent PID,
including after exit and before reaping. Information about other processes
still comes from the host. The XNU
development-kernel option that hides the `kern.proc` traced flag is not
modeled.

Guest fork and spawn establish private parent-child control connections. An
exec retains them, and reaping a child releases its parent endpoint. The
connections carry only the traced task and thread proxies described above;
they do not connect unrelated processes or preserve ancestor connections
through an intermediate process's exit. Each new process
requires a host socket pair, so host descriptor exhaustion can fail fork or
spawn even when the guest has descriptor capacity.

Before a connected child exits from a guest signal, it records the guest wait
status in memory shared with its parent. This preserves the signal in guest
`wait4` and `waitid` when the host must exit with a numeric fallback,
including cases where the guest signal would not normally terminate a host
process. The same mapping carries the traced flag and saved parent PID, so
process-info queries do not depend on draining the control socket. The
handoff does not report a core dump, and an external host parent cannot
consume the guest status from this mapping. Each fork or spawn also requires
a shared host memory mapping for this status.

Attachment and task-port authorization must account for the XNU credential and
MAC checks as well as the host's code-signing policy. Apple documents the
[debugging tool entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
and its relationship to target task access; that description alone does not
specify every `mac_proc_check_debug` or `task_for_pid` decision.

The native macOS 27.2 detach probe (`tools/darwin/ptrace_detach_probe.c`)
observes a child stopped on `SIGTRAP` terminate with `SIGTRAP` after
`PT_DETACH`, with either zero or `SIGUSR1` in `data`. A child stopped on
`SIGUSR1` receives `SIGUSR1` after detach even with zero or `SIGUSR2` in
`data`, whereas continue delivers the requested signal. The XNU 12377
`ptrace` implementation assigns `data` to `p_xstat` on detach and the
traced-signal path subsequently reads `p_xstat`. The reason for the observed
difference is unknown. The current detach path follows those observations;
other stopped signals and macOS versions have not been characterized.
While a task exception handler waits, a macOS 27.2 probe observed `PT_KILL`
leave the original `SIGUSR1` in `p_xstat` for data values `0`, `9`, `31`,
and `0x12345678`; the pinned XNU resume path assigns the request's data.
The current implementation retains the stopped signal for `PT_KILL` as well;
the cause of the difference and other stop modes are unknown.

In the `ptrace_sigexc_control` fixture, an exception handler delays its reply
while the parent continues the stopped child with signal zero. On macOS 27.2
the arm64 child suppresses `SIGUSR1`; an x86-64 child running under Rosetta
receives it. The same difference was observed when `PT_THUPDATE` with the
tracer's thread port and signal zero replaces the continue request. The
current implementation follows the arm64 result on both
guest architectures. Whether the difference also occurs on an Intel host
and its underlying cause are unknown. On an Apple silicon test host, the
x86-64 fixture checks the emulated result against the XNU signal path rather
than comparing it with Rosetta.
In `ptrace_attachexc_handler`, the task handler receives the initial
`EXC_SOFT_SIGNAL` for `SIGSTOP` and the parent continues the child while
the handler's reply is pending. The native arm64 child exits normally; in
five direct x86-64 Rosetta runs the child instead died from `SIGSEGV` after
the reply. The cause and physical Intel behavior are unknown. The x86-64
fixture checks the emulated sequence without a Rosetta comparison on Apple
silicon.
In the tracer-exit fixture, the x86-64 process under Rosetta sometimes dies
from `SIGUSR1` before its task exception handler receives the message. The
Apple silicon test checks the emulated x86-64 lifecycle against the XNU
tracer-exit path; native Intel behavior is not established here.
In a probe where the original traced signal is `SIGKILL`, the arm64 handler
receives the exception and the process dies after its reply; the x86-64
Rosetta run ended before the handler reported a message. That fixture also
checks the emulated x86-64 result without a Rosetta comparison.
After `PT_THUPDATE` during the exception handler, one concurrent x86-64
Rosetta run did not report `waitpid(..., WNOHANG)` returning zero after
`SIGKILL`; its return value was not captured. Thirty later direct runs
observed the kill pending until the handler replied. The reason for the
nonzero result is unknown, so that fixture checks the emulated x86-64
behavior without a Rosetta comparison on Apple silicon.

`ptrace_step_boundary` steps through an explicit stopping syscall and
subsequent instructions. Most native arm64 runs advanced the expected
instructions, but some observed the write one stop later; the cause is
unknown. Under Rosetta, repeated steps stopped without advancing the observed
x86-64 memory write. This host-side observation does not establish physical
Intel single-step behavior. On Apple silicon both fixtures check the explicit
instruction sequence under emulation, rather than asserting native parity;
the x86-64 case compares with native execution on an Intel test host.
In a separate `ptrace_step` lifecycle probe on macOS 27.2 arm64, five of
30 native runs reported another `SIGTRAP` stop after `PT_CONTINUE`; the cause
is unknown. The lifecycle fixture continues a bounded number of such stops
before checking the exit, while `ptrace_step_boundary` retains the explicit
instruction-boundary check.
Mach-only Arm stepping uses bit 0 (`SS`) of the saved `ARM_DEBUG_STATE64`
`mdscr_el1`, independently of BSD `PT_STEP`. The Darwin scheduler executes
one instruction through the direct user CPU when either controller arms SS;
task/thread suspension and BSD signal waits still take precedence. A retired
branch reports its target PC, and an instruction fault takes precedence over
the synthetic step exception. Host preemption before execution leaves SS armed.
Clearing SS through Mach also disarms a pending BSD step; BSD bookkeeping
does not override the thread's saved debug control.
The scheduler sets PSTATE.SS immediately before executing the armed user
instruction, matching the kernel's exception return. Arming a held thread's
Mach debug state alone leaves its saved PSTATE.SS unchanged. An instruction
fault preserves both saved PSTATE.SS and stored MDSCR.SS; it does not perform
the completed-step transition.
[`status.c`](../../specifications/darwin/xnu-12377.121.6/osfmk/arm64/status.c)
accepts this control bit;
[`sleh.c::handle_sw_step_debug`](../../specifications/darwin/xnu-12377.121.6/osfmk/arm64/sleh.c)
clears
stored SS, saved PSTATE.SS (bit 21), and DAIF (bits 9:6) before emitting
`EXC_BREAKPOINT` with codes `[1, 0]`. The engine applies the same transition
through its existing exception-port chain, retaining NZCV and other debug
registers. Debug arming and delivery discard the local exclusive reservation.

`tools/darwin/arm_mach_step_probe.c` installs a task breakpoint handler in an
untraced child, resumes its settled job stop through Mach, and inspects the
stopped GPR, debug, and exception states. Six variants passed 80 native
arm64 repetitions each on macOS 27.2 (480 runs). The five completed-step
variants have these raw ESR observations; the fault case follows below:

| First instruction / return path | Observed stop | ESR_EL1 |
| --- | --- | --- |
| `MOV X19,#0x1234` | Immediately after MOV | `0xcb000022` |
| `LDXR X19,[X21]` | Immediately after LDXR; following STXR fails after the exception | `0xcb000062` |
| `STXR W20,X19,[X21]`, no reservation | Immediately after failed STXR | `0xcb000022` |
| Nonblocking `getpid` SVC | Immediately after SVC | `0xca000022` |
| Blocking `read` SVC | After the following MOV, once the pipe is readable | `0xcb000022` |

These five have EC `0x32`, IL 1, and FSC `0x22`; ISV is bit 24 and EX is bit 6,
as defined in the pinned
[`proc_reg.h`](../../specifications/darwin/xnu-12377.121.6/osfmk/arm64/proc_reg.h).
The engine inspects at most 4 bytes
before a stepped instruction to form this syndrome; guest fetch, access
checks, and execution remain in the CPU. A retained ARM64 BSD entry is
matched to its original post-SVC context PC and effective call number,
independently of debugger changes to the user return PC. Continuing its service
does not retire a user instruction or complete an Arm instruction step. Final
return leaves stepping armed for the next user instruction, matching the
blocking-read observation. No guest CPU debug register is added. Entry storage,
step control and syndrome work take O(1)
time and space per selected thread. The existing scan and private wait-set
lookups remain O(T log(W + 2)) for T threads and W entered signal waiters.
Direct ISA semantics, SMIR interpretation/lifting and
lowering, JIT admission, VM backends/devices, oracle output, and C ABI are
unaffected; this is a Darwin debug-state and scheduling change.

The read fixture now proves entry before supplying pipe input: zero task holds,
`TH_STATE_WAITING`, saved PC at the read SVC's successor and `X16 == 3` must
all hold. It then observes an empty exception receive before writing. A
separate ready-data fixture queues the byte before resume and requires the
fast-return `0xca000022` stop; the proved-blocked fixture requires the following
instruction's `0xcb000022` stop. State-write variants preserve an unrelated
`X19` change, replace saved `X0` with an invalid descriptor, or redirect the
saved user PC past the following MOV. The entered read still completes with
its original arguments and result, returning at the selected user PC.

The earlier WAITING-only barrier did not prove read entry: a controlled
pre-entry thread hold passed it while PC still named SVC. The original CI
mismatch did not record prewrite saved state, so its exact scheduling cause
remains unknown. These separate preconditions retain the distinct ESR/PC
expectations rather than accepting either output.

The additional fault variant executes the unallocated word `0x00000000`.
Native macOS reports `EXC_BAD_INSTRUCTION` (2), codes `[1, 0]`, the faulting
PC, ESR `0x02000000`, stored MDSCR.SS 1, and saved PSTATE.SS 1. The first
engine candidate agreed on the exception and PC but incorrectly reported
saved SS as 0. Setting SS at user entry corrects this saved-state boundary;
the fixture skips the invalid word and explicitly disarms before replying.

The exception fixture explicitly clears SS before replying, following the
debugger workflow. An earlier native prototype without that explicit clear
stalled after its first successful exception reply despite querying stored
SS as 0; its cause is unknown. The fixture does not establish the behavior
of every exception-return controller sequence. Breakpoint/watchpoint
registers remain stored state without hardware event generation.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ARMSTEP1 | Mach SS controls the selected thread independently of BSD tracing; PSTATE.SS is armed on user entry and retained by an instruction fault. | Pinned status/step handlers and native Mach-only/fault probes. | One-instruction scheduling, saved state, and exception delivery. | Clear before resume, task/thread holds, branch targets, instruction faults, and exclusive accesses. | A native Mach-only probe does not stop at the covered frontier, or a local held/faulting thread retires an extra instruction or loses saved SS. | Revised after the native fault probe falsified the first candidate; confirmed for the corrected unit, native-comparison, and debugger cases below. |
| ARMSTEP2 | A proved-blocked Arm BSD read returns with stepping armed for the next user instruction. | Earlier blocking/getpid observations plus separate ready, entered-read and state-write controls. | Owned service continuation and distinct fast/slow ESR frontiers. | Entry PC and WAITING precondition, empty pipe, changed argument registers and selected return PC. | A proved-entered native read is retargeted by a scalar state write, or its return stops at the wrong instruction. | Confirmed for the measured read cases; the old WAITING-only precondition was insufficient, and other kernel paths remain bounded separately. |
| ARMSTEP3 | Kernel instruction inspection and execution observe the same instruction bytes. | Requests for this process are dispatched between guest instruction steps. | Synthetic ESR instruction classification. | Instruction fault and code replacement before the step. | A concurrently writable shared code mapping changes between inspection and guest fetch. | Retained; unsynchronized external writes to shared executable mappings are outside this probe's evidence. |
| ARMSTEP4 | A debug-control interruption may discard an earlier local exclusive reservation. | The user CPU already clears it on synchronous kernel exits; native exclusive-load step is followed by failed STXR. | Arming/delivery monitor reset and failed-store EX classification. | Exclusive load before the exception and store without a reservation. | A supported control writer preserves a reservation that allows a stepped store to succeed under this implementation. | Retained for control-boundary invalidation; no claim that native kernels always clear every reservation at every debug-state write. |

The corrected implementation passed 361 Darwin library tests serially and
all six Mach-step native comparisons in both debug and optimized runners.
The optimized runner also passed the complete 338-test Darwin integration
suite serially, with no failures, ignored tests, or filtered tests. The debug
runner's broad serial run was stopped when switching profiles; it is not a
completed debug integration gate. Linux AArch64 all-target compilation passed,
without Linux runtime execution.

A separate executable check uses Xcode LLDB (`lldb-2103.0.34.105`) and a
strictly signature-verified arm64 slice of Xcode's debugserver. With
`--no-stdio --kill-on-error --launch=posix-spawn` and no file-logging option,
the server launches an entitled child, LLDB connects through `gdb-remote`,
reads PC, runs `thread step-inst`, and reads PC again. Both native execution
and the corrected debug/optimized runners stop after dyld's first
`MOV X0,SP`, with an exact 4-byte PC advance. Continuing reaches the child's
proof-file write and exit status 42; LLDB and server both exit 0. The earlier
job/attach runner instead continued through to exit on `thread step-inst`.
This check exercises the actual debugserver executable, separately from the
pre-attach C fixture described above.

Earlier checks with file logging reached the target's normal exit but then
observed native `SIGABRT` and the earlier debug runner's `SIGBUS` during
server teardown. Their cause and the corrected runner's file-logging teardown
behavior are unknown; the clean executable checks above omit that option.
This medium-impact finding does not block the covered no-file-logging
workflow. Full non-family routing, native authorization, and hardware
breakpoint/watchpoint behavior remain outside this Arm-step correction. The
subsequent x86 TF implementation is described below.

The earlier `tools/darwin/ptrace_tf_probe.c` and
`ptrace_tf_boundary_probe.c` identified a missing x86 user-CPU TF retirement
path: the frozen Arm-step runner reported no trace traps for guest-set TF.
The direct user CPU now samples incoming `RFLAGS.TF` (bit 8), generates a
post-instruction `#DB`, and sets `DR6.BS` (bit 14). `POPF` enabling TF arms the
following instruction; `POPF` clearing an incoming TF still produces its own
trace event. Faults and explicit software traps take priority. Only successful
`MOV SS` and compatibility-mode `POP SS` suppress their own trace event;
`LSS` and `STI` do not inherit that debug suppression. These rules derive from
[pinned Intel SDM revision 086](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
Vol. 3A section 7.8.3 and Vol. 3B section 19.3.1.4.

Repeated memory strings execute one element per TF event. An unfinished REP
retains the prefix PC, updated indexes/count, and saved RF (bit 16); its final
or zero-count event reports the next instruction. REPE/REPNE termination also
retires before reporting. RF clears at instruction start and is set in the
covered fault frames, following Vol. 3B section 19.3.1.1. Tests cover MOVS,
STOS, LODS, CMPS, and SCAS at 8-, 16-, 32-, and 64-bit element widths, both
directions, 32-/64-bit addressing, early comparison termination, and a fault
after a completed element. User I/O string operations at elevated IOPL are
outside the fixed CPL 3 / IOPL 0 Darwin profile and this stepping campaign.
System-mode CPU stepping is unchanged.

Mach general-state writes and BSD `PT_STEP` use the same saved TF control.
Clearing TF through Mach overrides BSD step bookkeeping. Darwin captures and
clears the CPU's debug status on exception entry and updates DR6 only when
an x86 Mach debug-state image already exists, following the pinned
[`trap.c`](../../specifications/darwin/xnu-12377.121.6/osfmk/i386/trap.c).
A debug trap does not allocate a previously absent debug-register image.
Ordinary instruction boundaries belong to the CPU; the Darwin personality
reports the post-SYSCALL boundary only after syscall service completes. The
pinned XNU
[`idt64.s`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/x86_64/idt64.s)
selects SYSRET for the covered 64-bit syscall return.

The shared CPU change also reaches Linux and Windows user mode. Linux maps
BS to `TRAP_TRACE` (2), retains the trace status in both ptrace user-register
views, and clears it before a later status-free ICEBP is classified as
`TRAP_BRKPT` (1). Linux v6.19
[`do_syscall_64`](https://github.com/torvalds/linux/blob/v6.19/arch/x86/entry/syscall_64.c)
selects IRET when TF/RF prevents SYSRET, so guest TF steps the first user
instruction after a syscall; forced `PTRACE_SINGLESTEP` syscall reporting
retains its separate existing behavior. Windows preserves TF/RF in the saved
`CONTEXT` and clears the live handler-entry controls before dispatching a
guest exception callback, preventing recursive tracing of that handler.
Windows validation here is local emulation/unit testing, without a native
Windows execution claim.

Native regions are rejected while user TF is armed, including cached entry,
hot promotion, and explicit compilation/execution. A native POPF helper that
would enable TF returns before publishing its stack, flags, or read trace;
direct replay at the exact POPF frontier arms the next instruction. No SMIR
operation, ISA encoding, public ABI, backend/device behavior, or optimizer
rule changes. Debug bookkeeping uses O(1) time and space per instruction;
a TF-controlled REP attempt performs one bounded-width memory element.

`tools/darwin/x86_tf_probe.c` and the byte-identical `x86_tf` fixture assert
one signal at the exact saved PC after NOP, POPF clearing TF, a fast getpid
syscall, and a blocking read. A helper thread waits until Mach thread_info
reports the reader as TH_STATE_WAITING with suspend count 0 before writing
the byte; the signal handler rejects an event before that release. Native macOS 27.2 Rosetta and the debug runner
agree in these four cases. Rosetta differs from the Intel-defined MOV SS
suppression and per-iteration REP behavior: a separate native REP MOVSB
probe copied all three bytes before its first trap. A diagnostic UD2 fault
also reported RF 0 under Rosetta, whereas the implementation's fault-frame
RF expectation follows the Intel manual. These observations are recorded
separately; physical Intel results are unknown. Rosetta is not the parity
oracle for these three architectural cases. The available Xcode debugserver
contains arm64/arm64e slices only, so this campaign does not establish an
x86 debugserver executable workflow.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| XTF1 | Incoming TF selects the instruction's trace event. | Intel Vol. 3B 19.3.1.4 and native NOP/POPF probes. | CPU retirement and native POPF replay. | Enable/clear TF, fault priority, cached native code, and promotion. | A documented encoding or covered native probe reports an extra/lost event or a different PC. | Confirmed for covered CPU, helper, native, and personality cases. |
| XTF2 | Only MOV/POP SS use the relevant debug suppression. | Intel Vol. 3A 7.8.3; shared interrupt inhibition also includes STI/LSS. | Separate ephemeral debug marker. | Same-selector MOV SS, compatibility POP SS widths, STI, and LSS. | Primary semantics or physical Intel evidence contradicts the suppression boundary. | Specification-derived tests pass; Rosetta MOV SS differs; physical Intel unknown. |
| XTF3 | Syscall trace boundaries depend on the personality's return instruction. | XNU idt64.s, Linux v6.19 syscall_64.c, and native Darwin fast/blocking probes. | Darwin post-service trace and Linux first-user-instruction trace. | Blocking replay, normal completion, and Mach disarming. | The covered native read traps before readiness or at a different return PC; a Linux unit reports a syscall-entry trace. | Confirmed for covered return paths; other kernel return paths remain uncharacterized. |
| XTF4 | Defined Intel fault/REP frames govern the core where Rosetta differs. | Intel Vol. 3B 19.3.1.1, explicit partial-state unit expectations, and separately recorded Rosetta diagnostics. | REP PC/count/index/RF and fault-frame RF. | Width, direction, count zero, REPE/REPNE termination, and the next-element fault. | A primary architectural rule or physical Intel trace contradicts an asserted field. | Retained architectural basis; physical Intel execution unknown. |

The frozen x86 TF runner passed all 339 Darwin integration tests serially,
all 2,710 user-mode library tests serially, and the 52-test x86 user-CPU
suite on both arm64 and Rosetta hosts. Ten x86-native stack-flags JIT tests
also passed under Rosetta. The gated TF probe passed 80 native Rosetta and
80 optimized-runner repetitions (320 trace events per campaign), with the
reader observed waiting before release and no early read trap. Host
all-target builds, Clippy, and Linux AArch64 all-target compilation passed.
Linux/Windows native runtime and physical Intel execution were not exercised.
Whole-workspace formatting still differs in six pre-existing unrelated files;
owned-file formatting and whitespace checks pass.

On macOS 27.2, `tools/darwin/ptrace_cs_probe.c` observed the arm64 child's
code-signing status change from `0x22020201` to `0x32020021` after
`PT_TRACE_ME`; its parent's reported flags did not change. The x86-64 probe
under Rosetta observed `0x00000000` to `0x00000020`. The arm64 delta clears
`CS_KILL` (`0x00000200`) and sets `CS_DEBUGGED` (`0x10000000`) and
`CS_INVALID_ALLOWED` (`0x00000020`); the x86-64 delta sets only
`CS_INVALID_ALLOWED`. The pinned XNU [`cs_allow_invalid`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_cs.c)
is conditional on a MAC policy hook. Additional ad hoc probes without the
hardened runtime showed the same transition, while a hardened binary without
`get-task-allow` did not change; a hardened binary with that entitlement did.
For a successful `PT_TRACE_ME`, the tracing path generalizes these samples
to non-platform, non-restricted, non-hardened signatures and to signatures
with `get-task-allow`, and handles the observed zero-flags Rosetta case.
The generalization has not been established for every signature or MAC
policy. If both the cached and newly harvested signatures have a CDHash,
a mismatch prevents the newly observed policy from changing guest flags.
Replacement before the first harvest, or without comparable CDHashes,
remains unknown. On macOS 27.2, a child without `get-task-allow` and with
`CS_RESTRICT` set by its signature or by `csops` receives `EPERM` for
`PT_TRACE_ME` when its connected parent has the same non-root real and
effective UIDs. The tested `get-task-allow` children succeed with
`CS_RESTRICT` and receive the signing-flag transition. These cases are
modeled when the guest signing flags are known.
The parent credentials are published at fork and updated on the parent's
emulated exec. Other credential and restriction combinations remain unknown.
Known guest flags replace the host result for a connected parent's
`CS_OPS_STATUS` query when that host query succeeds; other cross-process
signing queries still use the host. A traced exec publishes its new image's
status before its exec stop.
These flag projections do not implement the accompanying VM-map or
code-signing enforcement changes.

The native CI host on macOS 27.0.1 reports SIP disabled, active CSR flags
`0x6f`, and a successful `csr_check(CSR_ALLOW_TASK_FOR_PID)` (`1 << 2`).
Its hardened-runtime children receive the invalid-page flag transition, and
its restricted children succeed without `get-task-allow`, in both ARM64 and
Rosetta x86-64 observations. The macOS 27.2 development host reports CSR 0
and a denied check; its existing restricted/hardened results remain different.
Both observed hosts have empty boot arguments, numeric real/effective UID 501,
and `security.mac.proc_enforce = 1`. The standalone
[`tools/darwin` probe](../../../tools/darwin/trace-policy.md) preserves the 16
native cases, image/source hashes, raw command results, and the policy context.

Host-services trace preparation now carries a successful read-only CSR debugging
check alongside the image-matched signing flags. For the observed non-platform
profile, that result permits restricted trace admission and the invalid-page
flag projection; otherwise the existing signature/entitlement predicates apply.
The check occurs only after a successful signing observation. Fallback or
CDHash-mismatched observations cannot select this profile. Closed processes do
not query CSR and do not consume host tracing observations. Platform images
retain their existing restrictions.

Assumption D3 is retained: this CSR result selects the observed third-party
debugging profile. A native denial or differing flag transition for that
profile with a successful check falsifies it. The two host samples also differ
in OS revision, so they do not isolate CSR causality or establish every private
MACF policy. No SIP, boot arguments, or host configuration is changed, and
fixture assertions and native test selection remain unchanged. Qualification
of this runtime revision is separate from qualification of the observation
tool and the earlier serial library counts below.

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
| Workqueue threads: a kernel-allocated stack (guard page, 512 KiB, the `pthread_t` above, 12 KiB into its last page on arm64), a pinned thread port, the TSD base, the `workq_threadmask` signal mask (reset on return), and `_pthread_wqthread(self, kport, stacklowaddr, keventlist, flags, nkevents)` with the upcall flags (a servicer of a workloop with a scheduler priority outside the QoS classes, `WQ_FLAG_THREAD_OUTSIDEQOS`); idle threads park and are reused | `workq` | `workq_setup_thread`, `workq_set_register_state`, `workq_thread_reset_pri`, `workq_thread_return` |
| The workqueue kqueue (`kevent_qos` with `KEVENT_FLAG_WORKQ`): knotes queued by QoS in seven buckets (the last the event manager's, for knotes without a QoS), each bucket's thread request, and its servicer receiving that bucket's events and data on its stack | `kevent::workq`, `kevent::call` | `kqworkq_*`, `kevent_workq_internal` |
| Workloops (`kevent_id`): made by ID on first use and freed with their last reference, one thread request made when an event arrives with neither a servicer nor an owner, the servicer's events with the workloop's ID below them, rebinding or unbinding as the servicer parks | `kevent::workq`, `kevent::call` | `kqworkloop_*`, `kevent_id` |
| `kqueue_workloop_ctl`: the parameters' size (`EINVAL` below their version), copy, and version (their size) checked before the command; `KQ_WORKLOOP_CREATE` checks the scheduling priority (1 to 63), policy (timeshare, round robin, FIFO), CPU percent and refill period, then the ID (`EINVAL` for 0 and -1, `EEXIST` for a live workloop), and the workloop it makes with those parameters (its thread request outside the QoS bands for a priority) keeps its reference until `KQ_WORKLOOP_DESTROY` releases it, once (`EINVAL` again, or for a workloop `kevent_id` made; `ENOENT` for none); another command does nothing. With `KQ_WORKLOOP_CREATE_WITH_BOUND_THREAD` the workloop has a thread of its own from the start (`EDOM` past the thread limit), parked until the workloop's events wake it (at the request's QoS, or its priority's band), which services them, parks on the workloop again when it finds none, and ends (the exit upcall) once the workloop is destroyed | `kevent::workq`, `kevent::call`, `workq` | `kqueue_workloop_ctl_internal`, `kqworkloop_get_or_create`, `workq_kern_threadreq_permanent_bind`, `kqworkloop_bound_thread_*`, `workq_kern_bound_thread_*` |
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
rather than reaped after five seconds. A workloop's scheduling policy and
CPU limit are kept but change nothing (one emulated CPU runs every thread).
Work intervals (no port names one:
`KQ_WORKLOOP_CREATE_WORK_INTERVAL` is `EINVAL`) and sync IPC links to
special reply ports (`NOTE_WL_SYNC_IPC` attaches fail with `ENOENT`, as
they do for ports outside an IPC chain) are not provided.

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
| Host signals: asynchronous host signals are the guest's (`rax-user` forwards them), a stop signal's default action stops the host process, and the state inherited across `exec` (ignored signals, action flags, mask) is the host process's. The host catches `SIGCONT` only while the guest does, and otherwise takes its default action as the guest would: a kernel need not report the continue of a process that catches `SIGCONT` to its parent's `waitid(WCONTINUED)` (macOS 27.0 reports none), so a handler the guest never installed would hide its continues; a guest at the default then keeps a blocked stop signal still pending across a continue | `signal::host` | `execsigs`, `psignal_internal` |

Pointer authentication uses RAX's configured QARMA algorithm and guest keys.
Each arm64 image activation initializes five 128-bit keys from checked entropy;
an explicit process seed makes that initialization reproducible. Threads and
fork inherit the task domain; exec creates a fresh domain. B keys enable
return-address signing, while A-key enables follow the arm64e JOP ABI selection.
This is a virtual key-domain model, not Apple's private hardware diversification.

The personality signs exported PC/LR with IA and FP/SP with DA, preserves an
already IB-signed LR, and authenticates or poisons incoming thread-state pointers
according to XNU's kernel pmap interface. Signal frames carry signed pointers,
keyed PC/LR validation tokens, and a signed ucontext pointer in the argument
token. Registered pthread entry points and signal trampolines authenticate before
becoming kernel-selected PCs; the callbacks passed to user code remain signed.
Shared-cache v5 rebasing selects IA/DA and blends the actual guest storage address
when address diversity is set. Each source retains its immutable key context and
owns its page cache; diagnostic file identity does not share signed contents.

Rosetta, the x86-64 test oracle, keeps an `SA_RESETHAND` action installed after the handler runs;
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

POSIX named semaphores (`sem_open`, `sem_close`, `sem_unlink`, `sem_wait`,
`sem_trywait`, `sem_post`; `bsd/kern/posix_sem.c`) are the host's too,
shared by name with every other process, the host checking flags, value,
existence, and permissions. The name's length (`ENAMETOOLONG` from 31
bytes with its NUL) and the descriptor table (`EMFILE`) are checked first,
as XNU does. An open semaphore is a descriptor, not close-on-exec, whose
number is the `sem_t *`; the other calls refuse a descriptor of another
kind (`EBADF`). Since the host thread must not block, `sem_wait` takes the
semaphore when it can and otherwise sleeps, looking again every
millisecond; a signal ends the wait with `EINTR` whatever `SA_RESTART`
says, as a Mach semaphore wait aborted by a signal does, and it is a
cancellation point.

`mach_vm_remap` and `mach_vm_remap_new` (and their `vm_remap` forms) map
the task's own memory a second time (`syscall::mach::remap`, after
`vm_map_remap` and `vm_map_remap_extract`). A shared remap maps the memory
itself: a part of the source that is a shared mapping maps its object, and
a private part first becomes a shared mapping of a new object holding its
contents (as XNU shares an entry's object, shadowing a copy-on-write one
first), so stores through either mapping are seen through the other; a
copy maps private memory holding the contents. The new mapping takes the
source's user tag and the given inheritance. `mach_vm_remap` keeps each
part's protections and reports the strictest of them, rounding the source
as the legacy path does (the start truncated, the size rounded on its
own); `mach_vm_remap_new` returns the data's address (the source's offset
in its page kept, every page the range touches covered), gives the
protections asked for when every part allows them (a copy needs only
readable memory; `KERN_PROTECTION_FAILURE` otherwise, and for a maximum
both writable and executable), and takes the task's read port as the
source for a copy or for memory mapped at most readable. Flags outside
`VM_FLAGS_USER_REMAP`, an empty range, a bad inheritance, and
`VM_FLAGS_RESILIENT_MEDIA` without a copy are `KERN_INVALID_ARGUMENT`; a
range with a hole is `KERN_INVALID_ADDRESS`. Another task's memory is not
reachable. A store through a mapping that is not executable does not make
the emulator drop code it decoded from an executable mapping of the same
memory elsewhere (so a JIT that writes code through such an alias is not
supported).

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
| Code signing (`csops`, `csops_audittoken`) of the calling process: XNU's checks in order (a change to another process refused without root, `EPERM`; the audit token's pid and pid version, `ESRCH`), then what the host kernel concluded of the executable at exec (status flags, code-directory hash, slice offset, identity and team, entitlements in XML and DER, the signature blob, validation category), with each operation's size rules (the 8-byte header with the length and `ERANGE` for a short buffer) and `EINVAL` once the process is invalid; and the flags the process changes (invalid, hard, killable, restricted, those `CS_OPS_SET_STATUS` may set, the installer's and library validation's cleared as XNU allows), a killable process dying of `SIGKILL` when it becomes invalid. Foreign-process signing queries in the host-services profile use the host's answer; the closed profile returns `ESRCH` before forwarding buffers | `codesign` | `csops_internal`, `csops_copy_token` |

In the host-services profile, the executable's signature is the host kernel's
verdict: the first `csops` of an image spawns the executable (the slice the
emulator loaded) suspended on the host, asks it every question, and kills it
before it runs; its `SIGCHLD` is not the guest's. Without a macOS host the process
is an ad hoc, linker-signed program without entitlements. Closed supplied-file
processes retain supplied signing state or that existing fallback; they never
spawn a host executable for signature sampling. Their foreign-process signing
queries return `ESRCH` before host buffer forwarding. The macOS 27
kernel refuses `CS_OPS_CDHASH_WITH_INFO` (`EINVAL`) at every size, so the
emulated process does too. `CS_ENFORCEMENT` and library validation are
reported, not enforced on the emulated process's memory and libraries.

Paths are the kernel's names for the files (`vn_getpath`): symbolic
links resolved, the root overlay's prefix removed, and laid out as
`vn_getpath` leaves them, the path at the start of its field and the copy
it was built as at the end. An image and a mapped file are named when
they are mapped.

In the host-services profile, another emulated process is a host process
running `rax-user`, so what the host says of it beyond its identity,
credentials, status, and resource usage (its name and path, arguments, descriptors, memory, and
threads) is the emulator's. A region's share mode and shared flag follow the kind of
mapping rather than the reference counts of its memory objects: two parts
of one private mapping split by `munmap`, or a region copied by `fork`, are
reported as private, and a shared mapping is shared before any fork. A
descriptor whose file the guest has mapped is reported as shared (the
mapping holds a duplicate of the host descriptor). dyld does not move to
its copy in the shared cache (the kernel maps the shared region at exec,
the emulator when dyld asks, so dyld finds none), so it makes no
registration of its own and the registration the loader records stays
open, where a native arm64 process's is final. A thread's CPU usage,
flags, and sleep time are 0 and its priority the default (31) under the
ceiling a QoS clamp or darwinbg the process inherited sets (the host's for
the emulator's own thread: utility's 20, background's 4), which also lowers
its maximum (63) and the task's priority; `PROC_PIDTHREADCOUNTS` is
`ENOTSUP`, before any thread is looked up, on a host without performance
counters (a virtual machine); `kqueue_dyninfo`'s servicing state is 0.
Setting a child's `TASK_KERNEL_PORT` or `TASK_HOST_PORT` by a spawn port
action, which XNU allows when SIP permits the kernel debugger (for
Mach-on-Mach emulation), is refused (`EINVAL`) on every host.

## Emulated machine

One CPU of the program's architecture: a Haswell-class Intel Mac for x86-64
(`CPU_SUBTYPE_X86_64_H`; `XCR0` enables x87, SSE, and AVX state), an
Apple-silicon Mac for arm64 (`CPU_SUBTYPE_ARM64E`, `PSTATE.SSBS` set for new
threads; pointer authentication uses configured QARMA and task guest keys;
data addresses ignore their top byte, instruction addresses do
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
the boot time, the stack top, the argument limit, the process name, the
calling process's arguments (`kern.procargs` and `kern.procargs2`: the
string area below the stack top as `sysctl_procargsx` copies it, from the
guest's memory as it is now, with its buffer rules, the zeros a short
buffer gets, and the path `procargs` appends), and a few constants the
emulation decides. The metadata nodes (`sysctl.name`,
`.next`, `.name2oid`, `.oidfmt`, `.oiddescr`) cover both, `next` merging
the two walks. Writes are refused (`EPERM`) once the node is found.

For an embedded process, `kern.version` (`CTL_KERN`, `KERN_VERSION`,
OID `[1, 4]`) reports the deterministic kernel identity already used by
Mach `host_kernel_version`, with one terminating NUL. Both numeric and
named queries support size discovery and the normal copy-out bounds;
this allows Intel dyld to identify the release kernel without host
services. Other host-owned nodes remain unavailable in the closed
profile. Processes with host services keep the host's `kern.version`.

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
group lookups, preferences, the keychain list, notifications, the
pasteboard, power management, IOKit, CoreServices' file IDs, and Launch
Services: `id`, `whoami`, `defaults`, `security`, `pbcopy`, `pbpaste`,
`pmset`, `ioreg`, `mdls`, `sips`, `textutil`, and `osascript` behave as
natively), and the code-signing queries (`codesign` signs and verifies).
Calls not implemented are answered with `ENOSYS` (or `KERN_FAILURE` /
`MIG_BAD_ID` for Mach) with a warning under `--strace` or
`RAX_DARWIN_WARN`; among them are `map_with_linking_np` (dyld then applies
its fixups itself) and `work_interval_ctl`. `kill` of the process group reaches this process only through
host-signal forwarding, and `kill(-1, sig)` signals only this process.

## Evidence

`cargo test --no-default-features --features x86_64-suite,smir-jit --test user_darwin`

- `fixtures`: the C programs in `tests/fixtures/user/darwin/src` are built
  for arm64 and x86_64 and must produce the standard output and exit status
  of their native runs (x86_64 through Rosetta), including the fatal
  `EXC_GUARD` of `guard_fatal`, the handlers, frames, masks, timers,
  faults, and final `SIGTERM` of `signals`, and the thread creation,
  joins, cancellation, contended synchronization, and main thread's QoS
  of `threads` and `threads_sync`, the filters and delivery protocol of `kqueue`, the
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
  parent and its forked and spawned children), the IOKit registry,
  matching, and property reads of `iokit`, the shared aliases, copies,
  reported and given protections, rounding, placement, and refusals of
  `mach_vm_remap` and `mach_vm_remap_new` in `remap`, and in
  `coreservices` (in the parent and a spawned child) the file-ID universe
  `coreservicesd` maps into the task, Launch Services lookups, and the
  session's shared memory page Launch Services maps and remaps, and the
  checks, lifetime, and SPI of `kqueue_workloop_ctl` and libdispatch
  workloops with a scheduler priority in `workloop_ctl`, and the bound
  threads of workloops (made, woken, parked, ended), the QoS their
  servicers run at, and libdispatch's bound and priority workloops in
  `workloop_bound`, and in `codesign` what `csops` reports of the process
  (flags, hash, offset, identity, team, entitlements, blob, category, and
  each size rule), the flags it changes, audit tokens, another process's
  answers, a killable process invalidated, and a copy `codesign` re-signs
  with an identifier, entitlements, and the hardened runtime, reporting on
  itself, and in `procargs` the calling process's `kern.procargs2` and
  `kern.procargs` (count, path, arguments, environment, size queries,
  buffer rules, a short buffer, the appended path, an argument changed in
  place, a forked child), the POSIX named semaphores of `psem` (the name
  limit, flags, value, and errors; counting; waits woken by another thread
  and another process, interrupted by signals, and cancelled; descriptors
  of another kind; unlinking), and in `shared_wait` threads sleeping on the
  same descriptor (in `poll` and `read`, woken by this process or a child)
  and a kqueue watching one socket both ways. `procinfo`, `kqueue`, and
  `mk_timer` run a second time with both runs clamped to utility QoS, as
  GitHub's macOS runners start jobs (priorities follow the clamp; timers
  and sleeps are coalesced, which the timer fixtures' critical timers and
  windows absorb).
- `programs`: `/bin/echo`, `/usr/bin/true`, `/usr/bin/false`, and `/bin/cat`
  likewise, `/usr/bin/env` running a program (and failing to), and
  `/bin/sh -c` with external commands, a command substitution, and an exit
  status (`/bin/sh` itself execs the shell it stands for).
- `generators`: the checked-in tables equal what the generators produce
  from the vendored sources (`--check`).
- `layouts`: the signal-frame and thread-state sizes the personality uses
  equal the SDK's, measured by a probe compiled against it.

The native run is an oracle only on the release whose kernel the personality
reproduces: on a host of another macOS release (whose SDK may also lack calls
the fixtures make) the comparisons report themselves skipped, as they do
without a macOS host or, for x86_64, without Rosetta. With
`RAX_USER_DARWIN_REQUIRE_ORACLE` set each such skip fails instead; push CI
runs the target that way on a macOS 27 runner. Both runs of a comparison start
with standard input, output, and error alone (inherited descriptors are closed
at exec, as a guest starts with the emulator's three standard descriptors)
in a process group of their own, which is killed when the run, or a process
still holding its output, outlives the timeout.
`RAX_USER_DARWIN_RUNNER` can select a copied engine executable for an oracle
campaign; otherwise the harness uses Cargo's `rax-user` output. Pinning a
copy and recording its hash prevents concurrent builds from changing the
engine halfway through a long comparison run.

The spawn waitid and timer independence fixtures avoid fixed scheduling
latency assumptions for their observations. The spawn waitid case waits for child post-fork readiness before
observing default SIGCONT behavior. The timer independence case receives
from both timer ports without comparing the other port's instantaneous
queue count: native utility-QoS runs observed both 0 and 1 at that point
across the 200 ms deadline gap. That medium-impact fixture instability did
not identify a timer implementation difference; both timers delivered in
the native and emulated runs.

Library tests under
`src/user/darwin/` cover the name space, message trailers, commpage and
stack layout, slide info, sysctl walks, values, and copy-out, the
host-information flavors, the host regions a service maps into the task
and the memory entries of them,
exception-to-signal translation, exception requests and reply checks,
signal actions, interval-timer
arithmetic, the thread-state flavors, psynch sequence arithmetic and queue
order, thread QoS requests, the pthread priority encoding, work-queue
admission and request selection, interpreter-line parsing, fat and thin
grading with binary preferences, `NCARGS` accounting, `execsigs`,
`fdt_exec`, the spawn layouts, and entitlement lookup in a signature.

### Closed signing and descriptor lifetime qualification

The closed-profile signing regressions exercise both guest ABIs with an existing
host image and check that trace preparation keeps the existing fallback without
sampling that image. A foreign status query with an unmapped output address
returns `ESRCH` before host buffer forwarding. Supplied signing state remains
covered by the existing trace-preparation test. These tests enforce the existing
`host_services = false` boundary; the host-services signing and trace-admission
policy is unchanged.

The Unix transport fixtures retain the original reference to a transferred
socket until the receiver adopts it. They still close the intermediate transport
before receipt in the handoff case and still check the adopted endpoint after
the original reference closes. A separate regular-file regression closes the
sender before flushing, then verifies the received file type, 8-byte length, and
exact `snapshot` contents. Production blob transfers therefore retain their
close-before-receipt check. Frame limits, receive budgets, and assertions are
unchanged.

On macOS 27.2 ARM64, ten consecutive parallel Darwin library runs passed all
420 selected tests; the full serial library run passed 8,788 tests with two
existing ignores. On the Linux x86-64 container running through host translation,
the full serial library run passed 8,778 tests with two existing ignores. Both
platforms passed all 191 C API tests, all-target compilation, and four installed
program comparisons (`true`, UTF-8 `printf`, a shell builtin, and a shell exec),
with matching output, empty standard error, and exit status 0. These finite
runs do not establish native x86-64 execution or resolve the separate macOS 27
native-oracle failures for hardened-runtime and restricted trace admission.
The macOS transport selection also passes all 16 tests with Cargo's default
features enabled. That selected run does not qualify the complete core suite
under those features; Assist's embedded dependency keeps its defaults disabled.
On native Windows ARM64, the five signing tests and three parallel Darwin
selections of 185 tests each pass, as do all 191 C API tests. The Unix transport
selection applies to macOS and Linux; it is not compiled on Windows.

### Sampled same-host reclaim pressure

The host-services profile reads the fixed read-only dispatch-pressure sysctl for
reclaim deadlines and accounting. Normal1 selects10s/10percent,warning2 selects
1s/5percent and critical4 selects0s/1percent. A zero period drains current bytes
before WMA division. Embedded profiles never query that host node and retain
the normal model; unavailable/malformed reads also retain that fallback. Active
swapping overrides,custom tunables and asynchronous guest-ring pressure walks
remain separate limitations. See the native-reclaim-pressure corpus for native
timestamp brackets,Apple source provenance and completed validation records.
