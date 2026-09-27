[← Documentation home](../../README.md)

# User-mode (process-level) emulation

`rax::user` executes guest programs and their processes without constructing a
machine. It supplies a guest address space, unprivileged CPU adapters, and an
operating-system personality. `rax-user` is the command-line front end: an ELF
program runs under the Linux personality (see
[Linux programs](../getting-started/linux-programs.md) for build and usage), a
Mach-O program under the [Darwin personality](user-mode/darwin.md).

```text
rax-user -> user::linux  -> user::{image,mm,cpu} -> ISA core
         -> user::darwin -> user::{image,mm,cpu} -> ISA core
```

| Module | Responsibility |
|---|---|
| `user::image::elf` | ELF parsing and acceptance |
| `user::image::macho` | Mach-O and fat-file parsing, slice grading, and XNU load planning |
| `user::mm` | VMAs, page backing, faults, and code invalidation |
| `user::cpu` | Unprivileged execution and architectural exits |
| `user::linux` | Linux loading, ABI conversion, syscalls, scheduling, and signals |
| `user::darwin` | macOS loading, `fork`, `execve` and `posix_spawn`, BSD system calls, Mach traps and messages, MIG kernel servers, threads and psynch, kqueues, work queues and workloops, signals |

## Runtime topics

| Topic | Detailed reference |
|---|---|
| Memory and CPU execution | [Address spaces, shared objects, faults, adapters, and cache invalidation](user-mode/core.md) |
| ABI and loading | [ELF, initial stacks, syscall dispatch, and i386 compatibility](user-mode/linux-abi.md) |
| Processes and scheduling | [Threads, fork/exec/wait, pidfds, futexes, and rseq](user-mode/processes.md) |
| Signals and timers | [Fault conversion, signal frames, forwarding, and timer delivery](user-mode/signals.md) |
| Files and notifications | [Descriptions, metadata, attributes, locks, and inotify](user-mode/files.md) |
| Descriptor I/O | [Event descriptors, epoll, splicing, and Linux AIO](user-mode/io.md) |
| Networking and IPC | [Sockets, netlink, interfaces, System V IPC, and message queues](user-mode/networking-ipc.md) |
| macOS programs | [Darwin personality: exec, fork and spawn, kernel entry, Mach IPC, MIG servers, threads, kqueues, work queues, signals, process information, sockets](user-mode/darwin.md) |
| Tracing and seccomp | [Tracer links, stops, register sets, stepping, events, and filters](user-mode/tracing.md) |

## Address spaces

The VMA map defines mappings, permissions, and backing. A radix page table
caches populated frames in an arena that commits host memory on demand.
Shared mappings refer to their host object's pages. Mapping and executable
page changes produce an invalidation log that CPU adapters consume before
resuming guest code.

[Memory details](user-mode/core.md#address-spaces) cover fault classification,
shared extents, memfd seals, memory controls, and process-memory access.

## CPU adapters

| Guest ABI | Privilege | System-call entry |
|---|---|---|
| x86-64 | CPL 3 | `SYSCALL` |
| i386 compatibility | CPL 3, IA-32e compatibility mode | `INT 0x80` |
| AArch64 | EL0t | `SVC` |
| RV64 | U-mode | `ECALL` |

The Darwin personality uses the x86-64 and AArch64 adapters with XNU's
conventions (`SYSCALL` with a class in `RAX[31:24]`; `SVC #0x80` with the
call in `X16`).

Adapters expose architectural exits to the personality and use the process
address space for memory. They clear exclusive reservations when leaving
guest code. [CPU contracts](user-mode/core.md#cpu-adapters) specify register
state, exception reporting, execute permissions, and host-time counters.

## Linux personality

The behavior reference is the vendored
[Linux 6.19 source](../specifications/linux/kernel-6.19.provenance.md).
Unless a section explicitly describes i386, syscall, signal-frame, thread,
and tracing coverage refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`).
The i386 conversion table is a separate, partial ABI.

Guest threads share one emulated CPU per process. Guest child processes are
host processes; this scheduler does not add SMP to the machine runtime.
Files, sockets, and IPC can use host resources, and `--sysroot` is a path
overlay. Host and ABI limits are listed in
[Status and limitations](../reference/status-and-limitations.md#required-user-mode-qualifications).

The [ABI reference](user-mode/linux-abi.md) describes program construction and
syscall conversion. The runtime topics above describe each subsystem's state
and transitions. The Linux personality is separate from the C engine ABI.

## Darwin personality

The behavior reference is the vendored
[XNU 12377.121.6 source](../specifications/darwin/xnu-12377.121.6.provenance.md);
programs run against the host's macOS user space. The
[Darwin reference](user-mode/darwin.md) describes process construction,
`fork`, `execve`, and `posix_spawn`, kernel entry, Mach IPC and the MIG
servers, the shared region, sockets, process information, the emulated
machine, and the current status.

## Evidence

The [validation inventory](../development/testing/user-mode.md) maps each
contract to its unit tests, recorded fixtures, and whole-program comparisons.
Its [interpretation boundary](../development/testing/user-mode.md#interpretation-boundary)
distinguishes decoded output agreement from independent architectural or
whole-system conformance. Test commands and oracle prerequisites are recorded
there rather than embedded in the runtime description.
