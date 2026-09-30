# Closed Linux process profile

`LinuxConfig::embedded(exec_path, argv, envp, input, console_capacity)` builds a
profile with `host_services = false`, supplied immutable files, captured streams,
a 128 MiB guest arena (134217728 bytes), seed 0, `/` as cwd, and disabled file
notifications. The constructor does not inherit the application's cwd, environment,
stdio, credentials, supplementary groups, umask, PID, parent PID or hostname.
Arguments and environment are explicit inputs. The main image and ELF/script
interpreters follow the supplied namespace described in [files.md](files.md).

Spawn rejects combinations with a host sysroot, missing supplied namespace,
host streams, unseeded entropy, host process creation, an IPC directory,
notifications, or syscall tracing before loading the image or opening resources.
The virtual process is PID 100, parent PID 1, UID/GID 0, with no supplementary
groups, umask `0022`, and hostname `rax-embedded`. Each instance has its own
process/thread namespace; guest IDs do not identify host processes.

`src/user/linux/embedding.rs::permits` is the explicit ABI-independent syscall
set. All five Linux guest ABIs use the gate before their native or compatibility
handler. Known calls outside it return `EPERM`; unknown numbers remain `ENOSYS`.
The closed profile supports supplied-file reads and metadata, private mappings,
process-local memory, emulated threads and futex continuations, signal handlers,
local signals, clocks/timers, and emulated event descriptors. Network endpoints,
external tracing, System V/POSIX IPC namespaces, inotify, AIO/io_uring, host
process creation and process-group mutation are denied. `clone` requests for a
new process retain the existing `processes = false` result (`ENOSYS`); thread
clones use the shared guest scheduler.

Guest `SIGSTOP` and other default stop signals park the guest process and make
bounded execution return `Blocked`. `SIGCONT` clears that state, and `SIGKILL`
can terminate a stopped guest. These operations do not call host `SIGSTOP` or
terminate the host. The closed scheduler does not drain the host's signal or
child-event queues or poll external tracer links. Disabled IPC state cannot
create a directory or acquire a namespace lock. Synthesized inotify limits do
not read the host's `/proc`.

This profile still uses host memory allocation, internal anonymous readiness
objects and clocks. A seeded random source does not make scheduling, wall time,
CPU instructions or the entire execution deterministic. The arena bound covers
guest memory; it is not a total bound on all emulator allocations. This is an
emulator service policy, not an OS containment boundary.

Use `LinuxProcess::run_slice` for cancellable embedding. Its budget counts
scheduler turns, not retired instructions or elapsed time. Stopped or waiting
guests preserve their continuations for later calls. The unbounded `run` method
retains its existing waiting behavior.

## Validation and surfaces

The five-ABI tests exercise virtual identity, output capture, service denial,
configuration rejection, stop/continue/kill and real guest exit instructions.
An AArch64 test checks guest thread round-robin ordering and futex blocking.
The existing supplied-file and captured-console tests cover path collisions,
interpreter lookup, mappings, descriptor lifetime and output bounds.

This change is Rust Linux-personality policy and lifecycle work. CPU encodings,
C ABI, Assist tool schemas and package inputs are unchanged. The current Linux
personality is compiled on Unix hosts; native Linux/macOS CI exercises this
profile through the existing `closed_` regression filter. Windows-host Linux
runtime portability is still required before cross-platform C API exposure;
a Windows build of the portable modules does not validate this personality.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| LE1 | Every permitted call stays within supplied or process-local objects. | Explicit syscall set, captured descriptors, no host namespace or process creation, no host signal collection. | Closed profile dispatch and lifecycle. | Five ABIs, legacy socket/IPC multiplexers, AIO/io_uring, invalid pointers to denied services, repeated stop/continue/kill. | Run `user::linux::tests::embedded::`; a host-backed descriptor/path, external operation, inherited identity or host stop falsifies the boundary. | Confirmed on macOS by the five-ABI tests; native Linux evidence tracked separately. |
| LE2 | Guest threading and bounded execution survive removal of external services. | Existing shared scheduler, emulated clone and futex machinery. | Usable process execution rather than only denied syscalls. | Real exit instructions on five ISAs; two-thread round-robin; indefinite futex wait. | The embedded execution tests must reach cached exit 37 or `Blocked` without losing threads or continuations. | Confirmed on macOS by execution, threading and futex tests. |

High-impact remaining scope: Windows-host Linux execution and Darwin's closed
profile are not yet exposed through the C API. Medium-impact limitation: dynamic
programs requiring writable files, pipes, child processes or denied services
cannot complete under this immutable profile. Their denial is explicit; it is
not reported as successful emulation.
