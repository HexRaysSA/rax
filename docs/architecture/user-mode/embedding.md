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

## Portable atomic object storage

`user::mm::SharedWords` owns anonymous atomic storage independently of a guest
personality. Linux `eventfd`, timer, memfd-seal and signal-mailbox objects use this
adapter. Unix uses `MAP_SHARED | MAP_ANON`; Windows uses an unnamed, non-inheritable
paging-file section and closes its handle after mapping the view. No filesystem
path is created. Windows section lifetime and zero initialization follow
[CreateFileMappingW](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw)
and [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile).

For `n` words, the allocation size is `max(n, 1) × sizeof(AtomicU64)` bytes.
Checked multiplication and the `isize::MAX` slice bound reject oversized requests
before any allocation. Zero words expose an empty slice while retaining a valid
mapping pointer. Access is O(1); mapped storage is O(n). Native CI runs the adapter's
zero-initialization, overflow, alignment and concurrent-increment tests on Windows,
macOS and Linux. A Unix-only fork test validates that the original cross-process
sharing contract survives the extraction; it does not claim Windows fork support.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SW1 | The mapping remains alive after closing its Windows section handle. | Microsoft documents that mapped views retain internal references and that view and handle can be closed in either order. | Atomic word lifetime. | Writes from four threads after handle closure, followed by destruction. | Native Windows `user::mm::shared_words::` tests fail or fault. | Documented; native CI validation required. |
| SW2 | Extracting allocation leaves Unix fork sharing intact. | Same anonymous shared mmap flags; all consumers retain atomic access. | Linux open-description state after fork. | Child stores a word, parent waits and observes the store. | `unix_mapping_remains_shared_after_fork` fails. | Tested on macOS; native Linux CI validation required. |

High-impact remaining requirement: this adapter alone does not provide the Linux
personality on a Windows host. Descriptor readiness, external-service adapters and
shared syscall compilation still require the broader port described above.

## Portable host clocks

`user::clock::read` separates the four host clock domains needed by the Linux
personality from the Unix service adapter. Unix uses the corresponding
`clock_gettime` IDs. Windows uses `GetSystemTimePreciseAsFileTime` for realtime,
`QueryPerformanceCounter` with its boot-fixed frequency for monotonic time, and
`GetProcessTimes`/`GetThreadTimes` for process/thread CPU time. Native errors are
returned as `io::Error`; Linux's existing infallible host wrapper fails explicitly
if a required host clock unexpectedly fails instead of substituting zero.

Windows `FILETIME` units are 100 ns. The Unix epoch offset is
`(369 × 365 + 89) d × 86400 s/d × 10⁷ ticks/s = 116444736000000000 ticks`.
Signed 128-bit conversion normalizes pre-epoch dates and avoids overflow when
adding user and kernel times. For performance-counter ticks `t` and frequency
`f > 0` Hz, the integer result is `floor(t × 10⁹ / f)` ns; conversion error is
less than 1 ns. The representation does not assert nanosecond clock accuracy.
All conversions take O(1) time and space.

Primary contracts:
[precise wall time](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime),
[performance-counter frequency](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency),
[process accounting](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[thread accounting](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadtimes).

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CK1 | Native CPU-clock domains distinguish the calling thread from the process. | Separate POSIX clock IDs and separate Windows accounting APIs. | Thread CPU timers and process CPU timers retain distinct sources. | A joining thread remains idle while another thread consumes at least 50 ms CPU. | `native_thread_clock_excludes_another_threads_work` charges worker time to the joining thread. | Confirmed on macOS; Windows/Linux CI validation required. |
| CK2 | Integer conversion covers the entire native counter domains. | Widened arithmetic and positive-frequency validation. | Normalized timestamps without overflow or sign loss. | Both signed counter extrema, maximal FILETIME sums, fractional division and pre-epoch timestamps. | Conversion regressions fail or a result has nanoseconds outside `[0, 10⁹)`. | Covered by host-independent boundary tests. |

The clock adapter changes no guest syscall IDs, guest time layouts, CPU execution,
C ABI, persistence, or Assist tool schema. It is another dependency of the Windows
host port, not a claim that the full Linux personality is available there.
