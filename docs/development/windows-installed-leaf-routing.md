# Installed Windows leaf tests and process CPU routing

A Windows AMD64 process on an ARM64 kernel can start in the paired ARM64
native-loader context. `WinCpu::run` deliberately retains the active decoder;
it has no module or private-memory ISA classifier. Tests that jump from that
cold state directly to an x64 installed NTDLL leaf must use the same routing
boundary as the process scheduler.

`process::sched::run_cpu` owns that boundary. It selects the existing routed,
guarded or ordinary CPU entry without changing the scheduler's instruction
budget. Process-scoped installed-leaf tests use it for their instruction
slices. Direct architectural CPU tests retain their raw entry points.
No service results, stack assertions, memory assertions or instruction budgets
are relaxed by this change.

The native startup context layout derives from `native_start::kernel_arch`,
which uses the selected native kernel machine. The compiled process ISA does
not determine whether the saved startup context is ARM64 or AMD64.

The private EC thunk fixture models an AMD64 call, rather than a native ARM64
CONTEXT resume. It copies the complete canonical x64 state into a fresh AMD64
CPU and retains the thread's CHPE binding before calling its two private EC
functions. Normal process routing then enters the installed compiler thunk and retains all original return-value,
stack, instruction-budget and immutable-thunk assertions.

## Measured baseline

The exact current Windows x64 library image reproduces both original failures:

| Test | Native PID | Creation FILETIME | Native exit |
| --- | ---: | ---: | ---: |
| Cold startup context | 1340 | 134390319159532650 | 101 |
| Private EC thunk call | 7724 | 134390319247326608 | 101 |

Both run one test, fail one, ignore zero and filter 12,981. The executable has
SHA-256 `e5895dd2a3e701d76352907ec0afba743224c55fa16e98e58347553eeae6f297`.
These are native child exits, independently recorded from the observer.
An independent public-API probe also demonstrates a cold paired CPU decoding
an x64 `NtYieldExecution` entry as ARM64, while the identical plain x64 CPU
retires the entry's three-byte instruction correctly.

The QEMU scalar-round abort, Windows kernel 29704 mapped-filename profile,
x86 license-value frontier and floating-point discrepancies remain separate
qualification limits. This harness correction does not change those contracts.
