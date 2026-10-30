# Software SMP debugger control

The software x86 debugger exposes one RSP thread per configured CPU. Thread IDs
are the CPU slot plus one: CPU 0 is thread 1, CPU 1 is thread 2. Register queries
and writes use the selected CPU; stop replies identify the CPU that stopped.

Previously enumeration returned only thread 1, `H` selections were ignored,
register access and legacy stepping selected CPU 0, and breakpoint/cache changes
were applied only to CPU 0. Three retained real TCP regressions reproduced the
first defects before production edits.

## Use

Build with `--features debug` and start the emulator with `--vcpus 4`,
`--gdb 1234` and `--wait-gdb` alongside the normal guest-image arguments.
Connect using the matching guest architecture and symbols:

```gdb
target remote localhost:1234
info threads
thread 2
set scheduler-locking step
stepi
info registers rax rip fctrl
```

Startup still determines whether an AP is online. A configured CPU can be
inspected while it waits for startup; stepping an offline CPU is rejected.
`set scheduler-locking step` requests that other CPUs remain parked while the
selected CPU steps. Without locking, a client's compound resume request may
continue peer CPUs. Internal execute breakpoints cover every CPU without
rewriting guest instruction bytes. Detach/disconnect clears debugger-owned
breakpoints and stepping, then resumes normal scheduling.

## State and protocol boundaries

The VMM owner applies complete resume plans before entry. Invalid thread IDs or
malformed actions do not publish a partial plan. Ordered `vCont` actions use the
first matching action; unmatched CPUs remain stopped. Interrupt delivery respects
that execution mask. A connection barrier separates old asynchronous events from
new-client responses. A completed I/O instruction is serviced before its debug
stop is published.

The amd64 description defines its flags type and required x87 core registers.
The bank contains exactly:

- integer registers: 16 * 8 B + 8 B RIP + 4 B EFLAGS + 6 * 4 B segments = 164 B;
- x87 payloads: 8 * 10 B = 80 B;
- x87 metadata: 8 * 4 B = 32 B;
- total: 276 B, or 552 hexadecimal characters.

Software x87 reads use exact 80-bit payloads and logical TOP mapping. Single
FSTAT writes change TOP without rotating physical payloads. The amd64 pointer
view preserves both 32-bit halves of each represented 64-bit pointer. Integer
writes preserve unrelated private state; x87 installation retains the new
materialized integer flags. Hardware banks without an export contract are
reported unavailable rather than filled with invented values.

A breakpoint setter that fails after mutation is included in compensation.
Failed compensation latches a VMM entry/capture failure. This algorithm is tested
with substituted setters; it is not evidence of native SDK failure behavior.

Primary protocol references: GNU GDB's [packets](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html),
[thread queries](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html),
[stop replies](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Stop-Reply-Packets.html),
and [required i386/amd64 features](https://sourceware.org/gdb/current/onlinedocs/gdb.html/i386-Features.html).

## Validation and remaining requirements

The qualification records exact source hashes, commands and test counts. Tests
exercise real TCP checksums, the VMM loop, two/four CPUs, register writes,
compound resume rejection, AP breakpoints, x87 state and reconnects. An installed
GDB independently enumerates, selects, steps and writes an AP. Its external case
is explicitly included in the dedicated CI job; missing GDB fails that job.

The first client test was invalidated: GDB continued after a failed Python
assertion and printed a later marker. The corrected test uses one assertion
sequence, requests scheduler locking, rejects XML/Python errors and prints its
marker only after all assertions. The old output remains in the evidence set.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| D1 | CPU slots remain stable during a connection; RSP IDs identify those slots | 2/4 CPUs, invalid/zero/all IDs, per-CPU values, AP stops | Selected software profile tested |
| D2 | Control is applied at the single-owner VMM boundary | Selected steps, pending interrupt/I/O regressions, compound rejection and reconnects | Selected software profile tested |
| D3 | Independent-client success requires the whole command sequence | Require a final marker from one assertion block and reject target-description/Python errors | Earlier acceptance falsified and replaced |

High-impact remaining work: debugger memory packets still use the existing
physical RAM view; per-CPU virtual translation remains required. Complete live
GDB-session checkpoint binding/restoration is not implemented by this runtime
change. Other target register descriptions, native bounded entry/debug overlays
and SDK failures, positive guest-OS signal delivery, clocks/replay and physical
Intel qualification remain open within the original four-finding objective.

Resume planning takes O(C*A) time and O(C) storage for C CPUs and A actions.
Breakpoint publication/compensation takes O(C) calls per address. Core register
packet size and x87 conversion storage are fixed.
