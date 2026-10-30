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

The VMM owns its listener and active socket. Destruction cancels owner-response
waits, shuts down a blocked socket read and joins the worker before releasing
guest resources. The port can be reused immediately, including when no client
connected or the client is waiting for attach or continue. Loss of the server's
command endpoint removes its stop mask and debug controls before another CPU
entry; a terminal debugger failure returns before any blocking command wait.

Whole-VM checkpoint import preserves the current target GDB session: selections,
memory mode, breakpoints and resume/step policy remain current. Software x86
replacement CPUs bind that session's host controls before publication. A target
with no session does not inherit saved host controls. If binding fails, the
prepared candidates are discarded. An import that would make a pending step's
CPU offline, or leave a current running plan with no runnable CPU, is rejected
before preparation. Guest TF and architectural registers remain
part of the imported guest state. Raw CPU-context imports, including the C API,
continue to import their represented debugger payload exactly. Native in-place
restore and native guest-TF/host-step ownership remain separate requirements.

Private CPU records can also contain pending GDB stop notifications. Raw imports
retain them, while session binding discards source `GdbStep`/`GdbBreakpoint`
notifications so they cannot complete a current request without guest progress.
Guest exceptions, natural INT3 and pending device exits retain their imported
state. This distinction is covered by typed context and actual instruction-step
tests, plus a public-API counterexample using an admitted context payload.

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

## Selected-CPU memory

With software x86, `m` and `M` resolve the selected general CPU's linear address
through its current paging state. The inspector does not execute guest accesses,
set page-table accessed/dirty bits, fill guest TLBs, deliver faults or retire
instructions. Debugger writes can modify an ordinary RAM page through a guest
read-only mapping. The complete packet must translate and pass backing, host
permission and device-hole checks before any byte is published. Writes invalidate
all CPUs' derived x86 code/translation caches and use the shared tracked-writer
boundary, including exclusive-monitor invalidation.

The software view includes the emulator's modeled overflow RAM backing above
the configured RAM size. A regression executes a guest load through that backing
before comparing debugger access. Registered MMIO ranges remain excluded. When
the software CPU has PCI routing enabled, the entire PCI MMIO aperture is
excluded, including unassigned space that the CPU reads as open bus. Tests
execute that guest read and verify that debugger access cannot expose its shadow
backing. Native Intel inspection remains bounded by its registered RAM window.

The default view is virtual. Explicit physical inspection uses the documented
QEMU vendor packets:

```gdb
maintenance packet qqemu.PhyMemMode
maintenance packet Qqemu.PhyMemMode:1
x/8bx 0xa000
maintenance packet Qqemu.PhyMemMode:0
```

A new connection resets physical mode. Malformed declared `M` lengths and
noncanonical, nonpresent, reserved, oversized or device-backed ranges return an
RSP error. A rejected cross-page write publishes no RAM prefix. An unexpected
cache synchronization or admitted RAM publication failure fences further entry,
later writes, all represented checkpoint capture APIs and checkpoint import.
The failure remains latched on that VMM owner.

GNU GDB can send an any-thread selector before ordinary memory requests. RAX
retains the selected general CPU for that selector. In the independent QEMU
reference run it selected CPU 0 instead; the raw trace and failed candidate
observations are retained. The reference harness therefore sends an explicit
CPU selector immediately before each memory packet. Its actual two-CPU guest
also executes loads through both CR3 roots, independently of the debugger.

Run the independent reference with installed LLVM, QEMU and Python-enabled GDB:

```sh
python3 -B tools/execution/x86_debug_memory_oracle.py \
  --work-dir /path/to/empty/evidence-directory \
  --scratch-dir /path/to/scratch \
  --llvm-bin /path/to/llvm/bin --gdb /path/to/gdb
```

The harness records commands, binary/source checksums, raw GDB packets and both
CPU observations in `manifest.json`; it preserves a failure manifest on errors
and removes its temporary guest objects, ELF and socket. It stops only its own
QEMU child. The ready bytes and guest load records must prove that both CPUs ran.

The shared read-only x86 walker also serves Intel HVF exit inspection. The HVF
debug adapter reads actual SDK paging registers and cached legacy PAE PDPTEs;
fallible TLB invalidation must succeed before data publication. Target
compilation does not qualify SDK execution. Software legacy PAE inspection
requires cached state that its current runtime does not provide and returns an
explicit error. Other CPU adapters retain their prior untranslated view.
ROM/device debugging, other target descriptions, native GDB-session checkpoint
binding, native overlays/SDK failures, positive guest-OS signals,
clocks/replay and physical Intel qualification remain high-impact requirements
within the original four-finding objective.

Primary references and retrieval hashes are retained in
[references/provenance.json](references/provenance.json), including
[QEMU's memory modes](https://www.qemu.org/docs/master/system/gdb.html#examining-physical-memory)
and [GNU memory packets](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

Resume planning takes O(C*A) time and O(C) storage for C CPUs and A actions.
Breakpoint publication/compensation takes O(C) calls per address. Core register
packet size and x87 conversion storage are fixed.

The cache-failure regression reproduced a separate checkpoint bypass: all three
base/CPU-set/full-bundle capture APIs accepted a globally failed debugger owner.
The corrected early admission check precedes checkpoint locks and restore
preparation, and coordinator entry checks it before routing platform requests.
Tests substitute failures at both the first and last CPU invalidation callback;
RAM remains unchanged and capture, import, later writes and entry are rejected.
This qualifies the VMM policy with substituted callbacks, independently of SDK
error-path execution.

A packet with N data bytes and P touched pages requires at most four wide
page-table reads per page in the tested long-mode profile. Planning uses O(P)
storage plus the O(N) output buffer; hole checks add O(P*H) time for H registered
device ranges. Cache invalidation visits all C CPUs and clears their derived
x86 entries. Scatter publication holds one writer-domain lock across all spans;
exclusive-monitor checks cannot observe a partially published packet.

Malformed Unicode in register/memory payloads is rejected before owner mutation;
an unknown Unicode command receives the unsupported response. Hex payloads
require ASCII hex digits in every pair. Trace previews truncate only at UTF-8
boundaries and never alter packet bytes or checksums. Hex decoding takes O(N)
time and O(N) storage for N input bytes. Binding C CPUs with B total internal
breakpoint entries takes O(B + C) expected insertion time; exporting sorted sets
adds the sum of O(b log b) per CPU. Worker shutdown has no guest callback under
its socket-control mutex.

Current-session assumptions, baseline failures, complete-suite results and
remaining native requirements are recorded in
[session-qualification.json](session-qualification.json). The earlier memory
qualification remains a separate historical source and test boundary.
