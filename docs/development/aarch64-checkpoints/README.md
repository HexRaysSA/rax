# AArch64 private checkpoints

The software adapter emits backend kind `5`, inner tag `RAXA6402` (with `RAXA6401` legacy import). The core
record retains raw integer/SP banks, modeled PSTATE and mixed-width state,
SIMD/FP/SVE state, complete system-register and MMU configuration, counters,
wait/event/pending-exception state, debug state, and pending native faults and
JIT policy/history. Host memory, translation, UART, controller and IRQ-line
identities remain target bindings. Compiled code, hot counters and code-page
bindings are rebuilt cold; pending faults survive cache invalidation and are
delivered before another instruction, clock advance or interrupt poll.

The adapter adds ordered memory observations, pending user traps and retirement
adjustments, shutdown/power flags, diagnostic history, and the physical exclusive
reservation. Independently owned GICs carry their state; clustered CPUs use the
one shared GIC/PSCI graph. CPU power flags are checked against that graph.

A modern restore prepares all CPU records and validates their public/private
projections before live mutation. The controller/device locks precede the RAM
writer lock. RAM is restored first, then admitted source reservations and CPUs;
the RAM boundary remains held until outer shared-controller and PCI publication
has finished. A detached replacement rejects execution until publication.
Capture uses the corresponding controller/endpoint/RAM boundary.

Execution extension `RAXEXE03` adds the PL011 receive FIFO and all represented
controls. `RAXEXE01` and `RAXEXE02` retain their original encodings and decoders.
C API contexts now emit format `8` with the private record and all mapped RAM;
format `4` and frozen AArch64 formats `1`/`2` remain readable with their previous
projection-only semantics. Ordinary map reconstruction invalidates an old
exclusive right while retaining the other private state.

## Legacy compatibility input

`legacy-v4.context` is an actual 7788-byte export from the previously recorded
pre-producer C API library, not a synthetic current serializer relabeled as an old version.
Its SHA-256 is
`7c0abc7f5d23b9de85370036f1b6826071ef478a3d4bd9c405fc60dcb359026d`.
`legacy-v4.provenance.json` records the exact producing library digest and guest
setup. The source commit of that library is unknown; its filename does not prove
source provenance. It maps 4096 bytes at address zero with permissions `7`, places
`MOVZ X0,#0x123; NOP` at `0x100`, executes one instruction, then exports. Restore
must expose `X0=0x123`, `PC=0x104`, and execute the NOP to `PC=0x108`.

## Verification and boundaries

Owning controls cover actual pending native authentication faults, cache and
interpreter entry changes, private-field round trips, semantic system-register
map equality, malformed/binding rejection, publication admission, writer
exclusion, outstanding LDXR/STXR rights, PL011 FIFO and fresh file continuation.
Current results and exact commands are recorded by the audit ledger; this text
alone is not a test result.

| ID | Assumption and basis | Stress test / falsification probe | Dependent result | Status |
|---|---|---|---|---|
| AC1 | Capture occurs between host execution calls. | Pause an actual native authentication fault; replace bytes, clear caches and resume. Any replacement retirement falsifies preservation. | Portable pending-event delivery. | Confirmed at tested native-return and interpreted instruction boundaries; arbitrary callback capture remains open. |
| AC2 | Target mapping/protection and external raw aliases are coordinated by the caller. | Controlled domain writers must block throughout publication; an external raw mmap writer violates this premise. | RAM/reservation atomic boundary. | Controlled writers tested; external raw aliases/mapping changes remain a retained caller precondition. |
| AC3 | A cold compiled cache changes promotion work, not modeled guest behavior. | Check interpreted/native retirement, faults and clocks; native entry history before capture must survive. | Derived cache reconstruction. | Tested for the modeled execution paths; future promotion work may differ. |

High-impact remaining work: historical/native setter rollback, arbitrary in-flight
host callbacks, other backend/platform closure, and full C-STATE qualification.
C-SMP still requires its remaining native/JIT/debug/clock/replay closure. A32-FP
and C-HVF retain their separate profile and native-hardware requirements. This
component does not close any of the four full findings.

## Qualified implementation

The final source passed **11176** library tests with two existing
ignored tests, **210** C API tests, and **47628** owning tests across **22** targets.
The unchanged guest emits `0` under QEMU, uninterrupted RAX and fresh file
restore, with its original kernel path unavailable during resume. The checkpoint
contains backend kind `5` at PC `0x40080fa0`, between LDXR and STXR. The guest
assembly SHA-256 remains `01a513b49bcabc631eabba613cf2f11d54d7f7ab55cad9ca008d078764c51718`.

Workspace Clippy and all-target compilation passed. The corrected doctest command
executed no tests; five existing doctests remain ignored. 18 C/C++ consumers and
six strict ABI objects passed, and their generated outputs were removed. The
interpreter-only build and Rosetta checkpoint controls passed; this is not
physical Intel HVF evidence. Exact commands, source digests and raw outputs are
retained in the audit ledger entry. RAM publication skips unchanged physical
copies while still invalidating old exclusive rights, preserving sparse RAM.
