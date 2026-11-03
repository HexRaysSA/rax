# Shared RISC-V reservations and coordinated restoration

RISC-V LR.W/LR.D and SC.W/SC.D now use the shared physical RAM writer domain in
system, embedded, translated C API, Linux process, and GSC memory adapters. The
native RISC-V JIT helpers use the same transactions. A peer store invalidates a
reservation even when it writes identical bytes or restores the old value after
an intervening change. SC validates write access on failure, consumes its
reservation, and commits a successful store under the writer lock. The modeled
reservation set covers the operand with 64-byte host-backed granules. A
contiguous, naturally aligned word or doubleword occupies one such granule;
fragmented backing can require several. The implementation may reject a
different-width or different-address SC within that set.

Memory views keep their own address maps and share stable locks for overlapping
host allocation ranges. The registry partitions uncovered gaps instead of
replacing locks held by existing views. Lock order is physical range address,
then reservation slot. Ordinary RISC-V RAM reads and all tracked RAM writes use
this boundary. Translation, MMIO, HTIF notification and other device callbacks
run outside it. Independent raw writers and aliases at different host virtual
addresses still require their owner's coordination.

The serialized reservation contains its guest-physical address and access width.
Host pointers, physical lock partitions and live mapping witnesses are not
serialized. Prepared CPU replacements register their target monitors before the
RAM publication lock is taken. Incoming rights are admitted before any live RAM
changes and installed after RAM restoration under that same boundary. A
cancelled preparation cannot enable the detached CPU.

| Producer | Current record | Legacy policy |
| --- | --- | --- |
| Generic RISC-V kind 3 | `RAXRV002`: physical reservation plus frozen core/adapter body | `RAXRV001` without an active LR is accepted; an active address-only LR is rejected |
| GSC state resource kind 3 | `RAXGSI02`: physical reservation plus frozen state image | `RAXGSI01` without an active LR is accepted; an active address-only LR is rejected |
| GSC descriptor kind 10 | `RAXGSC01`, unchanged | Existing verified resource framing remains required |
| C API envelope | Format 6, unchanged | Formats 1/2 retain their projection-only behavior |

The old address-only records cannot distinguish a valid reservation from one
invalidated by an observed same-value peer store and do not retain the LR width.
Restore reports that ambiguity before changing the live target.

C API register and PC updates preserve private execution state. Reset-style
public state installation clears reservations. Mapping reconstruction retains
rights only when the reserved bytes keep the same host backing. A live source
witness rejects an intervening store before the replacement engine is exposed;
removed or reallocated backing loses its rights. The C API explicitly publishes
its detached system RISC-V CPU instead of adopting an unactivated replacement.

GSC RAM stores, flash program/erase, synthetic ROM installation and the generic
RISC-V RAM/translated writers participate in invalidation. LR/SC over UART or
GSC peripheral/core-local registers is rejected before any device side effect.
Successful HTIF stores retain their existing event order outside the RAM lock.

## Specification and independent observations

The retained primary source is
[`riscv-unprivileged.txt`](../../specifications/riscv/riscv/riscv-unprivileged.txt),
RISC-V Unprivileged Architecture version 20250508, section 13.2 (Zalrsc), SHA-256
`15cf782ec980195c28fc3085b88bf5eb5c408b366f77ead536f10151e71f467f`.
The observed peer stores in these tests require SC failure under that rule.

The same retained bare-metal assembly is executed by the installed
`qemu-system-riscv64` reporting version 11.1.2 and by two actual RAX system
backend harts. The latter are interleaved by the witness host, rather than
started by the VMM. The control and completion words occupy separate reservation
granules; the writer publishes completion after FENCE w,w and the receiver
executes FENCE r,rw after observing it.

| Observed peer store | Required SC failure | RAX status | Installed QEMU status |
| --- | --- | --- | --- |
| Changed word | Yes | 1 | 1 |
| Same-value word | Yes | 1 | 0 |
| ABA word | Yes | 1 | 0 |
| Same-value doubleword | Yes | 1 | 0 |

RAX prints `1111`, while the installed QEMU prints `1000`. Three single-thread
TCG and three multi-thread TCG repetitions agreed. The discrepancy is retained;
QEMU is not treated as a passing oracle for those three cases. Its cause is
unknown. The reported upstream version's source tag could not be retrieved.
This observation concerns the installed binary and does not identify its source
implementation.

## Validation boundary

The complete root library ran without filters: 12106 passed,
0 failed and 35 ignored. The 43 independent affected executables
reported 799 passed, 0 failed and 8 ignored in aggregate;
this includes the complete C API library. Four host-gated targets
(`riscv_diff`, `riscv_vector`, `riscv_smir_x86_jit`, `hvf_intel_owner`) contained zero tests on this
macOS AArch64 host and qualify compilation only. HVF mock suites do not establish
native Intel execution. The focused run passed 55 checks; six supplemental
HTIF, partial-map, final-page operand, wrong-hart identity and exact-assembly
checks passed. All 19 C/C++ consumer programs
ran, and seven C ABI translation units compiled. Workspace formatting, all-target
build/check/Clippy and no-debug/no-JIT checks completed. Doctest commands
completed with zero examples executed and five ignored; exact
commands, counts, skips and immutable input hashes are in
[qualification.json](qualification.json).

The targeted native cases assert actual native execution at O0/O1/O2 and include
both direct and native peer writers. Ordinary backend tests cover RV32 words and
RV64 words/doublewords, system/embedded/process modes, virtual aliases, same-value
and ABA stores, unrelated granules, competing same-value SCs, permission faults,
side-effect-free device rejection, current/legacy private records, poisoned
locks, cancelled publication and source-free multi-hart files. Shared-domain
cases cover differing complete map views, partial host allocation views,
replaced backing, source-witness invalidation, writer exclusion during frozen
publication and a 16-byte reservation across sixteen separate allocations.

The test scope does not establish VMM secondary startup, platform interrupt or
timer delivery, shared AMO/Zacas indivisibility, physical RISC-V execution, native
Intel Hypervisor.framework execution, or all four audit findings' completion.
The separate two-hart AMOADD.W probe still loses an increment and remains a
required follow-up under C-SMP. Two additional current Zacas controls fail:
compare-miss on read-only memory omits mandatory write admission, and RV32
even-pair AMOCAS.D is rejected despite enabled Zacas. Both retained-primary
section 15.1 requirements belong to the next atomic transaction/profile group.
The A32-FP and remaining backend/native profile
requirements remain open.

The lock acquisition and read cost is O(R) for R physical ranges in a view; the
common one-range path allocates no guard vector. Invalidation additionally scans
the relevant ranges' live monitor slots. Reservation mapping uses at most sixteen
byte lookups. Large fragmented-map performance is unqualified. Source/private
record encoding retains its existing byte and collection limits.


## Assumption register

| ID | Assumption and dependent result | Stress or falsification probe | Disposition |
| --- | --- | --- | --- |
| A1 | Naturally aligned 4/8-byte operands fit one 4096-byte translation page | Last aligned operand, aliases and denied SC; an N-aligned offset is at most 4096-N because N divides 4096 | Confirmed within the existing translation contract |
| A2 | Legacy address-only reservations lack width and invalidation history | Empty/active legacy imports and same-value peer store | Confirmed; active legacy import rejects |
| A3 | WFI step returns Hlt and consumed Shutdown replays as Shutdown | Inspect actual step and halted-state mapping | Falsified fixture assumption; corrected witness, unchanged production exit contract |
| A4 | Remapping may clear retained rights and register/PC updates may reset private state | Full C API remap, update_state and set_current_pc cases | Falsified initial implementation; target-aware transfer and preserving update/PC methods now pass |

| Impact | Remaining scope |
| --- | --- |
| High | Shared AMO/Zacas indivisibility, complete RISC-V VMM startup/controller/clock/replay, remaining A32-FP/C-STATE/C-HVF profiles and actual Intel HVF execution |
| Medium | Fragmented-view performance and external raw/alternate-host-address aliases require separate qualification |
