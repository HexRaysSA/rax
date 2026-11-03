# Backend-owned checkpoint contexts

The public CPU register structures omit execution state owned by individual
backends. Bundle capture now carries an additional ordered context set whenever
a backend exports one. Runtime restoration admits all public projections and
opaque contexts before changing the first CPU, RAM, or legacy device. The
existing base snapshot and section 11 representations remain unchanged.

The standalone AArch32 producer retains its versioned `RAXA3202` context (`RAXA3201` remains readable). The
actual ARM1176/S3C64xx VMM adapter uses `RAXS3C02` (`RAXS3C01` remains readable): its complete represented
`Armv7Cpu`, CP15 and banked registers, exclusive reservation, instruction count,
halt/shutdown state, last bridge fault, power-off latch, both VICs, PWM counter
phase, SYSCON registers, and attached UART registers/input FIFO. MMU/privilege
views are derived before the next access. Decoder and host tracing caches are
not guest state. UART attachment topology must match the target.

Complete S3C private restores prepare CPU and bridge replacements offside.
The target UART owner is retained, locked across all CPU records and RAM
publication, and assigned once after every shared image has been admitted.
Conflicting images for the same owner reject before publication; cancelling
a prepared CPU or publication permit leaves the live UART unchanged. Historical
projection-only imports and standalone per-CPU setters retain their narrower
contracts. See [S3C publication](s3c-uart-publication/README.md) for current
qualification and the remaining full-audit boundaries.

Both ARM platform adapters also retire WFI past its ARM/Thumb instruction and
advance active IT state before becoming halted. Explicit wake resumes at the
following instruction. The S3C64xx file continuation test uses this boundary
directly, without repairing the restored PC.

The retained predecessor reproduction writes CPACR `0x00500000`, captures the
public projection, and reads CPACR after restoring into a fresh actual S3C64xx
adapter. Uninterrupted execution reads `0x00500000`; projection restoration reads
the reset `0x00f00000`. The input words, product-library hash, and raw failure are
under `rax-audit-work/four-findings-s3c-context`. Earlier fixture attempts did not
reach the intended control witness and are retained separately.
The first runtime validation passed six tests and stopped the file continuation
case at the existing minimum-memory configuration check. Its 4 KiB fixture was
replaced with the supported 128 MiB configuration before rerunning.

## File framing

Required tagged-v8 section 14, schema 1, contains the following little-endian
fields, without padding:

| Field | Bytes |
| --- | ---: |
| Tag `RAXBCK01` | 8 |
| Configured CPU count | 4 |
| Per-CPU table row: producer kind, payload length | 4 + 8 |
| Payloads, in CPU order | Explicit lengths |

Producer kind 1 identifies standalone AArch32; kind 2 identifies S3C64xx.
Kind/length zero denotes an absent record. Every other record has nonzero kind
and length. The count equals the configuration's 1–255 CPUs, each payload is at
most 16 MiB, and the section is at most 1 GiB. The whole length table must agree
with the frame before payload allocation. An all-absent extension is rejected.
Backend import validates the producer, inner version/tag, target CPU identity,
private-state invariants, and equality with the associated public projection.

Section 14 follows the CPU set and any execution state, and precedes PCI,
physical memory, media, and RAM. Duplicate sections, optional aliases, wrong
schemas, reordered sections, inconsistent counts/lengths, and truncation are
rejected. Base extraction cannot silently discard the required component.
Backend kinds that the target does not implement are rejected before mutation.
Files without this extension retain their previous projection import behavior;
their omitted private state cannot be recovered.

A present producer set must include the private record required by each known
software target. An absent row no longer silently selects public-only restore
for such a CPU. Generic sparse framing and absent-section compatibility remain
separate contracts. See [required private records](private-context-admission/README.md)
for the producer declaration, rejection boundary and qualification.

For C CPUs and B encoded context bytes, framing takes O(C + B) time and space,
within the limits above. Model capture/import costs also include the producer's
CPU fields, UART FIFO, and device registers. These are algorithmic bounds.

## Assumptions and verification

| ID | Assumption and dependent result | Stress or falsification probe | Status |
| --- | --- | --- | --- |
| B1 | The saved record comes from the actual configured backend | Trace the VMM constructor and producer kind; resume through fresh actual S3C64xx adapters | Verified by constructor trace and 1/2/4-context file continuation |
| B2 | CPU state is captured at an instruction boundary | Safe Rust ownership excludes concurrent execution of the same CPU during capture; save after guest CP15/device writes | Local CPU ownership and controlled S3C UART writer exclusion verified; raw external writers remain separate |
| B3 | All CPU records are admitted before publication | Corrupt the last of four records and compare all target CPU contexts, RAM, and UART | Corrupted-final records, final compatible-setter failure and conflicting shared UART images reject without earlier S3C context/RAM mutation |
| B4 | Device state preserves subsequent behavior | Save/load a real file, construct a new VMM, resume CPACR/PWM/VIC reads and queued UART input, compare against uninterrupted execution | 1/2/4-context file continuations passed with exact private-context comparison |
| B5 | Public and backend representations agree | Change a public register without updating the opaque record | Standalone and C API conflicting-projection rejection passed |

The runtime regressions operate actual VMM capture/file/constructor/restore
paths. They explicitly run each represented CPU before and after capture;
they do not establish secondary startup or scheduler execution for ARM.

## Remaining full-audit requirements

| Impact | Boundary |
| --- | --- |
| High | Other software/native/platform backends still require complete private and in-flight contexts |
| High | Shared-controller ownership and all independent writers require coordinated quiescence |
| High | Late native/model publication failures require complete transactional recovery |
| High | SMP scheduling, architectural secondary startup, bounded JIT/native execution, and physical Intel HVF validation remain required |
| Medium | Legacy projection-only files cannot reconstruct state they never recorded |

Architectural CP15/exception expectations use the pinned ARM references listed
in `a32-fp-controls.md`. PWM/VIC/UART continuation compares the represented
device models in `src/devices/s3c64xx.rs`; it does not establish additional
hardware fidelity for those models.

## C API system-mode AArch32 contexts

The exported C functions now write context format 5 for system-mode AArch32.
After the unchanged public/emulator records, a u32 producer kind and u64 payload
length precede the complete standalone context. Legacy formats 1/2 remain
readable with their original projection-only state. AArch32 user mode retains
format 3 and AArch64 retains format 4. New private records are bounded to 16 MiB
and validated against the public projection before the candidate CPU/memory is
published. Region counts are admitted against the remaining frame before table
allocation. Unknown kinds, invalid lengths, corrupt records, and every truncated
prefix reject without replacing the target engine.

Mapping reconstruction also imports the backend context before publication,
retaining FP controls and an outstanding LDREX reservation. The C API's documented
observation counter restarts at zero after context restoration while the raw
backend counter survives; a host counter origin keeps those contracts separate.
Ordinary memory-map changes retain the existing cumulative counter behavior.

The native C API suite passed all 195 tests. Four new tests cover guest-written
CPACR/FPEXC denials with and without mapping reconstruction, LDREX/map/save/restore/
STREX, legacy formats, and corruption/truncation nonmutation. Both CPACR and
FPEXC failures were separately reproduced through the pre-fix exported dynamic
library; its hash, raw contexts, Python caller, and failure output are retained.
The first whole-suite run passed 193 tests and failed an older system-format
assertion; that assertion now expects format 5 while the user-context behavior
remains exercised. Exact validation receipts are recorded in the audit ledger.

RISC-V producer kind 3 (`RAXRV002`; inactive legacy `RAXRV001` import) adds the configured interpreter profile,
physical reservation width/validity, raw counters, complete represented hart state and ordered pending
adapter events. See [RISC-V backend contexts](riscv-backend-context.md) for its
binding, admission, C API format-6 compatibility and validation boundaries.

Software x86 producer kind 4 (`RAXX8602`, with `RAXX8601` import) retains CPU/MMU private state, XCR0,
ISA configuration, pending input/native exits, private user descriptors/traps,
consumed debug status, and complete BIOS bindings. Required section 15 carries deduplicated immutable
media. Software x86 replacements are prepared before VMM publication; other
backends and whole-VM late-failure transactions retain separate requirements.
See [software x86 contexts](x86-backend-context.md) for format 7, resource
framing, map/reset behavior and the actual file/ABI verification boundaries.


Software AArch64 shared interrupt and power state is now a VM-owned RAXEXE02
execution payload, captured once instead of duplicated into CPU projections.
It retains controller interfaces, queued power requests and target-owned IRQ
handle identities across restoration. This complements the CPU projection;
full core/bridge private context and exclusive reservation closure remain open.
See [AArch64 cluster ownership](aarch64-cluster.md).


Cortex-M producer kind 8 (`RAXCM001`) carries represented core, internal
NVIC/SCB/SysTick, sleep/event/counter and local adapter state. Its VMM candidates
use a matching-memory publication permit; exported C contexts use format 9.
Absent-section and C versions 1/2 retain projection-only compatibility.
See [Cortex-M checkpoints](cortex-m-checkpoints/README.md) for exact scope,
controller side-effect tests, current-session debug ownership and qualification.


Hexagon producer kind 9 (`RAXHX001`) retains represented packet/core and adapter
phase, including working/packet-entry registers, input, undelivered output,
deferred RAM, forwarding and local rights. C engines emit format 10. Matching
RAM publication guards detached CPUs; legacy absent sections and formats 1/2
remain projection-only. See [Hexagon checkpoints](hexagon-checkpoints/README.md)
for admission, exact output-boundary semantics and qualification.

## GSC RV32/Ti50 platform contexts

Producer kind 10 (`RAXGSC01`) references verified kind-3 state and kind-4 AP flash
resources. The complete represented core/runtime/bridge image is admitted offside
and remains unable to enter before matching RAM publication. A new checkpoint
VM selects the saved producer before CPU construction, without GSC environment,
file reopening or synthetic ROM writes. Generic RISC-V private files override a
conflicting GSC selector; absent-section files retain legacy projection behavior.
See [GSC checkpoints](gsc-checkpoints/README.md) for the exact schema, bounds,
actual 1/2/4-context continuations, assumption probes and remaining full findings.
