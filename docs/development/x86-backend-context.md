# Software x86 checkpoint contexts

Software x86 CPUs export producer kind 4 in required checkpoint section 14.
The versioned `RAXX8602` record carries their represented CPU, private execution,
MMU, and user-mode state. Complete immutable boot media are stored once in
required section 15, independently of the 16 MiB per-CPU record limit.
The original `RAXX8601` decoder remains available. Version 2 preserves the
original base layout and adds the user-mode consumed DR6 snapshot; the optional
snapshot must match the presence of a user binding. Attempt-local trace
suppression is reconstructed as false. See the frozen
[pre-integration control](x86-context-integration/README.md) for wire provenance
and rejection tests. The C API outer format remains 7 and the VM producer kind
remains 4.

## State and bindings

| State | Capture and restore contract |
| --- | --- |
| Registers and system registers | Preserve the raw register image, plus the existing public materialized projection; reject conflicting projections |
| x87, lazy flags, MSRs, PKRU, MXCSR, halt and interrupt shadow | Preserve the legacy emulator image and validate its architectural invariants |
| XCR0 and XGETBV1 | Preserve both controls; validate XCR0 against the selected ISA configuration before publication |
| Optional ISA capabilities | Preserve all nine software capability switches; reset retains the selected configuration |
| Input completion | Preserve width, register or memory destination, and batch count, separately from any undelivered native exit |
| Deferred native exits and VSIB restart | Use a stable exit representation independent of debug build features; deliver a pending exit once before further execution, without retirement |
| User mode | Preserve pending syscall/exception traps, compatibility mode, consumed debug status, and all 128 private GDT bytes |
| Memory observations | Preserve recording/fetch configuration and ordered buffered access records; draining consumes each record once |
| Inline LAPIC | Preserve every modeled field and elapsed timer phase; restore rebases phase into the target clock domain |
| RAM, shared LAPIC, PCI and process translation | Retain the target's external bindings; require matching binding modes and PCI aperture |
| Mini-BIOS | Preserve RAM-size reporting and the complete optical-medium identity and content |
| Decode, TLB, native-code and promotion caches | Reconstruct cold, retaining logical pending exits/restart hints; active verifier transactions must finish before capture |

CPU and MMU capture use exhaustive Rust destructuring so a newly added field
requires an explicit classification. This does not replace behavioral tests.
The safe ownership boundary is between synchronous CPU/native invocations;
independent shared writers still require coordinated quiescence.

## Native retirement and deferred exits

Runtime x86 JIT regions retain one original instruction per CFG block. The
lifter records its exact source encoding. O2 retains its ordinary cross-
instruction optimization; the compiler then reconstructs the original dynamic
instruction CFG, including NOPs and branches whose semantic operations vanished.
Native
admission rejects missing, multiple, or cross-instruction provenance before
emitting executable code. Validation takes O(B + I + O) time and O(B) auxiliary
space for B blocks, I source encodings and O semantic operations. Reconstruction
uses O(B + I + O) time and space and follows original edges rather than sorting
guest PCs; merged chains can cross backward in the address space.

The x86 and AArch64 host bridges carry an append-only absolute wrapping
retirement counter. A completed block increments it in O(1) time without
changing guest registers or flags. Successful early exits commit explicitly;
fault/deoptimization exits leave the current instruction uncounted. A native
CALL commits only after its return-address push succeeds and transfers the
count through the interpreted callee. Verification restores the original count
before replay and compares the resulting retirement count.

A pending native I/O exit is captured after its instruction has retired.
Delivery and input completion consume that existing state without another
retirement. This accounting does not establish a per-invocation native execution
budget or complete SMP scheduling.

## Immutable resource section

Section 15 uses schema 1 and follows sections 11/13/14 when present. It precedes
PCI, physical-memory, storage-media and RAM payloads. Its little-endian payload
has no padding:

| Field | Bytes |
| --- | ---: |
| Tag `RAXRES01` | 8 |
| Unique resource count | 4 |
| Each table row: kind, logical byte length, SHA-256, compressed byte length | 4 + 8 + 32 + 8 |
| Resource frames in table order | Explicit lengths |

Kind 1 identifies a complete boot CD medium. A present empty medium differs
from an absent binding. Keys are strictly ordered and unique. The format admits
at most 1024 resources and 68,719,476,736 logical bytes in aggregate. Each medium
uses exactly one regular Zstandard frame with at most 8,388,608 bytes of decoder
history. Full decompressed length and SHA-256 must match before any binding is
published. Truncated, concatenated, skippable, trailing, duplicate and unordered
frames or table rows reject. Required-section aliases and extraction through
the base-only snapshot API also reject.

Reported RAM, storage media and immutable resources together must fit within
68,719,476,736 bytes, including projection-only bundles without a physical-memory
section. The resource table is checked against the remaining budget before
reading compressed payloads. Full physical backing retains its existing
separate limit accounting for RAM padding.

Restoration verifies that the resource dictionary equals the union of all CPU
references. Missing and unreferenced media reject before changing live CPUs,
RAM or devices. Verified media are shared through `Arc` across restored CPUs.
Existing immutable bindings can be retained during map reconstruction without
copying or recompressing them.

With C CPUs, P total CPU/observation bytes, R unique resources and M unique
resource bytes, framing and compression take O(P + M + R log R) time and
O(P + M + R) space, excluding guest RAM and compression workspace. Source
identity capture currently hashes each CPU's attached medium; when all C CPUs
share one medium, that adds O(CM) hashing work. Decoder history is bounded
independently of M.

## Publication and compatibility

Software x86 prepares replacement CPUs offside over the target's admitted
bindings. Resource lookup, profile validation, context decoding and replacement
allocation complete before publication. VMM capture also retains the existing
execution/controller, clock, physical-memory and PCI components.

The C API writes format 7 for both system and user x86 engines. It keeps the
public and legacy emulator images, adds the producer-kind/length/backend record,
then a u64 resource-section length and complete resource bytes before region
records. Zero resource length means no immutable media. Restore constructs a
candidate CPU and memory map before replacing the engine. Format 1/2 inputs
retain their original projection-only semantics; omitted private state cannot
be reconstructed. Earlier libraries cannot read format 7.

Map/unmap/protect reconstruction preserves full backend state. Architectural
reset retains ISA and BIOS configuration but clears architectural execution
state. The public `rax_emu_icount` starts at zero after context restoration;
the backend's raw count is retained through a separate observation origin.

## Assumptions and verification

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| X1 | Media identity depends on full content rather than the original host path | Read an unread CD sector in a fresh CLI process after removing the original ISO path |
| X2 | Only derived host caches may be discarded | Import over a populated target decode cache and resume native I/O and partial instruction frontiers |
| X3 | External bindings belong to the target | Restore over distinct RAM/controllers; reject mismatched binding modes before changing target state |
| X4 | Per-CPU transport does not prove SMP execution | Require separate VMM secondary-startup, scheduling and IPI workloads |

The owning regressions exercise pending register and forward/backward REP input,
XCR0, profile rollback, TLS, syscall traps, BIOS disk and memory services,
buffered memory records, relative timer phase, malformed contexts/resources,
and fresh VMM file continuation for 1/2/4 actual software CPUs. The file tests
explicitly step each CPU; the SMP proof obligation remains separate.

`tools/checkpoint/x86_context_oracle.py` compares QEMU and RAX guest output and
restores one actual file without the source ISO path. The retained predecessor
emits `S` uninterrupted and `F` after restore. The corrected path must emit `S`
in both processes. `tools/checkpoint/x86_context_capi.py` exercises guest
XSETBV/XGETBV through an actual exported library in 32- and 64-bit modes,
including map reconstruction and the documented public counter origin.

The audit ledger records final executed counts, failed fixture attempts and
host coverage. Translated x86 tests do not establish physical Intel HVF
behavior. Native VSIB execution requires a suitable host and cannot be inferred
from a preserved restart field.

## Remaining full-audit requirements

High-impact requirements remain: other backend/platform/private/in-flight
contexts, all-writer quiescence, whole-VM recovery from late publication failure,
architectural secondary startup, bounded JIT/native scheduling, remaining A32
admission controls and physical Intel HVF MMIO/interrupt validation. Preparing
software x86 replacements does not establish complete VM transactions.
