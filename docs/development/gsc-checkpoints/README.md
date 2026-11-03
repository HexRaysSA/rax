# GSC private and platform checkpoints

GSC checkpoint files now retain the represented RV32/Ti50 core, runtime phase,
peripheral state, bridge profile and immutable AP flash. New-file construction
selects the GSC producer before creating CPUs, without consulting GSC environment
settings, opening its source inputs or installing synthetic ROM bytes. Generic
RISC-V private files likewise select their captured generic family despite a
GSC process selector. Ordinary non-checkpoint machine selection is cached once
per VM. Files without a private section retain legacy projection semantics.

Seven baseline actual-file witnesses failed: lost retirement count, mscratch,
PMU scratch, remaining UART input/arming, timer divisor, absent machine selector
and absent AP flash. An earlier fixture mistakenly rebuilt CLI configuration
from a deleted kernel; that fixture blocker was corrected with the existing
checkpoint configuration API before reproducing all seven defects. Kernel
reopening is not claimed as a RAX defect.

| Component | Identity / size |
| --- | --- |
| Backend producer | Kind 10, tag `RAXGSC01` |
| Descriptor | 8-byte tag + 4-byte CPU ID + two 44-byte keys = 100 bytes |
| State resource | Kind 3, current tag `RAXGSI02`, at most 67,108,864 bytes including tag |
| Immutable AP flash | Kind 4; full captured bytes, including a legitimate empty image |
| Resource identity | Kind, byte length and SHA-256; existing aggregate resource/RAM/media bound applies |
| Resource framing | Existing `RAXRES01`; older readers reject the new unknown kinds |

The state image explicitly covers the pre-existing 30 runtime fields, 21 shared
fields, eight bridge fields and nested configuration/TPM state. RAM pointers and
target publication controls are reconstructed, not serialized. Shared handles
and PC/time cells belong to the new target. Hash-table entries are canonical,
sorted and unique. Collection counts are bounded before entry reads: 65,536
rows/commands, 256 SPI bytes, 2,048 FIFO bytes and the overall state byte budget.
The RISC-V core decoder also bounds vector and vendor-CSR allocation without
changing its wire representation.

Restoration resolves verified resources and admits the public/private profile,
CPU identity, peripheral geometry and runtime phase before mutating live state.
A replacement remains unable to enter or recapture until its matching RAM
publication permit commits. Cancellation, foreign RAM and a malformed final CPU
record preserve the live CPUs and RAM. A standalone descriptor setter rejects
private import because resource bindings and RAM publication are required.
The maximum restored reset count now saturates and takes the modeled terminal
reset-loop path instead of overflowing.

| Validation | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| Producer resource/publication/field/in-flight TPM tests | 11 | 0 | 0 |
| Complete GSC runtime (includes those producer tests) | 64 | 0 | 0 |
| Actual-file GSC continuations and negative admission | 10 | 0 | 0 |
| Machine-family selection | 4 | 0 | 0 |
| RISC-V core checkpoint module | 4 | 0 | 0 |
| Resource module | 12 | 0 | 0 |
| Complete root library, zero filters | 11847 | 0 | 35 |
| Complete C API library, zero filters | 240 | 0 | 0 |

The actual files exercise 1/2/4 represented CPU contexts where applicable;
fresh-process profile/selector/AP cases use one context. Late malformed or
missing records cover two and four contexts. Fifteen CSR/MMIO/UART/SPI instruction words
were checked with installed LLVM assembly, linking and disassembly. The vendor
selector witness exercises the pre-existing Ti50 implementation; it is not a
new independent vendor-ISA conformance result. Workspace
format, all-target check/build/Clippy, doctests and the complete CI workflow
regression binary passed; exact commands, counts, hashes, ignored doctests and
assumption stress/falsification probes are in [qualification.json](qualification.json).

The qualified tree combines 40 master-only and 113 audit-only predecessor
commits. C API module declarations and both Darwin descriptor lifetime witnesses
were retained. A duplicate test close introduced by the textual merge was
removed after the combined compiler rejected it; qualification used the corrected
tree. Raw incoming reference bytes were preserved. The tested semantic commits
land in local master, and their audit branches and integration worktree are
removed; external receipts record the final fast-forward and idle build cleanup.

| Impact | Remaining boundary |
| --- | --- |
| High | S5L8900 and remaining backend/private/shared state, startup/IRQ/clock/replay and physical Intel requirements remain open. |
| High | The independent native streaming-FPSR defect remains unresolved. |
| Medium | Full physical GSC/real firmware/TPM conformance is unmeasured; represented multi-context tests do not prove physical multicore support. |

Capture assumes a stopped VMM-owned CPU and its private represented GSC owner
graph; external raw RAM writers retain the existing caller-quiescence requirement.
Canonical capture costs O(S + E log E) time and O(S + E) space for S state bytes
and E entries. Resource hashing is linear in captured byte length. No physical
time or hard host-time bound is inferred. All four full audit findings remain open.


The current `RAXGSI02` image prefixes the frozen state body with a separately
versioned physical reservation token. `RAXGSI01` imports remain accepted when no
LR is active; ambiguous active address-only reservations reject before live
mutation. RAM, flash programming/erase and synthetic ROM writes participate in
the shared invalidation boundary. The incoming token publishes after matching
RAM restoration; cancellation cannot activate a detached CPU. The descriptor
`RAXGSC01` and resource kinds are unchanged. Current reservation validation is
recorded in [shared reservations](../riscv-shared-reservations/README.md); the
earlier table above retains its original qualification counts.
