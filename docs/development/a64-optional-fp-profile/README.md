# AArch64 optional FP/SIMD profiles

This component connects the represented AArch64 JSCVT, FCMA, FRINTTS, BF16,
I8MM and DotProd flags to their ID fields, original-instruction admission,
native dependency guards and private-context migration. It does not establish
complete AArch32, SVE/SME or whole-CPU architecture-version conformance.

## Architectural and encoding inputs

The unmodified Arm PDFs and their provenance are in `primary/`. Arm
109697_2025_12_en identifies feature prerequisites and execution states;
DDI0616 B.a E3.2.11 defines the five owned ID_AA64ISAR1_EL1 fields. DotProd
uses ID_AA64ISAR0_EL1.DP[47:44], also declared in the existing
`docs/architecture/arm/asl/arm_regs.asl` register corpus (SHA-256
`6c6abff1b0aea7b357c2228ca7f7229da96ccca6a912e34e14d562f3366a4868`; upstream revision unknown). The represented fields use base values zero/one;
BF16 level two additionally requires behavior not represented by the BF16 flag.

The existing opcodesDB file is a secondary encoding index with an unknown
upstream revision. `tools/execution/a64_optional_fp_profile.py` requires its
exact SHA-256 and deterministically produces the 34 descriptions in
`encodings.json` and the Rust table. The index is not an independent semantic
oracle. All 34 descriptions have an LLVM-decoded witness accepted by QEMU's
A710 model; `native-witnesses.json` retains these witness words and tool output.

The local Arm ASL file also independently identifies base FRECPX and FSQRT
encodings, and the FCMA size/index restrictions. Its pinned SHA-256 is
`3c91ece6d0509f7ce9e8b2d8fa623787d7c7acb4cb24040a75cec5aa2789e611`;
its upstream revision is unknown. FRECPX and FSQRT occupy opcode neighbors of
FRINTTS and must not be rejected by the latter's reserved-size predicates.

The optional instruction scan takes O(K) time for K = 34 fixed descriptions
and O(1) auxiliary space. ID updates/migration inspect six fixed fields; mode
key construction and comparison use two fixed-width values.

## State semantics

The default v8.0 configuration now reports these six optional capabilities as
absent and rejects their instructions. Callers running such code must select
its capabilities explicitly; for example:

```rust
use rax::isa::arm::{AArch64Config, ArmFeatures};
let mut config = AArch64Config::default();
config.features.insert(ArmFeatures::BF16 | ArmFeatures::I8MM);
```

Constructor/reset and ordinary host state import derive the six owned ID fields
from selected capability flags, preserving other ID fields. Unsupported levels
are rejected before host-state mutation. FCMA half arithmetic independently
requires FP16; an H destination alone does not make BFCVT require FP16.

New private AArch64 contexts use `RAXA6403` with the existing payload shape.
Actual `RAXA6401` and `RAXA6402` records remain decodable. The public C API
uses outer context format 8 and reads legacy format 4. Libraries that do not
recognize the new private payload tag reject these newer records. Restoration compares
the original public/private images before migration. For supported old fields,
migration derives the six flags from the old advertised IDs and retains those
ID values. This preserves the advertised old guest contract; it does not
preserve every instruction the old implementation accidentally executed despite
absent flags and IDs. Legacy level-two BF16 and reserved FCMA level fifteen
are rejected transactionally.

The nine fixture pairs in `fixtures/` were exported by unmodified parent
`84d43c272c270bcf1038020d90aa9593390bb902` through the public codec and vCPU API.
Their manifest records the actual producer, bytes and hashes. They are not
hand-constructed examples. The fixture directory has a local Git ignore
exception so its 19 binary context and guest inputs are included in the commit. A test that changes an old tag to the current tag
is explicitly a forged current record and must not receive legacy migration.

Native mode keys carry translation/control state and capability bits in separate
fields. Original instruction dependencies are collected before optimization;
cache lookup and native entry require them to remain enabled. Synthetic
capability metadata on real integer code exercises these guards separately from
instruction-specific native execution support.

## Public C/C++ selection

ABI 1.16 adds `rax_arm64_fp_configure`, `rax_arm64_fp_get_config`, the
32-byte `rax_arm64_fp_config` prefix and eight explicit feature bits. The C++
wrapper exposes `configureFp` and `fpConfig`. Public masks cover FP16, FHM,
JSCVT, FCMA, FRINTTS, BF16, I8MM and DotProd; they are explicitly translated
into internal flags. FHM requires FP16 in the public setter. Unknown bits,
nonzero reserved words, short prefixes, wrong architectures and execution-time
calls fail before CPU changes. Unaligned buffers are supported. Getter writes
only the known prefix, retains the caller's size and leaves a future tail intact.

The dedicated backend operation updates selected flags and IDs and invalidates
derived translations. It preserves registers, RAM, retirement/cycle counts,
pending faults and shutdown state. The low-level backend continues to preserve
an inactive FHM selection without FP16 for existing Rust/context compatibility;
effective FHM admission and ID reporting require both flags. Reset and memory-map
reconstruction retain the selection, and context restore restores it. PAuth
selection and keys remain independent.

Public workflow tests exercise all 256 masks (192 accepted, 64 invalid FHM
combinations), 576 guest ID-register reads, absent-feature zero-retirement retry
for eight forms in both system and user mode, prefix boundaries, unaligned
buffers, callback rejection, reset, context and memory-map reconstruction. The
strict C ABI test checks size 32 bytes, alignment 4 bytes, offsets and signatures.
The C++ consumer executes 16 feature retries through public interfaces.

A core test injects a synthetic delayed FP-access fault, changes selection,
serializes/restores the private checkpoint and verifies one fault delivery with
zero retirement followed by one handler instruction. A backend test separately
preserves shutdown and RAM. These tests establish preservation of an existing
pending event; they do not claim that the 34 rejected optional native shapes
execute natively. Selection scans eight fixed mappings in O(1) time and space.

## Qualification and remaining findings

Targeted FP profile tests: 24 passed. Complete affected AArch64 backend module:
37 passed. Public FP API selection: 10 targeted tests passed. The 34 sampled native shapes all reject; real integer code with
synthetic per-capability metadata tests entry/cache guards, with no new native
optional-instruction execution claim.

Full library: 11226 passed, 0 failed, 2 ignored.
Owning targets: 47706 passed across 23 targets.
C API: 222 passed; 19 C/C++ consumers and 7 strict ABI checks passed.
Standalone ASL parser: 62 passed, 1 ignored. Its slice-regex repair is the separate preceding commit e6e08407.
Formatting, workspace Clippy, all-target build and interpreter-only compilation passed. Selected x86-64 interpreter tests ran under Rosetta; this is not physical Intel HVF validation.
Doctests: 5 ignored. Linux-only full native-reference and physical A32/Intel runtime gates were not run on this Apple Silicon host.
Earlier independent-parent Darwin transport failures remain unresolved; this passing run does not establish a fix for that unchanged source.


The independent neighborhood sweep includes 4,144 words, two execution levels,
two FPEN settings and four QEMU models (66,304 events). Actual model IDs are
retained. A76 advertises DotProd but not the other five capabilities; A710 has
all six base levels. QEMU `max` advertises BF16 level two and other additional
features, so it is diagnostic evidence rather than an identical represented
profile.

The full sweep intentionally includes neighboring instructions outside these
six descriptions. Its raw outputs and all mismatches are retained. It exposed
additional generic unallocated-encoding/access-priority and undefined-exit
retirement defects. The shared Undefined-result retirement path is corrected by the follow-up
component; wider allocation/FP-access priority remains open under the original
audit goal. Selected capability results are not a clean result for the entire
neighborhood or the whole ISA.

`reserved-controls.json` contains independent results for 52 boundary words,
including scalar AdvSIMD slots, base FRECPX/FSQRT overlaps and invalid optional
sizes. The test checks the oracle event, precise rejection state and retirement.
The selected 618-word kernel replay also checks saved execution mode, exception
syndrome, precise fault PC and an unchanged denied-instruction sentinel; all
7,416 events match the three represented QEMU profiles.

The broader diagnostic run includes explicit `Unimplemented` frontiers; these
are not by themselves proof of execution or incorrect system exception delivery.
The original sweep separately observed 62 `Undefined` exits that retired once
and advanced PC. The [follow-up retirement component](../a64-undefined-retirement/README.md)
corrects that shared exit path and its tested continuations. Wider allocation
and FP-access priority remain open.
Positive generated tests select their optional capabilities explicitly in both
helper templates and the allocation-characterization factory. Historical full
ASL corpus inputs and generator revision remain unknown; this change does not
regenerate architectural expectations from RAX itself.

## Assumptions and bounded scope

- OP1: legacy advertised IDs define supported guest capabilities when old flags
  were ignored. Stress tests use seven actual supported old profiles, opposing
  flags/IDs, unsupported levels, projection conflicts and post-restore execution.
- OP2: AArch64 extension implementation does not establish AArch32 instruction
  support. Arm separates AA32BF16/AA32I8MM; unsupported AArch32 aliases are not
  newly advertised. AArch32 FCMA/JSCVT/DotProd implementation and complete
  cross-state capability consistency remain part of the full audit goal.
- OP3: changing host capability selection must preserve an already pending
  execution event. Stress tests reject an unrelated flag without changing any
  checkpoint field, preserve the injected event across a valid change and
  private serialization, deliver it exactly once and verify unchanged counts
  until the handler retires. Status: confirmed for the tested synthetic event.
  Falsification probe: any altered non-profile checkpoint field, dropped or
  repeated event, or retirement before handler execution.
- High impact, open: generic neighboring decode/retirement defects, complete
  SVE/SME/debug/profile controls, complete private/in-flight/platform state,
  bounded SMP native execution and physical Intel HVF validation.

OP1 is confirmed for the represented legacy advertised contract. OP2 remains the explicit boundary against claiming full cross-state CPU conformance. OP3 is confirmed for the synthetic pending event and public reset/rebuild workflows. All four full audit findings remain partial.

## Later owned-GIC source framing

The [GIC source conservation followup](../a64-gic-sources/README.md) adds private
RAXA6405/06 and shared RAXEXE05/06 frames when a GIC source bank is present.
Private records without an owned GIC retain RAXA6403/04. Historical qualification
receipts and retained legacy FP fixtures above describe their captured revisions;
the followup preserves their optional-profile migration rules and rejects
ambiguous legacy GIC input sources.
