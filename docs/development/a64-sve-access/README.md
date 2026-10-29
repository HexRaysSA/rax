# AArch64 normal-execution SVE access and checkpoint coherence

Original SVE instructions check selected SVE/SME capability and represented
allocation restrictions before scalable-vector access permissions. Normal
non-streaming execution checks ZEN before FPEN at each applicable exception
level. This preserves the interleaving between local controls, EL2 controls,
and EL3 controls. ZEN=2 denies access at EL1. VHE, the represented security
state, and TGE select the applicable controls and exception target. A TGE
redirected SVE access trap retains EC=0x19.

For the common instruction shapes listed below, an SME-only profile checks
SMEN and FPEN, then raises the non-streaming SME
exception with EC=0x1d and ISS=2. Absence of both SVE and SME produces an
undefined instruction before permission checks. This does not introduce SME
streaming execution or architectural streaming state.
Complete instruction-specific SVE/SME capability and allocation admission
remain open as described below.

Denied instructions retain their original PC, register and memory state, and
retire zero instructions. System stepping delivers the architectural exception;
backend retirement-budget execution reports the state change before executing
the handler. Original native requirements and cache keys retain scalable
capability and permission dependencies. SME-only and represented reserved
encodings are rejected before native execution. The existing unsupported native
SVE frontier remains visible through interpreter fallback.

Generated ARM test helpers explicitly select SVE and enable CPTR_EL3.EZ.
Their owning generator templates produce the same checked-in helper; no
generated instruction expectations are rewritten to agree with the engine.

## Coordinated file restoration

The new two- and four-CPU file-restoration test exposed a separate CPU0
coherence defect. The base checkpoint and CPU-set entry were decoded
independently. Their implementation-defined system-register hash maps held
equal entries but could serialize in different orders. Comparing serialized
bytes rejected valid files with `CPU0 disagrees with base checkpoint`.

AArch64 CPU0 coherence now compares the complete typed state, including exact
integer representations of vector values and system-register map keys and
values. Both bounded encodes still run before admission. Other CPU kinds and
base-private payloads retain their existing comparisons. There is no checkpoint
wire-format, version, tag, or field change and no JSON state projection.

The focused parent test observed equal decoded states with different encoded
bytes and the erroneous rejection. Nine controls change GPR, vector, selected
feature, permission, map key/value, or base-private state and must still reject.
The original failed file is retained in the audit evidence.

## Provenance and independent observations

[Provenance](provenance.json) identifies the unchanged Arm XML 2025-12
[shared pseudocode](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml),
including `CheckOriginalSVEEnabled`, `CheckSVEEnabled`,
`CheckStreamingSVEEnabled`, `CheckSMEEnabled`, `SVEAccessTrap`, and
`SMEAccessTrap`. The archived primary
[Linux boot requirements](primary/linux-arm64-booting-v6.16.html) independently
identify the CPTR scalable-vector control bits. An extracted PDF table disagreed
about EZ's bit position; the retained source discrepancy records why the actual
bit-8 guest behavior and primary boot requirements govern this implementation.
The HTML retains upstream whitespace byte for byte; a local Git attribute
scopes its whitespace-check exception to that archived file.

The independent QEMU 11.1.2 guest checks exception target, EC, original or next
instruction PC, source execution mode, low ISS subtype, and a denied destination
sentinel. Its completion control is BRK. The five output characters encode
target EL, two hexadecimal EC digits, `I` for the original instruction PC or
`A` for the completion PC, and one hexadecimal ISS subtype digit.

The retained corpus contains 504 executions of seven instruction shapes across
72 explicit profiles. Shapes include predicate generation, integer and FP
arithmetic, vector load/store, RDVL, and CNTB. The checked-in
[replay cases](oracle-cases.json) are derived from raw QEMU observations.
Another [40 observations](reserved-oracle-cases.json) cover ten represented
reserved encodings under all four ZEN values; all returned `100I0`.

The first oracle run falsified an assumption: `max,sve=off` retains SME and
produced `11dI` in its initial four-character output format, rather than an
undefined instruction. The second oracle separately confirmed ISS=2. That counterexample,
all raw outputs, exact ELFs, and both oracle versions remain in the audit
evidence. The corrected absence profile explicitly disables both features;
SME-only cases are recorded separately. Neither version measures physical
SVE hardware behavior, FP arithmetic results, PMU values, or native SVE execution.

For a denied local SVE access, use an automatically cleaned scratch directory:

```sh
rax_sve_scratch=$(mktemp -d)
trap 'rm -rf "$rax_sve_scratch"' EXIT
llvm-mc -triple=aarch64 -filetype=obj \
  --defsym=TEST_EL=1 --defsym=CPACR=0x300000 --defsym=HCR=0x80000000 \
  --defsym=CPTR2=0 --defsym=CPTR3=0x100 --defsym=SECURE=0 \
  --defsym=OPCODE=0x2518e3e0 --defsym=INIT_SVE=1 \
  docs/development/a64-sve-access/guest.s -o "$rax_sve_scratch/guest.o"
ld.lld -T docs/development/a64-sve-access/guest.ld \
  "$rax_sve_scratch/guest.o" -o "$rax_sve_scratch/guest.elf"
qemu-system-aarch64 -machine virt,secure=on,virtualization=on \
  -cpu max,sve-max-vq=1 -m 128M -display none -monitor none -serial none \
  -semihosting-config enable=on,target=native \
  -device loader,file="$rax_sve_scratch/guest.elf",cpu-num=0 -no-reboot
```

Expected stderr is `119I0`: EL1, EC=0x19, original instruction PC, ISS=0.

## Assumption register and remaining scope

| ID | Assumption and dependent result | Basis | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| SV1 | Normal non-streaming SVE uses interleaved scalable and FP controls at each EL | Pinned Arm pseudocode | Competing ZEN/FPEN, EL2/EL3, VHE, security and TGE cases; any different target or EC falsifies the represented policy | Confirmed within the recorded normal-execution profiles |
| SV2 | Both-absent and SME-only profiles have distinct admission behavior | Actual first-run counterexample | Disable both features, then retain SME alone; collapsing the outcomes falsifies capability admission | Revised against retained counterexample |
| SV3 | Access policy adds no serialized CPU state | Derived requirements and cache keys | Re-encode the retained parent core fixture and restore controls before and after delivery; any changed bytes or duplicate handler execution falsifies compatibility | Confirmed within the recorded wire, denial and continuation cases |
| SV4 | Register-map ordering is not CPU-state identity | Typed equality, independent decoding and actual file-load failure | Equal maps must admit; every genuine public/private difference must reject | Confirmed by parent failure, corruption controls and actual file continuation |

Access checks and represented reserved-field classification take O(1) time and
space. Native requirement collection takes O(N) time over N original guest
instructions and O(1) additional space. CPU0 coherence requires O(B) bounded
serialization space and expected O(K) map comparison time for K entries, in
addition to fixed architectural fields; B is bounded by the existing per-record
limit of 16 MiB. Worst-case hash-map lookup behavior remains unchanged.

High-impact remaining scope includes complete SVE/SVE2 optional-instruction and
ID/system-register profile coherence, further allocation classes, SME streaming
state and ZA/ZT behavior, architectural halting-debug controls, complete backend
private/in-flight state and transactional coordinated restoration, remaining
startup/wait/debug/clock/replay and other-ISA/hardware SMP profiles, and physical
Intel HVF execution. These remain open full findings. Medium-impact limits are
the absence of scalability measurements and hardware SVE oracle coverage.
Neither CPU halted state nor an HLT instruction substitutes for halting debug.

This group does not establish completion of A32-FP, C-STATE, C-SMP, or C-HVF.

Final qualification: all 18 scalable-access checks and both CPU0 coherence tests
passed. The complete library passed 11,331 tests with two
ignored; 47,875 tests passed across all 27 complete owning
integration binaries, with native suites run serially. All 223 C API tests passed.
The complete generator package passed 70 tests in each of its default and serde
profiles, with one ignored doctest per profile. The main doctest run executed zero
cases and ignored five. Workspace format/Clippy/build, interpreter-only and
x86-64 compile checks passed. Independent QEMU observations total 544 cases in
the corrected normal-access and reserved corpora. Source freezes, retained parent
failures, corruption controls and document links were verified. Physical Intel
HVF, physical SVE and complete streaming/optional-profile validation did not run.
