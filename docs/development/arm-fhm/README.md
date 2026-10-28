# FP16/FHM profile admission and checkpoint compatibility

FEAT_FHM is independent of half-precision arithmetic and requires FEAT_FP16.
`ArmFeatures::FHM` selects that capability; the v8.4 and later base feature
sets include it. Standalone A32 uses `Cp15State.id_isar6[11:8]` and requires
MVFR1.SIMDHP=2. Values other than FHM=1 cannot enable long multiply/accumulate.
The standalone default remains its existing synthetic full-half profile.
These settings do not identify a complete physical CPU implementation.

| FP16 flag | FHM flag | A64 FP/AdvSIMD half fields | A32 FPHP/SIMDHP | A32/A64 FHM fields | FHM admission |
| --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0/0 | 2/1 | 0/0 | Undefined |
| 1 | 0 | 1/1 | 3/2 | 0/0 | Undefined |
| 0 | 1 | 0/0 | 2/1 | 0/0 | Undefined: FP16 dependency |
| 1 | 1 | 1/1 | 3/2 | 1/1 | Subject to FP access controls |

A32 FHM is ID_ISAR6[11:8]; A64 exposes the same value through ID_ISAR6_EL1
and ID_AA64ISAR0_EL1[51:48]. Half support is reported in
ID_AA64PFR0_EL1.FP[19:16] and AdvSIMD[23:20]. Constructor, reset and trusted
system-state import refresh those modeled fields from the selected features.
The mixed-width coprocessor preflight admits the modeled ID_ISAR6 read.
Capability denial precedes FP access traps and instruction effects. Illegal
execution state retains priority over decode rejection. The A64
entry guard also rejects reserved FHM size and top-bit encodings before PC
advance. The A32/T32 decoder continues to own its encoding constraints.

The actual stateless SMIR lifter declines all 16 A64 FHM forms with empty
Undefined frontiers. This change preserves that boundary; it does not add
native FHM admission. The CPU falls back to its profile-aware interpreter.
Tests cover an integer instruction before that frontier so it is neither
skipped nor executed twice. The Linux raw native-reference helper explicitly
selects FP16/FHM for the guest interpreter; its raw host programs retain their
existing host capability checks.

## Versioned private records

| Producer | New inner tag | Retained decoder |
| --- | --- | --- |
| Standalone A32 | RAXA3202 | RAXA3201, frozen positional CPU/CP15 layout |
| S3C64xx | RAXS3C02 | RAXS3C01, same frozen CPU/CP15 layout |
| Software A64 | RAXA6402 | RAXA6401, legacy FP profile migration |

The C API outer formats remain 5 for A32 and 8 for private A64. A32/S3C v2
records add explicit CP15.ID_ISAR6. Their v1 decoders preserve every old field
and assign the old implicit standalone FHM=1 setting. The existing VFP fields
still determine the half dependency. If those nested legacy layouts change,
the real legacy fixtures must continue to restore.

A64 v1 has the same structural layout but predates coherent FP/FHM IDs and the
FHM flag. Import first compares the original public and private projections.
Only then does it recover the FHM flag from the old ID field, subject to FP16,
and normalize the two half fields and FHM ID. V2 imports reject incoherent
fields before publication. Legacy public format-4 contexts use the same
explicit migration. Formats 1/2 retain their frozen decoding path.

`legacy-provenance.json` records three actual pre-change exports and their
hashes. The A32 and A64 fixtures save R0/X0=0x123, PC=0x104 and backend count=1.
The public C API meter deliberately restarts at zero after restore; the tests
check both counters and continue through the following NOP.
The S3C fixture saves R0=0x123, PC=0x50000000 and count=0. Its producer does
not claim single-step execution; that backend does not expose this operation.
The earlier failed fixture attempts remain in the external evidence directory.

## Independent profile witness

`oracle-baseline.json` preserves the 48 original QEMU command results. The
unchanged assembly inputs are in `guests/`. Each emits its guest-visible FHM
nibble, attempts one instruction, and reports U for Undefined or P for the
following SVC. Eight vector/indexed, add/subtract, D/Q forms run in ARM and
Thumb state. QEMU 11.1.2 produced 0U on Cortex-A53 and Cortex-A55 and 1P on
max. The corrected-group replay rebuilt all guest ELFs with identical SHA-256
hashes and reproduced all 48 outputs. QEMU models are independent software
oracles, not physical A32 measurements.

For example, from this directory with LLVM and QEMU on PATH:

```sh
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT
llvm-mc -triple=aarch64 -filetype=obj guests/arm-vector-add-d.s -o "$scratch_dir/guest.o"
ld.lld -T guests/guest.ld "$scratch_dir/guest.o" -o "$scratch_dir/guest.elf"
qemu-system-aarch64 -machine virt -cpu cortex-a55 -m 128M -display none -monitor none -serial stdio -kernel "$scratch_dir/guest.elf" -no-reboot
```

Expected serial output is `0U` and exit status 0. Replacing `cortex-a55` with
`max` yields `1P`. The local Arm primary sources are
[`HaveFP16MulNoRoundingToFP32Ext`](../../architecture/arm/asl/arm_defs.asl),
the FHM instruction guards in
[`arm_instrs.asl`](../../architecture/arm/asl/arm_instrs.asl), and the FHM
register fields in [`arm_regs.asl`](../../architecture/arm/asl/arm_regs.asl).

## Qualification and scope

The new tests include 128 mixed-state profile/trap combinations, 1024 synthetic
standalone field combinations, A64 vector/indexed legal and reserved forms,
constructor/reset/ID coherence, exact interpreter fallback, real legacy context
restoration, and rejection of conflicting or incoherent private records.
Synthetic field combinations test admission boundaries; they do not assert
that every combination is a valid hardware profile. Full owning-suite results
and source/artifact hashes are retained with this semantic group's receipts.

| Assumption | Stress test and falsification probe |
| --- | --- |
| FHM1: FP16 and FHM are separate capabilities with a dependency | Vary both flags, ARM/Thumb, every implemented form and access traps; disabled execution or mismatched guest IDs falsifies the contract |
| FHM2: Old positional checkpoints remain readable | Restore the actual old exports and continue; malformed source admission or lost declared state falsifies compatibility |

The [FP access retirement correction](../fp-access-retirement.md) routes denied
instructions through the common non-retiring fault path. The subsequent
[FP control group](../a64-fp-control/README.md) adds FPCR/FPSR admission,
represented CPTR/security/VHE controls, and native permission requirements
before optimization. The subsequent [half-admission group](../a64-half-admission/README.md)
adds optional FP16 and represented reserved-field admission, including original
native feature requirements; native FP16 execution support remains a separate
interpreter boundary. High-impact remaining work includes non-half capability/profile coherence,
unrepresented FP control states, complete checkpoint/in-flight and
publication coverage, SMP/native/debug/clock/replay closure, and physical
Intel Mac HVF qualification. All four full audit findings remain partial.
The whole Linux raw native-reference suite and physical A32 behavior are
separate runtime boundaries; Apple Silicon or Rosetta evidence cannot establish
them. The S3C synthetic FP profile is not a complete ARM1176 identity claim.
