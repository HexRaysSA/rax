# FP access faults and retirement

An A64 scalar/vector instruction or vector load/store denied by CPACR_EL1.FPEN
does not retire. Previously the decoder entered the exception handler and
returned `CpuExit::Continue` from inside instruction execution. The common
successful-instruction path then incremented both instruction and cycle counts.
The software adapter consequently reported one retired unit and spent the
caller's budget before the handler executed.

The decoder now reports `ArmError::ArchitecturalException { ec: 7, iss: 0,
target_el: None }`. The existing error path restores the fault PC and BTYPE
without incrementing counters. Full system stepping delivers the exception
afterward and still returns `CpuExit::Continue`. A retirement-budget call returns
zero retired units and `RetirementStop::StateChange`; the handler starts on the
next call. The per-step retired-instruction clock publishes zero units.

Direct `ArmCpu::step` and diagnostic stepping now expose this fault at the
instruction PC, as they already do for other synchronous faults. A user adapter
reports EC=7 to its embedder without entering EL1. This corrects the former FP
special case; callers that used direct stepping to obtain implicit FP vectoring
must select full system stepping instead. No public enum, ABI declaration or
checkpoint wire layout changes.

The existing modeled generic timer advances 16 ticks per system instruction
attempt, including this fault. It is separate from the caller-owned retirement
clock. This change does not redefine its rate or make it a physical elapsed-time
measurement. Checks cover the zero retirement at counter values zero and
`u64::MAX`, avoiding an increment/decrement correction that could overflow.

The C API preserves its existing distinction: user exceptions produce an
`RAX_OK` stop with `RAX_STOP_EXCEPTION` and exception number 7; diagnostic
system emulation reports an error. Both expose zero executed instructions and
the retry PC. Checkpoint save/restore at that boundary retains the selected FP
permission and allows exactly one retirement after access is enabled. The
software A64 private tag remains `RAXA6402`.

## Evidence and reproduction

Primary architectural sources are the local Arm ASL
[`AArch64.CheckFPAdvSIMDEnabled`](../architecture/arm/asl/arm_defs.asl),
`AArch64.AdvSIMDFPAccessTrap` (preferred return address `ThisInstrAddr()`), and
the FP instruction access checks in
[`arm_instrs.asl`](../architecture/arm/asl/arm_instrs.asl).

The parameterized [`guest.s`](fp-access-retirement/guest.s) independently checks
nine LLVM-assembled instruction forms across EL0/EL1 and all four FPEN values.
It verifies EC, fault/return PC, saved mode, and denied GPR/vector/base-register
and RAM effects. `D` means denied at the instruction; `P` means permitted through
the following SVC; `F` is a failed assertion. For example, from this repository:

```sh
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT
llvm-mc -triple=aarch64 -filetype=obj --defsym=TEST_EL=0 --defsym=FPEN=0 \
  --defsym=OPCODE=0x1e222820 docs/development/fp-access-retirement/guest.s \
  -o "$scratch_dir/guest.o"
ld.lld -T docs/development/fp-access-retirement/guest.ld \
  "$scratch_dir/guest.o" -o "$scratch_dir/guest.elf"
qemu-system-aarch64 -machine virt,virtualization=off,secure=off \
  -cpu cortex-a53 -m 128M -display none -monitor none -serial stdio \
  -kernel "$scratch_dir/guest.elf" -no-reboot
```

Expected output is `D`, exit status 0. FPEN=3 produces `P`. QEMU is an independent
software oracle for the guest-visible fault boundary; it does not measure RAX's
retirement meter, physical Arm behavior or Intel Mac HVF execution.

| Assumption | Basis and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| FR1: access denial completes no instruction | Arm access checks precede data effects and return to the same instruction; retirement and retry depend on this | Nine data/memory forms, EL0/EL1, all FPEN values, unmapped operands, maximum counters; any committed denied data effect or retirement falsifies it |
| FR2: checkpoint capture occurs between execution calls | Existing stopped-CPU ownership; no new in-flight field is introduced | Save before/after vectoring and resume the handler once; a duplicate attempt or lost exception state falsifies continuation |

## Remaining scope

High-impact work remains for complete FPCR/FPSR system-register access checks,
CPTR/security/virtualization routing, A64 half-precision admission beyond FHM,
and the full checkpoint/in-flight, SMP/native/debug/clock/replay requirements.
In particular, the FPCR/FPSR guest system-register paths currently lack the same
FP access checks. The four full audit findings remain partial. Physical Arm and
physical Intel Mac HVF validation are separate runtime boundaries.
