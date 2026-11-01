# Architectural EL0 ID access and Linux CPUID emulation

AArch64 EL0 ID reads now reach the architectural privilege fault. Linux arm64
implements its advertised `HWCAP_CPUID` service in the Linux personality after
that fault. The shared ISA core and OS-neutral user engine no longer contain a
Linux ID-read exception to the EL1 access policy.

For example, `MRS X0,MIDR_EL1` (`0xd5380000`) at EL0 preserves the original PC,
X0, and core retirement count when rejected. An EL1 read remains available.
`MSR MIDR_EL1,X0` (`0xd5180000`) is an unallocated write and cannot manufacture
an implementation-defined register entry. The represented architectural ID
sub-block (`op0=3, op1=0, CRn=0, CRm=0..7`) has no guest MSR writes.

The direct `ArmCpu::step` API retains its typed `InvalidExceptionLevel` error.
Full-system stepping delivers the guest Undefined exception, at the guest VBAR
vector, instead of returning a host emulator error. Diagnostic stepping reports
`InvalidInstruction` at the original PC. The public C API retains its ABI and
`RaxStatus::Fault` status for diagnostic faults and now provides the precise
`INVALID_INSTRUCTION` fault kind. An OS-neutral user engine reports its existing
exception exit; it does not silently enable Linux CPUID emulation.

## Linux continuation

The Linux handler rereads the faulting 4-byte instruction through readable user
memory. It accepts only qualifying MRS encodings after an actual undefined
access. Instruction-fetch faults and structured architectural exceptions,
including illegal execution state, keep priority. Unreadable executable code
cannot be reread for this Undefined-instruction emulation path.

Linux's exposed ID view follows the retained Linux 6.19 `cpufeature.c` tables:

- MIDR exposes the lower 32 bits. MPIDR returns its safe RES1 value (`1 << 31`),
  and REVIDR returns zero.
- The CRm=2..7 feature sub-block uses the kernel's visible masks and hidden safe
  defaults. Untracked slots return zero. AIDR and unrelated register classes
  remain outside the service.
- Conditional SVE, SME, pointer-authentication, MTE, BTI, GCS, and POE fields
  remain hidden because this personality advertises none of those process ABIs.
- An emulated word advances PC by 4 bytes, discards an XZR destination, and
  clears PSTATE.BTYPE as Linux's `arm64_skip_faulting_instruction` does.

Each emulated MRS consumes one user-run budget slot. Preceding core retirement
is deducted using wrapping `u64` subtraction. The handler cannot overrun a zero,
one-word, or exact budget. The emulated trap does not retire in the ISA core;
core counts and user scheduling slots remain distinct. The existing synchronous
exit policy clears the local exclusive reservation before the continuation, so
an LDXR reservation cannot survive this fault into a subsequent STXR.

The handler uses the existing public system-state export rather than adding an
OS policy field to CPU checkpoints. Its work and temporary storage are O(S)
for S modeled system-register entries; instruction decoding and mask selection
use fixed-size operations.

## State and execution planes

No public register layout, checkpoint record, or C ABI layout changes. Restored
EL0 full-system contexts continue through the architectural fault and guest
handler. The SMIR lifter supports only NZCV/FPCR/FPSR in this system-register
path and rejects these ID accesses. Native compilation must retain the exact
interpreter fault frontier rather than optimize away an ID read or write.

## Primary evidence and limits

The retained Arm DDI 0487B.a D7.2.73 accessibility table specifies MIDR_EL1 as
inaccessible at EL0 and read-only at represented privileged ELs. The retained
`AArch64.CheckSystemAccess` ASL requires EL1 for `op1=000`.

Linux's policy is defined by `is_emulated`, `emulate_sys_reg`, `do_emulate_mrs`
and `try_emulate_mrs` in the retained Linux 6.19 `arch/arm64/kernel/cpufeature.c`,
and by `do_el0_undef` and `arm64_skip_faulting_instruction` in `traps.c`. Safe
MPIDR identity is `SYS_MPIDR_SAFE_VAL` in that release's `sysreg.h`.

The [qualification record](qualification.json) links observed pre-fix failures, exact source and
primary-reference hashes, the mask derivation, strategic tests, complete owning
suites, and a physical Apple Silicon Darwin EL0 probe. That probe confirms only
SIGILL disposition for the four tested MRS words. It does not identify exact EC,
validate AArch32 hardware, or qualify Intel execution.

This change covers the represented profile without FEAT_IDST. An IDST profile
changes system-access exception classification and requires separate admission
and qualification. Restricted A32 rounding/NaN/subnormal profiles, remaining
security/debug controls, native scheduling/IRQ/replay, and physical Intel
qualification remain open under the original audit findings.

Primary references:

- [Arm DDI 0487B.a](../../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf), D7.2.73.
- [Arm shared ASL](../../architecture/arm/asl/arm_defs.asl), `AArch64.CheckSystemAccess`.
- [Linux CPUID implementation](../../specifications/linux/kernel-6.19/arch/arm64/kernel/cpufeature.c).
- [Linux trap/skip path](../../specifications/linux/kernel-6.19/arch/arm64/kernel/traps.c).
- [Linux safe register definitions](../../specifications/linux/kernel-6.19/arch/arm64/include/asm/sysreg.h).

## Historical allocation expectations

Two historical generated cases for `0xd5180000` required an allocated result.
The [focused correction](legacy-sysreg-correction.json) uses the retained
MIDR_EL1 primary definition and an independent EL1 QEMU payload. Both selected
QEMU CPU profiles report Undefined for all ten probed ID writes; positive MIDR
reads, identity and source-register preservation are checked separately.
This is software-oracle evidence and does not qualify physical EL1 execution.

The correction preserves every corpus byte outside the two assertions and
records the corrected output digest in `tests/generated/manifest.toml`.
Its guard tests reject changed source, scope, primary evidence and oracle
results. Run the checks from the repository root:

```sh
python3 -B tools/testgen/a64_sysreg_expectations.py
python3 -B -m unittest discover -s tools/testgen -p test_a64_sysreg_expectations.py -v
```

Use `--write` on the correction tool to refresh those two qualified expectations.
The independent [QEMU probe](qemu-readonly-id.py) accepts `--llvm-bin`, `--qemu`, and
`--output`. Write fresh oracle runs to a distinct output file for comparison
with the pinned evidence. The historical full-corpus input and generator
revision remain unknown; this tool is a focused correction, not a full
regeneration claim. RAX's own current characterization is not the independent
basis for these expected results.
