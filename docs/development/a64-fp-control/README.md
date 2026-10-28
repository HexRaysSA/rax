# A64 FP system-register access and native admission

Guest MRS/MSR accesses to FPCR and FPSR now check access controls before reading
or writing the register, including Rt=31. Data, SIMD and vector-memory access
paths share the represented higher-level controls. A denied instruction returns
the synchronous exception before retirement; system stepping delivers it at the
original instruction PC. Host register inspection and replacement remain host
operations and do not require guest permission.

The common policy represents CPACR_EL1.FPEN, CPTR_EL2.TFP or its VHE FPEN field,
CPTR_EL3.TFP, HCR_EL2.E2H/TGE, implemented exception levels, and the existing
security-derived EL2 enable predicate. Local access denial has priority over
higher controls; EL2 precedes EL3. A redirected local EL0 denial uses EC=0,
whereas the ordinary FP access trap uses EC=7. AArch32 retains its separate
local CPACR, FPEXC, security and syndrome rules and shares only the higher
AArch64 control policy.

Native admission retains data/system access requirements from the original
guest instructions before IR optimization. These requirements are independent
of the optimized function's host FP register liveness. The parent implementation
could optimize `MRS XZR, FPCR` out, clear `uses_fp`, and execute the cached native
region after FP access was disabled. The retained parent probe executed that
bypass. The corrected native entry refuses it before side effects; the
interpreter then retires preceding integer instructions and faults at the FP
access. Cold-cache admission and existing cached regions also recheck effective
higher-level permissions. Re-enabling permissions cannot retain a denied cache
memo under the enabled key.

Collecting requirements takes O(N) time over original IR operations and O(1) additional space.
These permission requirements are derived native caches. No public API, ABI,
or checkpoint wire layout changes. The software A64 private tag remains
`RAXA6402`; restored architectural controls determine access after restore.

## Primary provenance and source discrepancy

The unchanged [Cortex-A720 TRM](primary/cortex-a720-102530_0002_05_en.pdf),
Arm document 102530_0002_05_en, r0p2 Issue 05, contains the explicit FPCR access
pseudocode on printed pages 193–194. [Provenance](primary/provenance.json)
records its official URL and SHA-256. This source supports the FPCR register
entrypoint; it is not a claim that the configured PE is a Cortex-A720 or that
this manual contains an FPSR register section. The independent guest oracle
also exercises the matching FPSR access forms.

Data and higher-level rules use the pinned Arm XML 2025-12
[`shared_pseudocode-2025-12.xml`](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml),
in particular `AArch64_CheckFPEnabled`, `AArch64_CheckFPAdvSIMDTrap`, and
`AArch64_AdvSIMDFPAccessTrap`. Its SHA-256 is
`84c3572ef27cb9a7b12cba314d62d1b8afd71c770ee92d818cbdb4dc6ac37d6b`.
The older ASL under `docs/architecture/arm/asl/` differs for VHE FPEN=x0 in a
synthetic EL1/TGE=1 state. The newer pinned XML specifies denial unconditionally
for x0 and supplies the shared higher-level rule. EL1/TGE=1 is not a reachable
ERET target and is covered only as a synthetic unit-test stress case, never as
a physical-machine result.

## Independent oracle

[`guest.s`](guest.s) starts at EL3 using QEMU's generic loader, selects an
explicit normal-execution control profile, and enters the requested EL. It
checks exception level, EC, fault/return PC, saved mode, and the denied X0
destination. EL0 mode is verified through saved state rather than by issuing
the privileged CurrentEL read at EL0. The ELF is linked at 0x40200000 to avoid
QEMU's generic-loader device-tree reservation. Semihosting writes four bytes
and exits; no PSCI firmware assumptions are required.

For example:

```sh
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT
llvm-mc -triple=aarch64 -filetype=obj \
  --defsym=TEST_EL=1 --defsym=FPEN=3 --defsym=HCR=0x80000000 \
  --defsym=CPTR2=0x400 --defsym=CPTR3=0 --defsym=SECURE=0 \
  --defsym=OPCODE=0xd53b4400 docs/development/a64-fp-control/guest.s \
  -o "$scratch_dir/guest.o"
ld.lld -T docs/development/a64-fp-control/guest.ld \
  "$scratch_dir/guest.o" -o "$scratch_dir/guest.elf"
qemu-system-aarch64 -machine virt,secure=on,virtualization=on \
  -cpu max -m 128M -display none -monitor none -serial none \
  -semihosting-config enable=on,target=native \
  -device loader,file="$scratch_dir/guest.elf",cpu-num=0 -no-reboot
```

Expected semihosting output is `207I`: target EL2, EC=0x07, exception at the
tested instruction. `115A` means the access completed and the following SVC
entered EL1 with EC=0x15. `F` is an assertion failure. QEMU writes semihosting
text to stderr in the retained run.

The retained QEMU 11.1.2 corpus contains 25 explicit profiles, 225 unique
guests and 369 executed cases. It covers all four system-register operations
with Rt=0/31 and FADD, with Cortex-A53 plus max for non-VHE profiles and max
for VHE. Outcomes are explicit profile expectations, independently checked
against QEMU. Local FPEN controls also retain 64 older QEMU cases and the
actual parent CLI's 20 disagreements across 32 guests.

Owning unit checks cover all 32 Rt values, EL0/EL1, every FPEN setting, denied
side effects, illegal-state priority, security and optional VHE, native dead
results, cached/cold permission transitions, and exact fallback fault PCs.
Some overwritten-result and MSR region shapes are already native-ineligible;
those test the interpreter frontier. MRS XZR native cases must compile and
execute under enabled controls, so fallback cannot conceal the parent bypass.
Backend and C API checks cover private checkpoint restore, zero retirement,
exception delivery, and permission-enable retry.

## Assumption register and bounds

| ID | Assumption and dependent result | Basis | Stress / falsification probe | Status |
| --- | --- | --- | --- | --- |
| FC1 | Original guest accesses carry permission effects even when their results are dead | Arm access pseudocode; actual parent native bypass | MRS XZR before/after optimization, enabled native execution, disabled native refusal; any denied native side effect falsifies the guard | Confirmed for tested native shapes |
| FC2 | The existing EL2 security predicate selects higher control applicability | Existing represented SCR/implemented-EL/VHE state | Secure/non-secure oracle profiles and optional-VHE unit controls; disagreement in selected target/EC falsifies it | Confirmed within represented profiles |
| FC3 | The selected tests describe normal execution | Existing CPU has no architectural halting-debug or SME streaming state | Separate those architectural states before extending this policy; do not substitute HLT/CPU.halted for halting debug | Retained boundary |
| FC4 | Checkpoint capture occurs between execution calls | Existing stopped-CPU ownership; requirements are derived caches | Restore higher controls, deliver zero-retirement fault, resume once; duplicate or missing execution falsifies it | Confirmed at tested boundaries |

The subsequent [half-admission group](../a64-half-admission/README.md) adds
optional FP16 and represented reserved-field admission, including original
native feature requirements. High-impact remaining scope includes non-half
capability/profile coherence, full SVE/SME access behavior, unrepresented halting-debug controls, and the full
checkpoint/in-flight, multi-vCPU/native/debug/clock/replay requirements. These
remain open full findings. QEMU is a software oracle; Apple Silicon native
execution and Rosetta do not establish physical Intel Mac HVF behavior.

## Qualified implementation evidence

The current engine replays all 225 higher-control guests and matches the oracle.
The current CLI matches all 32 retained local-control guests, resolving the
parent CLI's 20 disagreements. Runtime sources are frozen before validation;
raw guest ELFs, outputs, parent failures and artifact hashes are retained in
this group's audit evidence.

Owning integration: 47706 passed across 23 targets. C API: 213 passed; 18 C/C++ consumers and 6 ABI checks passed. Library: 11202 passed, 0 failed, 2 ignored. Doctests: 5 ignored.

The earlier group retains an unchanged Darwin ptrace transport failure and its independent-parent reproduction. A passing new run does not establish a fix for that unchanged source or resolve its unknown root cause.

Rosetta validates x86-64 interpreter paths; it does not establish physical
Intel Mac HVF execution. All four full audit findings remain partially validated.
