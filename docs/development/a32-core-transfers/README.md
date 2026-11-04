# A32/T32 core-extension VMOV transfers

Core-extension VMOV decoding now selects RAX's existing Undefined response for
an R15 operand before checking FP access controls. This covers transfers between
one core register and an S register or an 8-, 16-, or 32-bit D-register lane in
both ARM and Thumb states. System-register transfers retain their separate
decoder, including VMRS APSR_nzcv,FPSCR.

The execution dispatcher also checks opcode bits27:24=1100 before selecting the
two-core-register handler. Byte-lane operations have bits27:24=1110 and can share
the other dispatch bits. Previously, `VMOV.8 d0[0],r0` with
R0=0xdead89a5 and D0=0x8877665590f0b180 produced D0=0xdead89a5dead89a5.
It now produces D0=0x8877665590f0b1a5. Signed byte reads also preserve the other
core registers and apply the required sign extension.

The primary source is the existing Arm ASL instruction definitions
`aarch32_VMOV_s_A`, `aarch32_VMOV_rs_A`, and `aarch32_VMOV_sr_A`, with
`aarch32_VMOV_d_A` and `aarch32_VMOV_ss_A` defining the distinct paired class.
Their exact source digest and the unknown ASL revision are recorded in
[provenance.json](provenance.json). Decode constraints precede execute-stage
`CheckVFPEnabled` or `CheckAdvSIMDOrVFPEnabled`. R15 is architecturally
unpredictable in these operand positions; Undefined preserves RAX's selected
policy. The independent oracle is used for valid transfers, without assuming
that another implementation must select the same unpredictable outcome.

## Regression and independent evidence

The complete unchanged Linux owning binary plus the three new regression tests
produced 488 passes and two failures: the two new admission/data tests failed,
and all 487 existing tests passed. The independent QEMU run produced 216 records;
the unchanged complete RAX product differed in 12 records. Both observations are
retained in [baseline.json](baseline.json).

| Matrix | Executed coverage |
|---|---|
| R15 admission | 640 iterations across ARM/Thumb, CPACR/FPEXC enabled/disabled, ten forms, FP bank boundaries and lane boundaries; GPR, D, FPSCR and CPSR remain unchanged |
| Valid data | 216 cases: both states, ten forms, S0/S31 or D0/D31, first/last lane, Rt0/Rt12/Rt14; all GPRs, all 32 D registers, FPSCR and CPSR checked |
| Failed ARM condition | Twenty cases with access enabled/disabled and no executed effects |
| Independent execution | QEMU Cortex-A15 TCG, 216 records; raw Rt0/Rt12/Rt14, all 32 D registers and FPSCR compared |
| Mixed execution | 216 independent valid records, 80 R15/access/trap combinations and 20 failed ARM/Thumb IT predicates; enclosing integer/vector banks, PC and retirement checked |

Each independent record contains six 32-bit words and 32 64-bit registers:
6 * 4 B + 32 * 8 B = 280 B. The complete result is 216 * 280 B = 60480 B.
The instruction word and execution state identify every record. The retained
[raw observations](qemu-results.bin), [case matrix](cases.json), and
[qualification receipt](qemu-qualification.json) pin all inputs and tool hashes.
The portable reproducer independently regenerated the identical 60480 bytes.

```sh
python3 -B tools/execution/a32_core_transfer_oracle.py \
  --output /path/to/fresh-observations \
  --llvm-mc /path/to/llvm-mc --ld /path/to/ld.lld \
  --qemu /path/to/qemu-system-arm
```

Expected output reports `qualified`, 216 cases and zero differences. The result
SHA256 is 85f19000710506d37a4fdbf3bc3b2dfd9cf370c5309efc15ea2bcb0a4b9af14b.
The tool requires a new output directory, records failures, and removes its
compiled guest object and ELF after terminal execution. Guest assembly, raw
results, command logs and digests remain available. The tool uses O(N) time and
space for N cases; product dispatch and each fixed-width transfer use O(1).

## Execution planes and qualification boundary

The shared ARM/Thumb decoder and AArch32 executor serve standalone and mixed
execution. State fields, backend record formats and the C ABI are unchanged.
The A32/T32 SMIR lifters reject these unimplemented VMOV forms; this change adds
no FP lowering or native admission. Shared decoder classification is observable
through the existing analysis surface.

The complete owning `arm`, `arm_vfp_a32` and `isa_oracle` binaries passed
46850, 524 and 102 tests respectively, with zero failures, ignores or filters.
The complete changed production library also matches all 216 independent records
byte-for-byte. [production-comparison.json](production-comparison.json) retains
that comparison. The mixed CPU additionally passed the same 216 records, 80
invalid-operand/control combinations and 20 skipped predicates; its
[source](mixed-transfers-v1.rs) and [receipt](mixed-transfers-v1.json) are retained.

The unfiltered production library run registered 12312 tests: 12275 passed,
two socket tests failed and 35 tests were ignored. Both failures reproduced
with the original long TMPDIR. The identical executable passed the complete
16-test socket module with a short TMPDIR. The original failing root result
is retained in [production-validation.json](production-validation.json);
[socket-environment.json](socket-environment.json) records the controlled
environment comparison. This is not a passing unfiltered root run and does
not establish general long-path socket correctness. The ignores include
signed native HVF, installed GDB, subprocess and microkernel fixtures.
The macOS doctest command succeeded with zero active cases and five existing
ignores; an initial observer assertion requiring positive execution was corrected
without repeating successful commands. No doc-test execution coverage is claimed.
Both separately signed native ARM64 worker controls passed on the physical
Apple M4 Max: SDK PC wrapping and nested caller timing identity. Their exact
results, original binary identity and signed-clone cleanup are retained in
[native-owner-controls.json](native-owner-controls.json). These are SDK/owner
controls and do not constitute physical A32 instruction execution.

No physical A32 or physical Intel HVF execution is established by these records.

[post-integration.json](post-integration.json) records final publication-base
workspace lint, complete owning suites and independent standalone/mixed probes
after upstream source integration. The earlier root receipt retains its original
frozen manifest.

| ID | Assumption and dependency | Stress test / falsification probe | Status |
|---|---|---|---|
| MOV1 | Preserve the selected Undefined policy for R15; operand admission precedes access controls | Every represented form and competing access denial; a primary definition admitting R15 would invalidate this selection | Confirmed by the primary constraint and standalone/mixed production regressions |
| MOV2 | Two-core-register transfers require the 1100 opcode class | Byte-lane aliasing, both directions and signedness, bank/lane boundaries, and preserved neighboring registers | Original product falsified the old classifier; corrected standalone/mixed production matches all 216 records |
| MOV3 | QEMU Cortex-A15 supplies an independent oracle for these valid transfers | Match every 280-byte record to primary-derived masks and sign extension; a mismatching record falsifies agreement | Confirmed for 216 records; physical A32 behavior remains untested |

| Impact | Remaining boundary | Blocks full audit goal |
|---|---|---|
| High | Remaining complete A32 profiles/admission, private and in-flight state, SMP execution and physical Intel HVF validation | Yes |
| Medium | The independent oracle is QEMU rather than physical A32 hardware | No physical A32 claim is made |
