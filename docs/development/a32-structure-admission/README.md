# A32 structure operand admission

RAX selects Undefined for an Advanced SIMD structure load/store whose base is
R15 or whose extension-register list runs beyond D31. Those operand checks now
run during decoding, before FP access checks and effects. This preserves the
existing handler policy independently of CPACR/FPEXC/HCPTR denial and applies
through the shared ARM/Thumb decoder and mixed-width execution.

These operands are architecturally unpredictable; they are not an unallocated
instruction family. Arm DDI0597 explicitly permits Undefined for overflowing
lists. This change does not require other implementations to choose the same
permitted outcome. Failed Thumb IT conditions still suppress execution.

The represented forms are VLD1-VLD4/VST1-VST4 multiple structures and single
lanes, plus VLD1-VLD4 single structures replicated to all lanes. Register indices
are dimensionless and bounded by the 32-register extension bank:

| Form | Final D-register index |
|---|---|
| Multiple structures | first + (streams - 1) * stride + registers_per_stream - 1 |
| Single lane | first + (streams - 1) * stride |
| All lanes | first + (streams - 1) * stride + registers_per_stream - 1 |

`first` is D:Vd, `streams` is1-4, the register stride is1 or2, and the represented
per-stream count is1-4. Every intermediate fits in `u32`; the result must be less
than32 and the base must differ from15. Classification uses O(1) time and space.
Existing size/alignment allocation checks remain in the decoder, and execution
handlers retain defensive validation. No register state or checkpoint layout
changes are introduced.

## Evidence

`baseline-probe.json` retains four observed failures through the unchanged
production RAX decoder/executor: multiple-list overflow, single-lane-list
overflow, replicated-list overflow and R15 base. All four incorrectly selected
an FP trap relative to the chosen Undefined operand policy. A valid-list trap
control passed. The owning-case baseline in `baseline-owning-cases.json` has
three failures and two passing controls; its mixed-width failure reports EC7
instead of the selected invalid-instruction diagnostic.

The owning `a32_fp_controls` target registers `structure_memory.rs`. It exercises
last-valid and first-invalid lists, both register strides, all represented
structure families and element widths, ARM/Thumb, access-enabled/denied/Hyp-trap
states, unchanged registers/memory on rejection, failed Thumb IT, and mixed-width
zero-retirement behavior. Complete changed-library compilation and the full
owning target are required before a green qualification is claimed. The first
whole-library compile exposed a required widening conversion from the new
unsigned register-span values to the decoder's signed immediate representation;
that correction is not a behavioral test result.

The A32/Thumb SMIR lifters currently do not implement these structure memory
families; their shared decoder does not introduce a newly executable IR form.
Direct/mixed backend behavior and all three full affected binaries passed
qualification. See `qualification.json` for the command receipts and scope. This component does not close A32-FP or the other three findings.

## Primary sources and assumptions

`provenance.json` pins the existing Arm A32/T32 Instruction Set for A-profile
architecture, DDI0597 ID032025 (2025-03), and all20 relevant instruction sections
in the existing Arm ASL source. The ASL revision is unknown; its exact digest is
retained. Decode operand checks precede execute-stage `CheckAdvSIMDEnabled` in
both sources. The retained primary files remain unchanged under `docs/`.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| S1 | Preserve RAX's existing Undefined operand policy | Control-independent invalid-operand admission | Last-valid/first-invalid lists, R15 bases, competing FP denials and failed IT; a changed valid operation or unexpected FP syndrome falsifies the result | Baseline counterexamples observed; complete production owning suites and workspace gates passed |

| Impact | Remaining boundary | Blocks full goal |
|---|---|---|
| High | All advertised A32 capabilities, controls and admission across every represented execution plane | Yes |
| High | Complete private/in-flight/backend state, actual native secondary startup and Intel HVF validation | Yes |
| Medium | Different permitted unpredictable outcomes on other implementations | No; no universal hardware-outcome claim is made |

## Completed production owning runs

The complete changed production library compiles on native Linux x86-64 using
the pinned stable compiler and existing Cargo dependency artifacts. The complete
expanded FP-controls binary passes84 tests, the pair binary passes5, and the VFP
binary passes487:576 passed,0 failed,0 ignored,0 filtered. The extra cases include
64-bit VLD1/VST1 elements and all three writeback/addressing forms. The first
84-case run also passed before that test-data expansion.

These are software-executor results on native Linux x86-64. They do not provide
physical A32 or Intel HVF execution proof. Canonical Cargo runs also pass the same576 cases without filters. Workspace
formatting, Clippy, all-target build, alternate-feature checking and doctests pass;
two compile-fail examples pass and five pre-existing doc examples remain ignored.
The qualified source includes separately pending native entry/ownership work;
A32 code/test hashes are checked independently. Physical execution scope and the
full four-finding status remain unchanged. Publication is recorded separately.
