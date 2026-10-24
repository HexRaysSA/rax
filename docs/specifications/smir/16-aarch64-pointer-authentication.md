# 16. AArch64 pointer authentication support contract

Status: implementation complete within the explicit execution frontiers below;
physical x86-64 runtime validation pending, 2026-10-24. Working-tree
baseline: `a36bd7f60a7a727fd8e1a90c0ae466b69f2882eb`. Rust source is
authoritative, followed by CI definitions and this derived specification. The
full plan is unfinished until its remaining validation requirements are met.

## Scope and architectural model

The shared decoder recognizes these 33 explicit forms and 13 HINT aliases:

| Group | Mnemonics |
|---|---|
| Signing | PACIA, PACIB, PACDA, PACDB, PACIZA, PACIZB, PACDZA, PACDZB |
| Authentication | AUTIA, AUTIB, AUTDA, AUTDB, AUTIZA, AUTIZB, AUTDZA, AUTDZB |
| Stripping / MAC | XPACI, XPACD, PACGA |
| Branch / call | BRAA, BRAB, BRAAZ, BRABZ, BLRAA, BLRAB, BLRAAZ, BLRABZ |
| Return | RETAA, RETAB, ERETAA, ERETAB |
| Load | LDRAA, LDRAB |
| HINT aliases | XPACLRI, PACIA1716, PACIB1716, AUTIA1716, AUTIB1716, PACIAZ, PACIBZ, PACIASP, PACIBSP, AUTIAZ, AUTIBZ, AUTIASP, AUTIBSP |

The address operations use PACA; PACGA uses PACG.
Without their feature, explicit instructions are UNDEFINED. Architectural HINT
aliases remain NOPs when their feature is absent. Adjacent MTE instructions
SUBP, SUBPS, IRG and GMI retain explicit lift rejection.

`AArch64Config.pauth` selects QARMA3 or QARMA5 and Base, PAuth2, FPAC or
FPACCOMBINE. The default selects QARMA5 with PAuth2, FPAC and FPACCOMBINE.
Default CPU feature bits are unchanged. ID-register fields report the selected
algorithm/profile only when its PAuth feature is enabled. Reset clears keys and
SCTLR authentication enables while retaining the configured algorithm/profile.
This is keyed execution; the previous FEAT_PACIMP identity model is removed.

Five independent 128-bit keys occupy the existing architectural system-register
storage: APIA, APIB, APDA, APDB and APGA. PAC/AUT use the selected key and
modifier. XPAC strips the PAC field and restores extension; PACGA writes its MAC
in bits [63:32] and clears bits [31:0]. Neither is a NOP. EPAC, PAuth_LR, GCS
and larger-address extensions are outside the accepted plan.

The runtime supports the existing non-LVA translation model: 16-48-bit virtual
addresses, with the 64 KiB granule's 47-bit restriction. Layout selection uses
the effective translation regime, TBI/TBID, upper/lower range and VHE controls.
The pure primitive supports wider layouts for independent arithmetic checks;
that does not advertise a wider architectural translation capability.

## Representation and admission

| Plane | Implemented contract | Principal source |
|---|---|---|
| Shared decode | All explicit/HINT forms; SP modifiers; distinct authenticated loads; reserved-field checks | `src/isa/arm/decoder/aarch64/pauth.rs` |
| Direct execution | Keyed signing/authentication, stripping, MAC, branches, loads and exception return | `src/isa/arm/aarch64/cpu/pauth.rs`, `pauth_execution.rs` |
| State and permissions | Five keys, feature/profile selection, SCTLR/HCR/SCR use and key-access controls, BTYPE and complete modeled PSTATE | `pauth_state.rs`, `cpu/state.rs`, `cpu/entry.rs` |
| SMIR lift | Feature-bound typed ArmPauth with Begin/Commit instruction boundaries | `src/smir/lift/aarch64/pauth.rs` |
| SMIR IR/interpreter | Explicit state effects and precise exceptions; shared framing validation and architectural planner | `src/smir/ir/ops/arm_pauth.rs`, `src/smir/interpret/arm_pauth.rs` |
| Optimizer | Architectural state remains observable at helper/fault boundaries; instruction frames survive optimization | `src/smir/optimize/`, `src/smir/ir/arm_instruction.rs` |
| AArch64 native | Opt-in scoped helper ABI; guest GPR/NZCV/FP preservation; conditional branches retain retirement markers | `src/smir/lower/aarch64/pauth.rs`, `blocks.rs`, `branch.rs` |
| x86-64 native | State-backed opt-in helper lowering; cross-checks and supplementary translated execution pass; physical x86-64 execution pending | `src/smir/lower/cross/aarch64_guest_to_x86_64_host/` |
| CPU JIT | Exact one-instruction PAuth regions, dynamic state and code revalidation, precise dispatcher exits | `cpu/pauth_jit.rs`, `cpu/pauth_user_jit.rs` |
| Backend/persistence | Complete keyed/system state, banked SPs and execution width; validation precedes mutation | `src/backend/emulator/aarch64.rs`, `src/vm/snapshot.rs` |
| C/C++ ABI | Additive configuration and key/control registers; strict format-4 contexts and frozen legacy readers | `capi/src/pauth.rs`, `capi/src/context/aarch64.rs`, `capi/include/rax.h` |
| Oracle | Explicit authenticated metadata and typed SMIR; default unconfigured lifting reports rejection | `src/oracle/arm_pauth.rs`, `arm_control_flow.rs` |

Without `LiftContext.aarch64_features`, all 46 forms return Unsupported through
explicit dispatch in both lifter modes. With a configured feature set, execution
checks exact feature equality and complete state. Lowerers require an explicit
scoped-helper opt-in; generic JIT safety does not imply native admission.
Unsupported state exits at the exact guest frontier before approximate effects.

The native ABI appends context/function fields at byte offsets 896/904;
`Aarch64GuestRegs` occupies 912 bytes without moving its previous fields. Guest
keys never become host PAC keys, and scoped runtime pointers are cleared after
execution. CPU promotion runs the region on a subsequent dispatcher step, so
instruction/timer boundaries are preserved. EL0 native admission is disabled
throughout memory-recorded steps.

`Aarch64MemoryBridge` supplies CPU fetch GP and checked architectural-load
semantics. Translated authenticated loads require that bridge; missing hooks
exit Unsupported. Flat loads resolve TBI, alignment and EE/E0E. Generic SMIR
accesses use the supplied memory backend, which must share coherent backing with
the CPU when both paths are used in one program.

## Precise architectural effects

Authentication precedes destination, LR, PC and load writeback changes. Modifier
and target aliases are read before a call updates X30. LDRAA/LDRAB have signed
10-bit offsets scaled by 8 bytes, with offset or pre-index addressing. Writeback
with `Rn == Rt != 31` selects the permitted UNDEFINED resolution. They cannot
enter the STR/post-index decoder path.

FPAC failures preserve pre-instruction registers, PC, NZCV and BTYPE. Their
synchronous exception has EC 0x1c and an ISS identifying data/instruction key
and key B. Key-access traps have complete system-register ISS; PAC-use traps,
feature absence, illegal execution state and guarded-page BTI have distinct
checks. ERET virtualization traps precede authentication and saved-state checks.
System exception delivery records the actual target EL, precise saved PC,
PSTATE, FAR and syndrome. HCR.TGE, stage 2 and external-abort routing are observed;
per-instruction fault metadata is reset.

ERETAA/ERETAB authenticate ELR with the source SP before restoring the saved
state. Successful return clears the local exclusive monitor and sends the local
event. Saved mode, implemented ELs, security and SCR/HCR execution-width controls
select legal return or illegal-return IL behavior. BTYPE, debug SS restoration
and the relevant PSTATE fields follow the retained Arm shared pseudocode.

## AArch32 exception-return handoff

Legal AArch32 returns restore ARM/Thumb execution, mode, Q, IT, GE, E, AIF,
PAN, SSBS, DIT, IL and modeled SS. Invalid/reserved IT combinations and SCTLR.ITD
use the documented constrained choices. The target is truncated to 32 bits;
Thumb clears bit 0 and ARM clears bits [1:0]. Authentication occurs first.
Consequently poison confined above bit 31 can be discarded by an AArch32 return
without FPACCOMBINE; tests retain this architectural behavior explicitly.

R0-R7 alias X0-X7. Other register aliases follow Arm `LookUpRIndex`:

| AArch32 mode | R8-R12 | R13 | R14 |
|---|---|---|---|
| User / System | X8-X12 | X13 | X14 |
| FIQ | X24-X28 | X29 | X30 |
| IRQ | X8-X12 | X17 | X16 |
| Supervisor | X8-X12 | X19 | X18 |
| Abort | X8-X12 | X21 | X20 |
| Undefined | X8-X12 | X23 | X22 |
| Hyp | X8-X12 | X15 | X14 |

AArch32 writes preserve the physical X register's upper 32 bits, an allowed
ZEROUPPER=FALSE choice. AArch64 SP banks remain independent. AArch32 D0-D31
alias the two 64-bit lanes of V0-V15; V16-V31 remain unchanged.

`cpu/aarch32/` bridges the existing ARM/Thumb executor to shared physical
registers and checked memory. It preserves exclusive reservations across steps,
checks the memory backend's reservation before stores and handles byte/halfword/
word/doubleword sizes and both data byte orders. Reset clears both the local and
memory-backed reservations, including across a subsequent switch to AArch64. Thumb fetch supports halfword
alignment and independent second-half fetch faults. SVC instruction length is
preserved through system and C API reporting. AArch64 handlers use the lower
AArch32 vector bank and can authenticate their return back to ARM/Thumb.

AArch32-mode handlers use their banked SPSR/LR, vector base and saved CPSR
format, including the different DIT location. Abort status uses DFSR/IFSR and
DFAR/IFAR rather than treating AArch32 EL1 as an AArch64 handler. Illegal-state
delivery distinguishes UNDEF at AArch32 EL1 from the illegal-state exception
delivered to AArch64 and Hyp handlers, and observes the destination's vector
controls.

This handoff does not add an AArch32 MMU implementation. An enabled AArch32
translation regime, or a coprocessor transfer whose shared-state contract is
unimplemented, returns UnsupportedExecutionState at the exact PC. It does not
use AArch64 page descriptors, default v7 CP15 values, or inject guest UNDEFINED.
AArch32 EL0 under an AArch64 translation regime uses the existing checked walker.

## State, ABI and Darwin integration

VM checkpoint format 8 rejects older layouts before decoding. C API context
format 4 preserves complete state; frozen formats 1/2 reject enabled
authentication without keys and cannot represent mixed-width state. AArch32
saved-state readers require complete execution controls and compatible PFR0/
SCR/HCR values before resetting or changing the destination CPU. Current SP
is canonical and overlays its physical alias or AArch64 bank consistently.

Linux exposes authentication failure as SIGILL/ILL_ILLOPN. Darwin carries EC/ISS
and the Mach PAC-failure code. Darwin capability sysctls and capability bits
follow the active PAuth feature/profile, and no longer advertise FEAT_PACIMP or
its legacy alias. Darwin arm64e image activation creates five keys
per exec using checked entropy, installs one task domain in all new threads,
and inherits it across fork. Thread cloning preserves keys, controls, SP banks
and modeled execution state. This virtual QARMA domain does not reproduce
Apple's private hardware key diversification.

Darwin cache-v5 rebases use key kind, diversity and actual guest storage address.
Each source owns a frozen key context and private page cache. Thread-state and
signal producers sign PC/LR/SP/FP and ucontext/token fields with the XNU
contracts; consumers authenticate or poison incoming pointers. Registered
pthread/workqueue and signal trampolines authenticate before becoming kernel-selected PCs. NOJOP, nullable fields and already IB-signed LR retain their ABI
behavior. Sources and exact string discriminators are retained in the provenance
records below.

## Requirement traceability

| Original item | Implementation and acceptance evidence |
|---|---|
| D1 / PAUTH-4 | BRAA/BRAB have explicit configured lift and unconfigured rejection; strict and non-strict tests |
| D2 / R7 | Zero-modifier branches and authenticated exception returns decode distinctly; reserved-field and register-slot campaigns |
| D3 / R7 | LDRAA/LDRAB have their own mnemonics, signed scaled offsets and exact load/writeback tests |
| D4 / validation | Complete-form direct/SMIR/native comparisons, exact faults and nonzero native-entry assertions |
| D5 | MTE remains an explicit unsupported frontier; no PAuth semantics are assigned to MTE |
| D6 / R3 | Independent PACA/PACG gates, including all four feature combinations; HINT absence retains architectural NOP behavior |
| R1 | Typed IR, metadata, interpreter, optimizer and both lowerers are connected and exercised |
| R2 | Key/control/PSTATE/SP/width state survives CPU, SMIR, native, C API and checkpoint adapters; incomplete state rejects before mutation |
| R4 | Precise authentication fault PC/EC/ISS/state and architectural exception-return priority are tested |
| R5 | QARMA3/QARMA5 replace identity semantics; independent C vectors and layout/fault campaigns |
| R6 | Both lowerers implement scoped helpers and reject without opt-in; AArch64 native execution is established; physical x86-64 validation remains pending |

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Pinned QEMU is an independent arithmetic cross-check; Arm remains architectural authority | Distinct unchanged C and Rust implementations, verified source hash | Primitive/layout evidence | Both algorithms, both key halves, corrupted signatures | Run reference scripts; any value/ISS mismatch falsifies agreement | Confirmed for executed cases |
| A2 | The non-LVA TxSZ FORCE/clamping choice matches the existing walker | `mmu::sanitize_tsz` and Arm effective PAC TxSZ | Runtime PAC layout | Granules, upper/lower ranges, TBI/TBID, VHE | Matched architectural configuration produces a different PAC field | Retained; resolved-layout oracle and regime tests pass |
| A3 | Private CPU mode/EL metadata is valid at semantic entry | Checked saved-state/control interfaces and private execution state | Bounded shifts and register-bank selection | Every legal mode, malformed images, unsupported width | Invalid mode reaches arithmetic or a bank access through a checked interface | Confirmed for tested boundaries |
| A4 | Mixed generic/CPU memory hooks share coherent backing | Bridge delegates the two access planes separately | Mixed memory execution | Generic store then authenticated load through an alias | Values differ between backing paths | Retained integration contract |
| A5 | One typed PAuth instruction does not change translation roots/keys before its last memory hook | Descriptor/effect inventory and ERET commit order | CPU bridge retains live system object | Dynamic keys, ERET, tagged faults, stale code | A supported effect changes controls before a later memory hook | Confirmed for current forms |
| A6 | Darwin's private shared region uses one virtual task QARMA domain per exec | Existing private mapping model and XNU inheritance | Kernel-produced and guest-consumed pointers agree | New threads, fork, fresh exec, remapping, nested signals | Wrong-domain authentication or cross-source page reuse | Retained model choice, with independent vectors and lifecycle tests |
| A7 | EL0 embedder code backing is guest RAM and translation probes have no guest I/O effects | `new_user` disables machine devices; checked GuestMemoryMmap | Compilation/code revalidation | Permission revocation, stale code, memory hooks | Probing performs guest I/O or adds a recorded instruction access | Retained; recording disables native admission |

## Validation and remaining evidence

The unchanged pinned QEMU primitive and architectural functions have passed
independently seeded campaigns, including 25,216 resolved-layout comparisons
with 4,420 exact authentication faults. Darwin has 20 independent signing
vectors and six Clang string-discriminator checks. These are arithmetic/ABI
checks, distinct from execution-plane evidence.

Complete-form execution campaigns cover 46 forms, two algorithms, four profiles,
both feature settings and O0/O1/O2: 2,208 interpreted and 2,208 actual AArch64
native comparisons. Successful-authentication campaigns add 1,104 cases per
execution plane; distinct-key and MMU bridge campaigns add 60 and 54 comparisons.
CPU native admission has 736 full-state system-step cases with nonzero native
entry counts, precise counters and no replay of a faulting instruction.

Mixed-width tests cover 384 direct legal handoffs, 768 SMIR and 768 native
O0/O1/O2 full-state comparisons, and 32 actual CPU native-admission handoffs that
continue through ARM/Thumb instructions. Additional tests cover IT restoration,
FP aliasing/access denial, reservations, exact saved state and C API/checkpoint
persistence. Loop/CFG tests add 48 interpreted and 48 native comparisons with
live NZCV/GPR values, two loop predecessors and faults after prior retirements.
Architectural condition destinations remain observable when folding branches.

The final aggregate checkpoint passes 10,544 library tests with 2 ignored,
including reset's cross-width monitor regression. The subsequent illegal-state
handler correction passes in the latest 114-test focused PAuth run. All 192
Darwin library tests pass after capability reporting changes. All 192 C API
tests pass, including mixed-width context/SVC/BKPT reporting and actual-native
AUT fault cases. Its targeted mixed-width rerun passes after breakpoint
classification was added. The C/C++ consumers passed at the preceding ABI
checkpoint; no public C layout changed in the mixed-width follow-up.

All 117 pre-existing Darwin host-oracle tests passed at the earlier broad
checkpoint. The updated required arm64e comparison passes again after the
capability correction, with matching `pauth=32 signal=1 thread=85 fork=1`
output on Apple hardware and under RAX. No oracle skip is accepted for that
comparison.

Workspace all-target Clippy passes with `--no-default-features --features
x86_64-suite,smir-jit`; portable library checking passes without default
features. The x86_64-apple-darwin library and test targets cross-check
successfully. Supplementary x86-64 execution under Rosetta passes 102 focused
tests with no ignores or self-skips at the reset checkpoint. These exercise the
cross-lowerer's complete-form, successful-authentication, key, MMU, CFG and
mixed-width matrices. `sysctl.proc_translated=1` confirms this is translated
execution; physical x86-64 native validation remains pending. An additional
Linux x86-64 cross-check stopped in a C dependency because
`x86_64-linux-gnu-gcc` is unavailable. Dependency and lockfile state are
unchanged. Formatting, owned-path review and whitespace checks pass; the index
is empty.

| Remaining requirement | Status |
|---|---|
| Physical x86-64 native execution of the registered matrices | Pending; this workspace is Apple Silicon. Cross-compilation, Rosetta and QEMU do not supply that evidence |
| Aggregate library/C API checks after mixed-width and CFG changes | Passed at the checkpoints above |
| Documentation/diff audit | Passed; untracked user content preserved and nothing staged |

## Bounded findings

| Impact | Evidence and task effect |
|---|---|
| Medium | CPU native PAuth regions retain one-instruction dispatcher boundaries; wider CPU CFG admission is conservative, while scoped runtime CFG execution is tested |
| Medium | AArch32 MMU formats and unbridged coprocessor transfers have explicit host-side frontiers; the handoff itself and supported subsequent instructions execute |
| Medium | Ordinary scalar loads retain the backing-memory byte-order contract; authenticated loads explicitly resolve SCTLR EE/E0E. General scalar endianness is outside this PAuth change |
| Medium | HVF exports the legacy state subset; complete keyed checkpoint writing rejects incomplete state. Hardware-backed keyed migration is not established |
| Medium | The no-JIT library-test configuration has pre-existing JIT-only references in memory-alignment tests; portable library checking passes |
| Medium | The standalone ASL-parser lockfile is stale; its locked test run is blocked, and dependency state is preserved |

## Maintenance requirements and provenance

A PAuth change must preserve explicit mnemonic coverage, guest feature gating,
precise fault/retirement boundaries, full key/control/width state, and deliberate
native rejection where lowering is incomplete. New effects require auditing IR
metadata, interpreter, optimizer, both lowerers, CPU admission and public state
adapters. Tests must compare complete relevant values and show nonzero executed
case counts without self-skips. Unsupported forms cannot become approximate
branches, loads, or NOPs.

Primary sources: [Arm/QEMU provenance](../arm/pauth/PROVENANCE.md), retained
Arm A64 XML 2025-12 shared pseudocode, [reference tools](../../../tools/pauth-reference/README.md),
and the checksummed XNU 12377.121.6 sources under
`docs/specifications/darwin/`. The independent C oracle is compiled only for
validation and is not linked into the RAX engine.
