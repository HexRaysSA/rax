# GIC pending sources and checkpoint restoration

A physical level, a software pending request, and a latched edge now have distinct
state. Previously, deasserting a PPI could erase a software request for the same
INTID, and ICPENDR could erase an asserted physical level. The source state now
survives private CPU and shared VM checkpoints. UART and external SPI publication
use physical input setters. Restore retains the destination IRQ Arc handles.

| Input operation | Level-triggered result | Edge-triggered result |
| --- | --- | --- |
| Software set-pending | Latch a software request | Latch a software request |
| Physical deassertion | Withdraw only the physical level | Retain a previously latched edge |
| Clear-pending | Clear software; an asserted level remains pending | Clear software and the edge latch |
| Acknowledge | Retain the existing software-clear policy and asserted level | Consume software and edge requests; retain physical input history |
| Unchanged asserted physical input | Keep its level | Generate no repeated edge |

Active state remains separate. The parent already excluded active-and-pending
interrupts from signalling; this group preserves that rule and adds an EOImode1
roundtrip control. Software-pending level acknowledgement follows the existing
implementation-defined policy: software withdraws that request through ICPENDR.

The ordinary SPI register domain is clamped to INTIDs 32-1019. Under RAX's admitted
992-slot storage capacity, the four slots corresponding to special INTIDs
1020-1023 remain outside ordinary SPI registers and input setters. This does not
classify 992 ordinary SPIs as an architectural configuration.

## Framing and admission

| Record | Current frame | Legacy treatment |
| --- | --- | --- |
| Private CPU with an owned GIC, unbound counter | RAXA6405 | RAXA6401/02/03 use the frozen old GIC layout |
| Private CPU with an owned GIC, VM counter | RAXA6406 | RAXA6404 retains its counter-domain header |
| Private CPU without an owned GIC | RAXA6403/04 unchanged | Existing optional-FP migrations retained |
| Shared GIC without UART | RAXEXE05 | RAXEXE02 uses the frozen old GIC layout |
| Shared GIC with UART | RAXEXE06 | GIC-bearing RAXEXE03 uses the frozen old layout |
| No shared GIC | Existing RAXEXE01/03/04 | Unchanged |

Current records validate source topology, aggregate pending consistency and
reserved slots. Each private CPU's last-published virtual/physical timer output
must match its GIC PPI27/PPI30 line state. Admission compares the publication cache,
not the desired comparator level: a reset can retain a still-owed deassertion.
Shared restoration requires the complete CPU cohort and rejects mismatches before
publishing CPU, controller, clock, coordinator or RAM state.

The user selected rejection of ambiguous legacy sources. A legacy pending PPI/SPI
or any edge-configured PPI/SPI is rejected; an edge input's line history is missing
even when its pending bit is clear. A nonpending level aggregate has the unique
inactive source interpretation under a coherent aggregate model. SGIs retain
their software-only interpretation. This inference does not recover physical or
software history already erased by a historical bug. It is a logical migration
of the encoded aggregate, not proof about an uncaptured historical device input.

Raw public CPU-interface pending-bit edits can be reconciled when they change an
observable bit. An idempotent raw assignment carries no new request event;
request-generating host callers use the canonical setters or guest MMIO methods.

## Primary rules and regression evidence

[Arm IHI0069H, ID020922](../../specifications/arm/gic-ihi0069.pdf), sections 4.1,
4.5, 12.11.27 and 12.11.10, defines the relevant lifecycle and pending-source rules.
Section 12.1.3 defines supported access widths; the guest regressions use 32-bit
pending-register accesses. Unsupported byte pending-register accesses have
UNPREDICTABLE behavior and are outside this repair. Section 2.3 and Table 2-1
separate ordinary SPI and special INTID ranges. The retained PDF hash is checked
in qualification.json. Initial missing-active-guard and defined-byte-access
hypotheses were falsified and did not produce production changes.

Two new PPI regressions failed on the unchanged parent root executable. A third
reserved-ID regression failed in a harness built from the exact parent GIC
component sources with a minimal Error shell; it was not a full-parent workspace
run. A further exact-parent component probe confirms that restoring a consumed
edge and publishing its unchanged asserted input repeats the edge. The final
source adds twenty Rust tests: ten controller, four private
backend/UART, one shared external-line and five real VMM tests.

Per runtime matrix execution, nine source-free files cover 1/2/4 prepared PEs:
software/physical overlap followed by deassertion; asserted levels followed by
clear-pending; and consumed edge history followed by unchanged-high and a fresh
edge. Both original kernel and checkpoint files are removed before each fresh
constructor. Continuations compare complete public CPU images, instruction counts,
coordinator, GIC source state and the VM-owned Retired clock. Five first/last-CPU
source mismatches test transactional rejection. These prepared peer cases do not
establish guest cold startup. Existing reset-frontier file tests also run.

The added source storage is O(16P+S), where P is the PE count and S the SPI storage
slot count. Reconciliation is O(16P+S); the existing O(P(32+S)) selection dominates.
The serialized source bank adds 16+3(16P+S) bytes: two u64 vector lengths and three
one-byte booleans per input. At S=256 this is 832, 880 or 976 bytes for P=1, 2 or 4.
No performance benchmark was performed.

## Scope

The full A32-FP, C-STATE, C-SMP and C-HVF findings remain incomplete. Extended GIC,
LPI/security profiles, complete backend/private/in-flight/startup/IRQ/clock/replay
coverage and physical Intel validation remain separate requirements. No new
physical hardware or QEMU oracle execution is claimed; evidence comprises retained
primary rules, LLVM-checked words, actual parent failures and final guest/file
execution. Exported C ABI identifiers/layout are unchanged; the owning C API suite
runs, without a separate C/C++ consumer rebuild.

Exact assumptions, commands, test counts, executable/source hashes, integration,
push and cleanup receipts are in [qualification.json](qualification.json).

## Git integration

At the user's request, the initial integration merge 179707fcc was removed from
master. The eight incoming commits were replayed after the original audit tip,
preserving all130 audit commit IDs and the incoming author/message/date metadata.
The resulting a41169a43 tree is byte-identical to the integration merge tree.
The replacement used an explicit lease for the old published tip; subsequent
semantic commits use normal pushes to origin/master.

The first broad root run exposed an existing missing-private-CPU assertion:
the new earlier rejection was correct but its diagnostic omitted "missing".
That failed run was interrupted and retained as discovery evidence. The final
complete run starts after the history rewrite and diagnostic correction; its
source/HEAD/executable guards must remain unchanged throughout.

Shared-GIC graphs require complete private CPU records even for callers primarily
comparing public CPU bytes. The represented-byte fixture now uses the full
producer capture and prepares peers through platform requests before public
register setters, so its private power state agrees with PSCI. The singleton
no-shared-graph legacy projection remains supported. A new1/2/4-CPU test removes
the entire private section and checks CPU/controller/coordinator/RAM preservation.

A separate pre-existing profile gap remains: distributor enables are coalesced
into one boolean and are not consulted by IRQ eligibility. IHI0069H4.7.2 requires
group forwarding controls. This group qualifies source conservation with forwarding
enabled; it does not establish disabled-distributor or independent-group conformance.
New host source fixtures explicitly enable distributor and CPU groups.


The historical untracked `ax.trace` preservation check failed: its previous
88,489,448 bytes were replaced by a 16-byte memory-trace header at 17:09:32 UTC.
The writer, cause and original-content recovery are unknown. The current file
remains untouched; `historical_trace_drift` records both states. Source/test
qualification does not imply that this historical user-file invariant passed.

## Final local validation

| Gate | Outcome |
| --- | --- |
| doctests-workspace-v12 | 0 passed / 0 failed / 5 ignored; 0 passed / 0 failed / 0 ignored |
| focused-gic-core-v12 | 171 passed / 0 failed / 0 ignored |
| focused-cpu-set-v12 | 4 passed / 0 failed / 0 ignored |
| owning-root-library-v12 | 12034 passed / 0 failed / 35 ignored |
| owning-arm-v10 | 46850 passed / 0 failed / 0 ignored |
| owning-arm_vfp_a32-v10 | 521 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_programs-v10 | 75 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_native-v10 | 0 passed / 0 failed / 0 ignored |
| owning-smir_jit_aarch32_aarch64-v10 | 26 passed / 0 failed / 0 ignored |
| owning-smir_jit_thumb_aarch64-v10 | 25 passed / 0 failed / 0 ignored |
| owning-checkpoint_cpus-v10 | 12 passed / 0 failed / 0 ignored |
| owning-checkpoint_resume-v10 | 10 passed / 0 failed / 0 ignored |
| owning-checkpoint_config-v10 | 1 passed / 0 failed / 0 ignored |
| owning-retired_clock-v10 | 13 passed / 0 failed / 0 ignored |
| owning-checkpoint_clock-v10 | 16 passed / 0 failed / 0 ignored |
| owning-retirement_clock-v10 | 10 passed / 0 failed / 0 ignored |
| owning-counter_ticks-v10 | 12 passed / 0 failed / 0 ignored |
| owning-retirement_budget-v10 | 14 passed / 0 failed / 2 ignored |
| owning-user_linux-v10 | 43 passed / 0 failed / 1 ignored |
| owning-capi-library-v10 | 241 passed / 0 failed / 0 ignored |

All-target build/check/Clippy, without-debug/without-JIT compilation, formatting and retained Windows corpus checks passed. Exact receipts are in qualification.json.

## Later group-forwarding framing

The [group-forwarding followup](../a64-gic-forwarding/README.md) replaces the
coalesced distributor enable with independent group controls. Current owned/shared
frames are RAXA6407/08 and RAXEXE07/08. The 05/06 frames qualified above retain
explicit source-bearing readers; their boolean control imports as its recorded
readback,0 or3. Historical qualification records continue to describe their
captured source revisions.
