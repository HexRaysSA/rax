# GIC group forwarding and restoration

GIC distributor enables are independent for Group 0 and Group 1. The distributor
and the target CPU interface must both enable an interrupt's group before it can
be selected, signalled or acknowledged. A disabled group cannot mask an eligible
lower-priority group. The selected implementation-defined policy excludes disabled
CPU groups for direct interrupts; exclusion is required for 1-of-N interrupts.

Disabling forwarding withdraws the published IRQ without clearing software,
physical-level or edge sources. Pending SGIs and edge requests received while
all distributor groups are disabled remain retained, an implementation-defined
choice. Active-state and running-priority checks remain separate; an IAR read
cannot activate a pending interrupt that cannot preempt the running priority.

The implemented single-Security-state GICv3/v4 profile reports DS and ARE as
read-as-one/write-ignored, matching SecurityExtn=0 and its affinity-only routing.
Reserved and unsupported control fields read zero. This does not add a legacy
GICC interface, extended interrupts or multiple Security states, or establish
complete GICv2/v4 conformance.

| Record | Current | Previous source-bearing | Older aggregate |
| --- | --- | --- | --- |
| Owned GIC, unbound counter | RAXA6407 | RAXA6405 | RAXA6401/02/03 |
| Owned GIC, VM counter | RAXA6408 | RAXA6406 | RAXA6404 |
| Shared GIC, no UART | RAXEXE07 | RAXEXE05 | RAXEXE02 |
| Shared GIC with UART | RAXEXE08 | RAXEXE06 | GIC-bearing RAXEXE03 |
| No owned/shared GIC | Existing frames | Unchanged | Unchanged |

Unframed derived `GicCheckpoint` serialization changes layout; the versioned
private/shared readers are the compatibility boundary. External consumers of
unframed controller bytes must version their transport alongside it.

Old coalesced distributor booleans migrate to their represented register readback:
false becomes 0, true becomes 3. This is a logical import of recorded behavior;
the original individual group-enable writes are unknown. Previously source-bearing
records retain their independently encoded input sources. The older aggregate
records retain the prior explicit rejection of ambiguous PPI/SPI pending and edge
histories. Newly captured records retain all four exact group-enable masks.

The parent producer's four actual GIC/codec records are retained in
[legacy-source-fixtures.json](legacy-source-fixtures.json), with its commit and
producer description. Its source files were copied byte-for-byte into the retained
component harness. The baseline is a component reproducer with a minimal Error
shell; it is not full-parent workspace execution. Five added regressions failed
there while nineteen existing tests passed. Initial harness build failures are
retained separately and are not behavioral red evidence.

The final tests cover distributor/CPU controls across 480 SGI/PPI/SPI, group,
mask and PE combinations; group-priority masking; Any routing; active priority;
IRQ withdrawal; invalid checkpoint masks; current roundtrips; and frozen-source
migration. Real VMM cases execute LLVM-verified MMIO/ICC words and continue from
12 files covering all four masks and 1/2/4 prepared PEs. Original kernel and
checkpoint files are removed before constructing each destination. Complete CPU,
coordinator, controller and Retired-clock states are compared through the guest
continuation. Prepared peers do not establish guest cold startup.

The direct `ArmCpu::step` API publishes current timer outputs with a zero-cycle
poll before consulting the controller. Its physical-timer fallback applies only
to a core without a controller. A bound GIC supplies the individually and group-gated
timer decision, matching the managed system path. The same public-API reproducer
is linked against the pre-correction and final root libraries. An additional
enabled-controller delivery probe exposed a missing publication step in the
intermediate correction; its observed failure and final positive control are
retained. No intermediate or interrupted file run is counted as a passing gate.

Source storage and selection complexity remain O(16P+S) and O(P(32+S)), where P
is the configured PE count and S the SPI storage count. Replacing the coalesced
boolean and three obsolete security/affinity booleans with a u8 mask reduces the
encoded controller payload by exactly three bytes. No throughput benchmark is
claimed. C ABI identifiers and layouts are unchanged.

[Arm IHI0069H, ID020922](../../specifications/arm/gic-ihi0069.pdf), sections 4.7.1-3
and 12.9.4, supplies the primary forwarding, disable and control-register rules.
Its retained PDF hash, commands, source/artifact hashes, assumptions and exact
validation counts are recorded in qualification.json.

The original A32-FP, C-STATE, C-SMP and C-HVF findings remain incomplete. High
remaining gaps include the shared IAR0/IAR1 and HPPIR/SGI group paths, Group 0
FIQ delivery, sleeping-PE 1-of-N selection, direct-API masked WFI wakeup,
complete startup/IRQ/clock/replay coverage, native streaming FPSR reentry, and
physical Intel validation. Six independently executed root-linked cases reproduce
wrong-bank IAR acknowledgement and EOIR deactivation in both groups, Group 0
IRQ-mask use and sleeping-PE 1-of-N selection. These failures remain open.
This group does not qualify those paths or imply full audit completion. No
hardware/QEMU oracle or physical Intel execution is claimed for this change.

Historical ax.trace preservation failed before this group: its writer, cause and
original-content recovery remain unknown. This group snapshots and guards the
current user-file bytes, primary executable and protected guest processes; it
does not recast the earlier failure as a successful preservation check.

A later test review made PE wakeup explicit in the new host, timer and guest
fixtures before forwarding assertions. The parent component still fails the same
five regressions with awake inputs. The final unfiltered root binary includes
these corrected fixtures; the sixteen owning executables remain byte-identical
to their successful v4 runs. That earlier interrupted root run is not a passing
gate. Source-free guest cases now begin with an explicit GICR_WAKER write.

## Final local validation

| Gate | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| focused-controller-and-codecs-v5 | 192 | 0 | 0 |
| direct-timer-bypass-green-v5 | 1 | 0 | 0 |
| direct-timer-publication-green-v5 | 1 | 0 | 0 |
| owning-root-library-v5 | 12052 | 0 | 35 |
| doctests-workspace-v5 | 0 | 0 | 5 |
| doctests-workspace-v5 | 0 | 0 | 0 |
| owning-arm-v4 | 46850 | 0 | 0 |
| owning-arm_vfp_a32-v4 | 521 | 0 | 0 |
| owning-aarch64_smir_programs-v4 | 75 | 0 | 0 |
| owning-aarch64_smir_native-v4 | 0 | 0 | 0 |
| owning-smir_jit_aarch32_aarch64-v4 | 26 | 0 | 0 |
| owning-smir_jit_thumb_aarch64-v4 | 25 | 0 | 0 |
| owning-checkpoint_cpus-v4 | 12 | 0 | 0 |
| owning-checkpoint_resume-v4 | 10 | 0 | 0 |
| owning-checkpoint_config-v4 | 1 | 0 | 0 |
| owning-retired_clock-v4 | 13 | 0 | 0 |
| owning-checkpoint_clock-v4 | 16 | 0 | 0 |
| owning-retirement_clock-v4 | 10 | 0 | 0 |
| owning-counter_ticks-v4 | 12 | 0 | 0 |
| owning-retirement_budget-v4 | 14 | 0 | 2 |
| owning-user_linux-v4 | 43 | 0 | 1 |
| owning-capi-library-v4 | 241 | 0 | 0 |

All-target build/check/Clippy, formatting and compilation without debug or JIT
passed. `aarch64_smir_native` is empty on macOS and supplies compilation evidence
only. Workspace doctests executed zero cases and ignored five. The v4 owning
results are reused after verifying all sixteen executables are byte-identical;
the final v5 root run covers the revised fixtures. Exact commands and limits are
in qualification.json.

## Later CPU-interface qualification

The [CPU-interface group](../a64-gic-interface/README.md) addresses the classic
IAR/HPPIR/EOIR banks, SGI forwarding, IRQ/FIQ masks, wait wakeup, Any participation
and active-state programming listed as open above. Its qualification retains the
remaining scope, discovered SPI capability-reporting defect and all original
finding boundaries; this historical group does not imply full audit closure.
