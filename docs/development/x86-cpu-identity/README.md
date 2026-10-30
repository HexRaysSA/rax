# Per-CPU x86 identity and bootstrap state

The configured vCPU ID supplies the initial APIC ID in software CPUID, the
public CPUID query, the native x86 JIT helper and Intel HVF's supported topology
leaf. Fresh standalone CPUs also seed their inline LAPIC ID from the configured ID.
Initial identity remains distinct from the modeled current LAPIC ID; context
restoration preserves the recorded current ID, including legacy records.
Existing feature bits and topology geometry are preserved by the projection;
this change does not implement complete topology enumeration.

Previously all software CPUs reported initial APIC ID zero and BSP=1. Intel
HVF also reported ID zero and returned BSP=0 for every CPU. Software rejected
BSP-flag changes, while native APIC-base writes succeeded without state changes.
The retained baseline reproduced the three software defects through real CPU
instructions and the public query. A separate pre-fix guest MMIO probe also
reproduced standalone CPU 3 reporting current LAPIC ID zero. Constructor seeding
fixes that path without rewriting guest-modified or restored current IDs.

C/C++ consumer qualification exposed an unconditional JIT-runtime type reference
in a lowerer layout constant when building without JIT. The constant now follows
the established append-only field offsets; the existing real-frame layout check
and both feature configurations validate the same offset.

## Current state and INIT

The software x86 and Intel HVF CPU models initialize APIC base `0xfee00000`, global enable set,
and BSP set only on configured CPU zero. The BSP flag is writable. Its value
survives unrelated public register imports and software INIT; reset selects the
configured boot identity again. The software VMM queries the current flag for
INIT, selecting boot execution or wait-for-SIPI accordingly. A running bootstrap
CPU ignores SIPI; CPU zero can wait for and accept SIPI after its BSP flag is
cleared. Tests use the modeled ICR queue and actual VMM dispatch.

Direct execution, optimized standalone SMIR and native x86 JIT MSR helpers retain
the represented APIC-base value. Standalone SMIR's APIC state has a valid CPU-zero
default and an explicit initial-ID constructor. The JIT verifier snapshots,
compares, restores and adopts the live value during replay. Native helper frames
retain their existing layout; identity and APIC-base state come from the owner.

Intel HVF's APIC-base handler uses the production portable publication policy.
Reads zero-extend EAX/EDX and complete the exact instruction. A successful write
publishes the model after SDK RIP completion. Any failed SDK register completion
or fault injection fences further entry, including partial SDK failures; no SDK
rollback is claimed. The previous model value survives a failed write. These
failure paths are tested with SDK substitution and compiled for the Intel target.

Global enable/disable, relocation and x2APIC mode/banks remain unimplemented
profiles here. Such writes fault before retirement instead of reporting an inert
success. Completing their actual architectural semantics remains part of the
original goal. Existing native feature/topology dimensions, advertised x2APIC,
full IRQ routing, native startup/thread ownership and complete Intel private
checkpoint state also remain required work.

## Private-context version boundary

`RAXX8603` wraps the unchanged version-2 base representation with the represented
APIC-base value. Full software VM bundles therefore preserve guest-written BSP
flags through prepared CPU replacement and coordinated restoration. The legacy
base-only checkpoint view remains a projection; this field requires the private
context. CPU zero remains the legacy base-record anchor even if its BSP flag is
changed by the guest.

Versions 1 and 2 remain readable with their original positional base layout.
They could not encode mutable BSP state; their missing field starts from the
corrected configured boot identity. In particular, an old AP record no longer
reconstructs the inherited erroneous BSP=1 report. The two 3250-byte version-2
fixtures were produced by the preceding engine commit, not by the new reader.
Their hashes and producer details are in
[legacy-v2.provenance.json](legacy-v2.provenance.json). The existing frozen
version-1 user fixture remains a separate compatibility control.

New contexts reject unsupported APIC-base state, wrong version payloads,
truncation and identity/binding disagreements before publication. The versioned
user-debug binding and outer C API/VM producer formats remain intact.

## Independent observations

```sh
python3 -B tools/execution/x86_identity_oracle.py \
  --llvm-bin /path/to/llvm/bin --scratch-dir /path/to/scratch \
  --work-dir /path/to/empty/evidence
```

The QEMU TCG guest starts 1, 2 and 4 CPUs and records seven observations of
initial CPUID/topology/LAPIC IDs, initial APIC base, attempted BSP changes and
restored state. ELF/object files are confined to a temporary directory and
removed; source, raw records, commands and hashes remain in the evidence output.
Initial identities and restored values match. QEMU ignores all seven BSP writes;
current upstream `apic_set_base` retains the old BSP bit. These disagreements
remain visible and do not redefine Intel's R/W rule. The driver rejects unknown
reference results. Its observed binary is not claimed to be built from the
currently inspected upstream source.

`tools/execution/x86_identity_compare.rs` executes actual software guest
instructions against these records. Its identity/default/restore comparison is
independent; BSP-write checks use the primary specification and report the raw
QEMU differences separately. The qualification records the exact linked engine
artifact and command. Generated x86 execution under Rosetta, SDK substitution and
physical Intel VMX remain distinct evidence classes. Physical Intel execution
has not been established.

Primary source: retained Intel SDM086, December 2024,
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`:
Volume 2A CPUID initial APIC ID (page 3-223), Volume 3A section 12.4.4
(page 12-8), Volume 4 Table 2-2 BSP Flag (R/W), and Volume 3A MP initialization
discussion of subsequent INIT using each processor's current BSP flag.
QEMU implementation cross-check:
[`apic_set_base`](https://github.com/qemu/qemu/blob/master/hw/intc/apic.c).

## Assumptions and completion limits

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| I1 | Configured CPU IDs provide initial identity; CPU zero starts as BSP | Public/guest/JIT/SMIR/HVF identity at multiple IDs, changed current LAPIC ID, reset and context continuation | Locally qualified; physical Intel unverified |
| I2 | Current BSP flag determines software INIT startup role | Change both CPUs' flags, route INIT/SIPI through ICR and check execution/wait selection | Locally qualified |
| I3 | Old contexts contain no mutable APIC-base state | Decode actual preceding-writer fixtures; compare exact old base bytes; verify explicit version-3 restoration | Locally qualified |
| I4 | SDK publication failures may have partial effects | Mutate then fail each SDK completion; require permanent entry exclusion and unchanged model publication | Substituted SDK qualified; physical failure behavior unverified |
| I5 | Capture occurs at the existing stopped publication boundary | Full bundle round-trip, malformed context rejection and preserved live controller bindings | Selected stopped software paths qualified; complete native/in-flight coverage remains open |

Identity projection and BSP admission take O(1) time and storage. Per-CPU state
storage is O(n) for n configured CPUs. High-impact remaining work comprises the
full APIC modes/topology/IRQ/native-state requirements above and all unfinished
A32-FP, C-STATE, C-SMP and C-HVF requirements. The original four-finding goal
remains active. Exact current counts, source hashes and retained failures are in
[qualification.json](qualification.json).
