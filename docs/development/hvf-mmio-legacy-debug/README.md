# Intel HVF pending-MMIO debug provenance

Older native CPU producers do not identify whether deferred MMIO data-breakpoint
causes were synthesized. The physical MMIO request is insufficient to recover
an omitted cause. The SDK-owner regression executes the production planner for
two linear aliases, 0x3ee00000 and 0xfee00000, mapped to GPA 0xfee00000. DR0
watches only the first linear address. The original pending causes differ:
0x1001 versus zero. After simulating the old omitted field and replacing the
already-fetched instruction bytes before capture, the entire saved CPU record
and all 16 KiB of fixture RAM are identical. The current RIP cannot recover
the executed address from the replaced code.

The pre-fix reader admits this ambiguous record. The regression fails at that
admission assertion, after both record/RAM equality checks pass. This is a
substituted-SDK control with no native guest instruction execution and no
historical RAX executable. The production baseline is commit
`7945d9e21cd5bf04324ddd1c6d87570f1d17ad59`.

The retained `baseline.stdout` records that admission failure. The separate
fixed `collision-proof.json` identifies the exported witness: 8,894 bytes for
each complete CPU tuple and 16,384 bytes for each RAM image. Both pairs and
their hashes are retained beside this document; `evidence-manifest.json`
identifies the exact files. The witness export compiles a copy of the current
owner test solely to save those bytes; it reports one inherited warning for an
unnecessary `unsafe` block and executes only the collision test. The complete
owner suites use the ordinary checked-in runner.

The corrected producer uses distinct tags while preserving the serialized body
and optional deadline trailer byte-for-byte. The reader retains old unambiguous
records and rejects ambiguous pending MMIO before destination register, FP,
VMCS or MSR publication. A nonzero old pending-debug field cannot identify a
corrected producer or prove that every new access cause was retained.

| CPU producer | Deadline trailer | Pending-MMIO data-debug guarantee |
|---|---|---|
| RAXHVI01 | Absent | Unknown; existing fixed-PAT migration retained |
| RAXHVI02 | Absent | Unknown |
| RAXHVI03 | Present | Unknown |
| RAXHVI04 | Absent | Corrected producer |
| RAXHVI05 | Present | Corrected producer |

Legacy rejection requires both a pending MMIO operation and a relevant enabled
memory watch. Reads match R/W=11; stores and modifying accesses also match
R/W=01. All four slots and local/global enable combinations participate.
Instruction and port-I/O watch conditions do not make a memory record ambiguous.
Disabled and irrelevant memory watches remain admissible. No historical trap
is invented for an access that had already retired before capture.

Old ambiguous terminal records are rejected too. Otherwise re-export or a later
replacement of captured debugger controls could incorrectly turn incomplete
provenance into a resumable record. Current terminal records retain their
readable failure latches and remain fenced. Raw rollback of current records
preserves its exact saved field. Saved port, width and debug registers still
permit deterministic reconstruction for old IN/OUT records.

The VMM validates every CPU through `validate_checkpoint_for_machine` before
resource preparation and publication. The native owner's validator and raw,
forward and rollback import paths use the same complete-record admission.
The SDK model additionally checks that rejection issues no destination write,
setter or guest-entry call and leaves the destination readable.

```text
pending MMIO + relevant enabled memory watch
                    |
          producer guarantee available?
             /                  \
           yes                   no
            |                     |
      retain saved causes    reject before publication
```

Local controls cover the byte-identical alias witness, 320 combinations of
access kind/slot/enable/condition, current success/failure carriers and old
port-I/O reconstruction. Portable codec controls verify old/new body identity,
legacy round trips, every truncation and trailing-data rejection. Complete
unfiltered owner suites pass 92 tests with debugging and 88 without;
the full root library passes 12,435 tests with 2 ignored. All 146 portable
cases across seven targets, 48 Python tests and 16 CI-policy tests pass. Format,
all-target build and Clippy pass with zero Clippy warning lines. Documentation
executes zero examples and ignores five. Exact commands and counts are retained
in `qualification.json`; C/C++ package/consumer gates were not rerun because no
public ABI or layout changed.

The native consumer preserves its 928-case prefix and adds 24 controls: sixteen
ambiguous old MMIO records (eight actions, cause present or cleared) must be
rejected without changing the destination's public state; eight old unwatched
records must resume and deliver the guest TF trap. The existing 96 old port
cases now explicitly use a legacy producer tag. The 952-case consumer compiles,
signs and verifies locally. Native run [42164048733](https://github.com/HexRaysSA/rax/actions/runs/42164048733)
passes all 952 ordered cases at commit `e3c73d70f26b0ee49a43b8b8f1caacea205b8afc`.
`native-pass-42164048733.json` binds the signed executable, 4,509 immutable
engine inputs, three consumer sources, tooling and both artifact ZIP hashes;
`native-observations-42164048733.jsonl` retains every observation. The host reports
GenuineIntel, no translation and a containing hypervisor; this is nested native
Intel execution, without a bare-host claim. Native owner replacement retains
RAM backing; the separate SDK-owner controls replace initialized RAM too.

The three independently committed Windows changes were preserved by rebasing
before publication. All 33 owned blobs are identical to the locally tested
commit. Full local gates precede those Windows changes; the native run builds
the combined source. `integration.json` records this validation boundary.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| L1 | Old request plus saved CPU/RAM cannot determine the original linear access | Two original aliases, different expected causes, replaced code and identical complete records/RAM | Confirmed by the pre-fix regression |
| L2 | Unknown producer provenance must not become a resumable pending memory record | All slots/enables/conditions, read/store/ALU/RMW, nonzero causes and terminal records | Confirmed by complete owner and portable gates |
| L3 | Corrected producers retain deferred causes under pending-I/O exclusion | New header/body identity, current carriers, restored native handlers | Complete owner controls and selected 952-case native gate pass |
| L4 | Legacy port requests remain recoverable independently of MMIO provenance | Explicit old tags, port/width/DR/DE reconstruction and current debugger controls | Complete local owner gates and 96 explicit legacy native port cases pass |

Admission checks four watch slots in O(1) time and auxiliary space. Record
encoding/decoding retains the existing bounded size and linear complexity.

High-impact remaining scope includes further MMIO/control/exception/reinjection
profiles, DEBUGCTL/BTF, streaming FPSR, complete backend/platform/writer state,
startup, clocks and replay. All four full findings remain partial. Medium-impact
compatibility limit: some correct pre-tag MMIO records are conservatively rejected
because they cannot identify their producer guarantee. Low-impact adjacent
changes: none required.

Primary architectural reference: retained Intel SDM086, December 2024,
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73;
Vol.3B 19.2.3-19.2.6/19.3.1.2, Vol.3C 28.7.3/29.3.4.

The single idle owned build directory was removed after all local gates.
`cleanup.json` records its empty open-file check and the preserved process,
trace and user-file state. The repository target directory was not touched.
