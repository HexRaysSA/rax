# Intel HVF MMIO translation coherence

The native diagnostic tests whether an admitted guest page-table change can
make the MMIO exit's physical address disagree with RAX's later software walk.
The production engine is unchanged. `validate_memory` in
`src/backend/hvf/mmio.rs` compares every operand byte against a fresh walk;
`entry_result` in `src/backend/hvf/intel_run.rs` retains execution errors.
A substituted-SDK characterization already
shows that a supplied mismatch latches a permanent execution failure, but it
does not prove that native guest execution can reach that state. This group's
native result is pending.

Run the existing native workflow with `candidate=false` and `profile=coherence`,
or invoke the driver on Intel macOS:

```sh
python3 tools/hvf/intel_mmio_native_probe.py --profile coherence --output <new-directory>
```

`--compile-only --export-guest` builds and signs without guest entry. Execute the
same source-bound artifact with `--execute-prepared <build-directory>` and the
same profile. The default `mmio` profile retains its 952 cases. The distinct
expected counts bind profile admission; every build also hashes all four Rust
consumer inputs, engine inputs and driver/support code.

The coherence profile runs four repetitions of each control:

| Mode | Guest action | Allowed second MMIO address |
|---|---|---|
| 0 | Store the unchanged PDE | 0x40000080 |
| 1 | Replace the PDE without invalidation | 0x40000080 or 0x40200080 |
| 2 | Replace the PDE and execute `INVLPG` | 0x40200080 |
| 3 | Replace the PDE while a second native guest CPU alternates it | Either address |

Every trial first completes an eight-byte read through the original mapping.
The guest then writes an aligned 64-bit PDE selecting one of two 2 MiB pages;
both target addresses are outside the fixture's 2,097,152 bytes of RAM. Code,
stack, page tables and observation words remain mapped through an unchanged
RAM translation. The second read must complete, store its reply and reach the
post-instruction marker and `HLT`.

Mode 3 uses two public CPU owners in the same configured VM. The observer waits
inside the guest until the peer has incremented a guest counter. Only native
guest instructions write the shared PDE while either CPU is entered. The host
stops and joins the peer before inspecting RAM. This is a direct SDK-client
concurrency control, not proof of VMM startup, scheduling or complete SMP.

All sixteen observations are retained even when an observer is fenced. The row
records the current PC, second instruction PC, exposed MMIO address, last PDE,
peer iteration count, reply/marker words and errors. `second_gpa=0` means the
CPU API never exposed the second MMIO request; its exact hardware exit GPA is
unknown in that row. The stopped checkpoint API additionally captures each
trial's complete CPU tuple in `coherence-case-<case>.cpu`; its represented PC
remains readable even when ordinary public register reads are prohibited.
The sixteen fixture records use the existing bounded native record format.
A permanently fenced owner is retried after both guest
CPUs stop and the host repairs the PDE, to distinguish a retained failure from
a transient mismatch. No device callback is dispatched by this diagnostic.

Each owner entry has a 100 ms host deadline; each observer stage admits at most
100 turns. The process has the driver's existing 900 s deadline. For k trials
and n admitted host turns per observer stage, host work is O(k n). Resident
guest RAM is one fixture at a time; retained diagnostic output grows as O(k).
A failing process,
missing row, false pass field or wrong order cannot qualify as a native pass.

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| T1 | A changed PDE may retain an old cached translation until invalidation | Intel SDM086 5.10.4.4; permit either GPA in modes 1/3 | Unchanged mapping and explicit `INVLPG` controls | A primary rule that disallows either represented outcome | Confirmed from the retained primary source |
| T2 | The peer performs guest page-table writes before the observer's second access | Guest counter and two public CPU owners; interpret mode 3 | Observer guest waits for peer progress; host reads only after join | Zero peer iterations, peer error or incomplete observer stage | Native evidence pending |
| T3 | An observed mismatch can be attributed to represented native instruction execution | Current production planner and exact source-bound executable | Stable/invalidation controls, PC and error retention | Control setup fails or the error arises outside MMIO inspection | Native evidence pending |
| T4 | The read-only record tool's dead-strip link flag removes Hypervisor.framework | Initial local portability assumption; no guest result depends on it | Inspect linked libraries, then read a known CPU tuple | Framework remains linked or the read-only program cannot run | Link assumption falsified; read-only loading and the codec control pass with the dependency retained |

High-impact open scope: translation/code coherence, other MMIO/control/IRQ
profiles, full native/private/in-flight checkpoints and VMM startup/clocks/replay.
A bounded run without a mismatch does not close those requirements. Medium
limit: the API does not expose the raw exit GPA after planner failure. Low-impact
adjacent changes: none required. A32-FP, C-STATE, C-SMP and C-HVF remain partial.

Primary source: retained Intel SDM086, December 2024,
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`;
Vol.3A 5.10.2.3, 5.10.4.4 and 5.10.5, PDF pages 3233 and 3242.

Local qualification: all 49 Python and 16 unfiltered CI-policy tests pass. The
Intel consumer and record reader compile with warnings denied; consumer signing
and verification pass. All 190 generated observer/writer bytes match independent
Clang assembly. Format checks pass. The read-only reader loads on this host and
reads the retained legacy collision tuple at RIP 0x100; no VM or guest is entered.
`qualification.json` retains commands, hashes and unrun-gate scope. Native
execution remains pending.

`cleanup.json` records removal of the idle 1,232,207,668-byte owned build cache.
The protected process identities, trace and original repository target remain
preserved. The small read-only decoder is retained outside the repository until
the pending native artifacts have been interpreted.
