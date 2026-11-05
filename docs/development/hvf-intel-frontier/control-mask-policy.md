# Finalize native Intel control-register masks before profile capture

[Run 41992554080](https://github.com/HexRaysSA/rax/actions/runs/41992554080)
passed 118 ordered native RAX guest cases: all 114 RAM/MMIO controls and four
PAT write/read controls. It then rejected the first private PAT checkpoint with
`native Intel context: saved control-register masks differ from policy`.
The retained [result](native-partial-41992554080.json),
[observations](native-partial-41992554080.jsonl), and
[stderr](native-partial-41992554080.stderr) preserve this partial result. It is
not a successful 130-case run.

The [SDK constructor matrix](ram-entry-controls.md) independently observes
CR0_MASK changing from `0x20` to `0x60000020`, and CR4_MASK from zero to `0x40`,
at guest entry. Explicitly initializing the SDK-required mask bits preserves
both masks across entry. The private producer previously froze the constructor
values before that SDK change and subsequently rejected its own captured bank.

The [mask initializer](../../../src/backend/hvf/intel_mask_policy.rs) queries
both SDK constraints before writing either mask, rejects contradictory or
incompatible constraints, retains the requested mask bits, adds mandatory bits,
and verifies exact readback. Profile construction calls it before freezing
producer controls. Capture and restore still require exact policy equality.
CPU construction failure destroys the unpublished SDK CPU.

The primary [SDK header](../../specifications/apple/hypervisor-sdk-27.2/hv_vmx.h)
defines `hv_vmx_vcpu_get_cap_write_vmcs`: its `allowed_0` word contains the bits
that must be set, while `allowed_1` contains the bits allowed to be set. The
implementation resolves that SDK 11.0 symbol at runtime. An unavailable API
rejects construction explicitly rather than adding a newer strong import.
Initialization performs a fixed two-field query/write/readback sequence, with
constant time and storage.

The SDK-owner regression reproduces the native mask change and failed capture
before the correction. Its baseline has zero passes and one failure. The
corrected complete `hvf_intel_owner` binary passes 62 tests, with zero failures,
ignored or filtered tests; this includes both constraint-query failures,
private capture/restore, rollback and 1/2/4-CPU checkpoint-file transactions.
The focused module passes 15 tests. Clippy also succeeds. The 130-case consumer
compiles, links, signs and passes strict signature verification against the
same corrected library. That local Apple Silicon check executes zero native
Intel cases. Both owned compiler directories were removed.

The first corrected test attempt crashed because its late-bound mock symbol
was removed by the linker and lookup reached the real SDK with a synthetic
handle. Explicitly retaining the mock fixed that harness defect; the crash is
recorded in [qualification](control-mask-qualification.json), not counted as a
successful test. The native mask correction still requires a new hosted run.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | SDK mask constraints explain the stale private producer policy | Constructor correction | Compare pre/post-entry masks in the independent matrix; reproduce native capture failure in the owner model; rerun native RAX | Matrix and model confirmed; corrected native continuation unqualified |
| A2 | Finalization preserves existing owner and checkpoint behavior | State-transfer compatibility | Complete owner target, including rollback and checkpoint-file transactions; inject either query failure | Confirmed in 62 SDK-model tests |

High-impact unresolved scope: physical CR4/EFER normalization, native private
continuation, timer ownership and interrupt delivery remain separate gates.
Medium impact: the hosted Intel process runs inside a hypervisor guest;
bare-metal Intel behavior is unqualified. The full A32-FP, C-STATE, C-SMP and
C-HVF findings remain open.
