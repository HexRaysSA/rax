# Original version-8 checkpoint fixture

`original-v8.rxc` was produced by the original untagged version-8 implementation,
including its mandatory AArch64 keyed-state layout, before PCI configuration
persistence and tagged sections were introduced.

- Source baseline: `eec3e1ccd2671d3dfd9f38f570403bd110f99a6a`, with later device-only audit overlays; config and snapshot sources were unchanged.
- `src/config/runtime.rs` SHA-256: `f543da63dc8d425d780cd3e29d358a38e2686fb9e8691b6945b5000efe8ab83c`.
- `src/vm/snapshot.rs` SHA-256: `f504c90e7647ae0e2a28c79d7f483652bdbacfea0706d51d65bb7ac0751bda86`.
- Actual original-library SHA-256: `3ebb38a1c1502d4ef18b4dbe6cffbd69431af48304385f0cd0830ef8180ade05`.
- Capture date: 2026-10-25.
- Fixture SHA-256: `985523c20acae5bd3438df306ff974dbe13ec720913492efce518efc30890cf5`.
- Magic/version: `RAXCKPT\0`, little-endian `u32` value 8.
- CPU: x86-64 default serialized registers; 4,096 RAM bytes containing `0xa5`.
- Instruction count: 123,456,789; recorded elapsed time: 987,654,321 ns.
- Kernel path: informational capture metadata; the loader does not need that file.

The retained generator is `tools/checkpoint/generate_original_v8.rs`. Compile it
against the original baseline library, its matching dependency directory,
`bincode` and `zstd`; pass a capture directory as its argument. It deliberately
uses the original public types rather than recreating missing production code.
It retains one device-state object while varying the source PCI flag. Both
configurations produce exactly the same file bytes because the old config did
not serialize that flag. A decoder cannot reconstruct the missing information;
legacy loading retains the original false default, with explicit CLI enablement
available when resuming.

The initial PIT timestamps come from the original timing implementation, so a
fresh capture can differ in those values. Validation is reproducible against the
retained fixture. It checks the exact observed binary, config/CPU/media fields
and successful decoding without access to the original kernel file. This is
serialization compatibility evidence, not complete machine-state or boot proof.


## Tagged version-8 configuration schema 1

`tagged-v8-schema1.rxc` was emitted by the actual tagged writer before image
fields were added. File SHA-256:
`3439598f08cd8a97277c8c80e8ad40699bf8e8b27a5880d6936c43782eda138b`.
It contains x86-64 default CPU state, PCI=true, 4,096 RAM bytes of value 31h,
instruction count 123456789 and elapsed count 987654321 ns. Config and all other
sections use schema 1. Its original kernel file was removed before compatibility
validation; the path remains informational metadata.

The retained public-API producer is
`tools/checkpoint/generate_tagged_v8_v1.rs`. Compile it against the predecessor
library that still writes configuration schema 1 and its matching dependency
directory. Linking it to the current library emits the current schema instead.
The actual captured producer library SHA-256, source hashes, command and outputs
are recorded in the configuration remediation ledger and retained evidence.
The fixture bytes are immutable. Fresh captures can have different PIT timing
values. They do not replace validation against the retained original file.
