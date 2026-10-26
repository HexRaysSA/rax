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
