# Native unscaled TSC and VM-clock record prototype

This component retains a VM clock sample, its host-TSC capture interval and
bounded CPU identity/rate/offset records. It admits the original unscaled native
TSC profile and matching destination rates. It is not integrated into the VMM.

For each CPU, restoration applies the same unsigned 64-bit delta:

```text
delta       = source_anchor - resume_anchor             (modulo 2^64)
offset_i'   = source_offset_i + delta                    (modulo 2^64)
offset_i' - offset_0' = source_offset_i - source_offset_0 (modulo 2^64)
```

The direct offset attribute preserves these relative phases without relying on
the kernel's `SET_TSC` synchronization heuristics. The VM clock excludes offline
wall time and includes elapsed work spent installing the CPU offsets. Capture
and publication intervals remain explicit: this is not an atomic, zero-error
cross-domain clock sample. All TSC intervals are recorded in cycles; VM time and
elapsed publication work use nanoseconds.

| Observation | Native scope and result |
|---|---|
| Independent direct UAPI | Six source-free one/two/four-CPU graphs, with and without an IRQchip; all 14 relative phases and bracketed TSC reads pass |
| Independent negative controls | Eight multi-CPU phase losses when saved TSC values are written independently with a deliberate 1 ms inter-CPU delay |
| Serialized Rust component | JSON and the unchanged production codec; 28 exact CPU phase restores across 12 fresh destinations |
| Invalid records and targets | 228 rejections; every destination's native offsets remain unchanged |
| Offline time control | 20 ms delay per destination; restored VM time is bounded by publication duration plus the declared 1 ms test tolerance |

The tolerance is a test bound, not a clock calibration or an architectural error
guarantee. The independent observations show that divergent two/four-CPU clocks
can have zero kernel clock flags and no returned host-TSC anchor. The record
therefore does not require those optional flags to be set.

[native.json](native.json) retains the four Rust commands, all source identities,
dependency-lock identity and executable cleanup. The earlier 168-control run is
retained in [pre-binary-controls-native.json](pre-binary-controls-native.json).
The exact clock helper is unchanged between these two runs. Only the copied
production codec's unused functions produce compiler/Clippy warnings.

[independent.c](independent.c) and
[independent-native.json](independent-native.json) retain the direct-UAPI
experiment. The first observer did not compile because Linux `__u64` and
`uint64_t` differ in their C format types. Its source and compile-only failure
are retained as [observer-format-error.c](observer-format-error.c) and
[observer-format-error.json](observer-format-error.json). Explicit casts corrected
the observer; no kernel assertion was weakened. Both terminal executables were
removed, and only the existing shared native Cargo cache was used.

Primary behavior is defined by the archived
[x86.c](../../kvm-public-state/references/kernel-x86-v6.8.c) functions
`kvm_arch_tsc_set_attr`, `__kvm_synchronize_tsc`, `get_kvmclock_base_ns` and
`kvm_vm_ioctl_set_clock`, together with the archived
[UAPI bindings](../references/sdk-serde-v0.14.2/src/x86_64/bindings.rs).

From the repository root, on Linux x86-64 with `/dev/kvm` and Rust 1.98 or later:

```sh
clock_work=$(mktemp -d /tmp/rax-clock-record.XXXXXX)
mkdir "$clock_work/src"
clock_docs=docs/development/kvm-native-private-state
cp "$clock_docs/clock-rebase/companion-Cargo.toml" "$clock_work/Cargo.toml"
cp "$clock_docs/clock-rebase/companion-Cargo.lock" "$clock_work/Cargo.lock"
cp "$clock_docs/clock-rebase/probe.rs" "$clock_work/src/main.rs"
cp "$clock_docs/clock-rebase/clock.rs" "$clock_work/src/clock.rs"
cp "$clock_docs/fixed-bank-wire/bank.rs" "$clock_work/src/bank.rs"
cp "$clock_docs/references/rax-codec.rs" "$clock_work/src/codec.rs"
CARGO_TARGET_DIR="$clock_work/target" cargo run --locked \
  --manifest-path "$clock_work/Cargo.toml"
# After the foreground command finishes, remove its completed build cache.
rm -rf "$clock_work/target"
```

Expected output has six JSON records, totaling 28 exact phases and 228 rejected
controls. Sources remain in the new scratch directory for inspection.

The complete [assumption register](qualification.json) records each dependency,
stress test, falsification probe and status. High-impact remaining work includes
the real common first-entry gate, scaled/unstable profiles, advancing MSR-counter
composition, full CPU/controller/in-flight records, and coordinated rollback
with VM-wide entry poisoning. No guest enters in these probes. No complete VM
file continuation or full C-STATE/C-SMP closure is established.

Capture, validation and publication take O(N) time and O(N) storage for N CPUs,
bounded by the managed profile's 255-CPU limit.
