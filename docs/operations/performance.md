[← Documentation home](../../README.md)

# Performance and benchmarking

Performance claims in an emulator are highly path-dependent. `rax` can execute through an interpreter, native SMIR region, KVM, or HVF; each path measures a different thing. A useful benchmark record identifies the path, host, build, guest workload, promoted/fallback fraction, and correctness checks.

## Included benchmark entrypoints

The repository includes examples such as:

```sh
RUSTFLAGS='-C target-cpu=native' \
    cargo run --release --example bench_loop

RUSTFLAGS='-C target-cpu=native' \
    cargo run --release --example bench_mem
```

The Makefile’s `bench` target runs the project-selected benchmark set. Read the current Makefile for the exact examples and feature flags.

`bench_loop` is a tight register-oriented guest workload and is useful for interpreter dispatch and native-region overhead. It is not representative of a kernel, MMU-heavy program, device workload, or mixed unsupported JIT region.

## The old 145 MIPS / 80× figures

The former root README reported approximately 145 MIPS for one interpreter run and roughly 80× speedup for the JIT on that loop. Those values should be retained only as a historical observation with the original:

- host CPU and frequency policy;
- operating system/kernel;
- Rust and LLVM versions;
- `rax` commit;
- build flags/features;
- benchmark parameters;
- elapsed-time distribution;
- JIT warm-up and compilation policy.

Without those conditions, the figures are anecdotes—not stable project properties. The rewritten root README therefore points to the benchmark command instead of advertising the numbers.

## Build configurations

### Portable baseline

```sh
cargo build --release --no-default-features
```

### Native-host interpreter/JIT build

```sh
RUSTFLAGS='-C target-cpu=native' \
    cargo build --release --no-default-features --features smir-jit
```

### Repository x86 baseline

The checked-in Cargo configuration uses `target-cpu=x86-64-v3`, enabling a reasonably modern x86-64 baseline rather than the oldest architecture. Record whether the local environment overrides it.

### Release profile

The release profile uses aggressive whole-program optimization settings including fat LTO and one codegen unit, while retaining panic unwinding for the C ABI containment contract. Changing panic mode, LTO, codegen units, debug information, or stripping can affect both performance and binary behavior.

## Interpreter benchmarks

Report:

- guest instructions retired;
- wall-clock elapsed time;
- MIPS = retired instructions / elapsed seconds / 1,000,000;
- whether JIT was disabled with `RAX_NO_JIT=1`;
- trace/debug/profile/logging state;
- guest memory behavior;
- decode-cache warm/cold state;
- host affinity and frequency policy;
- number of repetitions and dispersion.

Do not infer cycles per guest instruction from wall time without controlling host frequency and measuring host cycles.

## JIT benchmarks

A JIT benchmark needs more than total time:

- hot threshold;
- compilation time;
- number of candidate regions;
- number admitted/rejected;
- native entries;
- fallback exits and reasons;
- native guest-instruction coverage;
- cache hits;
- SMC invalidations;
- host feature set;
- guest/host pair;
- live verification enabled/disabled.

Measure both cold and warm runs. A tiny loop can amortize compilation almost perfectly; a large branchy workload may not.

Suggested matrix:

```text
interpreter only
JIT enabled, cold cache
JIT enabled, warm cache
JIT enabled + live verification
JIT enabled with memory disabled
JIT enabled with calls ending regions
```

## Hardware backend benchmarks

KVM/HVF measurements include hardware guest execution plus VM exits and device emulation. They are not directly comparable to interpreter MIPS because the project may not observe an exact guest instruction count.

For hardware paths, report:

- guest workload wall time;
- VM exit counts if available;
- I/O/device configuration;
- configured vCPU count and the number that executed the workload;
- host virtualization version/settings;
- guest kernel/configuration;
- whether the workload is CPU-bound or exit-heavy.

## Memory benchmarks

Memory performance depends on:

- guest virtual-to-physical translation;
- TLB hit rate and page size;
- MMIO aperture checks;
- direct host-pointer eligibility;
- alignment and page crossing;
- code-page write detection;
- device attachment;
- JIT helper calls;
- faults and replay.

Use separate workloads for sequential RAM, random RAM, translation stress, MMIO, string operations, and self-modifying code.

## PGO

The Makefile/scripts include PGO support and corresponding safety/build tests. A trustworthy PGO workflow has three stages:

1. instrumented build;
2. representative training workload;
3. profile-use build and independent measurement.

Record `PGO_TARGET_CPU`, `RUSTFLAGS`, training images, and profile merge tools. Never benchmark on the same data used to choose among variants without a holdout run.

## Correctness while benchmarking

Fast wrong execution is not useful. Pair performance runs with:

- expected final registers/checksum;
- interpreter comparison;
- `RAX_JIT_VERIFY=1` where supported;
- deterministic guest output;
- no unexpected fallback/exception;
- a named test target for any newly admitted operation.

Live verification changes performance and should be reported as a separate mode.

## Reproducible benchmark template

```text
rax commit:
date:
host CPU / microcode:
host OS / kernel:
power governor / affinity:
Rust / LLVM:
Cargo profile / features:
RUSTFLAGS:
guest architecture and image hash:
backend:
JIT controls:
optional devices:
benchmark command:
warm-up:
repetitions:
raw timings:
retired guest instruction count:
compile/promote/fallback counters:
correctness check:
```

Publish raw observations and summary statistics. Avoid one-decimal precision when run-to-run variance is larger.

## Performance non-claims

- A register loop does not predict Linux boot speed.
- Interpreter MIPS cannot be compared directly with hardware backend wall time without a common workload and accounting model.
- “One native instruction per guest instruction” is path- and operation-specific.
- `target-cpu=native` results may not run on another host.
- A feature-rich build and an instrumented/debug build are not neutral baselines.
- JIT speedup without native coverage/fallback data can conceal that only the easiest portion executed natively.
