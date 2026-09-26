[← Documentation home](../../README.md)

# Cargo features and build profiles

This is the exact root-package feature reference. For procedural setup, prerequisites, Make targets, PGO, and common failures, see [Building](../getting-started/building.md).

Linux process emulation is a separate binary, `rax-user`, with no dedicated
Cargo feature. It requires a Linux or macOS host at runtime. A software-only
build uses `--no-default-features --bin rax-user`; adding `smir-jit` enables
eligible x86-64 native regions and the opt-in RV64 path (`--riscv-jit`).
ELF32 i386 compatibility stays interpreted. Enabling KVM or HVF does not
change the process application's CPU adapters. See
[Linux programs](../getting-started/linux-programs.md) for its ABI limits.

## Root package

The root manifest currently declares:

```toml
[package]
name = "rax"
version = "0.1.0"
edition = "2024"
autotests = false

[features]
default = ["kvm", "smir-jit"]
kvm = ["kvm-bindings", "kvm-ioctls"]
hvf = []
trace = []
debug = []
profiling = []
x86_64-suite = []
x86-suite = ["x86_64-suite"]
smir-jit = []
```

`autotests = false` means Cargo integration targets are the explicit `[[test]]` entries in `Cargo.toml`. Adding a `.rs` file under `tests/` does not automatically make it a standalone target.

## Feature matrix

| Feature | Default | Adds to the build | Does not establish |
|---|---:|---|---|
| `default` | — | feature bundle enabling `kvm` and `smir-jit` | a portable host-independent build; use `--no-default-features` when either backend must be omitted |
| `kvm` | yes | Linux-target KVM bindings, ioctls, backend code, and x86 hardware-backed execution paths | usable `/dev/kvm`, permission, virtualization firmware settings, guest compatibility, or instruction-level observability |
| `smir-jit` | yes | Unix executable-memory runtime, hot-region integration, SMIR native lowerers for admitted host/guest combinations | that a region promoted, that every SMIR operation is lowerable, or that native execution is faster for a given workload |
| `hvf` | no | Hypervisor.framework backend code | entitlement signing, runtime availability, or support for every host/guest architecture pair |
| `trace` | no | instruction trace implementation | KVM/HVF per-instruction tracing or complete trace visibility outside the software retirement loop |
| `debug` | no | GDB Remote Serial Protocol server | correctness of every GDB packet or stepping support for every backend |
| `profiling` | no | per-mnemonic counters, live output, and JSON export | host performance measurement or visibility into instructions executed outside the instrumented path |
| `x86_64-suite` | no | generated aggregate x86-64 integration-test target | production runtime capability; this is a test-selection feature |
| `x86-suite` | no | compatibility alias for `x86_64-suite` | an independent test corpus |

## Recommended combinations

### Portable baseline

```sh
cargo build --release --no-default-features
```

Includes the software engines and ordinary command-line VM code without KVM or the native tier. This is the minimum-dependency starting point for the bundled AArch64 guest.

### Software execution plus native SMIR

```sh
cargo build --release --no-default-features --features smir-jit
```

Use on a supported Unix x86-64 or AArch64 host. JIT admission remains guest-, operation-, state-, and host-feature-dependent.

### Linux KVM without native JIT

```sh
cargo build --release --no-default-features --features kvm
```

This selects the hardware backend without including the `smir-jit` default feature.

### Default Linux development build

```sh
cargo build --release
```

Equivalent to enabling `kvm,smir-jit` from the root package. Host target gates still determine whether KVM dependencies and code are active.

### macOS HVF build

```sh
cargo build --release --no-default-features --features hvf
codesign -s - -f --entitlements rax.entitlements target/release/rax
```

Add `smir-jit` if both the native tier and HVF are desired:

```sh
cargo build --release --no-default-features --features hvf,smir-jit
```

### Software observability build

```sh
cargo build --release --no-default-features \
    --features smir-jit,trace,debug,profiling
```

Remove `smir-jit` when debugging the interpreter or when a native region would complicate reproduction.

### Generated x86 aggregate

```sh
cargo test --release --features x86_64-suite --test x86_64
```

The compatibility spelling is:

```sh
cargo test --release --features x86-suite --test x86_64
```

Use the canonical `x86_64-suite` name in new documentation and automation.

## Target and host gating

Cargo features are only one layer. Availability can also depend on `cfg` conditions and runtime probes.

### KVM

The KVM crates are target dependencies for Linux. The useful runtime path further requires x86-64 hardware virtualization and `/dev/kvm`. A Linux build on another architecture or a container without device access can compile a different subset than the prose suggests.

### HVF

HVF is a macOS backend. The host architecture constrains the guest path. Apple Silicon is the established AArch64 hardware-assisted route; Intel macOS uses the x86-oriented route. The executable must carry the hypervisor entitlement.

### SMIR JIT

The root manifest describes a Unix W^X runtime and native lowering on x86-64 and AArch64 hosts. Admission is fail-safe: unsupported register, flag, memory, call, width, feature, or control-flow contracts leave execution in the interpreter. The exact eligible set differs by host/guest combination.

### Observability

Trace, GDB, profiling, and instruction-count snapshots are most complete where the software backend owns retirement. A compiled feature does not turn a hardware backend into an interpreter-equivalent event source.

## Release profile

The root release profile is:

```toml
[profile.release]
lto = "fat"
codegen-units = 1
panic = "unwind"
strip = true

[profile.release.build-override]
opt-level = 3
```

`panic = "unwind"` is part of the C ABI safety contract. `rax-capi` catches engine panics and reports `RAX_ERR_INTERNAL`; a root release profile that aborts would prevent containment.

## x86-64 compiler baseline

The checked-in Cargo configuration applies:

```toml
[target.'cfg(target_arch = "x86_64")']
rustflags = ["-C", "target-cpu=x86-64-v3"]
```

This permits an x86-64-v3 instruction baseline. It is not suitable for older x86-64 CPUs. A local host-native build can use:

```sh
RUSTFLAGS='-C target-cpu=native' cargo build --release
```

A host-native artifact is not portable and must not be used for an unlabeled benchmark comparison.

## Workspace relationship

The root workspace contains:

```text
capi
```

and excludes independent packages/directories:

```text
microkernel
tools/asl-parser/asl-parser-rs
_ref
```

Therefore:

```sh
cargo build --workspace --release
```

includes the root package and C API member, but does not build the microkernel or the excluded tools.

## C API features

The `rax-capi` crate has its own forwarded feature names. The normative list is in [`capi/README.md`](../../capi/README.md). At present it documents:

| C API feature | Effect |
|---|---|
| `jit` | native hot-block JIT support exposed to the embedding library |
| `kvm` | builds KVM capability, although the C backend selector does not yet expose the KVM route |
| `hvf` | Hypervisor.framework support |
| `trace` | verbose trace support |

Example:

```sh
cargo build -p rax-capi --release --features jit
```

Do not assume root feature names and C API feature names are identical: root uses `smir-jit`; the C API forwards it as `jit`.

## Test-feature discipline

When reporting a test result, include the feature set. Examples:

```text
cargo test --release
cargo test --release --all-features
cargo test --release --features x86_64-suite --test x86_64
cargo test --release --no-default-features --test arm
```

Those commands do not select the same code. A passing default-feature test run is not evidence about `--no-default-features`, and vice versa.

## Related pages

- [Building](../getting-started/building.md)
- [Environment variables](environment-variables.md)
- [Verification model](../development/verification.md)
- [Performance](../operations/performance.md)
- [Embedding](../embedding.md)
