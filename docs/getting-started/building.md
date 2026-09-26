[← Documentation home](../../README.md)

# Building and Cargo features

This page describes the supported build shapes, their host dependencies, and the facilities each build actually contains.

## Prerequisites

The root package uses Rust edition 2024. Install a current stable Rust toolchain for ordinary builds. Some repository tooling—most notably the three-architecture microkernel—requires nightly Rust with `rust-src`; that requirement does not apply to the normal `rax` binary.

General prerequisites:

- Git and Cargo.
- A 64-bit Unix-like host for the currently exercised native runtime paths.
- A C toolchain and architecture-specific cross-tools for selected differential suites.
- KVM access for hardware-backed x86-64 execution and KVM differential tests.
- Apple code signing and the supplied entitlement for Hypervisor.framework.

The dependency graph contains work intended to make portions of the tree buildable on Windows, but the current host I/O, loader, and tested runtime matrix should not be described as Windows support.

## Build shapes

### Portable software interpreter

```sh
cargo build --release --no-default-features
```

This omits the default `kvm` and `smir-jit` features. It is the least host-dependent way to build the command-line emulator and is the appropriate build for the bundled AArch64 quick start.

### Software interpreter plus native JIT

```sh
cargo build --release --no-default-features --features smir-jit
```

Use this on a supported Unix x86-64 or AArch64 host when hardware virtualization is not required but native SMIR execution is.

### Default build

```sh
cargo build --release
```

The root package currently defines these default features:

```toml
default = ["kvm", "smir-jit"]
```

On Linux this includes the KVM dependencies and the SMIR JIT. The presence of the `kvm` feature does not guarantee that `/dev/kvm` exists or is accessible at runtime.

### Hardware virtualization on macOS

```sh
cargo build --release --features hvf
codesign -s - -f --entitlements rax.entitlements target/release/rax
```

The binary must be signed again after it changes. On Apple Silicon, AArch64 guests can use `--backend hvf`; the default backend for non-x86 guests remains the software emulator unless explicitly overridden. On Intel macOS, the backend selector can use HVF for x86-64.

### Observability build

```sh
cargo build --release --features trace,debug,profiling
```

This enables the implementation behind:

- `--trace`;
- `--gdb`, `--wait-gdb`, and GDB packet tracing;
- `--profile`, JSON profile output, and live profile intervals.

The CLI options are parsed by the normal binary, but their useful behavior depends on the matching feature. Build the feature before documenting or testing the facility.

### Complete development build

```sh
cargo build --release --features trace,debug,profiling,x86_64-suite
```

`x86_64-suite` primarily controls the generated x86-64 integration-test aggregate. It is not needed to boot a guest.

## Host tuning

The checked-in `.cargo/config.toml` sets the following Rust flag on x86-64 hosts:

```toml
[target.'cfg(target_arch = "x86_64")']
rustflags = ["-C", "target-cpu=x86-64-v3"]
```

This selects an x86-64-v3 baseline rather than the oldest x86-64 baseline. It allows LLVM to use AVX2, BMI2, FMA, POPCNT, LZCNT, and related instructions. A resulting binary is therefore not suitable for pre-v3 x86-64 CPUs.

For a local throughput build tied to one host:

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Do not publish numbers from that binary as portable performance. It may execute instructions unavailable on another host.

## Release profile

The root release profile uses:

- fat LTO;
- one codegen unit;
- `panic = "unwind"`;
- stripped output;
- optimization level 3 for build dependencies.

Unwinding is retained because the stable C ABI catches internal panics and converts them to `RAX_ERR_INTERNAL`. Changing the root release profile to `panic = "abort"` would invalidate that ABI contract.

## Make targets

```sh
make build          # cargo build --release
make build-debug    # cargo build
make test-quick     # cargo test --release
make test           # release tests + x86_64-suite + ignored tests
make bench          # host-native bench_loop and bench_mem
make pgo            # profile-guided, host-tuned release build
make linux          # fetch and build an uncompressed x86-64 Linux kernel
make run-linux      # invoke run.sh
make microkernel    # build all three bare-metal microkernels
make test-microkernel
```

The PGO target is explicitly host-tuned by default. Set `PGO_TARGET_CPU=x86-64-v3` when a more portable PGO artifact is required.

## Building Linux process emulation

`rax-user` is a root-package binary with no additional feature requirement:

```sh
cargo build --release --locked --no-default-features --bin rax-user
# Include eligible x86-64 and opt-in RV64 native regions.
cargo build --release --locked --no-default-features --features smir-jit --bin rax-user
```

It runs Linux ELF programs on Linux or macOS, selects the ABI from the ELF
header, and loads dynamic interpreters/libraries through `--sysroot`.
The primary ABIs are x86-64, AArch64, and RV64; i386 compatibility is partial
and interpreted. KVM/HVF, a kernel image, and machine configuration are not
part of this execution path. See [Linux programs](linux-programs.md).

## Building the C API

```sh
cargo build -p rax-capi --release
```

The workspace contains the `capi` member, while `microkernel`, `tools/asl-parser/asl-parser-rs`, and `_ref` are deliberately excluded because they have independent build targets or scripts.

See [Embedding rax](../embedding.md) and [`capi/README.md`](../../capi/README.md).

## Common build failures

### KVM dependencies on an unsuitable host

Use the software-only build:

```sh
cargo build --release --no-default-features
```

### Hypervisor entitlement failure

Re-run `codesign` after the final build. Signing a binary and rebuilding it invalidates the signature on the new file.

### Microkernel requests unstable `build-std`

Install nightly and `rust-src`:

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

Also provide `llvm-objcopy` or `objcopy`.

### Feature appears accepted but facility is inert or unavailable

Confirm the compiled feature set. CLI parsing alone is not evidence that `trace`, `debug`, or `profiling` code was included.

## Root feature reference

The root manifest currently declares:

| Feature | Default | Build effect | Runtime/validation note |
|---|---:|---|---|
| `kvm` | yes | Enables `kvm-bindings` and `kvm-ioctls` on Linux targets. | The usable path is Linux/x86-64 and still requires `/dev/kvm`; a compiled feature is not evidence that KVM ran. |
| `smir-jit` | yes | Includes the Unix W^X executable-memory runtime, native lowerers, and vCPU integration for supported host/guest paths. | Admission is partial and fail-safe; `RAX_NO_JIT=1` disables x86 hot-region promotion at runtime. |
| `hvf` | no | Includes Hypervisor.framework support. | Requires macOS, a valid host/guest combination, entitlement signing, and explicit `--backend hvf`. |
| `trace` | no | Includes SDE-style instruction trace support. | Meaningful on software execution paths that retire through the instrumented step loop. |
| `debug` | no | Includes the GDB Remote Serial Protocol server. | `--gdb`, `--wait-gdb`, and packet tracing require this code. |
| `profiling` | no | Includes per-mnemonic profiling and JSON output. | The runtime reports a feature error when profiling is requested from a build without it. |
| `x86_64-suite` | no | Includes the generated x86-64 integration-test aggregate. | Test/build feature, not a guest capability switch. |
| `x86-suite` | no | Alias that enables `x86_64-suite`. | Retained for compatibility. |

Useful explicit combinations:

```sh
# Software interpreter only.
cargo build --release --no-default-features

# Software interpreter + native tier.
cargo build --release --no-default-features --features smir-jit

# Linux KVM without the native tier.
cargo build --release --no-default-features --features kvm

# Full interactive software tooling, no KVM.
cargo build --release --no-default-features \
  --features smir-jit,trace,debug,profiling

# Run the generated x86 aggregate.
cargo test --features x86_64-suite --test x86_64
```

## Workspace and test discovery

The root workspace contains `capi`. The following in-tree packages are deliberately excluded from the root workspace because they have independent targets or scripts:

```text
microkernel
tools/asl-parser/asl-parser-rs
_ref
```

The package sets `autotests = false`. Integration tests are therefore registered explicitly in `Cargo.toml`; a `.rs` file under `tests/` is not automatically an independently runnable Cargo target. See [Test target map](../development/testing/README.md).

## Release profile and ABI consequence

The release profile uses fat LTO, one codegen unit, stripped output, and `panic = "unwind"`; build dependencies use optimization level 3. Unwinding is intentional: the C ABI wraps entry points in panic containment and promises to convert an internal panic to `RAX_ERR_INTERNAL`. Switching the release profile to `panic = "abort"` breaks that promise.

## Dependency and host notes

KVM dependencies are target-gated to Linux. Unix-specific host code supplies terminal handling, signal integration, and the executable-memory runtime used by the native tier. Comments and dependency patches aimed at future Windows buildability are engineering work, not a supported Windows runtime declaration.

For the current native and cross-build matrix, inspect `.github/workflows/README.md` and the workflow YAML. A successful cross-compile does not establish runtime behavior for terminal control, signals, executable memory, hypervisor APIs, or external oracle programs.

## Reproducible build record

For a binary or benchmark intended to be compared, record:

```text
rax commit:
rustc -Vv:
cargo -V:
host OS/kernel:
host CPU:
Cargo command:
Cargo features:
RUSTFLAGS:
PGO workload and PGO_TARGET_CPU, if any:
binary SHA-256:
```

## Related pages

- [Getting started](overview.md)
- [Performance](../operations/performance.md)
- [Test target map](../development/testing/README.md)
- [Embedding](../embedding.md)
- [Troubleshooting](../troubleshooting.md)
