# rax CI

A layered validation matrix that spreads rax's suite across as many
GitHub-hosted OS × CPU-architecture combinations as the platform offers, plus a
build sweep over many more ISAs via cross-compilation.

## Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| [`licensing.yml`](licensing.yml) | push, PR, dispatch | Resolves locked Cargo dependencies, then checks crate contents, license/notice synchronization and packaging regressions on Linux/macOS/Windows. |
| [`ci.yml`](ci.yml) | push, PR | Fast gate. Required `rustfmt` + `clippy`, then **build all targets** and run a **core test slice**, including EVEX masking/JIT regressions and Linux process recordings, on the declared native platforms. |
| [`full-suite.yml`](full-suite.yml) | nightly, dispatch | The registered suite, sharded by test binary across parallel jobs, on the declared Linux/macOS native platforms; runtime prerequisites can still cause self-skips. |
| [`cross.yml`](cross.yml) | push, PR, nightly | **Cross-compile** the core to many CPU architectures (build-only) to guard portability. |
| [`differential.yml`](differential.yml) | nightly, dispatch | Installs the **QEMU/llvm-mc/clang oracles** so the differential harnesses actually diff (they skip otherwise). One job per guest arch. |
| [`kvm.yml`](kvm.yml) | push (kvm paths), nightly | Enables `/dev/kvm`, gates the **KVM backend** + release build, and retains host-dependent silicon differentials as nightly diagnostics. |
| [`sanitizers.yml`](sanitizers.yml) | nightly, dispatch | **ASan/UBSan** on a core slice + a **stable/beta/nightly** toolchain sweep. |
| [`microkernel.yml`](microkernel.yml) | every push, PR | Builds the **bare-metal microkernel test suite** for **x86_64, AArch64 and ARMv6** (nightly + build-std; custom ARMv6 target) and **boots each under the emulator**, asserting `RESULT PASS` and an identical cross-arch n-body checksum. |
| [`capi-release.yml`](capi-release.yml) | `v*` tags, packaging PRs, dispatch | Five mandatory native SDKs plus seven experimental candidates (Windows ARM64, two native musl, four GNU/Linux cross targets executed under QEMU). Publishes validated tags after mandatory lanes pass; only fully tested candidate artifacts are included. |

## Platform coverage

RAX requires 64-bit targets. The patched memory dependency supports Windows;
`capi-release.yml` builds and runs the interpreter C API on Windows MSVC.
The broader ISA/JIT core matrix below remains Linux/macOS only.

Native run/build (GA runners, pinned — `macos-latest` is mid-migration in 2026):

| OS | x64 | arm64 |
|---|---|---|
| Linux | `ubuntu-24.04` | `ubuntu-24.04-arm` |
| macOS | `macos-15-intel` | `macos-15` |

Cross-compiled (build-only, all 64-bit): aarch64 (gnu/musl), riscv64gc, ppc64,
ppc64le, s390x, x86_64-musl, and best-effort tier-3 (sparc64, mips64/mips64el).

## Design notes

- **Feature gating is per-platform and deliberate.** `kvm` is Linux/x86-only and
  needs `/dev/kvm`; `smir-jit` pulls a `libc`-backed W^X runtime with x86_64 and
  AArch64 host backends. Linux and Apple Silicon portable lanes enable
  `smir-jit`; Intel macOS portable lanes omit it. `x86_64-suite` is enabled
  throughout this core matrix so the gated x86-64 binaries compile. The
  workflow matrices define the exact feature selections.
- **Why `cargo test`, not `cargo nextest`.** nextest runs each test in its own
  process. Plain `cargo test` groups generated cases within a process, and
  the workflows shard by explicitly registered integration-test binary with
  repeated `--test` flags. External differential targets — `arm_diff`,
  `differential`, `diff_fuzz`, and the EVEX diff — live in the `differential.yml` / `kvm.yml` lanes. Note that
  `neon_gen.rs` / `sve2_gen.rs` / `arm32_gen.rs` are **data tables** (`pub static
  ..._SWEEP`) `include!`d by `arm_diff*.rs`, not standalone tests, so they are
  never selected with `--test`.
- **Test builds stay on the dev profile.** The release profile's `lto = "fat"` /
  `codegen-units = 1` would blow compile time and RAM on the giant generated
  tables. The shared setup also drops debuginfo (`CARGO_PROFILE_*_DEBUG=0`).
- **Oracles skip gracefully.** The differential harnesses probe for
  `qemu-<arch>`, `llvm-mc`, `clang`/`cc`, etc. and skip when absent — that keeps
  `ci.yml` green without them; `differential.yml` installs them so the diffs run.
- **Shared setup** lives in [`../actions/setup-rust`](../actions/setup-rust):
  toolchain install + `Swatinem/rust-cache` + CI build defaults.

## Linux process validation

`ci.yml` selects `user_linux` in the serial core slice, and `full-suite.yml`
selects it in the serial unit shard alongside library tests. Its syscall
fixtures and morok whole programs compare recorded Linux output and exit
status for x86-64, AArch64, and RV64. The output projection, translator
substitutions, and i386 library-test boundary are described in the
[verification reference](../../docs/development/verification.md#linux-process-and-whole-program-comparisons).

Both workflows request ignored tests, but the live Docker comparison
reports `NOT RUN` unless `RAX_USER_DOCKER_ORACLE` is present. Recorded
comparisons run without a live Docker oracle. See the
[test-target registry](../../tests/README.md) for the current
Cargo target inventory.

## C API binary releases

See [the C API distribution contract](../../capi/README.md#binary-distributions)
for tag/version rules, target baselines, archive contents, and local validation.
Release jobs override the development x86-64-v3 baseline explicitly and use
stable Rust with locked dependencies. PR/dispatch runs upload test artifacts
without creating releases. The publish job alone has `contents: write`.

To enforce the licensing checks at merge time, add their job names to the repository's required status checks.
