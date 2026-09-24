[← Documentation home](../../../README.md)

# Development and testing

The test tree is organized by the property under test, not by the historical way a test was created.

```text
tests/
├── fixtures/          # buildable or executable guest inputs
├── generated/         # checked-in generated Rust/data; not Cargo targets
├── support/           # shared test support
└── suites/
    ├── api/            # public API contracts
    ├── backend/        # KVM/HVF/emulator integration
    ├── coverage/       # source/specification inventories
    ├── differential/   # rax versus an external reference
    ├── isa/            # direct instruction semantics
    ├── machine/        # boot and platform integration
    ├── smir/           # lift, lower, JIT, and round trip
    └── tooling/        # repository/build invariants
```

Cargo automatic integration-test discovery is disabled. Every runnable integration target is explicitly declared in the root `Cargo.toml`. Files under `tests/generated/` are included by suite runners and must not be treated as standalone targets.

## Standard commands

```sh
# Release-mode local suite.
make test-quick

# Broad release-mode suite, generated x86 aggregate, and ignored cases.
make test

# Ordinary Cargo selection.
cargo test --release

# One explicit target.
cargo test --release --test arm_diff

# One test name with output.
cargo test --release --test differential case_name -- --exact --nocapture
```

`make test` and `make test-quick` have different coverage. Read the Makefile before treating either as a universal validation command.

## Complete explicit target map

| Cargo target | Source | Domain |
|---|---|---|
| `aarch64_smir_native` | `tests/suites/smir/lower/aarch64_native.rs` | SMIR native lowering |
| `arm` | `tests/suites/isa/arm/main.rs` | Arm ISA aggregate |
| `arm_diff` | `tests/suites/differential/arm/aarch64.rs` | AArch64 differential |
| `arm_diff32` | `tests/suites/differential/arm/aarch32.rs` | AArch32 differential |
| `arm_vfp_a32` | `tests/suites/isa/arm/aarch32/vfp.rs` | AArch32 VFP |
| `asm_instructions` | `tests/suites/isa/x86_64/assembly.rs` | x86 assembly/encoding semantics |
| `ci_actions_pinned` | `tests/suites/tooling/ci_actions_pinned.rs` | CI supply-chain invariant |
| `diff_fuzz` | `tests/suites/differential/x86_64/fuzz.rs` | randomized x86/KVM/SMIR differential |
| `differential` | `tests/suites/differential/x86_64/kvm.rs` | x86 KVM differential |
| `hexagon_bare_metal` | `tests/suites/machine/hexagon_baremetal/boot.rs` | Hexagon machine boot |
| `hexagon_cf_diff` | `tests/suites/differential/hexagon/control_flow.rs` | Hexagon control flow |
| `hexagon_diff` | `tests/suites/differential/hexagon/scalar.rs` | Hexagon scalar differential |
| `hexagon_float_diff` | `tests/suites/differential/hexagon/float.rs` | Hexagon floating point |
| `hexagon_hvx_diff` | `tests/suites/differential/hexagon/hvx.rs` | Hexagon HVX register operations |
| `hexagon_hvx_mem_diff` | `tests/suites/differential/hexagon/hvx_memory.rs` | Hexagon HVX memory |
| `hexagon_mem_diff` | `tests/suites/differential/hexagon/memory.rs` | Hexagon scalar memory |
| `hexagon_smir_lift` | `tests/suites/smir/lift/hexagon.rs` | Hexagon lift/IR interpretation |
| `isa_oracle` | `tests/suites/api/isa_oracle.rs` | public static oracle API |
| `kvm_minimal` | `tests/suites/backend/kvm/minimal.rs` | minimal KVM backend integration |
| `microkernel_multiarch` | `tests/suites/machine/microkernel/multiarch.rs` | multi-architecture end-to-end harness |
| `pgo_build_script` | `tests/suites/tooling/pgo/build.rs` | PGO script/build invariant |
| `pgo_script_safe` | `tests/suites/tooling/pgo/safety.rs` | PGO script safety |
| `realmode_boot` | `tests/suites/machine/pc/real_mode_boot.rs` | x86 real-mode/ISO machine |
| `riscv_boot` | `tests/suites/machine/riscv_virt/boot.rs` | RISC-V bare-metal machine |
| `riscv_diff` | `tests/suites/differential/riscv/scalar.rs` | RISC-V scalar differential |
| `riscv_smir_lift` | `tests/suites/smir/lift/riscv.rs` | RISC-V lift/IR interpretation |
| `riscv_smir_aarch64_jit` | `tests/suites/smir/jit/riscv_aarch64.rs` | RISC-V native AArch64 host |
| `riscv_smir_x86_jit` | `tests/suites/smir/jit/riscv_x86_64.rs` | RISC-V native x86-64 host |
| `riscv_vector` | `tests/suites/differential/riscv/vector.rs` | RVV differential |
| `smir_avx10_roundtrip` | `tests/suites/smir/roundtrip/avx10.rs` | x86/AVX10 lift round trip |
| `smir_jit_evex_masking` | `tests/suites/smir/jit/x86_64_evex_masking.rs` | EVEX mask lowering/JIT |
| `smir_jit_vcpu` | `tests/suites/smir/jit/x86_64.rs` | x86 vCPU native x86-64 JIT |
| `smir_jit_x86_aarch64` | `tests/suites/smir/jit/x86_64_aarch64.rs` | x86 vCPU native AArch64 JIT |
| `smir_jit_aarch32_aarch64` | `tests/suites/smir/jit/aarch32_aarch64.rs` | AArch32 guest native AArch64-host JIT |
| `smir_jit_thumb_aarch64` | `tests/suites/smir/jit/thumb_aarch64.rs` | Thumb guest native AArch64-host JIT |
| `user_linux` | `tests/suites/user/linux/main.rs` | `rax-user` Linux personality: UAPI tables, fixture programs vs recorded Linux results, CLI |
| `x86_64` | `tests/suites/isa/x86_64/main.rs` | x86 direct ISA aggregate |
| `x86_64_apx_map4_qemu_diff` | `tests/suites/differential/x86_64/qemu_apx.rs` | APX staged QEMU differential |
| `x86_64_avx512_inventory` | `tests/suites/coverage/x86_64/avx512_inventory.rs` | AVX-512 coverage inventory |
| `x86_64_avx512_kvm_diff` | `tests/suites/differential/x86_64/kvm_avx512.rs` | AVX-512 KVM differential |
| `x86_64_evex_qemu_diff` | `tests/suites/differential/x86_64/qemu_evex.rs` | generated EVEX QEMU differential |
| `x86_64_unimplemented_manifests` | `tests/suites/coverage/x86_64/unimplemented_manifests.rs` | generated unimplemented manifest consistency |
| `x86_64_unimplemented_qemu_diff` | `tests/suites/differential/x86_64/qemu_unimplemented.rs` | rejection comparison with QEMU |
| `x86_64_unimplemented_source_inventory` | `tests/suites/coverage/x86_64/unimplemented_source_inventory.rs` | source/manifest coverage invariant |

This table is an interface: changing a target name breaks CI and developer commands even when the underlying source merely moves.

## Reachability rules

- `tests/generated/` files are included by a registered target and are never automatically runnable.
- `tests/suites/isa/arm/main.rs` preserves the active Arm module graph. Moving a dormant file does not make it execute.
- `tests/suites/isa/arm/legacy_aarch32_dormant/` remains dormant until explicitly included.
- A test source under `tests/` that lacks a `[[test]]` entry and is not included by another target is unreachable.
- Feature-gated modules can compile out while the target itself still succeeds.
- `#[ignore]`, name filters, host `cfg`, and runtime prerequisite checks can all reduce an apparent run to zero relevant cases.

## Test selection by change

| Change | Minimum focused tests | Additional validation |
|---|---|---|
| x86 decoder/semantics | `x86_64`, relevant inventory, `differential` | AVX-512/EVEX/APX target if affected; boot smoke test |
| Arm semantics | `arm`, `arm_diff` or `arm_diff32` | generated-suite regeneration check; AArch64 boot if system state changed; AArch32/Thumb AArch64-host JIT targets if lowering changed |
| Hexagon scalar/packet | matching `hexagon_*_diff` | `hexagon_bare_metal`; `hexagon_smir_lift` if lift affected |
| Hexagon HVX | `hexagon_hvx_diff` and/or `hexagon_hvx_mem_diff` | packet/SMIR tests |
| RISC-V scalar | `riscv_diff` | `riscv_boot`, `riscv_smir_lift`, host JIT target if admitted |
| RVV | `riscv_vector` | lift and both host-JIT targets where supported |
| SMIR optimizer | affected lift test plus native target | O0/O2 differential corpus and fallback counters |
| native x86 lowerer | `smir_jit_vcpu`, relevant EVEX test | runtime `RAX_JIT_VERIFY=1`, benchmark and SMC cases |
| native AArch64 lowerer | `aarch64_smir_native` or cross-host target | run on actual AArch64 host; fallback/flags cases |
| machine/device | matching machine target | guest integration, interrupt, checkpoint round trip |
| CLI/config | unit/API tests plus representative launch | precedence and error-message tests |
| C API | `cargo test -p rax-capi` plus C/C++ examples | static/dynamic build, panic boundary, symbol/ABI check |
| generated tooling | tooling/inventory target | regenerate in clean tree and assert no unexplained diff |

The table is a floor, not a substitute for impact analysis.

## External prerequisites

Potential prerequisites include:

- `/dev/kvm` plus permissions;
- host CPU instruction features;
- `qemu-x86_64`, `qemu-aarch64`, `qemu-arm`, `qemu-hexagon`, or `qemu-riscv64`;
- cross-compilers and assemblers;
- LLVM tools for generated encodings;
- Intel SDE for the optional microkernel comparison;
- AArch64 hardware for native EL0/lowerer cases;
- macOS HVF entitlement for hardware-assisted launch.

A test should either fail with an actionable missing-prerequisite message or print an explicit skip reason. Silent success with zero cases should be treated as a test bug.

## Reading Cargo output

Always check:

```text
running N tests
N passed; M failed; K ignored; F filtered out
```

Then inspect test-specific skip messages. A registered target compiling successfully establishes only that the selected code built.

## Adding a test

1. Choose the domain by the property being verified.
2. Put reusable artifacts in `fixtures/`, generated material in `generated/`, and shared code in `support/`.
3. Add a `[[test]]` entry if the new source is a standalone integration target.
4. Preserve historical target names when moving an existing test.
5. Make prerequisites and skips visible.
6. Record seeds and exact instruction bytes on failure.
7. Compare only architecturally defined state or mask undefined bits.
8. Add the target to CI/Makefile only when its prerequisites and runtime cost are understood.
9. Update this map and the root documentation index.

## Generated material

Generated Rust/data is checked in when reproducibility, reviewability, or build independence requires it. The generator, source corpus, command, tool version, and expected diff must be documented. See [Generated suites](../generated-suites.md).

## Evidence discipline

The repository engineering guide explicitly warns that a successful command is not proof that a host-specific or external-oracle path ran. Test reports should follow [Verification model](../verification.md), especially for README/status claims.
