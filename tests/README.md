# Test tree

The test tree is organized by what is being verified, rather than by how a
test happened to be created.

```text
tests/
├── fixtures/       # Buildable or executable guest inputs
├── generated/      # Checked-in generated Rust/data; never Cargo targets
├── support/        # Shared test support modules
└── suites/
    ├── api/        # Public API contracts
    ├── backend/    # Execution-backend integration
    ├── coverage/   # Source/specification inventory assertions
    ├── differential/ # RAX state compared with an external oracle
    ├── isa/        # Direct instruction-semantics tests
    ├── machine/    # Boot and platform integration
    ├── smir/       # Lift, lower, JIT, and round-trip validation
    └── tooling/    # Repository and build-tool invariants
```

Cargo automatic integration-test discovery must remain disabled. Each file
listed below is declared explicitly with a `[[test]]` entry in the root
`Cargo.toml`. Keeping the historical target names preserves existing
`cargo test --test <name>` and CI interfaces.

| Cargo target | Source |
|---|---|
| `aarch64_smir_native` | `suites/smir/lower/aarch64_native.rs` |
| `arm` | `suites/isa/arm/main.rs` |
| `arm_diff` | `suites/differential/arm/aarch64.rs` |
| `arm_diff32` | `suites/differential/arm/aarch32.rs` |
| `arm_vfp_a32` | `suites/isa/arm/aarch32/vfp.rs` |
| `asm_instructions` | `suites/isa/x86_64/assembly.rs` |
| `ci_actions_pinned` | `suites/tooling/ci_actions_pinned.rs` |
| `diff_fuzz` | `suites/differential/x86_64/fuzz.rs` |
| `differential` | `suites/differential/x86_64/kvm.rs` |
| `hexagon_bare_metal` | `suites/machine/hexagon_baremetal/boot.rs` |
| `hexagon_cf_diff` | `suites/differential/hexagon/control_flow.rs` |
| `hexagon_diff` | `suites/differential/hexagon/scalar.rs` |
| `hexagon_float_diff` | `suites/differential/hexagon/float.rs` |
| `hexagon_hvx_diff` | `suites/differential/hexagon/hvx.rs` |
| `hexagon_hvx_mem_diff` | `suites/differential/hexagon/hvx_memory.rs` |
| `hexagon_mem_diff` | `suites/differential/hexagon/memory.rs` |
| `hexagon_smir_lift` | `suites/smir/lift/hexagon.rs` |
| `isa_oracle` | `suites/api/isa_oracle.rs` |
| `kvm_minimal` | `suites/backend/kvm/minimal.rs` |
| `microkernel_multiarch` | `suites/machine/microkernel/multiarch.rs` |
| `pgo_build_script` | `suites/tooling/pgo/build.rs` |
| `pgo_script_safe` | `suites/tooling/pgo/safety.rs` |
| `realmode_boot` | `suites/machine/pc/real_mode_boot.rs` |
| `riscv_boot` | `suites/machine/riscv_virt/boot.rs` |
| `riscv_diff` | `suites/differential/riscv/scalar.rs` |
| `riscv_smir_lift` | `suites/smir/lift/riscv.rs` |
| `riscv_smir_aarch64_jit` | `suites/smir/jit/riscv_aarch64.rs` |
| `riscv_smir_x86_jit` | `suites/smir/jit/riscv_x86_64.rs` |
| `riscv_vector` | `suites/differential/riscv/vector.rs` |
| `smir_avx10_roundtrip` | `suites/smir/roundtrip/avx10.rs` |
| `smir_jit_evex_masking` | `suites/smir/jit/x86_64_evex_masking.rs` |
| `smir_jit_vcpu` | `suites/smir/jit/x86_64.rs` |
| `smir_jit_x86_aarch64` | `suites/smir/jit/x86_64_aarch64.rs` |
| `user_linux` | `suites/user/linux/main.rs` |
| `x86_64` | `suites/isa/x86_64/main.rs` |
| `x86_64_apx_map4_qemu_diff` | `suites/differential/x86_64/qemu_apx.rs` |
| `x86_64_avx512_inventory` | `suites/coverage/x86_64/avx512_inventory.rs` |
| `x86_64_avx512_kvm_diff` | `suites/differential/x86_64/kvm_avx512.rs` |
| `x86_64_evex_qemu_diff` | `suites/differential/x86_64/qemu_evex.rs` |
| `x86_64_unimplemented_manifests` | `suites/coverage/x86_64/unimplemented_manifests.rs` |
| `x86_64_unimplemented_qemu_diff` | `suites/differential/x86_64/qemu_unimplemented.rs` |
| `x86_64_unimplemented_source_inventory` | `suites/coverage/x86_64/unimplemented_source_inventory.rs` |

## Reachability rules

- Files below `generated/` are included by suite runners and are not
  standalone integration-test targets.
- `suites/isa/arm/main.rs` preserves the previous ARM reachability: one
  handwritten AArch64 leaf and the generated AArch64 suite are active.
- The handwritten ARM module graph and
  `suites/isa/arm/legacy_aarch32_dormant/` remain dormant. Moving them did not
  activate or delete any tests.
- `suites/isa/x86_64/main.rs` is the canonical x86-64 aggregate. It registers
  each semantic leaf directly; redundant nested `mod.rs` graphs are absent.
- External-oracle suites self-gate according to their existing host/tool
  checks; directory placement does not imply that an oracle is installed.

## Adding tests

Add behavioral cases beneath the matching suite domain. Add generated material
under `generated/` and record its provenance in `generated/manifest.toml`.
If a new executable runner is needed, add one explicit Cargo target and update
the table above.
