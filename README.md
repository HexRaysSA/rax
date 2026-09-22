<h1 align="center">
  <img width="128" src="./assets/ida.png" alt="rax" /><br>
  rax
</h1>

<p align="center">
  A Rust CPU emulator and virtual-machine monitor for inspecting guest execution across x86-64, Arm, Qualcomm Hexagon, and RISC-V.
</p>

`rax` contains software execution engines for x86-64, AArch64/AArch32, Qualcomm Hexagon, and RV64. Its x86-64 and AArch64 machines have Linux boot paths; Hexagon and RISC-V currently run bare-metal programs. Supported regions can be lifted into SMIR and, when an exact host-specific admission contract is satisfied, executed as native code on x86-64 or AArch64 hosts.

The project uses differential testing extensively. A harness initializes `rax` and a reference engine or host CPU from corresponding state, executes selected instructions or sequences, and compares the state that each side exposes. That is strong evidence for the cases, states, tools, and projections that actually run. It is not formal verification, exhaustive ISA conformance, or proof that the reference has no defect.

`rax` is a research project. It is not an official Hex-Rays product and it is not a production hypervisor or hardened security sandbox.

## Start with a checked-in guest

The shortest clean-checkout path uses the AArch64 kernel and initramfs already stored in the repository. On a supported 64-bit Linux or macOS host:

```sh
cargo build --release --no-default-features

./target/release/rax \
    --arch aarch64 \
    --backend emulator \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

The guest serial console is attached to the terminal. Press `Ctrl-A`, then `h`, for host-console help; press `Ctrl-A`, then `x`, to stop the machine.

This baseline deliberately excludes KVM, Hypervisor.framework, and the native JIT. It establishes the command-line binary, checked-in guest artifacts, software execution path, AArch64 machine, generated platform description, and serial console before optional host facilities are introduced.

Continue with [Getting started](docs/getting-started/overview.md) for host prerequisites and the path appropriate to your guest.

## Current project shape

| Guest family | Runnable paths | Machine-level use | Principal evidence | Important boundary |
|---|---|---|---|---|
| **x86-64** | software emulator; KVM on Linux x86-64; HVF on an appropriate macOS host; admitted SMIR native regions | direct Linux loading, serial PC platform, legacy real-mode/El Torito ISO route | direct ISA tests, KVM/QEMU differential suites, generated inventories, SMIR/JIT comparisons, machine tests | one executing vCPU; software Linux and JIT coverage are narrower than the architecture as a whole |
| **AArch64 / AArch32 / Thumb / Cortex-M/R** | software Arm cores; AArch64 HVF on Apple Silicon; selected AArch64-host native lowerers | AArch64 Linux virtual machine, DT-based and profile-specific 32-bit paths, SoC and microcontroller work | native AArch64 EL0 or QEMU comparisons, generated Arm cases, machine tests, microkernel, SMIR tests | AArch64 Linux is established; no general AArch32 Linux-to-shell result is claimed |
| **Qualcomm Hexagon** | packet-aware software emulator | bare-metal ELF machine with UART/halt integration | scalar, control-flow, floating-point, memory, HVX, HVX-memory, bare-metal, and lift targets | public ISA selector currently ends at `v69`; no general-purpose OS machine |
| **RISC-V RV64** | software emulator; selected state-backed SMIR/native paths | bare-metal ELF machine with UART/halt integration | scalar and vector QEMU comparisons, boot test, lift tests, x86-64/AArch64-host native tests | no complete privileged architecture or Sv39 Linux-capable machine |

The source and executable tests define current implementation state. The detailed pages below explain what is present, what is publicly selectable, what has a registered test, what can self-skip, and what remains unsupported.

## Documentation

This root `README.md` is the **single complete documentation entrypoint**. There is deliberately no `docs/README.md`. Every maintained breakout page links back here; no breakout page is intended to become a competing front page.

### Build and run

- [Getting started](docs/getting-started/overview.md) — choose the smallest path for a Linux guest, bare-metal program, bootable ISO, hardware backend, or development task.
- [Building](docs/getting-started/building.md) — prerequisites, supported build shapes, host tuning, Make targets, PGO, C API build, release-profile consequences, and common failures.
- [Linux guests](docs/getting-started/linux-guests.md) — checked-in AArch64 boot, AArch64 HVF, x86 software Linux, x86 KVM, image-format distinctions, serial milestones, and reproducibility records.
- [Bare-metal programs and bootable ISOs](docs/getting-started/bare-metal-and-iso.md) — RV64, Hexagon, microkernel, x86 real-mode/El Torito, machine-specific Arm images, stop conditions, and evidence requirements.
- [Troubleshooting](docs/troubleshooting.md) — known baselines and targeted checks for builds, image loading, consoles, hypervisors, external oracles, JIT admission, and checkpoints.

### Runtime architecture

- [Architecture overview](docs/architecture/overview.md) — CLI/configuration resolution, machine/backend/ISA separation, guest state, retirement, backend observability, and status vocabulary.
- [x86-64 architecture](docs/architecture/x86_64/README.md) — decode families, architectural categories, faults/system state, software/KVM/HVF paths, generated coverage, differential evidence, JIT routes, and gaps.
- [Arm architecture](docs/architecture/arm/README.md) — public profiles, AArch64, AArch32, Thumb, Cortex-M/R, AdvSIMD/VFP, SVE-family work, machines, differential tests, and limitations.
- [Hexagon architecture](docs/architecture/hexagon/README.md) — public revisions, packet commit, `.new` forwarding, predicates/loops, scalar and HVX state, bare-metal loading, oracle targets, and SMIR.
- [RISC-V architecture](docs/architecture/riscv/README.md) — scalar, compressed, atomic, floating-point, bit-manipulation, crypto, RVV, bare-metal machine, QEMU comparisons, SMIR/native paths, and privileged boundary.
- [Machines and boot](docs/architecture/machines.md) — image detection, x86 direct/legacy boot, AArch64 virtual platform, 32-bit Arm and SoC selection, Hexagon/RISC-V machines, memory, command lines, and restore construction.
- [Devices and platform wiring](docs/architecture/devices.md) — baseline PC devices, optional PCI attachment, interrupts, serial/VGA boundary, AArch64 and 32-bit Arm devices, bare-metal peripherals, checkpoints, and validation stages.
- [SMIR and native execution](docs/architecture/smir.md) — IR, lifters, interpreter, optimizer, lowerers, hot-region policy, per-host admission, helper/memory contracts, invalidation, runtime controls, and equivalence evidence.

### Verification and development

- [Verification model](docs/development/verification.md) — claim scope, oracle hierarchy, state projection, undefined behavior, corpus design, external prerequisites, false-green hazards, and defensible result language.
- [Test target map](docs/development/testing/README.md) — the explicit Cargo integration targets grouped by API, backend, coverage, differential, ISA, machine, SMIR, and tooling responsibility.
- [Generated suites](docs/development/generated-suites.md) — checked-in generated data, source/spec inventories, reproducibility, generator provenance, stale-output detection, and limits of inventory evidence.
- [Microkernel harness](docs/development/microkernel.md) — independent nightly build, x86-64/AArch64/ARMv6 payloads, result markers, cross-architecture checksum, SDE comparison, and interpretation.
- [Repository layout and ownership](docs/reference/repository-layout.md) — root map, source collaboration graph, canonical owners, change routing, test structure, truth hierarchy, and merge checklist.
- [Documentation policy](docs/documentation-policy.md) — one-entrypoint rule, claim classes, evidence qualifiers, ownership, update procedure, and style rules that prevent a return to synthetic completeness.

### Operate and measure

- [Observability and debugging](docs/operations/observability.md) — console multiplexer, instruction trace, GDB RSP and IDA attachment, packet logs, profiling, logging, checkpoint-assisted diagnosis, and backend capability boundaries.
- [Checkpoints and restore](docs/operations/checkpoints.md) — whole-machine `.rxc`, legacy `--resume`, interactive/signal/count triggers, output selection, safe points, device state, compatibility, and failure diagnosis.
- [Performance and benchmarking](docs/operations/performance.md) — repository benchmarks, interpretation of historical throughput claims, build normalization, interpreter/JIT/backend measurement, PGO, fallback accounting, and result templates.

### Exact reference

- [Command-line reference](docs/reference/command-line.md) — every current CLI option, accepted values, precedence, feature dependencies, checkpoint semantics, and complete examples.
- [TOML configuration reference](docs/reference/configuration.md) — file schema, exact enum spellings, defaults, profile selectors, load/entry fields, validation, and CLI precedence.
- [Cargo features and build profiles](docs/reference/build-features.md) — root feature table, recommended combinations, host gating, release profile, compiler baseline, workspace relationship, and C API feature-name differences.
- [Environment variables](docs/reference/environment-variables.md) — logging, JIT diagnostics, machine selection, `run.sh`, compiler/PGO controls, microkernel tooling, and reproduction records.
- [Status and limitations](docs/reference/status-and-limitations.md) — consolidated execution matrix, architecture-specific qualifications, machine/device/JIT/testing boundaries, security posture, embedding scope, and licensing scope.
- [Embedding through C and C++](docs/embedding.md) — library versus full-machine scope, builds, CMake/pkg-config, lifecycle, ABI, memory/register/exit contracts, hooks, stateless analysis, threading, and downstream validation.

## Common build profiles

The root package uses Rust edition 2024. Its default features are `kvm` and `smir-jit`.

```sh
# Portable software engines only.
cargo build --release --no-default-features

# Software engines plus admitted native SMIR execution.
cargo build --release --no-default-features --features smir-jit

# Root defaults: KVM plus SMIR JIT where target-gated code applies.
cargo build --release

# Add interpreter observability surfaces.
cargo build --release --features trace,debug,profiling
```

A compiled feature is not proof that the host facility initialized or that the desired path executed. KVM still requires a compatible Linux x86-64 host and usable `/dev/kvm`; HVF requires macOS, a valid host/guest pair, and entitlement signing; native regions must pass operation, register, flag, memory, helper, control-flow, and host-feature gates.

## Testing without false confidence

```sh
# Fast local release-mode suite.
make test-quick

# Broad release suite, including the generated x86 aggregate and ignored tests.
make test

# Representative differential targets.
cargo test --release --test differential
cargo test --release --test arm_diff
cargo test --release --test hexagon_hvx_diff
cargo test --release --test riscv_diff
```

External-reference and host-specific tests can self-skip when `/dev/kvm`, a required host architecture or CPU feature, QEMU user-mode binary, cross-toolchain, LLVM facility, or other prerequisite is absent. Record the target, features, host/tool versions, `running N tests`, and skip output. A zero exit status alone does not establish that a comparison ran.

## Boundaries to understand before adoption

- Only vCPU 0 executes; `--vcpus` is not SMP support.
- The software x86 Linux path is deliberately constrained and is not interchangeable with arbitrary KVM boot.
- AArch64 Linux is the established Arm Linux machine; the 32-bit Arm work does not currently justify a general Linux-to-shell claim.
- RISC-V and Hexagon are bare-metal machine paths, not general OS platforms.
- The public Hexagon ISA selector currently reaches `v69`, despite broader historical prose.
- Native JIT coverage is partial, host-specific, and designed to fall back to interpretation.
- A device model’s source file does not imply default attachment, guest enumeration, working interrupts/DMA, or checkpoint completeness.
- Trace, instruction profiling, code hooks, and software instruction-count triggers do not become equivalent on KVM/HVF.
- Differential agreement is not a formal proof, security certification, or exhaustive conformance result.
- The repository should not be treated as a hardened boundary for untrusted guest code without an independent threat model and review.

## Canonical repository references

- [`src/README.md`](src/README.md) — current production-source ownership map.
- [`tests/README.md`](tests/README.md) — current test-tree responsibility and target mapping.
- [`capi/README.md`](capi/README.md) — normative C/C++ API reference.
- [`docs/specifications/smir/`](docs/specifications/smir/) — derived SMIR design material; implementation remains authoritative when it lags.
- [`microkernel/`](microkernel/) — independent freestanding integration workload.
- [`.github/workflows/`](.github/workflows/) — automation that defines the actually attempted host/tool matrix.
- [`AGENTS.md`](AGENTS.md) — engineering truth hierarchy, validation rules, and false-green safeguards.

## Name

`RAX` is the x86-64 accumulator register. The project began with an x86-64 focus and retained the name as additional guest architectures were added.

## License

RAX is licensed under the [MIT License](LICENSE).
Third-party components are covered by their respective licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms and
[SECURITY.md](SECURITY.md) for vulnerability reporting.
