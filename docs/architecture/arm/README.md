[← Documentation home](../../../README.md)

# Arm architecture

`rax` contains several Arm execution profiles rather than one monolithic “ARM backend”:

- AArch64 application and system execution;
- AArch32 and Thumb execution;
- Cortex-M profiles;
- Cortex-R profiles;
- an AArch64 Linux virtual machine;
- AArch64 Linux ELF process execution through `rax-user` at EL0;
- selected 32-bit machine and SoC paths;
- SMIR lifting and AArch64 native lowering.

The existence of instruction semantics for a profile does not imply that every operating system or board for that profile boots.

`rax-user` reuses the AArch64 core with a process address space and Linux
syscall personality, including guest threads, signals, IPC, and ptrace.
Its software execution and guest single-step do not require HVF or a Linux
machine. This interface accepts AArch64 ELF, not AArch32 Linux programs;
see [Linux programs](../../getting-started/linux-programs.md).

## Public selectors

The architecture selector exposes:

```text
aarch64
armv7a
armv8a32
cortex_m
cortex_r
```

TOML additionally exposes profile selectors.

### AArch64 profiles

```text
v8_0, v8_1, v8_2, v8_3, v8_4, v8_5, v8_6, v8_7, v8_8,
v9_0, v9_1, v9_2, v9_3, v9_4
```

Default: `v8_0`.

### AArch32 profiles

```text
v6, v6_t2, v6_k, v7_a, v7_a_virt, v7_a_lpae, v8_a32
```

Default: `v7_a`.

### Cortex-M profiles

```text
v6_m, v7_m, v7_em, v8_m_baseline, v8_m_mainline, v8_1_m
```

Default: `v7_m`.

### Cortex-R profiles

```text
v7_r, v8_r, v8_r64
```

Default: `v7_r`.

A selected profile controls architectural configuration. It is not a promise that every optional extension associated with that revision is reachable.

## AArch64 scalar and system execution

The AArch64 core covers ordinary integer arithmetic, logical operations, shifts, bit manipulation, branches, calls and returns, loads and stores, atomics, system-register interactions, exceptions, and floating-point/SIMD families represented in the source and test corpora.

The Linux software-machine path includes:

- EL0/EL1 execution;
- stage-1 address translation;
- exception delivery;
- GICv3 distributor, redistributor, and ICC system-register behavior;
- the Arm generic timer;
- PL011 serial console;
- PSCI boot/control interface;
- generated device tree describing RAM and platform devices.

The same AArch64 Linux image can use the software backend on supported hosts. On Apple Silicon it can use Hypervisor.framework after building the `hvf` feature and signing the binary with the project entitlement.

## Generated A64 corpus configuration

The generated allocated-encoding smoke tests enable `ArmFeatures::PACA`, as do
both Rust-output templates and the generator's emulator characterization CPU.
The primary ASL `aarch64_memory_single_general_immediate_signed_pac` decode in
`asl/arm_instrs.asl` requires `HavePACExt()` and `size == 0b11`. The production
CPU default remains ARMv8.0-A; dedicated `test_ldraa_needs_feat_pauth_and_an_aligned_sp`
coverage checks rejection without the feature. These corpus checks characterize
RAX behavior and do not establish independent architectural correctness.

Assumption PA1: the corpus configuration and generation-time characterization
must expose the same features. The previous default-only helper violated this
for the three generated `LDRAA` cases `0xf8200400` and `0xf8201400` after the
production feature gate was added. Probe: run `cargo test --no-default-features
--test arm` and the ASL parser's `pointer_authenticated_load_allocation_survives_oracle_reset`
test. A generated allocation mismatch falsifies this assumption. Status: confirmed
by the full 46,850-test ARM corpus and repeated oracle-reset test on macOS. The helper is
portable Rust with identical Windows, macOS, and Linux configuration; native CI
results are tracked separately.

Medium-impact existing limitation: this generated corpus uses emulator-derived
expectations; the independent architectural checks remain in the direct-ISA and
differential suites. No assertion is skipped or relaxed by enabling the required
feature.

## Advanced SIMD, VFP, and floating point

The checked-in generated corpus and differential harnesses cover broad NEON/Advanced SIMD and scalar floating-point behavior, including FP16 and crypto families. The relevant state projection includes general registers, SP, NZCV, vector registers, and—where the harness supports it—predicate and control state.

“Bit-exact against QEMU” must always be read as:

- for the generated encodings that assembled;
- over the initial states produced by the harness;
- for the architectural state that the harness exports;
- on the reference version that ran;
- excluding memory/system interactions not represented by a register-only case.

## SVE, SVE2, and SVE2.1

The current high-level implementation inventory claims broad SVE, SVE2, and SVE2.1 register execution at vector length 128, including:

- predicate generation and predicate logical operations;
- predicated integer and floating-point arithmetic;
- comparisons and reductions;
- permutes and table-like data movement;
- shifts, widening, narrowing, long, saturating, and pairwise families;
- BF16-related operations;
- contiguous and gather/scatter memory forms represented in the software core;
- first-fault and FFR-related behavior;
- multi-register load/store families represented in the source.

The generated LLVM/ASL-derived sweep is the proper authority for finite encoding coverage. Register-only oracle sweeps cannot by themselves validate every multi-vector memory interaction, exception path, streaming mode, or SME surface. Documentation should preserve those exclusions whenever using “complete.”

## Modern A-profile extensions

Source and tests include work for newer architectural facilities such as:

- MTE-style tagging behavior;
- pointer authentication;
- FlagM-related operations;
- release-consistency atomic families;
- FP8 arithmetic work;
- newer crypto and matrix-adjacent instruction families represented in generated cases.

These facilities have different levels of machine integration. An instruction encoding being implemented does not imply a full system-level model of the surrounding security, memory-tagging, or privilege environment.

## AArch32 and Thumb

The 32-bit core includes A32 plus T16/T32 decode and execution, VFP/NEON surfaces, and hardware-exception routing. Generated differential cases compare selected 32-bit execution against `qemu-arm`. In user mode, `rax-user` runs static ARM EABI programs, built as A32 and as Thumb-2 code, against results recorded on Linux 6.19 for arm64 (`tests/fixtures/user/linux/`).

Machine-level status is more limited than instruction status:

- the `armv7a` DT path exists;
- selected Armv6 and SoC paths exist;
- Cortex-M platform work exists;
- no 32-bit target is documented as having reached an interactive Linux shell.

This is the central qualification for AArch32: the instruction core can be well tested while the Linux machine path remains unproven.

## Cortex-M and Cortex-R

Cortex-M support spans the public profiles from ARMv6-M through ARMv8.1-M and includes the platform control blocks expected by microcontroller execution, such as NVIC, SysTick, SCB, and MPU behavior where implemented. Cortex-R has separate profile selection and execution state.

Board support must be documented independently. A generic Cortex-M or Cortex-R profile does not create peripherals, firmware layout, flash, or board-specific reset state by itself.

## S3C64xx and S5L8900 work

The source includes selected Armv6 machine paths. The high-level project documentation identifies S3C64xx and Apple S5L8900 work. The S5L8900 path is selected through `RAX_MACHINE=s5l8900` and includes models for platform components such as interrupt controllers, GPIO/system control, timers, I²C-attached devices, UART, AES, NAND/ECC, DMA/data mover, SPI-attached display/touch devices, LCD, USB OTG, and NOR flash.

The named milestone is booting real firmware components into early iOS/XNU/IOKit bring-up. That is not the same as a supported iPhone emulator or a complete reproduction of the SoC.

## AArch64 image detection and boot

A Linux AArch64 `Image` can be recognized from its header. ELF inputs can be recognized from `e_machine`. The maintained bundled example is:

```sh
cargo build --release --no-default-features

./target/release/rax \
    --arch aarch64 \
    --backend emulator \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

The architecture can be omitted when detection succeeds, but explicit `--arch aarch64 --backend emulator` is better for reproducible documentation.

## Hardware-assisted AArch64

On Apple Silicon:

```sh
cargo build --release --no-default-features --features hvf
codesign -s - -f --entitlements rax.entitlements target/release/rax

./target/release/rax \
    --arch aarch64 \
    --backend hvf \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

The entitlement must be applied to the binary that is actually executed, after rebuilding. HVF does not provide the interpreter’s per-instruction trace, instruction-count profiler, or software snapshot semantics.

## Differential verification

Named Arm targets include:

| Target | Scope | Reference |
|---|---|---|
| `arm_diff` | AArch64 generated and handwritten differential cases | native EL0 on AArch64 hosts where available, otherwise `qemu-aarch64` |
| `arm_diff32` | AArch32 generated cases | `qemu-arm` |
| `arm` | direct Arm ISA suites reachable through the explicit test target | internal expected semantics and generated material |
| `arm_vfp_a32` | dedicated AArch32 VFP work | target-specific expected/reference path |
| `aarch64_smir_native` | AArch64 lift and native AArch64 lowerer | AArch64 interpreter/state comparison on an AArch64 host |

The native EL0 harness cannot exercise privileged system state as though it were an EL1 machine. QEMU user mode likewise validates user-visible instruction semantics rather than the complete Linux VM platform.

## SMIR status

AArch64 has lifters for scalar integer, control-flow, scalar floating-point, and a growing NEON surface. AArch64 native lowering is also a host backend for SMIR. Live paths currently include:

- x86 guest regions lowered to AArch64 under conservative admission;
- AArch64 guest regions executed natively on AArch64 hosts for the integrated surface;
- RISC-V state-backed regions lowered to AArch64;
- dedicated lift/lower tests for selected AArch64 scalar, FP, NEON, and memory cases.

An AArch64-to-x86 lowerer can exist as an emit-and-test path without being wired into a production run loop. Documentation must distinguish lowerer implementation from automatic runtime promotion.

## Known limitations and non-claims

- AArch32 Linux has not been demonstrated to an interactive shell.
- A profile selector does not imply every optional architectural extension is implemented.
- Register-only generated sweeps do not validate every memory, exception, privilege, or machine interaction.
- SME and other streaming/matrix facilities should not be inferred from SVE/SVE2 coverage.
- SoC milestones are image- and machine-specific, not general product support.
- HVF and the software interpreter have different observation, interruption, and checkpoint behavior.
- AArch64 JIT/live verification is not identical to the x86-64 host live-verify mode.
