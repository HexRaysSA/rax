[← Documentation home](../../../README.md)

# RISC-V architecture

The `rax --arch riscv64` machine path connects an RV64 software CPU to a small bare-metal machine. It loads an ELF, exposes a 16550-compatible UART over MMIO, and provides a halt path around the current environment-call convention. It is not a privileged RISC-V virtual machine and does not boot Linux.

The separate `rax-user` path runs RV64 Linux ELF programs in U-mode without
a kernel or board. It implements the Linux personality's processes, threads,
signals, files, networking, IPC, and tracing; `--riscv-jit` selects eligible
SMIR regions. This process path does not add privileged paging or Linux boot
to the machine. See [Linux programs](../../getting-started/linux-programs.md)
and [User-mode emulation](../user-mode.md) for syscall and tracing limits.

## Launching a bare-metal program

```sh
cargo build --release --no-default-features

./target/release/rax \
    --arch riscv64 \
    --backend emulator \
    --kernel program.elf
```

The ordinary ELF loader should define segment placement and entry state. Use a workload built for the machine’s memory map and UART rather than a generic Linux userspace binary.

## Scalar ISA surface

The current high-level inventory describes an RV64GC/RVA23-oriented scalar core with:

- RV64I integer and control-flow instructions;
- M multiply/divide;
- A atomics, including newer compare-and-swap work represented in source/tests;
- F and D floating point;
- Zfh half precision;
- compressed instructions;
- Zicsr and Zifencei;
- Zba, Zbb, Zbc, and Zbs bit-manipulation groups;
- Zicond;
- Zfa;
- Zbkb, Zbkx, and Zcb;
- scalar cryptography including SHA, SM3, SM4, and AES families represented by the implementation;
- selected newer compressed/macro and table-jump work represented in the JIT path.

The finite authority is the decoder/source inventory and differential corpus, not the umbrella name “RVA23.” The public project should avoid claiming a profile certification unless every mandatory profile item, privilege assumption, and behavioral obligation has been audited.

## Floating-point behavior

The implementation uses explicit residual/error analysis for rounding-sensitive operations and carries IEEE exception state through the architectural FCSR representation. Differential fuzzing compares the exported register and control state with QEMU.

Correct-rounding language should remain scoped to:

- the operations implemented by the relevant helper;
- the five rounding modes represented in the test inputs;
- the flags exported and compared by the harness;
- the finite randomized and edge-case corpus that ran.

It is stronger than merely using host floating point, but it is not an unrestricted formal proof of every floating-point sequence.

## RVV 1.0

The vector state includes V0–V31, `vl`, `vtype`, vector control/status state, scalar integer/floating registers used by vector instructions, and the configured VLEN. The current high-level inventory describes VLEN=128 and broad RVV 1.0 coverage:

- integer arithmetic and logical operations;
- fixed-point and saturating behavior;
- floating-point vector operations;
- mask operations;
- reductions;
- permutations and slides;
- widening/narrowing and conversions;
- vector configuration;
- unit-stride, strided, indexed, segmented, fault-sensitive, and masked load/store forms represented in the interpreter.

The dedicated differential suite compares the full serialized vector register file and vector configuration for each executed case. Memory exceptions, page crossing, and machine-level privilege interactions remain separate obligations.

## Bare-metal machine

The runnable machine provides enough platform state to execute purpose-built programs:

- ELF segment loading;
- RAM at the machine-defined address range;
- 16550-compatible serial output/input path;
- an environment-call or machine-specific halt convention;
- single-vCPU execution.

It does not currently provide:

- a complete privileged architecture;
- Sv39 page translation;
- supervisor-mode Linux boot;
- a full `virt` board with production-equivalent interrupt, timer, PCI, and firmware environment.

The Cargo target `riscv_boot` is the end-to-end machine regression for the implemented bare-metal contract.

## Differential verification

| Cargo target | Scope | Reference |
|---|---|---|
| `riscv_diff` | scalar instruction differential corpus | `qemu-riscv64` user mode |
| `riscv_vector` | RVV register/configuration and relevant memory cases | `qemu-riscv64` user mode |
| `riscv_smir_lift` | RISC-V decode/semantics versus lifted SMIR interpretation | internal RISC-V interpreter already covered by differential tests |
| `riscv_smir_x86_jit` | state-backed RISC-V regions lowered for x86-64 host | RISC-V interpreter |
| `riscv_smir_aarch64_jit` | state-backed RISC-V regions lowered for AArch64 host | RISC-V interpreter |
| `riscv_boot` | bare-metal machine launch and UART/halt integration | expected machine behavior |

User-mode QEMU is appropriate for user-visible instruction semantics. It does not validate a privileged machine that `rax` does not claim to implement.

## SMIR and native execution

The RISC-V lifter covers scalar, floating-point, vector, bit-manipulation/crypto, and CSR-related operations represented in the user-mode core. The state-backed JIT path groups cache-keyed straight-line regions, with a documented upper bound of 16 instructions in the current design.

Region construction stops at boundaries where replay or state commit becomes difficult, including control flow, fences, selected memory operations, and helper-sensitive behavior. Supported scalar, atomic, crypto, floating, and memory-free vector operations can execute natively on x86-64 or AArch64 hosts. Unsupported RVV memory or other boundary operations stay in the interpreter.

A faulting final operation must not commit effects from an instruction that did not retire. Region cache identity includes the instruction encodings used to construct the region so changed code cannot incorrectly reuse old native code.

## Known limitations and non-claims

- The current public machine is bare-metal only.
- There is no privileged/Sv39 environment capable of Linux boot.
- “RVV 1.0 coverage” refers to implemented and tested instruction behavior, not every OS/privilege/memory-system interaction.
- QEMU user mode is the external behavioral reference; it is not a formal ISA proof.
- State-backed native execution is selective. A JIT-enabled build does not mean every RISC-V instruction executes natively.
- Single-vCPU execution means no SMP or multi-hart memory-ordering validation.
- Profile names should not be treated as certification labels without a generated mandatory-extension audit.
