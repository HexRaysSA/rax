[← Documentation home](../../README.md)

# Architecture overview

`rax` separates four questions that are easy to conflate in emulator documentation:

1. **Which guest ISA is being decoded?**
2. **Which machine supplies the guest address map, boot protocol, and devices?**
3. **Which execution mechanism runs the guest?**
4. **Which observation and validation surfaces are active?**

A command is only fully described when all four are known. `--arch x86-64 --backend emulator`, for example, chooses an x86-64 software CPU, but the image format still determines whether the machine follows direct Linux loading or the legacy bootable-ISO path. Enabling the `trace` Cargo feature adds a trace implementation, but it does not make KVM execute one observable instruction at a time.

## Runtime layers

```text
CLI / TOML / checkpoint
          │
          ▼
validated runtime configuration
          │
          ├── machine selection ──► boot protocol, address map, devices
          │
          └── backend selection ──► KVM / HVF / software vCPU
                                      │
                                      ├── guest ISA decoder and semantics
                                      └── SMIR lift / interpret / optimize / lower
```

The source tree reflects those boundaries:

| Directory | Owns |
|---|---|
| `src/isa/` | Guest instruction decoding, architectural state, and instruction semantics |
| `src/machine/` | Machine selection, image loading, address maps, boot state, and device wiring |
| `src/backend/` | Execution mechanisms and `VCpu` adapters |
| `src/devices/` | Device models and I/O buses |
| `src/vm/` | Architecture-neutral runtime, memory, checkpoints, and vCPU contracts |
| `src/smir/` | Cross-ISA IR, lifting, interpretation, optimization, and native lowering |
| `src/oracle/` | Static decode/lift oracle material |
| `src/user/` | Process-level address spaces, CPU adapters, and the Linux personality |
| `src/debug/` | Interactive debugger protocols |
| `src/observability/` | Tracing and profiling |
| `src/host/` | Terminal and console integration |

The bounded `machine ↔ backend` coupling is intentional: machine construction can expose backend hooks, while platform-specific backend adapters consume machine constants. ISA semantics and device models remain owned by their respective directories.

## Guest architecture selectors

The public configuration model currently exposes:

```text
x86_64
hexagon
aarch64
armv7a
armv8a32
cortex_m
cortex_r
riscv64
```

Image detection can infer x86-64, AArch64, RISC-V, Hexagon, or 32-bit Arm from recognized ELF machine identifiers, and can recognize a Linux AArch64 `Image` through its header magic. Reproducible scripts should still set `arch` and `backend` explicitly.

Architecture names describe a CPU family. They do not imply that every family has a Linux-capable machine:

| Architecture family | Software execution | Hardware-assisted execution | Established machine-level use |
|---|---:|---:|---|
| x86-64 | yes | KVM on supported Linux hosts; HVF where implemented | direct Linux boot, PC devices, real-mode and ISO boot |
| AArch64 | yes | HVF on Apple Silicon | generated-DTB Linux virtual machine |
| AArch32 / Thumb | yes | no general hardware backend documented | Armv7 DT path and selected SoC/Cortex profiles; no demonstrated Linux shell |
| Cortex-M / Cortex-R | yes | no | microcontroller/profile-specific execution and platform work |
| Hexagon | yes | no | bare-metal ELF |
| RV64 | yes | no | bare-metal ELF with UART and halt path |

## Execution backends

The backend selectors below belong to the `rax` machine application. The
separate `rax-user` process application detects its Linux ABI from the ELF
header and uses the software CPU adapters without machine or device construction.

### Software emulator

The software backend owns the architectural step loop. It can expose per-instruction tracing, GDB stepping, instruction-count snapshots, profiling, software MMUs, and SMIR hot-region promotion. Its behavior is inspectable because decode and execute occur in-process.

### KVM

KVM executes supported x86-64 guest code on the host CPU and exits primarily for I/O, faults, and configured virtualization events. It is used both as a fast machine backend and as a hardware reference in selected differential tests. KVM execution is not equivalent to interpreter-level observability: enabling a trace or profiler feature does not make every hardware-retired guest instruction pass through the software step loop.

### Hypervisor.framework

The HVF feature provides the macOS hardware-virtualization backend. On Apple Silicon, the established path runs AArch64 guests and requires the binary to carry the Hypervisor entitlement. Hardware-assisted execution shares machine construction and device wiring with the corresponding platform path where the implementation supports it, but it has different observation and interruption behavior from the interpreter.

## Machine and ISA are separate

The ISA answers questions such as:

- how an instruction is decoded;
- which registers and flags it reads and writes;
- which exception it raises;
- how memory operands are formed;
- how vector and floating-point state is represented.

The machine answers different questions:

- where RAM begins;
- where a kernel or ELF is loaded;
- which boot state is synthesized;
- which UART, interrupt controller, timer, PCI bridge, or firmware interface exists;
- how guest shutdown and host console input are delivered.

This distinction matters for status claims. “The AArch32 decoder implements an instruction” is not the same claim as “an AArch32 Linux machine boots.” “An e1000 model exists” is not the same claim as “the selected machine wires it and a guest driver has exercised it.”

## State and retirement

The architecture-specific vCPU owns registers, flags or condition state, the instruction pointer, architectural control state, and pending exceptions. The VM runtime supplies guest memory and devices. An instruction is considered retired only after its architecturally visible effects have committed according to the relevant execution path.

For packetized Hexagon execution, retirement occurs at packet scope rather than after each individual instruction encoding. For JIT regions, native execution must preserve the same externally visible state transition as the interpreter for the admitted region. Faulting and replay-sensitive boundaries therefore restrict region construction.

## Process execution without a machine

`rax-user` connects `user::linux` to `user::{image,mm,cpu}` and the ISA cores.
It loads Linux ELF programs for x86-64, AArch64, and RV64, and ELF32 i386
programs through a partial compatibility ABI. It supplies guest VMAs, syscall
dispatch, signals, threads, files, sockets, IPC, and guest `ptrace`; it does
not require a kernel image, firmware, interrupt controller, or board.

Guest threads run cooperatively on one emulated CPU in each process. A guest
`fork` creates a host process; `execve` replaces its guest image. Thus RV64
Linux process execution coexists with an RV64 machine path that remains
bare-metal. See [User-mode emulation](user-mode.md) for ABI and host boundaries.

## One executing vCPU

The machine configuration accepts `vcpus`, but the current VM runtime executes vCPU 0 only. A value greater than one is not evidence of SMP. The process scheduler described above implements guest threads; it does not add SMP to the VM runtime.

## Documentation vocabulary

The architecture pages use the following terms deliberately:

- **Implemented:** source contains a reachable decode/execute or machine path.
- **Exposed:** a public CLI, TOML, C API, or runtime selector can request it.
- **Tested:** a named test exercises the claim under stated prerequisites.
- **Differentially compared:** a named harness compared a stated projection of state with a stated reference.
- **Booted:** a named image reached a stated milestone on a stated backend.
- **Complete:** only used when an executable inventory or exhaustive generator defines the relevant finite set and the document names the exclusions.

See [Verification model](../development/verification.md) for the evidence rules and [Status and limitations](../reference/status-and-limitations.md) for the consolidated support matrix.
