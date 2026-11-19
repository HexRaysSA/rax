[← Documentation home](../../README.md)

# Machines and boot

A CPU core can execute instructions without being a useful virtual machine. A machine supplies the reset state, image loader, physical address map, interrupt routing, timers, consoles, storage/network controllers, firmware interfaces, and shutdown behavior that turn a CPU into a runnable system.

## Selection flow

Ordinary launch configuration is resolved from:

```text
explicit CLI → TOML → image detection / host default → built-in default
```

Whole-machine checkpoint restore starts from the configuration embedded in the checkpoint and then applies the explicitly permitted CLI overrides.

The public architecture selector chooses a CPU family; the image type and architecture-specific configuration choose the machine path. Reproducible commands should provide `--arch` and `--backend` even when image detection works.

## x86-64 direct Linux machine

The direct Linux path bypasses legacy firmware and constructs the machine state expected by the 64-bit kernel entry path. The documented layout includes:

- kernel loaded near physical `0x01000000`;
- initrd placed below the top of RAM, with the Linux image limit honored where available;
- initial page tables covering early identity access and the expected high-half/direct-map regions;
- a minimal GDT;
- paging, PAE, and long-mode enable state;
- serial-console oriented kernel command line;
- legacy PC interrupt/timer/console devices;
- optional PCI controllers when requested.

The software path expects an uncompressed ELF `vmlinux` for the maintained workflow. `make linux` builds the configured Linux release, and `make run-linux` starts it through `run.sh` with the repository’s tested command line.

The KVM path can use the hardware backend and relevant Linux image form. Its machine/device behavior shares the VM platform where wired, but guest execution happens in hardware until an exit.

## x86 legacy firmware and ISO path

The legacy path starts in 16-bit real mode and supplies a small BIOS-like service surface rather than direct long-mode kernel state. The implementation includes selected interrupt services, an El Torito parser, and an ATAPI CD path. A boot image is placed at `0x7c00`, after which the guest is responsible for its own mode transitions.

TempleOS V5.03 is the named end-to-end workload. The milestone demonstrates:

- El Torito boot-image selection;
- real-mode entry;
- transition through protected and long mode;
- the guest’s CD/filesystem use;
- execution of its 64-bit environment.

It does not imply broad BIOS compatibility with arbitrary operating systems, VGA firmware, option ROMs, or all optical-media modes.

## AArch64 virtual machine

The AArch64 Linux path generates a DTB containing the implemented platform rather than requiring a checked-in board DTB. The documented platform includes:

- RAM;
- GICv3 distributor/redistributor and CPU interface;
- PL011 UART;
- Arm generic timer;
- PSCI;
- Linux `Image` entry state.

On the software backend, EL0/EL1, stage-1 translation, exception routing, interrupt controller, timer, and UART execute in the emulator. On Apple Silicon, Hypervisor.framework runs eligible guest execution with the machine’s platform interfaces integrated through the HVF path.

Both paths must agree on the guest-visible DTB and machine contract, but their observation and timing behavior are different.

## 32-bit Arm paths

The repository includes an Armv7 DT-oriented path and selected Armv6/SoC/Cortex machine work. External DTB input is available through `--dtb` or the TOML `arm_dtb` field for the paths that consume it.

Important boundary: the AArch32/Thumb instruction core and selected machine models exist, but no 32-bit Linux target is documented as reaching an interactive shell. A successful generated AArch32 differential suite is not machine-boot evidence.

## S5L8900 machine selection

The Apple S5L8900 research machine is selected with:

```sh
RAX_MACHINE=s5l8900 ./target/release/rax ...
```

It models a collection of SoC-specific devices and firmware storage sufficient for named early-boot experiments. It is not selected by the general `--arch` value alone, and it should not be described as a complete iPhone emulator.

## RISC-V bare-metal machine

The software RISC-V machine loads a bare-metal RV64 ELF and provides RAM,
a 16550-compatible MMIO UART, CLINT and PLIC. By default it uses the guest
`ECALL` convention for host shutdown and reports `EBREAK` as a debugger exit.
Select `RAX_MACHINE=riscv-virt` to run firmware with architectural synchronous
trap delivery. Firmware can shut down the VM by storing 1 at its ELF `tohost`
symbol.
The machine supports bare-metal firmware within its implemented privileged
and device profiles. [Platform and checkpoint details](../development/riscv-clint/README.md#synchronous-traps-in-the-virt-firmware-profile)

## Hexagon bare-metal machine

The Hexagon machine loads a Hexagon ELF and initializes the scalar/packet/HVX state needed by the program. Entry and load-address overrides exist for intentionally relocated/raw cases. It provides a UART/halt-oriented bare-metal environment, not a general-purpose Qualcomm SoC.

## Image detection

Recognized inputs include:

- ELF machine values for x86-64, AArch64, RISC-V, Hexagon, and 32-bit Arm;
- AArch64 Linux `Image` header magic;
- x86 Linux image forms handled by the selected boot path;
- x86 bootable ISO for the legacy path.

Detection is convenience, not a substitute for machine compatibility. An ELF machine field can select the CPU family while still containing a program linked for a different memory map or runtime environment.

## Memory configuration

Guest memory accepts integer bytes or suffixed values such as `512M` and `2G`. The built-in default is 512 MiB, and values below 128 MiB are rejected by the current runtime validation.

Memory size affects:

- RAM address ranges;
- initrd placement;
- generated DTB memory nodes;
- checkpoint size;
- guest workload viability;
- some direct-map assumptions.

It does not add devices or vCPUs.

## Kernel command lines

Built-in defaults are architecture-specific. The x86 default is serial oriented and disables several timing/mitigation features that complicate the controlled software-boot path. The AArch64 default selects PL011 and earlycon at the implemented UART address.

`run.sh` provides its own maintained x86 command line. If a custom kernel stalls, first reproduce with the helper’s default before removing or adding options.

## Checkpoint restore and machine construction

A whole-machine `.rxc` checkpoint contains the machine configuration, CPU state, compressed RAM, device state, and timing anchor required to reconstruct the saved VM. `--checkpoint` therefore does not require `--kernel` or `--config`.

Legacy `--resume` has a different contract: it restores into a machine reconstructed from current kernel/configuration inputs. Do not treat the two mechanisms as interchangeable.

See [Checkpoints](../operations/checkpoints.md).

## Support language

For machine-level status, document the exact milestone:

- “loads the ELF and writes to UART”;
- “reaches Linux early console”;
- “mounts initramfs and reaches BusyBox shell”;
- “enumerates e1000 and creates `eth0`”;
- “boots TempleOS V5.03 to its shell.”

Avoid the unqualified word “boots” when the stopping point matters.
