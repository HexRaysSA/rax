[← Documentation home](../../README.md)

# TOML configuration reference

The `--config` option loads persistent machine-construction settings from TOML. The schema is intentionally narrower than the command-line interface: it defines guest architecture, execution backend, memory, image inputs, architecture profiles, load addresses, DTB input, and the aggregate optional-PCI switch. Debugging, tracing, profiling, and checkpoint-trigger settings are not TOML fields in the current model.

## Precedence

For an ordinary launch:

```text
CLI override > TOML value > image/host detection > built-in default
```

For `--checkpoint`, the checkpoint’s embedded configuration is the starting point, followed by explicit CLI overrides.

A configuration file does not prevent image detection from filling an omitted architecture. To eliminate ambiguity in reproducible scripts, specify both `arch` and `backend`.

## Minimal examples

### Software x86-64

```toml
arch = "x86_64"
backend = "emulator"
memory = "512M"
vcpus = 1
kernel = "linux/vmlinux"
initrd = "initrd.cpio.gz"
cmdline = "console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr tsc=reliable nohz=off clocksource=tsc"
```

```sh
./target/release/rax --config x86.toml
```

### Bundled AArch64 Linux

```toml
arch = "aarch64"
backend = "emulator"
memory = "512M"
kernel = "linux-aarch64/Image"
initrd = "linux-aarch64/initramfs.cpio"
cmdline = "console=ttyAMA0 earlycon=pl011,mmio32,0x09000000"
aarch64_isa = "v8_0"
```

### RISC-V bare-metal

```toml
arch = "riscv64"
backend = "emulator"
memory = "512M"
kernel = "program.elf"
```

### Hexagon bare-metal

```toml
arch = "hexagon"
backend = "emulator"
memory = "512M"
kernel = "program.elf"
hexagon_isa = "v68"
hexagon_endian = "little"
```

## Core fields

### `arch`

Guest architecture. TOML uses snake-case values:

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

The architecture chooses a CPU family and influences machine selection. It does not promise that every architecture has a Linux-capable board.

### `backend`

Execution backend:

```text
kvm
emulator
hvf
```

Host-aware defaults exist, but explicit configuration is preferable for reproducible use. Unsupported host/guest combinations fail validation or initialization rather than silently becoming equivalent to the requested backend.

### `memory`

Guest RAM as an integer byte count or suffixed string:

```toml
memory = "512M"
memory = "2G"
memory = 536870912
```

The built-in default is 512 MiB. Values below 128 MiB are rejected.

### `vcpus`

Configured virtual-CPU count:

```toml
vcpus = 1
```

The minimum is one. The runtime schedules online vCPUs. The machine and backend determine how secondary CPUs start and receive interrupts. See [VM SMP](status-and-limitations.md#vm-smp).

### `kernel`

Path to the primary guest image:

```toml
kernel = "linux/vmlinux"
```

The file is required and validated for an ordinary launch. Whole-machine checkpoint restore is the exception because RAM and machine state are loaded from the checkpoint.

### `initrd`

Optional initial ramdisk:

```toml
initrd = "initrd.cpio.gz"
```

### `cmdline`

Guest kernel command line:

```toml
cmdline = "console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr"
```

Architecture-specific built-in defaults are used when this field is absent.

### `pci_devices`

Attach the aggregate optional PCI set on the supported PC path:

```toml
pci_devices = true
```

This is equivalent to `--pci-devices`. It does not select individual endpoints.

## Hexagon fields

### `hexagon_isa`

Accepted profiles:

```text
v4
v5
v55
v60
v62
v65
v66
v67
v68
v69
```

Default:

```toml
hexagon_isa = "v68"
```

The public selector’s upper bound is an interface fact. If source contains semantics associated with a later manual revision, document that separately rather than inventing a configuration value.

### `hexagon_endian`

```text
little
big
```

Default: `little`.

### `hexagon_entry`

Optional explicit entry address:

```toml
hexagon_entry = 65536
hexagon_entry = "0x10000"
```

Use the representation accepted by the current address deserializer. Hexadecimal strings are the least ambiguous for documentation.

### `hexagon_load_addr`

Optional explicit load address:

```toml
hexagon_load_addr = "0x10000"
```

Do not override ELF metadata without a machine-specific reason.

## Arm ISA selectors

These fields configure architectural profiles used by their corresponding software cores. A profile name is not a blanket statement that every optional extension associated with that architecture revision is implemented.

### `aarch64_isa`

Accepted values:

```text
v8_0
v8_1
v8_2
v8_3
v8_4
v8_5
v8_6
v8_7
v8_8
v9_0
v9_1
v9_2
v9_3
v9_4
```

Default: `v8_0`.

### `aarch32_isa`

Accepted values:

```text
v6
v6_t2
v6_k
v7_a
v7_a_virt
v7_a_lpae
v8_a32
```

Default: `v7_a`.

On the software S3C64xx and S5L8900 machines, `v6` and `v6_k` select
ARM1176-style D16 VFPv2 capabilities and A32 FP instruction rules.
`v6_t2` selects D16 VFPv2 with A32 and T32 FP instruction rules.
Guest initialization enables CP10 and CP11 in CPACR before using VFP
system registers, then sets `FPEXC.EN` to enable FP data instructions.
The default `v7_a` selects the D32 software FP profile without EL2.
`v7_a_virt`, `v7_a_lpae` and `v8_a32` include the EL2 FP control
registers. The VFPv2 settings use RAX's synchronous floating-point
exception interface.
[AArch32 FP profile details](../development/a32-fp-controls.md#arm1176-style-vfpv2-selection)
[EL2 FP controls](../development/a32-fp-controls.md#configured-armv7-a-el2-and-platform-hstr)

### `cortexm_isa`

Accepted values:

```text
v6_m
v7_m
v7_em
v8_m_baseline
v8_m_mainline
v8_1_m
```

Default: `v7_m`.

### `cortexr_isa`

Accepted values:

```text
v7_r
v8_r
v8_r64
```

Default: `v7_r`.

## Arm load and platform fields

### `arm_entry`

Optional Arm entry address:

```toml
arm_entry = "0x80000"
```

### `arm_load_addr`

Optional Arm load address:

```toml
arm_load_addr = "0x80000"
```

### `arm_dtb`

Path to a device tree blob used by the selected Arm machine path:

```toml
arm_dtb = "microkernel/dtb/s3c6410.dtb"
```

This is the TOML equivalent of the CLI `--dtb` input. The AArch64 virtual machine’s generated DTB path should not be confused with an arbitrary external DTB.

## Full schema table

| Field | Type | Built-in behavior | CLI equivalent |
|---|---|---|---|
| `arch` | architecture enum | detected from known image metadata, otherwise x86-64 | `--arch` |
| `backend` | backend enum | host-aware, then constrained by guest architecture | `--backend` |
| `memory` | size | 512 MiB; minimum 128 MiB | `--memory` |
| `vcpus` | integer | 1 | `--vcpus` |
| `kernel` | path | required for ordinary launch | `--kernel` |
| `initrd` | path | optional | `--initrd` |
| `cmdline` | string | architecture-specific default | `--cmdline` |
| `hexagon_isa` | enum | V68 | `--hexagon-isa` |
| `hexagon_endian` | enum | little | `--hexagon-endian` |
| `hexagon_entry` | address | image/machine-derived | `--hexagon-entry` |
| `hexagon_load_addr` | address | image/machine-derived | `--hexagon-load-addr` |
| `aarch64_isa` | enum | V8.0 | no direct CLI selector |
| `aarch32_isa` | enum | V7-A | no direct CLI selector |
| `cortexm_isa` | enum | V7-M | no direct CLI selector |
| `cortexr_isa` | enum | V7-R | no direct CLI selector |
| `arm_entry` | address | image/machine-derived | no dedicated CLI option |
| `arm_load_addr` | address | image/machine-derived | no dedicated CLI option |
| `arm_dtb` | path | machine-generated or absent, depending on path | `--dtb` |
| `pci_devices` | boolean | false | `--pci-devices` |

## Validation behavior

Before an ordinary machine starts, configuration validates at least:

- vCPU count is nonzero;
- memory meets the minimum;
- required kernel input exists;
- optional initrd exists when supplied;
- selected backend and guest architecture are not an explicitly unsupported combination;
- architecture-specific values parse and belong to the exposed enum.

The source currently constrains important combinations:

- Hexagon uses the software emulator;
- 32-bit Arm profiles use the software emulator;
- AArch64 KVM is not the current backend path;
- HVF depends on macOS host architecture and compiled feature support.

When a configuration fails, do not “fix” it by silently substituting another backend in documentation. State the supported combination.

## Values not stored in TOML

The following operational controls are absent from the current file schema:

- trace output path;
- GDB port, wait mode, and packet tracing;
- snapshot interval, exact counts, directories, and output path;
- whole-machine checkpoint input;
- legacy resume input;
- profiler enablement, output path, and reporting interval.

Apply them on the command line:

```sh
./target/release/rax \
    --config x86.toml \
    --trace boot.trace \
    --gdb 1234 \
    --wait-gdb \
    --snapshot-out checkpoint.rxc \
    --profile \
    --profile-output profile.json
```

The corresponding Cargo features must still be compiled.

## Reproducible configuration practices

- Use repository-relative paths only when the working directory is controlled.
- Pin `arch` and `backend` rather than relying on host-aware defaults in automation.
- Record the exact guest image hash; a filename is not provenance.
- Keep architecture profile and machine model coherent.
- Do not set `vcpus > 1` to imply SMP.
- Treat checkpoint-embedded configuration as revision-sensitive state.
- Keep debugging and measurement switches in the invocation or test harness so persistent machine configuration remains reusable.

## Related pages

- Public flags: [Command-line reference](command-line.md)
- Supported combinations: [Status and limitations](status-and-limitations.md)
- Machine interpretation of fields: [Machines and boot](../architecture/machines.md)
- Build feature requirements: [Building](../getting-started/building.md)
