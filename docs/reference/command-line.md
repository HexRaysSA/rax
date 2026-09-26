[← Documentation home](../../README.md)

# Command-line reference

This page describes the public options exposed by the current `rax` command-line parser. The executable’s `--help` output and `src/cli/mod.rs` remain authoritative when this page lags.

`rax-user` has a separate parser in `src/bin/rax_user.rs`. Its ELF-selected
ABI, sysroot, syscall logging, environment, scheduling-slice, and host-signal
options are documented in [Linux programs](../getting-started/linux-programs.md).
Machine `--arch`, `--backend`, GDB, and checkpoint options do not apply to it.

## Invocation model

```sh
rax [OPTIONS]
```

A normal launch constructs configuration from defaults, an optional TOML file, detected image metadata, and explicit command-line values. A whole-machine checkpoint launch first reads the checkpoint’s embedded configuration and then applies explicit CLI overrides.

In ordinary launches, the practical precedence is:

```text
explicit CLI value
    > TOML configuration value
    > image detection / host-aware selection
    > built-in default
```

Do not assume that every CLI option has a TOML equivalent. Debugging, tracing, profiling, and checkpoint-trigger controls are currently CLI-only.

## Configuration input

### `--config <FILE>`

Load a TOML configuration file.

```sh
./target/release/rax --config vm.toml
```

Explicit command-line values override values loaded from the file. See [TOML configuration reference](configuration.md).

### `--arch <ARCH>`

Select the guest architecture instead of relying on image detection or the x86-64 default.

Current command-line architecture families are:

```text
x86-64
hexagon
aarch64
armv7a
armv8a32
cortex-m
cortex-r
riscv64
```

Clap renders enum values in kebab-case on the CLI. TOML uses the snake-case spellings documented in [TOML configuration reference](configuration.md).

Architecture selection is not machine-independent. For example, `riscv64` currently selects the bare-metal RISC-V machine; it does not produce a privileged Linux-capable platform.

### `--backend <BACKEND>`

Select the execution backend:

```text
emulator
kvm
hvf
```

- `emulator` executes guest instructions through the software CPU and is the path for instruction-level tracing and software semantic work.
- `kvm` is the Linux hardware-virtualization backend. It is meaningful only on compatible hosts and guest paths.
- `hvf` selects Hypervisor.framework on supported macOS host/guest combinations and requires the `hvf` Cargo feature.

Compiling a backend and selecting its name does not guarantee host availability. Runtime initialization still depends on host architecture, operating system, permissions, entitlements, and guest combination.

### `--memory <SIZE>`

Set guest RAM. The parser accepts a byte count or a binary suffix such as `K`, `M`, `G`, `T`, `P`, or `E`, case-insensitively.

```sh
--memory 536870912
--memory 512M
--memory 2G
```

The default is 512 MiB. Configuration rejects memory smaller than 128 MiB.

### `--vcpus <COUNT>`

Set the configured vCPU count.

```sh
--vcpus 1
```

At least one vCPU is required. The current runtime executes only vCPU 0; values above one do not provide SMP guest execution and must not be documented as such.

## Guest image and boot input

### `--kernel <PATH>`

Select the guest image. Depending on architecture and machine this may be:

- an uncompressed Linux ELF `vmlinux`;
- a Linux bzImage for the appropriate x86 path;
- an AArch64 Linux `Image`;
- a bare-metal ELF;
- a bootable x86 ISO;
- a machine-specific firmware or flat-binary input where that path explicitly supports it.

A kernel/image is required for an ordinary launch. It is not required when `--checkpoint` restores a self-contained whole-machine snapshot.

```sh
--kernel linux/vmlinux
--kernel linux-aarch64/Image
--kernel program.elf
--kernel /path/to/bootable.iso
```

### `--initrd <PATH>`

Select an initial ramdisk:

```sh
--initrd initrd.cpio.gz
--initrd linux-aarch64/initramfs.cpio
```

The path is validated during ordinary configuration. Its format must match what the selected guest kernel expects.

### `--dtb <PATH>`

Provide a device tree blob for an Arm machine path that consumes an external DTB.

```sh
--dtb microkernel/dtb/s3c6410.dtb
```

The established AArch64 Linux virtual machine can generate its platform DTB. Do not add `--dtb` to that path unless intentionally overriding the generated description and the implementation supports the combination.

### `--cmdline <STRING>`

Override the guest kernel command line.

```sh
--cmdline 'console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr'
```

Built-in defaults are architecture-specific:

- x86-oriented default: `console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr tsc=reliable nohz=off clocksource=tsc`
- AArch64-oriented default: `console=ttyAMA0 earlycon=pl011,mmio32,0x09000000`

A helper script may use a more restrictive x86 command line for the known software-boot path.

## Hexagon controls

### `--hexagon-isa <VERSION>`

Select the exposed Hexagon ISA profile:

```text
v4, v5, v55, v60, v62, v65, v66, v67, v68, v69
```

The current default is `v68`.

This selector is a public configuration surface. A source file or README claim about later instructions does not automatically extend the accepted selector values.

### `--hexagon-endian <ENDIAN>`

Select:

```text
little
big
```

The default is little-endian.

### `--hexagon-entry <ADDRESS>`

Override the program entry address. Addresses accept conventional numeric notation, including hexadecimal forms such as:

```sh
--hexagon-entry 0x10000
```

Prefer ELF entry metadata unless the selected image and machine intentionally require an override.

### `--hexagon-load-addr <ADDRESS>`

Override the address at which a non-self-describing image is loaded:

```sh
--hexagon-load-addr 0x10000
```

Entry and load addresses are independent. Setting one does not necessarily set the other.

## Tracing and debugging

### `--trace <FILE>`

Write the instruction trace produced by the trace-enabled software path.

```sh
cargo build --release --features trace
./target/release/rax ... --backend emulator --trace boot.trace
```

The `trace` Cargo feature is required. The interpreter owns the instruction step loop; KVM/HVF do not become equivalent instruction-trace sources through this option.

### `--gdb <PORT>`

Start a GDB Remote Serial Protocol server:

```sh
cargo build --release --features debug
./target/release/rax ... --backend emulator --gdb 1234
```

The `debug` feature is required.

### `--wait-gdb`

Wait for a debugger connection before starting guest execution. This is normally paired with `--gdb`:

```sh
--gdb 1234 --wait-gdb
```

### `--gdb-trace`

Enable packet-level logging for the GDB RSP path. Internally, this augments the tracing filter for the debugger module. Use it only with `--gdb`; packet logs can be verbose and can contain guest addresses or data.

General logging is also controlled with `RUST_LOG`:

```sh
RUST_LOG=debug ./target/release/rax ...
RUST_LOG=rax::debug::gdb=trace ./target/release/rax ... --gdb 1234
```

## Snapshots and restore

### `--snapshot-interval <N>`

Request a checkpoint every `N` retired software instructions. `0` disables interval checkpoints.

```sh
--snapshot-interval 10000000
```

This facility belongs to the software execution/VM control path. Do not assume hardware virtualization exposes the same retirement count or trigger semantics.

### `--snapshot-at <N,N,...>`

Request checkpoints at exact instruction counts:

```sh
--snapshot-at 1000000,5000000,10000000
```

The values are a comma-separated list.

### `--snapshot-dir <DIR>`

Select the directory for interval and exact-count snapshots:

```sh
--snapshot-dir snapshots
```

The current default is the working directory.

### `--snapshot-out <FILE>`

Select the destination used by interactive or signal-triggered checkpoints:

```sh
--snapshot-out checkpoint.rxc
```

This is the target for `Ctrl-A s` and the supported signal-triggered save path.

### `--checkpoint <FILE>`

Restore a self-contained whole-machine `.rxc` checkpoint:

```sh
./target/release/rax --checkpoint machine.rxc
```

The checkpoint carries embedded machine configuration and state. A normal `--kernel` or `--config` is not required. Explicit CLI values are still overrides; an incompatible override can make a previously valid checkpoint unusable.

### `--resume <FILE>`

Use the legacy restore path:

```sh
./target/release/rax \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --resume legacy-state-file
```

Unlike `--checkpoint`, this path rebuilds a machine from ordinary configuration and then restores state into it. Do not use the names interchangeably.

## Optional platform devices

### `--pci-devices`

Attach the current aggregate set of optional PC PCI devices.

```sh
./target/release/rax ... --pci-devices
```

The switch currently covers the repository’s optional e1000, AHCI, NVMe, AC'97, and UHCI attachment path. It is not a per-device list and does not imply that every model in `src/devices/` is attached or guest-validated. See [Device architecture](../architecture/devices.md).

## Profiling

### `--profile`

Enable instruction profiling:

```sh
cargo build --release --features profiling
./target/release/rax ... --backend emulator --profile
```

The executable reports an error if profiling was not compiled.

### `--profile-output <FILE>`

Write machine-readable profile output, currently JSON:

```sh
--profile --profile-output profile.json
```

### `--profile-interval <N>`

Control periodic live profile reporting by instruction count:

```sh
--profile --profile-interval 10000000
```

Use `0` to disable periodic reporting while retaining end-of-run profiling, where supported by the implementation.

## Architecture detection and defaults

When `--arch` is omitted, the configuration layer examines known image metadata:

- AArch64 Linux `Image` magic;
- ELF `e_machine` values for x86-64, Arm/AArch64, Hexagon, and RISC-V.

Unknown images fall back to x86-64. A raw image or ISO may therefore need an explicit architecture even when the operator considers it obvious.

Host-aware default backend selection is subsequently constrained by guest architecture and compiled features. Non-x86 guests normally select the software backend unless a supported HVF path is explicitly requested.

## Complete examples

### Portable bundled AArch64 guest

```sh
./target/release/rax \
    --arch aarch64 \
    --backend emulator \
    --memory 512M \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

### Software x86 with trace and snapshots

```sh
./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --memory 1G \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --trace boot.trace \
    --snapshot-at 1000000,10000000 \
    --snapshot-dir snapshots \
    --snapshot-out manual.rxc
```

### Whole-machine restore with an intentional output override

```sh
./target/release/rax \
    --checkpoint manual.rxc \
    --snapshot-out resumed.rxc
```

### Hexagon bare-metal

```sh
./target/release/rax \
    --arch hexagon \
    --backend emulator \
    --kernel program.elf \
    --hexagon-isa v68 \
    --hexagon-endian little
```

## CLI-only versus TOML

The current TOML schema covers guest/machine construction fields. These notable options are CLI-only:

- trace output;
- GDB port, wait mode, and packet tracing;
- checkpoint trigger/output controls;
- whole-machine checkpoint and legacy resume input;
- profiling enablement and output controls.

Keep operational/debugging state outside persistent machine configuration unless the implementation schema is deliberately extended.

## Related pages

- Build the required feature: [Building](../getting-started/building.md)
- Persistent fields: [TOML configuration reference](configuration.md)
- Tools and snapshot semantics: [Observability and debugging](../operations/observability.md)
- Machine compatibility: [Status and limitations](status-and-limitations.md)
