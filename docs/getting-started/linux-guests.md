[← Documentation home](../../README.md)

# Linux guests

This page describes the Linux-capable machine paths in `rax`, the image format expected by each path, and the minimum evidence needed before describing a boot as supported. It deliberately separates the guest architecture, machine, and execution backend: a kernel accepted by KVM is not automatically accepted by the software x86 machine, and an AArch64 `Image` is not interchangeable with an x86 bzImage or ELF `vmlinux`.

## Fastest clean-checkout path: bundled AArch64

The repository contains an AArch64 kernel and initramfs at:

```text
linux-aarch64/Image
linux-aarch64/initramfs.cpio
```

Build the software-only binary and boot them directly:

```sh
cargo build --release --no-default-features

./target/release/rax \
    --arch aarch64 \
    --backend emulator \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

The explicit `--arch` is not strictly required when the Linux `Image` magic is detected, but keeping it in scripts makes the selected guest family obvious. The software backend avoids KVM, Hypervisor.framework, executable JIT memory, and host virtualization permissions.

The AArch64 virtual machine constructs the platform description used by the guest. Its established platform includes guest RAM, a PL011-compatible serial console, GICv3 interrupt-controller state, the generic timer path, and PSCI-facing boot coordination. The console command line normally uses:

```text
console=ttyAMA0 earlycon=pl011,mmio32,0x09000000
```

A successful boot should be described by the milestone actually observed—for example, “reached an initramfs shell”—rather than simply “boots Linux.” Record the exact kernel and initramfs artifacts when the result matters.

## AArch64 through Hypervisor.framework

On Apple Silicon, build the `hvf` feature and sign the resulting executable with the repository entitlement:

```sh
cargo build --release --features hvf
codesign -s - -f --entitlements rax.entitlements target/release/rax

./target/release/rax \
    --arch aarch64 \
    --backend hvf \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

Re-run `codesign` after every rebuild because signing applies to a particular binary. Feature compilation, entitlement signing, and runtime availability are separate conditions; an `hvf` build does not prove that a given host/guest combination initialized successfully.

The hardware-assisted path is useful for running the guest with substantially less CPU-emulation overhead. It is not the path for instruction-by-instruction interpreter tracing. Trace, per-instruction hooks, software instruction counts, and some checkpoint trigger semantics belong to the software execution loop.

## x86-64 software Linux path

The maintained helper path builds an uncompressed ELF kernel and launches it with the repository initramfs:

```sh
make linux
make run-linux
```

`make linux` obtains the configured Linux source release and builds:

```text
linux/vmlinux
```

The helper script uses:

```text
initrd.cpio.gz
```

and a command line chosen for the current software machine. `run.sh` accepts these overrides:

```sh
RAX_KERNEL=/path/to/vmlinux \
RAX_INITRD=/path/to/initrd.cpio.gz \
RAX_ARCH=x86-64 \
RAX_BACKEND=emulator \
RAX_MEMORY=512M \
RAX_CMDLINE='console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr ...' \
./run.sh
```

The established software path uses an ELF `vmlinux`, not a generic claim that every x86 Linux boot format is equivalent. The software machine initializes the x86 platform, loads the kernel and initramfs, constructs the boot parameters, and enters the interpreter. The known command line disables or constrains facilities that have historically exposed gaps in the software CPU or platform model.

A direct invocation equivalent to the helper is:

```sh
cargo build --release --no-default-features

./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --memory 512M \
    --cmdline 'console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr tsc=reliable nohz=off clocksource=tsc'
```

The helper script is preferable while debugging because it preserves the repository’s current baseline. Change one variable at a time after that baseline works.

## x86-64 through KVM

The KVM path is intended for a Linux x86-64 host with hardware virtualization enabled and a usable `/dev/kvm`:

```sh
cargo build --release

./target/release/rax \
    --arch x86-64 \
    --backend kvm \
    --kernel /path/to/bzImage \
    --initrd /path/to/initrd.img \
    --memory 512M
```

The root package’s default features include `kvm` and `smir-jit`. KVM still requires:

- a Linux host;
- a compatible host CPU and enabled virtualization;
- permission to open `/dev/kvm`;
- a kernel image accepted by the KVM machine path;
- a guest configuration compatible with the available platform devices.

KVM is the high-throughput x86 path. It exits to userspace for defined events rather than retiring every guest instruction through the software interpreter. Consequently, enabling the KVM backend does not provide the same instruction trace, hook, software profiling, or JIT behavior as `--backend emulator`.

## Image-format distinctions

Use the image expected by the selected machine:

| Path | Normal image | Notes |
|---|---|---|
| AArch64 virtual machine | Linux `Image` | Architecture may be detected from the image magic; platform DT data can be generated by the machine. |
| x86 software Linux | uncompressed ELF `vmlinux` | Current documented software baseline. Prefer `make linux` and `make run-linux`. |
| x86 KVM | Linux bzImage | Hardware-backed boot path; may also consume an initrd. |
| x86 legacy firmware/ISO | bootable ISO | Uses the real-mode mini-BIOS and El Torito/ATAPI path, not direct Linux loading. |
| AArch32/SoC paths | machine-specific image plus, where required, DTB/load information | No general AArch32 Linux-to-shell claim is currently made. |

Do not infer image support from filename extensions alone. ELF machine metadata, Linux `Image` magic, command-line architecture selection, and the chosen machine all participate in configuration.

## Memory and vCPU configuration

The normal memory default is 512 MiB; configuration rejects values below 128 MiB. Examples:

```sh
--memory 512M
--memory 2G
```

`--vcpus` configures the machine CPU count. The examples here use one vCPU. For evidence on secondary startup and execution by machine and backend, see [VM SMP](../reference/status-and-limitations.md#vm-smp).

## Serial console and host controls

The Linux paths are serial-console oriented. On an interactive terminal, the host console uses a `Ctrl-A` multiplexer. Important controls include:

```text
Ctrl-A h    show console help
Ctrl-A x    stop the virtual machine
Ctrl-A s    write a whole-machine checkpoint
```

The exact guest console device differs by machine:

- x86 uses the serial path selected by `console=ttyS0`;
- AArch64 uses the PL011 path selected by `console=ttyAMA0`.

VGA source presence does not imply a wired graphical console. Treat the current PC machine as serial-first.

## Adding tracing, GDB, profiling, or checkpoints

Build the feature before using its CLI surface:

```sh
cargo build --release --features trace,debug,profiling
```

Example software x86 invocation:

```sh
./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --trace boot.trace \
    --gdb 1234 \
    --wait-gdb \
    --profile \
    --profile-output profile.json \
    --snapshot-out checkpoint.rxc
```

Do not add all tools while establishing the first boot. First reach a stable serial milestone, then add one observability surface at a time. See [Observability and debugging](../operations/observability.md) and [Checkpoints and restore](../operations/checkpoints.md).

## Boot evidence checklist

For a reproducible Linux result, record:

```text
rax commit:
host OS and architecture:
host CPU / virtualization availability:
Cargo command and features:
backend:
guest architecture:
kernel path and SHA-256:
initrd path and SHA-256:
memory:
command line:
optional devices:
first observed milestone:
last observed milestone:
exit, panic, or timeout:
trace/checkpoint/profile artifacts:
```

A screenshot or log ending at early decompression is not evidence of reaching userspace. A shell prompt is not evidence that every device or ISA extension is correct. Describe only the milestone observed.

## Known boundaries

- The software x86 Linux path is intentionally narrower than KVM boot.
- The boot examples qualify the listed guest images and configurations. [VM SMP](../reference/status-and-limitations.md#vm-smp) records the multivCPU test scope.
- AArch64 Linux is the established Arm Linux path; AArch32 Linux has not been demonstrated to an interactive shell.
- Hardware backends do not expose the interpreter’s per-instruction observability.
- Optional PCI devices are off by default and do not imply complete guest-driver validation.
- A successful boot is an integration result for one image/configuration, not an exhaustive ISA-conformance result.

## Related pages

- [Getting started](overview.md)
- [Building](building.md)
- [Bare-metal and ISO guests](bare-metal-and-iso.md)
- [Machines and boot](../architecture/machines.md)
- [Command-line reference](../reference/command-line.md)
- [Troubleshooting](../troubleshooting.md)
