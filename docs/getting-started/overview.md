[← Documentation home](../../README.md)

# Getting started

This page begins with a path that uses only files in the repository and the portable software backend. Optional hypervisors, external guest images, cross-compilers, QEMU binaries, LLVM tools, and observability features are introduced only after that baseline works.

## What you need

For an ordinary command-line build:

- Git;
- Cargo and a Rust toolchain capable of compiling a Rust 2024 crate;
- a supported 64-bit host for the runtime path you intend to use;
- enough memory and disk space for a release build.

Additional tasks add their own requirements:

| Task | Additional requirement |
|---|---|
| KVM execution or x86 KVM differential tests | Linux/x86-64, host virtualization, and usable `/dev/kvm` |
| HVF execution | macOS, matching host/guest architecture, `hvf` feature, and code signing with `rax.entitlements` |
| Arm/Hexagon/RISC-V QEMU differential tests | the exact QEMU user-mode binary and the test’s compiler/assembler |
| APX encoding checks | a sufficiently new LLVM toolchain; the QEMU execution path remains dependent on QEMU support |
| Microkernel | nightly Rust, `rust-src`, and `llvm-objcopy` or `objcopy` |
| Tracing, GDB, profiling | the matching Cargo feature |
| Linux program execution with `rax-user` | Linux or macOS, a supported guest ELF, and its interpreter/libraries for dynamic linking |

Check the local toolchain before diagnosing the repository:

```sh
rustc -Vv
cargo -V
cc --version
```

## Run a Linux program without booting a machine

For process execution, build `rax-user` and run a checked-in static guest:

```sh
cargo build --release --locked --no-default-features --features smir-jit --bin rax-user
./target/release/rax-user tests/fixtures/user/linux/bin/aarch64/hello
```

This fixture prints its argument/environment report and exits with 41 by
design (`40 + argc`), exercising guest exit-status propagation.

The ELF header selects x86-64, AArch64, RV64, or the partial i386
compatibility ABI. Dynamic programs use `--sysroot` for their interpreter
and libraries. See [Linux programs](linux-programs.md) for processes,
threads, signals, sockets, IPC, tracing, and limitations.

## Clean-checkout machine baseline

Build the command-line binary without the default KVM and JIT features:

```sh
cargo build --release --no-default-features
```

Inspect the interface compiled into that binary:

```sh
./target/release/rax --version
./target/release/rax --help
```

Boot the checked-in AArch64 Linux image and initramfs:

```sh
./target/release/rax \
    --backend emulator \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

This exercises:

- CLI parsing and configuration resolution;
- AArch64 `Image` detection;
- the software AArch64 CPU;
- the AArch64 virtual machine;
- generated DTB construction;
- GICv3, PL011, timer, and PSCI wiring used by the guest;
- the terminal-backed serial console.

It deliberately does not depend on KVM, HVF, the native SMIR tier, an externally built kernel, or an external oracle.

### Console controls

When stdin is a terminal, the serial console uses a `Ctrl-A` multiplexer:

| Sequence | Action |
|---|---|
| `Ctrl-A h` | Show console help. |
| `Ctrl-A s` | Write a whole-machine checkpoint to the configured snapshot output. |
| `Ctrl-A x` | Stop the machine. |
| `Ctrl-A Ctrl-A` | Send a literal `Ctrl-A` to the guest where supported by the console path. |

A hard kill may leave a terminal in raw mode. Recover with:

```sh
stty sane
```

## Build and boot the maintained x86 software guest

The established software-x86 path uses an uncompressed ELF `vmlinux`, not an arbitrary distribution kernel configuration. The root Makefile can fetch and build the configured Linux release:

```sh
make linux
make run-linux
```

`make linux` requires network access and Linux build dependencies. It produces `linux/vmlinux`. `make run-linux` invokes the checked-in `run.sh`, which uses the repository initramfs and the serial/timing command line maintained for this path.

A manual launch is:

```sh
./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz
```

Do not replace `vmlinux` with a bzImage on this path and assume equivalent behavior. The direct software boot path and the KVM path use different initial-state and image-loading contracts.

## KVM on Linux/x86-64

Build the default feature set:

```sh
cargo build --release
```

Confirm that the host exposes KVM and that the current user can open it:

```sh
ls -l /dev/kvm
id
```

Run a user-supplied Linux image:

```sh
./target/release/rax \
    --arch x86-64 \
    --backend kvm \
    --kernel /path/to/bzImage \
    --initrd /path/to/initrd.img
```

KVM is the hardware-assisted path. It does not feed every guest instruction through the software interpreter’s trace, GDB-step, hook, or profile surfaces. A guest that boots under KVM but not under the emulator has not isolated the defect to the machine or kernel; the CPU execution path is different.

## Hypervisor.framework on macOS

Build the backend, then sign the final executable:

```sh
cargo build --release --features hvf
codesign -s - -f --entitlements rax.entitlements target/release/rax
```

On Apple Silicon, run an AArch64 guest:

```sh
./target/release/rax \
    --arch aarch64 \
    --backend hvf \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

On Intel macOS, HVF is the matching hardware-assisted path for x86-64 guests. Re-sign after every rebuild. The entitlement applies to the generated binary, not the source tree.

## RISC-V bare-metal ELF

```sh
cargo build --release --no-default-features

./target/release/rax \
    --arch riscv64 \
    --backend emulator \
    --kernel /path/to/program.elf
```

The current RV64 machine is a bare-metal execution environment with an MMIO UART and a project-specific halt/exit path. It is not a privileged Sv39 Linux virtual platform.

## Hexagon bare-metal ELF

```sh
./target/release/rax \
    --arch hexagon \
    --backend emulator \
    --hexagon-isa v68 \
    --hexagon-endian little \
    --kernel /path/to/program.elf
```

Optional load and entry overrides accept decimal or hexadecimal addresses:

```sh
--hexagon-load-addr 0x10000
--hexagon-entry 0x10000
```

The public selector currently exposes revisions from V4 through V69 and defaults to V68. The old root README’s unqualified V73 wording is documented as a version-interface conflict in the [Hexagon guide](../architecture/hexagon/README.md).

## Legacy x86 bootable ISO

```sh
./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --kernel /path/to/bootable.iso \
    --memory 512M
```

This selects the real-mode mini-BIOS and El Torito/ATAPI route. The named TempleOS V5.03 milestone is one demonstrated integration path, not a claim of general PC BIOS compatibility.

## Enable observability features

Build the code behind trace, GDB, and profiling flags:

```sh
cargo build --release --no-default-features \
    --features smir-jit,trace,debug,profiling
```

Trace the software x86 path:

```sh
./target/release/rax \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --trace boot.trace
```

Start the GDB Remote Serial Protocol server and wait for an IDA/GDB client:

```sh
./target/release/rax \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --gdb 1234 \
    --wait-gdb
```

Collect per-mnemonic counts:

```sh
./target/release/rax \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --profile \
    --profile-output profile.json
```

These surfaces attach to software execution. See [Observability and debugging](../operations/observability.md).

## Run initial tests without mistaking skips for evidence

```sh
make test-quick
```

For the broad release suite:

```sh
make test
```

Representative named targets:

```sh
cargo test --release --test differential
cargo test --release --test arm_diff
cargo test --release --test hexagon_hvx_diff
cargo test --release --test riscv_diff
```

For every host- or tool-gated comparison, read:

- the `running N tests` line;
- filtered and ignored counts;
- explicit skip output;
- the selected Cargo target;
- the actual external binary or device used.

A zero exit status can mean “the prerequisite was absent and the suite deliberately skipped.” See [Verification model](../development/verification.md).

## First-run decision tree

1. **Does the software-only build compile?** If not, remove default features and inspect the first compiler error.
2. **Does the bundled AArch64 guest run?** If not, the issue is independent of external images and hypervisor access.
3. **Does the desired guest run under the software backend?** This separates image/machine questions from KVM/HVF availability.
4. **Does the required feature exist in the build?** Trace, GDB, profiling, KVM, HVF, and JIT are not implied by the flag alone.
5. **Did the intended test execute?** Verify count, prerequisites, and skips.
6. **Did the JIT admit the region?** Hotness alone is insufficient; unsupported contracts fall back.

Continue with [Troubleshooting](../troubleshooting.md) for symptom-specific checks.

## Next pages

- [Building](building.md)
- [Command-line reference](../reference/command-line.md)
- [TOML configuration reference](../reference/configuration.md)
- [Machines and boot](../architecture/machines.md)
- [Status and limitations](../reference/status-and-limitations.md)
