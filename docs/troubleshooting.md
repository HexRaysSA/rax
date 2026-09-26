[← Documentation home](../README.md)

# Troubleshooting

Start with the smallest path that removes optional host facilities. Do not debug a custom kernel, custom devices, a cross-ISA JIT, and an external oracle at the same time.

## Establish a known baseline

```sh
cargo build --release --no-default-features

./target/release/rax \
    --backend emulator \
    --kernel linux-aarch64/Image \
    --initrd linux-aarch64/initramfs.cpio
```

This checks the command-line binary, software backend, checked-in AArch64 kernel/initramfs pair, architecture detection, virtual platform, and terminal console without KVM, HVF, the JIT, or external tools.

## Build fails

### KVM crates or host interfaces are unavailable

```sh
cargo build --release --no-default-features
```

Add only the feature needed:

```sh
cargo build --release --no-default-features --features smir-jit
```

### HVF reports an entitlement or permission error

```sh
codesign -s - -f --entitlements rax.entitlements target/release/rax
```

Run this after the final build. Rebuilding replaces the signed binary.

### The binary requires AVX2/BMI2/FMA on an old x86-64 host

The checked-in build configuration targets x86-64-v3. Remove or override that Rust flag for an older host, understanding that such a build is outside the documented performance baseline.

### Microkernel build requests `-Z build-std`

Use nightly Rust, install `rust-src`, and provide `llvm-objcopy` or `objcopy`.

## Kernel or program is rejected

- Confirm the file exists; normal configuration validation checks the kernel and initrd paths.
- Pass `--arch` explicitly when the image lacks recognizable ELF or AArch64 `Image` metadata.
- Use an uncompressed ELF `vmlinux` for the established x86 software Linux path.
- Use a bzImage with KVM when following the hardware-backed path.
- Use an ELF for the RV64 and Hexagon bare-metal loaders unless the specific machine documents a flat-binary path.
- Use `--checkpoint` without a kernel only for a self-contained `.rxc` machine checkpoint; `--resume` is the older restore path and expects the machine to be rebuilt from normal configuration.

## Guest starts but no console appears

- x86 Linux: keep `console=ttyS0` and the early serial parameters.
- AArch64 Linux: keep `console=ttyAMA0 earlycon=pl011,mmio32,0x09000000`.
- Check that the guest expects the UART model and address provided by its machine.
- Do not expect VGA output; the current PC path is serial-console oriented and VGA is not wired into the active machine.
- Run from a TTY when testing the interactive `Ctrl-A` mux.

## x86 software Linux stalls

Return to:

```sh
make linux
make run-linux
```

The helper command line disables SMP, APIC/LAPIC use, mitigations, KASLR, and tickless timing for the current controlled path. Re-enable one kernel behavior at a time. KVM success does not imply software-interpreter success because the execution engines and machine interactions differ.

## `--trace`, `--gdb`, or `--profile` does not work as expected

Compile the corresponding feature:

```sh
cargo build --release --features trace,debug,profiling
```

Then force the software backend. Hardware virtualization does not supply the same instruction-by-instruction step loop.

For GDB:

```sh
./target/release/rax ... --backend emulator --gdb 1234 --wait-gdb
```

Use `--gdb-trace` or `RUST_LOG=rax::debug::gdb=trace` when packet exchange itself is the problem.

## A test command is green but no comparison ran

External-reference suites self-gate on host architecture, cross-compilers, QEMU binaries, KVM access, and sometimes host CPU features. Inspect:

- the number of tests executed;
- ignored and filtered counts;
- explicit skip output;
- whether the named Cargo integration target was selected;
- whether generated material was included by a runner rather than mistaken for an independent target.

A zero exit status is a process result, not proof of oracle execution. See [Verification model](development/verification.md).

## KVM is unavailable

Check:

```sh
ls -l /dev/kvm
id
```

Possible causes include disabled hardware virtualization, missing kernel modules, container restrictions, or group permissions. Use `--backend emulator` to separate KVM availability from guest correctness.

## QEMU differential suite skips

Confirm the exact user-mode binary required by the architecture:

- `qemu-aarch64`;
- `qemu-arm`;
- `qemu-hexagon`;
- `qemu-riscv64`;
- `qemu-x86_64` for selected generated x86 corpora.

Also check the required cross-compiler or assembler. APX comparison remains special: the staged QEMU path skips until the installed QEMU supports the required encodings, while LLVM is used for encoding provenance.

## JIT does not promote a region

First confirm that `smir-jit` was compiled and `RAX_NO_JIT` is not set. Then consider admission boundaries:

- unsupported SMIR operation;
- memory, FP/SIMD, APX register, virtual-temporary, or flag-contract restrictions on x86-on-AArch64;
- locked/RMW operations;
- double-width division;
- replay-sensitive, fence, memory, or control-flow boundaries on RV64;
- a frontier-less spin loop;
- a region previously memoized as ineligible;
- self-modifying code invalidation;
- host CPU feature gates for native vector operations.

Use profiling or JIT counters in the relevant tests rather than assuming that a hot loop compiled.

## JIT and interpreter disagree

On supported x86-64-host paths, enable:

```sh
RAX_JIT_VERIFY=1 ./target/release/rax ...
```

Then reduce the guest to the smallest region and run the corresponding SMIR/JIT integration target. A mismatch can originate in lifting, optimization, register allocation, lowering, helper calls, state import/export, or the direct interpreter reference; do not assume the lowerer is the only candidate.

## Checkpoint will not resume

- Use `--checkpoint file.rxc` for the self-contained whole-machine format.
- Do not change memory size unless you understand the embedded configuration and snapshot-size check.
- CLI options override embedded values, even when the resulting combination is nonsensical.
- Use `--resume` only for the legacy path that rebuilds a machine from the supplied kernel/configuration.
- A normal run validates kernel and initrd files; a checkpoint run intentionally does not require those files because RAM and machine state come from the checkpoint.

## Terminal remains in raw mode

The host layer installs restoration handlers, but an uncatchable kill or host failure can still leave the terminal altered. Run:

```sh
stty sane
```

Then reproduce with a catchable exit and report the signal/exit path.

## Linux program execution fails

For `rax-user`, first identify the ELF class/machine and use `--strace` to
find the failing guest syscall. A missing interpreter/library needs the
appropriate `--sysroot`; a path absent from the overlay falls back to the host.
An i386 `ENOSYS` can indicate a missing compatibility conversion even when the
64-bit handler exists. `INT 0x80` from a 64-bit process remains `ENOSYS`.
Machine GDB/checkpoint options do not apply to this binary. Compare with the
checked-in fixture using the same ELF, inputs, and execution mode; see
[Linux programs](getting-started/linux-programs.md) for the ABI boundary.

## Documentation and source disagree

Treat the source, tests, Cargo configuration, and workflows as authoritative for the repository interface. Record the conflict in [Status and limitations](reference/status-and-limitations.md) or the owning architecture page. Do not silently rewrite one side around an assumption.
