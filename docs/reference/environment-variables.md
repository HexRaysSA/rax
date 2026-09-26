[← Documentation home](../../README.md)

# Environment variables

`rax` does not use one centralized environment-variable schema. Variables are read by the runtime, helper scripts, benchmarks, or the independent microkernel build. Their scope and stability therefore differ. Prefer CLI or TOML for persistent VM configuration; use environment variables for host tooling, diagnostics, or script overrides.

## Runtime logging

### `RUST_LOG`

Controls the `tracing_subscriber` filter used by the command-line binary.

```sh
RUST_LOG=debug ./target/release/rax ...
RUST_LOG=rax::vm=trace ./target/release/rax ...
RUST_LOG=rax::debug::gdb=trace ./target/release/rax ... --gdb 1234
```

Without a valid environment filter, the CLI uses an `info` default. `--gdb-trace` adds the debugger module’s trace directive to the effective filter.

Operational caution: trace-level logs can contain addresses, register values, protocol traffic, paths, and guest-derived data.

## SMIR/JIT runtime controls

These variables are developer controls rather than stable public configuration fields. Keep source and tests authoritative.

### `RAX_NO_JIT`

Disables x86 hot-region promotion at runtime in a build that contains `smir-jit`:

```sh
RAX_NO_JIT=1 ./target/release/rax ...
```

Use it to establish an interpreter baseline without rebuilding. It does not remove JIT code from the binary.

### `RAX_JIT_VERIFY`

Enables runtime comparison for supported x86-64 compiled regions:

```sh
RAX_JIT_VERIFY=1 ./target/release/rax ...
```

Verification mode is itself scoped: it compares the state projection implemented by that path for regions that are admitted and executed. It is not formal proof and may alter performance substantially.

### `RAX_JIT_NO_CALL`

Disables or rejects helper/call-containing native regions in the relevant JIT path:

```sh
RAX_JIT_NO_CALL=1 ./target/release/rax ...
```

Use it when isolating helper ABI, call-clobber, or region-admission problems.

### `RAX_JIT_NO_MEM`

Disables or rejects memory-containing native regions in the relevant JIT path:

```sh
RAX_JIT_NO_MEM=1 ./target/release/rax ...
```

Use it to distinguish register/flag lowering from guest-memory helper behavior.

These controls are not equivalent to Cargo features. `RAX_NO_JIT=1` changes runtime promotion; `--no-default-features` omits the native tier from the build.

## Linux process execution and validation

`RAX_NO_JIT` also establishes an x86-64 interpreter baseline for `rax-user`.
RV64 process JIT selection uses its `--riscv-jit` option; i386 compatibility
code stays interpreted.

`TMPDIR` selects the host temporary namespace used by emulated System V and
POSIX IPC, macOS abstract Unix sockets, and the emulated inotify hub. Processes
that must share those objects need the same namespace. The fixture runner
allocates a private `TMPDIR` for each run so unrelated cases do not share it.

`RAX_USER_DOCKER_ORACLE` is a presence switch used only by the ignored
`user_linux` live Docker comparison. Without it, that test reports `NOT RUN`
even with `--include-ignored`; setting it also requires a usable Docker daemon
and the three-architecture execution setup. The ordinary recorded-result
comparisons do not need Docker.

```sh
RAX_USER_DOCKER_ORACLE=1 cargo test --release --locked --no-default-features \
    --features smir-jit --test user_linux -- --ignored --nocapture
```

`--seed` controls `AT_RANDOM` and `getrandom` bytes; it does not make host
timing or all process scheduling deterministic. See [Linux programs](../getting-started/linux-programs.md).

## Machine-selection control

### `RAX_MACHINE`

Some 32-bit Arm integration work uses an implementation-specific machine selector. The documented value is:

```sh
RAX_MACHINE=s5l8900 ./target/release/rax ...
```

Treat this as a specialist development interface, not a general substitute for `--arch`. The selected machine still requires a compatible image, ISA mode, load/entry state, and devices. Record it in reproduction instructions because omitting it can select a different machine path.

## `run.sh` overrides

The root `run.sh` helper reads the following variables before launching the software x86 Linux baseline.

### `RAX_KERNEL`

Kernel path. Default:

```text
linux/vmlinux
```

Example:

```sh
RAX_KERNEL=/tmp/linux/vmlinux ./run.sh
```

### `RAX_INITRD`

Initramfs path. Default:

```text
initrd.cpio.gz
```

Set an empty or alternate path only if the script and selected guest support that use.

### `RAX_ARCH`

Guest architecture passed to the CLI. Default:

```text
x86-64
```

### `RAX_BACKEND`

Backend passed to the CLI. Default:

```text
emulator
```

### `RAX_MEMORY`

Guest memory passed to the CLI. Default:

```text
512M
```

### `RAX_CMDLINE`

Overrides the helper’s known x86 software-boot kernel command line.

Example:

```sh
RAX_KERNEL=linux/vmlinux \
RAX_INITRD=initrd.cpio.gz \
RAX_ARCH=x86-64 \
RAX_BACKEND=emulator \
RAX_MEMORY=1G \
RAX_CMDLINE='console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr' \
./run.sh
```

The helper variables are script inputs. They are not automatically read by a direct `./target/release/rax` invocation.

## Compiler and performance controls

### `RUSTFLAGS`

Adds Rust compiler flags. Common local examples:

```sh
RUSTFLAGS='-C target-cpu=native' cargo build --release
RUSTFLAGS='-C target-cpu=x86-64-v3' cargo test --release
```

This can change instruction selection, performance, host compatibility, code generation, and therefore test behavior. Include it in benchmark and bug reports.

### `PGO_TARGET_CPU`

Controls the CPU target used by the repository PGO flow. The script defaults to `native`; use an explicit baseline when the output must run elsewhere:

```sh
PGO_TARGET_CPU=x86-64-v3 make pgo
```

Record the training workload and final target CPU. PGO artifacts cannot be compared meaningfully without them.

### `PGO_TMPDIR` and `TMPDIR`

The PGO script creates its private working directory under `PGO_TMPDIR`, falling back to `TMPDIR` and then `/tmp`:

```sh
PGO_TMPDIR="$HOME/.cache/rax-pgo" make pgo
```

The selected parent must permit creation of a user-owned mode-`0700` temporary directory. The script validates ownership and permissions before placing raw profiles there. `PGO_TMPDIR` is the project-specific override; `TMPDIR` is the conventional process fallback.

### `LINUX_VERSION`

Overrides the Linux tag fetched by `make linux`; the current Makefile default is `v6.12`:

```sh
make linux LINUX_VERSION=v6.6
```

The output path remains `linux/vmlinux`. A different kernel version can expose a different software-CPU or platform surface, so include the tag in boot reports.

## Microkernel build and runner controls

The `microkernel/` package is independent of the root Cargo workspace and has its own Makefile/scripts.

### `RAX_BIN`

Selects the `rax` executable used by the microkernel runner:

```sh
RAX_BIN=../target/release/rax make -C microkernel run
```

### `FORCE_BUILD`

Forces rebuild behavior in the microkernel scripts where supported:

```sh
FORCE_BUILD=1 make -C microkernel run
```

### `MEM`

Controls the memory argument used by the microkernel runner:

```sh
MEM=256M make -C microkernel run
```

This name is specific to the microkernel tooling; it is not the root VM CLI’s environment interface.

### `OBJCOPY`

Selects the object-copy tool when constructing flat or architecture-specific artifacts:

```sh
OBJCOPY=llvm-objcopy make -C microkernel
```

### `SDE_PATH`

Selects the directory containing `sde64` for the hosted x86 comparison:

```sh
SDE_PATH=/opt/sde make -C microkernel test-sde
```

The microkernel Makefile invokes `$SDE_PATH/sde64`; alternatively, put `sde64` on `PATH`. Intel SDE is external and is not downloaded by the root build.

## Variables versus CLI/TOML

Use this priority when choosing a control surface:

1. Use CLI for a one-off, visible VM invocation.
2. Use TOML for persistent guest/machine configuration.
3. Use `run.sh` variables only when invoking `run.sh`.
4. Use runtime developer variables for targeted diagnostics.
5. Use build variables for compiler/PGO/microkernel tooling.

Do not place secrets in these variables merely because they are not command-line flags. They may appear in process environments, shell history, CI logs, crash reports, or diagnostic output.

## Reproduction template

Include only the variables that were actually set:

```text
RUST_LOG=
RUSTFLAGS=
RAX_NO_JIT=
RAX_JIT_VERIFY=
RAX_JIT_NO_CALL=
RAX_JIT_NO_MEM=
RAX_USER_DOCKER_ORACLE=
RAX_MACHINE=
RAX_KERNEL=
RAX_INITRD=
RAX_ARCH=
RAX_BACKEND=
RAX_MEMORY=
RAX_CMDLINE=
PGO_TARGET_CPU=
PGO_TMPDIR=
TMPDIR=
LINUX_VERSION=
RAX_BIN=
FORCE_BUILD=
MEM=
OBJCOPY=
SDE_PATH=
```

An unset variable and an explicitly empty variable can have different shell/script effects; preserve that distinction.

## Related pages

- [Command-line reference](command-line.md)
- [TOML configuration](configuration.md)
- [Cargo features](build-features.md)
- [Performance](../operations/performance.md)
- [Microkernel](../development/microkernel.md)
