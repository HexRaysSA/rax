[← Documentation home](../../README.md)

# Observability and debugging

The software interpreter is the observability path. It owns instruction fetch, decode, execution, state commit, exception delivery, and VM polling, so tracing, single-step debugging, instruction-count profiling, and instruction-count checkpoints can attach to the actual software execution loop.

KVM and HVF execute guest instructions in hardware between exits. They are useful for speed and reference comparisons, but they do not become per-instruction software tracers merely because the binary was built with observability features.

## Linux process observability

`rax-user` uses a separate process loop. `--strace` logs guest syscall names,
arguments, results, and TIDs without the machine `trace` feature:

```sh
./target/release/rax-user --strace tests/fixtures/user/linux/bin/aarch64/hello
```

Guest `ptrace` supports linked parent/child and descendant processes, memory
and register access, syscall stops/editing, job-control and process events,
and seccomp inspection. Single-step is implemented for x86-64 and AArch64;
block-step is x86-64 only. RISC-V stepping and i386 ptrace calls are refused.
This is the emulated Linux syscall interface, with the reach and regset limits
in [Process tracing and seccomp](../architecture/user-mode/tracing.md); it is separate from
the machine GDB RSP server. `rax-user` has no `--gdb`, machine trace/profiler,
or `.rxc` checkpoint CLI options.

## Build the required features

```sh
cargo build --release --no-default-features --features trace,debug,profiling,smir-jit
```

Feature requirements:

| Facility | Cargo feature | Runtime option |
|---|---|---|
| Instruction trace | `trace` | `--trace <FILE>` |
| GDB RSP server | `debug` | `--gdb <PORT>` |
| Wait before execution | `debug` | `--wait-gdb` with `--gdb` |
| GDB packet logging | `debug` | `--gdb-trace` with `--gdb` |
| Instruction profiler | `profiling` | `--profile` |
| JSON profile output | `profiling` | `--profile-output <FILE>` |
| Periodic live profile | `profiling` | `--profile-interval <N>` |

An option parsing successfully is not enough; use a build that includes the feature and the software backend for the instruction-level facilities.

## Host console

On an interactive TTY, the serial console enters raw mode and uses a `Ctrl-A` command prefix. The documented controls include:

- `Ctrl-A h` — display the current command help;
- `Ctrl-A x` — request machine exit;
- `Ctrl-A s` — write a whole-machine checkpoint through the configured snapshot output path.

Use the runtime help rather than assuming the command set is frozen. The terminal guard should restore termios on normal exit, panic, and handled signal paths. If a crash leaves the terminal unusable, `stty sane` is the ordinary recovery command.

Redirected/non-TTY input does not necessarily use the same raw-mode multiplexer behavior.

## Instruction trace

Build and run:

```sh
cargo build --release --no-default-features --features trace

./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --trace boot.trace
```

The x86 trace format is intended to be comparable with Intel SDE-style instruction traces and can contain:

- retired instruction address and disassembly;
- changed registers/flags;
- memory reads/writes where emitted;
- vector-state changes where emitted.

A trace is not automatically complete for every architectural component. Before diffing against another tool, normalize:

- address-space relocation;
- undefined flags;
- timestamp or counter fields;
- instruction spelling;
- vector-state formatting;
- exceptions and asynchronous events;
- guest input and device timing.

### Trace scope

Use `--backend emulator`. KVM and HVF do not send every instruction through the interpreter’s trace hook. If the JIT promotes a region, trace semantics depend on whether the native path emits equivalent events or falls back; for a canonical instruction-by-instruction trace, disable the JIT:

```sh
RAX_NO_JIT=1 ./target/release/rax ... --trace boot.trace
```

### Trace minimization workflow

1. Reproduce with fixed guest image/configuration.
2. Disable JIT and optional devices unless implicated.
3. Capture the smallest prefix around the first divergence.
4. Record initial register/memory state.
5. Reduce to a standalone instruction or short sequence.
6. Add a differential regression rather than relying only on a boot trace.

## GDB Remote Serial Protocol

Start the server and wait before guest execution:

```sh
cargo build --release --no-default-features --features debug

./target/release/rax \
    --arch x86-64 \
    --backend emulator \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --gdb 1234 \
    --wait-gdb
```

Connect a GDB-compatible client to `localhost:1234`. The server exposes the register/memory/continue/step operations implemented by the current architecture adapter.

### IDA Pro

Configure an appropriate remote GDB debugger in IDA and connect to the RSP port. The debugger’s processor/bitness and loaded symbols must match the guest. For a Linux kernel, load the same `vmlinux` used by `rax`; a compressed `bzImage` is not a symbol-rich substitute.

Useful practices:

- disable ASLR with the controlled kernel command line where appropriate;
- keep the guest image and symbols from the same build;
- use `--wait-gdb` for breakpoints at the first instruction;
- distinguish physical addresses, guest virtual addresses, and host addresses;
- expect architecture-specific register packet layouts.

### Packet logging

```sh
RUST_LOG=rax::debug::gdb=trace \
./target/release/rax ... --gdb 1234 --gdb-trace
```

Packet logs can be large and may contain guest memory/register data. Treat them as potentially sensitive artifacts.

## Profiling

```sh
cargo build --release --no-default-features --features profiling

./target/release/rax \
    --backend emulator \
    --kernel linux/vmlinux \
    --profile \
    --profile-output profile.json \
    --profile-interval 10000000
```

The profiler counts instructions/mnemonics observed by the software path and can emit a hot-instruction summary plus JSON output. The default live interval is documented as 10 million instructions; `0` disables periodic live reports while retaining final output where supported.

Profiler counts should be interpreted as software-path retirement counts. They are not hardware performance-counter events, cycles, or an exact KVM/HVF instruction count.

### Profiling with the JIT

A JIT can change where execution is accounted. For interpreter workload characterization, set `RAX_NO_JIT=1`. For JIT behavior, report both:

- guest instructions represented by promoted regions;
- native/fallback/promotion counters exposed by the path;
- time spent compiling;
- cache hits and invalidations where available.

Do not compare interpreter mnemonic counts with hardware backend wall time as though they measure the same layer.

## Logging

`rax` uses Rust logging filters through `RUST_LOG`. Examples:

```sh
RUST_LOG=info ./target/release/rax ...
RUST_LOG=debug ./target/release/rax ...
RUST_LOG=rax::debug::gdb=trace ./target/release/rax ... --gdb 1234
```

Prefer module-specific filters for noisy subsystems. A bug report should include the filter used because debug logging can materially change timing.

## Checkpoints during diagnosis

Use `Ctrl-A s`, `SIGUSR1`, `--snapshot-interval`, or `--snapshot-at` to capture a reproducible state near a failure. Whole-machine restore is documented in [Checkpoints](checkpoints.md).

A checkpoint is particularly useful when:

- the failure occurs after a long boot;
- the next instruction is deterministic;
- device queues and RAM must be preserved;
- a developer needs the same state without the original guest image.

It is less useful when the failure depends on nondeterministic host input or an unsupported snapshot/device configuration.

## Backend capability matrix

| Facility | Software emulator | KVM | HVF |
|---|---:|---:|---:|
| Per-instruction decode/execute trace | yes | no | no |
| Software single-step through every guest instruction | yes | backend/debug dependent, not equivalent | backend/debug dependent, not equivalent |
| GDB RSP through the software vCPU adapter | intended path | not the same path | not the same path |
| Per-mnemonic software profiler | yes | no equivalent | no equivalent |
| Instruction-count snapshot triggers | software path | not equivalent | not equivalent |
| Whole-machine state save/restore | configuration/device dependent | configuration/device dependent | configuration/device dependent |
| External hardware-reference testing | not itself | yes, selected x86 tests | not the principal oracle described |

## Security and operational caution

The GDB server, trace files, profile output, logs, and checkpoints expose guest state. Bind the debugger only where intended, avoid untrusted networks, and handle artifacts as potentially sensitive. The repository does not currently present a hardened remote-debug security boundary.
