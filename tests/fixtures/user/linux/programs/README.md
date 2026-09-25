# morok program corpus

97 C and C++ programs from the morok project, built as static Linux
executables for `x86_64`, `aarch64`, and `riscv64`, with the standard output
and exit status each one produced on a real Linux kernel. The `programs`
module of the `user_linux` test target (`tests/suites/user/linux/programs.rs`)
runs every program under `rax-user` in five execution modes (x86-64 with and
without the SMIR JIT, AArch64, and RV64 with and without `--riscv-jit`) and
requires the recorded result, byte for byte, after the `noise.txt` filters.

The programs cover integer, floating-point, and SIMD arithmetic, calling
conventions, control flow (computed `goto`, `setjmp`/`longjmp`, C++
exceptions, RTTI, coroutines), memory access patterns, thread-local storage,
atomics, inline assembly, and the file, `mmap`, signal, socket, and
`fork`/`exec` system calls. Unlike the fixtures one directory up, which
check system calls one by one, these are whole programs whose compiled code
exercises the CPU emulation broadly: the corpus found an x86-64 decoder
defect (the SSE shift-by-immediate forms ignored REX.B) behind seven
programs' wrong results, and the direct x86-64 engine's binary64 x87
registers, which made the C library print last digits wrongly.

| Path | Content |
|---|---|
| `src/` | The programs, trimmed as described below. |
| `LICENSE` | morok's MIT license. |
| `upstream.sha256` | SHA-256 of every upstream source, as vendored. |
| `cases.txt` | Every program, with its command-line arguments. |
| `build.sh` | Rebuilds `bin/` and `manifest.toml`. |
| `bin/<arch>/<program>` | Static, stripped executables. |
| `manifest.toml` | Toolchain, flags, and SHA-256 of every binary (checked by the test). |
| `record-expected.sh` | Records `expected/` on Linux through Docker. |
| `expected/<arch>/<program>.{stdout,status}` | Recorded results. |
| `expected/ORACLE` | Kernel, Docker server, CPU count, cross-check, and overrides of the recording. |
| `oracle-overrides.txt` | Expectations that do not come from the recording, with the reason. |
| `noise.txt` | Output that differs between two runs on one kernel, masked (or, for a line printed only sometimes, dropped) before comparing. |
| `known-divergences.txt` | rax's open defects: programs that must still differ in a given mode. |

## Provenance

- Project: morok, `https://github.com/19h/morok`, commit
  `3d6970f41a0ab8e794e328455d62849806238df5` (27 July 2026); the
  `programs/` directory was last changed by commit
  `4863090aba4c3f018e6f8aaae3ec695ddfefe07a` (3 July 2026).
- Retrieved: 25 September 2026, from a local clone at that commit with a
  clean `programs/` directory.
- License: MIT, "Copyright (c) 2026 Morok contributors" (`LICENSE`, copied
  from the repository root).
- Integrity: `upstream.sha256` lists the upstream SHA-256 of all 97 files.
  The test requires every file in `src/` either to match its upstream hash
  or to mark its changes with `rax:` comments.

## Changes from upstream

The upstream programs are benchmarks and instruction-mix samples: many run
for seconds natively, minutes under an emulator, and 62 of them print
nothing. Two kinds of change make them a test corpus; each changed line
carries a `rax:` comment, so `diff` against upstream shows exactly what
changed.

1. **Trimmed work** (`/* rax: was <upstream value> */`): loop counts, and
   where one iteration was already too long, data sizes, reduced so that a
   release build of `rax-user` runs each program in 40 ms or less on every
   architecture (measured on an Apple M-series host), while every function
   is still called and every branch class upstream takes is still taken
   (periodic `i % K` conditions still fire; sizes still cross page
   boundaries). Exceptions and compromises:
   - `cf_exception` and `cpp_exception_variant_unwind` still take 100-350 ms:
     each C++ throw costs 2.5-8 ms under `rax-user` (the unwinder runs
     emulated), and the trimmed counts are the smallest that still throw and
     catch every exception type.
   - `int_crc32` steps its buffer length by 71 instead of 1 (15 lengths from
     1 to 995), because for lengths below 256 its five CRC variants cancel
     in the checksum.
   - `int_galois` fills 64 x 64 entries of its 256 x 256 multiplication
     table; lookups past it read 0, deterministically.
   - `cf_switch_sparse` no longer reaches `case 10000`, and
     `cpp_exception_variant_unwind` no longer reaches the round-8 throw.
   - `syscall_file_ops` and `syscall_mmap` run their outer loop once.
   - `syscall_signals`'s `kill` test blocks `SIGUSR1` before telling the
     parent it is ready and waits with `sigsuspend` instead of `pause`:
     upstream, a signal sent between the child's `write` and its `pause` is
     lost and the child hangs, which on one CPU happens every time.
2. **Observable results** (`/* rax: print the result so that runs can be
   compared */`): programs that only stored their result into a `volatile`
   sink print it before returning from `main`, as `name=value` lines.
   Integers are printed in decimal or hexadecimal; floating-point results
   are printed as their raw IEEE 754 bits, so a formatting difference in the
   C library cannot hide or fake a computation difference. The `syscall_*`
   programs print only the deterministic part of their result
   (`result_det`), subtracting descriptor numbers, process IDs, ports, and
   socket buffer sizes, which differ between runs and systems. Programs
   whose only result mixes in cycle counters (`asm_arch_detect`) or that
   write undefined data (`asm_syscall_raw` on x86-64, whose inline
   `write` passes the length in the wrong register) are left silent.

`02_fibonacci` takes its argument from `cases.txt`; upstream's
`run_programs.sh` passes 30, the corpus passes a smaller value.

## Build

- Toolchain: Zig 0.16.0 (`zig cc`/`zig c++`: bundled clang, musl 1.2.5,
  libc++), Homebrew bottle `zig 0.16.0_1` on macOS 27 arm64, as for the
  fixtures one directory up.
- Flags: morok's (`-O2`, `-std=c11` or `-std=c++23`, `-D_GNU_SOURCE`,
  `-lm`), plus `-static -s -fno-sanitize=all -ffile-prefix-map=<dir>=.`
  for self-contained, reproducible executables (`manifest.toml` records
  them). The Zig targets use the baseline CPU of each architecture
  (x86-64 with SSE2 and nothing newer, AArch64 with NEON but without the
  cryptography extension, RV64GC), per the compiler's predefined macros.

The 291 executables take 21 MiB (the 16 C++ programs link libc++
statically, about 0.5 MiB each). They are committed rather than built by
the test because the recorded results belong to these exact binaries (for
example `cpp_rtti` prints addresses from them, and code generation differs
between compiler versions), and because the test hosts need neither Zig nor
cross toolchains.

## Recording

`record-expected.sh` runs every program twice per architecture in a
container (`alpine:latest`) with `--init`, without Docker's default seccomp
profile, on one CPU (`--cpuset-cpus 0`, because `rax-user` runs all guest
threads on one host thread and reports one CPU, and `05_thread_pool` prints
the CPU count), in a fresh working directory with standard input from
`/dev/null`. AArch64 runs natively; x86-64 and RV64 run through the Docker
host's `binfmt_misc` handlers (Rosetta and `qemu-riscv64`), and the x86-64
results are cross-checked under `qemu-x86_64` user mode; `expected/ORACLE`
names all of them and lists any disagreement. A program whose two runs
differ outside its `noise.txt` filters is reported as nondeterministic.

Results legitimately differ between architectures: clang contracts
`a * b + c` into fused multiply-adds on AArch64 and RV64 but not on
baseline x86-64 (`fp_*`, `simd_dot_product`), plain `char` is signed only on
x86-64 (`syscall_file_ops`, `syscall_mmap`), out-of-range float-to-integer
conversions saturate differently (`mem_sequential`), the SIMD kernels and
inline assembly differ per architecture (`simd_image_filter`, `asm_*`), and
`cpp_rtti` mixes in `type_info::hash_code()`, the address of the type's name
in the static executable. Each architecture therefore has its own recording.

`oracle-overrides.txt` replaces a recording where the translator running it
does not behave like Linux: `qemu-riscv64` lets user mode read the `cycle`
counter, which Linux 6.19 disables by default, so `asm_arch_detect`'s RV64
expectation (death by `SIGILL`, status 132) comes from the kernel source
(`docs/specifications/linux/kernel-6.19/drivers/perf/riscv_pmu_sbi.c`).

## Known divergences

`known-divergences.txt` lists, per execution mode, the programs whose
result `rax-user` does not yet reproduce, each with its cause. The test
fails when a listed program starts to match (the entry must then be
removed) and when an unlisted program differs, so the list is always the
exact set of open defects.

## Updating

1. Edit `src/` (mark every change with a `rax:` comment) or `cases.txt`,
   then run `./build.sh` (requires Zig 0.16.0).
2. Run `./record-expected.sh` on a host with Docker able to run all three
   architectures and with network access (for `qemu-x86_64`), and review
   the diff under `expected/` and `expected/ORACLE`.
3. Run `cargo test --no-default-features --features x86_64-suite,smir-jit
   --test user_linux programs`. Each execution mode runs the programs in
   parallel; the five modes take about 30 s with a debug build on a 16-core
   Apple M-series host.
