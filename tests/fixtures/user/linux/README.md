# rax-user Linux fixtures

Static Linux programs that exercise the `rax-user` Linux personality, with
the output a real Linux kernel produced for each of them. The
`user_linux` test target (`tests/suites/user/linux/`) runs every case on
every architecture and requires a byte-for-byte match.

| Path | Content |
|---|---|
| `src/*.c` | Self-checking C sources. Each check prints `ok <name>` or `FAIL <name>: ...`. |
| `build.sh` | Rebuilds `bin/` and `manifest.toml`. |
| `bin/<arch>/<program>` | Static, stripped executables for `x86_64`, `aarch64`, and `riscv64`. |
| `manifest.toml` | Toolchain, flags, and SHA-256 of every binary (checked by the test). |
| `cases.txt` | Case table: program, standard-input file, and arguments. |
| `input/` | Standard-input files referenced by `cases.txt`. |
| `record-expected.sh` | Records `expected/` on Linux through Docker. |
| `oracle-overrides.txt` | Cases whose expectation for one architecture is another architecture's real-kernel result, with the reason. |
| `expected/<arch>/<case>.{stdout,status}` | Recorded results. |
| `expected/ORACLE` | Kernel, Docker server, binfmt handlers, overrides, and recording time of the oracle run. |

## Programs

| Program | Covers |
|---|---|
| `hello` | `argc`/`argv`/`envp`, exit status |
| `fileio` | `open` flags and errors, `read`/`write`/`pread`/`lseek`, `O_APPEND`, `ftruncate`, `stat` family, `rename`/`link`/`symlink`/`readlink`, directories and `getdents64`, `*at` calls with a directory descriptor, pipes, `dup2`/`dup3`, `fcntl` descriptor and status flags, non-blocking pipes |
| `memory` | `malloc` across the mmap threshold, `brk`, anonymous and private file mappings, `mprotect`, `madvise(MADV_DONTNEED)`, `munmap` holes, `mincore`, `MAP_FIXED`/`MAP_FIXED_NOREPLACE`, `mremap` with move, argument errors |
| `mman` | Per-VMA `madvise` (`DONTNEED` on private and shared memory, `FREE`, `REMOVE`, `POPULATE_READ`/`WRITE`, holes, a refusing VMA ending the walk), `mprotect` validation order, partial application up to a hole, `PROT_GROWSDOWN` on the stack, shared mappings of read-only files, `personality` |
| `process` | IDs, `uname`, auxiliary vector, clocks and `nanosleep`, resource limits, affinity, `getrandom`, `prctl`, `umask`, `/proc/self/exe`, `/proc/self/maps`, `ENOSYS`/`EBADF`/`EFAULT` |
| `timers` | `alarm` and `pause`, a periodic `ITIMER_REAL`, `getitimer`, `nanosleep` interrupted with the time left, a pipe `read` interrupted (`EINTR`) and restarted (`SA_RESTART`), `poll` not restarted, `pselect6` writing back the time left, `sigtimedwait` taking a timer's `SIGALRM`, `clock_nanosleep` on the thread CPU clock (`EOPNOTSUPP`) and the monotonic clock |
| `hostsig` | Not a recorded case: the `user_linux` `host_signals` tests send it host signals and follow its output (`siginfo` of a `kill`, a blocking `read` of standard input interrupted by a handler, death by `SIGTERM`) |
| `signals` | Handlers with `siginfo` from `raise`/`kill`/`sigqueue`, the mask during and after a handler, `SA_NODEFER`, `SA_RESETHAND`, delivery order of several unblocked signals, real-time queueing with `sigtimedwait`, `sigsuspend`, ignored signals, `SA_ONSTACK` alternate stacks, recovering from `SIGSEGV` (MAPERR, ACCERR), `SIGBUS`, and traps with `siglongjmp`, a handler editing the saved PC to skip a faulting store, `SIGPIPE`, and `abort()` after its handler returns (status 134) |
| `stdin` | Reading standard input to end of file |
| `segv` | Fatal `SIGSEGV` (status 139) |
| `abort` | `abort()` → `tgkill(SIGABRT)` (status 134) |
| `trap` | `__builtin_trap()`: `SIGILL` on x86-64 and RISC-V (132), `SIGTRAP` on AArch64 (`BRK`, 133) |

## Provenance

- Toolchain: Zig 0.16.0 (`zig cc`, bundled clang and musl 1.2.5), Homebrew
  bottle `zig 0.16.0_1` on macOS 27 arm64.
- Flags: `-static -Os -s -fno-sanitize=all -fno-stack-protector
  -ffile-prefix-map=<dir>=.`, targets `x86_64-linux-musl`,
  `aarch64-linux-musl`, `riscv64-linux-musl`.
- The build is reproducible: running `build.sh` twice produces identical
  `manifest.toml` hashes, and adding a program leaves the others' hashes
  unchanged.
- Size: 36 binaries (12 programs × 3 architectures), 859 KiB in total; each
  is stripped and statically linked so that no guest sysroot is needed.
- The expected results were recorded with `record-expected.sh` on the
  Linux kernel named in `expected/ORACLE` (OrbStack Linux 7.0.14, arm64).
  AArch64 binaries ran natively on that kernel. x86-64 binaries ran through
  a `binfmt_misc` translator (both Rosetta and `qemu-x86_64` are registered;
  `expected/ORACLE` lists them); their `mman` results are identical to the
  native AArch64 run, so their system calls reached the kernel. RV64
  binaries ran through `qemu-riscv64` user mode, which emulates some system
  calls itself (for example, it ignores most `madvise` advice). Where that
  emulation diverges from Linux in architecture-independent kernel code,
  `oracle-overrides.txt` substitutes the native result and says why.
  Where the x86-64 translator (Rosetta) diverges, the case runs under
  `qemu-x86_64` user mode installed in the container instead (its version
  is in `expected/ORACLE`): Rosetta resets an `SA_RESETHAND` disposition
  before running the handler.
- Containers ran with `--init` so the fixture was not the PID-namespace
  init (the kernel ignores default-action signals sent to an init, which
  would make `abort()` loop), and with `--security-opt seccomp=unconfined`
  so Docker's default seccomp profile did not refuse valid arguments (it
  returns `EPERM` for `personality(READ_IMPLIES_EXEC)`).
- License: the binaries statically link musl libc (MIT) and Zig's
  compiler-rt (MIT); the sources in `src/` are part of RAX (MIT).

## Updating

1. Edit `src/`, then run `./build.sh` (requires Zig 0.16.0).
2. Run `./record-expected.sh` on a host with Docker able to execute all
   three architectures, and review the diff under `expected/`.
3. Run `cargo test --no-default-features --features x86_64-suite,smir-jit
   --test user_linux`.

A case added to `cases.txt` is picked up by the test automatically; a new
program must also be added to `build.sh`. An override must name its source
architecture and a reason; the test checks that the overridden files equal
the source architecture's recording.
