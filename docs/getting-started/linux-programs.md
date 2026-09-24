[← Documentation home](../../README.md)

# Running Linux programs with `rax-user`

`rax-user` runs a single Linux user-space program — not a whole machine —
on RAX's software CPUs. It loads an ELF executable the way the Linux
kernel's `binfmt_elf` does, executes it in the CPU's unprivileged mode, and
services its system calls on the host. It is the process-level counterpart
of the `rax` machine emulator, comparable in scope to QEMU's user-mode
emulators (`qemu-x86_64`, `qemu-aarch64`, `qemu-riscv64`).

| Guest ABI | ELF `e_machine` | CPU core |
|---|---|---|
| x86-64 Linux | `EM_X86_64` (62) | RAX x86-64 interpreter with the SMIR JIT on x86-64 hosts |
| AArch64 Linux | `EM_AARCH64` (183) | RAX AArch64 interpreter at EL0 |
| RV64 Linux | `EM_RISCV` (243), ELFCLASS64 | RAX RISC-V interpreter in U-mode (optional SMIR JIT) |

The host must be Unix (Linux or macOS). On other hosts the binary builds but
reports that the host is unsupported.

## Build and run

```sh
cargo build --release --no-default-features --features smir-jit --bin rax-user

./target/release/rax-user ./hello-aarch64 arg1 arg2
echo $?
```

The guest ABI comes from the ELF header, so the same command runs x86-64,
AArch64, and RV64 programs. Standard input, output, and error are the
host's. The exit status is the guest's:

| Status | Meaning |
|---|---|
| `0`–`255` | The program called `exit`/`exit_group` with this value (mod 256). |
| `128 + N` | Signal `N` killed the program (for example 139 for `SIGSEGV`). A diagnostic line with the signal, `si_code`, fault address, and PC goes to standard error. |
| `125` | The emulator could not continue (for example a deadlock with no runnable thread). |
| `126` | The file is not an executable for a supported ABI, or loading it failed. |
| `127` | The file does not exist. |

## Options

| Option | Effect |
|---|---|
| `-L`, `--sysroot DIR` | Guest root overlay: an absolute guest path that exists under `DIR` resolves there, anything else resolves on the host (QEMU `-L` semantics). Symbolic links inside `DIR` resolve inside `DIR`. `/dev`, `/proc`, and `/sys` always resolve on the host or are synthesized. |
| `-E`, `--env VAR=VALUE` | Set a guest environment variable (repeatable). |
| `-U`, `--unset-env VAR` | Remove a guest environment variable (repeatable). |
| `--clear-env` | Start from an empty environment instead of `rax-user`'s own. |
| `-0`, `--argv0 NAME` | Pass `NAME` as `argv[0]`. |
| `-C`, `--cwd DIR` | Guest working directory (default: the current directory). |
| `--strace` | Log every system call as `[tid] name(args) = result` on standard error. |
| `--seed N` | Deterministic `AT_RANDOM` bytes and `getrandom` output. |
| `-s`, `--stack-size SIZE` | `RLIMIT_STACK` soft limit and `[stack]` mapping size (default `8M`). |
| `--memory SIZE` | Guest memory arena (default `16G`, committed by the host only as touched). |
| `--riscv-jit` | Execute RISC-V guests through the SMIR JIT where the host supports it. |
| `--kernel-release R` | `uname -r` value (default `6.19.0`). |
| `--slice N` | Instructions per scheduling slice for AArch64 and RV64 guests. |

Sizes accept `K`, `M`, `G`, and `T` suffixes (powers of 1024).

## What the guest sees

- **Address space.** Linux 6.19's layout with randomization disabled
  (`setarch -R`): x86-64 PIEs load at `0x555555554000` and their
  interpreter just below `0x7ffff7fff000`; AArch64 PIEs at `0xaaaaaaaa0000`
  (64 KiB alignment); the stack ends at `STACK_TOP` (`0x7ffffffff000` on
  x86-64). Page permissions are enforced exactly; an access to an unmapped
  page raises `SIGSEGV`/`SEGV_MAPERR`, to a protected page
  `SIGSEGV`/`SEGV_ACCERR`, and past the end of a mapped file `SIGBUS`.
- **Initial stack and auxiliary vector.** Byte-for-byte the layout of
  `create_elf_tables` for the vector RAX produces (no `AT_SYSINFO_EHDR`,
  because no vDSO is mapped; C libraries then use system calls for time).
- **CPU.** One CPU executes every guest thread. `sched_getaffinity` reports
  CPU 0 only, and `/proc/cpuinfo` describes that CPU.
- **Files.** Host files, directories, pipes, and terminals, with Linux
  `errno` values. `/proc/self` (`exe`, `maps`, `auxv`, `cmdline`, `environ`,
  `stat`, `status`, `comm`, `fd/`), `/proc/cpuinfo`, `/proc/meminfo`,
  `/proc/uptime`, `/proc/version`, and the CPU-topology files under
  `/sys/devices/system/cpu` are synthesized.
- **Identity.** The host process ID, user, and group IDs.

## Current limitations

These are tracked in [Status and limitations](../reference/status-and-limitations.md)
and in the [user-mode architecture page](../architecture/user-mode.md):

- Signal handlers are recorded but not yet invoked: a signal whose
  disposition is a handler terminates the process as its default action
  would. Fatal default actions, `SIG_IGN`, and ignored-by-default signals
  behave as on Linux.
- A single guest thread runs; `clone`, `fork`, `vfork`, and `execve` are not
  yet implemented, and a futex wait with no timeout ends the process with a
  deadlock diagnostic.
- The 32-bit `INT 0x80` system-call ABI on x86-64 returns `-ENOSYS`.
- Sockets, `epoll`, `eventfd`, timers delivered as signals, and writable
  `MAP_SHARED` file mappings (writes do not reach the file) are not
  implemented.
- Terminal attribute changes (`TCSETS*`) are accepted but not applied to the
  host terminal; `TCGETS` reports Linux's default terminal settings.
