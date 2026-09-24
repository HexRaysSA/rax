# Linux 6.19 user-space API headers provenance

- Canonical title: Linux kernel user-space API (UAPI) headers, as exported by
  `make headers_install`
- Issuing organization: the Linux kernel project
- Revision: Linux 6.19.0 (`LINUX_VERSION_CODE` 398080 in
  `any-linux-any/linux/version.h`)
- Distribution used: the sanitized per-architecture header trees vendored by
  Zig 0.16.0 under `lib/zig/libc/include/` (Homebrew bottle
  `zig 0.16.0_1`); the directory names `x86-linux-any`, `aarch64-linux-any`,
  `riscv-linux-any`, `arm-linux-any`, and `any-linux-any` are Zig's and are
  preserved verbatim.
- Upstream source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
  (tag `v6.19`), paths `include/uapi/`, `arch/*/include/uapi/`, and the
  generated `asm/unistd_{32,64}.h` tables.
- Retrieved: 24 September 2026
- Integrity: `uapi-6.19.sha256` lists the SHA-256 of every imported file.
- License: the headers carry `GPL-2.0 WITH Linux-syscall-note` (66 files),
  `GPL-2.0-only WITH Linux-syscall-note` (5 files), or
  `GPL-2.0+ WITH Linux-syscall-note` (7 files) SPDX identifiers. Nine
  files have no SPDX line: the six generated syscall tables and the
  generated `linux/version.h`, derived from kernel sources under the same
  terms; `linux/membarrier.h`, whose upstream header has none; and
  `any-linux-any/asm/socket.h`, Zig's one-line wrapper that includes
  `asm-generic/socket.h`. The license and exception texts are the
  kernel tree's `LICENSES/preferred/GPL-2.0` and
  `LICENSES/exceptions/Linux-syscall-note`. The Linux-syscall-note states that user programs using kernel services by
  normal system calls are not derived works of the kernel.

## Use in RAX

The `rax-user` Linux personality (`src/user/linux/`) is an independent
implementation of the Linux system-call ABI for emulated user-space programs.
These headers are the normative reference for:

- system-call numbers per guest ABI (`asm/unistd_64.h` for x86-64, AArch64,
  and RV64; `asm/unistd_32.h` for i386 and RV32; `asm/unistd-eabi.h` for
  ARM EABI);
- `errno` values (`asm-generic/errno-base.h`, `asm-generic/errno.h`);
- open, `fcntl`, `mmap`, `clone`, `futex`, `prctl`, timer/event/signal
  descriptor (`timerfd.h`, `eventfd.h`, `signalfd.h`), and signal constant
  encodings, including the ARM/AArch64 `O_DIRECTORY`/`O_NOFOLLOW`/`O_DIRECT`/
  `O_LARGEFILE` divergence from `asm-generic/fcntl.h`;
- structure layouts marshalled across the ABI (`struct stat`, `struct statx`,
  `struct timespec`, `struct rlimit`, `struct utsname`,
  `struct signalfd_siginfo`, socket addresses and options (`linux/socket.h`,
  `linux/un.h`, `linux/in.h`, `linux/in6.h`, `linux/tcp.h`,
  `asm-generic/socket.h`), signal frames);
- auxiliary-vector tags and per-architecture `AT_HWCAP` bits.

`tests/suites/user/linux/abi_tables.rs` (Cargo target `user_linux`) parses the syscall and errno tables in
this directory and compares them with the Rust tables, so the numbering is
checked against this primary source on every test run without requiring a
cross toolchain.

The files are reference inputs; do not reformat or edit them. To move to a
newer kernel, import a complete new `uapi-<version>/` tree with its own
provenance record and update the consuming test.
