# Own-child AArch64 Linux ptrace controls

`control.c` traces only its own children and uses PTRACE_O_EXITKILL to bound
their lifetime. All ten cases completed and the process exited zero under
Debian kernel 6.1.0-54-cloud-arm64 in QEMU TCG on 12 November 2026. The input
image hash held before and after execution. Exact source/image hashes, cloud
image checksum and scope are in `provenance.json`; stdout is `native.jsonl`.
This is an AArch64 Linux kernel API control, not physical hardware or installed
host-library qualification. The control uses static musl.

The measured virtual CPU exposes DebugVer 0xa, six breakpoint slots and four
watchpoint slots. The emulator's existing base profile exposes DebugVer 6;
these profile values must not be equated. The common measured semantics are:

- Header and padding writes are ignored; a fresh 264-byte regset has zero
  comparator fields.
- An address write creates a disabled default object. Invalid later controls
  leave the new object and committed address intact.
- Disabled controls retain their attributes. Enabled A64 execution controls
  normalize contiguous lengths to four bytes and privilege to EL0.
- A partial address returns EINVAL; a full sixteen-entry input returns ENOSPC
  after allocating the six available disabled breakpoint objects.
- PTRACE_CONT without disarming an instruction comparator produces the same
  hardware SIGTRAP again at the unchanged PC. Disarming permits completion.
- The write-watchpoint control also repeats at the store PC; the watched data
  remains zero at each stop. Core watchpoint execution is not qualified by
  implementing only the instruction regset.

The pinned implementation references are Linux v6.19
[ptrace.c](../kernel-6.19/arch/arm64/kernel/ptrace.c),
[hw_breakpoint.c](../kernel-6.19/arch/arm64/kernel/hw_breakpoint.c) and
[hw_breakpoint.h](../kernel-6.19/arch/arm64/include/asm/hw_breakpoint.h).
The automatic perf stepping branch is conditional on the default overflow
handler; ptrace installs its own callback and does not select that branch.
Compile the C file with an AArch64 Linux compiler and run it without arguments.

The separate `lifetime.c` control includes `control.c` and traces a fork and
an exec. Both new banks are empty and all descendants exit zero; exact
output is `lifetime.jsonl`, with image/source hashes in `provenance.json`.
