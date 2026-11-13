# Own-child Linux ptrace debug controls

`instruction.c` and `fork.c` trace only children created by the control.
Their unmodified stdout is in the adjacent JSONL files. Both controls exited
zero on Debian kernel `6.1.0-54-cloud-amd64` under QEMU TCG on 12 November 2026.
This establishes native Linux kernel API behavior under that virtual CPU;
it does not establish physical Intel debug hardware behavior. Source, image
and primary-reference hashes are in `provenance.json`.

The instruction control covers four execution slots, local/global enables,
DR4/DR5 zero-write rejection, arbitrary virtual DR6 writes, invalid execution
length rejection and unchanged requested DR7, reserved DR7 readback, precise
fault PC, slot-specific DR6, kernel-supplied RF, and successful child completion
after one continuation. Its first version expected address `0x800000000000`
to be rejected. The VM advertises 57-bit virtual addressing and accepted that
address; the retained control instead tests a kernel address. The emulator's
existing four-level `TASK_SIZE_MAX` profile is not inferred from this VM.

The fork control observes a traced fork event. The new child has no comparator
address, but retains its parent's virtual DR6 and requested DR7. Both processes
then exit zero. `PTRACE_O_EXITKILL` bounds the controls to their own descendants.
Build either C file with a Linux C compiler and execute it without arguments.

The implementation contract is Linux `v6.19`:

- [ptrace.c](../kernel-6.19/arch/x86/kernel/ptrace.c): `ptrace_get_debugreg`,
  `ptrace_set_debugreg`, `ptrace_write_dr7` and its restoring pass.
- [hw_breakpoint.c](../kernel-6.19/arch/x86/kernel/hw_breakpoint.c): type/length
  validation, effective DR7 encoding and RF on execution breakpoint handling.
- [traps.c](../kernel-6.19/arch/x86/kernel/traps.c): `exc_debug_user` resets the
  virtual status to the current cause before comparator callbacks add bits.
- [process.c](../kernel-6.19/arch/x86/kernel/process.c): `copy_thread` clears
  comparator objects; `flush_thread` also clears virtual status and control.

These controls qualify instruction-debug plumbing. Core data watchpoint
execution, ARM debug regsets and full same-host process execution remain
separate acceptance requirements.
