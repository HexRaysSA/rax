[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Linux signals and timers

Architectural faults, guest signal frames, host forwarding, interval timers, and
POSIX timers.

Unless explicitly marked i386, Linux syscall and signal-frame coverage here
refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`). Host and ABI
qualifications remain in [Status and limitations](../../reference/status-and-limitations.md#required-user-mode-qualifications).

## Exceptions to signals

x86-64 follows `arch/x86/kernel/traps.c` (`INT3`/`INTO` DPL-3 gates, other `INT n`
as #GP, #DE → `FPE_INTDIV`, #XM code from MXCSR), AArch64 `traps.c`/`fault.c` (`BRK`
→ `TRAP_BRKPT`, undefined and EL1-only accesses → `ILL_ILLOPC`), and RISC-V
`traps.c`.

## Signals

Generation, queueing, and delivery follow `kernel/signal.c`: per-thread and process
pending sets with the kernel's dequeue order (faults first, then the lowest number),
coalesced standard signals and queued real-time signals, ignore-at-generation,
`SIGCONT`/stop cancellation, forced synchronous signals, and default actions.
Delivery runs on every return to user mode and nests a frame for each deliverable
signal.

Frames are each architecture's `rt_sigframe`, byte for byte: x86-64 with the
64-byte-aligned XSAVE area, `_fpx_sw_bytes`, and `FP_XSTATE_MAGIC2`, and handlers
starting in the initial FPU state; AArch64 with the FP/SIMD record, the ESR record
after a fault, and the frame record; RV64 with the D registers and, on a core with
V, the vector record.

`rt_sigreturn` validates as the kernel does (x86 `XRSTOR` header and MXCSR checks,
arm64 `valid_user_regs` and record parsing, riscv extension headers). Interrupted
system calls return the internal restart codes, resolved per `SA_RESTART` as
`arch_do_signal_or_restart` does.

Handlers without `SA_RESTORER` (all RV64 handlers, AArch64 handlers that omit it)
return through a `[vdso]` page holding the vDSO's trampoline instructions.

### i386 frames

Implementation: `signal::frame::ia32`, `syscall::compat::signal`.

A handler installed by a 32-bit call is marked `SA_IA32_ABI`
(`sigaction_compat_abi`, never reported) and runs on an i386 frame
(`arch/x86/kernel/signal_32.c`): `struct sigframe_ia32` with `sigreturn`, or with
`SA_SIGINFO` `struct rt_sigframe_ia32` (a `struct compat_siginfo` and `struct
ucontext_ia32`) with `rt_sigreturn`. `get_sigframe` places it without a red zone
at the i386 function-entry alignment, `(frame + 4) % 16 == 0`, below a 112-byte
FSAVE header converted from the FXSAVE image (`convert_from_fxsr`: the full tag
word, the pointers' 32-bit offsets, `magic` 0) and the 64-bit frame's XSAVE area,
whose extended size counts the header; a stack segment other than `__USER_DS`
without `SA_RESTORER` switches to the `sa_restorer` stack, which must lie on the
alternate stack. The handler gets `-mregparm=3` arguments in EAX, EDX, and ECX,
DS, ES, and SS reloaded with `__USER_DS`, and CS `__USER32_CS`; without
`SA_RESTORER` it returns through `__kernel_sigreturn` or `__kernel_rt_sigreturn` in
a `[vdso]` page holding the `vdso32/sigreturn.S` instructions (no ELF vDSO or
`AT_SYSINFO` is provided).

The 32-bit returns restore EAX-EBP, ESP, and EIP zero-extended, the `FIX_EFLAGS`
bits, each data selector the handler changed (a selector that does not load becomes
null, as the kernel's fixup leaves it), and the FPU state with the FSAVE header
folded over the FXSAVE or XSAVE image (`convert_to_fxsr`: FOP from the upper half of
`fcs`, which is zero). The return to user mode checks the code and stack selectors
as `IRET` does: an invalid one raises `SIGSEGV` with the restored state and the
trap recorded, and a return to 64-bit mode (`__USER_CS`) is not provided.

On every ABI, a sigreturn that finds its frame bad after reading the frame's mask
keeps that mask (`set_current_blocked` precedes the register restore), then forces
`SIGSEGV`. A 32-bit call's result is sign-extended from its low half before restart
processing (`syscall_get_error`).

## Signal targeting

A signal is queued for a thread or for the process; `complete_signal` then wakes the
thread that should take it — the suggested thread if it wants it (unblocked, and
running or without a signal pending), else the next such thread from `curr_target` —
and a fatal signal without a core dump ends the process at once. A thread that
blocks a signal meant for it passes it on (`retarget_shared_pending`).

## Host signals

Implementation: `host::forward_host_signals`.

An async-signal-safe host handler records each forwardable signal and its `kill`
sender in atomics and writes a byte to a non-blocking close-on-exec wake pipe; the
personality turns them into process-directed Linux signals (`SI_USER` with the
sender, else `SI_KERNEL`) before every delivery and every wait.

Between `rax-user` processes the sender does not come from the host (`sigmail`): XNU
keeps a signal's `siginfo` in per-process fields that a child's exit overwrites (a
signal whose sender exits at once arrives as `CLD_EXITED`), and one that arrives
while the target is forking has none. So before its host `kill`, a `rax-user` sender
posts the target, signal, its PID, and its guest UID in a table shared by every
process forked from the first, and the target's handler claims the record; records
older than the target (a reused PID) or than two seconds (a duplicate a pending
signal absorbed) are ignored. A signal from another process keeps the host's report.

Signals that report an emulator failure (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`,
`SIGTRAP`, `SIGABRT`) keep their host dispositions. A guest killed by a signal
without a core dump ends `rax-user` with the same host signal.

## Timers and restarts

Implementation: `timers`.

`ITIMER_REAL` follows `kernel/time/itimer.c`: it re-arms only when its `SIGALRM` is
dequeued, at the next interval multiple after the last expiry, so a blocked
`SIGALRM` accumulates no expiries; the CPU-time timers add `TICK_NSEC` and re-arm at
expiry (`posix-cpu-timers.c`). Interrupted sleeps and `poll` save a `restart_block`
so `restart_syscall` resumes them with the remaining time; `select` and `poll` write
back the time left and `revents` as `poll_select_finish` and `do_sys_poll` do.

## POSIX timers

Implementation: `posix_timers`.

The state machine of `kernel/time/posix-timers.c` and `posix-cpu-timers.c` over
expiries in nanoseconds on a base clock (host wall-clock or monotonic time, or the
emulator's CPU time); relative `CLOCK_REALTIME` settings count on monotonic time, as
`common_hrtimer_arm` makes them. Expiry is found lazily: the scheduler passes the
time between slices (and sleeps no longer than the next wall-clock or monotonic
expiry), and an expired timer queues its one preallocated signal record, tagged with
the timer in the pending queue (`SIGQUEUE_PREALLOC`).

A periodic timer stays stopped until that record is dequeued
(`__posixtimer_deliver_signal`), then moves forward past now by whole periods
(`hrtimer_forward`), which become the signal's overrun count; a setting or deletion
since the signal was queued makes the dequeue drop it and take the next signal.

An ignored periodic signal is parked and queued again when a handler replaces
`SIG_IGN` (`posixtimer_sig_unignore`). `execve` deletes the timers and every queued
`SI_TIMER` record (`exit_itimers`, `flush_itimer_signals`); a forked child has none.

## Evidence and related contracts

[Linux signals and timers tests](../../development/testing/user-mode.md#signals-and-timers)
record the unit, differential, and host-specific evidence for these contracts.

See also [Linux processes and scheduling](processes.md).
