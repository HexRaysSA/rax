[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Linux process tracing and seccomp

Tracer links, stops, register sets, stepping, process events, and syscall filtering.

Unless explicitly marked i386, Linux syscall and signal-frame coverage here
refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`). Host and ABI
qualifications remain in [Status and limitations](../../reference/status-and-limitations.md#required-user-mode-qualifications).

## Process tracing

Implementation: `ptrace`: the tracee's side in `ptrace::tracee`, the tracer's
requests in `syscall::ptrace`.

A tracer and its tracee are separate host processes, joined by the link each `fork`
makes between parent and child (an `AF_UNIX` stream pair carrying framed messages):
a process traces its children or its parent along them, and the processes its
tracees fork along links passed to it, and any other process is out of reach
(`EPERM`).

### Memory and register requests

The tracee carries out its tracer's requests on its own memory and registers
(`PEEKDATA` and `POKEDATA` through the permission-ignoring path that keeps code
caches coherent, the general registers as each architecture's `ptrace.h` lays them
out and its `ptrace.c` checks them, `struct user` on x86-64, siginfo, signal masks,
options), and the tracer sleeps until the answer comes.

### Signal stops and tracer lifetime

A traced thread stops before taking any signal but `SIGKILL` (its process's other
threads run on), as a group stop when a stop signal's default action would stop it,
and after `execve` (`SIGTRAP`, or the `PTRACE_EVENT_EXEC` stop); the tracer learns
of each stop from the link, reports it from `wait` without `WUNTRACED` and with
`SIGCHLD` (`CLD_TRAPPED`), and resumes the thread with a signal the thread then
takes as `ptrace_signal` does. A stop undoes the provisional system-call restart, so
the tracer sees the call as it ended. Signals a traced thread ignores are queued,
and a fatal one does not end the process before the tracer sees it. A link that ends
detaches its tracees (with `PTRACE_O_EXITKILL`, kills them). A tracer records a
tracee as its attach goes out and keeps answers that arrive with a link's end, since
a tracee stops as soon as it answers an attach and may die as soon as it answers a
request.

### System-call stops

System-call stops (`ptrace::stops`) follow each architecture's entry path and the
generic `syscall_trace_enter` and `syscall_exit_work`: under `PTRACE_SYSCALL` or
`PTRACE_SYSEMU` a thread stops as a call enters, before seccomp, with x86-64's `rax`
and RISC-V's `a0` already `-ENOSYS` and AArch64's `x7` showing the direction; once
resumed, the call is made with the number and arguments its registers then hold (-1,
or on RISC-V any number outside the table, skips it and keeps the result register,
as does a stop under `PTRACE_SYSEMU`, whose flags are the ones read before the
stop), and under `PTRACE_SYSCALL` it stops again as the call finishes, before the
restart and signal delivery (an `execve`'s event stop comes first). The signal a
system-call stop is resumed with is sent from the kernel (`SI_KERNEL`; a tracer's
end at a stop without `PTRACE_O_TRACESYSGOOD` sends `SIGTRAP`).

### System-call inspection

`PTRACE_GET_SYSCALL_INFO` and `PTRACE_SET_SYSCALL_INFO` read and write the call
through `ptrace::call` (each architecture's `asm/syscall.h`), and AArch64's
`NT_ARM_SYSTEM_CALL` holds its number.

### Single-step

A stepping thread runs one instruction at a time (x86-64 through the core's precise
step, never native code), then takes `SIGTRAP` (`TRAP_TRACE`); a stepped system call
reports as it finishes (x86-64's `TRAP_BRKPT`, AArch64's generic `SI_USER`), and
entering a handler stops before its first instruction. RISC-V has neither
`PTRACE_SYSEMU` nor stepping (`EIO`).

### Block-step

x86-64 alone block-steps (`PTRACE_SINGLEBLOCK`, `EIO` elsewhere): the thread still
runs one instruction at a time, and traps only after one that branches, as
`DEBUGCTL.BTF` makes the processor do. Before each instruction its bytes and the
state before it decide (`user::cpu::x86_64::branch`): `JMP`, `CALL`, `RET`, `IRET`,
the `FF /2`..`/5` forms, and APX `JMPABS` always branch; `Jcc`, `LOOP*`, and `JRCXZ`
when their condition holds, even to the next instruction.

### Register sets

The register sets beyond the general ones are laid out as each architecture's kernel
lays them out: the floating-point registers (`NT_PRFPREG`: x86-64's `FXSAVE` area,
which `xfpregs_set` takes whole and with a valid MXCSR only, and which
`PTRACE_GETFPREGS` also reads; AArch64's `struct user_fpsimd_state` and RISC-V's
`struct __riscv_d_ext_state`, which take a prefix), x86-64's XSAVE area
(`NT_X86_XSTATE`, with `xstate_fx_sw_bytes`, written whole or `EFAULT`), and
AArch64's `NT_ARM_TLS`; x86-64's `PTRACE_ARCH_PRCTL` sets and reads the tracee's
segment bases. x86-64's I/O permission bitmap (`NT_386_IOPERM`: `ENXIO`, no writer)
and shadow-stack pointer (`NT_X86_SHSTK`: `ENODEV`) have no contents here, as
`ioperm` is refused and the CPU has no user shadow stacks. A read's error comes
before its copy out, and a write's refusal before its buffer counts, where
`copy_regset_to_user` and `copy_regset_from_user` put them.

### Pending signals and rseq queries

`PTRACE_PEEKSIGINFO` walks the thread's or the process's queue of pending records in
order, and `PTRACE_GET_RSEQ_CONFIGURATION` reports the thread's rseq registration.

### Job control

Job control follows `do_signal_stop` and `do_jobctl_trap`: a traced thread that
takes a stop signal's default action begins its process's group stop (the other
traced threads join it) and traps, a seized thread with `PTRACE_EVENT_STOP` and the
stop's signal, an attached one with the signal alone; the tracer's `SIGCHLD` says
`CLD_STOPPED` for these traps and `CLD_TRAPPED` for every other stop.
`PTRACE_INTERRUPT` makes a seized thread trap (a sleeping call ends and is restarted
after), and `PTRACE_LISTEN` keeps a thread in a `PTRACE_EVENT_STOP` trap stopped and
out of its tracer's sight until `PTRACE_INTERRUPT` or a job-control change traps it
again: `SIGCONT` ends the group stop and makes every seized thread trap. `SIGSTOP`
to a child or to the parent travels along their link, since the host would stop the
receiving host process outright.

### Thread, exit, and seccomp events

Events: with `PTRACE_O_TRACECLONE` (or `CLONE_PTRACE`) a new thread is traced as its
maker is, starting with `SIGSTOP` (a trap when seized), its tracer is told of it,
and the maker stops with `PTRACE_EVENT_CLONE` before its exit stop; with
`PTRACE_O_TRACEEXIT` an exiting thread stops first (`exit`, `exit_group` once the
other threads are gone, a fatal signal other than `SIGKILL`), finishing its exit
once resumed; with `PTRACE_O_TRACESECCOMP`, `SECCOMP_RET_TRACE` stops the thread and
the call is looked at again with the registers the tracer left (skipped for a
negative number). Every traced call shows its architecture's entry view (`-ENOSYS`
in x86-64's `rax` and RISC-V's `a0`) at any stop inside it. A tracer reaps the
traced threads that exit, with the group's status once the group began to exit.

### Fork and vfork events

With `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACEVFORK`, or `PTRACE_O_TRACECLONE`
(whichever `kernel_clone` picks: `CLONE_VFORK`, then an exit signal other than
`SIGCHLD`), or with `CLONE_PTRACE`, a forked process is traced as its forker is: the
forker makes a new link and passes its tracer that end (`SCM_RIGHTS`) before the
fork's event stop (the new PID as the message), and the new process, along its end,
starts with `SIGSTOP` (a trap when seized). A `vfork` stops for its event before it
sleeps (a stopped thread's sleep ends only once it is resumed) and for
`PTRACE_EVENT_VFORK_DONE` after. The tracer reaps the new tracee when it exits; the
real parent, a separate host process, learns of that exit from the host as it
happens rather than once the tracer has reaped it (`wait_task_zombie`'s
`EXIT_TRACE`).

### Seccomp suspension and filter queries

As on a kernel with checkpoint and restore, a tracer holding `CAP_SYS_ADMIN` (root)
and under no seccomp of its own may suspend its tracee's seccomp
(`PTRACE_O_SUSPEND_SECCOMP`: no mode or filter is checked while the option is set)
and read the tracee's filters (`PTRACE_SECCOMP_GET_FILTER`: a filter's classic BPF
as installed, counted from the oldest; `PTRACE_SECCOMP_GET_METADATA`: its
`SECCOMP_FILTER_FLAG_LOG`); any other tracer is refused (`EPERM`, `EACCES`).

## Seccomp

Implementation: `seccomp`, `syscall::seccomp`.

Each thread has a mode and a chain of classic BPF filters, newest first, shared with
the threads and processes that inherited it (`clone` and `fork` copy it, `execve`
keeps it, `SECCOMP_FILTER_FLAG_TSYNC` gives the caller's chain to every thread whose
own chain it extends).

A filter must pass `bpf_check_classic` and `seccomp_check_filter`, and a chain is
bounded by its length as `bpf_convert_filter` converts it to eBPF (each return of a
constant two instructions, a division by `X` five, a conditional jump one or two,
and a three-instruction prologue), as the kernel bounds it.

A call is checked when it enters (a call that slept is not checked again when it
runs on), before its handler: the filters run over its `struct seccomp_data`
(number, `AUDIT_ARCH_*`, the address after the calling instruction, arguments), the
action ranking lowest wins (the newest filter's on a tie), and it is decided as
`__seccomp_filter` decides it: an errno (capped at 4095), `SIGSYS` with
`SYS_SECCOMP` and the registers untouched, the thread's death (alone while others
live) or the process's by `SIGSYS`, or `ENOSYS` for a tracer or listener that cannot
exist.

Strict mode allows `read`, `write`, `exit`, and `rt_sigreturn` and kills the thread
alone with `SIGKILL`; on x86-64 it also sets `TIF_NOTSC`, as `PR_SET_TSC` does,
which is the thread's CR4.TSD, so `RDTSC` and `RDTSCP` fault with `SIGSEGV` on every
execution path. x86-64 `INT 0x80` calls are checked as `AUDIT_ARCH_I386` ones.
`no_new_privs` is a thread's, as in Linux.

## Evidence and related contracts

[Linux process tracing and seccomp tests](../../development/testing/user-mode.md#tracing-and-seccomp)
record the unit, differential, and host-specific evidence for these contracts.

Guest ptrace is distinct from the machine GDB interface; see
[Observability](../../operations/observability.md#linux-process-observability).
