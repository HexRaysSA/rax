[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Linux processes and scheduling

Guest threads, child processes, waits, pidfds, futexes, scheduling state, and
restartable sequences.

Unless explicitly marked i386, Linux syscall and signal-frame coverage here
refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`). Host and ABI
qualifications remain in [Status and limitations](../../reference/status-and-limitations.md#required-user-mode-qualifications).

## Threads and scheduling

Implementation: `sched`.

The process's threads run round-robin on the one emulated CPU: a thread keeps the
CPU until its slice ends, it sleeps in a system call, it yields, or it exits.
`clone`/`clone3` follow `copy_process` and each architecture's `copy_thread` (return
value 0, stack, `CLONE_SETTLS`, a cleared alternate stack, RV64 vector state
cleared, `CLONE_*_SETTID` and `CLONE_CHILD_CLEARTID` words, the arm64/riscv
`CONFIG_CLONE_BACKWARDS` argument order).

Thread exit follows `do_exit`: process signals meant for the thread go to others
(`exit_signals`), the robust list is walked and PI futexes handed on
(`futex_exit_release`), and the `clear_child_tid` word is cleared and woken
(`mm_release`); the last thread's code becomes the process's
(`synchronize_group_exit`).

## Sleeping in system calls

Implementation: `wait`.

A call that must sleep records what ends the wait (descriptors, a deadline, another
thread's event such as `FUTEX_WAKE`) and its progress, and its thread is parked
instead of blocking the host. When the wait can end — or, for an interruptible wait,
a signal is sent to the thread (`TIF_SIGPENDING`) — the call is dispatched again
with its record and re-evaluates its condition in the kernel's order: as in
`do_poll` and `pipe_read`, a ready descriptor before a pending signal, a signal
before the deadline.

When every thread sleeps the host waits in `poll` on their descriptors, the
host-signal wake pipe, and the nearest deadline; a wait nothing can end ends the
process with a diagnostic. Pipes the guest creates are non-blocking on the host, so
one thread's transfer never stops the others.

## Processes

Implementation: `children`, `exec`.

A new process forks the host process: the child continues the guest child with a
copy of the address space and descriptor table, one thread, and no pending signals
or interval timers (`copy_process`). It reports to its parent through a status pipe
— `E` when a `CLONE_VFORK` child calls `execve`, `X` with the Linux wait status when
it ends, which the host's exit status cannot express — and ends the host process
itself, so a forked child never returns to the embedder.

The parent watches its children through the host `SIGCHLD`, keeps exited ones as
zombies for `wait4`/`waitid` (`wait_task_zombie`, `wait_task_stopped`,
`wait_task_continued`), and generates the guest's `SIGCHLD` as `do_notify_parent`
does.

The forwarded host signals stay blocked across the host `fork` until each process
has set up its own records, so a signal sent to a child the moment it exists is not
lost, and the child discards the compiled native code it inherited and compiles it
again (on Apple-Silicon macOS hosts, JIT code inherited across the host `fork`
intermittently faults on its first execution).

`execve` builds a complete new image (`exec::load_image`, shared with the initial
program) before replacing anything, so an error leaves the caller intact, then does
what the point of no return does (`commit_exec`).

## Pidfds

Implementation: `fs::pidfd`, `syscall::pidfd`.

A pidfd is an anonymous-inode file of `pidfs` (mode `0700` without a file type,
owned by root, one inode per task, `anon_inode:[pidfd]` in `/proc/<pid>/fd`) naming
a task by its process's host PID and its thread ID. What it reports depends on where
the task lives. A thread of the calling process and a child of it are known exactly
from the process's own records; a thread's exit and a child's reaping reach every
pidfd of it through the process's registry of its pidfds' tasks (as `pidfs_exit`
does), with the wait status, and wake threads sleeping in `poll`, `select`, or
`epoll`.

Any other process is watched through the host from the moment the pidfd is made (a
host pidfd on Linux, a kqueue with an `EVFILT_PROC` filter on macOS), so a PID the
host reuses is never taken for it; it is gone once it exits, since only its parent's
records know its zombie. A forked child watches the tasks of the pidfds it inherits
the same way from the fork on (a kqueue does not survive `fork`), and a task that
had the child's new PID is gone.

`pidfd_send_signal` finds the task by its ID and directs the signal at it or at its
thread group through the paths of `tgkill` and `kill`; `waitid(P_PIDFD)` selects the
child a pidfd names, `WNOHANG` and then `EAGAIN` for a non-blocking pidfd;
`CLONE_PIDFD` checks the free descriptor and the result word before the task exists,
so neither failure leaves a task behind.

## Futexes

Implementation: `futex`.

FIFO wait queues keyed as `get_futex_key` keys them (private and shared keys never
match), with `futex_wake`'s count rule, requeue and wake-op counting, PI ownership
words (`FUTEX_WAITERS`, `FUTEX_OWNER_DIED`, hand-over to the first waiter on unlock
or owner exit), `futex_waitv`, and the `futex2` calls; a woken wait returns 0
whatever else happened, as `futex_unqueue` reports.

## Scheduling attributes

Implementation: `priority`, `syscall::priority`.

Each thread carries the kernel's scheduling state: policy, static, normal, and
effective priorities, real-time priority, `reset_on_fork`, the fair slice, deadline
parameters, timer slack, and its I/O context, which the threads that `CLONE_IO` made
share (a priority set through one is all of theirs; a `CLONE_IO` child process gets
its own copy). The calls change and report it with `__sched_setscheduler`'s checks
and permission rules (`RLIMIT_NICE`, `RLIMIT_RTPRIO`, `CAP_SYS_NICE` being root),
`sched_fork` applies it to new threads and processes, and `/proc/<pid>/stat` shows
it; nothing is scheduled by it, the threads sharing one emulated CPU.

The kernel modelled has one CPU (a 700 µs base slice), `CONFIG_HZ=250`, no
utilization clamping, and no `SCHED_EXT`; deadline tasks are admitted within 95% of
the CPU less the fair server's 5%. A task is named by a thread of the calling
process; another process's tasks are not reachable, except that root always has some
(`init`), which another user's `ioprio_set` may not change.

## Restartable sequences

Implementation: `rseq`, `syscall::rseq`.

A thread's registration lives with it (not inherited by new threads, kept by a
forked child, dropped by `execve`). Each thread records whether it last left user
mode through a preemption at the end of its slice or a fault (the generic IRQ
entry's `user_irq`) or through a system call, and the scheduler notes when another
thread ran in between (a context switch).

The return to user mode then writes the IDs when due (after registration; on arm64
at every switch, as its slow path does) and, for an interrupted thread, checks the
critical section `rseq_cs` names: inside it the thread resumes at the abort handler,
whose preceding word must be the signature; outside it `rseq_cs` is only cleared.

Signal delivery to an interrupted thread does the same before the handler's frame
saves the instruction pointer. A bad descriptor, a fault, or a wrong signature
forces `SIGSEGV`. The emulated CPU is CPU 0 of node 0.

## Evidence and related contracts

[Linux processes and scheduling tests](../../development/testing/user-mode.md#processes-and-scheduling)
record the unit, differential, and host-specific evidence for these contracts.

See also [Linux signals and timers](signals.md).
