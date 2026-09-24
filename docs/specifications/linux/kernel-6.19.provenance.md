# Linux 6.19 kernel sources provenance

- Canonical title: Linux kernel source tree, selected files
- Issuing organization: the Linux kernel project
- Revision: tag `v6.19`
- Source URL: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
  (tag `v6.19`); files were retrieved from the GitHub mirror
  `https://raw.githubusercontent.com/torvalds/linux/v6.19/<path>`, which serves
  the same tagged tree.
- Retrieved: 24 September 2026
- Integrity: `kernel-6.19.sha256` lists the SHA-256 of every imported file,
  relative to `kernel-6.19/`.
- License: each file carries an SPDX identifier: `GPL-2.0` (35 files),
  `GPL-2.0-only` (21), `GPL-2.0-or-later` (10), `GPL-2.0+` (1), or
  `GPL-1.0+` (1). The license texts are the kernel tree's `LICENSES/preferred/GPL-2.0`
  and `LICENSES/deprecated/GPL-1.0`. The files are reference material for an
  independent implementation; no RAX source is derived from their text.

Paths under `kernel-6.19/` mirror the kernel tree. The files are reference
inputs; do not reformat or edit them. To move to a newer kernel, import a
complete new `kernel-<version>/` tree with its own provenance record.

## Use in RAX

The `rax-user` Linux personality (`src/user/linux/`) implements the Linux
system-call ABI for emulated user-space programs. These files define the
behavior it reproduces beyond what the UAPI headers
(`uapi-6.19.provenance.md`) specify:

| Area | Files |
|---|---|
| `execve` loading, initial stack, auxiliary vector | `fs/binfmt_elf.c`, `fs/exec.c`, `arch/{x86,arm64,riscv}/include/asm/elf.h` |
| Address-space layout | `mm/util.c` (`mmap_base`), `arch/x86/mm/mmap.c`, `arch/x86/include/asm/page_64_types.h`, `arch/arm64/include/asm/processor.h`, `arch/riscv/include/asm/{processor,pgtable}.h` |
| Memory-management system calls | `mm/mmap.c`, `mm/vma.c`, `mm/mprotect.c`, `mm/madvise.c`, `mm/mremap.c`, `arch/arm64/include/asm/mman.h` |
| Signal generation, queueing, and delivery | `kernel/signal.c`, `include/linux/signal.h`, `include/linux/signal_types.h`, `include/linux/sched/signal.h`, `kernel/entry/common.c`, `include/linux/entry-common.h` |
| Signal frames and `rt_sigreturn` | `arch/x86/kernel/signal.c`, `arch/x86/kernel/signal_64.c`, `arch/x86/kernel/fpu/{signal.c,core.c,xstate.c,xstate.h}`, `arch/x86/include/asm/sighandling.h`, `arch/x86/include/asm/fpu/{signal.h,types.h,xstate.h}`, `arch/arm64/kernel/signal.c`, `arch/arm64/kernel/ptrace.c`, `arch/arm64/include/asm/ptrace.h`, `arch/arm64/kernel/vdso/sigreturn.S`, `arch/riscv/kernel/signal.c`, `arch/riscv/kernel/vdso/rt_sigreturn.S` |
| Sleeping, timers, and restarts | `kernel/time/hrtimer.c`, `kernel/time/itimer.c`, `kernel/time/posix-timers.c`, `kernel/time/posix-cpu-timers.c`, `kernel/time/alarmtimer.c`, `kernel/time/time.c`, `include/linux/restart_block.h` |
| Blocking I/O, `poll`, and `select` | `fs/select.c`, `fs/pipe.c`, `drivers/tty/n_tty.c` |
| Threads: creation, exit, and scheduling | `kernel/fork.c`, `kernel/exit.c`, `include/linux/sched/task.h`, `kernel/sched/syscalls.c` (`sched_yield`), `arch/x86/kernel/{process.c,process_64.c}`, `arch/arm64/kernel/process.c`, `arch/riscv/kernel/process.c` (`copy_thread`) |
| Futexes and robust lists | `kernel/futex/{core.c,futex.h,syscalls.c,waitwake.c,requeue.c,pi.c}` |
| Process attributes | `kernel/sys.c`, `kernel/exec_domain.c` (`personality`) |
| Synthesized `/proc` | `fs/proc/base.c`, `fs/proc/array.c`, `fs/proc/task_mmu.c` |

Code comments name the kernel function whose behavior an implementation
follows (for example `do_mprotect_pkey` or `madvise_walk_vmas`); that
function is in one of these files.
