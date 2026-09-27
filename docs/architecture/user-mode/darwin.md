[← User-mode emulation](../user-mode.md)

# Darwin (macOS) personality

`user::darwin` runs macOS user-space programs for x86-64 and arm64 on RAX's
software CPUs. `rax-user` selects it for a Mach-O or fat executable; the
program runs against the host's `dyld`, dyld shared cache, and system
libraries (or a guest root given with `--sysroot`), so its user space is
the host's macOS release.

```text
rax-user --arch arm64 /bin/echo hello
rax-user --arch x86_64 ./program args...
```

## Behavior references

The kernel behavior reproduced is XNU 12377.121.6
([provenance](../../specifications/darwin/xnu-12377.121.6.provenance.md)),
with dyld 1378, libpthread 539.100.4, and Libc 1752.120.2 for the user-side
contracts the kernel serves. The user space the programs run is newer
(macOS 27, kernel `xnu-13432`, unpublished). Where that kernel's published
interface extends an XNU 12377 structure, the personality follows the SDK
([macOS 27.0 SDK headers](../../specifications/darwin/MacOSX27.0.sdk.provenance.md))
and says so next to the implementation. The native kernel is the test
oracle (see [Evidence](#evidence)).

## Process construction

`DarwinProcess::spawn` does what `exec_mach_imgact` and `load_machfile` do
for a first program:

| Step | Module | XNU counterpart |
|---|---|---|
| Fat slice choice and grading (arm64e host grades on Apple silicon, x86_64h on Intel) | `user::image::macho` | `exec_fat_imgact`, `fatfile_getbestarch` |
| Segment mapping, page zero, entry point, `LC_UNIXTHREAD`/`LC_MAIN` | `user::image::macho`, `loader` | `parse_machfile`, `load_segment` |
| `dyld` mapping above the image | `loader` | `load_dylinker` |
| Stack (64 MiB `MAXSSIZ` reservation, `DFLSSIZ` limit, guard) and strings | `stack`, `loader` | `create_unix_stack`, `exec_copyout_strings` |
| `apple[]` strings (`executable_path`, entropy, `ptr_munge`, `th_port`, ...) | `loader` | `exec_add_apple_strings` |
| Commpage (x86-64 at `0x7fffffe00000`; arm64 read-only and read-write pages) | `commpage` | `commpage_populate` |
| Task and thread ports: thread `0x103`, task `0x203` | `process` | `ipc_task_enable`, `thread_self` |

Address-space layout randomization is disabled: slides are zero and `dyld`
maps the shared cache at its unslid address.

## Kernel entry

| ISA | Entry | Selector | Arguments | Error |
|---|---|---|---|---|
| x86-64 | `SYSCALL` | class in `RAX[31:24]` (1 Mach, 2 BSD, 3 machine-dependent, 4 diagnostics), number below | `RDI RSI RDX R10 R8 R9`, then the stack | `CF` set, `RAX` = errno |
| arm64 | `SVC #0x80` | `X16`: positive BSD, negative Mach trap, `0x80000000` platform call | `X0`-`X7` | `C` set, `X0` = errno |

`syscall::dispatch` routes BSD calls by number through the table generated
from `bsd/kern/syscalls.master` (`abi::tables`, `tools/darwin/gen_abi.py`),
Mach traps through the table generated from `osfmk/kern/syscall_sw.c`, and
the machine-dependent calls (thread pointers: `thread_fast_set_cthread_self64`
on x86-64, `TPIDRRO_EL0` on arm64). Results follow each call's
`sy_return_type`. A call that must sleep records a `Wait` and returns
`ERESTART`, which backs the PC up over the trap so the call runs again when
its thread wakes; all guest threads run on one host thread (one emulated
CPU, `hw.ncpu` = 1).

## Mach IPC

| Area | Module | XNU counterpart |
|---|---|---|
| Name space: names `(index << 8) \| generation`, rights and user references, dead names, port sets, dead-name and port-deleted requests | `mach::ipc` | `ipc_entry.c`, `ipc_right.c`, `ipc_object.c` |
| Messages in transit, descriptors, trailers | `mach::msg` | `ipc_kmsg.c` |
| `mach_msg2_trap` and the legacy traps: vectors, send and receive options, queue limits, timeouts, `MACH_RCV_LARGE`, pseudo-receive of failed sends | `syscall::mach::msg` | `mach_msg.c`, `ipc_mqueue.c` |
| Copy-in and copy-out of header and body rights, out-of-line memory and port arrays, guarded descriptors; no-senders, send-once, dead-name, port-destroyed, and send-possible notifications | `syscall::mach::kmsg` | `ipc_kmsg.c`, `ipc_notify.c`, `ipc_port.c` |
| `_kernelrpc_mach_port_*` traps and the `mach_port` routines | `syscall::mach::port`, `mig::port` | `mach_port.c`, `mach_kernelrpc.c` |
| Port guards: the guard is the port's context; misuse of a guarded or immovable port is a fatal `EXC_GUARD` (`SIGKILL`) | `syscall::mach::guard` | `mach_port_guard_exception` |
| Semaphores and `__semwait_signal` | `syscall::mach::sync` | `sync_sema.c`, `kern_sig.c` |

Kernel objects (task, thread, host, clock, semaphore ports) answer messages
through MIG servers (`mig`), dispatched by message ID from the table
`tools/darwin/gen_mig.py` generates from the vendored `.defs` files. The
servers check request layouts as MIG's generated code does and build the
same replies: `host` (`host_info`, statistics, clock services, kernel
version, page size), `task` (`task_info`, special and exception ports,
threads, semaphores, policies, restartable ranges, dyld registration),
`thread_act` (`thread_info`, policies, exception ports, suspension),
`mach_vm`/`vm_map` (allocation, protection, regions, reads and writes), and
`clock`.

## Memory

Mach VM calls and `mmap` share one VMA map with the Mach attributes (maximum
protection, inheritance, user tag) in each VMA's personality flags
(`vm::VmFlags`). `shared_region_map_and_slide_2_np` maps the dyld shared
cache from the host's cache files; slid mappings (slide info v2 and v5) are
rebased page by page on first touch, as XNU's shared-region pager does.

## Emulated machine

One CPU of the program's architecture: a Haswell-class Intel Mac for x86-64
(`CPU_SUBTYPE_X86_64_H`), an Apple-silicon Mac for arm64 (`CPU_SUBTYPE_ARM64E`;
the implementation's pointer-authentication algorithm is the identity), with
16 GiB of memory. Mach absolute time, uptime, and `kern.boottime` share one
clock that starts with the emulator. Process identity (pid, credentials,
audit token) is the host process's.

## Status

Single-threaded programs linked against libSystem run on both
architectures: `dyld` and libSystem initialization, file and path calls,
memory calls, `sysctl`, Mach messaging with the kernel servers above,
semaphores and sleeping. Not yet implemented, and answered with `ENOSYS`
(or `KERN_FAILURE` / `MIG_BAD_ID` for Mach) with a warning under `--strace`
or `RAX_DARWIN_WARN`: thread creation (`bsdthread_create`, work queues),
`kqueue`/`kevent`, `psynch` synchronization, signal handler delivery and
`sigreturn`, `fork`/`execve`/`posix_spawn`, sockets, `proc_info`, and
exception delivery to Mach exception ports.

## Evidence

`cargo test --no-default-features --features x86_64-suite,smir-jit --test user_darwin`

- `fixtures`: the C programs in `tests/fixtures/user/darwin/src` are built
  for arm64 and x86_64 and must produce the standard output and exit status
  of their native runs (x86_64 through Rosetta), including the fatal
  `EXC_GUARD` of `guard_fatal`.
- `programs`: `/bin/echo`, `/usr/bin/true`, `/usr/bin/false`, and `/bin/cat`
  likewise.
- `generators`: the checked-in tables equal what the generators produce
  from the vendored sources (`--check`).

Without a macOS host (or without Rosetta, for x86_64) the comparisons have
no oracle and report themselves skipped. Library tests under
`src/user/darwin/` cover the name space, message trailers, commpage and
stack layout, slide info, sysctl nodes, and the host-information flavors.
