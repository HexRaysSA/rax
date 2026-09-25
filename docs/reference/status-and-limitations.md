[← Documentation home](../../README.md)

# Status and limitations

This page consolidates the current project boundary. It is intentionally conservative: source presence, a parser accepting a selector, a unit test, a differential corpus, a boot milestone, and production support are different statuses.

## Status vocabulary

| Term | Required evidence |
|---|---|
| **Present** | Source exists. No execution claim follows. |
| **Constructible** | Public configuration can instantiate the path on an appropriate build. |
| **Unit-tested** | A repository test directly exercises the behavior. |
| **Differential-tested** | Selected cases compare defined state with a named external reference. |
| **Machine-tested** | A registered test reaches a named machine/boot milestone. |
| **Boot-demonstrated** | A named image/configuration reached a named guest milestone. |
| **Benchmarked** | Host, compiler, features, workload, run method, and result are recorded. |
| **Supported** | Maintainers intend users to rely on the documented combination and maintain its contract. |
| **Complete** | Avoid unless a finite scope and exhaustive evidence are stated. |

## High-level execution matrix

| Guest | Software execution | Hardware backend | Machine-level result | Principal evidence | Current boundary |
|---|---|---|---|---|---|
| x86-64 | interpreter plus admitted SMIR native regions | KVM on Linux x86-64; HVF on appropriate Intel macOS path | direct Linux boot, legacy real-mode/ISO path, PC platform | direct ISA tests, KVM/QEMU differential targets, generated inventories, JIT equivalence tests, machine tests | one executing vCPU; software Linux and JIT coverage are narrower than the architecture as a whole |
| AArch64 | interpreter plus native-lowering paths | HVF on Apple Silicon | AArch64 Linux virtual machine | native EL0 or QEMU differential tests, generated Arm data, machine boot, SMIR tests | advanced extension breadth is not equivalent to full system/profile conformance |
| AArch32/Thumb | software cores and profile-specific machines | none documented as a general backend | machine-specific paths including Cortex-M and SoC work | direct ISA tests, QEMU/ASL-derived cases, microkernel | no general 32-bit Linux-to-shell result |
| Hexagon | packet-aware software emulator | none | bare-metal ELF machine | scalar/control/float/memory/HVX differential targets plus bare-metal test | public ISA selector ends at `v69`; no general OS machine |
| RV64 | software emulator plus selected SMIR/native paths | none | bare-metal ELF machine | scalar/vector QEMU differential tests, lift/JIT tests, boot test | no privileged/Sv39 Linux-capable machine |

## x86-64 status

### Established x86-64 surfaces

- legacy, REX, VEX, EVEX, and REX2/APX-oriented decode structures are present;
- broad integer, flag, control-flow, system, x87, SSE/AVX, AVX-512, AVX10, crypto, and state-management implementation exists;
- x87 instructions execute on exact binary80 registers, with precision and rounding control, exception flags, masked responses, and stack faults, through one implementation shared by the direct engine and SMIR;
- the software machine has a serial-oriented PC platform and direct Linux loading;
- KVM provides a hardware-backed x86 execution path on suitable Linux hosts;
- the real-mode/El Torito/ATAPI route has a named TempleOS demonstration and a registered real-mode machine test;
- x86-64-host and AArch64-host SMIR paths exist with different admission contracts.

### Required x86-64 qualifications

- No prose inventory is the authoritative instruction list. Decoder dispatch, execution source, generated manifests, and executable tests must agree.
- KVM differential results apply only to cases that actually execute on the host CPU and to the compared state projection.
- APX cannot be described as hardware-verified in this repository setup; encoding and semantic checks use LLVM/documentation-oriented evidence.
- The software Linux path is known against constrained kernels and command lines; it is not equivalent to arbitrary KVM boot compatibility.
- One vCPU executes.
- VGA is not a generally usable wired console; serial is the maintained interface.
- Optional PCI interrupts and guest-driver behavior remain narrower than a production PC hypervisor.

## Arm status

### Public Arm families and selectors

CLI architecture families:

```text
aarch64
armv7a
armv8a32
cortex-m
cortex-r
```

TOML exposes profile selectors for AArch64, AArch32, Cortex-M, and Cortex-R. The selector names describe intended architectural profiles; they do not prove every optional feature named by an Arm revision is implemented.

### Established Arm surfaces

- AArch64 scalar/system, floating-point/AdvSIMD, SVE-family, crypto, and modern extension code is present;
- AArch32 and Thumb execution is present across application, microcontroller, and real-time profiles;
- the AArch64 virtual machine boots the checked-in Linux image through the software backend and can use HVF on Apple Silicon;
- native AArch64 EL0 and QEMU user-mode differential paths exist;
- generated architecture cases and SMIR lowerer tests provide additional coverage;
- machine-specific S3C64xx/S3C6410 and S5L8900 work exists.

### Required Arm qualifications

- AArch64 Linux success does not imply AArch32 Linux success.
- A selector such as `v9_4` is a configuration value, not proof of complete Armv9.4-A/SME2 system conformance.
- QEMU or native EL0 user-mode comparisons do not exercise all privileged state, exception levels, MMU behavior, interrupts, or devices.
- SVE/SVE2 implementation breadth must be stated with the tested vector lengths, operations, predicates, exception behavior, and reference.
- SoC source and early boot progress must be described by exact image and milestone, not as general device/platform support.

## Hexagon status

### Established Hexagon surfaces

- packet decode/execute state and `.new`-style packet dependencies are modeled;
- scalar, control-flow, floating-point, memory, HVX, and HVX-memory test domains are separate registered targets;
- a bare-metal ELF machine with UART/halt behavior exists;
- Hexagon-to-SMIR lifting has a registered test target.

### Required Hexagon qualifications

- The public selector is `v4` through `v69`, with selected intermediate revisions and `v68` default. The older README’s `V73` claim conflicts with that interface and must not be repeated without implementation/interface changes.
- “Every opcode” is not an acceptable unqualified status. A finite decoder manifest, generation source, revision, packet forms, HVX width, reference version, and number of executed cases would be required.
- QEMU comparison inherits QEMU’s supported revision and semantics and can self-skip if the toolchain is unavailable.
- No general-purpose operating-system machine is documented.

## RISC-V status

### Established RISC-V surfaces

- RV64 scalar, compressed, atomic, floating-point, bit manipulation, crypto, and vector implementation exists;
- a bare-metal `riscv64` machine loads programs and provides UART/halt integration;
- scalar and vector QEMU differential targets are registered;
- SMIR lift and host-specific native tests are registered.

### Required RISC-V qualifications

- Extension names in source or old prose do not replace an exact, generated, tested extension matrix.
- The runnable machine does not provide a complete privileged architecture or Sv39 Linux platform.
- Vector comparison must state VLEN/ELEN assumptions, tested LMUL/SEW combinations, masking/tail policy, exception behavior, and QEMU version when claiming breadth.
- Native tests are host-specific and may self-gate.

## User-mode (Linux program) status

`rax-user` runs Linux ELF programs for x86-64, AArch64, and RV64 on Unix
hosts ([usage](../getting-started/linux-programs.md),
[architecture](../architecture/user-mode.md)).

### Established user-mode surfaces

- `binfmt_elf`-equivalent loading, initial stack, and auxiliary vector (unit-tested against hand-derived kernel layouts);
- exact page-permission enforcement and Linux fault classification (unit-tested, including a model-based differential);
- 261 system calls across descriptors, paths (with device and FIFO nodes, file times, extended attributes, and file locks), memory management, identity (with supplementary groups), limits, clocks, timers, signals, threads, futexes, processes, pidfds, POSIX timers, event, timer, and signal descriptors, `epoll`, and sockets;
- signal delivery: queueing and dequeue order, default actions, handlers with each architecture's `rt_sigframe` (x86-64 XSAVE state, AArch64 FP/SIMD and ESR records, RV64 FP and vector state), `rt_sigreturn`, alternate stacks, `SA_*` flags, and system-call restart (unit-tested against kernel layouts on every ISA);
- host signals forwarded to the guest with Linux `siginfo`, and a guest killed by a non-core signal ending `rax-user` with that signal (integration-tested with the `hostsig` fixture on every ISA);
- interval timers (`alarm`, `setitimer`) and interruptible blocking calls: pipe and terminal I/O, `poll`/`ppoll`/`select`/`pselect6`, sleeps, and signal waits, with Linux's `EINTR`/`SA_RESTART`/`restart_syscall` outcomes (unit-tested on every ABI; differential-tested by the `timers` fixture);
- threads on one emulated CPU: `clone`/`clone3` threads with Linux's register state and TID words, futexes (wait/wake/bitset/requeue/wake-op/PI, `futex_waitv`, the `futex2` calls), robust-list and `clear_child_tid` handling at thread exit, `complete_signal` targeting of process signals, per-thread names and `/proc/<pid>/task` (unit-tested on every ABI; differential-tested by the `threads` and `threadexit` fixtures, whose x86-64 and RV64 expectations are the AArch64 kernel's because Rosetta and QEMU user mode lack `clone3`, `futex_waitv`, and, in QEMU, robust lists);
- processes: `fork`/`vfork`/non-thread `clone` as host processes, `wait4`/`waitid` statuses for exits, deaths, stops, and continuations, `SIGCHLD` with its `siginfo`, `SA_NOCLDSTOP` and automatic reaping, `execve`/`execveat` of ELF programs of any supported ABI and of `#!` scripts with Linux's kept and reset state (unit-tested; differential-tested by the `exec` and `fork` fixtures, whose translated-ABI expectations come from the AArch64 kernel where Rosetta and QEMU diverge);
- POSIX timers (`timer_create` on the realtime, monotonic, boot-time, TAI, and CPU-time clocks, with `SIGEV_SIGNAL`/`SIGEV_NONE`/`SIGEV_THREAD_ID`; one queued signal per timer with its overrun count; stale signals of changed or deleted timers dropped; ignored periodic signals parked until a handler returns) and `eventfd`/`timerfd`/`signalfd` with Linux's checks, readiness, and blocking, an `eventfd` or `timerfd` staying one object across `fork` (unit-tested on every ABI; differential-tested by the `events` fixture, whose RV64 expectation is the AArch64 kernel's because QEMU user mode lacks `TFD_IOC_SET_TICKS`, does not check `signalfd4`'s mask size, and substitutes its own timer IDs);
- `epoll` (`epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_pwait`/`epoll_pwait2`): level-triggered, edge-triggered, and one-shot items, the kernel's ready-list order and `maxevents` rotation, items keyed by open file description, nesting and loop limits, and `EINTR` without restart; `poll` and `select` report pipes as `pipe_poll` does (unit-tested on every ABI; differential-tested by the `epoll` fixture);
- sockets (`AF_UNIX` stream, datagram, and, on Linux hosts, sequenced-packet; `AF_INET` and `AF_INET6` TCP and UDP) as host sockets: every socket call in the kernel's check order, Unix names through the VFS, the abstract namespace and autobind on every host, blocking with socket timeouts and signal interruption, `SCM_RIGHTS` within and across processes, `SO_PASSCRED`, `SIGPIPE` by protocol, and `sock_poll` readiness (unit-tested on every ABI; differential-tested by the `sockets` and `sockmsg` fixtures, whose RV64 expectations are the AArch64 kernel's because QEMU user mode drops unknown socket type flags, writes `socketpair`'s descriptors only on success, and ignores `recvmmsg`'s timeout);
- netlink: on Linux hosts the host's `AF_NETLINK` sockets, every protocol; on macOS hosts `NETLINK_ROUTE` emulated over the host's interfaces (link dumps and lookups, address dumps, one IPv6 address) with `af_netlink.c`'s port IDs, groups, acknowledgements, dump pacing, and options, so musl's `getifaddrs` and `if_nameindex` work (unit-tested on every ABI; differential-tested by the `netlink` fixture, whose RV64 expectation is the AArch64 kernel's because QEMU user mode translates netlink messages itself);
- System V shared memory (`shmget`, `shmat`, `shmdt`, `shmctl` with `IPC_STAT`, `SHM_STAT`, `SHM_STAT_ANY`, `IPC_INFO`, `SHM_INFO`, `IPC_SET`, `IPC_RMID`, `SHM_LOCK`, `SHM_UNLOCK`) shared by every `rax-user` process of a host user, with the kernel's identifiers, permissions, attach counting by mapping (across `fork`, `execve`, exit, and a killed process), and removal at the last detach (unit-tested on every ABI; differential-tested by the `sysvshm` fixture, whose x86-64 and RV64 expectations are the AArch64 kernel's because Rosetta returns 1 from a failed `shmat` and QEMU user mode converts the IPC structures itself);
- System V semaphores (`semget`, `semop`, `semtimedop`, `semctl` with every command) shared by every `rax-user` process of a host user: operation lists applied all or none, waits counted by `GETNCNT` and `GETZCNT` and ended by a value, a timeout, a removal (`EIDRM`), or a signal (`EINTR`), and `SEM_UNDO` applied at exit (differential-tested by the `sysvsem` fixture);
- System V message queues (`msgget`, `msgsnd`, `msgrcv`, `msgctl` with every command) shared by every `rax-user` process of a host user: message types (`MSG_EXCEPT`, the least type up to a bound), `MSG_NOERROR`, queue limits, and senders and receivers waiting across processes, ended by room or a message, a removal (`EIDRM`), or a signal (differential-tested by the `sysvmsg` fixture, whose RV64 expectation is the AArch64 kernel's because QEMU user mode converts `struct msqid64_ds` itself);
- seccomp (`seccomp` and `prctl`'s `PR_SET_SECCOMP` and `PR_GET_SECCOMP`): strict mode and classic BPF filters with the kernel's program checks, eBPF-length chain bound, action precedence, `SIGSYS` records, per-thread kill rules, `SECCOMP_FILTER_FLAG_TSYNC`, inheritance across `clone`, `fork`, and `execve`, and the `/proc` status lines; per-thread `no_new_privs`; x86-64 `PR_SET_TSC` and strict mode's `RDTSC` faults (unit-tested on every ABI; differential-tested by the `seccomp` fixture, whose x86-64 and RV64 expectations are the AArch64 kernel's because Rosetta and QEMU user mode refuse seccomp);
- interface requests (`SIOCGIFCONF`, `SIOCGIFNAME`, `SIOCGIFINDEX`, `SIOCGIFFLAGS`, `SIOCGIFMTU`, `SIOCGIFHWADDR`, `SIOCGIFADDR`, `SIOCGIFNETMASK`, and the rest of `dev_ioctl` and `devinet_ioctl`): the host's answers on Linux hosts; on macOS hosts answered from the host's interfaces with the kernel's routing by family, name handling, and error order, so `if_nametoindex` and `if_indextoname` work (unit-tested on every ABI; differential-tested by the `ifreq` fixture);
- shared memory: shared file mappings are the files' own pages (write-back, coherence with `read`/`write` and other processes' mappings, `msync`), and anonymous and `/dev/zero` shared memory stays shared across `fork`; `mremap` duplicates shared mappings; `MADV_REMOVE` punches the object; truncation drops pages past the end (unit-tested; differential-tested by the `shmem` fixture, whose x86-64 and RV64 expectations are the AArch64 kernel's because Rosetta traps duplicating a mapping and QEMU checks `mremap`'s zero length early and lacks `MADV_REMOVE`);
- `memfd_create` and file seals, enforced on writes (a grow seal stopping a write at the chunk that would extend the file), `ftruncate`, `fallocate`, `fchmod`, `mmap`, `mprotect`, and `MADV_REMOVE`, with `F_SEAL_WRITE` refused while a shared mapping may write (unit-tested; differential-tested by the `memfd` fixture, whose RV64 expectation is the AArch64 kernel's because QEMU lacks `MADV_REMOVE`);
- pidfds for the process's threads, its children, and other processes: `pidfd_open`, `pidfd_send_signal` (every scope, `PIDFD_SELF_*`, the process's `/proc/<pid>` directory), `pidfd_getfd`, `PIDFD_GET_INFO`, `CLONE_PIDFD`, and `waitid(P_PIDFD)`, with `poll` readiness at exit and reaping and another process watched through the host so a reused PID is never mistaken for it (unit-tested on every ABI; differential-tested by the `pidfd` fixture, whose x86-64 and RV64 expectations are the AArch64 kernel's because Rosetta lacks `pidfd_getfd` and `clone3` and QEMU the pidfd `ioctl`s);
- `/proc/<pid>/fdinfo` with `seq_show`'s lines and those of pidfds, `eventfd`, `timerfd`, `signalfd`, and `epoll` (unit-tested; differential-tested by the `fdinfo` fixture, whose x86-64 and RV64 expectations are the AArch64 kernel's because the translators leave its flag encoding in the text);
- 36 static musl fixture cases on each ISA match output and exit status recorded on Linux (differential-tested for that corpus; the RV64 `mman` expectation is the AArch64 kernel's result for architecture-independent memory-management code the RV64 translator emulates, and the x86-64 `signals` expectation comes from QEMU user mode because the x86-64 translator, Rosetta, mishandles `SA_RESETHAND`);
- the morok program corpus: 97 C and C++ programs (integer, floating-point, and SIMD arithmetic, calling conventions, C++ exceptions and RTTI, `setjmp`/`longjmp`, TLS, atomics, inline assembly, and file, `mmap`, signal, socket, and `fork`/`exec` calls), trimmed to run in milliseconds, match the output and exit status recorded on Linux on each ISA and in every execution mode, apart from the divergences listed in its `known-divergences.txt` (differential-tested for that corpus; see [its README](../../tests/fixtures/user/linux/programs/README.md));
- dynamically linked programs load their interpreter and libraries through `--sysroot`: Alpine Linux 3.24 BusyBox (`ld-musl`, AArch64 and x86-64) runs shell, text-processing, hashing, and file applets (demonstrated, not differential-tested).

### Required user-mode qualifications

- `ITIMER_VIRTUAL`/`ITIMER_PROF` and CPU-time POSIX timers count the emulator's host CPU time, including emulation overhead, and other processes' CPU clocks are refused; the alarm clocks need root; `TFD_TIMER_CANCEL_ON_SET` never cancels (host clock changes are not observed); `/proc/<pid>/fdinfo` mount IDs only tell file systems apart, file locks and sockets' `scm_fds` are not shown, and `epoll` items are listed in insertion order; an `epoll` instance is copied by `fork`, readiness from outside the emulator reaches edge-triggered items once per growth and in insertion order, and the watch and wake-up-path limits are not enforced;
- a `CLONE_VM` child process is a copy (`vfork` parent sleeps correctly but does not see the child's stores); processes sharing tables with their parent, `CLONE_PARENT`, `CLONE_INTO_CGROUP`, namespaces, and the requeue-PI futex operations are unsupported; a pidfd sees another process's zombie as gone and names no thread of another process, `pidfd_getfd` reaches only the caller's descriptors, and `PIDFD_GET_INFO` has no cgroup ID, the host's credentials for another process, and exit information only for the caller's threads and reaped children; signals to other processes are host signals (no `sigqueue` values, real-time signals only to the sender, `kill(-1)` limited to children, and on macOS hosts a signal from a process outside `rax-user` may lose its sender when it arrives while the target forks or one of its children exits) and `PR_SET_PDEATHSIG` is never delivered; a thread must share the descriptor table and file-system context (so `unshare` of either is `EINVAL` while other threads exist, and namespaces are `EPERM`); all threads of a process share one emulated CPU;
- no vDSO image (AArch64 and RV64 map a `[vdso]` page holding only the signal-return trampoline, and no `AT_SYSINFO_EHDR` is given); the x86-64 `INT 0x80` (i386) ABI returns `-ENOSYS` (after seccomp has checked the call);
- seccomp has no user notification (`SECCOMP_FILTER_FLAG_NEW_LISTENER` is `EINVAL`, as on a kernel without it, so `SECCOMP_RET_USER_NOTIF` is `ENOSYS`) and no tracer (`SECCOMP_RET_TRACE` is `ENOSYS`); `SECCOMP_RET_LOG` and `SECCOMP_FILTER_FLAG_LOG` log nothing, `SECCOMP_FILTER_FLAG_SPEC_ALLOW` changes nothing, and `CAP_SYS_ADMIN` is being root;
- a private file mapping copies each page at its first touch (later file changes do not reach it); a shared mapping of a block device is a copy; another process truncating a file mapped shared here, past a page touched here, faults `rax-user` instead of raising the guest's `SIGBUS`; a `memfd` passed to another process or reopened through `/proc` is an ordinary file there (no seals), `F_SEAL_WRITE` counts only this process's writable shared mappings, and an `MFD_HUGETLB` `memfd` cannot be mapped;
- socket families other than `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK` are `EAFNOSUPPORT`; on macOS hosts netlink has only `NETLINK_ROUTE` (other protocols are `EPROTONOSUPPORT`), answers only link and address requests (routes, neighbours, rules, and changes are `EOPNOTSUPP`, changes `EPERM` without privilege), reports the host's interface names (such as `lo0`) and 32-bit counters, leaves out rtnetlink attributes about kernel internals, sends no notifications to joined groups, refuses messages to other sockets' ports (`ECONNREFUSED`), gives a forked child a copy of a socket rather than sharing it (and passed with `SCM_RIGHTS` a socket reaches only its own process); interface changes (`SIOCSIF*`, `SIOCADDMULTI`, IPv6's `SIOCSIFADDR`) are `EOPNOTSUPP` with privilege on macOS hosts, and the requests whose `ifr_data` points to more data (`SIOCETHTOOL`, `SIOCWANDEV`, the time-stamping and private requests) are `EOPNOTSUPP` on every host; routing, ARP, bridge, VLAN, and wireless requests are not socket requests here (`ENOTTY`); options and IP control messages without a host counterpart are accepted without effect; an `SCM_RIGHTS` description without a host descriptor reaches only its own process, and one reaching another process keeps only its access mode and `O_APPEND`; `SO_PASSCRED` reports the connected peer; peers see relative Unix paths as absolute; on macOS hosts, abstract names are files in a per-user directory, sequenced-packet Unix sockets are unavailable, and a peer's `SHUT_RD` is not reported by `poll`;
- `madvise` guard regions (`MADV_GUARD_INSTALL`/`REMOVE`) are refused with `EINVAL`, and `mlock` does not set `VM_LOCKED`;
- System V objects are shared only among `rax-user` processes (the namespace is a directory of the host user's, which host programs do not see) and are counted against the limits of a fresh kernel (`SHMMNI`, `SHMMAX`, `SHMALL`); `SHM_HUGETLB` finds no huge pages (`ENOMEM`), `SHM_LOCK` pins nothing, a killed process's attaches count until it is reaped, and `/proc/sysvipc` is not provided; a waiting semaphore operation tries again every 2 ms rather than being woken in queue order, and a killed process's undo adjustments apply once it is reaped; a waiting message receiver finds a message on its next try rather than being handed it as it is sent, so another receiver may take it first, and `MSG_COPY` is `ENOSYS` (as without `CONFIG_CHECKPOINT_RESTORE`);
- file locks are host locks: a waiting POSIX lock call detects no deadlock (where Linux fails with `EDEADLK`, it waits until a signal), macOS hosts have no OFD locks (`F_OFD_*` fail with `EINVAL`), and descriptions the host cannot lock (anonymous inodes, synthesized `/proc` files, and on macOS hosts pipes and sockets) are granted every lock;
- extended attributes are the host file's: no POSIX ACLs (`system.posix_acl_*` is `EOPNOTSUPP`), a Linux host also requires its own privilege for `trusted.*`, and a macOS host keeps names it cannot hold under a hashed name; device nodes need a host that lets `rax-user` make them;
- terminal attribute changes are not applied to the host terminal.

## SMIR and JIT status

### Established SMIR/JIT surfaces

- shared IR data structures, lifters, interpreter, optimizer, native lowerers, executable-memory runtime, cache, and hot-region integration exist;
- the root `smir-jit` feature is enabled by default;
- x86 guest on x86-64 host, x86 guest on AArch64 host, RISC-V host-native paths, and architecture-specific lift/lower tests are present;
- unsupported regions are intended to remain interpreted rather than being compiled speculatively.

### Required SMIR/JIT qualifications

- JIT availability is not JIT admission.
- Admission differs by host and guest. The x86-on-AArch64 route is materially narrower than x86-on-x86-64.
- Register, flag, memory, calls, helper ABI, width, host feature, exceptions, and control flow are independent correctness obligations.
- Interpreter/JIT equality tests apply to the state projection and regions exercised.
- Runtime verification changes performance and does not replace independent oracle comparison.
- Self-modifying code and cache invalidation require dedicated machine-level evidence.

## Machines and devices

### Current machine classes

The source tree contains:

- PC/x86 platform code;
- AArch64 virtual machine and FDT construction;
- S3C64xx/S3C6410 and S5L8900-oriented Arm work;
- Cortex-M-related platform paths;
- RISC-V bare-metal virtual machine;
- Hexagon bare-metal machine;
- microkernel-specific launch integration.

### Device-status rule

A device can be:

1. implemented as a model;
2. reachable through an I/O bus;
3. attached by a machine;
4. enabled only by `--pci-devices`;
5. enumerated by a guest;
6. driven successfully by a guest;
7. included in checkpoint state;
8. covered by machine tests.

Do not collapse those stages into “supported.”

### Current platform limitations

- serial console is the maintained UI;
- VGA is not a general wired display path;
- optional e1000, AHCI, NVMe, AC'97, and UHCI attachment is aggregate and off by default;
- PCI interrupt behavior is not equivalent to a production platform and has historically used polling-oriented integration;
- device reset, DMA, interrupt, migration/checkpoint, and guest-driver behavior require separate evidence.

## Observability and checkpoints

- instruction tracing requires `trace` and a software path that emits the events;
- GDB requires `debug`; stepping capability varies by engine/backend;
- profiling requires `profiling` and counts the instrumented execution path;
- whole-machine `.rxc` checkpoints include embedded configuration, CPU/memory/device/timing data according to the current snapshot contract;
- `--resume` is a legacy restore-into-reconstructed-machine path and is not interchangeable with `--checkpoint`;
- checkpoint compatibility across commits is not an unlimited stable serialization guarantee.

## Build and host support

- Rust edition 2024 is used;
- root defaults are `kvm` and `smir-jit`;
- KVM dependencies are Linux-target-gated;
- Unix host code supplies terminal, signal, and executable-memory behavior;
- dependency comments and patches aimed at Windows buildability do not establish a supported Windows runtime;
- checked-in x86-64 Rust flags target x86-64-v3, excluding older CPUs unless overridden;
- HVF requires macOS and code signing with the supplied entitlement;
- the microkernel needs nightly Rust, `rust-src`, and object-copy tooling.

## Testing and false-green risks

External-oracle and host-specific tests can skip because of:

- absent `/dev/kvm` or permission;
- wrong host architecture or CPU feature;
- missing QEMU user-mode binary;
- missing cross-compiler/assembler/linker;
- unsupported QEMU ISA revision;
- missing LLVM/APX tooling;
- filtered, ignored, or feature-elided targets.

Therefore, report:

```text
command
Cargo features
target name
running N tests
passed/failed/ignored/skipped counts
skip messages
host and external-tool versions
```

A green process result without those facts is not a complete validation statement.

## C/C++ embedding status

The `rax-capi` workspace member exposes a stable hand-authored C header and C++17 wrapper. Its current documentation states:

- arbitrary memory mapping and code/data loading;
- register access;
- run, bounded execution, and step on engines that advertise stepping;
- code, block, interrupt, I/O, MMIO, invalid-instruction, and memory hooks;
- context save/restore;
- stateless decode/analysis;
- panic containment as `RAX_ERR_INTERNAL`;
- no global state or hidden threads;
- one engine handle is not thread-safe, while distinct handles can run independently.

The C API’s KVM feature is not yet exposed through the C backend selector according to its own README. The embedding interface should therefore not be advertised as identical to every root CLI backend.

## Security posture

`rax` executes untrusted guest-controlled instruction streams and parses executable/kernel/media formats. It is a research emulator, not a hardened sandbox or security boundary.

Before security-sensitive deployment, independently evaluate:

- decoder and loader memory safety;
- guest-to-host bounds checks;
- arithmetic overflow and allocation limits;
- device DMA and MMIO validation;
- executable-memory W^X transitions;
- FFI argument validation and panic containment;
- denial-of-service through infinite execution or pathological inputs;
- checkpoint deserialization trust;
- external debugger exposure;
- supply-chain and dependency policy.

See [SECURITY.md](../../SECURITY.md) for private vulnerability reporting and maintenance scope.

## Licensing boundary

RAX is licensed under the [MIT License](../../LICENSE).
Third-party components are covered by their respective licenses; see
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

## Adoption checklist

Before depending on a path, answer:

- Is the architecture selector public and accepted?
- Is the machine constructible from documented inputs?
- Does the chosen backend run on the intended host?
- Is the required image format documented?
- Which exact milestone has been demonstrated?
- Which tests execute on the intended host rather than skip?
- What state does the oracle compare?
- Which features and environment variables change behavior?
- What happens on unsupported instructions, devices, and JIT regions?
- Is checkpoint compatibility required?
- Is untrusted guest input in scope?
- Is the license grant packaged in the repository?

## Related pages

- [Architecture overview](../architecture/overview.md)
- [Verification model](../development/verification.md)
- [Test target map](../development/testing/README.md)
- [Machines](../architecture/machines.md)
- [Devices](../architecture/devices.md)
- [Documentation policy](../documentation-policy.md)
