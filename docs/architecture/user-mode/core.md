[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# User-mode memory and CPU adapters

Guest address-space construction, memory faults, shared objects, CPU exits, and
code-cache invalidation.

## Address spaces

An `AddressSpace` holds:

- a **VMA map** (ordered, non-overlapping page ranges with permissions and a
  backing) that is the source of truth for what is mapped;
- a **lock-free page table** — a three-level radix tree of atomic entries
  (36-bit page numbers, 48-bit addresses) — caching the frames of pages
  that have been touched;
- a **frame arena**: one anonymous host mapping created with
  `MAP_NORESERVE`, exposed as guest-physical memory at address zero, so the
  host commits memory only as the guest touches it.

A translation is a few atomic loads when the page is populated. On first
touch the slow path consults the VMA map, allocates a zeroed frame, and
fills it from the backing (anonymous zero, or a page of a file or byte
source). Faults are classified as Linux classifies them: no VMA
(`SEGV_MAPERR`), a VMA forbidding the access (`SEGV_ACCERR`), or a file page
past end of file (`SIGBUS`, `BUS_ADRERR`). Huge `PROT_NONE` reservations cost
one VMA and no page-table memory.

**Shared memory.** A page of a shared mapping is not a copy: it is the
object's own page. The object — the mapped file, or for anonymous shared
memory (`MAP_SHARED | MAP_ANONYMOUS`, a shared mapping of `/dev/zero`) a
Linux `memfd` or an unlinked temporary file standing for the `shmem`
object — is attached to the arena in 256 KiB *extents*, each a host
`MAP_SHARED` mapping laid over an extent of the arena taken from its top
(so every host page size divides it), and the page-table entry points
into it. The guest's stores therefore reach the host page cache: the file
sees them, `read`, `write`, and other mappings (of this or another
process) agree with the mapping, `msync(MS_SYNC)` writes them out, and a
host `fork` leaves the pages shared with the child, as Linux does. An
extent is shared by every page, of any mapping, that lies in it, is
attached read-only for a file not open for writing (and attached again
for writing when a writable mapping needs it), and is detached when no
page points into it. `mremap` duplicates a shared mapping (an old length
of 0) by mapping the same object again. A file the guest truncates loses
its pages past the new end in every mapping, so the next access is
`SIGBUS`, as after `truncate_pagecache`.

**`memfd`** (`fs::memfd`, `syscall::memfd`). A `memfd` is such a nameless
host object wrapped as a regular file, its seals a word of memory shared
with forked processes (so `dup`s, children, and descriptions passed within
the process all see them), enforced where `mm/shmem.c` enforces them:
writes (a grow seal stops a write at the first page-sized chunk that
would extend the file), `ftruncate`, `fallocate`, `fchmod`, `mmap`
(`memfd_check_seals_mmap`), and `MADV_REMOVE`; `F_SEAL_WRITE` is refused
while a shared mapping in this process may write.

Mapping, unmapping, protection changes, `mremap` moves (which move frames
without copying), and population all take the VMA lock; reads of the page
table do not. Every guest thread of a process runs on one host thread, so
no guest access can race a mapping change, and a guest atomic instruction
is atomic with respect to every other guest thread.

**Code invalidation.** CPU cores cache decoded instructions and compiled
regions. The address space logs, with an epoch, every event that can make
such a cache stale — removing execute permission, unmapping or replacing
executable pages, and any write (by a CPU or by the host) to an executable
page. Each adapter applies the log before it resumes guest code.

## CPU adapters

| ISA | Core | Privilege | Syscall exit | Memory path |
|---|---|---|---|---|
| i386 compatibility | `X86_64Vcpu` in IA-32e compatibility mode | CPL 3 (`__USER32_CS` 0x23) | `INT 0x80` exits to the i386 syscall table | Flat process translation with 32-bit linear-address wrapping |
| x86-64 | `X86_64Vcpu` in user mode | CPL 3 (`__USER_CS` 0x33) | `SYSCALL` retires with RCX/R11 set and exits `VcpuExit::SystemCall` | `Mmu` flat translation through the address space; fetches checked as executes |
| AArch64 | `AArch64Cpu` via `ArmCpu::step` | EL0t | `SVC` returns `CpuExit::Svc` | `ArmMemory` over the address space; no alignment requirement (SCTLR.A clear) |
| RV64 | `RiscVCpu` | U-mode | `ECALL` returns `RiscVExit::Ecall` | `riscv::Memory` over the address space, with the `fetch_u16` hook for execute permission |

The x86-64 user mode (`src/isa/x86_64/user_mode.rs`) is a default-off
engine mode: paging is replaced by the installed `FlatTranslation`, the IDT
is bypassed and every exception or software interrupt is reported as an
`X86UserEvent` with its vector, error code, and the return RIP the
architectural frame would have held, and `HLT` raises #GP at CPL 3 as the
SDM specifies. System emulation is unchanged when user mode is not enabled.

Adapters clear LL/SC reservations (AArch64 exclusive monitor, RISC-V `LR`
reservation) whenever they leave guest code, as exception entry and return
do on hardware, so an interrupted `LDXR`/`STXR` or `LR`/`SC` sequence fails
and retries. The AArch64 generic timer and the RISC-V `time` CSR follow
host time (62.5 MHz and 10 MHz).

## Process memory and kernel objects

Implementation: `syscall::task`, `syscall::procmem`, `syscall::kcmp`,
`syscall::iov`.

A call naming a task by ID or pidfd finds the caller's threads, and its leader after
that has exited while others run (without memory, tables, I/O context, or undo list;
its signal handlers stay). Another process lives in another host process whose
memory and tables this one cannot reach, so the right to inspect it fails as a
denied `ptrace_may_access` does, for root too: `process_vm_readv` and
`process_vm_writev` return `EPERM`, `process_madvise` `mm_access`'s `EACCES`, `kcmp`
`EPERM`.

Transfers reach the caller's memory as `get_user_pages` does: page by page from the
start of each remote vector, a read needing `VM_READ` and a write `VM_WRITE`, so a
transfer ends at the first page it cannot reach or at a local fault, exactly, with
the bytes moved so far.

Every vectored call (`readv`, `writev`, the positioned forms, `sendmsg`, `recvmsg`,
and these) imports its vectors as `__import_iovec` does before anything moves: the
count an `unsigned int`, a single vector capped at `MAX_RW_COUNT` before
`access_ok`, several each checked at full length and then capped to `MAX_RW_COUNT`
in total.

`kcmp` compares the objects modelled per task: the address space, descriptor table,
and file-system context shared by every thread, the signal handlers, each thread's
I/O context and undo list, and open file descriptions (with epoll items found by
descriptor and offset), ordered by their identities under fixed per-type cookies.

## Memory-management system calls

Memory calls act VMA by VMA as `mm/mprotect.c` and `mm/madvise.c` do, including
partial application before a failing VMA or hole; the Linux VMA properties that
change results (`VM_GROWSDOWN` on `[stack]`, `VM_MAYWRITE` clear on shared mappings
of read-only files, `VM_READ` apart from readable pages, `VM_LOCKED` and
`VM_LOCKONFAULT`, the special `[vdso]` mapping, `VM_SEALED`) live in `Vma::flags`
(`abi::vma_flags`).

A sealed VMA (`syscall::mseal`) refuses what `vma_is_sealed` refuses where the
kernel checks it: every unmapping (`munmap`, and `mmap`, `shmat`, or `mremap` over
it) with nothing changed, `mremap` of it, `mprotect` VMA by VMA, and discarding
advice on private anonymous memory that could not be written; `brk` and `shmdt`
leave it mapped.

Memory locking (`syscall::mlock`) keeps `mm->locked_vm` as the kernel keeps it, a
count the calls raise and lower (so a `MREMAP_DONTUNMAP` move of locked memory
leaves its old pages counted, as on Linux), checks `RLIMIT_MEMLOCK` wherever the
kernel does (`mlock`, `mlockall`, `MAP_LOCKED`, and `MCL_FUTURE` growth by `mmap`,
`brk`, `mremap`, and `shmat`), brings locked pages in, and makes `madvise` refuse to
discard them; a new process starts with nothing locked.

One deliberate deviation: `MADV_GUARD_INSTALL` and `MADV_GUARD_REMOVE` are refused
with `EINVAL`, as on a kernel without guard regions, instead of being accepted
without effect. `MADV_REMOVE` zeroes the object's bytes (its size kept), which is
what a punched hole reads as.

## Evidence and related contracts

[User-mode memory and CPU adapters tests](../../development/testing/user-mode.md#memory-and-cpu-contracts)
record the unit, differential, and host-specific evidence for these contracts.
