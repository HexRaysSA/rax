# User CPUs over imported process-owner memory

The process-memory owner remains authoritative for VMAs, permissions, private
frames, file overlays and code-change metadata. `OwnerMemory` connects the four
user CPU adapters to one independently mapped view of that actual storage.
Workers do not construct a second allocator, page table or VMA map.

This component does not enable owner-backed execution in the Linux process
scheduler. Guest clone/exec integration, descriptor registration and Darwin
fileless memory-right transport remain separate requirements. The existing
native owner transport is Unix-specific; Windows continues to use its existing
`AddressSpace` path. This extension does not implement a Windows process-family
broker or establish complete host-library process emulation.

The execution lease itself has adapters for Unix and Windows. Unix retains one
canonical file descriptor and a POSIX byte-range record lock. Windows uses an
unnamed, noninheritable kernel mutex, transferred only through an explicit
process-bootstrap handle list. Adoption queries the native object type/owner
and clears the handle's inheritance flag. A missing native owner-query export
reports `Unsupported`; an unsuccessful query prevents adoption or authorization.
Windows process identities retain the complete native unsigned 32-bit range.

Both adapters share the same lexical recursion, different-space rejection and
process-local panic poisoning. Native owner death permits the next worker to
acquire the lease. On Windows, `WAIT_ABANDONED` grants ownership, as specified by
the [native wait contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).
This does not roll back shared guest bytes: structural MM state belongs to the
broker, and a new acknowledged turn replaces the old worker's token. Windows
mutex ownership is thread-associated; the common guard releases on the same
host thread that acquired it. The [mutex contract](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects)
and [`MutantOwnerInformation` declaration](https://github.com/winsiderss/phnt/blob/master/ntexapi.h)
define these native mechanics. The Windows broker transport and scheduler are
still separate requirements.

## Storage and CPU interfaces

The existing `X86UserCpu`, `A64UserCpu`, `RvUserCpu`, `UserArmMemory` and
`UserRiscVMemory` names remain concrete aliases over `AddressSpace`. Existing
constructors and unbound methods therefore retain function-item type inference
as well as ordinary call behavior. Register APIs and feature selection retain
their existing behavior.

Each architecture module exposes `CpuWithSpace<M>` for a selected
`CpuAddressSpace`, constructed through `with_space`. AArch64 additionally
provides `with_space_config` to select the architecture. The AArch64 and RV64
memory wrappers use `MemoryWithSpace<M>`. These generic types share the existing
implementation; the concrete aliases do not add another execution path.
`A32UserCpu` retains its
`A32AddressSpace` interface. The added execution-generation and fatal-error
hooks have defaults, preserving existing custom AArch32 storage implementations.
No C ABI layout or public C identifier changes.

The Linux ABI dispatcher similarly keeps `arch::GuestCpu` as a concrete alias
over `AddressSpace`, with its existing `new` constructor and function-item
inference. `arch::CpuWithSpace<M>` executes x86-64, i386, AArch64, AArch32 and
RV64 through the same ABI implementation over `LinuxAddressSpace`. This does
not change the scheduler's concrete storage selection.

Linux x86 fault frames need one additional memory fact: whether the address
has a populated page in a VMA with at least one permission. `PROT_NONE` and an
untouched read-only page do not set the page-fault present bit. The dispatcher
queries this fact from the owner under the active turn. The query does not
populate a page or change the memory mutation generation. A failed query is
an internal exit, without a fabricated signal frame.

The generic internal `clone_to_space` methods copy the existing architectural
thread state into a CPU over the selected storage type. Cached code,
translations and local exclusive monitors start fresh in the destination.

`Session::cpu_memory` imports storage inside an acknowledged native lease and
reuses one shared `OwnerMemory` per endpoint/MM. Its weak endpoint reference
does not prolong the client's descriptor lifetime. An endpoint that changes MM
receives a new imported view; retained old views cannot authorize that new MM.

The physical-memory Arc is retained by the ISA cores. It is not a type-enforced
lease: direct use of a retained physical pointer or `core_mut`/`vcpu_mut` to
execute the underlying core bypasses the adapter's entry checks. Personality
integration must execute through the user CPU adapters inside `Client::with`.

## Linux MM bookkeeping

`MmState` implements the owner's explicit private-fork preparation. It preserves
the loaded program, stack layout, break and mmap base, clears the child's mapping
lock flags and lock accounting, and creates a fresh pinned-page counter. The
preparation operates on the unpublished snapshot. A shared clone retains the
existing owner MM and its metadata record, including its pinned-account identity.

The native child path and owner preparation use the same mapping-lock reset
helper. Registered `io_uring` buffers retain their original account when a private
child receives new bookkeeping or an exec worker leaves a shared MM. Releasing
the last old-MM worker releases its mappings; a retained buffer keeps its account
alive until the buffer is dropped and uncharged. No serialized counter substitutes
for that lifetime-bearing object. The process scheduler still owns a local
`ProcState::space` and `ProcState::mm`; this preparation does not synchronize
those fields with the broker or admit new worker-side mmap resources.


`brk` now has one MM operation shared by the native syscall adapter and Linux
owner dispatch. The caller supplies its ABI, personality, lock privilege and
`RLIMIT_MEMLOCK` in bytes. The break, VMA locks and lock-page count come from
the owner's live MM. Mapping changes, break publication, accounting and optional
population execute under one owner turn before the response is sent. This
preserves the existing refusal, sealing, guard-gap and execution-permission
rules; it does not add unrelated kernel policies such as `RLIMIT_DATA` checking.

The private personality request carries at most 4,096 serialized bytes. Strict
Linux decoding precedes mutation; malformed, stale, unsupported or oversized
requests retire that endpoint. Guest errno travels in the typed Linux reply,
separately from fatal transport/protocol errors. Every admitted personality
request conservatively changes the worker's CPU mutation generation. Malformed
or lost replies revoke its active window before returning the first error; no
operation is retried. The broker can finish a request after the reply endpoint
has closed, leaving surviving shared workers with the completed MM state. There
is no rollback promise for an arbitrary underlying memory error or broker death.

`munmap`, `mprotect` and `mseal` also share whole MM operations between their
native adapters and the owner. Unmapping checks all overlapping seals before
releasing lock accounting or mappings. Sealing validates the complete range
before changing any VMA. Protection changes retain the existing ascending-VMA
partial-error behavior: changes before a later hole, denied write or seal remain
visible when guest errno is returned. A lost reply does not roll those changes
back. Each operation has its own narrow expected reply type; a reply naming a
different operation is a fatal protocol error even when its result shape fits.

The Linux guest locking operations (`mlock`, `mlock2`, `munlock`, `mlockall`
and `munlockall`) similarly share MM-owned methods. The calling process supplies
its ABI, privilege and `RLIMIT_MEMLOCK` in bytes; range rounding, VMA flags,
default future-lock flags, locked-page accounting and population remain in the
owner. Overlapping ranges count only their newly locked pages. A later hole or
population error retains the earlier flag/account changes. `MCL_FUTURE` changes
the shared MM's mapping policy without retaining the caller's limit as MM state.
Private forks clear lock flags and accounting; shared workers retain them.

`mmap` now shares its non-fixed area selection and complete MM publication with
owner dispatch. Offset alignment still precedes file lookup; length/type checks
precede the existing file/resource preparation. The common operation preserves
fixed replacement, seal and lock admission order, lock accounting and optional
population. A registered request resolves an endpoint-scoped backing ID to the
actual owner-held `PageSource` or `SharedObject`, including its opaque `Keep`.
Releasing the catalog entry does not release a live VMA; private snapshots keep
the same demand-paging source and independently copied private resident pages.
Anonymous shared objects are created by the owner. This does not yet admit files
opened later in workers or move notification/record-lock authority between host
processes. No serialized bytes substitute for those resources.

`msync` and `mincore` also share whole MM operations with the owner. `msync`
uses the actual mapped object and preserves flag, range and hole checks without
faulting untouched pages in. `mincore` collects residency without populating the
queried pages, then writes its byte vector through the same owner address space
inside the turn. An aliased output therefore observes residency collected before
the output write. Guest output faults remain guest errno; a lost reply does not
undo a completed vector write. This is the existing local memory-copy contract,
not a claim of new kernel-equivalence or storage-durability qualification.

`madvise`, including population and shared-file hole punching, now runs as one
owner operation. It retains the local validation and ascending-VMA partial-effect
order: a later hole or rejected VMA does not undo earlier effects, including when
the reply is lost. Memfd mappings retain their actual inode seal object beside
the notification token in `Keep`. Closing the last guest descriptor therefore
does not erase `F_SEAL_FUTURE_WRITE` before `MADV_REMOVE`; a private MM snapshot
retains the same inode. The open description itself closes independently, so
mapping retention does not delay its descriptor/record-lock bookkeeping. The
final mapping and catalog release drop the inode state. This retains resources
already admitted in the owner; late worker file admission and cross-process
notification/record-lock authority still require integration.

Linux owner metadata now consumes the actual `MmState` and AIO `Table` together
in a non-cloneable `MmResources` record. Shared workers keep this one record;
private forks clear only the child AIO table while inheriting its ring VMAs.
Pending polls retain the original `OpenFile` and eventfd references, completions,
context serials and ring object. Exec replaces the record, and the last old-MM
release drops its pending requests independently of inherited ring VMAs.

`mremap` runs as a complete operation over those resources. Destination unmap,
lock accounting, actual ring lookup and context relocation, page movement and
population retain the local operation's validation and partial-effect order.
An inherited ring without a child context rejects relocation after the fixed
destination unmap. A lost reply neither retries nor reverses a completed move.
The local syscall uses the same operation with its actual local AIO table.
Submission, cancellation and wait servicing still require migration before
shared-process scheduling can use the owner.

`io_setup` now shares a complete operation between the local syscall and owner
dispatch. It reads the caller's ABI-width context pointer before validating the
event count, selects and maps the real shared ring, charges the actual AIO table
and publishes the output handle under one turn. A final handle-copy fault removes
only the newly allocated context and ring; existing pending poll and eventfd
references remain intact. Future-lock limits are checked before mapping, while
the special ring itself remains unlocked. A lost reply retains the completed
setup for surviving shared workers. Private forks retain inherited ring VMAs
and receive a fresh empty table. The existing `aio-max-nr` accounting remains
per MM rather than kernel-global; this ownership extraction does not change that
policy or enable process scheduling by itself.

Linux fork advice is recorded on the actual VMA subranges. `MADV_DONTFORK`
omits those ranges from a private child; `MADV_DOFORK` clears that policy.
`MADV_WIPEONFORK` accepts private anonymous memory and makes the child's pages
start at zero, retaining the flag for nested forks; `MADV_KEEPONFORK` clears it.
Private file and shmem mappings reject WIPEONFORK. Seals are checked before
advice changes flags, and advice over holes preserves its mapped-range effects
before returning `ENOMEM`. Protection and relocation preserve the flags;
replacement mappings start with their new attributes.

The local child initializer and the owner's private-fork metadata use the same
Linux inheritance step after the storage snapshot. The storage primitive itself
still copies all VMAs/pages before this step; omitted bytes may therefore be
copied transiently into the unpublished snapshot. Shared-MM forks, including
the local `CLONE_VM | CLONE_VFORK` path, do not consume private inheritance
policy. An unexpected inheritance error invalidates the unpublished child.
The local initializer records an internal exit and preserves the normal fork
handoff, so the child's identity, status pipe and single remaining thread are
installed before exit processing; no child guest instruction runs.

The private snapshot primitive now also uses real Windows placeholder-backed
storage. Its page/VMA copy loop and shared-object reattachment are common with
Unix; Unix keeps its independently importable process file. Sparse private pages,
readonly shared aliases, file-copy overlays, lazy source offsets and allocator
reuse have the same contract. This does not add a Windows worker endpoint or
bootstrap handle transfer.

The remaining memory syscalls still use local `ProcState` fields. Enabling the
owner in the scheduler requires migrating those operations and resource
lifetimes together; raw mapping RPCs alone do not maintain Linux MM accounting.

## Entry, reservations and host errors

Every adapter admits entry before execution, including zero-budget entry and
precise instruction stepping. Imported memory validates the native PID,
thread, MM and active turn. A synchronous owner code-change query detects an
already lost endpoint before cached code can execute without a new fetch.
It does not promise instantaneous detection of asynchronous broker death.

A foreign-worker turn, another CPU consumer, an owner-side mutation or a view
mapping/write generation change invalidates retained code and local exclusive
state conservatively. Consecutive turns of the same worker preserve AArch64
reservations across a pure instruction-budget yield when these generations are
unchanged. A same-value host write still invalidates a reservation. RV64 and
AArch32 retain their existing exit policies.

Only a typed owner guest-memory fault becomes an architectural memory fault.
Transport and preparation failures stop with an internal CPU exit. The first
original typed failure can be drained once through `OwnerMemory::take_error`;
the diagnostic latch remains set afterward. The personality returns that error
from its `Client::with` callback. A failing End acknowledgement cannot replace
an earlier transport or preparation error. RV64 restores the faulting user
frontier before reporting the internal error instead of retaining M-mode trap
entry state.

Linux AArch64 software CPUID emulation rereads the trapped instruction after
the architectural CPU has returned. The ABI dispatcher checks the fatal-error
latch again after that reread, before translating the exit into a Linux signal.
A host failure remains an internal exit; an ordinary guest reread fault retains
the existing `SIGILL` result. A failed reread does not advance PC or write the
emulated register result.

## Trace metadata

Trace mappings come from the owner's real VMA snapshot, including names and
permission bits. Serialized metadata is transferred in chunks of at most
65,536 bytes under the existing frame bound. UTF-8 bytes can cross a chunk
boundary; parsing occurs after complete reassembly. No worker VMA is created.

The stateless owner re-encodes the snapshot for each chunk. For B serialized
bytes and chunk limit C = 65,536 bytes, this costs
O(B * ceil(B / C)) work, O(B) temporary storage and O(B) transported bytes.
Map snapshots are used for tracing rather than instruction translation.

Once a CPU has requested trace metadata, a traced session refreshes its final
snapshot before End while the same native lease is held. CPU destruction after
End records that saved snapshot without an inactive RPC or access to a later
worker's MM. This includes mappings added after the CPU's last instruction.

## Behavioral controls

The owning library contains native worker tests for all four guest ISAs over
imported storage; same-worker AArch64 reservation continuation; same-value host
writes; AArch32 local-monitor invalidation; same-turn CPU changes; foreign-MM
shared-file code and reservation changes; large escaped/UTF-8 map metadata;
and traced CPU destruction after End. A four-ISA failure matrix closes the
transport before entry acknowledgement and during instruction fetch, checking
internal exits, unchanged faulting PCs and preservation of the first error.

Additional native worker controls exercise all five Linux guest ABIs through
the generic dispatcher, including syscall registers, TLS, CPU cloning and
inactive entry. Linux x86 controls distinguish untouched, populated,
`PROT_NONE` and unmapped pages through real owner IPC. Malformed and lost
page-state replies retain the first typed transport failure. The AArch64
software-CPUID regression independently injects a host reread failure and an
ordinary guest reread fault, with explicit PC and result-register checks.

Linux MM controls check layout and private-fork initialization for all five guest
ABIs, empty MMs, and retention of existing ring accounts. Native Unix lease-holder
processes exercise shared metadata, nested private snapshots, exec turn rotation,
old-MM retirement and uncharging through `Imu::drop`. The portable MM
initialization controls also run on Windows; they do not exercise a Windows owner
transport.

These controls establish component behavior. They do not establish guest
process scheduling, Windows owner transport, Darwin memory-right transfer or
complete Linux/macOS/Windows application startup.
