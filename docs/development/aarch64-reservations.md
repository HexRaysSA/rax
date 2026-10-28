# AArch64 physical exclusive reservations

Software AArch64 adapters sharing the same cloned `GuestMemoryMmap` backing
share a reservation domain. Each PE owns a local slot in that domain. A
load-exclusive reads RAM and installs its slot while holding the domain lock;
a store-exclusive consumes its slot and conditionally writes RAM under that
same lock. A successful store invalidates every overlapping PE reservation.
An ordinary tracked write invalidates reservations even when it writes identical
bytes or changes bytes and subsequently restores their old value (ABA).

The default profile uses a 64-byte reservation granule, matching
`CTR_EL0.ERG=4` (2^4 words). Reservations retain their exact physical starting
address and access width, independent of that invalidation granule. Another
granule and a distinct physical backing do not share reservation rights. The
registry retains a backing clone while its domain lives, preventing a freed
host address from being mistaken for the old live backing.

## Writers and execution boundaries

The AArch64 bridge routes ordinary and exclusive RAM writes through this
domain. Its mixed AArch32 execution bridge uses the same atomic transactions:
`LDREX` does not re-mark a reservation after returning from its memory access,
and `STREX` does not separate its monitor check from its write. Doubleword
AArch32 operations transfer the complete value once while preserving element
order in both endiannesses.

The VMM DMA adapter, debugger memory writes, RAM-wrapper restore writes,
physical checkpoint writes, C API host writes, C API AArch32 user writes, and
process frame-arena writes participate through `write_guest_memory`.
The process-level `UserArmMemory` also registers one physical monitor per CPU
view. Its exclusive transactions translate the virtual address and check user
permissions before entering the shared RAM domain. Two threads using cloned
`AddressSpace` handles therefore cannot retain stale rights across a tracked
peer or kernel write. Naturally aligned widths of 1, 2, 4, 8 or 16 bytes fit
within one 4096-byte page, so one translation covers the complete transaction.
A write is preflighted before RAM or reservation mutation. This prevents a
failed crossing store from publishing its accessible prefix. Loads and stores
remain subject to their existing translation and permission checks.

Exclusive accesses require natural alignment. Paired accesses preserve the
first register at the first memory element in either endianness, and 64-bit
pairs require 16-byte alignment. Acquire fences follow successful acquire
loads; release fences precede release stores. Full-machine UART/GIC windows do
not implement exclusive transactions and raise an unsupported-atomic fault
before accessing device state or backing RAM. A user embedder's explicit RAM
mappings remain usable at those numeric addresses.

The tracked writer preflights the complete range even when no reservation
domain exists or the previous domain has expired. Every writer retains a
per-backing domain through its checked copy, including before the first PE
exists. A PE registering during that copy joins the same live domain and
waits for its RAM lock. The registry is released before the copy begins;
RAM copies for unrelated backings do not hold the process-wide registry.

Lock order is domain then local slot; the registry is released before either
lock is acquired. Translation callbacks, device handlers,
and memory-recording callbacks run outside the domain lock. Only checked
mmap reads/writes execute inside it. A poisoned host lock conservatively clears
exclusive rights before use; it cannot manufacture a successful conditional
store.

## Boundaries still requiring audit closure

This component does not serialize reservations. The preserved checkpoint guest
that loses its outstanding reservation remains a required C-STATE control.
Whole-VM capture/restore still needs complete private producer state and
coordinated publication with RAM, devices and pending operations.

Raw `GuestMemoryMmap` writes, direct host-pointer writes, independently mapped
file aliases, external file modifications and mapping replacement do not pass
through this helper. Their callers must coordinate them with guest execution;
this domain does not establish all-writer quiescence. Independent process
address spaces remain separate domains even when their virtual addresses match.
Native code needs its own admission/ownership proof. This component does not
close C-STATE, C-SMP, A32-FP or C-HVF.

## Validation and assumptions

`aarch64_cluster` includes real adapter controls for cross-PE identical/ABA
stores, simultaneous outstanding reservations, granule edges, paired widths,
alignment faults, endian element order, mixed AArch32 execution and exclusive
device-window rejection. Internal unit tests cover cloned/distinct backings,
failed crossing writes, two host threads contending for one exclusive store,
and the actual VMM DMA adapter. Additional controls cover failed first writes
without a monitor, failed writes after the last domain expires, and a successful
first write across adjacent regions followed by PE registration. Both failing
first-write controls changed the accessible RAM prefix on the parent revision;
they now return the error without that mutation. C ABI tests exercise `rax_mem_write` between
`LDXR` and `STXR`. Real user-CPU tests cover identical/ABA peer stores,
tracked address-space writes, competing conditional stores, granule edges,
distinct spaces at equal virtual addresses, and read-only store rejection.
The retained direct user-memory reproducer succeeds before the domain binding
and rejects the stale store afterward.

The retained guest from the original failure runs unchanged on QEMU and the
real RAX CLI. Both must print `1` after the AP completes a store observed by the
BSP before its `STXR`. The previous committed RAX CLI printed `0`. Source,
commands, raw output and executable hashes are retained in the audit evidence.

| ID | Assumption and dependent result | Stress test / falsification probe | Boundary |
| --- | --- | --- | --- |
| R1 | Cloned mmap regions retain backing identity; their PEs select one domain. | Clone handles and compare distinct backings at equal guest addresses; an intervening clone writer allowing `STXR` falsifies it. | Region layout and host mapping identity; independent file aliases remain outside this proof. |
| R2 | Tracked RAX writers enter the domain. | Identical/ABA, DMA, C ABI, overlap and failed crossing controls; any stale successful conditional store falsifies it. | External raw writers and remapping remain separate requirements. |
| U1 | User address-space clones retain physical backing identity. | Two CPU views, tracked kernel writes, competing stores, and separate spaces at equal virtual addresses. | Cloned backing only; mapping replacement remains separate. |
| U2 | An aligned access of at most 16 bytes occupies one 4096-byte page. | Each admitted width divides 4096; reject unsupported widths and misalignment before translation. | One checked translation covers the complete transaction. |
| U3 | Translation and page population finish before the domain lock. | First-touch and permission controls plus lock-order inspection. | Callbacks remain outside the RAM-domain critical section. |
| R3 | The configured default reservation granule is 64 bytes. | Writes at offsets 63 and 64 must have distinct effects; compare default CTR ERG. | Arbitrary imported/custom granule profiles require admission proof. |

With R memory regions, D registry entries and P registered PE slots
(including expired slots awaiting pruning), write lookup takes
O(R log(D + 2)) work. Domain creation also scans the D registry entries;
invalidation takes O(P). An
exclusive transaction uses O(W) payload space for width W <= 16 bytes and
O(P) monitor work on a successful write. No throughput claim is made.

High-impact remaining work is private-state persistence and all-writer
checkpoint coordination. Medium-impact remaining work is independent alias
identity and mapping-generation ownership.

Primary implementation reference: archived Arm ASL
`docs/architecture/arm/asl/arm_instrs.asl`,
`aarch64_memory_exclusive_single` load/store pseudocode, and
`docs/architecture/arm/asl/arm_defs.asl`,
`AArch64.ExclusiveMonitorsPass` and `AArch64.SetExclusiveMonitors`.
The former specifies endian pair element order and alignment; the latter
requires the associated write to refer to the same physical locations.

Final local qualification passed the complete ARM-related target set, checkpoint
and process targets, full library, C API JIT, C/C++ consumers and strict ABI
objects, native Arm and Rosetta cluster targets, formatting, workspace Clippy,
all-target build and debug-feature check. Two existing library tests and the
Docker/binfmt Linux oracle remained ignored; the Windows-host memory target
ran zero cases on macOS. This establishes no physical Intel HVF or Windows
native-runtime result. The final CLI reproduced the cross-PE fix, while fresh
file restore still lost an outstanding reservation at PC 0x40080fa0 before
STXR at 0x40081140. The qualification receipt retains exact commands/counts.

The user-adapter binding was separately qualified with a captured parent failure
(2 passing and 4 failing regressions), then 49 user-CPU tests, 10796 library
tests, 208 C API tests, 118 Darwin, 43 Linux and 544 Windows-personality
process tests, plus Rosetta user-CPU and cluster controls and the C/C++
consumers. The two existing library ignores, Linux Docker/binfmt oracle
ignore and macOS-empty Windows-native memory target remain explicit limits.
The final all-target build includes the separately owned pending A32 admission
change; the user-adapter source remained unchanged throughout qualification.
Exact commands, source hashes and artifact identities are in the user-adapter
qualification receipt. No complete private checkpoint or native-HVF result
is inferred from these checks.

The first-write publication change preserves O(R log(D + 2)) registry lookup
and uses O(R) temporary identity space. Creating a domain additionally prunes
O(D) registry entries; existing-domain lookup skips that scan. The O(B) checked
copy and range preflight hold only the backing's domain lock, for B payload
bytes. The original registry-held-copy implementation passed its tests but
was superseded to avoid blocking unrelated backings during the copy. No
throughput claim is made. The retained first-domain interleaving is a source-level argument,
while prefix corruption and its correction were observed in executable tests.
Whole-VM capture/restore still requires a coordinated transaction across CPU
private state, RAM, controllers, devices, mappings and pending operations.

The final per-backing writer implementation passed seven reservation tests
(the parent had five passes and two failures), 10799 library tests, 187
checkpoint tests across 12 targets, 26 cluster tests, 208 C API tests, the
seven reservation tests under Rosetta, 18 C/C++ consumers, six strict ABI
objects, formatting, workspace Clippy and the all-target build. Two existing
library tests remained ignored. The unchanged public-helper control now
retains the original RAM byte after its range error. Exact producer hashes
and the superseded global-copy-lock checks are retained separately.
