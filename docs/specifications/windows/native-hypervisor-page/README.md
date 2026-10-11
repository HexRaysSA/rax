# Native hypervisor shared-page query evidence

This group implements `NtQuerySystemInformation` class197,
`SystemHypervisorSharedPageInformation`, for the existing Windows guest profile
without a hypervisor timing-page mapping. It returns a guest null pointer:
4 bytes for x86/WoW64 and8 bytes for x64/ARM64. No host pointer or host kernel
query is forwarded. Other query classes retain their previous behavior.

Baseline RAX is af25e4dc53a5f86ce53675835d76942a04b960d4; owning Assist root is
5de79ced11b9d97b3bf882f59dfc45576e2432d2. Its compiled C++ sources correspond to
c4cb8f6a0dd7c0d068d2defd411599fba9e32b7e: the later root commit changes engineering
records and the RAX Gitlink. Four final compiled RAX inputs are frozen in
source-hashes-reviewed.json. Runtime documentation is a fifth owned source path.

## Primary contracts and native observations

The pinned [PHNT ntexapi.h](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntexapi.h)
defines enum197 and the single-pointer `SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION`
layout, including NULL when the page is unavailable. The exact header and
license are retained in ../native-processor-features and independently hashed
by the checker. Microsoft's public
[NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
contract supplies the four-argument entry. The private class's buffer ordering
comes from observations, not from an inferred public API guarantee.

All four selected Windows11 build10.0.29683.1000 profiles return a null pointer.
ARM64 and x64 compatibility each supply210 ordinary rows plus2 upper-user-range
guard rows. x86 and x86 LARGEADDRESSAWARE each supply239 rows:
2*(210+2)+2*239=902 observations. Native machine types/LAA bits and executable
hashes are recorded, while executable bytes remain outside the repository.
x64 compatibility on ARM64 is not physical native x64 kernel evidence.

The final C++ producer uses VirtualQuery/ReadProcessMemory snapshots clipped to
the actual accessible extent, and skips still-armed guards. Snapshot observation
does not consume them. All external SEH exception codes are zero. Private output
and returned-length regions start with0xA5 poison. Captures include every
length0..19, null/read-only/unmapped pointers, unaligned pointers, aliases,
page crossings, guards/repeats, user-range overflow, and selected large lengths.
The originals preserve their byte content and newline conventions.

| Contract | Native64 | WoW64 |
|---|---|---|
| Required output |8 bytes |4 bytes |
| Output alignment |4 bytes, checked before range/probe |None |
| Declared output span |Entire nonzero span probed before dispatch |Only converted4-byte store touched |
| ReturnLength |4-byte direct write probe before class/length |Written after conversion; unaligned allowed |
| NULL output, nonzero length |Output fault before length |Attempt0xFFFFFFFC ReturnLength, then access violation |
| Short nonnull output |INFO_LENGTH_MISMATCH after probes; ReturnLength required |Temporary capture reservation precedes mismatch |
| Adequate output |Pointer-width null; suffix unchanged |Atomic4-byte null; suffix unchanged |
| Output/ReturnLength alias |ReturnLength published last |ReturnLength published last |
| Upper output range |AV before consuming guard |Converted pointer store fault |
| Crossing ReturnLength guard |GUARD; guard consumed |GUARD after output; guard consumed |

Status codes are SUCCESS0x00000000, INFO_LENGTH_MISMATCH0xC0000004,
ACCESS_VIOLATION0xC0000005, DATATYPE_MISALIGNMENT0x80000002,
GUARD_PAGE_VIOLATION0x80000001, and NO_MEMORY0xC0000017.
The one-shot PAGE_GUARD behavior is also described in Microsoft's
[memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants).

## Temporary WoW64 storage and falsified initial expectation

Initial portable tests incorrectly treated every large unused output span as
allocation-free. Captured ULONG_MAX and approximately2 GiB lengths return
NO_MEMORY before all nonnull output and ReturnLength probes, including guards.
NULL nonempty output bypasses this allocation and retains the translated error
length/fault ordering. Selected16 MiB and all smaller captured sizes succeed
with mapped destinations. The host allocation failure threshold between16 MiB
and approximately2 GiB is unknown; this record does not interpolate one.

The selected System32 wow64.dll and the matching Microsoft symbol-server PDB
independently establish the wrapper. wow64-wrapper-provenance.json records
DLL/PDB hashes, RSDS GUID, image base, function RVAs, and the original symbol URL.
RSDS age1 matches DBI age1; PDB information-stream age3 is separately recorded.
The bounded original LLVM identity output is in wow64-pdb-identity.txt. DLL/PDB
bytes and full disassembly/public-symbol dumps are not redistributed.

The wrapper's temporary capacity is align_up(u64(L)+4,16); the heap fallback
adds a16-byte list node before RtlAllocateHeap. Allocation failure raises
STATUS_NO_MEMORY. Its native query length is L==0 ?0:u32(L+4). Microsoft's
[HeapAlloc contract](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
provides the public allocation-failure context; the precise wrapper arithmetic
comes from the selected native instructions and matching symbols.

RAX projects that temporary fallback storage into its existing guest
no-paging-file quota rather than a fixed inferred host threshold:

    capture_bytes = align_up(u64(L)+4,16)+16
    charge_bytes  = align_up(capture_bytes,4096)
    reject if charge_bytes > commit_limit_bytes - committed_bytes
           or charge_bytes > high_user_address - low_user_address

No caller-sized host buffer is allocated and no persistent guest reservation is
created. The portable test covers exact available-20 versus available-19 byte
length boundaries, quota exhaustion, ULONG_MAX, aliased destinations, and armed
guards. Length arithmetic widens before addition. Native64 time complexity is
O(ceil(L/4096)) for the existing whole-span probe; WoW64 time and additional
space complexity are O(1), with fixed4-byte publication.

The phase logs are explicit: macos-before-portable has0pass/9fail unsupported
baseline; macos-after-portable has9pass; macos-final-portable has10pass but
contains the subsequently falsified ULONG_MAX expectation. The first quota
fixture has10pass/1fail because its observer directly read an armed guard.
Correcting that observer, without another product edit, gives11pass. The final
four compiled hashes own the final targeted and broad gates below. These older
phase passes are not final native conformance proof.

## Final validation and owning continuation

| Host / selected environment | Targeted | Full pass/fail/ignored/filtered | C API | All targets | Integration |
|---|---|---|---|---|---|
| macOS ARM64 native |11 |7580/0/2/0 |168 |pass |Unix Windows fixtures544; Windows-memory cfg0 |
| Linux x86-64 container under ARM64 translation |11 |7573/1/2/0 |168 |pass |Unix Windows fixtures544; Windows-memory cfg0 |
| Windows ARM64 native |12 |6971/5/2/0 |168 |pass |Native Windows memory4; Unix fixtures cfg-excluded |

The extra native Windows targeted case invokes the installed ARM64/WoW64 leaf.
Linux retains a_multishot_timeout_reports_each_expiry; its isolated nine-test
timeout selection passes. Its full-run failure cause is unknown. Windows retains
four BZHI flag assertions and one FP16 vector assertion. Exact test names and
original terminal summaries are in validation.json and the raw full logs.
No all-suite success is claimed. Final selected counts are7582/7576/6978.

All five owning C++ consumers pass on each host against the embedded Assist
Rust/RAX archive: process tool, RAX-disabled refusal, process ABI execution,
C ABI drift, and single-Rust-archive linkage/unwinding. Linux process-tool count
is184; Windows count182 reflects its existing platform selection. The process
ABI consumer executes162 checks. macOS also builds the owning CLI, passes7/7
CTests, and scans one artifact with zero protected-static-text failures.
Windows performs a paired assist-rs/rax-capi clean and rebuild after the standard
matrix, then uses the current Cargo compiler-artifact's feature-empty RAX rlib
for the private continuation. Both large archives pass a complete ar member
walk; current byte sizes/hashes/member counts are retained in
native-owning-archive-hashes.json. This is not shipping IDA/Qt/package execution
proof or physical native Linux x86-64 proof.

The byte-identical before/after private diagnostic clears PEB.ProcessHeap and
enters LdrInitializeThunk using a saved initial context. These are diagnostic
workarounds, not changes to production bootstrap.

    before: turn33364 NtQuerySystemInformation(class197) -> unsupported
    after:  turn33364 NtQuerySystemInformation(class197) -> SUCCESS
            turn33566 NtQuerySystemInformation(class55)  -> unsupported

33566-33364=202 additional scheduler calls, not instructions. Four ordinary
programs (ARM64 smoke, MSVCRT streams, UCRT streams, whoami) still exit with
STATUS_ACCESS_VIOLATION. Class55 and production native heap/Ldr/CRT startup
remain full-goal frontiers, without guessed completion claims.

## Assumption register and bounded scope

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Final status |
|---|---|---|---|---|---|---|
| A1 | Guest has no hypervisor page mapping | Startup maps KUSER_SHARED_DATA; x86 CPUID hypervisor bit clear |Null guest pointer |All guest ABIs/native leaf |Introduce/observe modeled page or advertised capability |confirmed for current profile |
| A2 | Selected build buffer behavior applies to selected runtime |Fresh NTDLL hashes;902 native observations |Probe/store ordering |Aliases, nulls, odd sizes, read-only, guards, upper range |Replay status/bytes/guard mismatch |confirmed for selected build |
| A3 | x64 compatibility is limited to this ARM64 host |Actual producer PE/profile |Limits on native64 provenance |Physical native x64 kernel |Repeat on physical x64 and compare |retained |
| A4 | Native upper output check precedes guard while ReturnLength touches directly |Four original upper-guard rows |Class197-only range adapter |Last-user-page guards |Native guard state reversal |confirmed |
| A5 |WoW capture needs temporary backing, constrained by existing guest quota |Matching wrapper formulas plus native OOM |Guest quota projection, not host threshold |Quota exact boundary, ULONG_MAX/null/guards |Formula/order disagreement or guest quota violation |revised and confirmed for guest profile |

Windows query dispatch, shared guest semantics, test registration, owning
archives and engineering pin records are affected. Linux/macOS compile and run
the same Windows guest implementation; the native installed-leaf adapter is
Windows-only by contract, with portable coverage on both other hosts. Current
CMake/Assist consumers retain existing source membership. Plugin lifecycle, UI,
conversation/native+ACP request policy, prompt, tool schema, permissions,
main-thread seam, Mesh/MCP, transport/crypto, persistence, public C ABI, optional
engine defaults, dependency pins and package contents have no class197 contract
change. No new service registration or capability is introduced. C API stays
1.11.0. Instruction lowering, processor model and host syscall forwarding do
not change in this group.

Bounded findings: high, production ordinary Windows bootstrap and broader
application/native-package matrices remain incomplete and block the overall
full-userland goal. Medium, retained Linux timer and Windows lowering failures
limit broad validation; their sources are untouched here. Medium, older query
classes' upper-span behavior needs its own native baseline before changing it.
No nonblocking adjacent change is included.

Quality gates: QG1 requires no normative content; QG2 register includes probes;
QG3 this class197 group is covered by originals, portable/native tests and owning
consumers; QG4 byte widths/page rounding and scheduler delta are reproducible;
QG5 native ordering/aliases/guards are replayed and host-threshold unknown is
bounded; QG6 primary source/license/native producer/symbol/artifact identities
are frozen; QG7 discoveries and overall-goal limits are recorded.

Run `python3 check_native_hypervisor_page.py`. The manifest is mandatory, hashes
all retained inputs except itself, and pins the four compiled source files.
`--source-root` permits checking the frozen source checkout explicitly. The
checker validates every native row independently of guest query execution,
recorded gate selection/summaries, archive identity and continuation boundaries;
it does not rerun the native programs or convert recorded passes into live proof.
Historical replay against later changed source requires the frozen commit.
