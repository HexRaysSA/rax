# Guest working-set query evidence

Baseline RAX cd09c0004fc74299bee1f8d37d975bdfd84b27cb; Assist
00b25c6fa26845970ee225af4e2c6354221d7c69. Both trees were clean before this
semantic group. Owned code: native/virtual_memory.rs, new
native/virtual_memory/working_set.rs,
services_tests/virtual_memory_tests.rs, new services_tests/working_set_tests.rs,
and services_tests/virtual_memory_leaf_tests.rs. Owned evidence: this directory
and native-runtime.md. Root publication owns the RAX gitlink,
VENDORED_VERSIONS.md and src/emulation/native-process-emulation.md.

Acceptance: MemoryWorkingSetExInformation (class4) uses actual guest page
residency and protection without faulting targets; retains captured native and
WoW64 ABI/fault priority, typed query rights and bounded work; executes all guest
ABIs on all three host OSes and actual selected installed NTDLL leaves on
Windows. No request is forwarded to the host kernel. Full native startup is a
separate outstanding requirement of the overall process-emulation goal.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| W1 | Windows 10.0.29683.1000 ARM64 native and x86/x64 compatibility captures define this ABI profile | Two original process-local probes, 684 queries total | Ordering, lengths, alignment and guard behavior | Aliased destinations, guards, read-only input, invalid handles, incomplete records | Repeat retained sources on this build; compare independent checker | confirmed for captured build; retained for other builds |
| W2 | Current Windows VM owners use private anonymous guest frames, normal priority5, one NUMA node, base pages; no paging file, page locking, modified standby list or graphics state | VirtualMemory commit uses Mapping::anonymous; non-faulting AddressSpace::is_resident; Microsoft default memory priority | Shared/count/node/locked/large-page/list flags and residency model | Resident image versus private mapping; guarded/no-access resident page; untouched committed page | Inspect each Windows mapping owner and assert target residency/protection before and after queries | confirmed for current owners; retained for future shared/paging adapters |
| W3 | WoW64 conversion scratch can be bounded by the configured guest backing capacity | Original huge SIZE_T requests return STATUS_NO_MEMORY before input capture; closed guest memory budget | Explicit guest resource-limit failure without proportional host allocation | Count*16 overflow, 2 GiB request, inaccessible output | Native huge-request observations and guest limit boundary tests | retained; native resource threshold is unknown |

## Change-surface map

| Plane | Status and reason |
|---|---|
| NT service / scheduler ABI | Affected: existing six-argument NtQueryVirtualMemory dispatch gains class4; no new service/index |
| Memory / guest ownership | Affected read-only consumer: existing allocation/state runs and non-faulting PTE residency; output probes preserve guard side effects |
| Direct ISA / CPU state / SMIR / optimizer / lowering / JIT / hardware backends / devices / static analysis | Unaffected: no instruction, register layout, IR operation or backend implementation changes |
| C ABI / stable layouts / package features | Unaffected: internal NT dispatcher only; owning C API/Assist archives require rebuild and tests |
| Plugin/UI/context/history/permissions/MCP/transport/crypto/update | Unaffected: no factory/schema/copy/state/route policy change; existing native-library selection authorization remains |
| Windows/macOS/Linux targets | Affected shared portable Rust; all guest ABIs run on each host, installed Windows leaves run natively; all owning Assist archives and five C++ checks require validation |
| Tests/docs | Affected: strategic class4 behavioral tests, original native oracles and independent checker, explicit limits and final evidence ledger |

## Bounded scope

High impact: real native loader/RTL heap/CRT startup and wider NT APIs still
block the overall full-process goal. This class4 increment must not imply their
completion. Medium impact: other Windows builds/physical Intel kernels and
native resource exhaustion thresholds are unknown; the guest has its own
explicit finite backing model. Existing BZHI/FP16 and timing suite failures are
independent unresolved evidence. No unrelated implementation changes are
authorized by their discovery.

## Contract, arithmetic and provenance

The array contains VirtualAddress (ULONG_PTR) then VirtualAttributes
(ULONG_PTR). Let w be guest pointer width in bytes, r=2w bytes per record,
n=floor(L/r) records for supplied length L bytes, and P=nr bytes. Native
64-bit r=16 bytes; WoW64 r=8 bytes. Native requires L>=16, checks the separate
BaseAddress against the exclusive guest user limit, then output alignment of
8 bytes, probes all L bytes and optional SIZE_T ReturnLength, and validates
typed process query/query-limited rights. It writes n flag fields, preserves
all input addresses and incomplete final bytes, and publishes L last.

WoW64 first best-effort probes the optional 4-byte ReturnLength. A fault consumes
that guard and disables final publication. Minimum length and the separate
BaseAddress bound follow. Native conversion uses 16n scratch bytes; this
guest checks 16n against configured VirtualMemory::commit_limit before reading
input and returns STATUS_NO_MEMORY above that finite guest budget. That resource
threshold is a guest contract, not an asserted host-kernel threshold (W3).
There is no proportional host allocation. P bytes are read-probed before handle
validation, then write-probed after a successful handle check. Only P bytes
participate; incomplete tail bytes may be inaccessible. A successful query
publishes P last, kernel/capture/copy failures preserve ReturnLength, and an
initial ReturnLength fault disables publication even when shared-page output
later succeeds. Read-only input with a null handle therefore returns
STATUS_INVALID_HANDLE on WoW64 and STATUS_ACCESS_VIOLATION natively.

Input capture and writing flags cannot overwrite a later input address; the
kernel handler has no scheduler yield or callback. Probes establish the entire
processed extent before per-record work, with checked extent arithmetic.
n=floor(L/r) implies P<=L, so multiplication and offsets fit SIZE_T. WoW64
ReturnLength is at most 0xFFFFFFF8 bytes and fits ULONG. Runtime work is
O(q+n(log a+log s)): q input/output probe pages, a allocation records, and s
state-run boundaries in each allocation. Page-table residency lookup is bounded
by page-table depth. Auxiliary query storage is O(1); probes can populate guest
output/input pages normally. They never read or probe a separate target address.

Resident, committed and accessible guest pages use Valid bit0, actual reported
Win32Protection in bits4..14, normal priority5 in bits24..26. Resident guarded
or no-access pages use the Invalid union, Location=Resident in bits22..23 and
normal priority5. Their guards and residency are unchanged. Untouched committed,
reserved, freed, null and out-of-range targets return flags0 with query success.
All current Windows VM frame owners use Mapping::anonymous; image or NLS
classification does not create shared physical frames. ShareCount/Shared/
SharedOriginal remain zero. Node0, no locks, no large pages, no paging file,
modified standby list, bad-page or graphics state are the current closed guest
model (W2). Host-native transient share counts, ModifiedList and memory pressure
are not copied. Non-default memory-priority/lock/trim/sharing APIs remain explicit
service frontiers; this query does not claim they exist.

Primary layout: retained PHNT ntmmapi.h at
53fbbdc5b5d2b08761db1c7b26bfa8c820924356, lines230..295; public union/array,
QueryWorkingSetEx and default priority: MicrosoftDocs/sdk-api at
656e9656bfaef34dd29cd7ee9e1146aec17e924c. Original text and applicable
CC-BY4.0/code-MIT and PHNT notices are retained or cross-referenced with exact
SHA-256 checksums in sources.json. The two C++ oracles modify only their own
scratch/output pages, catch and distinguish SEH from NTSTATUS, and remove guards
only after observation to capture bytes. They ran with Visual Studio18.7.1
on Windows10.0.29683.1000 ARM64: native ARM64 and compatibility x86/x64, not
physical Intel/native32-bit kernels. Each ABI has 168 matrix, 30 fault, 6 rights
and 24 byte-capture queries: (168+30+6+24)*3=684 original queries. The checker
imports no emulator code or fixtures and verifies statuses, records, rights,
guard retention/order, aliases and all retained source hashes. Dynamic host
sharing/priority/list values are treated according to their valid union, not
asserted constant guest outputs.


## Validation ledger

The missing-service regression initially failed with explicit unsupported
class4 at RAX cd09c000, then passed. Ten shared tests cover all three guest ABIs
on each host. One additional Windows-only test executes actual selected ARM64
and x86 NTDLL leaves, including their return/stack cleanup, array lengths,
lazy residency, invalid targets and target guard retention.

| Final controlled validation | Result |
|---|---|
| Complete macOS RAX library | 7,525 passed, 0 failed, 2 ignored, 0 filtered; /tmp/assist-native-working-set-final-full-macos.log |
| Complete Linux RAX library | 7,519 passed, 0 failed, 2 ignored, 0 filtered; /tmp/assist-native-root-cpp-linux/native-working-set-final-full.log |
| Complete native Windows RAX library | 6,906 passed, 5 failed, 2 ignored, 0 filtered; /tmp/assist-native-windows-29683/native-working-set-final-full.log |
| Separate complete C API | 168 passed, no failures, ignored or filtered on each OS; corresponding final C API logs |
| Owning Assist archives / C++ consumers | RAX compiled into current locked archive on all three; five adapter/factory/disabled-factory/ABI/archive-link checks pass |
| All-target Rust builds | all three passed; corresponding final all-targets logs |
| Registered user_windows integration | 544 passed on macOS/Linux; cfg(unix) excludes native Windows |
| Registered user_windows_memory | 4 passed on native Windows; cfg(windows) excludes macOS/Linux |
| Ordinary native Windows startup | Four controlled programs still return STATUS_ACCESS_VIOLATION; final archive-output log |

The complete library selections are 7,527 / 7,521 / 6,913 tests on
macOS/Linux/Windows. Windows failures are the same four AArch64 BZHI lowerer
assertions and host-unavailable FP16 case. No lowerer, assertion or skip was
changed. Prior Linux readiness/exec/fork/io_uring timing failures remain
unresolved historical evidence; absence here is not remediation.
The first Windows transfer failed before any test ran. A subsequent test
compile exposed an incorrect constructor name in the new Windows-only test;
that was corrected to the existing spawn_image API and the complete library
rerun. Neither interrupted run establishes passing Windows library evidence.
Final transferred hashes match all five owned Rust files. The other OSes do
not compile this cfg(windows) test; its constructor correction changes no
production code or their selected tests. Current owning archives/C API compiled
the final production implementation and need no attribution to the excluded
Windows test compile.


## Loader frontier and quality gates

The final current-owning-archive isolated trace returns STATUS_SUCCESS for
class4 at scheduler slice2778, service0x23, PC0x180001240, arguments
[-1,0,4,0xABF530,80,0]. All five 16-byte records preserve target addresses
0x180001370, 0x1800014E0, 0x180001410, 0x1800013B0, 0x1800012A0; each flags
field is 0x05000201: Valid1, PAGE_EXECUTE_READ0x20, priority5, private guest
frame. This advances to slice3237, service0x12 NtOpenKey, PC0x180001130,
arguments [0xABE638,1,0x180360E70], named
\Registry\MACHINE\System\CurrentControlSet\Control\Session Manager. The
existing selected NLS snapshot explicitly rejects that key. The 459-slice
advance counts scheduler calls, not proven retired instructions. This retained
diagnostic clears PEB.ProcessHeap and enters a saved context; production
native loader/RTL heap/CRT bootstrap remains incomplete.

Self-red-team: target PTE inspection never invokes translation; target guard
bits remain armed; output/return guard priority has independent byte evidence;
read-only input and invalid handle cover WoW64 input capture; incomplete tails
are never copied; typed rights are shared with established class0/6; existing
export/service indices, C API1.11.0, layouts, dependencies, lockfiles, defaults,
permissions, discovery, packages, CPU/SMIR/JIT and other guest personalities
remain unchanged. Quality gates apply to this bounded semantic increment;
full-process acceptance remains open at the documented high-impact boundaries.
