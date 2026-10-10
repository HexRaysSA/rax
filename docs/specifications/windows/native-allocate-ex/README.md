# Native NtAllocateVirtualMemoryEx private allocations

Baseline: RAX 5819cac75703915de6e5eee6640944613e1c0ed7; Assist
451f3cac8c09369f81a269b87c230f812a864c3e. Both trees were clean before
this group. Concurrent root history/accounting work was committed separately as
f7ff53473bc0259816e2beb3ca482cb37ecf2df9. Initial owning builds use the
baseline root; final owning builds use an isolated worktree at that new root
commit. Those user changes are preserved. No real IDB, user profile or
persistent Assist state is used.

Acceptance: implement the actual seven-argument NT service used by installed
NTDLL, including default and nonzero address requirements, guest reservation/
commit state, status/probe/publication behavior, three guest ABIs and image LAA
limits. Use the existing guest VM allocator; no guest allocation is forwarded to
the host kernel. Preserve existing ordinary allocation semantics and unsupported
facilities. No ABI version/layout, options/defaults, permissions, persistence,
package, metadata/discovery, dependencies or instruction-lowering changes.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The captured NT profile governs these private allocations | Pinned PHNT declaration, Microsoft structures and 1,356 independently checked native observations on Windows10.0.29683.1000 | ABI capture, alignment, faults and publication | ARM64, compatibility x64, x86 non-LAA/LAA; guards, invalid pointers, duplicates, full array capture | Repeat original oracles on another release and physical x64 Windows | confirmed for measured profiles; other releases and physical x64 guard behavior unknown |
| A2 | Guest VM bounds, backing and existing image LAA policy own allocation results | Existing VirtualMemory allocator and process address-limit construction | Range selection and commitment | Occupied/untracked mappings, top-down search, impossible alignment, LAA at 2 GiB, commitment-limit rollback | Assert exact guest reservations/protection/data and toggle executable PE flags | confirmed by portable model tests; no host address or NUMA topology is inherited |
| A3 | This service removes the isolated loader dependency | Current owning-archive saved-context/cleared-PEB-heap diagnostic previously stops at service0x78 | Loader continuation | Actual installed NTDLL entry and current owning archive | Rerun the retained private diagnostic and ordinary process probes | confirmed for the private continuation: three allocation calls return0 before NtOpenPartition; production startup remains a separate gate |
| A4 | NUMA payload validation checks its complete64-bit value | SDK-typed aligned native oracle,32 calls including reserve and reserve-plus-commit controls | Guest node0 validation | Low32 bits zero with upper32 bits1 or0xFFFFFFFF, four measured ABI/image profiles | Native NtAllocateVirtualMemoryEx succeeds for a high-only payload | confirmed for measured profiles |
| A5 | WoW64 conversion precedes kernel validation; NUMA validation follows capture and process access | Independent alignment/mixed/handle/protection oracles,800 calls | Parameter capture/alignment and status precedence | Unknown/reserved/duplicate types plus faulting requirements; types1/3 versus2/4/5/6; invalid handle/type/access plus invalid NUMA/protection | Native status differs from the retained checker table | confirmed for measured profiles |
| A6 | The address-requirements payload is a full64-bit pointer even in WoW64 | Final24 native pointer-upper calls with valid low pointer controls | Deep capture address and fault result | Upper32 bits1/0xFFFFFFFF/0xA5A5A5A5 with mapped lower pointer; lower-only and null-low controls | WoW64 succeeds when a nonzero upper payload aliases its valid low pointer | confirmed; upper payload is not truncated |

High: production Ldr/RTL heap/CRT and ordinary Windows applications remain the
overall goal's acceptance gate; an isolated dependency test is not process
startup proof. Wider NT/POSIX, native application, IDA and package matrices remain
incomplete. Medium: other Windows releases and physical x64 guard behavior are
unknown. Partition/user-physical/image-machine extended facilities, nonzero
attribute policies and other-process allocations remain explicit boundaries of
this private allocation profile. These limits block a claim of full process
support; they do not invalidate the measured bounded service implementation.

## Contract and native evidence

Three original C++ oracles issue 500 final native calls: 53 allocation cases,
51 fault/count cases and 21 precedence cases for each of ARM64, compatibility
x64, x86 and x86 LAA. Every allocation created by the final helpers is released,
including allocations published before a WoW64 size-copy failure. Original
result bytes are retrieved through Base64 or an existing controlled host share
and independently matched against native SHA256 values. Failed
initial SEH compilation, a VM result-retrieval error and an initial x64 cleanup
helper error are excluded from passing evidence. Independent replay validates
all final statuses, guards, copy effects, releases, sizes, bounds and alignment;
it uses no fixed ASLR address for unconstrained success. No DLL is redistributed.

Additional native oracles contribute856 calls. The checker requires every
retained result file and validates exact status/output effects; missing files
are failures. SDK-typed records are explicitly16-byte aligned.

| Oracle | Calls across four ABI/image profiles | Purpose |
|---|---:|---|
| Original allocation/fault/precedence |500| Allocation and capture/publication contract |
| Aligned NUMA payload |32| Zero controls and nonzero upper32-bit payloads, two flag combinations |
| Parameter alignment |48| Types1/2/5 at offsets0/1/4/8 |
| Mixed capture |288| Unknown/reserved/duplicate records with pointed faults |
| Additional mixed types |240| Types0/3/4/6/7, conversion and capture precedence |
| NUMA/process access order |96| Invalid/self/thread/query-only handles and pointed faults |
| NUMA/protection order |128| Same boundaries plus invalid protection |
| Pointer union upper bytes |24| Full64-bit pointed payload in WoW64 and native64 |
| Total |1356| All observations replay successfully |

The initial minimal NUMA helper's16 calls are retained separately and excluded
from this passing corpus: its WoW64 zero controls return DATATYPE_MISALIGNMENT.
That helper did not record its original array address; the later controlled
alignment oracle identifies the conditional alignment contract without claiming
the earlier exact stack address. Initial transfer/compiler/helper failures do
not count as native behavior proof.

| Representation | Exact contract |
|---|---|
| NtAllocateVirtualMemoryEx | HANDLE, PVOID*, PSIZE_T, ULONG allocation type, ULONG protection, MEM_EXTENDED_PARAMETER*, ULONG count |
| MEM_EXTENDED_PARAMETER | 16 bytes on all three ABIs; 64-bit type/reserved field at0, 64-bit payload at8 |
| Address requirements | Three guest pointer-width values: lower address, inclusive highest ending address, base alignment; 12 bytes x86,24 bytes ARM64/x64 |
| Default requirements | Three zero fields equal omission; zero base selects an address; null-base COMMIT implicitly reserves |
| Bounds/alignment | Lower bound multiple of65,536 bytes; nonzero upper bound ends at granularity-1 and is below guest VM high; alignment zero or power of two >=65,536 bytes |
| Nonzero base | Nonzero requirements rejected; all-zero requirements preserve native page/granularity rounding of the existing allocator |
| NUMA/attributes | Guest node0 and attribute0 accepted; full64-bit nonzero NUMA rejected after capture/process access and before allocation/protection; nonzero attributes rejected during parsing; invalid/duplicate/reserved types rejected; no host NUMA policy forwarded |
| Full capture | Entire16*count-byte parameter extent probed before type or pointed-requirement validation; no proportional host buffer |
| ARM64/x64 parameter alignment | 8 bytes for parameter and requirements pointers; output pointer destinations may be unaligned |
| WoW64 capture | Count>6 rejected before output probes; all low-type1 requirements captured before kernel type validation; low-type1/3 conversion creates aligned parameters, otherwise original array needs8-byte alignment; pointed requirements allow unaligned addresses; size capture can consume a read guard as access violation |
| Output guards | ARM64 returns guard status; measured x64 compatibility output guards clear and retry; parameter/requirements guards return guard status |
| WoW64 publication | Base then size copied after allocation, including unsuccessful kernel results; a late size-copy fault retains an already published allocation |
| Failure atomicity | Native64 outputs probed before allocation; VM commit failure rolls back its newly created reservation; invalid/no-space requirements do not mutate allocations |

The Microsoft VirtualAlloc2 public wrapper requires page-size input and aligned
nonzero BaseAddress. The measured NT layer accepts size1/4097 and unaligned
nonzero base0x20000001. NT observations own this NT adapter; public-wrapper checks
are not imposed on it. The existing allocator rounds null-base size to pages and
fixed-base reservation start down to64 KiB, with the end rounded to4 KiB pages.

The actual loader request has zero requested base, size0x02001000 bytes,
MEM_RESERVE|MEM_TOP_DOWN (0x00102000), PAGE_READWRITE (4), one address-requirement
record and three zero requirements. Its size is32*2^20+4096=33,558,528 bytes,
or8,193 pages at4,096 bytes/page. Reservation size is page-rounded, while the
base address has64 KiB alignment. This request reserves guest address space;
it does not allocate those pages in the host process [A1,A2].

Address selection converts an inclusive nonzero upper bound H to the half-open
ceiling H+1, and uses L=max(requested lower,VM low). Rounded length is
ceil(size/4096)*4096. Before occupied ranges are examined, the first aligned
candidate must fit the empty interval; otherwise STATUS_INVALID_PARAMETER is
returned. If the interval is valid but occupied, STATUS_NO_MEMORY is returned.
The existing find_free() merges reservations and directly mapped VMAs, searches
bottom-up/top-down and supplies a fixed candidate to the ordinary allocator.
Null-base COMMIT adds RESERVE at that selected address so it retains implicit
reservation; the existing commit path owns rollback [A2].

With N occupied ranges, selection takes O(N log N) time and O(N) temporary space.
Native parameter probing takes O(P log M) time for P spanned pages and M address
mappings, with constant adapter scratch space; parsing can admit at most six
distinct declared types. WoW64 bounds count to six before probing. Output fields
span at most two pages each. Existing reservation metadata is proportional to
state/protection runs, not requested bytes. Existing commit work depends on the
number of committed guest pages. No new guest-controlled host-sized allocation
is introduced by the adapter.

Six portable cases fail before implementation:0 pass/6 fail/7,547 filtered.
Final twelve-case portable coverage adds fixed-base rounding, unaligned
destinations, commitment rollback, untracked mappings, PE LAA alignment,
conditional WoW64 parameter alignment, conversion-before-type capture and
NUMA capture/handle/protection precedence. The conditional alignment and mixed
capture tests fail before their adapter corrections; original failure logs are
retained. NUMA ordering is established independently by native observations; a
separate failing model execution before that last correction is not claimed. A Windows
case executes the actual installed host-ABI/x86 NTDLL entries, including RET28
callee cleanup, and checks guest reservations and committed zero-filled data.

## Change-surface map

| Plane | Status/evidence |
|---|---|
| Plugin lifecycle | No lifecycle or real IDA state change |
| UI state | No widget, theme, user copy or resource change |
| Conversation/lane | No history, lane, cancellation or transcript contract change |
| Agent backend | No native/ACP request change |
| Prompt/context | No prompt or trusted context change |
| Tool schema | Existing process tool; no schema/name/discovery change |
| Permission/mutation | Guest allocation only; existing host permissions and access gates retained |
| Main-thread dispatch | No IDA, Hex-Rays or Qt call introduced |
| Mesh/MCP | No routing, identity, transport or manifest change |
| Transport/crypto | No authentication or cryptographic input change |
| Persistence | No settings, history, schema or profile write |
| SDK/ABI | C API1.11.0 and layouts retained; only internal Rust allocation/dispatch added |
| Optional engines | RAX only; no optional backend or fallback policy change |
| Update/release | Published pin and engineering records; no release/package/default change |
| Targets/platforms | Common Rust allocator/service compiled on Windows/macOS/Linux; model tests on all three; installed NTDLL case on Windows; owning archives/C++ consumers checked separately |
| Tests/docs | Portable/installed entry tests, original native/replay evidence, source/gate hashes and loader continuation |

Final gate counts, owning-archive continuation and quality-gate audit follow.

## Validation phases

The source-hash registries distinguish each phase. The original implementation
has nine portable cases. The caller-frame correction only changes the
Windows-installed-entry test. Conditional WoW64 alignment/capture corrections
add two portable cases; the final NUMA precedence correction adds one more.
Earlier passing runs are evidence for their exact source, not the final adapter.

| Phase/host | Library pass/fail/ignore/filter | Selection | Other gates |
|---|---|---:|---|
| Original formatted macOS |7554/0/2/0|7556| C API168; all targets; Unix544 |
| Original formatted Linux container |7548/0/2/0|7550| C API168; all targets; Unix544 |
| Corrected caller Windows |6943/5/2/0|6950| Installed entry1; all targets |
| Capture-corrected macOS |7556/0/2/0|7558| Portable11; C API168; all targets; Unix544 |
| Capture-corrected Linux container |7548/2/2/0|7552| Portable11; C API168; all targets; parallel integration stalled |
| Capture-corrected Windows |6945/5/2/0|6952| Selected12; C API168; all targets; native memory4 |
| Final NUMA-corrected macOS |7557/0/2/0|7559| Portable12; C API168; all targets; Unix544 |
| Final NUMA-corrected Linux container |7550/1/2/0|7553| Portable12; C API168; all targets; Unix544 serial |
| Final NUMA-corrected Windows |6946/5/2/0|6953| Selected13; C API168; all targets; native memory4 |

Known Linux io_uring timer failures remain intermittent: both appear in the
capture-corrected full run; remove/update appears in the final full run. Windows
retains four BZHI assertions and the host-unavailable FP16 assertion; historical
strict thread-clock/readiness evidence remains unresolved. No unrelated timer,
lowerer, assertion or skip is changed. Full suites with those failures are
reported as failures.

The capture-corrected parallel Linux integration stops making output, has
zombie CLI children and zero observed CPU use. Its exact process/wait state is
retained in linux-parallel-integration-stall.txt. Only that owned container is
stopped; unrelated builds remain running. The cause is unknown. The final run
passes the complete544-case integration set with test-threads=1; it does not skip
fixtures, alter assertions or establish the stalled parallel path as passing.

Initial isolated owning Assist Rust archives and five C++ consumers pass all
three platforms at the original root baseline. Windows reports182 process-tool
and162 RAX-process checks; Linux184 and162. Disabled-RAX refusal, C API ABI
drift and static archive linkage are checked separately. The baseline macOS
owning CLI and all seven selected CTests pass, including both manifest checks;
compiled130 tools/26 conditional descriptors equal existing manifest bytes.
Protected CLI plaintext scanning reports0 failures. Final owning builds at
rootf7ff5347 pass the same five Linux consumers and all seven macOS CTests.
The current owning CLI plaintext scan reports0 failures; both manifest checks
pass. Final Windows owning validation passes all five consumers:182 process-tool
checks,162 RAX-process checks, disabled-RAX refusal, ABI drift and static
archive linkage. The exact transferred30-file rootf7ff5347 snapshot hashes
are retained; its unrelated changes are not included in this group. Completed final macOS/
Linux source and owning logs are retained with hashes in
numa-final-local-gate-hashes.json.

Linux is an x86-64 bullseye container on an ARM64 host; physical native x86-64
hardware is not claimed. Windows is build29683 ARM64 with compatibility x86/x64
oracles. Unix544 is cfg-excluded Windows; native external-memory4 is cfg-excluded
macOS/Linux. Plugin/Qt, a real IDB and the full package matrix are not exercised
by these focused owning builds. Original complete log bytes, native retrieval
hashes and source-phase registries distinguish compilation, controlled tests,
installed entries and private loader continuation.

## Installed-entry regression and caller-frame correction

The initial Windows full library run reports6,941 pass/7 fail/2 ignore/0 filter,
selection6,950. Four BZHI assertions, the host-unavailable FP16 assertion and
the previously observed strict thread-clock assertion fail. The seventh failure
is the new installed-entry allocation test; it is not counted as passing proof.
Its original ARM64 default/constrained calls and x86 default call succeed. The
second x86 call returns STATUS_INVALID_PARAMETER. The retained diagnostic source
and original native result bytes identify a test caller-frame error:

```text
first call ESP     0x0025FFC0
first RET 28 ESP   0x0025FFE0  (+4 return bytes +28 argument bytes)
second count slot  0x0025FFE0 +4 +6*4 =0x00260000
scratch/base field 0x00260000  overwritten with count1
```

The second call therefore captures a nonzero requested base with nonzero
address requirements, whose expected native status is INVALID_PARAMETER. The
test now recreates the caller's original stack frame before each call, while
retaining exact callee-cleanup, status, output size, address, state and guest-data
assertions. This also prevents successive x64 return slots from advancing the
argument area into scratch. That caller-frame correction makes no service/
allocator policy or portable model assertion change; the subsequent capture/NUMA adapter corrections are
recorded as separate source phases above. The corrected installed-entry/full-library gates are recorded above.

The original final-source Windows C API168, all-target compilation, native
external-memory4 and current locked owning archive/five C++ checks pass. Windows
process-tool reports182 checks and RAX-process162; disabled-RAX, ABI and archive
link checks pass. All four ordinary Windows process probes still return AV.
The corrected test does not change those shipping inputs; their exact production
and model hashes remain equal. Initial raw gate hashes, the failing diagnostic
source/log, primary source hashes and local gate hashes retain the distinction.

## Current owning-archive loader continuation

The exact original private diagnostic source is reused again with the final locked
owning Assist RAX rlib. It captures the saved thread context, clears only its
private emulated PEB heap field and enters selected LdrInitializeThunk. It does
not alter production process startup. Original source/output/build bytes are
retained and verified against native SHA256 in after-trace-hashes.json
(original source phase) and numa-final-native-owning-hashes.json (final adapter
and rootf7ff5347). Cargo compiler-artifact JSON selects the actual owning RAX
rlib; a guessed archive path is not used.

```text
turn11,315  NtAllocateVirtualMemoryEx: reserve33,558,528 bytes ->0
turn11,397  NtAllocateVirtualMemoryEx: commit4,096 bytes      ->0
turn11,542  NtAllocateVirtualMemoryEx: reserve4,295,098,368 B  ->0
turn12,660  NtOpenPartition service0x131 PC0x180002350        ->unsupported
```

The third reservation is0x100020000=2^32+131,072=4,295,098,368 bytes,
or1,048,608 pages. Reservation creates guest address metadata, without a host
allocation proportional to its requested length. Delta12,660-11,315=1,345 is
scheduler calls, not instructions. No exception is substituted for the explicit
next unsupported service. The four ordinary production probes still return AV;
the private saved-context/cleared-heap diagnostic is not full startup proof [A3].

## Final quality-gate audit

Independent replay verifies all1,356 native observations, including full64-bit
address-requirements pointers in WoW64, upper NUMA payloads, conditional capture/
alignment and NUMA/access/protection precedence. Final thirteen selected Windows
cases pass, including the installed entry, followed by the complete full suite,
C API168, all-target compilation and native memory4; its five full-suite failures
remain explicitly reported. The final owning archive/five C++ consumers and
private continuation complete. Final macOS/Linux gates are recorded above.
A missing re import in the added replay extension is corrected before the final
successful1,356-case replay; that failed checker execution is not native failure
or passing replay evidence. No production edit follows the final matrices.

| Root quality gate | Evidence/status for this bounded service group |
|---|---|
| QG1 normativity | Technical scope requires no normative judgment |
| QG2 assumptions | A1-A6 reconciled; stress probes and explicit unknowns retained |
| QG3 requirements | Seven-argument dispatch, bounds/state/capture/publication and guest ABI/image cases have source, native and model evidence; owning consumers checked |
| QG4 calculations | Page/granularity/union widths, inclusive bounds, reservation arithmetic and complexity reproduced above |
| QG5 edges/contradictions | Conditional WoW64 conversion, deferred NUMA validation, late output fault and caller-stack defect resolved for measured profile; known unrelated failures and other-release/native-x64 unknowns explicit |
| QG6 provenance | Seven retained primary source/license hashes match; original native sources/result bytes and independent checker retained |
| QG7 bounded scope | High overall-startup/application/package/IDA gaps and medium other-profile/parallel-stall limitations recorded; adjacent production behavior unchanged |

The RAX nine-gate audit additionally checks exact worktree ownership, native
behavioral evidence without skip/fallback, registered tests and source/target/
document consistency. Both indexes are empty before authorized exact-path
staging. Only this group's owned files are included; root publication owns
VENDORED_VERSIONS.md, src/emulation/native-process-emulation.md and the160000
submodule pin. Concurrent rootf7ff5347 is preserved as the publication parent.
Known full-suite failures do not become passing evidence. Full native process
startup remains incomplete and blocks completion of the overall goal.
