# Native NUMA processor-map query evidence

This group implements NtQuerySystemInformation class55, SystemNumaProcessorMap,
for RAX's existing node0/group0/single-processor Windows guest. HighestNodeNumber
is0 and processor mask1. No host topology, host virtual address or kernel call
is transferred into the guest. Other query classes retain their previous policy.

Baseline RAX:da90b59312b971e3b0d06862eb41a335771516e2; owning Assist root:
fe3155bb1446b067dcacf10b1c8834db929c083c. Its compiled owning C++ source remains
c4cb8f6a0dd7c0d068d2defd411599fba9e32b7e: later root changes are engineering
records and Gitlinks. Four final compiled RAX source hashes are recorded in
source-hashes-reviewed.json; native-runtime.md is a fifth owned source path.

## Primary declarations and independent observations

The pinned [PHNT declaration](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntexapi.h)
identifies class55 and SYSTEM_NUMA_INFORMATION: HighestNodeNumber, Reserved,
and a union containing GROUP_AFFINITY records and a ULONGLONG padding array.
MAXIMUM_NODE_COUNT is16/64 for x86/native64; complete declared sizes are
264/1032 bytes. Those declarations do not require the query to write the entire
structure. The pinned header/license in ../native-processor-features are hashed
by the checker. Microsoft's
[GetNumaHighestNodeNumber](https://learn.microsoft.com/en-us/windows/win32/api/systemtopologyapi/nf-systemtopologyapi-getnumahighestnodenumber)
contract distinguishes highest node number from total node count. Guest node0
comes from the existing single-NUMA-node allocation and CPU/group model.

Four selected Windows11 build10.0.29683.1000 profiles retain395 ordinary rows
each; native64 adds two upper-user-range guard rows each:
4*395+2*2=1584 observations. Profiles are ARM64, x64 compatibility, x86 WoW64,
and x86 WoW64 LARGEADDRESSAWARE. Actual PE machine/LAA identities and executable
hashes are recorded without redistributing executable bytes. x64 compatibility
on ARM64 is distinct from physical native x64 kernel proof.

The producer initializes private output/returned regions to0xA5. VirtualQuery
and ReadProcessMemory snapshots clip accessible extents and skip armed guards,
so observation cannot consume them. Every external SEH code is zero. Captures
cover short/adequate/oversized lengths, pointer alignment, nulls, read-only and
unmapped destinations, output and ReturnLength page crossings, aliases,
one-shot guard/repeated calls, user-range overflow and ULONG_MAX span probes.
Snapshots capture up to2048 bytes, independently proving untouched padding,
unused records, suffixes, and converted native tails.

| Query behavior | Native64 | Selected WoW64 |
|---|---|---|
| Nonzero output |DWORD alignment; full declared write span probed |Same native output alignment/span probe |
| Native upper output span |Reject before consuming guard |Original32-bit address widened for native probe |
| Caller ReturnLength preprobe |Direct4-byte write probe before dispatch |Private stack ReturnLength instead |
| L<4 bytes |INFO_LENGTH_MISMATCH; publish4 if ReturnLength valid |INFO_LENGTH_MISMATCH; caller ReturnLength untouched |
| 4<=L<24 bytes |SUCCESS; write HighestNodeNumber only; return4 |Same output; caller ReturnLength4 after success |
| L>=24 bytes, one node |Write HighestNodeNumber and16-byte affinity at+8; return24 |Native write then in-place12-byte affinity conversion; return20 |
| Reserved at+4 |Preserved |Preserved |
| Native tail at+20..24 |Written by native affinity |Survives conversion; still zero for this node/group |
| ReturnLength fault |Prevents output publication |Occurs after successful output/conversion |
| Aliased ReturnLength |Published last |Published last |
| ULONG_MAX with output guard |Guard before later unmapped-span failure |Same; no temporary output capture allocation |

The one-node native host mask is0xFF; the guest projects mask1. The guest affinity
bytes at+8..24 are mask1 as a native64 value, group0 and zero reserved fields.
WoW64's in-place conversion folds low32(mask)|high32(mask), writes group at+12
and zeroes its reserved fields, leaving the original native tail. These exact
bytes coincide for the current one-CPU guest. A future topology change must
revisit mask folding, record count/extent and all consumers together.

Status values: SUCCESS0x00000000; INFO_LENGTH_MISMATCH0xC0000004;
ACCESS_VIOLATION0xC0000005; DATATYPE_MISALIGNMENT0x80000002;
GUARD_PAGE_VIOLATION0x80000001. PAGE_GUARD is one-shot as described in Microsoft's
[memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants).
Native64 upper-span rejection leaves its guard armed; a ReturnLength store
crossing the upper boundary consumes its first-page guard. ULONG_MAX probes
consume an encountered output guard before later accessible-span failure,
without a WoW64 conversion allocation or NO_MEMORY translation.

## Matching WoW64 symbol/instruction provenance

wow64-wrapper-provenance.json records the exact selected System32 wow64.dll
identity, PE ARM64 image base, Microsoft symbol URL and matching PDB hashes/GUID.
The unchanged module is reverified along with both NTDLL files after capture.
RSDS age1 matches DBI age1; PDB information-stream age3 is separately retained.
wow64-pdb-identity.txt is the bounded original LLVM identity output. DLL/PDB
bytes, complete public-symbol lists and full disassembly remain private.

PDB dispatcher whNtQuerySystemInformation is RVA0x18980; its class55 case calls
whNtQuerySystemInformation_SpecialQueryCase at RVA0x19B60. The selected class55
body is RVA0x1A3A4. It forwards the original output address/ULONG length with a
private stack ReturnLength; a negative status bypasses caller-length publication.
On success its conversionCount is nativeReturned>8 ?(nativeReturned-8)>>4:0;
each converted affinity is12 bytes. The published caller length is
min(nativeReturned,8+12*conversionCount):4 or20 for this selected one-node host.
Original captured data and matching instructions independently establish that
reported20 bytes can coexist with24 native bytes having been written.

Production scratch space is a fixed16-byte affinity; extra space is O(1).
Time complexity is O(ceil(L/4096)) for whole-span probes, with checked native64
range addition. L is a ULONG byte count and the probe widens its address arithmetic.
No caller-sized host allocation or persistent VM mutation is introduced.

The seven initial behavioral regressions fail against the unsupported class55
baseline. An eighth regression covers ULONG_MAX guard/probe ordering. The first
post-edit run has7pass/1fail: its ReturnLength guard incorrectly lies inside the
huge output's first mapped span, so that guard becomes the actual first fault.
The fixture is corrected by placing an inaccessible gap before ReturnLength,
matching the native producer's independent regions; production code is unchanged
by that correction. The final eight portable tests pass. The initial missing
fixture import is retained separately as a compilation attempt, not a behavioral
baseline. Phase logs and frozen final source hashes distinguish those results.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Final status |
|---|---|---|---|---|---|---|
| A1 |Guest has node0/group0 and one CPU |Existing NUMA allocation validation, PEB/basic/group queries |Highest0/mask1 |All guest ABIs and installed leaves |Find conflicting guest topology contract |confirmed |
| A2 |Selected build buffer contract applies to selected runtime |Fresh selected DLL hashes;1584 original observations |Probe/store/length ordering |Nulls, aliases, whole span, odd sizes, guards |Raw replay mismatch |confirmed for selected build |
| A3 |Full PHNT declaration size and returned query extent differ |264/1032-byte declarations versus4/24 native return and4/20 WoW return |Variable output sizing; preserved padding |L0..25 and declared-size boundaries |Returned length/data differs |revised and confirmed |
| A4 |Private loader diagnostic only measures kernel-query continuation |Cleared PEB heap/manual saved-context Ldr entry |Limit on startup claim |Separate ordinary programs and production trace |Ordinary startup completes independently |confirmed limitation |
| A5 |WoW mask folding is equivalent to mask1 bytes for current topology |Matching class55 instructions and one-CPU contract |Fixed16-byte guest affinity write |Future high32 mask or extra node |Guest topology ceases to be one CPU/node/group |confirmed for current profile |

## Change surface and bounded findings

| Plane | Status and owning evidence |
|---|---|
| Plugin lifecycle |Unaffected: no plugin/lifecycle code changes; guest query only |
| UI state |Unaffected: no Qt/widget/copy changes |
| Conversation/lane |Unaffected: existing process result and failure paths |
| Agent backend |Unaffected: native/ACP request contracts unchanged |
| Prompt/context |Unaffected: no prompt/context source changes |
| Tool schema |Unaffected: process tool names/schema/metadata unchanged |
| Permission/mutation |Unaffected: existing native-runtime file scope; no host kernel forwarding |
| Main-thread dispatch |Unaffected: Rust guest memory only; no IDA/Qt API calls |
| Mesh/MCP |Unaffected: no registration/discovery/transport changes |
| Transport/crypto |Unaffected: no transport, identity, secret or crypto changes |
| Persistence |Unaffected: no settings/history/schema/persisted runtime format changes |
| SDK/ABI |Unaffected: C API1.11.0 and public headers unchanged; owning drift/link tests |
| Optional engines |Unaffected: no JIT/KVM/HVF/default/ISA/lifter/lowerer change |
| Update/release |Unaffected: no version grammar/package/dependency/release changes |
| Targets/platforms |Affected: shared RAX guest query compiled/tested on all three; installed-leaf adapter Windows-only; existing owning archive/C++/CLI consumers |
| Tests/docs |Affected: eight portable and one installed-leaf test; native producer/replay/source/gate records; engineering pin documents |

High: ordinary native Windows bootstrap/RTL heap/CRT and wider native
application/package/IDA matrices still block the full userland goal. Medium:
retained Linux timing and five Windows lowering failures limit broad validation;
physical native x64 kernel evidence is absent from translated/compatibility runs.
Medium: later topology expansion would invalidate this one-node projection.
No nonblocking adjacent implementation is changed. Ordinary production bootstrap
is observed separately without PEB/context/startup changes.

## Final recorded standard and owning gates

| Host/environment |Targeted |Full pass/fail/ignored/filtered |C API |All targets |Affected integration |
|---|---|---|---|---|---|
|macOS ARM64 native |8 |7588/0/2/0 |168 |pass |Unix Windows fixtures544; Windows memory cfg0 |
|Linux x86-64 container under ARM64 translation |8 |7581/1/2/0 |168 |pass |Unix Windows fixtures544; Windows memory cfg0 |
|Windows ARM64 native |9 |6980/5/2/0 |168 |pass |Native Windows memory4; Unix fixtures cfg-excluded |

Selected full counts are7590/7584/6987. The Windows installed-leaf test makes
ten calls: five lengths on ARM64 and WoW64, checking actual caller cleanup.
Linux's full failure is a_timeout_is_removed_or_updated; the isolated nine-timeout
selection passes. The full-run cause is unknown. Windows retains four BZHI flag
assertions and one FP16 vector assertion. Exact names/original terminal summaries
are in validation.json and the raw logs. No all-suite success is claimed.

All five owning Linux C++ consumers pass, including process-tool184 checks,
RAX-disabled refusal, process ABI162 checks, version1.11 drift and the single
Rust archive's runtime/allocator/unwinding. Owning macOS CLI rebuild/seven CTests
and one protected-text artifact scan pass with zero scan failures. The Linux
focused-timeout setup attempt omitted the pinned toolchain environment and
attempted an unavailable channel download; that original setup failure is
separate from the successful pinned nine-test selection. It is not a test failure.


All five native Windows owning C++ consumers pass: process-tool182 checks,
RAX-disabled refusal, process ABI162 checks, version1.11 drift and archive runtime/
allocator/unwinding. Fresh owning Assist/core archives pass complete structural
walks of4673/260 members. Their lengths/SHA256 and the four native source hashes
are in native-owning-archive-hashes.json. The continuation is linked to the same
owning build's fresh feature-empty RAX core artifact; Cargo JSON is retained.

## Paired continuation and ordinary startup

The byte-identical private cleared-heap/saved-context observer changes from an
unsupported class55 stop at33566 to SUCCESS at that call, then reaches unsupported
NtQuerySystemInformationEx class107 relationship6 at40500. The difference is
40500-33566=6934 additional scheduler calls, not instructions. That diagnostic
modifies PEB.ProcessHeap and manually enters installed LdrInitializeThunk; it
does not establish ordinary production startup.

Four ordinary C++ programs using the fresh Assist archive (smoke, MSVCRT/UCRT
streams and whoami) still exit with STATUS_ACCESS_VIOLATION. The separate
native-numa-after-production-trace.rs observer leaves startup, PEB and CPU context
as selected by spawn_image. It observes the first exception at turn1459:
NTDLL PC0x180026528, SP0xABF9C0. The trace records X19=0x10000, the published HLE
heap handle; LDR X8,[X19,#312] loads0x80006 and LDR W9,[X8,#8] faults at0x8000E.
The ordinary trace terminates at1500 with0xC0000005. The exact internal NTDLL
routine name remains unknown; no export-name inference is needed for the fault.
Source separately establishes that start.rs publishes the HLE heap into the
PEB in native mode, heap.rs retains allocator metadata in Rust maps rather than
a native RTL heap header, and lifecycle.rs uses synthetic RtlUserThreadStart
and host-managed notifications. This high-impact bootstrap contract blocks the
full userland goal and is outside the class55 semantic group.

## Reproduction and quality gates

Run python3 check_native_numa_map.py from any directory. The checker requires
evidence-hashes.json, checks every retained byte identity, four compiled source
hashes, primary declaration/license identities, producer/profile identities,
matching PDB ages/GUID, all1584 native statuses/captured bytes/aliases/guard states,
22 recorded gates, exact retained full-suite failures, owning artifact/source
coherence, paired continuation and the ordinary first-fault observation. A later
source change requires --source-root pointing to this group's frozen checkout.
Replaying records does not execute the native oracle or any recorded build.
Python -O, missing manifests and tampered inputs are rejected. Original drivers
record the selected host setup and absolute paths; they are capture scripts,
not a portable one-command provisioning procedure. The exact owning C++ helper sources are retained as assist-cpp-build.py and
owning-linux-cpp-build.py, with native-process-probe.cpp for ordinary programs.
The Windows helpers were copied and hash-verified from the native build host.

The initial producer identity in baseline.json is a planning-phase identity;
the final395-case source/profile identities are native-probe-hashes-reviewed.json
and the checker's frozen source hash. Original CRLF/raw logs are preserved.
No DLL, PDB, EXE, full private disassembly or complete symbol list is redistributed.

| Gate | Class55 acceptance evidence and limit |
|---|---|
| QG1 | No normative content required |
| QG2 | A1-A5 register includes stress/falsification probes and final status |
| QG3 | Query semantics, dispatch/cleanup, three-host builds and owning consumers covered; full userland goal remains active |
| QG4 | Byte extents, status values, mask projection, allocation-free probes and scheduler-call delta reproducible |
| QG5 | Initial fixture conflict corrected; selected contract edge cases replayed; broader bootstrap failures explicitly bounded |
| QG6 | Pinned PHNT/license, selected native DLL/PDB identity, original captures/source/archive hashes verified |
| QG7 | High bootstrap blocker and medium suite/environment/topology limits recorded; no adjacent implementation changed |
