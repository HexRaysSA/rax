# Installed processor-feature query and initialization frontier

The retained oracle measures `NtQuerySystemInformation`, class 250
(`SystemProcessorFeaturesBitMapInformation` in phnt), on Windows
10.0.29683.1000 ARM64. The x86 and x64 probes use that installation's
compatibility execution profiles, not physical x86 or x64 kernels. The compiler
is Microsoft Visual Studio 2026 Community 18.7.1 with an ARM64 host.
`sources.json` records exact reference and probe SHA-256 values. Installed
Microsoft DLLs and public PDB binaries are not redistributed.

## Measured query contract

| Property | ARM64 / x64 | WoW64 x86 |
|---|---|---|
| Class | 250 | 250 rejected with `STATUS_INVALID_INFO_CLASS` (`0xC0000003`) |
| Layout | Two little-endian `ULONG64` words: 16 bytes = 128 bits | No output or `ReturnLength` publication |
| Bit index | Bit `k` reports processor-feature index `64 + k`, for `0 <= k < 128` | No conversion |
| Supplied length | At least 16 bytes and a multiple of 8 bytes | Rejection precedes destination probing |
| Successful write | First 16 bytes; excess supplied bytes unchanged | Neither destination touched |
| `ReturnLength` | 16 bytes on success or length mismatch; optional and unaligned accepted | Unchanged, including invalid or guarded pointers |
| Initial probes | For nonzero length, 4-byte output alignment then entire supplied output span; optional 4-byte `ReturnLength` write probe next | Neither probe occurs |
| Alias | Output first, `ReturnLength` second | No publication |
| Guard page | `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`), one encountered guard consumed | Guard remains armed |

The native bitmap on this installation is `0x000000004000001B` followed by a
zero word. Its set bits 0, 1, 3, 4 and 30 correspond to API indices 64, 65,
67, 68 and 94. Treating those bits as baseline indices 0, 1, 3, 4 and 30
would conflate two distinct processor-feature ranges. The local oracle compares
the extended indices with `IsProcessorFeaturePresent`; the retained Wine test
independently compares `64 + k` with `RtlIsProcessorFeaturePresent`.

The RAX guest uses its existing CPU feature policy. `KUSER_SHARED_DATA` contains
64 baseline BOOLEAN bytes at offset `0x274`; HLE API results and this startup
array now share that policy. The class-250 bitmap describes the separate
extended indices 64 through 191. The current policy does not advertise any
extended index, so its extended bitmap is zero. Host features are not copied.
Unknown processor-feature indices remain false. The 128-bit bitmap costs
O(128) feature evaluations and O(16) bytes of additional storage; the baseline
array costs O(64) evaluations and O(64) bytes during spawn.

## Native initialization remains incomplete

The retained initial startup driver captures the first ARM64 fault at
`0x180026528` inside installed NTDLL. Register `X19` is the HLE process-heap
handle `0x10000`. The preceding load reads `[X19 + 0x138] = 0x80006`; the
faulting load reads `[0x80006 + 8] = [0x8000E]`. The HLE heap reserves only
`0x100` bytes for its header. Later loader allocations occupy the location
native RTL interprets as heap metadata. The public symbol label at the fault
is `RtlpAllocateNTHeapInternal + 0xD8`.

An isolated call to exported `RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL,
NULL)` with guest `PEB.ProcessHeap` cleared still faults. It dereferences a
null pointer at `RtlpWaitOnCriticalSection + 0xDC` (`0x18003D4DC`), using the
uninitialized native `RtlpProcessHeapsLock` at `0x1803CAD80`. A value returned
to the callback frontier by `CSpecificHandler` is an exception-search result,
not a heap handle; it is rejected. No valid native heap was created.

The isolated `LdrInitializeThunk` driver receives an actual guest `CONTEXT`
image and reaches class 250 after 36 instructions. The retained before-change
trace ends in an explicit unimplemented-query result. These drivers use the
locked Assist dependency's core RAX library at commit
`4ec0b557c31bafb82b5cc0c41dd7ff1c8a99bc46`, a 268,435,456-byte guest arena,
closed general host filesystem access, and one-instruction scheduling slices.
They establish diagnostic frontiers, not completed native process startup.

After class 250 is implemented, the same isolated driver reaches instruction
141 and stops explicitly at `NtCreateEvent`, service `0x48` at `0x1800014C0`.
The query prerequisite advances the diagnostic path; it does not add a native
loader initialization phase to the production lifecycle. The four current
ordinary installed-DLL startup probes still end with guest access violations.

Public symbol labels are diagnostic inference. The installed image CodeView
GUID is `7DB9D778-C2F5-4816-1C99-84382D15362E`, age 1. Microsoft's corresponding
public symbol-server response has the same GUID, age 4, and corroborates the
export RVAs (`RtlCreateHeap = 0x24F40`, `LdrInitializeThunk = 0xEF6E0`). The
age difference is retained explicitly; no exact private-symbol match is
asserted. The PDB source is
`https://msdl.microsoft.com/download/symbols/ntdll.pdb/7DB9D778C2F548161C9984382D15362E1/ntdll.pdb`.

```text
modeled HLE process heap -> native DLL startup -> incompatible heap read -> AV
PEB.ProcessHeap = NULL   -> native RtlCreateHeap -> uninitialized lock read -> AV
native LdrInitializeThunk -> class 250 query -> kernel prerequisite frontier
```

## Assumptions and scope

| ID | Assumption and dependent result | Basis | Stress test / falsification probe | Status |
|---|---|---|---|---|
| F1 | Bitmap bit `k` means PF `64 + k`; query serialization depends on it | Native API comparison plus retained Wine test | Compare all 128 bits with native RTL on another Windows build | Confirmed on recorded ARM64/x64 profiles; broader builds unknown |
| F2 | Extended guest feature indices currently remain false | Existing guest policy's default-false branches | Inspect every feature consumer; enable a known extended guest feature and require bitmap/API parity | Confirmed current policy; no host capability import |
| F3 | Recorded length, probing, alias and WoW64 rules define this native profile | Three native oracle logs | Null, misaligned, readonly, guarded, oversized and overlapping destinations | Confirmed recorded profiles; another kernel build unknown |
| F4 | Initial guest CPUs share the process feature model used for shared-data initialization | Created main-thread CPU and HLE CPUID-based implementation | Compare each guest ABI's shared bytes with API results and child-thread CPU policy | Retained for the default stable process CPU profile; external post-spawn CPU model replacement is outside this claim |

High, blocking full native process support: real NTDLL process initialization,
native RTL heap bootstrap, broader NT services and ordinary Win32/CRT startup
remain incomplete. Medium: private query behavior and symbolic labels require
new native evidence on another Windows build or architecture. Neither item is
resolved by a passing query leaf or a passing HLE process fixture.

Primary public API sources are retained unchanged: Microsoft's
`KUSER_SHARED_DATA` and `RtlCreateHeap` pages, the public symbol-server guide,
phnt declarations, and Wine's native query test. Microsoft's existing
[`IsProcessorFeaturePresent`](../services/slist/isprocessorfeaturepresent.md)
and [`NtQuerySystemInformation`](../native-query/ntquerysysteminformation.md)
reference copies supply the baseline public API contracts; inspect their
provenance alongside the private native observations.
