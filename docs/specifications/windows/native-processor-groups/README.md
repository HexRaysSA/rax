# Native processor-group query

This semantic group implements `NtQuerySystemInformationEx` class107
(`SystemLogicalProcessorAndGroupInformation`), relationship4 (`RelationGroup`)
through the existing admitted NTDLL service registry. It returns the modeled
process's one CPU, active mask1 and one processor group. Host CPU counts and
affinity are not copied into the guest; the measured host had eight processors
and mask0xFF. Other classes/relationships remain explicit unsupported stops.

The C ABI remains1.11.0. No host kernel request is forwarded, and no permission,
default feature, dependency, persisted format, DLL selection or package layout
changes. This group does not establish ordinary native Windows process startup.

## Assumptions and bounded scope

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | This modeled process has one CPU and one group | Startup writes PEB.NumberOfProcessors=1; existing basic-system query returns processor count1 / active mask1 | MaximumProcessorCount=ActiveProcessorCount=1, one active group, mask1 | All guest ABIs; consistency with existing PEB/system queries | A configurable CPU topology or existing consumer contradicts those owners | confirmed for the current model; SMP is outside this group |
| A2 | The measured buffer contract applies to the selected Windows10.0.29683.1000 runtime | Native ARM64, x64 compatibility, x86 and x86 LAA originals with native-side SHA256 | Native64 and WoW64 query paths | Every output field boundary, extra spans, aliases, guard repeats and upper limits | Recompile the retained oracle on another runtime and compare observations | confirmed for these four profiles; other releases unknown |
| A3 | The next private loader request is class107 / relationship4 | Owning archive trace reads input bytes04 00 00 00 at the previous service stop | First supported extended query | Repeat owning continuation after implementation | Another class/relationship precedes this call in the same continuation | confirmed |
| A4 | ReturnLength follows the same upper-limit range-before-page ordering as the declared spans | Initial inference from generic probe documentation | First attempted upper-limit guard test | Native guard at the last user page | Native ReturnLength consumes the guard before reporting a crossing store | falsified; the implementation and regression preserve the distinct direct-touch path |

High, overall-goal blocker: ordinary native Windows heap/bootstrap still needs
separate work. The private continuation restores a saved loader context and
clears the PEB heap pointer; it is not the ordinary process-start path. Medium,
not this group's blocker: native multi-group/high-mask conversion remains
unknown on this eight-CPU, one-group host. Medium, not this group's blocker:
the separately recorded Linux timeout and Windows lowerer failures are not
remediated here.

## Primary definitions and exact byte layout

The class107 identity and six-argument prototype are in the retained
[PHNT ntexapi.h](../native-processor-features/phnt-ntexapi.h), pinned to
[53fbbdc5b5d2b08761db1c7b26bfa8c820924356](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntexapi.h).
Its MIT license is retained beside that header. The public layout is
[SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex).
The buffer mechanics below are native observations, rather than a claim that
this undocumented NT entry has a cross-version public guarantee.

| Field | Byte offset | Extent in bytes | Guest value |
|---|---|---|---|
| Relationship | 0 | 4 | 4 |
| Size | 4 | 4 | 76 / 80 |
| MaximumGroupCount | 8 | 2 | 1 |
| ActiveGroupCount | 10 | 2 | 1 |
| Group.Reserved | 12 | 20 | zero |
| MaximumProcessorCount | 32 | 1 | 1 |
| ActiveProcessorCount | 33 | 1 | 1 |
| GroupInfo.Reserved | 34 | 38 | zero |
| ActiveProcessorMask | 72 | 4 / 8 | 1 |

Exact integer arithmetic: header8B + group prefix24B + processor-group prefix40B
+ pointer-width4/8B =76/80B. WoW64 writes76B; native64 writes80B. A larger supplied
capacity leaves its suffix unchanged. Short capacity returns
`STATUS_INFO_LENGTH_MISMATCH` and publishes the required length when possible.

Absent input pointer or zero input length returns `STATUS_INVALID_PARAMETER`
before destination probes. Nonempty input requires four-byte alignment on every
ABI. The relationship DWORD is captured before aliasing output/length writes;
the extra supplied input span need not be mapped. Native64 checks that its
declared input span stays within the modeled user-address limit; WoW64 captures
only the DWORD, including a supplied input length of `ULONG_MAX`.

The generic [ProbeForRead](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread)
and [ProbeForWrite](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforwrite)
contracts distinguish range checks from page touches. The retained native upper
guard probes establish the ordering for this entry:

```text
native64 input/output crossing user limit -> access violation, guard stays armed
native64 ReturnLength crossing user limit -> guard violation, guard is consumed
```

Native64 probes the entire supplied output span (four-byte base alignment) and
then ReturnLength before class/length dispatch. WoW64 skips those destination
probes, converts output fields directly, writes the header after group fields,
then publishes ReturnLength. Its output and ReturnLength accept unaligned
addresses. Native64 ReturnLength also accepts unaligned addresses.

```text
WoW64 partial publication:
counts[8..12) -> reserved[12..28) -> reserved[28..32)
 -> maxCPU[32] -> activeCPU[33] -> mask[72..76)
 -> reserved[34..72) -> relationship[0..4) -> size[4..8)
 -> ReturnLength
```

Native boundary prefixes below76B reproduce those partial writes. A fault in
the converted destination leaves ReturnLength unchanged. A fault in ReturnLength
can leave the complete WoW64 output, whereas native64 output remains untouched
when its pre-dispatch ReturnLength probe fails.

For output length L and page size P=4096B, native64 validation is
O(ceil(L/P)) time plus constant record construction; WoW64 is O(1). Both use
O(1) auxiliary space, at most80B of record storage. Input lengths never drive
an allocation or page walk. No topology collection is acquired from the host.

## Reproduction, validation and limits

Run `python3 check_native_processor_groups.py` in this directory. Required
originals, source hashes, native field values and validation counts are checked;
missing or altered inputs fail. Python optimization mode is rejected so replay
cannot silently discard assertions.

The oracle uses only its own allocated/protected buffers and read-only system
queries. Four compiled profiles each contain371 general observations; the two
64-bit profiles add three upper-limit guard observations, for
4*371+2*3=1490 native observations. x64 here is Windows ARM64 compatibility;
a physical x86-64 kernel oracle remains unknown. No installed DLL is included.

Eleven portable library tests cover the three guest ABIs, including lengths,
alignment, null pointers, ordering, every output boundary, extra spans, guard
consumption, aliases, optional ReturnLength, explicit unsupported diagnostics,
and upper-limit spans. One Windows-only test executes the selected installed
host and WoW64 leaves, including actual x86 RET24 / total caller-SP delta28B.
That leaf is cfg-excluded on non-Windows hosts, rather than claimed as native
Windows coverage there.

The behavioral baseline records the admitted service's missing implementation.
The before continuation stops at turn13286 with class107, relationship4,
input length4B, output capacity3152B and no ReturnLength. Final validation and
the owning continuation are recorded in `validation.json` and their originals.

| Host | Full library passed/failed/ignored/filtered | Focused group tests | C API | All targets | Affected integration |
|---|---|---|---|---|---|
| macOS ARM64 | 7569 / 0 / 2 / 0 | 11 passed | 168 passed | passed | Unix Windows-fixture544 passed; Windows-memory0 by cfg |
| Linux amd64 container | 7562 / 1 / 2 / 0 | 11 passed | 168 passed | passed | Unix Windows-fixture544 passed; Windows-memory0 by cfg |
| Windows ARM64 | 6959 / 5 / 2 / 0 | 12 passed, including selected native/WoW64 leaves | 168 passed | passed | Windows-memory4 passed; Unix fixture suite cfg-excluded |

Linux's final full run retains `a_timeout_is_removed_or_updated`; an interim run
also failed `a_multishot_timeout_reports_each_expiry`. All nine timeout tests pass
when run alone with one test thread. Their cause and native-kernel agreement
remain unknown. Windows retains the same four BZHI and one FP16 lowerer failures.
The full suites are not collectively green.

All five owning C++ consumers pass on each host: process-tool184 checks on
macOS/Linux and182 on Windows, process adapter162, disabled-RAX refusal,
ABI1.11/header1.11 and one-archive linking. macOS also builds the idalib CLI,
runs seven selected CTests and passes protected plaintext scanning. Linux
amd64 execution here uses host translation; it is not physical x86-64 kernel
proof. Windows uses a freshly paired C API/Assist rebuild after the standalone
profile, then fresh compiler-artifact JSON selects the exact owning core.
Both Windows archives pass structural member walks (4673 and260 members).

The byte-identical owning continuation returns success for service0x16E at
turn13286, then stops at turn33364 on `NtQuerySystemInformation` class197
(service0x36, PC0x1800013A0, output0xABEB08, capacity8B, ReturnLength0).
33364-13286=20078 additional scheduler calls; this is not an instruction count.

```text
class107 / RelationGroup stop13286
    -> group query succeeds; installed loader/allocator continues
    -> class197 stop33364
```

Four ordinary native process probes still return `STATUS_ACCESS_VIOLATION`.
The continuation proves the narrower service/loader progress; it does not prove
ordinary native initialization or full Windows userland support.

The change surface is confined to the native export registry, pure guest query,
registered scheduler/leaf tests, evidence and the root RAX pin. Direct ISA, SMIR,
JIT, backends, C ABI, main-thread/Qt ownership, UI, tools, permissions, mesh,
transport, persistence, update policy and package layout retain their existing
contracts. The owning archives compile the same query on Windows, macOS and
Linux. Native IDA/product/package execution remains separate from archive and
controlled-target checks.
