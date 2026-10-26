# Private x86 TEB second page

Installed x86 NTDLL on Windows 10.0.29695 writes its scheduler shared-data
slot at `TEB + 0x1018`. The previous RAX allocation placed the PEB after one
4096-byte x86 TEB page. This made that write replace `PEB.ProcessHeap` with
the scheduler mapping address. A later RTL allocation dereferenced an absent
heap lookup table and faulted at address `0x4`.

The primary evidence is the selected installed DLL's instruction bytes and
RAX's CPU register/memory observations in [trace-29695-v1.json](trace-29695-v1.json).
The store observer stopped immediately before `NTDLL + 0xb71c8`: EDI equaled
the guest TEB, `0x7ffde000`. Executing `89 87 18 10 00 00` wrote EAX to
`0x7ffde000 + 0x1018 = 0x7ffdf018`, which was the PEB at `0x7ffdf000`
plus its `ProcessHeap` offset `0x18`. A separate repeated-visit observer
isolated the later fault at `NTDLL + 0x94477`, `cmp edx, [eax+4]`, with EAX zero.
The earlier successful visits to that instruction were not faults.

These are guest-execution traces on an ARM64 Windows kernel using its selected
installed x86 DLL. They are not independent physical-x86 or AMD64-kernel
controls, and do not establish an exact private `sizeof(TEB)`.

## Allocation contract

The minimum observed extent is `0x1018 + 4 = 0x101c` bytes. Rounding this
up to a 4096-byte page gives 8192 bytes. Both x86 and native64 TEB allocations
now reserve and commit two private pages. The native64 companion remains
8192 bytes before the x86 TEB; its reverse offsets and TLS identities are unchanged.

| View | Previous bytes | Current bytes |
|---|---:|---:|
| Ordinary x86 TEB | 4096 | 8192 |
| Ordinary native64 TEB | 8192 | 8192 |
| WoW64 native64 + x86 pair | 12288 | 16384 |

The extent comes from `layout::offsets(arch).teb_size` for allocation,
commitment, ownership claims and teardown. Companion allocation adds the two
extents rather than retaining a one-page x86 assumption. Calculating the extent
uses constant time and storage; the arena's existing selection algorithm is
unchanged. Commitment increases by 4096 bytes for each x86 thread.

## Regression boundaries

The ordinary regression exercises x86, x64 and ARM64 guest profiles. It writes
the entire second page, verifies PEB and neighboring TEB bytes, destroys the
thread, checks both pages were decommitted, then reuses the slot and checks
the new second page is zero. It fails on the former x86 layout before the fix.
The companion regression exercises both admitted hardware and software WoW64
profiles, including native-companion isolation and reclamation of all four pages.
Existing guest-decommit and replacement-allocation ownership tests remain active.

The unchanged local hardware-fault fixture supplies a separate native startup
check; its source, binaries, assertions and instruction/time limits are preserved.
That combined local tree includes an existing exception-entry draft. Its results
must not be attributed solely to this published layout change.

The final selected suites have no failures or ignored tests:

| Host | Thread / rollback | WoW64 | Native-start | Scheduler-slot | C API |
|---|---:|---:|---:|---:|---:|
| macOS | 4 | 8 | 8 | 4 | 191 |
| Linux | 4 | 8 | 8 | 4 | 191 |
| Windows ARM64 | 4 | 8 | 9 | 5 | 191 |

Windows includes actual installed native-start and scheduler-slot leaves.
The full Windows-personality filter also passes 1457 tests on macOS and 1451
on Linux, without failures or ignored tests. macOS and Windows retain the separate exception-entry draft;
Linux uses the shared-runtime overlay and excludes that draft and unrelated
Windows-only leaf refinements. These source frames are distinct.

The original hardware-fault fixture still fails overall. ARM64 completes;
x86 passes the previous heap fault and stops at unsupported `NtRaiseHardError`
service `0x175` during startup. The reported hard-error status and its cause
are unknown here and require a separate trace. Neither that service nor
class-63 fault reporting is changed to return success by this correction.

## Assumptions and remaining scope

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| TEB1 | Two pages cover the observed installed x86 TEB accesses. | The recorded store ends at byte offset 0x101b. | Allocation extent for the selected startup. | An installed access at or beyond 0x2000 disproves coverage. | Confirmed for the recorded access; no universal private-layout claim |
| TEB2 | The ownership ledger must retain the complete pair even when guest fields or mappings change. | Existing host-owned claim and parent-allocation identities. | Isolation, teardown and slot reuse. | Decommit an extracted thread's full extent, create another thread, or replace the parent reservation before teardown. | Covered by the shared lifecycle regressions |

High, blocking full process support: broader installed Win32/CRT startup and
exception continuation still require their own complete validation. Medium,
non-blocking for this correction: future TEB tails beyond 8192 bytes need a
new extent; this observation does not qualify such layouts or other Windows
kernel identities. Linux/macOS host process personalities, public C ABI,
installed DLL selection, NT service semantics and package membership are unchanged.
