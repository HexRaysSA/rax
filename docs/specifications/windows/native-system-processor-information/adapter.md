# Virtual processor-information adapter

`NtWow64GetNativeSystemInformation` is an x86-only four-argument service. Its
new export family follows every prior NTDLL export table, retaining previous
synthetic ordinals and trap RVAs. The existing three-platform clock/CPU runner
executes the query regressions inside the existing CI jobs.

| Query view | Class1 | Class63 |
|---|---|---|
| Ordinary x86 | Intel, guest CPUID signature | Same x86 view |
| Ordinary x64 on ARM64 kernel | AMD64, guest CPUID signature | Legacy ARM descriptor |
| Ordinary ARM64 | ARM64 | Legacy ARM descriptor |
| Native WoW64 on ARM64 kernel | ARM64 | Legacy ARM descriptor |
| Native WoW64 on AMD64 kernel | AMD64, guest CPUID signature | Intel, same guest CPUID signature |

Legacy ARM describes a query record and does not advertise ARM32 execution.
Kernel selection uses the admitted native-machine metadata. A spoofed guest
version cannot choose another kernel view. Synthetic x86 uses a virtual AMD64
kernel with the existing IA-32e compatibility CPU. KUSER_SHARED_DATA's native
architecture describes that kernel rather than the process ISA.

The record size is 4 * 2 bytes + 4 bytes = 12 bytes: four little-endian u16
values and a u32 feature mask. Its maximum processor count is one, matching the existing virtual
topology. Family, extended family, model, extended model and stepping come from
the guest CPUID signature; captured physical CPU identities are never copied.
On the measured ARM64 kernel the native mask is 0xA0000000 and the ordinary
x86 translator clears it. AMD64's mask advertises the mapped capabilities of
the virtual CPU and its execute-protection policy. Unmodelled private kernel
bits remain absent; the field is not a copy of host KeFeatureBits. It is also
distinct from the PF-indexed shared/API bitmap, whose broader compatibility
view corrections remain separate work.

Native CPU entries, including ordinary x86, probe the entire nonempty output
span with four-byte alignment, then optional four-byte ReturnLength, before
length dispatch or copying. Length0 ignores output but still probes
ReturnLength. Lengths below12 publish required size12 after successful probes.
Lengths at least12 copy only12 bytes and preserve the suffix. ReturnLength is
written after the native record. ARM64-kernel compatibility translators then
rewrite selected identity/feature fields for ordinary x86, and identity fields
for ordinary x64 class1. Aliases therefore retain view-specific partial writes.
Read-only guarded output consumes the reached
guard during probing. Both destination guards and their visitation order are
checked against the original native control.

Record selection/encoding takes constant time and space. The memory probe
walks pages until the requested span ends or its first fault: O(P) time for P
visited pages, O(1) auxiliary space. Even ULONG_MAX describes a checked span,
not an allocation of that size.

The native WoW64 helper accepts classes0/1/62/63/114 and rejects other classes
before visiting either destination. Basic classes0/62 retain the 44-byte
conversion, untouched three-byte tail and late ReturnLength store. Class0's
native address ceiling is truncated to the caller width; class62 reports the
process's own ceiling. Class114 forwards a 64-byte native record. Ordinary
x86 rejects114 without probing. Native AMD64 basic records preserve padding;
the captured ARM64 kernel zeros it. The address ceiling is metadata about the
virtual native kernel and does not map additional guest memory.

The independent producer, frozen capture and references are in this directory.
The runtime replay retains all 768 CPU query rows: statuses, bytes copied,
aliases, output/return probe order and guard transitions. Only processor
identity and the virtual one-processor count are projected. Further tests
exercise native helper widths, whitelist rejection, extended CPUID signatures,
capability masks, previous export slots and the installed WoW64 leaf.

`processor-alias-v2.cpp` isolates each alias offset0..16 in its own process.
Its frozen `processor-alias-29683-v2.json` retains all136 attempts, compiler/
executable hashes and unchanged-input checks. Of these,135 returned successful
records. Ordinary x64 class1 with ReturnLength at output+1 exited255 without a
result, including under SEH; its cause and guest equivalent remain unknown.
The runtime replay qualifies the135 successful rows and explicitly preserves
that one excluded native outcome. It does not infer a successful guest result
from the exit. The earlier v1 bulk observer stopped at the same x64 boundary;
its source remains immutable alongside v2.

The successful offset controls establish that the ARM64-kernel x86 translator
rewrites bytes0..6 and8..12, while x64 class1 rewrites only bytes0..6 after the
native ReturnLength write. MaximumProcessors and suffix bytes retain aliases.
The startup request has ReturnLength NULL and does not encounter the excluded
case. This unresolved native x64 corner limits broader alias-fidelity claims.

To reproduce from a matching MSVC architecture environment:

```text
cl /nologo /std:c++20 /MT /EHsc /utf-8 /W4 /WX processor-alias-v2.cpp /Fe:processor-alias-v2.exe
processor-alias-v2.exe NtQuerySystemInformation 1 0
processor-alias-v2.exe NtWow64GetNativeSystemInformation 63 16
```

Use x86 for the second command's native-WoW64 API. Run each class1/63 and offset
0..16 as a separate child, preserving its raw stdout and process exit code.
The producer uses only an owned80-byte buffer and metadata queries. A missing
result is retained rather than converted to an NTSTATUS or retried silently.

Feature-bit positions are corroborated by the primary ReactOS NDK header at
commit e46f4bb1a1ea7c722f941231565144fe0c286d3e,
[amd64/ketypes.h](https://github.com/reactos/reactos/blob/e46f4bb1a1ea7c722f941231565144fe0c286d3e/sdk/include/ndk/amd64/ketypes.h).
SDK10.0.26100.0 shared/ksamd64.inc independently binds the TSC, CR4, global/
large-page, CX8, syscall, XSTATE, XSAVEOPT and FSGSBASE positions; captured file
SHA-256 is e22aa90e0848d12f544bcd2056605915d21ab2bc4af673bc9455938eb51474aa.
The native controls remain the authority for observed Windows behavior.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| CA1 | Caller and native-kernel identity must be selected separately. | ARM64 kernel29683 and AMD64 kernels20348/26100 controls. | Query views and shared native architecture. | x86 and x64 compatibility callers. | Independent matching-profile control disagrees with the selected view. | Confirmed by controls; adapter validation recorded separately. |
| CA2 | The guest CPU/topology owns advertised virtual capabilities. | Deterministic guest CPUID, one virtual processor, executable-page enforcement. | Signature, count and mapped private feature mask. | Extended signatures, missing OSXSAVE, NX, vendor differences. | A returned bit contradicts its owning CPU or kernel policy. | Required invariant; no physical identity imported. |
| CA3 | Native basic information can describe a wider address ceiling than the caller can map. | Native WoW64 classes0/62/114 observations. | Record width, truncation and ceiling metadata. | Narrow pointers and exact-size boundaries. | A query creates mappings or converts114 to44 bytes. | Confirmed observation; guest allocation bounds remain unchanged. |
| CA4 | One copy/ReturnLength order describes every processor view. | Initial adapter interpretation. | Initial alias implementation. | ReturnLength overlaps each record byte. | Frozen x86/x64 compatibility rows overwrite an earlier ReturnLength while native rows retain it. | Falsified; per-view identity/feature rewrites implement the successful controls. |

This adapter does not establish complete installed-library process startup,
native64 RTL/callback support, shared/PF API parity or a linked Assist artifact.

The unchanged Windows29683 hardware-fault fixture now passes the missing
NtWow64GetNativeSystemInformation request and reaches
`NtSetInformationProcess` class63, which remains unimplemented. Its original
input binaries, assertions and instruction/deadline budgets are unchanged.
The installed WoW64 CPU query leaf and all seven focused Windows tests pass;
both private CPU-model tests also pass. macOS's full combined-tree library
suite passes8429 tests with2 ignored; Linux's clean-parent Windows-personality
suite passes1442 tests. C API results and final ownership/build records remain
in the changeset's validation ledger. Windows test compilation initially found
a missing local helper; only an appended Windows-gated test helper differs
from the earlier macOS/Linux source frame. No shared runtime code changed
after those successful checks.
