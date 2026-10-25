# WoW64 processor-feature service

The installed x86 NTDLL on Windows 10.0.29683 calls
`NtWow64IsProcessorFeaturePresent` while initializing a process that imports
KERNEL32. The native exception fixture reached this unimplemented service
before its intended fault. The same fixture had completed through installed
ARM64 NTDLL; the WoW64 failure is retained separately from exception-frame
validation.

`native-wow64-processor-v1.cpp` measures the full 32-bit service return,
`RtlIsProcessorFeaturePresent`'s byte return and the Win32 Boolean for 259
indices: 0 through 255 inclusive, 65,536, 2,147,483,648 and 4,294,967,295.
The driver compiles an x86 child and records its actual native kernel machine,
build, source, compiler and executable hashes. Its outputs contain scalar
feature results only. Build and temporary directories remain in the owning
worktree and are removed after the child exits.

The local build-29683 ARM64-kernel observation has no disagreement between the
three APIs. Indices 2, 3, 6, 8, 10, 12, 13, 14, 17, 22, 28, 32, 36, 37, 38,
39 and 40 return one; every other tested index returns zero. These are the
native control's capabilities, not the emulated CPU's advertised capabilities.
Independent x64-kernel observations are pending.

The first hosted run passes on build 20348. Build 26100 fails the strict
zero-or-one projection before printing its rows, so the specific native value
is unknown. `run-v2.py` preserves bounded scalar rows and source/executable
identities on that failure, then retains the original failed verdict. Its
failure-receipt tests reject unknown fields and oversized values; the native
producer and the original validator remain unchanged. This pending receipt
can invalidate a cross-kernel claim about canonical Boolean returns.

The bounded build-26100 receipt resolves that projection failure: indices
64 through 191 have zero in AL and nonzero upper EAX bits, while RTL and Win32
return zero. A full-register zero-or-one assertion therefore fails. The exact
raw register value is retained in the diagnostic record, not copied into the
guest CPU policy. The interpretation of those upper bits as defined API data
is unknown; the service is undocumented in the Microsoft SDK.

`native-wow64-processor-v2.cpp` calls the same export through both full-register
and byte-return declarations. `run-v3.py` retains the raw register result,
checks its low byte against the independently typed byte call, and requires
agreement with RTL and Win32 for every index. All 259 local byte comparisons
pass. The hosted byte comparison remains pending; the earlier failed
full-register projection is preserved. Two new projection tests pass on all
three hosts. No runtime code changes for this observation correction.

The model registers the service only for x86 and shares the existing guest CPU
policy with the Win32 API and shared-data initialization. No host feature bit
is imported. A separate tail export table preserves preceding synthetic
ordinals and trap addresses. The service accepts one `ULONG`, returns zero or
one in the integer return register, changes no guest memory, and has constant
time and additional-space complexity. Common service tests exercise all 259
indices and preserve the transition's return address, argument and stack
position. The installed RTL regression also exercises the WoW64 path.

The processor-feature slice passes five tests on each of macOS and Linux and
six on native Windows, where the extra test executes the installed native and
WoW64 RTL leaves. Two projection tests pass on every host. The same hardware
fault fixture now advances beyond this service to an unimplemented
`NtQueryInformationProcess` class 34 request in WoW64 startup; its overall
exception-delivery result remains a failure. The runtime tests include the
separate, uncommitted native dispatcher draft and do not qualify that draft.

| ID | Assumption | Basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|---|
| WP1 | The service answers the selected x86 CPU's feature policy. | Local three-API comparison and Wine's independent native tests. | Shared guest implementation. | Repeat the exact control on x64 kernels and compare all 259 rows. | Confirmed locally; cross-kernel validation pending |
| WP2 | The existing guest CPU policy is stable during a service call. | Serialized guest execution and existing CPUID policy. | Consistency with Win32 and initialized shared data. | Change the guest CPU policy and compare API, service and shared bytes. | Retained existing contract |

High impact, blocking full process qualification: other installed-library
startup dependencies and complete exception delivery still require their own
validation. This service does not establish ordinary Windows program support.

Primary references: Microsoft's
[Win32 API contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
and Wine's [native WoW64 tests](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/tests/wow64.c).
The native observation is in `local-29683-v1.json`; no Microsoft DLL or private
instruction bytes are redistributed.
