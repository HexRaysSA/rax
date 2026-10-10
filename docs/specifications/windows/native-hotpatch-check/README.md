# Native hotpatch availability prerequisite, 2026-10-10

This record owns the disabled `NtManageHotPatch` class 9 profile required by
installed NTDLL initialization. RAX has no admitted patch loading, application,
unloading or section-creation implementation. Its availability query therefore
returns `STATUS_NOT_SUPPORTED` (`0xC00000BB`), with the measured kernel and
WoW64 buffer effects. Other operation classes remain explicit unsupported
results. No guest request invokes a host hotpatch operation.

## Provenance and experimental scope

The pinned [phnt declaration](../native-processor-features/phnt-ntexapi.h)
from commit `53fbbdc5b5d2b08761db1c7b26bfa8c820924356` declares
`ManageHotPatchCheckEnabled = 9`, an 8-byte `{ ULONG Version; ULONG Flags; }`
structure and four arguments. Its [license](../native-processor-features/phnt-LICENSE)
is retained alongside that existing header. The declaration is private ABI
evidence; it is not a Microsoft stable API guarantee.

The original query-only C++ probe and complete ARM64/x86/x64 outputs here were
captured on Windows ARM64 10.0.29683.1000 with VS2026 18.7.1. x86 and x64 run
through Windows compatibility execution on this ARM64 kernel. Each ABI tests
192 version/flag/length combinations, 16 pointer/protection cases and 15
additional alias/fault/span cases: 223 calls per ABI, 669 total. No patch
mutation class is issued. Other Windows builds and enabled profiles are unknown.
`sources.json` identifies exact original bytes, SHA-256 and notices; retained
logs preserve CRLF. Private system DLLs/PDBs are not distributed in this record.

## Recorded disabled semantics

| Partition | ARM64/x64 native entry | x86 WoW64 conversion |
|---|---|---|
| Information length | Ignored, including 0/1/4/7/8/9/12/16 | Must equal 8; otherwise `STATUS_INVALID_PARAMETER` before either pointer |
| Version / Flags | Neither read nor validated | Captured and copied without validation for length 8 |
| Information pointer | Unused; null, unaligned, readonly, guard and inaccessible storage do not affect the kernel query | Read 8 bytes before ReturnLength; unaligned input accepted |
| ReturnLength | Mandatory 4-byte write of 0; unaligned destinations accepted | Same kernel effect after capture |
| Null / inaccessible ReturnLength | Access violation; no information access | Kernel fault followed by information copy-back |
| Guarded ReturnLength | Guard consumed, `STATUS_GUARD_PAGE_VIOLATION`, value untouched | Guard consumed before copy-back; subsequent copy-back fault can replace status |
| Information copy-back | None | Captured 8 bytes written back even after the kernel returns an error |
| Readonly information, writable ReturnLength | `STATUS_NOT_SUPPORTED`, ReturnLength 0, input unchanged | Copy-back access violation after ReturnLength becomes 0 |
| Readonly information, guarded ReturnLength | Guard status, ReturnLength untouched | Guard consumed, then copy-back access violation; ReturnLength untouched |
| ReturnLength aliases information | Corresponding 4 bytes zeroed | Captured 8 bytes restore alias, overwriting the zero result |
| Input crosses inaccessible second page | Unused; ReturnLength still zeroed | Capture fails before ReturnLength is touched |

The header marks ReturnLength optional and defines structure Version 1. The
recorded disabled kernel requires ReturnLength and ignores the structure;
the selected ARM64 NTDLL loader supplies Version 1 and Flags 0. The earlier
working assumption of Version 0 was falsified by the explicit buffer trace.
The optional-output declaration and mandatory-output observation differ. RAX implements the explicitly
recorded disabled profile without imposing enabled-profile validation.

```text
WoW64: length == 8 -> capture 8 bytes -> kernel ReturnLength probe/write
                                             | consume kernel guard
                                             v
                                      copy captured 8 bytes back
                                             |
                              copy-back fault replaces kernel result
```

Input capture faults return before the kernel step and consume any input
guard once. Kernel return faults do not suppress copy-back. Guard consumption
must occur before that copy-back, so a later access violation does not leave a
kernel guard armed. The corrected fault-order regression failed before this
ordering was implemented and passes afterward. The initial class-9 regression
also failed while the service was unimplemented and passes with this change.
Synthetic NTDLL imports use the same NT status boundary: access violations
and guard faults return a status with ordinary callee cleanup and no guest
exception frame. A separate observed regression initially terminated the
synthetic caller on a null ReturnLength; it passes after explicit status
conversion. Native kernel dispatch already returns that status. Other native
query/event synthetic-entry wrappers were not changed in this group and need
a separate fault-boundary audit.
Query capture/probes/serialization are O(1) time and O(1) space: at most 8
information bytes captured and copied, with a 4-byte ReturnLength field.

## Assumption register

| ID | Assumption and basis | Dependent result | Stress / falsification | Status |
|---|---|---|---|---|
| P1 | No emulated hotpatch operations are admitted; registry and mutation-class tests | Explicit unavailable query and unsupported other classes | Any admitted load/apply/unload/section operation requires capability revision; class requests must not mutate guest or host state | Confirmed current source and tests |
| P2 | Recorded disabled native64 gate ignores information and requires ReturnLength | Native fault ordering and 0 publication | Null/unaligned/readonly/guard/span/alias and all version/flag/length combinations; differing native output falsifies | Confirmed all three native oracle ABIs; other builds unknown |
| P3 | WoW64 captures input then copies back after kernel errors | Aliases, partial output and fault precedence | Readonly input plus guarded ReturnLength; differing status/guard/output falsifies | Revised after counterexample, then confirmed native probes and corrected regression |
| P4 | phnt Version 1 declaration does not define disabled-kernel validation | Opaque input; Version 0/1 queries accepted | Version 0/1/2/all-ones and opaque flags; enabled-kernel results require a distinct capability profile | Revised loader-version assumption to 1 from explicit trace; disabled acceptance confirmed; enabled profile unknown |
| P5 | Synthetic and admitted native NTDLL entries share NT fault-status semantics | Explicit status conversion and callee cleanup | Null/inaccessible/guarded return pointer, readonly input, all guest ABIs; a guest SEH frame or termination falsifies | Confirmed observed red-green synthetic-entry regression |

## Change surfaces and bounded findings

| Plane | Change / evidence |
|---|---|
| Windows native service / WoW64 dispatcher | Appended `NtManageHotPatch` export metadata, shared class-9 implementation; existing export indices preserved |
| Windows loader / heap lifecycle | No production initialization or native heap integration change; isolated diagnostic kept separate |
| Public C ABI / Assist consumers | API 1.11.0, structs, selectors, adapters and permissions unchanged; current owning archives checked separately |
| ISA / IR / JIT / Linux and Darwin guest policy | No implementation changes; shared Windows code compiled and tested on all three host OS configurations |
| Dependencies / defaults / locks / package wiring | Unchanged; archive linkage does not establish native IDA, harness or package execution |
| Tests / documents | Five shared behavior tests; Windows installed selected NTDLL query leaf test; full library and C API packages, current Assist C++ surfaces |

| Impact | Finding | Blocks full process goal? |
|---|---|---|
| High | Ordinary Windows CRT startup and native NTDLL/RTL heap bootstrap remain incomplete | Yes |
| High | Wider NT services, namespaces/security and full POSIX process behavior remain incomplete | Yes for dependent programs |
| Medium | Other kernel builds/enabled hotpatch profiles and physical x86/x64 kernels are unknown | Limits this profile's coverage |
| Medium | Existing synthetic query/event fault wrappers require an independent NT status-boundary audit | Outside this service group; relevant to complete synthetic fallback behavior |
| Medium | Existing Linux timing/signal interference and Windows BZHI/FP16 failures remain separately recorded | Full test matrix may remain failing |

## Validation and isolated frontier

The first Windows library attempt stopped at compilation: the new installed
leaf test used a moved `CpuStop` in its assertion message. That original error
is retained in `windows-test-compile-before.log`; no tests or leaf pass are
attributed to that attempt. The owned test now formats its diagnostic before
passing ownership to `handle_stop`.

| Surface | Final result | Evidence |
|---|---|---|
| Initial service regression | Fails before admission, passes after | `regression-before.log`, `regressions-after.log` |
| WoW64 fault-order regression | Fails with guard status before unconditional copy-back, passes after | `fault-order-before.log`, `regressions-after.log` |
| Synthetic-entry regression | Caller terminates before NT fault-status conversion, returns normally after | `builtin-entry-before.log`, `regressions-after.log` |
| Shared query tests | Five pass on each host OS configuration | Complete library logs below |
| macOS full library | 7,483 passed, 0 failed, 2 ignored, 0 filtered | `/tmp/assist-native-hotpatch-full-macos.log` |
| Linux full library | Final 7,477 passed, 0 failed, 2 ignored, 0 filtered; earlier 7,475 passed and 1 known timeout failure | `/tmp/assist-native-root-cpp-linux/native-hotpatch-full.log`, `first-native-hotpatch-full.log` |
| Windows full library | 6,858 passed, same 5 BZHI/FP16 failures, 2 ignored, 0 filtered | `/tmp/assist-native-windows-29683/native-hotpatch-complete-full.log` |
| Installed NTDLL query leaf | Selected ARM64/x86 query SVC/transition and real RET cleanup pass | Same Windows full log |
| Complete C API package | 168 passed, 0 failed, 0 ignored, 0 filtered on each OS | `/tmp/assist-native-hotpatch-capi-macos.log`; `/tmp/assist-native-root-cpp-linux/native-hotpatch-capi.log`; `/tmp/assist-native-windows-29683/native-hotpatch-complete-capi.log` |
| macOS current Assist archive | Five CTests pass | `/tmp/assist-native-hotpatch-root-macos-{build,ctest}.log` |
| Linux current Assist archive | Tool 184 / adapter 162 / disabled factory / ABI 2/2 / archive link pass | `/tmp/assist-native-root-cpp-linux/native-hotpatch-{shipping,cpp}.log` |
| Windows current Assist static-CRT archive | Tool 182 / adapter 162 / disabled factory / ABI 2/2 / archive link pass | `/tmp/assist-native-windows-29683/assist-native-hotpatch-complete-{shipping,cpp}.log` |
| Four ordinary Windows installed-DLL startups | All still exit guest `STATUS_ACCESS_VIOLATION`; complete CRT startup not established | `/tmp/assist-native-windows-29683/native-hotpatch-complete-archive-output.log` |
| Formatting / owned source whitespace | Complete workspace formatting and source checks pass | `/tmp/assist-native-hotpatch-format-final.log` |

The earlier Linux multishot timeout failure is retained; the final pass is not
remediation evidence. The Windows failures are the existing four AArch64 BZHI
lowerer byte assertions and host FP16 execution failure. No implementation in
those planes changed. Zero-test C API doctest output is separate from its 168
package tests and contributes no behavioral evidence.

The unchanged original loader diagnostic reaches `NtOpenKey` service `0x12`
at PC `0x180001130`, zero-based turn 709. The additional kernel/buffer trace
explicitly records hotpatch turn 160: class 9, info `0xABFAF8`, length 8,
ReturnLength `0xABFAF0`; the result is `0xC00000BB`, ReturnLength 0, and the
information is Version 1 / Flags 0 without modification. Execution proceeds
through subsequent event creation, basic-system and process-cookie queries
before the new registry stop. The next requested absolute key is
`\Registry\Machine\System\CurrentControlSet\Control\Nls\CodePage`,
with `GENERIC_READ` and null security/QoS inputs. It is not implemented by this
group. The delta 709 - 160 = 549 is the number of diagnostic slice calls,
not a CPU retired-instruction measure. The original before/after driver and
additional trace driver/output are retained with checksums. Diagnostic `turn` values are zero-based
run-slice indices with a one-instruction budget, not retired-instruction counts.
The retained driver clears guest `PEB.ProcessHeap` and supplies RAX's existing
initial context/continuation. It is a prerequisite probe, not native kernel
initial-thread-entry or complete production bootstrap evidence.
