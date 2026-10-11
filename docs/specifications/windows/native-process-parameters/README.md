# Modern Windows process-parameter extent

This change reserves and zeroes the complete `RTL_USER_PROCESS_PARAMETERS`
layout through Windows 11 22H2 `HeapMemoryTypeMask`. The previous reservation
ended before `RedirectionDllName`; subsequent heap strings occupied fields read
by the installed Windows 10.0.29683.1000 NTDLL.

The default empty `HeapPartitionName` must remain a zero `UNICODE_STRING`.
The loader therefore does not interpret the following image-path string as a
partition descriptor. No host partition service, new access grant, kernel-object
model, C ABI, dependency, permission, persisted schema or native-library selection
policy changes.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The captured installed runtime consumes the modern parameter tail | Native instruction trace loads 16 B at parameters + 0x420 and publishes them as the partition name | Extent correction and diagnosis | Distinct image names, x86/x64/ARM64 guest layouts | Check the retained write trace and independent structure offsets | confirmed for build29683 |
| A2 | Default optional modern parameters are zero | Four suspended-child snapshots and pinned PHNT declarations | Zero initialization without selecting optional features | Native ARM64, x86, x86 LAA and x64 compatibility | Replay every original hash and tail byte | confirmed for these profiles; other releases unknown |
| A3 | Existing allocation initializes the entire requested parameter block | Process construction uses checked zeroed heap allocation | Enlarging `pp_size` initializes the tail | Six portable guest cases with string overlap checks | Run the regression on each host and inspect the whole modern tail | confirmed by focused macOS, Linux and native Windows regressions; broader host gates recorded below |
| A4 | The saved-context/cleared-PEB-heap trace is an isolated diagnostic | Retained source explicitly changes the context and clears ProcessHeap | Loader continuation evidence | Ordinary production process probes | Compare diagnostic source with the production path and run ordinary probes | confirmed as a diagnostic; does not prove production startup |
| A5 | A successful Cargo build log proves the stored native archive remains readable after storage exhaustion | The first Windows shipping build returned success before VM interruption | Reliance on the first owning archive | Interrupted host writes and cached dependency profiles | Inspect archive member headers and link the owning consumers | falsified; recovered archives and all owning consumers pass, replacing reliance on the interrupted artifact |

## Independent layout and arithmetic

Pinned reference: [PHNT ntrtl.h](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntrtl.h),
`RTL_USER_PROCESS_PARAMETERS`. The entire reference and its MIT license are
retained with byte hashes. The probe compiles the exact declarations under
renamed identifiers. Its `STRING` member is replaced by the equivalent SDK
`ANSI_STRING`; the checker verifies that transformation exactly.

| Field/extent (bytes) | x86 | x64 / ARM64 |
|---|---|---|
| Previous structure extent | 0x2A4 = 676 | 0x410 = 1040 |
| RedirectionDllName | 0x2A4 | 0x410 |
| HeapPartitionName | 0x2AC | 0x420 |
| DefaultThreadpoolCpuSetMasks | 0x2B4 | 0x430 |
| DefaultThreadpoolCpuSetMaskCount | 0x2B8 | 0x438 |
| DefaultThreadpoolThreadMaximum | 0x2BC | 0x43C |
| HeapMemoryTypeMask | 0x2C0 | 0x440 |
| Complete aligned structure extent | 0x2C4 = 708 | 0x448 = 1096 |
| Added structure bytes | 708 - 676 = 32 | 1096 - 1040 = 56 |
| Heap block alignment | 8 | 16 |
| Added rounded heap backing | 712 - 680 = 32 | 1104 - 1040 = 64 |

All calculations are exact integer byte counts. RAX allocates the header and
its pointed-to strings separately. Its `Length` and `MaximumLength` identify
the header extent. The native suspended-child values include additional storage
and are larger; this change does not claim to reproduce their aggregate byte
counts or allocation addresses.

Construction continues to use O(S) zero/copy work for S parameter/string bytes
and the existing heap bookkeeping. This change adds a constant 32/56 header
bytes; no new search, process, filesystem or host-kernel operation is introduced.

## Reproduction and native originals

Run `python3 check_native_process_parameters.py` from this directory. Every
manifest input is required; absent or altered files fail replay.

The C++ oracle creates only its own suspended child, captures its original
context/PEB/parameters with read-only queries, never resumes it, and checks
termination plus handle cleanup. All four default tails are zero. Native x64
execution here is Windows ARM64 compatibility, not a physical x86-64 kernel
initial-context oracle. No Microsoft DLL or executable is redistributed.

The old private trace used the owning RAX archive at parent
`420b52da531d7e00ea592bbfd445b7cbcc872705`. Its descriptor watch establishes:

```text
params = 0x10100, previous extent = 0x410
  params + 0x420 = 0x10520: UTF-16 image-path bytes
      |
turn 12647: LDR Q7, [X21, #0x420]
turn 12648: STR Q7, [X9] (X9 = 0x1803c93c0)
      |
turn 12660: NtOpenPartition receives Length=67 and invalid
            Buffer=0x70005c00700070; service remains unsupported
```

The service was genuinely unimplemented, but that invocation was caused by an
out-of-extent read. The observed request does not establish a valid default
partition dependency. The independent `NtOpenPartition` probes remain separate
research and are not presented as an implemented feature.

The regression fails under the old extent (observed x86 Length676 versus708),
then checks all three guest architectures with two image paths, explicit
arguments/environment/current directory, modern zero fields, string disjointness
and preserved image text. Initial test-authoring compiler errors are not
behavioral baseline evidence; only `macos-parameters-baseline-v2.log` is used.

## Owning-archive continuation

The diagnostic source is byte-identical to the prior saved-context/cleared-heap
trace. Fresh Cargo compiler-artifact JSON selects the owning core rlib; its
SHA256 and current Windows source hashes are retained. The installed NTDLL
remains10.0.29683.1000; its native ARM64 file SHA256 is retained without copying
the DLL.

The corrected block produces no service0x131/NtOpenPartition request. The same
three allocation calls return success at turns11315,11397 and11542. Execution
continues to turn13286, where NtQuerySystemInformationEx service0x16E stops
explicitly at PC0x180002720. Its class is0x6B, input length4 bytes, output
capacity0xC50 =3152 bytes, ReturnLength pointer0. The next input's semantic
contents are unknown; a separate native oracle and guest memory capture are
required before implementing that operation.

```text
old extent -> aliased image-path descriptor -> NtOpenPartition stop12660
new extent -> zero optional partition field -> NtQuerySystemInformationEx stop13286
                                                   delta =626 scheduler calls
```

626 =13286 -12660 is an exact scheduler-call delta, not an instruction count.
Four ordinary native process probes still return0xC0000005
(STATUS_ACCESS_VIOLATION). The continuation does not prove production bootstrap.

## Change-surface map

| Plane | Effect/evidence |
|---|---|
| Process/kernel boundary | Process parameter allocation extent and default optional field values change |
| Guest memory/loader | Header/string disjointness changes; installed NTDLL consumes the corrected tail |
| Direct decode/execute and CPU state | Unaffected: no ISA or register/context implementation changes; retained trace identifies an existing load/store |
| SMIR/lift/IR/interpreter/optimizer/lowering/JIT/backend/device/oracle | Unaffected: the change only supplies Windows process data before existing execution |
| C API/SDK/ABI | Public layouts/version unchanged; process construction consumed through the existing engine and archive |
| Assist tool/schema/permissions/mutation/IDA thread/UI/MCP/transport/persistence/update | Unaffected contract: shared Rust process construction is embedded through existing call paths; no corresponding policy or source changes |
| Windows/macOS/Linux | Common Rust data construction implements identical x86/x64/ARM64 guest layouts; host gates and owning archive consumers are recorded below |
| Native platform mechanics | Windows-only runtime observation; selectors unchanged. Linux/macOS do not acquire Windows host runtime capability |
| Tests/docs/packages | One registered library regression; references, originals, replay checker and pin documentation. No package layout/default/dependency changes |

## Validation

The original profile and final source hashes are retained separately. The
focused regression passed on macOS, Linux and native Windows ARM64, executing
six x86/x64/ARM64 guest construction cases on each host.

| Host | Full library pass/fail/ignored/filtered | C API | All-target build | Registered affected integration |
|---|---|---|---|---|
| macOS ARM64 | 7558 / 0 / 2 / 0 | 168 passed | passed | Unix Windows-fixture suite544 passed; Windows-memory target0 tests |
| Linux amd64 container | 7551 / 1 / 2 / 0 | 168 passed | passed after storage recovery | Unix Windows-fixture suite544 passed; Windows-memory target0 tests |
| Windows ARM64 | 6947 / 5 / 2 / 0 | 168 passed | passed after storage recovery | Windows-memory4 passed; Unix fixture suite cfg-excluded |

Linux's unchanged-source io_uring failure is
`a_multishot_timeout_reports_each_expiry`: two MORE timeout completions were
observed where the assertion expected one. Its cause and native-kernel agreement
are unknown. Windows retains the same four BZHI and one FP16 lowerer failures
recorded at the parent pin. This is not an all-suite-green result.

The owning macOS archive, idalib CLI and seven selected CTest entries passed,
including five C++ consumers, with protected plaintext scan0 failures. All five
owning Linux C++ consumers passed:184 process-tool checks,162 process checks,
archive linking, disabled-RAX behavior and ABI version1.11.0/header1.11.
All five native Windows consumers pass after recovery:182 process-tool checks,
162 process checks, disabled-RAX behavior, ABI1.11.0/header1.11 and archive linking.
The same verified owning core artifact supplies the continuation below.

The first owning macOS build failed with `No space left on device`, Docker
clients returned `unexpected EOF`, and Parallels reported the VM stopped.
Those failures are retained as storage interruptions. The user restored host
space; further task-owned generated compile caches were removed, with exact
removed-file hashes. Source, dependency sources, worktrees, current shipping
archives/binaries and raw logs were preserved. The VM restarted at
2026-10-11T00:30:26Z without changing its existing81920 MB memory configuration.
No task processes survived the shutdown. Interrupted original logs were copied
and hashed before resumed logs used separate names.

The first Windows owning archive is structurally corrupt: its1101162336-byte
file contains a zero member header at offset1005889936, and the native linker
returns LNK1127. The selected RAX rlib passes the structural member walk. Cleaning
only assist-rs removes that archive, but the rebuild fails E0463 when resolving
the cached RAX C API dependency. This attempt is retained as failure101. The
successful recovery rebuilds both rax-capi and assist-rs after the RAX test jobs
finish; the fresh archive and selected core rlib pass4673/260 structural member
walks, then all five native consumers pass.
No semantic source, ABI, dependency pin or compile default changes during
recovery. Structural archive checks alone do not validate the embedded objects;
the owning consumers and selected-artifact continuation supply that evidence.

## Bounded findings

| Impact | Finding | Evidence | Blocks this correction? |
|---|---|---|---|
| High | Production native startup still has separate initial-context, PEB loader/heap and real heap ownership gaps | Diagnostic explicitly clears ProcessHeap and replaces the entry context; native initial-child capture | No; blocks the full process goal |
| Medium | Future or different Windows runtime revisions can require a larger process-parameter tail | PHNT version annotations and the fixed current extent | No; current independent profile is explicit, other revisions unknown |
| Medium | Historical unrelated library failures and integration liveness failures require separate classification | Previous native-allocate-ex record and final jobs below | No if the affected parameter checks pass; no all-suite-green claim |
| Low | Valid partition service implementation may be needed by applications explicitly selecting HeapPartitionName | Separate native partition oracle | No; no such configuration is added here |

## Quality gates

| Gate | Evidence / result |
|---|---|
| QG1 | No normative or ethical judgment is required |
| QG2 | A1-A5 include dependent results, boundary probes and confirmed/falsified status |
| QG3 | Complete modern ABI extent, zero default tail, disjoint pointed strings and all affected owning consumers verified |
| QG4 | Exact byte offsets, alignment rounding, header/native aggregate distinction and626-call delta reproduced |
| QG5 | Current correction has no unresolved contradictory observation; unrelated full-suite/startup limits are explicit |
| QG6 | Pinned primary declarations/license, native original hashes, exact source hashes and owning artifact identity replay |
| QG7 | High/medium/low bounded findings identify full-goal limits without implementing adjacent services |
