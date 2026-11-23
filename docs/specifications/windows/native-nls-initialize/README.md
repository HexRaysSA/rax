# Native NLS initialization

This group implements the measured `NtInitializeNlsFiles` initialization profile
for Windows 10.0.29683.1000, using an immutable snapshot of the installed
`locale.nls` mapping and its native locale ID. Guest outputs, handles and paths
never enter host acquisition. The independently qualified 29695 profile is
recorded in [the later kernel qualification](../native-nls-build-29695/README.md).
Builds outside the measured initialization profiles return an explicit
unsupported result for this service.

Four independently inspected ARM64/x64/x86/x86-LAA producers supply 316 calls:
140 succeed and 176 fail without caller SEH. The third and fourth declared
outputs remain untouched, even when their addresses are invalid or guarded.
Native64 probes destinations and stores base before locale ID; WoW64 captures
its base destination for reading, then copies locale ID before the base. The
mapped-view enumeration establishes eight retained mappings after late WoW64
output faults. Those mappings remain owned and charged by the guest VM until
explicit unmap or process teardown. Aliased outputs preserve the measured copy
order; no generic address-looking-word substitution is used.

An independent original ARM64 startup observer sees one successful four-argument
call, a 864256-byte readonly mapped locale view, locale ID 0x409 and natural
native child exit 41. This is native control evidence, separate from ordinary
emulated completion. Forty-eight further native protection/free controls show
that only READONLY protection succeeds; other measured protection changes
return 0xC0000045 and private RELEASE/DECOMMIT return 0xC000001B. All 48 views are
explicitly unmapped. These observations support reuse of the existing fixed NLS
view contract, including interior-address unmap.

The selected initialization payload is bounded to 8 MiB, and retained NLS payloads
combined remain at most 64 MiB. Snapshot construction accounts O(S) numbered
sections and retains immutable Arc bytes. Each initialization maps/copies N
payload bytes in O(N) time and uses the existing bounded guest VM budget.
The native reader validates the real 48/28-byte host memory-query layout,
readonly mapped extent and unchanged unused outputs; bounded RPM copies bytes
before RAII closes the uniquely owned host view. Live host locale changes do
not update an already selected guest snapshot.

The primary PHNT declaration and license are pinned by exact SHA-256 under
`references/`; observed runtime behavior owns the private output/copy rules.
Raw CRLF/source bytes are preserved. Run `python3
 docs/specifications/windows/native-nls-initialize/check.py` for native identities
and counts. Compiler, core, installed-leaf, owning and ordinary-startup validation
are separate evidence; the completed results are recorded below.


The installed x86 export has an actual `C2 0C 00` (RET12) instruction. Its
callee ABI consumes three argument slots, despite the four-output PHNT
prototype. The initial native-leaf test retained a strict expected-SP failure
when it passed four slots. The implementation now separates x86 three-slot
exports from native64 four-slot exports; the same strict stack check uses the
actual argument vector and remains enabled. The 32-bit host FFI declaration
also uses three stdcall arguments. Legacy direct-control producers used the
four-slot PHNT caller declaration; their fourth x86 slot was extra caller
stack data, not a parameter consumed by the leaf. Their original observations
remain retained and are not presented as proof of four-slot x86 cleanup.


## Completed validation

Canonical compiler: Rust 1.95.0; core default features remain disabled.

| Host | Full library passed/failed/ignored | Final NLS focus | C API | Scoped embedding |
|---|---|---|---|---|
| macOS ARM64 | 7830/0/2 | 13 | 168 | CLI/MCP;7 CTests;2 protected scans |
| Linux x86-64 container | 7824/0/2 | 13 | 168 | shipping archive;5 C++ consumers |
| Windows ARM64 native | 7253/5/2 | 14 | 168 | shipping archive;5 C++ consumers |

All-target checks pass on all three hosts. Unix runs 544 Windows integration
cases; native Windows runs 4 external-memory tests, while `user_windows` is
cfg-empty there and establishes compilation only. The five Windows failures
are the unchanged four BZHI and one FP16 native-lowerer failures. The two ignored
microkernel tests remain explicit. Current scoped archives bind 299 selected
code/fixture identities per host to an empty-feature RAX core, with full hashes
and structural member walks. Nine current-root C++ identities match the frozen
Assist exports. Whole-current-root, plugin, interactive GUI and package gates
are unrun; these scoped embeddings do not imply those proofs.

The complete Unix libraries use epoch 3. Final epoch 4 differs only in the
Windows-specific host adapter's 32-bit stdcall declaration; shared Unix runtime
and tests are unchanged. Epoch4 focused/all-target checks and all three owning
builds verify the final inputs. Windows executes the complete epoch 4 library
and actual installed ARM64/x86 leaves. Initial native-producer include errors,
eight Windows module-path diagnostics, the original strict x86 SP failure and
all source epochs are retained. No assertion or timeout was relaxed.

The unmodified ordinary ARM64 smoke observer passes NtInitializeNlsFiles and
reaches NtCreateFile 0x55, PC 0x180001590, turn 2132074. This advances 9910 observer
turns from the prior NLS boundary. The request names `\Device\ConDrv\Server`.
Whoami remains at NtTraceEvent 0x5e. The separate absent probe is not counted as
executed. Ordinary Windows guest completion count remains zero, and the full
process-userland objective remains active. Separate controlled process-persona
experiments are not shipping configuration or ordinary-completion evidence.

Run `python3 docs/specifications/windows/native-nls-initialize/validation/check.py`
for raw hashes, fourteen final code inputs, all source epochs, actual test
counts, exact known failures, native installed-leaf positives and scoped archive
proof. Runtime errors, source/native/package limits and retained failures are
not converted into an all-tests-pass claim.

## Hosted ARM64 observation

The installed-process workflow accepts `measure_arm64_nls_initialize`.
It builds the four existing producers as native ARM64 and runs their original
initialization, mapping protection/free, installed export and first-call
controls. The artifacts record source, PE, output, installed NTDLL and
`locale.nls` identities. The same runner separately exercises the installed
command through RAX's C ABI.

[Run 44722025758](https://github.com/HexRaysSA/rax/actions/runs/44722025758)
qualified Windows 10.0.26200 for native ARM64 guest initialization on a
physical ARM64 host. The [observation record](profile-arm64-26200-v1.json)
binds the 79 initialization cases, 12 mapping protection and free cases,
three export leaves, and successful first-call control to the installed
images. The initialization and protection projections match the existing
ARM64 controls. The measured 862808-byte file occupied 211 pages of 4096
bytes, for a readonly 864256-byte mapping. The runtime acquires the installed
mapping at selection time. This profile is specific to initialization.

## Hosted WoW64 observation on Windows ARM64 26200

The [native run](https://github.com/HexRaysSA/rax/actions/runs/45156726419)
observed the installed pure x86 `SysWOW64/ntdll.dll` and translated x86
`SyChpe32/ntdll.dll` on an ARM64 host. All 79 initialization rows matched
the original x86 corpus in three launch modes with and without large-address
awareness. Each profile acquired 35 call-published views and retained four
additional views on late pointer-copy faults. The 12 protection and free
cases matched the earlier x86 controls, and installed `NtInitializeNlsFiles`
uses service `0x108` and `RET 12` in each mode.

The installed 862808-byte `locale.nls` and the native ARM64 `ntdll.dll`
match the separately captured native ARM64 installation. RAX acquires the
page-rounded 864256-byte read-only host snapshot and maps its bytes in the
guest. The existing x86 copy order and guest view lifetime apply to this
profile. The [projection](profile-wow64-arm64-26200-v1.json) records the
installed providers, producer identities and canonical replay results.
Regenerate it by passing the extracted native artifact directory to
`python3 -B docs/specifications/windows/native-nls-initialize/project-wow64-26200.py`.

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- | --- |
| NLS-WOW64-26200-1 | The x86 output and mapping behavior matches the retained corpus on the measured ARM64 installation. | Admit x86 initialization on ARM64 build 26200. | Compare pure and translated x86, large-address awareness, aliased pointers, late mapping ownership and installed leaf cleanup. Any changed status, copyback or mapping lifetime would invalidate the shared replay. | Confirmed for the captured installation. |
| NLS-WOW64-26200-2 | Both caller ABIs select the same installed locale file. | Acquire the immutable locale bytes through the existing host snapshot. | Compare the mapped file name and extent against the independently identified native ARM64 file and validate guest bytes through the installed x86 leaf. | Native observations confirmed. |

Initialization takes O(N) time and O(N) guest storage for an N-byte mapping.
High-impact remaining scope includes the x64 compatibility initialization
profile on this kernel and the remaining stock x86 application startup
services.
