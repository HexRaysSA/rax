# Native NLS initialization

This group implements the measured `NtInitializeNlsFiles` initialization profile
for Windows 10.0.29683.1000, using an immutable snapshot of the installed
`locale.nls` mapping and its native locale ID. Guest outputs, handles and paths
never enter host acquisition. The independently qualified 29695 profile is
recorded in [the later kernel qualification](../native-nls-build-29695/README.md).
Other Windows builds remain explicitly unsupported for this service while
existing NLS services retain their behavior.

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
