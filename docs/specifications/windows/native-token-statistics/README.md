# Native token statistics

`NtQueryInformationToken` class 10 publishes the fixed, pointer-free
`TOKEN_STATISTICS` of the selected token. Its 56-byte layout is checked by
independent MSVC builds for ARM64, x64 and x86. The ten member offsets are
0, 8, 16, 24, 28, 32, 36, 40, 44 and 48 bytes. Microsoft documentation,
enumeration and their licenses are retained at the immutable source revision
recorded in `sources.json`.

The record belongs to its immutable captured subject. TokenId,
AuthenticationId, ExpirationTime, TokenType, ImpersonationLevel, dynamic-memory
counts, GroupCount, PrivilegeCount and ModifiedId retain their native bytes.
Token IDs differ across independent producer processes; cross-ABI equality of
whole records is neither assumed nor required. An impersonation object cannot
publish primary-token statistics. Missing metadata stays explicitly unavailable.

Acquisition uses the same private token handle as the existing SID, group and
privilege capture. Two fixed, eight-byte-aligned buffers start with opposite
byte poisons. Both calls must succeed, return exactly 56 bytes and produce
identical complete records. Counts must agree with the captured subject.
The enclosing subject capture compares complete samples with its existing
three-attempt bound. No guest handle, selector, address or length reaches these
host calls. Each statistics pair uses O(1) time and storage: two 56-byte buffers.

## Observed publication behavior

Native64 requires ULONG output alignment and probes the full declared output
span, then the mandatory four-byte ReturnLength destination. Handle, type and
TOKEN_QUERY checks precede size handling. A short output receives required
length 56 and STATUS_BUFFER_TOO_SMALL. On success, ReturnLength is stored
before the 56 data bytes, so overlapping output wins.

WoW64 uses private native storage. It does not align or probe the complete
caller capacity. A null output with nonzero length returns access violation
and optionally copies zero ReturnLength. Handle errors likewise optionally
copy zero. Short buffers optionally receive length 56. Successful data copying
precedes the optional length store, so a later length fault retains all data
and an overlapping length store wins.

All 55 interior page crossings, four protections, five ReturnLength roles,
two token types and three process ABIs leave every output byte unchanged on
copy failure: 6,600 independent boundary calls. Writable guards consume once;
read-only guarded writes fail without consuming their guard. The adapter uses
a checked 56-byte write, rather than assuming an ordered partial-copy sequence.

The WoW64 workspace uses the existing configured guest commit/address budget;
it never allocates host storage proportional to a guest length. Allocation
failure returns STATUS_NO_MEMORY and sets last error to 8. All measured calls
preserve last status; other calls also preserve last error. Workspace admission
and record publication take O(1) work, apart from existing page-probe traversal.

## Native controls

Each ABI records 9,412 calls: 6,084 full buffer/length/destination combinations,
1,120 handle-priority combinations, eight opposite-poison controls and 2,200
interior-copy-boundary cases. The three ABIs total 28,236 calls on one ARM64
Windows 10.0.29695 kernel. These are three process ABIs, not three physical
kernel architectures. Actual mapped NTDLL files and executed images are hashed
before and after each campaign; x86 maps SyChpe32 NTDLL.

The observer reconstructs and checks every arena byte from its poison, actual
56-byte output window and eight watched ReturnLength bytes. This preserves
aliases and non-prefix writes without assuming a copying implementation.
`changed_output_extent` is an observed extent, not a store count. The raw JSONL,
per-process primary/impersonation records and original receipt retain their
bytes. `controls-v1.json` binds the exact final producer and observations.
Earlier successful observers and the initial pre-build controller-path failure
are preserved separately as iteration evidence.

Verify retained identities on Windows, macOS or Linux:

```text
python tools/ci/windows_token_statistics.py --verify-corpus
```

Capture fresh controls and replay both retained and fresh records on native
64-bit Windows with MSVC, CMake, Python and the repository Rust toolchain:

```text
python tools/ci/windows_token_statistics.py
```

The runner checks exact matrix selection, native layout, source/provider/image
identities and all seven selected Windows tests. CI preserves observations,
actual executables and records even if a later check fails.

## Assumptions and boundaries

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| T1 | Same-handle complete statistics can be retained with the token subject. | Immutable publication without host-query forwarding. | Opposite-poison acquisition, whole-subject equality and group/privilege count agreement; any unstable or undefined sample rejects capture. | Confirmed for measured subjects. |
| T2 | The measured native64 and WoW64 probe/copy orders apply to the selected personality. | Shared semantics and the narrow WoW64 adapter. | Every arena byte, guard transition, error state and handle-priority case, plus all 55 interior copy boundaries; fresh CI repeats the independent controls. | Confirmed on the measured kernel; other kernels need their own observations. |

This query does not implement token creation, thread-token attachment, policy
mutation or complete process startup. Those services retain their own explicit
boundaries. Ordinary-token whole startup still encounters protected IFEO input
acquisition. Complete Linux/macOS/Windows process support remains active.
