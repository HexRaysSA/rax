# Growing read-only CSR client views

Installed-runtime admission failed before any guest instruction with
`CSR client data differs from measured readonly view profile`. Both the unchanged
hardware-fault test binary and an independently linked diagnostic reproduced
the failure. The selected USER handle-table allocation had grown its committed
prefix from 8192 bytes to 12288 bytes; its allocation, protections, pointer
identities and protocol layout remained unchanged.

The original `native-csr-client-connect-v6.cpp` producer was reused byte for
byte. ARM64, x64 and x86 observers all returned success, preserved canaries and
stable double reads, and reported these mappings on Windows 10.0.29683:

| View | Reserved allocation | Committed prefix | Remaining reserve |
|---|---:|---:|---:|
| USER handle table, slot16 | 2097152 bytes | 12288 bytes | 2084864 bytes |
| Shared data, slot40 | 32768 bytes | 32768 bytes | 0 bytes |

Earlier frozen four-view captures recorded an 8192-byte prefix. Thus current
commitment is `12288 + 32768 = 45056` bytes, an increase of 4096 bytes. The
validated entry stride remains 32 bytes. This gives 384 committed table slots,
not a count of occupied handles, versus 256 in the earlier capture.

`CsrClientData::selected` now admits a nonempty page-aligned committed prefix
within the same 2 MiB table allocation, with an optional contiguous reserved
tail. Fully committed tables also fit this bounded contract. Sparse commitment,
extra runs, changed allocation extents, foreign pointers and uncommitted
pointer targets remain rejected. The second view remains exactly 32768 committed
bytes. The common DataSection constructor continues to enforce run coverage,
alignment, byte counts and resource bounds.

The native acquisition adapter is unchanged: it validates allocation ownership
and full extents with VirtualQuery, accepts only readonly MEM_MAPPED pages and
reserved tails, uses bounded ReadProcessMemory, requires stable snapshots, and
checks the selected kernel/session/architecture and CSR identities. No host
write, guessed relocation, additional host allocation capture, or broader
filesystem/process permission is introduced. Guest publication remains
transactional at the captured addresses, with identity/protection checks on
reuse. Existing collisions and guest commitment limits still fail explicitly.

Maximum retained bytes are `2097152 + 32768 = 2129920`, or 2.03125 MiB. Snapshot
acquisition/copy uses O(B + R) time and O(B + R) storage for B committed bytes
and R region runs; admission checks O(R) metadata plus 18 typed pointers.
The existing byte payload stays opaque. Old captures retain their original
40960-byte expectations.

The geometry-only receipt in `geometry-29683-v1.json` binds the producer,
compiler, executables, information bytes and committed payload hashes. Full
raw stdout and failed diagnostics remain in the task evidence archive. The
model regression uses those observed extents with controlled payload bytes;
it does not claim that synthetic payloads reproduce the new native snapshot.
The original four native byte-for-byte snapshots remain separate tests.

Producer source:
`../native-alpc-csr/native/native-csr-client-connect-v6.cpp`, SHA-256
b2dd00ddae8338f3757da59e53cc67785523ec5879e8e74cf006dbadad5d6b10.
For each matching MSVC architecture environment, compile with
`cl /std:c++20 /MT /EHsc /utf-8 /W4 /WX native-csr-client-connect-v6.cpp`
and run the resulting owned observer with the architecture name as its first
argument. Hash source, compiler and executable before and after execution.
The producer performs two fixed own-process USER queries, snapshots only the
two returned bounded allocations and preserves raw statuses and handle counts.

The existing three-platform C API CI job now runs the `native_csr_client_data`
filter. Regression cases cover one-page/current/larger/full prefixes, observed
grown geometry, exact bytes, readonly pages, reserved boundaries, rollback,
reuse, sparse runs, wrong extents and pointers in either selected view. The
boundary between adjacent views is a valid pointer target in the second view;
the end of both views is rejected.

macOS and Linux each pass all 8 selected CSR regressions, all 38 object-namespace
regressions and all 191 C API tests. macOS validates the combined tree with the
preserved native-entry draft; Linux validates the published parent with this
owned source overlay. Their selected tests have no ignored cases.

The Windows VM upgraded from kernel 29683 to 29695 during this campaign and
moved the task directory into Windows.old. The interrupted compiler run and
immutable observations are retained; the directory was restored at its original
path after verifying source hashes and terminal process identities. On the replacement kernel, all 8 CSR regressions and all 39 object-namespace
regressions and all 191 C API tests pass. The unchanged original hardware-fault fixture now stops at
`NtSecureConnectPort requires a matched selected guest server and owned shared
views`. Its earlier 29683 ProcessFaultInformation stop is a separate historical
observation. The new kernel remains distinct from the 29683 capture profile;
this geometry change does not qualify its native layout or service behavior.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| CG1 | Committed table pages can grow without a new SHAREDINFO ABI. | Same frozen producer: earlier 8192, current 12288, unchanged allocations/protections/identities in three views. | Validate bounded committed prefix. | One page, current size, larger prefix, full table. | Native geometry or typed identities contradict that shape. | Confirmed by native captures and all three model-test hosts. |
| CG2 | The class 63 ProcessFaultInformation report does not explain this admission failure. | Both original test binary and independent diagnostic fail before guest execution. | Fix capture, then trace the earlier guest exception. | Unchanged original fixture after admitted capture. | Class63 is reached without a preceding unexpected fault. | Retained for kernel 29683; its guest exception remains unknown. Kernel 29695 now stops at the unselected server profile. |

This change does not establish full Windows startup or complete the wider
Linux/macOS/Windows installed-library objective. The original fixture, binary,
assertions, instruction budget and deadline remain unchanged.
