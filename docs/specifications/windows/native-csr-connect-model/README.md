# Selected CSR connection model

This is a bounded implementation and validation record. Native controller child
exit code 41 is distinct from an emulated ordinary program exit.

Three bounded ARM64 native controls observe the original nine-argument
NtSecureConnectPort startup call on Windows 10.0.29683.1000. The reply preserves
the final 16 bytes of a 48-byte startup packet, reports maximum message 952 bytes,
and supplies the server readonly base, statics address and PID. Two independent
readonly producers bind those fields to this host process's PEB and selected
SharedSection alias. The four-entry observer sees one secure connection and no
other monitored ALPC/LPC calls before its owned child exits naturally with code 41. This
absence is bounded to the monitored entry points, main thread and that child.

The implementation admits the measured ARM64/session 0 packet on builds 29683
and 29695. The [additional kernel qualification](../native-csr-kernel-profiles/README.md)
retains the new native observations and limits. Historical 29683 results below
keep their original source/kernel identities.
It requires the System SID, measured QoS bytes, a 65536-byte writable committed
pagefile section, nonoverlapping writable outputs and matching immutable CSR
metadata. Other ABI/build/session/packet forms remain explicit unsupported
frontiers. In particular, readonly information-length success behavior is
unknown and is refused; missing-endpoint readonly-length behavior remains
covered by the earlier 396-row corpus. Full Windows completion across supported
ABIs remains part of the active objective.

The selected metadata reader uses only initialized host-process metadata and
fixed readonly APIs. It compares the own-PEB readonly alias prefix with the
captured section, validates PEB session/build and server base, and reads the
pointer-width CSR PID export only within the measured native profile. Guest
pointers, handles and requests never enter host IPC. Pinned PHNT references and
license are retained; actual A64 export bytes and native observations supply
the private-layout/runtime evidence rather than a claim about all Windows builds.

A successful model connection maps actual shared pagefile backing in distinct
client/server address spaces and creates typed endpoints. The server VM also
maps the matched readonly section at its protocol server base. The peer-view address belongs to the modeled server VM.
The guest readonly snapshot keeps opaque server pointers unchanged. Six fixed
output spans require 136 bytes of undo data, with all preparation before
publication. Failure releases owned resources; generation tokens protect
explicitly unmapped/reused client addresses from delayed endpoint cleanup.

The model limits active server connections to 32. Each server address space has
a 1048576-byte frame arena, bounding their combined frame budgets to 33554432 bytes
(32 MiB), separate from the caller VM budget. This is an emulator resource bound,
not a measured native port quota. Peer VM lifetime follows the modeled endpoint
object; native CSRSS remote-endpoint close timing is unknown and not claimed.
General CSR messaging and unobserved service families remain unsupported.

Run `python3 docs/specifications/windows/native-csr-connect-model/check.py` to
verify primary source/raw identities, original reply fields, PEB relationships,
System SID/QoS and natural native child outcomes. Raw CRLF bytes are preserved;
normalization is confined to parsing. The first original controller's zero-length
post-call remote-view dump is excluded from remote 24-byte evidence; its corrected
successor verifies all 24 output bytes. No timeout/assertion is weakened.


## Completed epoch3 validation (Rust 1.95.0)

| Host | Library passed/failed/ignored | CSR focus | LPC focus | C API | Other selected execution |
|---|---|---|---|---|---|
| macOS ARM64 | 7825/0/2 | 10 | 7 | 168 | 544 shared Windows integration tests |
| Linux x86-64 container | 7819/0/2 | 10 | 7 | 168 | 544 shared Windows integration tests |
| Windows ARM64 native | 7247/5/2 | 12 | 7 | 168 | 4 native external-memory tests |

All three all-target checks and production `rax-user` builds completed. Windows
`user_windows` contains zero runnable tests under its native configuration; its
result is compile evidence only. The four `user_windows_memory` tests executed.
The two ignored microkernel checks and the five unchanged Windows AArch64
lowerer failures remain explicit in `validation/results.json`. Initial LPC and
CSR fixture compile errors and their source epochs are retained. No assertion,
timeout, service status or lowerer behavior was weakened.

Scoped Assist validation rebuilt the empty-feature RAX core on all three hosts
and verified 285 selected code/fixture identities per host, plus the unchanged
native helpers. macOS rebuilt the CLI/MCP, passed seven CTests and both protected
text scans. Linux and Windows rebuilt the embedding and each executed five C++
consumers, including process tools, process execution, ABI drift and archive
panic containment. The archive records include full hashes and structural
member walks. Nine current-root C++ source identities were rechecked against the
frozen exports. These results do not establish whole-current-root, IDA plugin,
interactive GUI or package validation.

The unchanged ordinary-startup observer advanced ARM64 `smoke.exe` from the
old secure connection at turn 2115163 to `NtInitializeNlsFiles` service `0x107`,
PC `0x1800020b0`, turn 2122164: a difference of 7001 observer turns. `whoami.exe`
still stops at `NtTraceEvent` service `0x5e`, turn 121349. The separate probe path
was absent and is excluded from executed-program counts. Controller exit zero
is not guest completion; ordinary Windows guest completion count remains zero.

Run `python3 docs/specifications/windows/native-csr-connect-model/validation/check.py`
for archived hashes, current-versus-compiled input equality, actual test counts,
exact retained failure identities, installed NTDLL positive execution and scoped
owning/archive evidence. The corpus contains an explicit allowlist of source,
text and JSON artifacts; local executables and object files remain external.
