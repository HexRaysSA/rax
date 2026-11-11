# Current-session ARM64 CSR binding

Installed Windows acquisition binds CSR metadata to the current native
process's session, its selected readonly SharedSection, and its ApiPort.
Session 0 uses \Windows; a nonzero session uses
\Sessions\<session>\Windows. The fixed host USER query uses this independently
validated directory. Guest names, pointers, handles and connection requests
never enter that host query or host IPC.

The guest connection still requires the measured architecture/build profile,
exact selected section identity, matching captured and guest PEB sessions,
server PID, QoS, required server SID, packet shape and real owned pagefile
backing. The modeled server owns an independent address space and shared-view
peer. Native and WoW64 PEB publication and port/view retirement retain their
existing contracts. The change removes the session-0-only restriction while
preserving these identity checks.

## Independent current-session observations

All three controls ran under the same ordinary-user SID and native NTDLL
SHA-256. Their source, host-built executable and raw output identities are
retained. The process PEB reports version 10.0.29698 and session 1.

| Control | Observation | Completion/lifetime |
| --- | --- | --- |
| Initialized ARM64 process | SharedSection prefix matches its independent readonly alias; fixed USER query succeeds with 584 bytes | Process handles before/after the explicit section open/close controls: 55/55 |
| Fresh ARM64 child | First NtSecureConnectPort to \Sessions\1\Windows\ApiPort succeeds | Child naturally exits 41 |
| Fresh pure x86 child, CHPE disabled | First NtWow64CsrClientConnectToServer to \Sessions\1\Windows succeeds | Controller stops only its owned child with code 70 after the return |

The initialized-process repeat secure connection returns
STATUS_PORT_CONNECTION_REFUSED (0xC0000041) with unchanged caller buffers.
It is separate from the successful first-startup call.

The native shared section has a 1,048,576-byte allocation: a 20,480-byte
readonly committed prefix followed by 1,028,096 reserved bytes. The native
server base, prefix words, statics offset 0x750 and CSR PID match the genuine
first connection's reply. The 48-byte reply preserves its final 24 caller
bytes, returns a 952-byte maximum message, and reports a 48-byte information
length. The 24-byte remote-view output is zero. The client has a real
65,536-byte pagefile view.

The fixed USER reply identifies a 2,097,152-byte handle-table allocation and
a 32,768-byte shared allocation. In this observation their readonly committed
prefixes are each 32,768 bytes; the remaining handle-table pages are reserved.
The existing acquisition validates full allocation identities, committed
regions and the declared pointer slots, then copies stable bounded snapshots.
The observed committed-prefix size does not become a fixed protocol size.

The x86 control records process/native-PEB/WoW64-PEB session IDs of 1, an
unchanged eight-byte BASE input, a zero inside-server Boolean, one new ALPC
handle and the expected readonly/shared mappings. Its leaf uses RET20:
0x028FED38 - 0x028FED20 = 0x18 = 24 bytes, comprising 20 argument bytes
and the four-byte return address. The controlled stop is not a natural
ordinary-program exit.

    python3 -B docs/specifications/windows/native-arm64-session-csr/verify.py
    cargo +1.95.0 test --locked --offline --no-default-features --lib current_session::
    cargo +1.95.0 test --locked --offline --no-default-features --lib csr

The replay retains the native caller's opaque bytes and substitutes only the
actual guest-owned section handle. Additional session-ID cases 0, 42 and
u32::MAX exercise formatting and identity boundaries; they are synthetic
model cases, not native observations of those sessions. Negative cases cover
foreign guest/native PEB sessions, captured-session changes, the global root,
and global/foreign/copied section owners. Those failures must publish no
output, handle or view.

The session-path change adds O(1) bounded work and storage. For a nonzero
32-bit session ID with d decimal digits, the directory has 18 + d
UTF-16 units and its ApiPort path has 26 + d; 1 <= d <= 10. The longest
directory including its terminator has 29 units, or 58 bytes. Existing
snapshot, VM, connection-count and caller-buffer bounds remain in force.

## Evidence limits and remaining work

These controls establish the recorded session-1 native behavior and bind it
to the retained binaries. They do not prove every Windows version, caller,
kernel architecture, session, CSR message or ordinary program exit. Existing
build/architecture admission remains finite.

The rebuilt ordinary-user native executable passed all 43 selected Windows
CSR cases and both installed ARM64/x86 leaves. Including focused reruns, it
passed 52 case-runs covering 45 unique cases, with none failed or ignored.
The source/artifact manifests join the host build to the native executable;
they do not assert a native rebuild. macOS passed the five new session cases,
two kernel-profile cases, 117 broadly selected CSR cases, and strict library
Clippy.

The rebuilt installed CMD attempt passes the earlier secure-connection
boundary and stops later at NtAlpcSendWaitReceivePort with an unmeasured CSR
message/profile. Its captured message has API number 0x0001001b, 40 data
bytes, 80 total bytes and a declared 1,660-byte information buffer. The semantic
API name remains unknown in this changeset. This requires a separately measured
reply, not a generic success fallback.

The terminal sample reports an instruction-budget bound of 4,395,008:
(68,671 + 1) slices * 64 instructions/slice. This is an upper bound, not an
independently counted retired-instruction total. The diagnostic wrapper exits
0 after recording the guest Internal error; CMD has not completed successfully.

## Standalone C API fixture qualification

A separate cross-built Windows C API run under SYSTEM initially passed 241
cases and failed two because they opened PE/DLL fixtures through the Mac
build's CARGO_MANIFEST_DIR. The raw failure receipt is retained. These tests
now embed the same 21 existing binaries; supplied DLL names, all three guest
ABIs, exit statuses, CRT stdout/stderr bytes and assertions are unchanged.
The standalone executable no longer requires the source checkout at runtime.

The rebuilt Windows executable passed all 243 registered C API tests with
none ignored under SYSTEM (SID S-1-5-18). This context is separate from the
ordinary-user CSR core/installed-leaf evidence above. The two repaired cases
also pass individually on macOS, followed by all 244 macOS C API cases.
Fixture membership and SHA-256 identities are retained alongside the native
source/artifact manifest.

## ARM64EC connection on build 29704

The original AMD64 fixture on ARM64 Windows 10.0.29704.0 reaches the installed
ARM64EC `NtSecureConnectPort` wrapper. A native hardware-breakpoint observation
captures one successful connection to `\Sessions\1\Windows\ApiPort`,
followed by natural process exit with code zero. Its 48-byte client view,
24-byte server view, System SID, QoS and 48-byte information packet match the
ARM64 connection geometry. The reply reports a 952-byte maximum message,
preserves the final 24 information bytes, supplies the captured server
base/statics/PID and creates the two shared view addresses.
[Native ARM64EC observation](arm64ec-profile-29704-v1.json).

The guest admits this pairing when the captured host machine is ARM64,
the server metadata belongs to ARM64 build 29704, and the AMD64 thread is
executing in its active ARM64EC context. Session, Section identity, pagefile
backing, output-span, SID, QoS and information-packet validation apply before
publication. The implementation reuses the existing owned client/peer mapping
and rollback paths.

The [observer](arm64ec-observe-29704-v1.cpp) builds as an ARM64 console program
with the Windows SDK. Run it beside the unchanged AMD64 fixture named
`x64.exe`. It recognizes the captured complete installed wrapper, uses one
available thread hardware-breakpoint slot, and observes the SVC boundary and
its return. Receipt hashes bind the producer and stdout. The controller
disables debugger kill-on-exit and allows its owned child to finish.

The focused CSR selection passes 20 tests on macOS, 20 on native Linux and
22 on native Windows, including the installed-library leaf checks. The original
ARM64 and x86 emulation fixtures exit with code zero. The original AMD64
emulation fixture passes the connection and reaches the emulator's
AMD64 exception-dispatcher frame qualification boundary.
