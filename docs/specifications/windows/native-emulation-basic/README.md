# Native SystemEmulationBasicInformation (class62)

Baseline: RAX d315a607fd2bb6480f6d9e2fea2d50bbce8a7ee5; Assist
e2a128e990bec107088ad11e284cd6e0187fbb56. Both trees clean before edits;
root remotes verified. Current owning-archive private saved-context/cleared-PEB
heap diagnostic reaches unsupported class62 at scheduler turn11,206,
NtQuerySystemInformation service0x36 PC0x1800013a0, output0xabf450/64 bytes.

Acceptance: support class62 with native measured guest-width lengths, padding,
fault/probe/write ordering, one-shot guards, aliasing and large-address-aware
limits. Report guest VM/CPU values; never forward a guest request to the host
kernel. Preserve class0/50/250 and explicit unsupported classes. No ABI/layout,
options/defaults/schema/persistence/permissions/dependency/package/lowerer change.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| E1 | Class62 uses SYSTEM_BASIC_INFORMATION with class0 behavior for current measured profiles | PHNT primary declaration plus original length/pointer/guard/alias oracles | Shared guest contract | x86 LAA/non-LAA, ARM64/x64, length/probe/alias boundaries | Compare exact native statuses/bytes/order across all four profiles | confirmed for build29683; other releases unknown |
| E2 | Guest VM limits/CPU/memory metadata own the emulated result | Existing class0/KUSER/PEB coherence contract | Value derivation | 32-bit address limit and backing-size rounding | Independent guest field assertions and executable LAA toggle | confirmed by six portable cases |
| E3 | Matching the bounded query removes this isolated loader dependency | Current archive trace stops at class62 | Next loader progress | Real installed NTDLL leaves and isolated Ldr continuation | Rebuild current owning archive and rerun source-hashed diagnostic | confirmed for isolated loader dependency; production startup incomplete |

High: production native Ldr/RTL heap/CRT still fails four ordinary Windows apps;
wider NT/POSIX/native application/package/IDA matrices remain incomplete. Medium:
other Windows releases/physical host architectures are unverified; class114 is
only a native comparison control and remains outside this change. No adjacent
non-blocking implementation is included.


## Implemented contract and validation scope

Class62 dispatches through the existing basic-information serializer and probes;
no guest string or query is passed to the host kernel. Required length is exactly
44 bytes for x86 or64 for ARM64/x64; mismatched lengths return0xC0000004 and the
required length, with ABI-native probe precedence. The x86 converted output
writes41 bytes and preserves three padding bytes;64-bit output writes64 bytes.
ARM64/x64 require ULONG (4-byte) alignment and probe supplied output extent then
ReturnLength before class/length processing. WoW64 accepts unaligned output and
copies fields before a later returned-length write/fault; null x86 output writes
0xFFFFFFEC then returns access violation. ReturnLength may be unaligned or alias
output and is written after output. Guards are consumed once [E1,E2].

| Profile | Exact size / copied bytes | Native observed maximum user address | Guest maximum |
|---|---|---|---|
| x86 non-LAA |44 /41|0x7FFEFFFF|vm.high()-1 with executable LAA policy|
| x86 LAA |44 /41|0xFFFEFFFF|vm.high()-1 with executable LAA policy|
| ARM64/x64 |64 /64|0x7FFFFFFEFFFF|vm.high()-1|

Guest page/frame counts derive from VM backing/commit limits, address bounds from
that VM, and one guest CPU/affinity from the existing emulated contract. For the
64 MiB fixture,64*2^20 bytes /4096 bytes=16,384 pages; highest frame=16,383.
Guest timer resolution10,000 units*100 ns=1 ms. No host memory/CPU/timer numbers
are forwarded. New class handling adds O(1) dispatch/serialization space/time;
existing supplied-output probing remains O(P) in spanned guest pages and one
64-byte record scratch. No new allocation, input extent, ABI layout, default,
permission or platform adapter is introduced.

Four original C++ oracles produce196 reported native query records plus four
successful alias baseline queries. Native ARM64, compatibility x86/x64 and a
separate x86 LAA executable are queried on build29683. Independent replay checks
all lengths/raw bytes, class0/62 equality, exact ABI faults/guards/write order,
padding and x86 limits. Class114 is rejected by WoW64, matches basic data for
native64-bit profiles, and remains a comparison control outside this group.
Original bytes are fetched with Base64/native SHA256 verification; no DLL binary
is redistributed. Initial temporary oracle build interpolation and test module
path errors are corrected and excluded from passing evidence.

Six portable cases fail before implementation (0 pass/6 fail/7,541 filtered),
then pass (6/0/7,541 filtered). A seventh Windows-only case executes actual
installed host-ABI/x86 NTDLL leaves and returns through their real RET/stack
cleanup, checking guest memory metadata/padding/limits rather than native host
values. Full source hashes precede final cross-platform matrices.


## Change-surface map

| Plane | Status/evidence |
|---|---|
| Plugin lifecycle | Existing native runtime selection; no new lifecycle/IDA state operation |
| UI state | No widget/copy/theme/resource changes |
| Conversation/lane | No history/lane/cancellation contract change |
| Agent backend | No native/ACP request policy change |
| Prompt/context | No source or trusted context change |
| Tool schema | No name/schema/description/discovery changes |
| Permission/mutation | Guest VM writes under existing kernel contract; no host access/permission change |
| Main-thread dispatch | No IDA/Qt call introduced |
| Mesh/MCP | No routing/identity/protocol/manifest changes |
| Transport/crypto | No framing/authentication/crypto input changes |
| Persistence | No settings/history/schema/state migration |
| SDK/ABI | C API1.11.0/private Rust dispatch only; existing consumer/layout gates |
| Optional engines | RAX only; no Z3/Frida/debugger/Hex-Rays change |
| Update/release | Pin and engineering ledger only; no release/default/package change |
| Targets/platforms | Shared dispatch and model cases compile/run all three; native leaves on Windows; owning archives/C++ checks all three |
| Tests/docs | Six portable cases, installed NTDLL case, original native/replay/provenance and loader trace |

## Final validation

| Host/configuration | Unfiltered library pass/fail/ignore/filter | Selection | C API | All targets | Registered integration |
|---|---|---|---|---|---|
| macOS ARM64 Rust1.95 |7,545/0/2/0|7,547|168 pass|compile pass|Unix544 pass; Windows memory cfg-excluded|
| Linux x86-64 Rust1.95 bullseye container on ARM64 host |7,537/2/2/0|7,541|168 pass|compile pass|Unix544 pass; Windows memory cfg-excluded|
| Windows29683 ARM64 Rust1.95 |6,933/5/2/0|6,940|168 pass|compile pass|Unix cfg-excluded; native memory4 pass|

Linux failures are the previously observed multishot/remove-update io_uring
assertions; Windows retains four BZHI and one FP16 assertion. Historical
readiness/clock evidence remains unresolved. No assertion, skip, selection,
lowerer or unrelated service changed. Actual installed NTDLL class62 leaf passes
inside the Windows unfiltered suite, alongside all six new portable cases. Full
suites use the formatted final source; no later test/production source adjustment.

Locked owning assist-rs archives and five production C++ checks pass all three
hosts, including ABI drift, static linkage and explicit disabled-RAX refusal.
The owning macOS CLI and seven CTests (including both manifest checks) pass;
protected CLI text scan passes. No metadata/manifest, plugin/Qt/real IDB/full
package matrix changed or was newly exercised. Linux container translation is
not physical native x86-64 kernel proof. Initial Linux rustup manifest network
refresh timed out before tests; explicitly selecting the verified installed
1.95.0 toolchain reruns all checks without changing the pin or source. Original
Windows result bytes have native SHA256 verification. Full gate/source/transfer
hashes preserve exact selection and compiler input.

The current owning-archive loader boundary is below.


## Current owning-archive loader boundary and self-review

The private saved-context/cleared-PEB.ProcessHeap diagnostic uses the current
locked owning archive's RAX rlib selected from Cargo JSON artifact output.
Class62 returns success at turn11,206. At turn11,315, PC0x1800017c0,
NtAllocateVirtualMemoryEx service0x78 is explicitly unsupported. Observed
registers begin process=-1, base-pointer=0x1803c50d8, size-pointer=0xabe950,
allocation-type=0x102000, protection=4, extended-pointer=0xabe8e0 and count=1.
Delta11,315-11,206=109 is scheduler calls, not instructions [E3]. No extended
allocator semantics are inferred by this group. Four ordinary Windows smoke/
msvcrt/ucrt/whoami programs still return STATUS_ACCESS_VIOLATION; this diagnostic
is not production native process entry. Full native Ldr/RTL heap/CRT and wider
NT/POSIX/native application/package/IDA matrices remain incomplete.

Self-review confirms no guest-to-host forwarding, unchanged class0/50/250 paths,
measured class62 lengths/probes/padding/guards/order/alias limits, guest metadata
coherence and executable LAA policy. New shared/native cases, source/primary/
license/original-result hashes and exact full-suite selections establish this
bounded semantic group. Other release/host profiles remain an explicit limit;
comparison class114 does not enter the dispatch contract [E1-E3].
