# Native WoW64 startup information

```text
python docs/specifications/windows/native-wow64-startup-information/run-v2.py
```

This control reads only its own process metadata. It observes the main thread
and one newly created, joined thread; it changes no TEB fields, process policy,
guest fixture, or RAX runtime. The small C++ observer uses the native x86 ABI,
Windows headers and the TEB intrinsic. Its portable Python driver selects MSVC,
keeps build outputs inside this worktree, checks the PE machine and binds source,
driver, compiler and pre/post executable hashes. The existing Windows exception
profile workflow runs the controls on Windows 2022 and 2025.

The local build-29683 ARM64-kernel observation is recorded in
[local-29683-v2.json](local-29683-v2.json). Both thread samples pass. Their
32-bit TEB has `WowTebOffset = -8192` bytes; the 64-bit companion has the reverse
offset `+8192` bytes. Native self pointers and the companion's 32-bit TEB link
agree. Native TLS slot 10 points to one process-shared information object, while
the application's 32-bit TLS slot 10 is null. The object is 1168 bytes (`0x490`)
after the 32-bit PEB in this measured process. This is an observation, not a
universal PEB-size or placement assertion.

The first three 32-bit words are native page size 4096 bytes, CPU flags 2 and
execute flags 0. The 40-byte layout's machine fields agree with
`IsWow64Process2`: native machine `0xAA64`, emulated machine `0x014C`. The
compatibility view's `GetNativeSystemInfo` instead reports processor architecture
9 (AMD64), so that value cannot identify the physical kernel by itself.
The fourth word, section handle and work-list pointer are retained only as
nonzero predicates. Their raw values and all TEB/object addresses are omitted.
Thread-local TLS contents and companion geometry are observed independently;
the validator does not require those unrelated thread fields to match.

Primary declarations are pinned in [references.json](references.json): PHNT's
older SDK-derived definition covers the initial 16 bytes and companion-TIB
linkage; Wine's current definition describes the 40-byte extension and reserved
native TLS slot 10. The sources differ in their fourth-field nomenclature.
This control labels that word unknown and does not assign a pointer contract.
Native observations, rather than either declaration alone, establish the
captured machine fields and process sharing.

The emulator investigation reached the installed `SysWOW64\\ntdll.dll`
instruction at RVA `0xCD87A`, `mov eax, [eax]`, with EAX zero. The preceding
sequence selected TLS slot 10 through the TEB view; the guest had neither a
companion offset nor the information pointer. This fault occurred before the
fixture's intended write to `0x1000`, and before its class-63 fault notification.
Independent single-step and ordinary-slice diagnostic runs retain the same
immutable fixture and identify the same fault. The control supplies evidence
for the missing startup state; it does not implement that state or establish
successful emulated exception continuation.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| WI1 | The native TLS object is shared across threads in one process. | Pointer identity and word comparison in main and new thread. | Process-owned startup information. | Independent thread TEB allocation. | Different native pointers or words. | Confirmed on ARM64 build 29683 and independent x64 builds 20348 and 26100. |
| WI2 | Native companion linkage is required by the selected x86 startup path. | Installed instruction sequence and zero-pointer fault; native negative offset, reverse link and slot observation. | Companion TEB initialization. | Application TLS slot 10 remains independently usable. | Native startup reaches a valid object without the companion path. | Confirmed for the measured build and path. |

The runtime now constructs guest-owned companion TEBs and the shared information
for the three captured kernel profiles. Selection uses captured native kernel
identity rather than the guest-reported version; unknown native x86 profiles
fail with `STATUS_NOT_SUPPORTED`. Built-in x86 and native 64-bit processes keep
their existing paths. The compound TEB allocation is 12288 bytes: the native
view precedes the 32-bit view by 8192 bytes. Host-owned allocation claims survive
scheduler extraction and guest decommit; teardown uses allocation identity,
without trusting guest-writable offsets or freeing a replacement allocation.

The independent [resource observer](native-wow64-resources-v2.cpp), reproduced
with `python docs/specifications/windows/native-wow64-startup-information/run-resources-v1.py`,
identifies the opaque word as executable `xtajit.dll` image code at RVA `0x34000`
on build 29683. It is not an NTDLL base. RAX uses its own instruction execution
and code coherency; the guest opaque word remains zero. Its native64 PEB is an
identity page, without a separate native64 RTL loader, heap or parameter block.
Broader native64 RTL and instrumentation callback equivalence remains unknown.

[The captured resources](local-resources-29683-v2.json) contain a 16384-byte
`SEC_COMMIT` section, access mask `0xF001F`, object attributes zero and no section
base address. Its quiescent 48-byte header reports 408 free entries and offset 16328. The
pinned Wine declaration uses 40-byte entries, consistent with those values:
`floor((16384 - 48) / 40) = 408` entries, with the last entry at
`48 + 407 * 40 = 16328` bytes. Work head/counter and reserved header words are
zero. RAX creates an ordinary guest shared section and a process-owned view;
closing its handle leaves the view live. All queue initialization is bounded
O(408) time and O(16384 bytes) storage. No host handle or pointer is copied. The complete native free chain was not
read by this observer; the model chain is checked separately.
The original local executable/controller hashes remain in that record; the
portable reproduction is separately versioned and does not replace them.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| WS1 | Captured kernel identity selects the layout. | Three independently observed kernel profiles. | INFO placement and CPU flags. | Spoofed guest version or unknown native machine/build. | Select a different layout from the same captured identity. | Retained; unknown profiles are explicitly rejected. |
| WS2 | The software profile owns an ordinary shared section with the recorded initial queue. | Native section/object queries and 48-byte queue read. | Section lifetime and guest aliases. | Handle close, alias writes and failed publication. | A close invalidates a live view or rollback leaks resources. | Confirmed by native resource observation and model tests. |
| WS3 | RAX does not execute native XtA callbacks or a separate native64 RTL for x86. | Opaque word belongs to ARM64 XtA image code; the guest executes through RAX. | Zero opaque word and native64 identity page. | Installed initialization and cross-process instrumentation. | Installed code requires an absent callback or native64 RTL interface. | Retained limitation; full continuation remains unqualified. |
| WS4 | Active TEB claims survive guest memory and scheduler state changes. | Current thread can be extracted from the scheduler map during calls. | Allocation tokens and identity-checked teardown. | Guest decommit, field corruption, failed creation, replacement allocation. | Live extent reuse or replacement bytes changed by teardown. | Confirmed by focused lifecycle tests on all three hosts. |

Six focused startup/resource/lifecycle tests pass on macOS, Linux and Windows.
The combined development tree passes 8421 macOS library tests (two ignored)
and 191 C API tests. Linux initially reports 8405 passes, nine failures and two
ignored tests: direct `docker exec` supplied parent PID zero and umask `000`.
With an in-container parent and umask `022`, all 705 Linux personality tests
pass using the same binary and unchanged assertions. A separate clean-parent
source check, excluding the older native exception-entry drafts, passes the six
startup tests and all 191 Linux C API tests. The Windows combined tree also
passes all 27 process-query tests. These results are development/clean-source
checks, not an owning Assist shipping artifact or package qualification.
The unchanged installed Windows exception fixture advances beyond the original
NULL load and currently stops at the unimplemented
`NtWow64GetNativeSystemInformation` service. This does not establish successful
emulated exception continuation. High impact, unresolved: that service and the
broader native64 RTL/callback interfaces require further qualification. Older
NLS profiles, DPI and complete Linux/macOS/Windows installed-library userland
are also outside this result. Public C API 1.15.0, feature defaults and execution
budgets are unchanged.
