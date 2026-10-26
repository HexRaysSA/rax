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
profile workflow runs the control on Windows 2022 and 2025.

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
| WI1 | The native TLS object is shared across threads in one process. | Pointer identity and word comparison in main and new thread. | Process-owned startup information. | Independent thread TEB allocation. | Different native pointers or words. | Confirmed locally; independent kernels pending. |
| WI2 | Native companion linkage is required by the selected x86 startup path. | Installed instruction sequence and zero-pointer fault; native negative offset, reverse link and slot observation. | Companion TEB initialization. | Application TLS slot 10 remains independently usable. | Native startup reaches a valid object without the companion path. | Confirmed for the measured build and path. |

High impact, unresolved: RAX must construct guest-owned companion TEBs and shared
information with correct lifecycle and resource semantics. Native section
handles, work-list pointers and unknown fields must not be copied into guest
memory. The full Windows process fixture, older NLS profiles, DPI and complete
Linux/macOS/Windows installed-library userland remain unqualified by this
observation. Public C API 1.15.0, Assist's private ABI, feature defaults and
execution budgets are unchanged.
