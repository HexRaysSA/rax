# Native thread opening

[Documentation entrypoint](../../../../README.md)

`NtOpenThread` opens an existing guest thread object. The installed NTDLL
service table selects the service number; the emulator does not assume that
`0x139`, observed on ARM64 kernel 10.0.29695, is portable. Appending a registry
family preserves earlier synthetic export ordinals and trap addresses.

The motivating installed CMD call requests `0x001FFFFF`, supplies a zero process
identifier and its own guest thread identifier, and leaves every object
attribute except `Length = 48` zero. The stopped-process inspection uses the
public process/CPU/memory APIs and does not replace the service with a stub.

## Native measurements and ABI

The primary signature and object-name requirement are documented by Microsoft:
[NtOpenThread](https://learn.microsoft.com/windows/win32/devnotes/ntopenthread).
The documented rights and query/set implications are in
[Thread Security and Access Rights](https://learn.microsoft.com/windows/win32/procthread/thread-security-and-access-rights).
Fault precedence, ignored fields, reserved-mask behavior and caller copies below
are independent native observations rather than conclusions supplied by those
pages.

`probe-v4.c` is the complete 290-case producer. Earlier versioned producers and
runners are immutable investigation records. Runner v2 lacked `advapi32.lib`
and failed to link; runner v3 corrected that link without editing its C source.
Runner v6 uses the same complete C producer as v5 and additionally records
`IsWow64Process2` machine identities. CI requires native machine `0x8664` and a
native runner process before executing the AMD64/WoW64 controls.

Each case runs in a fresh process. It records returned NTSTATUS separately from
an escaping exception, original LastError, output bytes, handle-count delta,
granted access, inheritance, and the six 4096-byte page protections. Owned worker
threads leave through an event, are joined, and have their handles closed. Token
privilege changes apply only to that case's process. No protection setting,
foreign process/thread or installed system image is modified.

The retained ARM64-host corpus covers native ARM64, x64 compatibility and x86
WoW64, with 290 rows each. These are three guest ABIs on one native kernel;
independent AMD64 kernel qualification is a separate CI gate.

| Contract | Native64 | WoW64 |
|---|---|---|
| Input alignment | Four-byte OBJECT_ATTRIBUTES and CLIENT_ID alignment | Unaligned caller structures are converted |
| OBJECT_ATTRIBUTES capture | ObjectName and Attributes; 28-byte accessible prefix suffices; Length/root/SD/QoS ignored | Length must be 24; name, SD and QoS headers are widened before output probing |
| CLIENT_ID | Two eight-byte values | Two four-byte values |
| Output | Complete eight-byte writable HANDLE checked first, without alignment requirement | Complete four-byte HANDLE checked after conversion |
| Readonly guarded output | Reached guard is consumed and reported | Write denial preserves the guard |
| Failed publication | No surviving new handle or caller-byte change | Same |

PID zero permits lookup by thread ID. A supplied nonzero PID must match the
owning guest process exactly. Thread-ID low tag bits are ignored; high native64
bits are not truncated. Names or a NULL CLIENT_ID produce
`STATUS_INVALID_PARAMETER_MIX`. Attribute bits `0x10`, `0x20` and `0x80` are
rejected after identity lookup; bit 2 controls inheritance. Ignored SD and QoS
headers do not change the target object's security.

Lookup uses the object table, including the dispatched current thread and
exited objects retained by handles/waits. Closing the last native user handle
races unobserved kernel teardown references in case 42. Its three rows therefore
assert the bounded native result; they are not presented as deterministic
timing replays. A separate test explicitly retains/releases the guest scheduler
and handle references and checks that final release removes the identity.

## Opening rights and host boundary

Native selection captures opening rights of a fresh, default-security thread
created and joined by the adapter. Its retained handle keeps the exited native
object discoverable throughout capture. Four fixed opens measure maximum
access, system-security status, reserved-bit bypass, and combined maximum plus
system-security access. All native handles are private RAII owners and are
closed. A host impersonation token makes this primary-subject capture explicitly
unavailable. No guest pointer, handle, identifier, access mask or syscall number
enters a host syscall.

The shared model maps generic access, adds the observed limited query/set and
resume implications, preserves the measured zero-request denial, and separates
reserved-bit admission from privilege admission. A missing capture refuses the
operation before creating a handle. The portable built-in personality retains
its fixed default subject without the system-security privilege. Custom thread
security descriptors, token changes and foreign-process namespaces require
their own implementation; this handler does not fabricate those capabilities.

Identity lookup costs O(O) time for O retained objects. Handle creation costs
O(H) time for H handles. Extra state is O(1); WoW64 converts only fixed-size
headers. The caller's complete HANDLE is probed before allocation, and a final
store failure closes the newly created handle.

## Assumption Register

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| TO1 | CMD's target belongs to the guest namespace; stopped registers and CLIENT_ID identify its current TID | Object-table lookup | Current/peer/exited objects, tagged IDs, zero/wrong/high PID/TID; falsified by acceptance of a foreign guest owner | Confirmed for the measured namespace |
| TO2 | Shared native64 and separate WoW64 capture contracts explain the retained kernel observations | Probe/copy ordering | Unaligned/truncated/aliased/guarded inputs and output, every access bit; rerun on independent AMD64 kernels to falsify cross-kernel parity | Confirmed in retained ARM64-host ABIs; AMD64 checked per CI receipt |
| TO3 | Fresh default-thread controls match the captured primary subject | Access ceiling | Refuse host impersonation; join controls and repeat capture while checking process handle count; any leaked handle or admitted unsupported subject falsifies it | Native ARM64 adapter and repeated-handle control passed |
| TO4 | Opening grants must remain usable by existing Win32 consumers; native controls admit resume-only and execute grants | ResumeThread access gate | Compare both consumers, previous/final counts and LastError for six masks on every guest ABI; any native mismatch falsifies the rule | Confirmed in 18 native ARM64-host controls |

## Scope and validation

The replay checks 867 deterministic retained rows, every caller byte in the
24576-byte case arena, grants, handle counts, LastError and guard transitions.
The three case-42 timing rows have explicit bounds as described above. Separate
tests cover object lifetime, independent handle grants, absent capture and a
reduced ceiling. Native Windows tests execute installed NTDLL leaves, verify
WoW64 RET16 cleanup, and check that repeated native capture leaves no handles.

The Windows CI job collects 580 fresh AMD64/WoW64 rows on each of its native
Windows 2022/2025 kernels and supplies that receipt to the same replay. It also
retains the original complete hardware-fault fixture and its budgets. Compilation
or recorded replay on a Unix host does not establish native Windows execution.

High impact, nonblocking to this individual service: full Linux/macOS/Windows
installed-library process emulation remains incomplete. Windows child-process
namespaces, custom thread security and subsequent installed-program kernel
services remain part of that larger objective. The existing explicit rejection
of custom `CreateThread` security descriptors is unchanged.


The installed build-29695 ARM64 CMD now passes `NtOpenThread` and stops at
unimplemented `NtSetInformationVirtualMemory` (`0x1B0`), returning emulator exit
125 before stdout. Native CMD returns zero and emits the echo marker. Its SHA-256
is `d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`
before and after both runs. This establishes service progress, not complete CMD
or full process qualification.


## Resume-only grants and existing Win32 consumers

The complete opening corpus grants `0x1000` for a resume-only request and includes
that right in `GENERIC_EXECUTE` (`0x00121800`). A separate owned-worker control
in `probe-resume-v1.c` checks six specific/generic grants through actual
`SuspendThread` and `ResumeThread` calls. All 18 ARM64-host observations preserve
previous suspend counts and LastError. The worker is joined before both handles
are closed. The retained receipt is
`resume-observations-arm64-29695-v1.json`.

The shared built-in ResumeThread consumer now accepts either `0x2` or `0x1000`.
SuspendThread continues requiring `0x2`. The replay opens the guest handle through
NtOpenThread, then checks both consumers, their errors and final suspend count.
CI supplies 12 fresh AMD64/WoW64 observations per kernel to the same replay.

The native capture handle-count test runs in a dedicated exact-test child
process. This makes the resource check independent of other tests opening real
host handles concurrently; the child must report the completed count check.
