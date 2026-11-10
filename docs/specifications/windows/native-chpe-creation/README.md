# Initial CHPE V2 process data on ARM64 kernel 29704

The completed `creation-v1.cpp` control creates three unchanged private startup
fixtures with `CREATE_SUSPENDED`, reads their native and compatibility PEB fields,
resumes each main thread exactly once and waits for natural process exit. All
three children and the controller exit 0. It uses no debugger, context write,
remote-memory write, fault injection, process termination or wall deadline.
The separate earlier debug-event observer is not a prerequisite or a completed
verdict for this capture.

For the AMD64 input PE, the 8-byte field at native `PEB+0x338` points to
`PEB+0x7d8`. Its 32-byte initial record contains flags 0, native machine `0xaa64`,
emulated machine `0x8664`, and zero Section, work-list and final pointer fields.
The record is committed private read/write memory. Native ARM64 and i386
children have zero native fields; i386's 4-byte compatibility field at
`PEB32+0x218` is also zero. Every child is resumed with a previous suspend count
of 1 and completes the original thread-lifecycle fixture with exit 0.

`IsWow64Process2` reports process machine 0 for both the ARM64 and AMD64 inputs
at this creation boundary. The input PE machine and captured record identify
the AMD64 case. That API value alone cannot select this initial guest profile.

The [Wine record declaration](../native-arm64ec-bridge/wine-winternl.h) and
[PHNT PEB field reference](../native-arm64ec-bridge/phnt-ntpebteb.h) identify
the private field names. The completed Windows capture owns the measured bytes
and lifecycle; Wine's initialization code is not Windows runtime proof.

The emulator selects only guest AMD64 with captured native ARM64 kernel
`10.0.29704`, independently of the mutable guest-reported version. It publishes
the record and its guest-relative pointer within the existing process-owned PEB
page before any guest instruction. Both ranges are checked before either write;
previous publication, modified record bytes, unknown native identity and
unwritable memory are rejected. No native address, handle or callback is copied.
The installed RTL owns any later flags, Section and work-list initialization.
Closed mode, other guest ABIs and a native AMD64 host retain their existing
creation behavior. Unmeasured translated-AMD64 native identities are explicit
unsupported results.

The captured native query reports a 12,288-byte PEB region and a larger private
allocation. The initial 32-byte record fits inside its first 4,096-byte page.
This change uses the existing guest PEB page; it does not claim complete native
PEB allocation geometry or implement the later CHPE work-list/callback state.
The initializer takes O(1) time and space and allocates no guest resources.

The retained archive is `native-chpe-creation-29704-v1.zip`, 1847291 bytes,
SHA-256 `5d60b1e5883c9bb438ba269240dbbe42c9de92172f44f2509b6653e4cc81609a`.
It contains 12 payloads plus a manifest: exact controller and three original
child images, source, build commands, package, launch binding, original receipt,
stdout and captured XtA provider. The seven installed DLL identities and every
acquisition input hold before/after execution. The raw XtA PE machine is ARM64;
its image extent and timestamp agree with the earlier guest-side image diagnosis.

Verify the public source and frozen projection:

```text
python3 -I -B docs/specifications/windows/native-chpe-creation/verify-v1.py
```

Add the retained archive path to verify all payloads, executed inputs, original
verdicts and an independent field/lifecycle projection. On Windows use `python`.
No-argument verification does not check the separate raw archive. For compressed
archive size B and total uncompressed payload size U, verification takes
O(B + U) time and space. It does not rerun native controls.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| CH1 | The normal creation boundary supplies the initial AMD64 metadata independently of debug events. | Completed normal suspended creation and natural exits of all three original fixtures. | Finite initial-record producer. | Guest ABI, native identity, version spoofing, prior mutation and memory faults. | Different initial fields or failed original child exit. | Confirmed for this capture; emulator qualification is separate. |
| CH2 | Process-machine query identifies AMD64 before RTL starts. | Expectation before the normal-creation capture. | None. | Three input PE machines. | AMD64 input reports process machine 0. | Falsified; parsed PE and captured native identity select the profile. |

High-impact remaining scope includes complete AMD64 installed-library startup,
hybrid exception-frame qualification and the later translator work-list state.
The unresolved file-read IOSB-padding failure is a separate service-path issue.
This initial-record increment does not establish full process emulation.
