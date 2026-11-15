# Initial CHPE V2 process data on ARM64 kernels 29704 and 29708

The original completed `creation-v1.cpp` control on 29704 creates three unchanged private startup
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
`10.0.29704` or `10.0.29708`, independently of the mutable guest-reported version. It publishes
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

## Independent build 29708 controls

`profile-29708-v1.json` retains fresh observations from ARM64 Windows 10.0.29708.
The unchanged creation, segment and XSTATE producers were compiled and executed
natively. Three unchanged committed `tests/fixtures/user/windows/bin/*/smoke.exe`
children replace the unavailable historical private thread-lifecycle images;
their input hashes and PE machines are explicit. Creation resumes each child
once and observes natural status 0. The segment controller independently queries
one suspended AMD64 smoke child, resumes it once and observes natural status 0.
All three compilers, three producers and the acquisition controller exit 0.

The AMD64 initial record retains `PEB+0x338 -> PEB+0x7d8`, with the same 32
bytes, private read/write protection and zero later-initialization fields.
The ARM64 and x86 control fields remain zero. Selectors, FS base, descriptor
instructions and XSTATE configuration agree with the retained 29704 profile.
The eight native descriptor queries still return `STATUS_NOT_IMPLEMENTED`;
hidden bases in the suspended child and raw GDT bytes remain unknown.

The unchanged active-context fixture separately completes four worker context
cycles and 78 assertions in each of ARM64, x64 compatibility and x86 processes:
12 cycles, 234 assertions and three InitOnce callbacks in total. All three
compilers, producers and their controller exit 0. These are native controls;
installed emulation and complete-binary qualification remain separate gates.

| Archive | Bytes | SHA-256 | Payloads |
|---|---:|---|---:|
| `chpe-startup-native-29708-v1.zip` | 9274135 | `9d50c165bb219c96da20042bc1850c8f7d0591b2a9a4ad620a9f0254bf809a52` | 54 |
| `chpe-active-native-29708-v1.zip` | 9086852 | `2f6783a05860f4175217f8c5616b3f42158c7cebd5195f8186be8961d11ecfa2` | 50 |

Verify the public projection and inputs, or supply both retained private archives:

```text
python3 -I -B docs/specifications/windows/native-chpe-creation/check-29708.py
python3 -I -B docs/specifications/windows/native-chpe-creation/check-29708.py path/to/chpe-startup-native-29708-v1.zip path/to/chpe-active-native-29708-v1.zip
```

On Windows use `python`. No-argument verification does not check the raw archives.
Archive verification checks all payloads, source/image/provider bindings, native
PID and creation identities, actual terminal statuses, original stdout and exact
projection. It runs under Python optimization too. Pure historical validators
are reused with only their expected kernel literals changed to 29708; the
executed producers and historical archives are unchanged. For compressed bytes
B and uncompressed payload bytes U, verification takes O(B + U) time and space.

Admission adds exactly 29708 with native machine `0xaa64`. Adjacent builds,
foreign machines, reported-version spoofing, pre-existing storage, memory
faults, main/child contexts and cloned carriers retain explicit regression
coverage. The 32-byte record ends at offset `0x7f8`, below the existing
`0x1000`-byte guest PEB page; no guest allocation geometry is inferred from a
captured host address. These observations do not qualify an AMD64 Windows
kernel, later CHPE work-list initialization, or unrelated native services.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| CH08-A1 | Exact 29708 ARM64 AMD64 startup retains the measured initial record, selectors and XSTATE. | Fresh source-bound native creation/segment/XSTATE controls and four natural child exits. | Exact kernel admission and saved initial context. | Adjacent identity, spoofing, mutation and memory faults. | A new native projection or installed leaf differs. | Native observations confirmed; model qualification is separate. |
| CH08-A2 | Native RTL context ownership applies on exact 29708. | Fresh unchanged active-context fixture: 234 assertions in three process ABIs. | Selected main/child CHPE context owner. | Partial saves, quantum boundaries, explicit context transfers, replaced allocations and clones. | Ownership replay or installed active-context execution fails. | Native controls confirmed; model qualification is separate. |

High-impact remaining scope includes complete installed-library process startup
and unmeasured native service profiles. Neither blocks retaining these bounded
native observations; both remain required for the full process-emulation goal.
