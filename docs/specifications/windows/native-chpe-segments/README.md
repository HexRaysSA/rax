# Initial AMD64 segment state on ARM64 Windows build 29704

The independent native controller in `segments-v1.cpp` and `segments-v1.S`
records a normal AMD64 process and an unchanged, CRT-free AMD64 child on native
ARM64 Windows kernel 10.0.29704. The child is created with `CREATE_SUSPENDED`,
queried before its first user instruction, resumed exactly once, and waited to
natural exit code zero. No debugger or thread-context modification is used.

`GetThreadContext` observes CS/SS/DS/ES/FS/GS as
`0x33/0x2B/0x2B/0x2B/0x53/0x2B`. Direct segment-register reads in the controller
independently observe the same selectors after CRT startup. `RDFSBASE` returns
zero. `LAR`/`LSL` observe FS access rights `0x0040F300` and limit `0xFFF`, a
4,096-byte, writable, present, DPL 3, byte-granular, 32-bit data segment.
These descriptor/base instructions run after CRT startup; the capture does not
claim to query the suspended child's hidden segment bases or raw GDT bytes.

All eight `NtQueryInformationThread(ThreadDescriptorTableEntry)` calls return
`STATUS_NOT_IMPLEMENTED` (`0xC0000002`), leaving their poisoned descriptor
buffers unchanged. The public profile preserves this unavailable result.
`RtlCaptureContext` returns flags `0x0010000B` and zero segment fields in the
controller; those fields do not establish the live selectors. The direct
instruction reads supply that observation. The initial child context also
returns flags `0x0010000B`; its populated selector fields agree with the direct
reads.

The finite profile applies to an AMD64 guest with native ARM64 identity and
kernel 10.0.29704. Initialization must precede the saved loader context and
the CHPE shared context. The synthetic guest descriptor uses the observed FS
access rights and limit with base zero; GS uses the existing guest TEB base.
No captured host address or native handle enters guest state. Later CONTEXT
selector changes retain the existing validation rules.

The private eight-payload archive binds producer source, assembly, image,
build commands, original child image, native binding, callback and stdout.
The callback records unchanged SHA-256 identities for eight installed DLLs.
Verify the archive with:

```console
python3 docs/specifications/windows/native-chpe-segments/verify-v1.py <archive.zip>
```

The verifier checks every archive member, public-source identity, producer and
child completion, literal selector/base/descriptor observations, and exact
projection into `profile-29704-v1.json`. It also works with Python optimization
enabled. Failed native descriptor queries remain explicit unknowns.

## Independent build 29708 qualification

The unchanged `segments-v1.cpp` and `segments-v1.S` producer was rebuilt and run
on ARM64 kernel 10.0.29708 against the unchanged committed AMD64 smoke child.
The compiler, controller and naturally resumed child exit 0. Initial and live
selectors, FS base and all four LAR/LSL observations agree with 29704; the eight
native descriptor queries remain unavailable with `STATUS_NOT_IMPLEMENTED`.
The combined [29708 profile](../native-chpe-creation/profile-29708-v1.json)
retains the original raw-output identity, executed images, source and physical
provider bindings. Its [portable checker](../native-chpe-creation/check-29708.py)
verifies the separate 54-payload startup archive and 50-payload context archive.

The finite selector profile now admits exactly 29704 and 29708 with native ARM64
identity. Main and child loader-context replays consume both observations.
This does not establish raw descriptor bytes or suspended hidden bases; GS
continues to use the guest-owned TEB. An independent AMD64 kernel is unmeasured.
