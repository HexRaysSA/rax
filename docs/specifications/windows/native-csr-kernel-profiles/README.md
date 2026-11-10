# Measured CSR kernel profiles

The selected ARM64 CSR path admits Windows 10.0 builds 29683,
29695, 29698 and 29704. It retains the existing section, metadata, pointer, packet and ownership
checks. Other architectures and unmeasured builds are not admitted by this
profile. Each session retains its captured metadata and namespace identity. This is a CSR qualification, not complete installed-library startup.

## Build 29704 and the current session

`profile-29704-v1.json` retains fourteen fresh native observations on kernel
10.0.29704, session 1: two metadata producers, SharedSection geometry and USER
acquisition for each of ARM64, AMD64 compatibility and x86 compatibility,
plus native ARM64 secure-connection and USER-exchange observers. Three
additional provider observers run before and after those fourteen controls.
ARM64 and AMD64 compatibility map `System32/ntdll.dll`; x86 compatibility
maps `SyChpe32/ntdll.dll`. The physical provider paths, SHA-256 values and
export bytes agree before and after the complete sequence. A logical
System32 path is not substituted for the x86 provider identity.

The measured secure connection uses `\Sessions\1\Windows\ApiPort`, with
the same 48-byte client view, 24-byte zeroed server view, 48-byte connection
information and 952-byte maximum message. Its server base, statics offset
`0x750` and PID agree with independently captured process metadata. The USER
exchange retains flags `0x20000`, an 88-byte envelope, 48 data bytes and a
628-byte capture containing 584 zero input bytes and one pointer field at
offset 72. The readonly section is 1,048,576 bytes, with 20,480 committed
bytes and a 1,028,096-byte reserved tail. All three callers observe identical
committed section bytes. The current USER handle table has a 32,768-byte
committed prefix in its existing 2,097,152-byte allocation; the separately
selected shared-data allocation remains 32,768 bytes. Session growth changes
the committed prefix, not the allocation or pointer-validation contract.

Six original sources remain unchanged. The seven files in
`captured-29704-v1/` preserve the separately identified executed inputs:
four x86 printing-type corrections, two protocol observers with deadline
termination removed and debugger kill-on-exit disabled, and the new readonly
physical-provider observer. Native calls, capture bounds and success
assertions are unchanged in the derived protocol observers. Their owned
children exit naturally with the original result 41. These captured producer
inputs retain their exact bytes and hashes.

The canonical observation archive additionally retains exact compiler/linker
commands and identities, original strict-warning failures, all seventeen
native executable identities, twenty raw stdout streams, and the source
inputs. Its name, byte count and SHA-256 are recorded in the projection.
Regenerate the complete 29704 projection with the portable standard-library
verifier and compare its output bytes with `profile-29704-v1.json`:

```sh
python3 -I -B docs/specifications/windows/native-csr-kernel-profiles/project-29704-v1.py \
  path/to/csr-29704-native-artifacts-v2.zip > profile-29704-rebuilt.json
```

The archive has 1232328 bytes and SHA-256
`6d6866212ccec57a522c94fc272d39394e7f82df11c18a8eef19d92c4f179956`.
The verifier checks all fourteen controls and six provider observations,
original and captured producer identities, PE machines, allocation geometry,
protocol fields and compiler/linker receipt coverage.

The metadata regression was first run against the preceding build predicate:
the genuine 29704/session 1 data failed constructor selection. The amended
predicate admits exactly 29704, with adjacent builds, foreign architectures
and changed native identities covered by refusal cases. Existing secure and
USER dispatch matrices additionally exercise the fourth measured build.

This amendment does not admit the independently gated WoW64 BASE bridge,
BASE NLS reply, NLS initialization or any other unmeasured service profile.
Native observations do not establish successful emulated process startup.
The subsequent NLS qualification and the current startup-fixture result are
recorded in [the build-29704 NLS profile](../native-nls-build-29704/README.md).

Windows upgraded to 29695 during validation. The unchanged original fault
fixture then stopped at NtSecureConnectPort because no selected server profile
was available. The additional build is supported by rerunning frozen controls,
not by extending a version interval or inferring compatibility from the name.
The same failure recurred after the installed kernel advanced to 29698. Frozen
controls were compiled and executed again before admitting that exact build.

## Native evidence

`profile-29695-v1.json` records the actual kernel, compiler/executable/source
identities, before/after input checks and typed projections. Full stdout is
retained in the task archive. Six metadata observations span ARM64, x64
compatibility and x86 compatibility on an ARM64 kernel. These compatibility
observations do not establish physical AMD64-kernel support.

| Contract | Build 29695 observation |
|---|---|
| Own-process CSR metadata | Major 10, minor 0, session 0; PEB statics offset 0x750; independent prefix/server-base correlation |
| Native PID getter | Two independent producers retain identical code bytes; bounded ARM64 load/select/return, pointer-width result 876 |
| SharedSection allocation | 1048576 bytes: 20480 committed readonly MEM_MAPPED bytes, then 1028096 reserved bytes; all three views agree |
| Client USER allocations | 2097152-byte table with 8192 committed bytes after reboot; second 32768-byte view fully committed readonly |
| Secure connection | 48-byte client view, 24-byte server view, 65536-byte pagefile backing; exact System SID/QoS and 48-byte information packet |
| Secure reply | Maximum message 952 bytes, matching captured server base/statics/PID, final 16 information bytes preserved, 24 server-view bytes zero |
| USER request | 88-byte envelope, 48-byte data portion, index 3, 584 information bytes, flags 0x20000, no attribute or timeout inputs |
| USER capture | Length 628, pointer count 1, information at capture+40, pointer-field offset 72, 584 zero input bytes |
| Native child outcomes | Secure-only child exits 41 after one successful call; exchange child exits 41 after secure and USER calls |

`profile-29698-v1.json` retains six fresh metadata observations, three complete
SharedSection geometry observations, three USER acquisition observations and
two ARM64 protocol observations. Fourteen executable identities and all six
unchanged C++ source hashes bind these observations. The 29698 invariants in
the table are unchanged, except that the captured server PID is 660. PID and
server addresses are native identities, not constants for the modeled server.
The two ARM64 getter captures agree on all 64 bytes. Independent LLVM
disassembly of its first seven instructions confirms byte-flag and
pointer-width loads, comparison, conditional selection and return. Address
immediates differ from the prior kernel; the no-argument ABI is unchanged.

The canonical 29698 archive is `csr-29698-native-artifacts-v2.zip`, 6339530
bytes, SHA-256
`bc92d53251b7de3a9173b016726b8ad229f3846a7d3ff53e8bfd9e0ee45af294`.
It binds ARM64 and x64 compatibility to the actual `System32/ntdll.dll` and
x86 compatibility to `SyChpe32/ntdll.dll`, with before/after identities and
hashes. The first archive's x86 bookkeeping hashed the logical `System32`
path from native Python. The corrected repeat supersedes that provider binding
and re-executes all fourteen unchanged observers.

Regenerate and verify the typed projection from the retained archive:

```sh
python3 -I -B docs/specifications/windows/native-csr-kernel-profiles/project-profile-v1.py \
  path/to/csr-29698-native-artifacts-v2.zip profile-29698-rebuilt.json \
  --archive-sha256 bc92d53251b7de3a9173b016726b8ad229f3846a7d3ff53e8bfd9e0ee45af294
```

The result reports six metadata samples and fourteen native images. Compare
the output bytes with the checked-in `profile-29698-v1.json`. The projector
checks every archive payload hash, source and executable identity, PE machine,
raw stdout identity, actual provider binding, getter instruction pattern,
section geometry and typed connection/exchange fields before writing output.
It normalizes CRLF only after checking the raw stdout hash. This command needs
the separately retained archive; the projection alone cannot reconstruct the
original binaries or stdout.

The capture allocation arithmetic is `40 + 584 = 624` bytes of header and
information, plus 4 allocation-padding bytes: `624 + 4 = 628`. Padding is outside
the information input and is not required to be zero. Native allocator fill in
reserved header/padding fields is retained as evidence, not interpreted as a
new service input. Model server addresses, message identifiers and thread
identity belong to the modeled server; whole native-reply byte equality is not
claimed.

The unchanged primary producers are:

- `../native-csr-connect-model/native-csr-readonly-metadata.cpp` and
  `native-csr-readonly-metadata2.cpp` in that directory;
- `../native-csr-connect-model/native-secure-connect-first-call2.cpp`;
- `../native-alpc-csr/native/native-alpc-csr-trace-v1.cpp` and
  `native-csr-client-connect-v6.cpp` in that directory;
- `../native-shared-section/native-windows-shared-section-geometry.cpp`.

Compile each in its matching MSVC environment with C++20, static CRT, EHsc,
UTF-8 and W4/WX. For example, in a matching Native Tools command prompt, create
an in-tree output directory and compile from that directory:

```bat
cl /nologo /std:c++20 /MT /Od /EHsc /utf-8 /W4 /WX path\to\native-csr-readonly-metadata.cpp /Fe:metadata1.exe /Fo:metadata1.obj
metadata1.exe > metadata1.log
```

Repeat for ARM64, x64 and x86 using both metadata sources, the section source
and `native-csr-client-connect-v6.cpp`; pass the architecture label to the
client executable. Compile the secure and exchange debugger controls for
native ARM64. The archive also retains the exact CMake source and compiler
commands. The frozen debugger controls additionally suppress only
C4100/C4456/C4505 for their existing architecture-unused/shadowed declarations.
The initial strict-warning compile failure is retained. No producer source,
original fault fixture, assertion or deadline was edited. All binaries and
compiler inputs are hashed before and after execution. The metadata controls
read only their own process; debugger controls instrument only owned children.
The fixed native observer child exit 41 is distinct from emulator completion.

[The pinned PHNT PEB definitions](https://raw.githubusercontent.com/winsiderss/phnt/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntpebteb.h)
name the CSR-related fields. Runtime offsets and export ABI are bound by the
native observations, rather than treated as a public SDK layout guarantee.

## Implementation and verification

`csr::supports_kernel` owns the finite build set for installed metadata capture,
NtSecureConnectPort and the typed NtAlpcSendWaitReceivePort USER exchange.
Major/minor checks are shared. Machine, session, full readonly allocation,
stable bytes, typed pointer identities, packet schema, selected handles,
nonoverlapping outputs, transactional publication and endpoint lifetime retain
their previous checks. No guest-directed host operation or capability is added.
The version check is O(1), with no additional retained runtime storage.

The successful secure connection test now runs all four ARM64 builds with
matching selected metadata and guest configuration. The previous test helper
reset the guest build to 29683 after the caller selected another build; the
new helper takes the build explicitly and asserts the selected metadata.
The USER test runs all four builds against four existing native payload
fixtures and four repeated exchanges per fixture: `4 * 4 * 4 = 64` exchanges.
Those payload fixtures retain their original kernel/source identities. A
separate constructor regression consumes the actual 29698 prefix, metadata
and allocation geometry; unused view bytes are zero padding, not a claim of
whole-view replay. Adjacent-build, major/minor and
unknown-build refusals preserve output bytes, handle counts, commitment and RNG
state. The existing installed ARM64 test exercises the measured native profile;
unmeasured builds retain the unavailable-path assertion. The existing CI step
runs the `csr` filter, without adding a job.

Historical 29695 qualification: macOS and Linux each passed 85 selected tests and 191 C API tests, with no failures
or ignores. Their shared-runtime frame is unchanged by the final Windows-only
installed-test update. Windows passes all 86 selected tests, including the actual installed-native
connection, all 39 object-namespace tests and all 191 C API tests. Its final source frame adds only
the Windows-only installed-test update after the Unix runs. The unchanged
original fault fixture now passes CSR startup and stops at
`NtInitializeNlsFiles native build profile is unmeasured`; complete startup is
not established. Combined macOS/Windows trees retain the
separate native-entry draft; that draft was excluded from that changeset.
These historical counts do not qualify the 29698 amendment. The current
installed CLI passed the CSR boundary on 29698 and stopped at the independent
`NtInitializeNlsFiles native build profile is unmeasured` boundary. Full
cross-platform qualification of the amended source is recorded separately.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| KP1 | The 29695 selected CSR layout matches the existing ARM64/session 0 contract. | Frozen native metadata, full allocations and natural protocol observations. | Add 29695 to the finite build set. | Full section extent, two client views, exact packet widths and pointer identities. | Any observed protection, extent, schema or identity mismatch. | Confirmed for recorded native inputs; model/native validation retained separately. |
| KP2 | The 29695 getter retains the measured pointer-width, no-argument ABI. | Two independently compiled observers, identical export bytes and decoded load/select/return. | Reuse fixed readonly native getter. | Compare code, PID, PEB version/session and selected prefix. | Export ABI or identity correlation differs. | Confirmed on the measured ARM64 kernel. |
| KP3 | The 29698 ARM64/session 0 layout retains the selected CSR contract. | Fresh frozen metadata, allocation, acquisition and natural protocol controls with corrected physical provider bindings. | Add exactly 29698. | Full section geometry, pointer identities, packet widths, readonly acquisitions and actual getter bytes. | Any captured geometry, protection, ABI, status or identity mismatch. | Confirmed for the fourteen recorded native observations; shared and installed-runtime validation remain distinct. |

High-impact outstanding scope: other ARM64 sessions, generic CSR families and
complete Windows startup remain unqualified. Physical AMD64 kernels have a
separate finite 20348/26100 profile in `csr::supports_profile`; the ARM64
compatibility observations here do not establish AMD64 build 29698 support.
Other NT contracts need independent qualification where reached on 29698.
[NLS initialization and query-only MUI](../native-nls-build-29695/README.md)
have their own measured qualification and predicate. The CSR predicate does
not substitute versions into those contracts. The full Linux/macOS/Windows
installed-library objective remains active.
