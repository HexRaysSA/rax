# Measured CSR kernel profiles

The selected ARM64/session 0 CSR path admits Windows 10.0 builds 29683 and
29695. It retains the existing section, metadata, pointer, packet and ownership
checks. Other architectures, sessions and builds are not admitted by this
profile. This is a CSR qualification, not complete installed-library startup.

Windows upgraded to 29695 during validation. The unchanged original fault
fixture then stopped at NtSecureConnectPort because no selected server profile
was available. The additional build is supported by rerunning frozen controls,
not by extending a version interval or inferring compatibility from the name.

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
UTF-8 and W4/WX. The frozen debugger controls additionally suppress only
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

The successful secure connection test now runs both builds. The USER test runs
both builds against four existing native payload fixtures and four repeated
exchanges per fixture: `2 * 4 * 4 = 32` exchanges. Those payload fixtures retain
their original kernel/source identities. New adjacent-build, major/minor and
unknown-build refusals preserve output bytes, handle counts, commitment and RNG
state. The existing installed ARM64 test exercises the measured native profile;
unmeasured builds retain the unavailable-path assertion. The existing CI step
runs the `csr` filter, without adding a job.

macOS and Linux each pass 85 selected tests and 191 C API tests, with no failures
or ignores. Their shared-runtime frame is unchanged by the final Windows-only
installed-test update. Windows passes all 86 selected tests, including the actual installed-native
connection, all 39 object-namespace tests and all 191 C API tests. Its final source frame adds only
the Windows-only installed-test update after the Unix runs. The unchanged
original fault fixture now passes CSR startup and stops at
`NtInitializeNlsFiles native build profile is unmeasured`; complete startup is
not established. Combined macOS/Windows trees retain the
separate native-entry draft; that draft is excluded from this changeset.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| KP1 | The 29695 selected CSR layout matches the existing ARM64/session 0 contract. | Frozen native metadata, full allocations and natural protocol observations. | Add 29695 to the finite build set. | Full section extent, two client views, exact packet widths and pointer identities. | Any observed protection, extent, schema or identity mismatch. | Confirmed for recorded native inputs; model/native validation retained separately. |
| KP2 | The 29695 getter retains the measured pointer-width, no-argument ABI. | Two independently compiled observers, identical export bytes and decoded load/select/return. | Reuse fixed readonly native getter. | Compare code, PID, PEB version/session and selected prefix. | Export ABI or identity correlation differs. | Confirmed on the measured ARM64 kernel. |

High-impact outstanding scope: physical AMD64 CSR admission, other sessions,
generic CSR families and complete Windows startup remain unqualified. Other
NT contracts need independent qualification where reached on 29695.
[NLS initialization and query-only MUI](../native-nls-build-29695/README.md)
have their own measured qualification and predicate. The CSR predicate does
not substitute versions into those contracts. The full Linux/macOS/Windows
installed-library objective remains active.
