# Native SystemPolicyInformation

Class 134 carries a descriptor with nested request and reply buffers. The virtual
service implements QueryPolicy0 over an immutable catalog captured during
explicit installed-Windows-runtime selection. Guest policy names, commands,
pointers, and lengths do not reach a host operation.

The selected native kernel is Windows 10.0.29698.1000 on ARM64. Measurements
include ARM64, x64, and x86 processes on that kernel. Physical x86 kernel behavior
and other Windows builds have not been independently measured by these probes.
Runtime selection checks a fixed size-only QueryPolicy0 request against the
captured catalog before admitting this protocol.

## Descriptor and copy behavior

| Property | ARM64 and x64 | x86 through WoW64 |
|---|---|---|
| Descriptor fields | Two 8-byte pointers, three ULONGs, four padding bytes | Two 4-byte pointers and three ULONGs |
| Supplied outer length | Exactly 32 bytes | Ignored by the measured wrapper |
| Outer alignment | Four bytes when supplied length is nonzero | Unaligned fields accepted |
| Version | Ignored | Ignored |
| ReturnLength | Optional ULONG; value 32 | Optional ULONG; value 32 |
| Nested output-size copy-back | Updated after a successful nested copy, including a null-output size query | Original descriptor unchanged |
| Probe order | Outer writable span and ReturnLength before dispatch | Capture descriptor, probe ReturnLength, execute converted native request |

Null nested input or zero input length returns STATUS_BUFFER_TOO_SMALL. Nested
buffer faults retain reached guard and copy effects before the outer ULONG
ReturnLength store. A reply copy can retain complete preceding pages when a
later page faults. Padding and unrelated descriptor fields remain unchanged.

The independent pointer probe records every changed byte in its complete
32,768-byte arena and all eight final page protections. Its size-only request
produces a 244-byte reply without undefined block-alignment padding.

## Protocol and catalog

The outer message has three ULONG-length-prefixed blocks: encrypted parameters
with an eight-byte checksum, a 160-byte round descriptor, and an eight-byte key.
Blocks contain big-endian 32-bit words. Arithmetic wraps modulo 2^32. The
descriptor selects 32 variable rounds; request and reply directions each add
eleven fixed rounds. Descriptor selectors 31 through 255 disable a round.
The checksum stores the XOR of plaintext bytes as an eight-byte little-endian
integer. It is a compatibility checksum, not a cryptographic authentication tag.

QueryPolicy0 carries a response descriptor/key, nonce, terminated UTF-16 name,
query flags, and requested data capacity. Names compare as exact UTF-16 units.
Replies preserve the nonce, native value type, required size, and query result.
Data capacity zero returns metadata; insufficient nonzero capacity returns
zero-initialized data with STATUS_BUFFER_TOO_SMALL in the reply result field.
The wire result field is the status OR 0x10000000, giving 0xD0000023 for this
short-buffer result and 0x10000000 for success.
Unknown names retain the native not-found status. Other policy commands stop
explicitly as unsupported operations.

ProductPolicy supplies names rather than authoritative values. Of 662 names in
the observed registry blob, Kernel-ExpirationDate returned different native
bytes, and Security-SPP-AzureImdsResponse returned STATUS_NO_MATCH. The selected
kernel declares fourteen additional callback names, nine absent from the blob.
The adapter captures native query results for their union. Successful data and
types must agree across initialized-buffer captures. Native errors remain
catalog entries. The adapter closes all host HKEYs before guest execution.
The virtual catalog has no external policy-cache updater.

Limits are 2,097,152 request bytes, 8,388,608 source-catalog bytes, 4,096 selected
names, 1,048,576 bytes per captured value, and 16,777,216 aggregate name/data
bytes. Parsing and encoding take O(P+R) time and temporary space for request
size P and reply size R. Lookup adds O(L log N) comparison work for name length
L and N catalog entries. Catalog parsing takes O(B+L_total log N) work and
O(B+V+L_total) peak storage, excluding allocator and map overhead, for source
size B, captured value bytes V, and total name units L_total.

## Independent reproduction

Build inside this checkout from a Windows developer environment with CMake,
Python 3, and the chosen MSVC target toolchain:

```text
cmake -S docs/specifications/windows/native-system-policy -B target/native-system-policy-probes -A ARM64
cmake --build target/native-system-policy-probes --config Release
target\native-system-policy-probes\Release\native-system-policy-abi.exe
target\native-system-policy-probes\Release\native-system-policy-pointer.exe
```

Use separate in-checkout build directories and `-A x64` or `-A Win32` for the
other process ABIs. The cipher-input and cipher-response targets reconstruct
the exact original independently compiled source from templates and fixed
request bytes. The response collector also emits host catalog observations;
retain those reports locally. Microsoft images, symbols, and machine-specific
catalog snapshots are excluded from the published corpus.

Run `python docs/specifications/windows/native-system-policy/verify.py` to check
corpus membership, raw hashes, and exact generated-source reconstruction.

The owning tests replay 1,350 scalar ABI cases, 2,496 complete arena cases, and
296 cipher/query controls. The cipher corpus retains exact defined encrypted
prefixes and complete semantic fields. Its native alignment tail is excluded
from the oracle; virtual replies initialize that tail to zero.

## Assumption register

| ID | Assumption and dependent result | Evidence and falsification probe | Status |
|---|---|---|---|
| P1 | The recorded descriptor and WoW64 ordering describe the selected native runtime. | Three-ABI scalar and complete-arena probes; rerun on another kernel and compare lengths, guards, aliases, and every byte change. | Confirmed for the measured kernel |
| P2 | Native acquisition remains a fixed host-input boundary. | Fixed HKLM selection, fixed callback-name list, host-owned buffers, immutable records, and a fixed qualification request; a guest-selected host operation or retained HKEY would falsify it. | Retained and enforced by the acquisition interface |
| P3 | The recovered arithmetic represents both protocol directions. | Exact captured request recovery, all31selectors with four key profiles, disabled selectors, native checksums/nonces, and golden encrypted prefixes; any fresh mismatch rejects qualification. | Confirmed for measured controls |
| P4 | Raw registry policy bytes can substitute for native query results. | Two observed counterexamples above; paired native captures are used instead. | Falsified |
| P5 | A selected snapshot is stable during capture. | Paired defined-data/type reads and source-blob recheck; changing or undefined results must exhaust the bounded attempts and report unavailable. | Checked during every selection |

## Bounded scope

High: complete native application startup remains a separate full-goal gate;
supporting this query does not prove that every later NT service is implemented.
Other policy commands and external licensing-service update workflows remain
explicitly unsupported. Medium: the vendored vm-memory Windows ARM64 calling-
convention warning is pre-existing and outside this changeset.

The public API entry is documented by
[Microsoft](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
The private descriptor also appears in the repository's pinned PHNT header at
`../native-wnf-query/primary/phnt-ntexapi.h`. The owning native bindings and probe
source hashes are recorded beside this document.
