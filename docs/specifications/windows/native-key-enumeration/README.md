# Native key enumeration controls

This directory records independently produced Windows `NtEnumerateKey` results.
The runtime implements class 0 (`KeyBasicInformation`) over immutable selected
metadata. Classes 1 and 2 are valid native selectors whose payloads remain
explicitly unsupported. Other tested selectors return `STATUS_INVALID_PARAMETER`.

The interface and fixed layout are described by Microsoft:

- [ZwEnumerateKey / user-mode NtEnumerateKey](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey)
- [KEY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_basic_information)

The native controls own no guest process and perform no registry writes. Fixed
MACHINE, Command Processor and KnownPackageManagers paths select metadata.
A MACHINE enumeration captures immediate child names and times, not arbitrary
HKLM descendant bodies. The fault campaign uses MACHINE so it also runs on
hosts where the optional Command Processor descendants are absent.

## Reproduce and verify

From the repository root, on any supported host:

```text
python tools/ci/windows_key_enumeration.py --verify-corpus
```

Expected retained dimensions are 14,616 basic rows and 17,028 fault/rights rows
from three process ABIs. The portable service replay executes all 14,580
class-0/invalid-selector rows and all 17,028 fault/rights rows. The 36 valid
class-1/class-2 records remain retained evidence of native selector admission;
their payloads are outside this implementation.

On native Windows with MSVC and CMake installed:

```text
python tools/ci/windows_key_enumeration.py
```

The runner detects the kernel architecture with `IsWow64Process2`, builds x64
and x86 probes, and also builds ARM64 probes on an ARM64 kernel. Each PE machine,
process pointer width, source hash, executable hash and terminal handle count is
checked. All build trees and temporary outputs stay inside the checkout.
Successful compilation alone is insufficient: the executables must run, their
native reports must validate, and the guest replay must pass.

The runner retains configure/build logs, raw JSON, stderr and a compact
`observations.json` below `target/native-key-enumeration-v1`. It passes that
corpus through `RAX_KEY_ENUMERATION_CORPUS` to the service tests. Its final JSON
identifies the corpus hash and executed process ABI count. The CI job uploads
this directory even on failure. Preserve an existing output directory before
choosing another `--output`; the runner refuses to overwrite it.

The portable retained gate is:

```text
cargo test --locked --no-default-features --lib registry_tests::key_enumeration:: -- --test-threads=1 --nocapture
```

Without an explicit fresh corpus, that gate reports zero fresh rows and still
runs the complete retained matrix. Installed acquisition has a separate native
Windows test: independent NT reads bracket the runtime snapshot, then compare
ordered names and FILETIMEs for MACHINE and both Command Processor views.
Changing native inputs cause a bounded retry and ultimately a failure, never a
successful skip.

## Recorded behavior

A class-0 record has a 16-byte prefix: 8-byte FILETIME, reserved 4-byte
`TitleIndex`, and full 4-byte name length. Name length is in bytes; names are
UTF-16 without a terminator. FILETIME counts 100 ns intervals since
1601-01-01 UTC. The complete required size is `16 + 2 * name_units` bytes.
A capacity below 16 bytes returns `STATUS_BUFFER_TOO_SMALL`; a partial name
returns `STATUS_BUFFER_OVERFLOW`. A partial odd final byte is zero after
whole-WCHAR copying; the full `NameLength` and required size remain unchanged.
Output tail bytes beyond the copied record remain as supplied.

Invalid selectors bypass both native entry probing and WoW64 conversion.
Native entry then validates handle type and rights
before probing destinations. It then checks nonempty output alignment and
writable extent, followed by the mandatory byte-aligned `ResultLength`
destination, before enumeration. Enumeration requires `KEY_ENUMERATE_SUB_KEYS`. End of enumeration
returns `STATUS_NO_MORE_ENTRIES` without publishing a sizing result.

After valid-selector admission, the measured WoW64 entry realigns an output
address not divisible by 8. Its zero-length conversion returns
`STATUS_NO_MEMORY` before destination or handle checks. For a nonzero length it first copies the caller's entire
buffer into aligned storage and copies that capacity back after native status
failures too. `ResultLength` can therefore be published before a failing output
copy, and an aliased sizing result can be overwritten by copy-back. Guard-page
consumption and partial stores are checked separately from returned status.
No caller-visible exception occurred in the retained extended fault matrix.

The basic probe guarantees and verifies a 16-byte-aligned buffer and records
the actual low three bits of both pointers in every row. An earlier x86
stack-buffer experiment omitted that observation; its offsets did not identify
physical alignment. That earlier experiment is not used as the final alignment
oracle.

## Evidence and boundaries

`probe-v1.c` and `fault-v1.c` produced the retained ARM64, x64 and x86 reports on
Windows build 29695 with an ARM64 kernel. These are three real process ABIs on
one kernel architecture; native AMD64 kernel behavior requires the fresh CI
campaign. The acquisition controller used MSVC C11, `/O1`, `/W4`, `/WX` and the
static CRT. CI independently builds the same source through Release CMake.

`controls-v1.json` contains source and image hashes, process widths, terminal
handle counts, ordered metadata and indexed case matrices. Equal datasets are
shared only after their complete normalized contents compare identically.
Rows reference deduplicated output records. Buffer prefixes padded with A5
restore every observed 384-byte output monitor; result prefixes padded with CC
restore every observed 32-byte sizing monitor. The projection checks this
round trip for every raw record. Original report hashes identify the archived
native captures; the compact JSON does not reproduce original JSON whitespace.

Portable replay projects each measured parent's metadata into an ordinary owned
fixture key. That isolates encoding, probing and handle rights without
inventing unmeasured descendant bodies. Installed acquisition and actual
installed-program execution qualify path selection separately. Passing this
matrix does not establish completion of CMD, all NT registry services, arbitrary
HKLM traversal, writable registry semantics or every kernel revision.

## Assumption register

| ID | Assumption | Basis and dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- | --- |
| ENUM1 | Captured native index order and per-child FILETIME define class-0 output at snapshot time. | Independently produced NT output and Win32 metadata; immutable ordered child records. | Different views, reordered names and changing timestamps; compare raw native payload with independent metadata. | Retained for stable acquisition; no atomic whole-registry snapshot claim. |
| ENUM2 | Copy behavior is qualified by the observed kernel profile. | ARM64-kernel captures and separate AMD64 CI capture; WoW64 copy adapter. | Native AMD64 source-identical replay; a differing status, byte or guard effect falsifies parity. | Retained until the fresh host gate passes. |
| ENUM3 | A partial output is simply the full record's byte prefix. | Initial implementation assumption. | Odd capacities 17, 19, 23 and 25 bytes; native trailing byte differs. | Falsified; the encoder zeros the partial half-WCHAR byte. |
| ENUM4 | A stack union's requested alignment identifies physical pointer alignment on every ABI. | Initial basic-probe assumption. | x86 zero-length conversions and explicitly reported pointer bits. | Falsified; final producer checks alignment and reports pointer bits. |
| ENUM5 | Neighboring key-query entry order can be reused for enumeration. | Initial implementation inference. | Invalid selectors and denied/wrong-type handles combined with bad destinations; compare untouched guards and statuses. | Falsified; enumeration admits selectors and resolves handle rights before native probes, and invalid selectors bypass WoW64 conversion entirely. |
