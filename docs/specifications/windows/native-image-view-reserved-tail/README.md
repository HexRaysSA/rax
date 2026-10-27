# Native image bytes and reserved owner tails

Installed pure x86 Kernel32 on ARM64 Windows `10.0.29695` has a logical
image/view size of `0xF0000` bytes. Its final `VirtualQuery` region starts at
offset `0xE5000` and reports `0xF000` reserved bytes with the same allocation
base and `MEM_IMAGE` type. The old capture required that entire run to fit
inside the logical view and stopped the unchanged x86 startup fixture with
`selected native image region exceeds its view`.

The bounded copy span is `0xF0000 - 0xE5000 = 0xB000 = 45056` bytes.
The reserved allocation continues to `0xE5000 + 0xF000 = 0xF4000`, leaving
`0x4000 = 16384` reserved bytes outside the logical image. The logical image
is 983040 bytes; the complete owner is 999424 bytes. No padding bytes are read,
committed or copied.

## Captured native contract

The [probe-v3.cpp](probe-v3.cpp) control executes real native APIs in three
separately compiled MSVC executable profiles: ARM64, x64 compatibility and x86
compatibility, all on the recorded ARM64 kernel. It maps three images from
each of `\KnownDlls`, `\KnownDlls32` and `\KnownDllsChpe32`, using three
machine selectors, two rebase flags, three requested sizes and two unmap
targets: `9 * 3 * 2 * 3 * 2 = 324` cases per profile, or 972 cases total.
There are 216 successful views per profile, or 648 total; all three programs
exit 0. Unsupported machine projections remain recorded failures.

| Full image family | Executable extension bytes | Final reserved padding | Additional owner extent | Native class-6 flags |
| --- | ---: | ---: | ---: | --- |
| KnownDlls, ARM64 caller | `0x1000` | `0x3000` | `0x4000` | `0x70` |
| KnownDlls, x64 caller | `0x2000` | `0x2000` | `0x4000` | `0x70` |
| KnownDlls32, native64 callers | 0 | `0x4000` | `0x4000` | `0x70` |
| KnownDllsChpe32 | 0 | 0 | 0 | `0x30` |
| Partial 4096-byte views | 0 | 0 | 0 | `0x31` |

The x86 WoW64 wrapper returns `STATUS_INVALID_INFO_CLASS` for class 14;
this limitation is captured explicitly rather than interpreted as evidence
that executable extensions do not exist. Native64 callers expose the class-14
records used by installed runtime acquisition. `ImageExtensionPresent` is
independent of whether those records contain executable bytes: pure x86
reserved-only tails still set bit `0x40`.

Class-6 queries at the header, last logical byte and last owner byte retain
the same image base, declared image size and relevant flags. Successful unmap
through the reserved tail releases the complete view. Partial views have no
tail. Both implicit and explicit full lengths, original/rebase flags and
default/explicit x86 selectors agree. The original failing reserved run is
observed in 16 cases per profile, or 48 total.

The raw captured logs preserve CRLF bytes and are bound to source, executable,
compiler and stdout SHA-256 identities in [native-inputs.json](native-inputs.json).
Git attributes preserve these identities under either checkout newline policy.
Run `python3 -B check-evidence.py` to verify the full partition, image-region
ownership, code-extension capability, logical/physical extents, metadata and
release behavior. A controlled owner-extent corruption must be rejected even
when hash verification is bypassed to exercise the semantic verifier directly.
Earlier executed probe versions and their artifacts remain in the task archive.

## Implementation and ownership

The portable `image::region::Query` validator retains allocation identity,
exact cursor/page alignment, `MEM_IMAGE`, state/protection and overflow checks.
Only a bounded reserved run may cross the logical end; committed overruns,
foreign owners and malformed metadata fail. The copy/protect/read length is
the checked intersection with the logical image. After capturing explicit
executable extensions, one metadata-only query records trailing same-owner
reserved pages. Both the earlier overhang and the final owner extent must agree.

`ImageTemplate` stores reserved padding separately from PE bytes and executable
extension records. Rebase snapshots must agree on it. The selected bounds are
64 MiB for image bytes, at most two 64 KiB executable extensions and at most
64 KiB trailing reservation; exceeding a bound fails explicitly.

Full ordinary views reserve the complete owner, retain the logical output size,
and keep the Section alive after handle closure. Unmapping from the reserved
tail releases the whole allocation. Partial and native large-page views retain
their existing policy and omit this tail. `ImageExtensionPresent` includes a
retained reserved tail; class 14 still describes executable extension bytes
only. The existing exclusion of host signing levels from guest trust is preserved.

Per queried region validation uses O(1) time/storage. Acquisition remains
O(B + R) for B logical image bytes and at most 256 region runs, plus at most
two bounded extension copies. Reserved padding consumes address space and
metadata, not guest frames. No guest pointer or arbitrary path enters native
mapping/query calls.

## Provenance, assumptions and scope

[Microsoft VirtualQuery documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)
defines a region by allocation, state and protection; its size is not a PE
`SizeOfImage` boundary. The native measurements establish the exact reserved
tail and lifetime behavior on this installation. The retained primary PHNT
`MEMORY_IMAGE_INFORMATION` declaration and class-14 provenance are in
[native-image-extension/references](../native-image-extension/references/sources.json).
The bound `phnt-ntmmapi.h` SHA-256 is
`8acd89a95f890f929da824cc841383770a4f21f312bb04d0d12f03cb3a00e079`.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- | --- |
| IG1 | A valid native reserved run may exceed logical image bytes. | 48 original-predicate failures, each with matching owner/type and measured reserved overhang. | Bounded acquisition intersection. | Foreign owner, committed overrun, zero/unaligned lengths and arithmetic overflow must fail. | Confirmed on captured kernel. |
| IG2 | Reserved tails belong to full image owners and are omitted from partial views. | Base/tail unmaps and complete release across all three profiles. | Reservation, lookup and lifetime. | Re-run with partial/rebased views, occupied tail or insufficient allocation. | Confirmed on captured kernel. |
| IG3 | Class-6 extension presence includes reserved-only tails. | Full pure x86 flags `0x70`; CHPE flags `0x30`; partial flags `0x31`. | Guest image metadata bit `0x40`. | Compare class 6 at header/logical-end/owner-end independently of class 14. | Confirmed on captured kernel. |

This changes native image acquisition, private template metadata, guest image
allocation ownership and their tests. ISA/SMIR/JIT execution, public C API,
persisted schemas, permissions, namespace selection and package layout are
unchanged. C++ is limited to the independent native-ABI control; production
logic and regression tests are Rust.

High impact: complete native process startup, other kernels and physical AMD64
qualification remain separate acceptance requirements. Medium impact: an
unmeasured committed overrun or trailing reservation beyond the selected bound
requires an explicit acquisition extension, not silent truncation or forwarding.
The full Linux/macOS/Windows host-library objective remains intact.

## Final source-frame validation

| Host | Namespace / capture | Image memory | Section services | C API | Full Windows-personality filter |
| --- | ---: | ---: | ---: | ---: | ---: |
| macOS | 42 passed | 10 passed | 5 passed | 191 passed | 1468 passed |
| Linux | 42 passed | 10 passed | 5 passed | 191 passed | 1462 passed |
| Windows ARM64 | 43 passed | 10 passed | 7 passed | 191 passed | Not run in this group |

The listed suites have zero failed or ignored tests. Windows additionally
executes the installed native map/unmap leaves. macOS/Windows retain the separate
native-entry draft; Linux uses the shared-runtime overlay without that draft
or unrelated Windows-only leaf refinements. This changeset excludes those files.
An initial new service fixture had incorrect machine-warning expectations;
its failed versions are preserved. The corrected matrix retains the existing
AMD64 mismatch warning and ARM64/WoW64 relocated-view status, without changing
production status semantics.

The original hardware-fault fixture remains failed overall: ARM64 completes;
x86 gets beyond image acquisition and stops at unimplemented
`NtWow64CsrClientConnectToServer` (`0x1E9`) at the private transition `0x150000`.
Its source, binaries, assertions and 60 s / 16384-slice / 4096-instruction
limits remain unchanged. No CSR success stub or fault-reporting bypass is added.

These are source/library checks, separate from linked Assist shipping-plugin,
package and complete native-runtime qualification. Public RAX C API 1.15.0 and
its 73534-byte header SHA-256
`baaf643f62c525d923529ccbf75a97505a31831592a8aa91ab9be71f5ec144b5`
remain unchanged.
