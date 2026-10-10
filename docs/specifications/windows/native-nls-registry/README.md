# Installed NLS registry metadata and native key services

This implementation captures one fixed installed runtime key during explicit
Windows native-library selection:
`\Registry\Machine\System\CurrentControlSet\Control\Nls\CodePage`.
The host adapter opens `HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage`
with `KEY_QUERY_VALUE` only, captures raw value names/types/data and a 65,536-entry
UTF-16 upcase table, and closes its host HKEY before returning. Guest kernel
calls use immutable private records; no guest name selects a host registry key.
The supplied-only profile has no installed registry snapshot.

Selection rejects more than 4,096 values, names above 16,383 UTF-16 code units,
data above 1,048,576 bytes per value, or total names/data above 16,777,216 bytes.
It requires two matching complete enumerations surrounded by unchanged key
metadata. Three attempts bound observed instability; this is a stability fence,
not a linearizable snapshot under arbitrary concurrent host modification.
Unexpected host errors retain their actual cause; `ERROR_MORE_DATA` and
`ERROR_NO_MORE_ITEMS` during enumeration cause a bounded restart. No live host
registry handle, mutation callback or copied host token/ACL is stored.

`NtOpenKey` creates the public Rust `Object::Key(Arc<Key>)` variant in the shared
handle table. Handles share immutable records, support tagged lookup, inherit
flags and normal close/reference lifetime, and are nonwaitable. Existing handles
retain their snapshot after another record is selected. The C ABI remains
1.11.0. The guest model admits explicit read rights under `KEY_READ=0x00020019`,
maps `GENERIC_READ`, `GENERIC_EXECUTE` and `MAXIMUM_ALLOWED` to that mask, and
denies writes, zero access and unsupported access bits. This is an explicit
read-only one-principal model, not a host DACL/token/security-namespace model.
Both WoW64 view flags together return invalid parameter. A snapshotted missing
value returns name-not-found; an unsnapshotted absolute key fails explicitly as
unsupported rather than fabricating namespace absence. A key with no children
can establish absence of a relative child. A nonempty unrecorded child namespace
is unsupported. Valid security descriptors/QoS are outside this model.

The retained primary declarations and Microsoft pages specify public names and
layouts. Private error/copy priority below is measured on Windows
10.0.29683.1000, not asserted as a stable contract of every build. The three
original query-only oracle programs execute ARM64, x86 and x64 processes on
the Windows ARM64 kernel. Compatibility entry points do not establish separate
Intel-kernel or physical-x86 validation. They perform 1,476 value queries and
37 key opens per ABI: 4,428 queries and 111 opens total. Successful handles close;
the probes never create, modify, delete or change security of any key.

| Operation | Native64 observed order | WoW64 observed order |
|---|---|---|
| Open | Probe and zero pointer-width output; capture 48-byte, 8-byte-aligned attributes/name; validate and publish handle | Capture 24-byte unaligned attributes/name/security structures first; then probe/zero 4-byte output and validate |
| Root plus absolute name | Validate root handle/type, then path-syntax failure | Path-syntax failure precedes root-handle validation |
| Query | Validate class, typed handle and query right; capture name; validate output alignment; publish mandatory ResultLength; copy defined prefix | Capture nonnull name descriptor first; validate class/handle before reading its text; convert misaligned output through private scratch; native result then compatibility copy-out |
| UNICODE_STRING | Unaligned descriptor accepted; odd Length rejected; MaximumLength ignored | Query descriptor captured earlier, text after kernel validation; open conversion captures text before output |
| Faults | NT access/guard status, completed prefix retained, no guest SEH | Same, subject to capture/copy-out priority; later copy fault supersedes native status |

For all admitted classes, the measured native output requirement is **4-byte**
alignment when Length is nonzero. This includes classes whose PHNT structures
carry `DECLSPEC_ALIGN(8)`; the declaration does not override the observed probe.
An unaligned native output fails before ResultLength even if it is too short
for a header. Length zero bypasses output alignment. ResultLength is a mandatory
unaligned 4-byte destination. It is written before an output-copy fault and can
be overwritten when it aliases the output.

| Class | Fixed header bytes | Required bytes | Defined fields |
|---|---|---|---|
| 0 BasicInformation | 12 | `12 + NameBytes` | TitleIndex 0, Type, NameLength, stored canonical UTF-16 name without added NUL |
| 1 FullInformation | 20 | `align_up(20 + NameBytes, 8) + DataBytes` | TitleIndex 0, Type, DataOffset, DataLength, NameLength, name, zero padding, raw data |
| 2 PartialInformation | 12 | `12 + DataBytes` | TitleIndex 0, Type, DataLength, raw data |
| 3 FullInformationAlign64 | 20 | Same as class 1 | Same defined layout |
| 4 PartialInformationAlign64 | 8 | `8 + DataBytes` | Type, DataLength, raw data |

Length below the header returns `STATUS_BUFFER_TOO_SMALL` and required length,
without defined output. Header <= Length < required returns
`STATUS_BUFFER_OVERFLOW` and that bounded prefix. A name ending at an odd byte
boundary retains complete UTF-16 units and zeroes the final incomplete byte;
raw value data retains its byte prefix. Sufficient length returns success. The
unused supplied
tail is not probed on native entry: a 22-byte result can succeed with Length 64
when only those 22 bytes are writable. A later-page fault preserves a completed
first-page prefix. Classes 5 and higher return invalid parameter before native
handle/name/ResultLength probing. WoW64's prior nonnull name conversion can fault
before that class validation.

WoW64 converts output unaligned to 4 bytes, and classes 3/4 unaligned to 8 bytes.
It copies its entire supplied temporary-buffer length, including undefined
tails and error-result bytes. Native traces can contain previous allocator
contents in those bytes. RAX uses zero-initialized private scratch instead;
only defined serialized fields/statuses are oracle claims. Conversion is bounded
to 16,777,216 bytes and fails explicitly beyond that implementation bound.
The exact host scratch allocation history and copy-fault granularity are unknown;
they are not promoted to deterministic Windows guarantees.

For ACP=`1252\0`, NameBytes=6 and DataBytes=10: basic requires 18 bytes, full
requires `align_up(26,8)+10 = 42` bytes, partial requires 22 bytes, and aligned
partial requires 18 bytes. These are controlled build29683 oracle values.
Installed selection preserves the actual host locale and raw type/data; it
never installs those US-locale values as defaults or synthesizes terminators.
Lookup folds one UTF-16 unit through the selected table, preserving surrogates
and the original stored name. Query lookup costs O(N log V) comparisons for N
name units and V values; serialization/copy costs O(N+D+P) time and O(N+D) space
for D data bytes and P destination pages, plus O(Length) conversion scratch when
required. Handle publication costs O(H) for H existing handles.

| Assumption | Basis | Dependent behavior | Stress/falsification probe | Status |
|---|---|---|---|---|
| R1: explicit runtime selection includes required fixed NLS metadata | User full-installed-runtime goal; existing explicit native selector | Fixed query-only snapshot; supplied-only remains empty; no general registry forwarding | Default profile/other-key tests; inspect host adapter for guest-selected names, retained HKEYs or writes | Confirmed implementation; native adapter proof recorded in validation |
| R2: build29683 priority owns this admitted profile | Retained original three-ABI native queries; PHNT declarations and Microsoft interfaces | Capture, status, alignment, descriptor/text ordering, aliases and partial writes | Retained three-ABI oracle versus shared service tests; other Windows builds unknown | Revised: 8-byte native output, aligned UNICODE_STRING and copied odd name-byte assumptions falsified; query descriptor-only capture and native odd-length rejection-before-text confirmed; observed profile implemented |
| R3: guest read-only grant differs from host authorization | Explicit snapshot scope and shared handle access table | KEY_READ mapping, denied writes/zero rights, typed query access | Generic/view masks, wrong/pseudo/closed handles, explicit write denial; copied host token/ACL would falsify | Retained explicit model, broader NT authorization incomplete |
| R4: selected ordinal UTF-16 case table owns lookup | Captured RtlUpcaseUnicodeChar and independent RtlEqualUnicodeString comparison | Raw names preserved; no Rust expanding case conversion | Every BMP unit compared with installed RtlEqualUnicodeString; raw surrogate/collision tests | Shared model confirmed; native result in validation |
| R5: locale data is selected, not fabricated | Fixed public system NLS key and raw enumeration/query comparison | Raw actual ACP/OEMCP/MACCP values | Independent host RegQueryValueExW comparison; alternate-locale native execution remains unknown | Actual native values checked; NLS file/section services remain separate work |
| R6: undefined WoW64 scratch bytes are outside defined-field fidelity | Repeated native alignment/error probes expose allocator-dependent bytes | Private zero scratch, measured status/defined prefix, bounded copy | Error/unaligned/short queries and retained allocator-dependent native bytes | Retained documented fidelity limit; exact native scratch history unknown |

All retained source/oracle bytes and accompanying notices are SHA-256 identified
in `sources.json`. `regressions-before.log` records both missing-service failures;
`regressions-after.log` records their passing state. Odd-name-byte and
descriptor/text priority regressions have separately retained before/after
failures and passing captures. Shared matrices, independent
installed metadata/case checks and installed NTDLL leaves have separate roles.
Current full-suite and owning-archive results are recorded in
`src/user/windows/native-runtime.md` for the final validated source.

Scope: shared guest policy/serialization/object lifetime compile and run on
Windows, macOS and Linux. The installed snapshot adapter is Windows-specific,
matching the existing selector capability; host mismatch remains explicit.
ISA/SMIR/JIT, C layouts, dependency pins, locks, defaults and package target
membership are unchanged. Assist's existing native-runtime permission selects
this adapter; tool copy discloses the fixed metadata read and compiled discovery
must be regenerated. **High:** complete native loader/RTL heap/Win32 CRT startup
and wider NT/security/registry services remain incomplete. **Medium:** arbitrary
concurrent host registry changes and exact WoW64 scratch lifecycle are outside
this profile. **Low:** sharing metadata across separate processes is a possible
allocation optimization and is not implemented.
