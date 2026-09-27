# CRT raw memory/string contracts and retained references

This archive supports the checked Windows CRT memory/string foundation. Its
17 primary Markdown documents and two owning license notices are pinned to
MicrosoftDocs/cpp-docs commit
`f2355df9f7136d8a2097193fc507882a7caeb5f5`, retrieved 2026-09-27. Canonical
titles, document dates, raw URLs, local/original SHA-256 and license URLs are in
[manifest-memory.json](../manifest-memory.json). Upstream code commit/version
for the actual native CRT implementations is unknown; this documentation
repository commit is not a native CRT version or execution oracle.

All 19 primary files are byte-identical to that upstream commit, including
both owning licenses' absent terminal LF. Documentation prose is
CC-BY-4.0 under [LICENSE](LICENSE); code samples are MIT under
[LICENSE-CODE](LICENSE-CODE). Retention does not merge the prose and code scopes.
The source text is otherwise unchanged, including unrelated secure/multibyte
API descriptions and examples. Those descriptions do not expand implementation
scope. Combined `api_location` frontmatter is not a complete per-name, per-DLL,
per-version native export inventory.

## Admitted behavior

Common tables contain five byte-buffer functions (`memcpy`, `memmove`,
`memset`, `memcmp`, `memchr`) and 20 narrow/wide string functions (`strlen`,
`strcmp`, `strncmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`,
`strrchr`, `strstr`, and their `wcs` counterparts). UCRT supplemental tables
contain `strnlen`/`wcsnlen`, not augmented into legacy MSVCRT. VCRUNTIME tables
contain all five byte-memory functions and the six narrow/wide search names.
API-set resolution follows the selected host-routing personality; the combined
host's other exports are not a per-name API-set contract or permission oracle.
Wide `wmem` operations are checked raw-unit algorithms exercised through
unit-only descriptors, not manufactured DLL exports: consulted import/header
evidence identifies inline implementations rather than genuine IAT names.
Full native DLL export inventories remain unknown; this is admitted scope.

Parameters use Cdecl on x86 and existing scalar Windows ABIs on x64/ARM64.
Counts and pointer returns use the guest's 32-bit or 64-bit pointer width.
Comparison results are 32-bit `int`: only their sign is the public contract.
Byte comparisons are unsigned; Microsoft wchar_t is 16-bit with range
0..65,535 ([Data Type Ranges](data-type-ranges.md)), so wide operations compare,
copy and search raw unsigned 16-bit units. They do not decode Unicode scalars,
reject unpaired surrogates, replace malformed sequences, or apply locale rules.

Unbounded scanners return only at a real NUL, never at an artificial host
buffer/length cutoff. Bounded length returns the bound if no NUL was found.
Character search includes the terminator; an empty substring needle returns
the original haystack. `strncpy` pads the complete requested count with NUL
after source termination, but adds no extra NUL when the count is exhausted.
`strncat` appends at most its count and writes the terminating NUL. No secure,
multibyte, `_l`, case-folding, collation, or speculative aliases are admitted.

## Checked access and fault profiles

Copy/fill validate complete guest-width intervals and preflight source-read
then destination-write permissions before buffer writes. Their working buffer
is at most 256 bytes, bounded by guest page boundaries. memmove traverses
backward precisely when the destination begins inside a higher-addressed
overlap; all other copies traverse forward. memcpy overlap is undefined and
has no overlap-result guarantee.

Comparison/search and string operations read only the next required byte or
16-bit unit. A page-end NUL is not followed by an unnecessary read of the next
page. A wchar_t unit that itself crosses a page is checked as two bytes.
Pointer-width overflow faults rather than wrapping to an unrelated allocation.
The first inaccessible read/write propagates through the shared HLE classifier
for AV, one-shot guard, and stack handling; CRT does not consume guards itself.

The personality returns early without dereferencing pointers for zero-count
buffer operations, bounded length/comparison, and bounded copy. Invalid-pointer
zero-count native behavior and native parameter/fault precedence are unknown.
These branches are explicit profiles, not measured native equivalence.

String writes stream in increasing unit order. A later inaccessible source or
destination can leave the previously written prefix, including NUL padding.
Fixed-buffer preflight normally prevents such guest writes on invalid spans,
but can materialize host residency before failing. The underlying AddressSpace
page residency/metadata costs are separate from the constant working buffer.
Neither profile claims the fault-time partial completion of native optimized
CRT implementations, atomic rollback, or native SIMD overread behavior.

### Retained source contradiction

[strncpy](strncpy-strncpy-l-wcsncpy-wcsncpy-l-mbsncpy-mbsncpy-l.md) has a `char*`
prototype and states in Return value that the destination is returned with no
reserved error value. Its later invalid-parameter paragraph states that NULL
pointers or count <= 0 invoke the invalid-parameter handler, then return -1
with EINVAL if execution continues. Those statements conflict for a pointer
return and zero-count branch; no native version is identified to resolve them.
The selected zero-count profile returns destination without dereference. For
nonzero invalid memory, this group propagates checked guest faults rather than
claiming the uncertain documented handler path. Valid nonoverlapping n > 0
copy/padding semantics are independently specified and implemented.

[strnlen](strnlen-strnlen-s.md) states that NULL causes an access violation but
does not separately establish NULL with a zero bound. That combination is the
same explicit no-dereference profile, not a native assertion.

## Complexity and reusable helpers

For N accessed raw units, buffer/string copy, fill, comparison, and length or
character search take O(N) time and O(1) auxiliary working storage. Early
comparison/search results can reduce the number of accesses. Substring search
uses the bounded-storage naive algorithm: O(H * M) worst-case time for haystack
length H and needle length M, O(1) auxiliary storage. No throughput or optimal
substring-search claim is made. Address-map probing/materialization retains
the existing guest-page costs; it is not O(1) total host memory consumption.

`strings::string_len(&Ctx, address, unit, Option<bound>)` and
`memory::copy(&Ctx, dest, source, bytes)` are shared with strdup/wcsdup. Scanner
units are 1 or 2 bytes; unsupported internal widths return an explicit internal
error. strdup callers own allocation rollback on checked-copy failure.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| M1 | No other guest execution changes mappings during one HLE operation | Existing serialized Windows scheduler/AddressSpace contract | Preflight then buffer writes | Source/destination pages protected or guarded; late string fault | Mapping changes between preflight and chunk access falsify the no-interleaving premise | Retained execution-model constraint; checked errors remain propagated |
| M2 | Invalid pointers with zero count follow the no-dereference profile, not an asserted native result | Explicit admitted scope; strncpy documentation contradiction and strnlen NULL/zero ambiguity | Zero-count early returns | NULL and SIZE_MAX pointers, both unit widths | Native per-version callback/fault trace could falsify equivalence, which is not claimed | Retained profile; native invalid-branch behavior unknown |
| M3 | Checked streaming/preflight fault order is a personality profile | Native optimized implementations and fault-time partial completion are not specified by the cited pages | Guest faults and partially written string prefixes | Page boundaries, read-only destination, guarded source, insufficient mapping | Native memory/exception trace showing another partial prefix or access order | Retained profile; native partial-completion equivalence unknown |

## Change surface and bounded findings

Only Windows user-personality HLE tables, checked guest-memory operations,
unit tests, and references are affected. Direct ISA decode/execute, architectural
CPU state, SMIR, optimizer, native lowering/JIT, backend, machine/devices,
oracle instruction analysis, and C ABI are unaffected because these operations
execute wholly inside existing HLE and do not add instruction admission.

High, nonblocking: native invalid-parameter/fault precedence is unknown and the
strncpy source is contradictory; explicit profiles prevent a false equivalence
claim. Medium, nonblocking: naive strstr can perform O(H * M) accesses on long
repetitive inputs; a constant-space linear matcher is outside this group.
Medium, nonblocking: complete native export inventories are unknown; only the
selected common/UCRT tables are admitted. Secure/multibyte/locale strings remain
outside scope, with no fabricated successful aliases.

## Validation record

The owned source graph has 17 unit test functions (7 buffer, 10 string), each
covering all three guest ABIs. They cover overlap directions, raw surrogate
units, unsigned ordering, zero counts, count/guest-width overflow, SIZE_MAX,
read-only and guard faults, page-end terminators, no truncated unbounded
success, padding/concatenation/search, late-write prefixes, and a length beyond
64 KiB. Native Windows differential execution is unknown. Cargo/build/test
execution is root-coordinated and was not run by this owner; the parent feature
report supplies observed combined-tree results.

Exact owned Rust formatting succeeded using rustfmt --edition 2024. Local
archive verification from repository root:

```sh
jq -r '.sources[] | "\(.sha256)  docs/specifications/windows/crt-foundation/\(.path)"' docs/specifications/windows/crt-foundation/manifest-memory.json | shasum -a 256 -c
```

Observed result: 19 OK, with 19 unique paths and 19 unique local SHA-256 values.
Independent curl/shasum comparisons match all 19 raw upstream hashes. The two
license terminal LFs initially introduced by apply_patch were removed by the
authorized exact-path mechanical formatter `perl -0pi -e 's/\n\z//'`; hashes
before and after established that this restored the upstream bytes exactly.
