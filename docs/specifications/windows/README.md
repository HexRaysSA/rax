# Windows source evidence

`sources.json` records issuing organization, source and canonical URLs,
retrieval date, licensing location, and SHA-256 of each retained reference.
Mutable-branch documentation revisions are **unknown**; the content hashes
identify the exact consulted bytes. The PE parser's original source record is
also preserved in `microsoft-docs/pe-format.provenance.md`.

Microsoft documentation copies retain their original front matter. The local
`microsoft-docs/LICENSE` is the cpp-docs CC-BY-4.0 license; the metadata links
each other source's owning repository license. MinGW headers retain their
public-domain notices and are implementation references, not Microsoft SDK
oracles. `resource-directory-entry.h` is an exact declaration fragment from
Microsoft's SDK-header repository, not a standalone compilable header.

Known source conflicts are explicit. PE Format describes 32-bit resource integer
IDs and case-sensitive resource-name ordering; the SDK declaration exposes a
16-bit `Id` member. RAX's format parser retains all 32 bits and exact UTF-16
names. This does not establish Windows `FindResource` matching equivalence.
HeapCreate describes architecture-dependent fixed-heap block ceilings, whereas
HeapAlloc states a uniform `0x7FFF8` limit. Exact native ceiling behavior remains
unknown without a Windows execution oracle.

PE Format marks the 28 non-alignment TLS Characteristics bits reserved; the
current SDK additionally defines bit 0, `IMAGE_SCN_SCALE_INDEX`. The exact
SDK definition is retained in `microsoft-docs/tls-characteristics.h`. RAX rejects
this recognized but unimplemented feature explicitly rather than classifying
it as a proven malformed native image. Native desktop acceptance is unknown.

Executable public layout probes and compiler/header versions are recorded in
`tests/fixtures/user/windows/layout/`. Private PEB/TEB/LDR field offsets are a
supplied compatibility profile; no modern Windows private-symbol verification
is implied. Native Windows differential results remain unknown.

The CRT foundation's allocation/error and memory/string references are retained
under `crt-foundation/`, with separate content-hash manifests for disjoint
semantic ownership. ABI references remain the existing `microsoft-docs/`
copies; the fixture graph records which exact retained inputs it uses. These
are primary contract references, not native Windows execution recordings or a
complete DLL export/ordinal inventory.

The [allocation/error manifest](crt-foundation/manifest-alloc.json),
[memory/string manifest](crt-foundation/manifest-memory.json), and
[binding/header evidence](crt-foundation/bindings/README.md) retain exact source
identity, disjoint hashes, license notices and explicit native unknowns.

[Constructor-table evidence](crt-initializers/README.md) retains Microsoft
contracts, MinGW initializer/startup sources, real import-archive observations
and the distinction between documented behavior and native-unverified profiles.
