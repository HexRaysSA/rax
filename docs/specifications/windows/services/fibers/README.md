# Windows fibers and FLS primary references

Microsoft Learn API/concept source Markdown retained on 2026-09-27 from the
official MicrosoftDocs SDK API, Win32 and SupportArticles repositories. Learn Edit links were
verified for each source family. Source front matter retains canonical titles,
API signatures, upstream dates and metadata. Microsoft is the issuer.
Microsoft documentation prose uses Creative Commons Attribution 4.0 International;
Microsoft code samples use the owning repository's separate MIT LICENSE-CODE notice.
All three repositories' LICENSE and LICENSE-CODE notices are retained.

[sources.json](sources.json) records canonical/rendered URLs, raw source URLs,
retrieval date, licenses and local SHA-256 hashes. Exact upstream commit revision
is unknown: the `docs`/`main` branches are mutable. Local hashes pin consulted bytes.
Microsoft source text is unchanged except trailing blank-line normalization/terminal LF;
resolve upstream relative links using the manifest's canonical URL.

[analysis.md](analysis.md) separates API facts from current source evidence,
implementation profiles and native unknowns. No native Windows oracle was run.
The primary GetCurrentFiber/GetFiberData pages describe macros; they do not
establish the full private fiber record or every architecture's byte layout.
The manifest includes 22 Markdown sources, two 108-line header excerpts and
eight license notices. System Error
Codes documents ERROR_ALREADY_FIBER (1280) and ERROR_ALREADY_THREAD (1281);
the retained MinGW-w64 14.0.0 winerror.h definitions independently agree.
The Visual C++ troubleshooting article establishes a concrete process-exit
FLS callback path, not universal callback-context or teardown-order semantics.

## Installed public-header evidence

The verbatim [MinGW-w64 14.0.0 excerpt](mingw14-winnt-fiber-excerpt.h) and
[Zig-bundled MinGW 13.0.0 excerpt](zig-mingw13-winnt-fiber-excerpt.h) retain
the header notice, NT_TIB declarations, IA64 macro conditionals and actual
x86/x64/ARM64 inline GetCurrentFiber/GetFiberData implementations. Inclusive
input ranges, exact `sed` extraction recipes, installed paths, full-input hashes,
local hashes, release-lineage URLs and unknown exact commits are in sources.json.
Each excerpt concatenates those ranges without added separators or byte edits;
it is reference material, not a replacement compilable header.

Installed winnt.h does not mark these ranges Public Domain. Both distributions'
actual COPYING files are retained and specify ZPL-2.1 as the package default,
with exceptions only for prominently marked components. This license scope is
separate from the Microsoft Markdown/code licenses above.

Both installed MinGW 14.0.0 x86/x64 full hashes are
`d9924297c155c1e955d5262a1a6fa1dcccf12608afcc5327d7b848fb7514af0b`,
also matching the independently fetched MinGW v14.0.0 release header. The
installed Zig 0.16.0_1 bundled header hash is
`1bffc405c3dff7133fbb03d5902b384d31db8e76d6a6dffa89f495a2e2728828`;
it differs from the v13.0.0 release-tag hash
`696cd8229475c0e2c75c062cb640c8ce740ca259427b1be834606c9aae1226d9`.
The MinGW v13.0.0 URL identifies release lineage, not byte equivalence to that
installed Zig copy. Its exact upstream commit is unknown.

The earlier macro lines 2746–2747 (MinGW 14) / 2738–2739 (bundled 13) belong
to an IA64-only branch. The supported-ABI implementations use x86 FS:0x10,
x64 GS plus FIELD_OFFSET(NT_TIB,FiberData), and ARM64 X18 with NT_TIB.FiberData.
GetFiberData dereferences the first pointer at that identity. Existing
[public layout probes](../../../../../tests/fixtures/user/windows/layout/README.md)
establish 0x10 for x86 and 0x20 for x64/ARM64. This is public-header compatibility,
not evidence for the remaining native private fiber-object layout.

Integrity check from the repository root:

```sh
jq -r '.sources[] | [.sha256, ("docs/specifications/windows/services/fibers/" + .path)] | join("  ")' docs/specifications/windows/services/fibers/sources.json | shasum -a 256 -c -
```
