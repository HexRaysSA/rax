# Windows DLL lifecycle primary references

Microsoft Learn API/concept source Markdown retained on 2026-09-27 from the
official MicrosoftDocs repositories reached through the corresponding Learn
pages' Edit links. Microsoft is the issuer; the four retained repository licenses
are Creative Commons Attribution 4.0 International. License files separately
record the SDK API, Win32 concepts, C++ documentation and WDK DDI repositories.

[sources.json](sources.json) records every retained source, its official rendered
URL, raw source URL, local SHA-256, retrieval date, normalization and license URL.
An exact upstream commit revision is unknown: the retrieved `docs`, `main` and
`staging` branches are mutable. Local hashes pin this archive's consulted bytes.

The PE format TLS sections and ExitProcess/TerminateThread documentation were already retained
elsewhere; the manifest records their existing paths/provenance rather than
duplicating them. No native Windows oracle was run for this analysis.

[lifecycle-analysis.md](lifecycle-analysis.md) separates documented behavior,
current implementation evidence, design dependencies, explicit native unknowns,
and proposed falsification probes. Its implementation section distinguishes
source completion from executable validation. The source snapshots retain upstream relative links as published; use the
manifest's canonical URLs to resolve links outside this archive.

Integrity check from the repository root:

```sh
jq -r '.sources[] | [.sha256, ("docs/specifications/windows/services/dll-lifecycle/" + .path)] | join("  ")' docs/specifications/windows/services/dll-lifecycle/sources.json | shasum -a 256 -c -
```
