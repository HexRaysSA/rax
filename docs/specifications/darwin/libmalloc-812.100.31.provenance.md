[← Documentation home](../../../README.md)

# libmalloc 812.100.31 sources provenance

- Canonical title: libmalloc source tree, selected files
- Issuing organization: Apple Inc. (Apple Open Source)
- Revision: tag `libmalloc-812.100.31`
- Source URL: https://github.com/apple-oss-distributions/libmalloc (tag
  `libmalloc-812.100.31`); the files were extracted from the tag's archive
  `https://github.com/apple-oss-distributions/libmalloc/archive/refs/tags/libmalloc-812.100.31.tar.gz`
  (archive SHA-256
  `a2966b7790c9dc7b66af22160070b9f7faa9aceb8eb1f89b36cbeb82811d5fff`)
- Retrieved: 27 September 2026
- Integrity: `libmalloc-812.100.31.sha256` lists the SHA-256 of every
  imported file, relative to `libmalloc-812.100.31/`.
- License: `src/malloc.c` and `src/malloc_config.c` carry the Apple Public
  Source License 2.0 header (the license text is the APSL 2.0 in
  `xnu-12377.121.6/APPLE_LICENSE`). `src/xzone_malloc/xzone_segment.c` is
  under the MIT license with Microsoft Research's and Apple's copyright
  (derived from mimalloc); the license text is
  `src/xzone_malloc/LICENSE`, imported beside it. The files are reference
  material for an independent implementation; no RAX source is derived from
  their text.

Paths under `libmalloc-812.100.31/` mirror the libmalloc tree. Do not
reformat or edit the files.

## Use in RAX

| Area | Files |
|---|---|
| The deferred-reclamation ring the xzone allocator allocates at start-up (its capacities, the log on any failure), the processes that do without it (by program name) | `src/xzone_malloc/xzone_segment.c` (`xzm_reclaim_init`), `src/malloc_config.c` (process identities, `_malloc_process_identity_disables_xzone_malloc`), `src/malloc.c` (`getprogname` as the identity) |
