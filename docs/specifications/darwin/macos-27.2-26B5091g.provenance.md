[← Documentation home](../../../README.md)

# macOS 27.2 (26B5091g) host probes provenance

- Canonical title: observations of a macOS 27.2 kernel through its public
  system calls
- Issuing organization: Apple Inc. (the observed software); the
  observations were made for RAX
- Revision: macOS 27.2, build 26B5091g; kernel `Darwin Kernel Version
  27.2.0: Sun Sep 13 19:46:18 PDT 2026;
  root:xnu-13432.40.162~92/RELEASE_ARM64_T6041`, on an Apple M4 Max
- Source: produced on the development host by the programs named below;
  there is no download location
- Retrieved: 27 September 2026
- Integrity: `macos-27.2-26B5091g.sha256` lists the SHA-256 of every file,
  relative to `macos-27.2-26B5091g/`.
- License: the files are measurements, not Apple's text; they are
  reproduced here as reference data for an independent implementation.

| File | What it records | How it was produced |
|---|---|---|
| `sysctl-hw-machdep-arm64.tsv` | Every node of the arm64 kernel's `hw` and `machdep` sysctl subtrees as the metadata nodes report them, one per line, tab-separated: name (`{0,1}`), OID, kind and format (`{0,4}`), and description (`{0,5}`), interior nodes before their first leaf, then in `{0,2}` order (`\t`, `\n`, and `\\` escape those characters) | `tools/darwin/sysctl_dump.c`, run natively as `sysctl_dump hw machdep` |

The files describe this host's kernel, which the Darwin personality's
arm64 guests are given (they run on the host's user space); a newer or
older macOS release would differ in places. To move to another release,
record a new `macos-<version>-<build>/` tree with its own provenance.
