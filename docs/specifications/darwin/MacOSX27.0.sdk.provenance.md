[← Documentation home](../../../README.md)

# macOS 27.0 SDK headers provenance

- Canonical title: macOS SDK 27.0 (`MacOSX27.0.sdk`), selected public
  headers
- Issuing organization: Apple Inc., distributed with Xcode 27.0 (build
  27A266a); SDK build version 26A425
- Source: `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk`
  on the development host (Xcode is distributed at
  https://developer.apple.com/xcode/)
- Retrieved: 27 September 2026
- Integrity: `MacOSX27.0.sdk.sha256` lists the SHA-256 of every imported
  file, relative to `MacOSX27.0.sdk/`.
- License: each imported header carries the Apple Public Source License 2.0
  header (`APPLE_OSREFERENCE_LICENSE_HEADER`); the license text is the APSL
  2.0 in `xnu-12377.121.6/APPLE_LICENSE`. The files are reference material
  for an independent implementation; no RAX source is derived from their
  text.

The emulated programs run the host's macOS 27 user space, whose kernel
(`xnu-13432`) is newer than the vendored XNU release. Where the SDK's
published interface extends a kernel structure that release defines, the
Darwin personality follows the SDK and records it here.

## Use in RAX

| Area | Files |
|---|---|
| `vm_region_submap_info_64` revision 3 (`pages_wired`, `wire_tag`; 21 words) returned by `mach_vm_region_recurse` | `usr/include/mach/vm_region.h` |
