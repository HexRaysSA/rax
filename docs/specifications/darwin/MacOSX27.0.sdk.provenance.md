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
  2.0 in `xnu-12377.121.6/APPLE_LICENSE`. Of the manual pages,
  `usr/share/man/man2/fcntl.2` and `open.2` carry the APSL header
  (`APPLE_LICENSE_HEADER`), and `pipe.2` and `dup.2` the University of
  California's BSD notice. The files are reference material
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
| User-visible layouts of signal frames: `siginfo_t`, `ucontext_t`, `mcontext64` (arm64) and `mcontext_avx64` (x86-64), and the arm64 thread-state flags (`__DARWIN_ARM_THREAD_STATE64_FLAGS_*`, the user diversifier mask) | `usr/include/sys/signal.h`, `usr/include/sys/_types/_ucontext.h`, `usr/include/arm/_mcontext.h`, `usr/include/i386/_mcontext.h`, `usr/include/mach/arm/_structs.h`, `usr/include/mach/i386/_structs.h` |
| System calls macOS 27 adds where the vendored XNU release has none (`tools/darwin/gen_abi.py` takes their numbers and prototypes from here): `pipe2` and `dup3` | `usr/include/sys/syscall.h`, `usr/include/sys/unistd.h` |
| Close-on-fork descriptors (`O_CLOFORK`, `FD_CLOFORK`, `F_DUPFD_CLOFORK`) and the flags `pipe2` and `dup3` take, with their errors | `usr/include/sys/fcntl.h`, `usr/share/man/man2/fcntl.2`, `usr/share/man/man2/open.2`, `usr/share/man/man2/pipe.2`, `usr/share/man/man2/dup.2` |
