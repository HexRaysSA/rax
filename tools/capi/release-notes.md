Prebuilt RAX C/C++ SDKs contain shared and static libraries, `rax.h`, the header-only C++17 wrapper `rax.hpp`, CMake/pkg-config metadata, and build provenance.

- Select the archive matching your **host** architecture and OS/toolchain ABI.
- x86-64 binaries use the baseline x86-64 CPU target. AArch64 binaries use the generic target.
- Linux x86-64 is built on Ubuntu 22.04; AArch64 on Ubuntu 24.04. These are the tested Linux runtime baselines, not a promise of compatibility with older glibc. Exact symbol requirements are in `build-info.json`.
- macOS targets deployment version 11.0; runtime tests run on macOS 15.
- Windows binaries target x86-64 MSVC with the dynamic CRT; GNU/MinGW libraries are not included in this release matrix.
- These SDKs use the interpreter. JIT, KVM, HVF, and trace features are disabled.
- Both C and C++ consumers are compiled and executed against shared and static libraries after SDK relocation. Rust C API tests must also pass before publishing.

Each archive has an adjacent SHA-256 checksum and an internal file checksum manifest. See the included README for linking instructions. Shared libraries still depend on OS libraries; static archives require the documented system link dependencies.
