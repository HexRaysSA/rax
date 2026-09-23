# Licensing tools and source records

## Distribution files

RAX is licensed under the MIT License in `LICENSE`.
`THIRD_PARTY_NOTICES.md` contains component attributions and third-party notices.
The matching files under `capi/` are kept byte-identical by
`tools/licensing/check.py`.

The root and C API manifests use explicit Cargo include lists. The engine crate
contains Rust source, Cargo metadata, README and legal files. Reference manuals,
guest fixtures, integration suites and examples remain in the repository.

C API SDK and debug archives contain both legal files. Archive sealing checks
their contents before generating checksums. CMake installs them under
`${CMAKE_INSTALL_DATADIR}/licenses/rax`.

## Checks

Run from the repository root with Python 3.11 or later, Cargo and Git installed:

```sh
python3 tools/licensing/check.py
python3 -m unittest discover -s tools/licensing -p 'test_*.py' -v
python3 -m unittest discover -s tools/capi -p 'test_*.py' -v
```

The package checker compares the Intel notice against
`src/smir/interpret/mod.rs`, checks root/C API synchronization and validates
Cargo's package file lists. Cargo lists package files with host path
separators; the checker validates them as `/`-separated archive paths (see
[`cargo-package-list.md`](cargo-package-list.md)). The CI workflow runs these
checks on Linux, macOS and Windows.

## Source records

`sources.json` records retrieval URLs, dates and hashes for the license texts.
Source and generator records for test corpora are in
`tests/generated/manifest.toml`.

The Hexagon generator reads QEMU v9.0.0 encoding definitions and attributes
from `tools/hexagon/qemu/` and writes `src/isa/hexagon/generated/opcodes.rs`.
The input headers specify GPL-2.0-or-later.

## Cargo registry packaging

The C API currently uses a path-only engine dependency without a version
requirement; Cargo rejects registry archive creation for that manifest.
Native SDK builds use the workspace dependency directly.

Cargo removes workspace dependency patches when normalizing source packages.
In particular, the engine's `linux-loader` patch is absent from its registry
archive. Validate platform support using the unpacked package as well as the
workspace build.
