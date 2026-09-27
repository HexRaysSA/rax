# CRT binding and header evidence

This directory retains installed primary header/import-definition material and
derived observations of import archives. It is not a measured native Windows
DLL export table. The exact retained bytes, installed input paths and hashes,
extraction commands, versions, and retrieval date are in
[manifest-abi.json](manifest-abi.json). The existing Microsoft ABI archive is
referenced in [the parent provenance](../../sources.json); the fixture records
its five ABI/license inputs separately in
[manifest-abi.json](../../../../../tests/fixtures/user/windows/crt/manifest-abi.json).

The installed package is Homebrew MinGW-w64 `14.0.0_3`. The import inventories
were read using `/Users/int/local/bin/llvm-nm`, LLVM `23.0.0git`, executable
SHA-256 `20e1aa425fda511df6d594ba6ff5298871644a6a74dea8d6da38ea0b3ad2c94f`.
The raw `.def` inputs came from Zig `0.16.0`'s bundled MinGW directory; its exact
upstream source commit is unknown. They are retained, not rewritten into a
claimed SDK export inventory.

Evidence and limits:

- `vcruntime140-{x86,x64}-iats.txt` contains genuine import symbols for the same
  11 names: `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `strchr`,
  `strrchr`, `strstr`, `wcschr`, `wcsrchr`, and `wcsstr`. The raw common `.def`
  agrees. The fixture API-set binding imports ten of these from VCRUNTIME140,
  leaving `memset` in the CRT string API-set inventory. No C++ EH support is
  inferred from other names retained in the common `.def`.
- `msvcrt-x64-state-symbols.txt` distinguishes genuine `I __imp_*` imports from
  `lib64_libmsvcrt_extra_a-*` compatibility implementations (`T` function and
  sometimes `D __imp_*` local pointer). `_errno`, `__doserrno`, and
  `_get_heap_handle` are genuine imports. `_get/_set_errno`, `_get/_set_doserrno`,
  global invalid-parameter handlers, and `strnlen`/`wcsnlen` are compatibility
  implementations in this archive. Generic Microsoft `api_location` metadata
  can also list MSVCRT; that discrepancy does not establish the export table of
  any particular native Windows version. The admitted legacy facade deliberately
  excludes these additional names.
- `ucrtbase-x64-state-symbols.txt` confirms UCRT import objects for the error
  accessors, handler accessors, and bounded string lengths. No nonsecure
  `wmemcpy`, `wmemmove`, `wmemset`, `wmemcmp`, or `wmemchr` import is found by the
  retained filter. The MinGW `wchar.h` excerpt explicitly identifies the static
  `libmingwex.a` declarations and inline implementations. The fixture does not
  manufacture named `wmem*` PE imports. UTF-16 string operations remain covered.
- The raw API-set definitions place `_strdup`/`_wcsdup` in `string`, not `heap`.
  `string` includes `memset`, but not the other byte-memory or character-search
  functions above. The fixture uses the corresponding real binding groups.

The `wchar.h` excerpt is exactly `sed -n '1,5p;1108,1158p'` from the installed
full header, whose SHA-256 is recorded in the manifest. It retains its public
domain notice. Installed `COPYING` files retain the owning ZPL 2.1 notices.
`DISCLAIMER.PD`, not present in the installed packages, was retained from the
MinGW-w64 `v14.0.0` tag at the recorded URL; it is not falsely described as an
installed byte-for-byte input. ARM64 native export availability and all native
Windows differential results are unknown: ARM64 PE compilation and RAX execution
are separate evidence.

Regenerate each derived symbol observation with its exact `command` in the
manifest and compare output bytes. Compare raw copies to each `input_path`, and
the header excerpt to its `extraction_command`. Archive generation and runtime
tests do not use these installed import libraries as link inputs: fixtures use
their retained handwritten minimal `.def` files and freshly generated stubs.
