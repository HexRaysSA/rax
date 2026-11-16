# Native C API linkage after Cargo stripping

## Failure and repair

On macOS ARM64, a successful Rust 1.95 build can produce a `librax.dylib`
that Apple's native linker rejects with `mis-aligned LINKEDIT string pool`.
The failure was reproduced from clean RAX parent
`461abad02ebf1b12ac7f5b73508bcc77d4c7ebee` with the development profile,
`CARGO_PROFILE_DEV_DEBUG=0`, and optional engine features disabled.
Cargo exited 0; compiling the external `x86_64_basic.c` client exited 1.

The rejected file's `LC_DYSYMTAB` indirect-symbol table began at byte offset
55,142,312 and contained 589 entries of 4 bytes each:

```text
55,142,312 bytes + 589 * 4 bytes = 55,144,668 bytes
55,144,668 bytes modulo 8 bytes = 4 bytes
```

Its `LC_SYMTAB.stroff` was exactly that unaligned table end. With the
package-specific `strip = "none"` override, the native string table instead
began at byte offset 55,201,632, divisible by 8. The same C client then linked
and executed successfully. These offsets describe the captured artifacts;
symbol-layout changes can change both the offsets and whether a particular
stripped binary exposes the defect.

The workspace disables Cargo stripping for `rax-capi` in the development and
release profiles. Other packages retain their profile policy. Optimization,
LTO, unwind behavior, default features, public headers, ABI identifiers and
the Windows CRT selection are unchanged. The package overrides also apply
through the corresponding inherited test and benchmark profiles.

Cargo automatically requests debug stripping when debug information is
disabled unless stripping is explicitly configured. In Rust 1.95's Darwin
link path, this invokes the toolchain's `rust-objcopy` after native linking.
Changing `strip` on `PATH` therefore does not select a different post-link
tool. See the preserved [compiler implementation](rust-1.95.0-link.rs),
[Cargo profile reference](cargo-profiles.md), and
[Cargo development-cycle explanation](cargo-implicit-strip.html).

Separate same-input ARM64 controls found that LLVM `--strip-debug` and
`--discard-all` produced the rejected alignment, while Apple `strip -S`
and `strip -x -S` preserved native linkage and execution. The corresponding
x86-64 controls linked and executed in all five variants. Do not infer that
every architecture or symbol layout fails.

The production SDK packager already sets
`CARGO_PROFILE_RELEASE_STRIP=none`, creates debug sidecars, and applies native
stripping before relocated consumer tests. The repair covers direct Cargo
and CMake builds that do not use that packaging environment. Applying Apple
strip to an already damaged LLVM-stripped file did not repair the captured
ARM64 artifact; native stripping must start from native-linker output.

## Reproduction

Run from the repository root on macOS ARM64 with Rust 1.95.0 and Apple's
command-line developer tools. Use an otherwise unused in-tree output directory:

```sh
mkdir -p target/capi-link-repro/tmp
export CARGO_TARGET_DIR="$PWD/target/capi-link-repro"
export TMPDIR="$CARGO_TARGET_DIR/tmp" TMP="$CARGO_TARGET_DIR/tmp" TEMP="$CARGO_TARGET_DIR/tmp"
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_DEV_CODEGEN_UNITS=8
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true
export RUSTFLAGS=
unset CARGO_ENCODED_RUSTFLAGS CARGO_PROFILE_DEV_STRIP
cargo +1.95.0 build --locked --no-default-features -p rax-capi --lib \
    --target aarch64-apple-darwin -vv
cc -arch arm64 -std=c11 -I capi/include capi/examples/x86_64_basic.c \
    "$CARGO_TARGET_DIR/aarch64-apple-darwin/debug/librax.dylib" \
    "-Wl,-rpath,$CARGO_TARGET_DIR/aarch64-apple-darwin/debug" \
    -o "$CARGO_TARGET_DIR/native-c-client"
"$CARGO_TARGET_DIR/native-c-client"
```

The captured parent library SHA-256 was
`a700c2d8e7008b4de9a0be261f1ec03876e907a8506279811e8fd0669012852f`.
The repaired library SHA-256 was
`435bd654f1fd3ea4f6e19bcf24ff4b3588b0f664c07c9051752111b891f43f73`.
Hashes bind the local observations, not a promise of bit-for-bit output on
other toolchain or operating-system installations.

## Validation boundaries

The existing `test-capi` CI job builds native C API SDKs and executes the
18 shared/static C and C++ consumers on Linux, macOS and Windows. Its shared
Rust setup disables development debug information. The SDK release workflow
also declares the x86-64 and ARM64 configurations for those operating systems.
These are executable integration gates; a successful Rust library build or
Rust unit test alone does not establish native client linkage.

The recorded development-profile results are:

| Configuration | Execution environment | Owning tests passed | External clients passed |
|---|---|---:|---:|
| macOS ARM64 | Native ARM64 | 245 | 18 |
| macOS x86-64 | Rosetta on ARM64 | 245 | 18 |
| Linux ARM64 | Linux 6.1 kernel in QEMU TCG | 245 | 18 |
| Linux x86-64 | Linux 6.1 kernel in QEMU TCG | 245 | 18 |
| Windows ARM64 | Native ARM64 kernel, build 29708 | 244 | 18 |
| Windows x86-64 | x86-64 application emulation on that ARM64 kernel | 244 | 18 |

All 1,468 owning tests passed without failures, ignores or filters. All 108
external clients passed without failures or skips. Each exact compiled test
image's discovered descriptor inventory was reconciled with its terminal
results. Windows native process exit codes were checked independently of the
Parallels command's exit status.

The ordinary macOS ARM64 release profile also passed 245 owning tests, with
the actual test compiler command selecting fat LTO. Its installed libraries
passed all 18 clients after the native stripping commands used by packaging.
That control did not rerun debug-sidecar extraction or create a complete
release SDK archive. The other release SDK targets retain their existing
native workflow gates.

macOS and Linux loader output identified the relocated library for each shared
client and no RAX shared library for static clients. Windows PE imports and
the exact colocated DLL bytes were checked; an additional native ARM64 load
probe resolved that DLL's path and called its C ABI version function.
Per-client Windows module enumeration is not claimed. Consumer libraries came
from the repaired Cargo builds and production CMake install rules; the CMake
Cargo target was not rebuilt in these metadata controls. The Linux cross
consumer toolchain explicitly linked the unwind library required by Zig's C
driver; production SDK metadata was unchanged.

[qualification.json](qualification.json) records the image and receipt hashes,
counts, assumptions and evidence limits. These finite runs do not establish
physical x86-64 host coverage, complete Linux/macOS/Windows process-family
emulation, memory ownership, scheduling or an Assist shipping artifact.

## Assumptions and scope

| ID | Assumption | Basis and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| L1 | Excluding only `rax-capi` from stripping preserves native linkage while other packages retain their profile policy. | Observed parent/fixed ARM64 artifact and actual compiler invocations; owns the Cargo repair. | Six development library/test configurations and native executions, plus ordinary ARM64 release; falsified by continued native-link failures or changed dependency profile settings. | Confirmed for the recorded configurations. |
| L2 | Existing native shared/static clients exercise the relevant external-link boundary. | Parent C client fails at native link; corrected client and all 108 development and 18 ARM64 release clients execute successfully. | Relocated prefixes, both languages and both linkage modes; falsified by a skipped client, wrong image architecture or unintended library load. | Confirmed for the recorded client inventories and stated loader checks. |
| L3 | These finite C API owning binaries need no runtime repository fixture copy on the transported platforms. | Both Linux and both Windows runs transported images, controllers and manifests; all owning descriptors passed. | Complete unfiltered inventory; falsified by a missing runtime input or incomplete result. | Confirmed for these binaries; no arbitrary engine-test claim. |

High-impact separate work: complete native-process and process-family
integration remains outside this build repair and blocks the larger process
emulation goal. Medium-impact limitation: a package built as a dependency of
another workspace uses that workspace's profiles, so its root manifest must
own the corresponding stripping policy. Neither item changes the C ABI.

Original reference bytes and license notices are preserved here.
[sources.json](sources.json) records canonical titles, issuing organizations,
revisions, retrieval times, URLs, lengths and SHA-256 digests.
