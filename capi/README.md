# rax — C/C++ API for the RAX emulation engine

`librax` is the embeddable C (and C++) face of the RAX CPU emulator. It is built
for **arbitrary emulation**: open an engine for a CPU architecture, map guest
memory at any address, load code and data, read/write the full register file,
then run, single‑step, or step a bounded number of instructions with complete
control over stop conditions and a rich set of execution hooks.

- **Stable ABI.** A single, hand‑authored header (`include/rax.h`) is the source
  of truth. Status/enum values are frozen; structs are versioned or reserved for
  forward‑compatible extension.
- **Idiomatic C++.** `include/rax.hpp` is a header‑only C++17 RAII wrapper with
  typed register access, `std::function` (lambda) hooks, and exceptions.
- **Embeddable.** No global state, no hidden threads, no required runtime files.
  The library validates every argument and can never let a Rust panic cross the
  FFI boundary. The crate intentionally rejects `panic=abort` builds because
  they cannot uphold that containment contract.
- **Cross‑platform.** Uses the portable software emulator backend, so the same
  code runs identically on Linux, macOS (Intel and Apple Silicon), etc.

## Quick start (C)

```c
#include <rax.h>
#include <stdio.h>

int main(void) {
    rax_engine *e;
    rax_engine_open(RAX_ARCH_X86, RAX_MODE_64, &e);

    /* mov rax,0x1337 ; mov rcx,1 ; add rax,rcx ; hlt */
    unsigned char code[] = {0x48,0xC7,0xC0,0x37,0x13,0,0, 0x48,0xC7,0xC1,1,0,0,0,
                            0x48,0x01,0xC8, 0xF4};
    rax_mem_write(e, 0x1000, code, sizeof code);
    rax_reg_write_u64(e, RAX_X86_REG_RSP, 0x8000);

    rax_emu_start(e, 0x1000, RAX_NO_ADDR, /*timeout_us*/0, /*count*/0);

    uint64_t rax;
    rax_reg_read_u64(e, RAX_X86_REG_RAX, &rax);
    printf("RAX = 0x%llx\n", (unsigned long long)rax);   /* 0x1338 */

    rax_engine_close(e);
}
```

## Quick start (C++)

Typed arithmetic and enum register values use native C++ scalar representation
on little- and big-endian hosts. Raw register buffers and aggregate template
arguments retain the C ABI's little-endian byte representation. Template types
must be trivially copyable and match the register's natural byte width.

```cpp
#include <rax.hpp>

rax::Engine e(rax::Arch::X86, RAX_MODE_64);
e.memWrite(0x1000, code);                 // std::vector<uint8_t>
e.hookCode([](rax::Engine&, uint64_t pc, uint32_t) {
    printf("exec 0x%llx\n", (unsigned long long)pc);
});
e.setReg(RAX_X86_REG_RSP, uint64_t(0x8000));
e.start(0x1000);                          // throws rax::Error on a fault
uint64_t result = e.regU64(RAX_X86_REG_RAX);
```

## Building

The library is produced by Cargo from the `rax-capi` crate:

```sh
cargo build -p rax-capi --release --locked
```

| Target toolchain | Shared library | Static archive |
|---|---|---|
| macOS | `librax.dylib` | `librax.a` |
| Linux | `librax.so` | `librax.a` |
| Windows MSVC | `rax.dll` + `rax.dll.lib` import library | `rax.lib` |
| Windows GNU/MinGW | `rax.dll` + `librax.dll.a` import library | `librax.a` |

Artifacts are in `target/release/`, or `target/<triple>/release/` when using
`--target`. An import library links to the DLL; it does not contain the static
implementation. The `rlib` is for Rust tooling and is not part of the native SDK.
The package version in Cargo and the C ABI version in `rax.h` are independent.

### CMake

```sh
cmake -S capi -B build -DCMAKE_INSTALL_PREFIX=/path/to/sdk
cmake --build build --config Release
cmake --install build --config Release
```

Both library forms are installed by default. `RAX_BUILD_SHARED` and
`RAX_BUILD_STATIC` select installed targets; Cargo still produces its declared
crate types. `RAX_CARGO_TARGET` selects a Rust triple and must match the CMake
C/C++ toolchain. `RAX_FEATURES` accepts a semicolon-separated feature list.
Builds use `--locked` and rerun Cargo's freshness check for source changes.

Downstream, no Rust installation or source checkout is required:

```cmake
find_package(rax 1.3 REQUIRED CONFIG)
target_link_libraries(myapp PRIVATE rax::rax)         # shared
# or: target_link_libraries(myapp PRIVATE rax::rax_static)
```

Set `CMAKE_PREFIX_PATH` to the extracted SDK. Shared targets expose the Windows
import library and `RAX_DLL` definition automatically. On Windows, deploy
`bin/rax.dll` beside the executable or add that directory to the loader search
path. MSVC archives use the dynamic CRT (`/MD`); keep the application toolchain
and runtime configuration compatible. GNU/MinGW SDKs use their own import/static
archive formats and are not interchangeable with MSVC static archives.

On macOS the dylib identity is `@rpath/librax.dylib`; configure the application's
runtime search path for its deployment layout. On Linux the SONAME is
`librax.so`; configure an appropriate RUNPATH or system library installation.
CMake supplies build-tree runtime paths when linking these imported targets.

### pkg-config / Makefile (Unix)

```sh
make -C capi install PREFIX=/path/to/sdk
```

Export `PKG_CONFIG_PATH` before compiling:

```sh
export PKG_CONFIG_PATH=/path/to/sdk/lib/pkgconfig
cc app.c $(pkg-config --cflags --libs rax) -o app
```

The `.pc` and CMake package paths are relative to their installed location, so
SDKs can be moved. Static Unix linking requires platform system libraries:
macOS CoreFoundation/Security/SystemConfiguration, iconv, objc and pthread;
Linux pthread, dl, m, rt and util. `pkg-config --static --libs rax` supplies
these dependencies; use the explicit `librax.a` path when both library forms
are present and static linking is required. CMake's `rax::rax_static` selects
the archive unambiguously. Shared libraries still depend on OS libraries.

`make -C capi test` builds the library and compiles/runs the examples.

## Binary distributions

[The release workflow](../.github/workflows/capi-release.yml) runs on `v*` tag
pushes. Tags must be exactly `v<version>` from `capi/Cargo.toml`, for example
`v0.1.0`. To release a prerelease, use matching versions such as package
`0.2.0-rc.1` and tag `v0.2.0-rc.1`; GitHub marks it as a prerelease. Mismatched
or malformed tags fail before building. This does not change the independent
C ABI version (currently 1.3.0).

| SDK triple | Build/runtime-test host | Compilation baseline |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04 | x86-64; glibc |
| `aarch64-unknown-linux-gnu` | Ubuntu 24.04 ARM | generic AArch64; glibc |
| `x86_64-apple-darwin` | macOS 15 Intel | x86-64; deployment target 11.0 |
| `aarch64-apple-darwin` | macOS 15 Apple Silicon | generic AArch64; deployment target 11.0 |
| `x86_64-pc-windows-msvc` | Windows Server 2022 | x86-64; dynamic MSVC CRT |

The five targets above are mandatory. The following **experimental candidate**
lanes also build on each release run. A candidate archive is included only if
its complete Rust tests and relocated C/C++ shared/static consumers pass;
failure leaves that candidate absent without blocking the mandatory SDKs.

| Candidate SDK triple | Build and execution environment |
|---|---|
| `aarch64-pc-windows-msvc` | Native Windows 11 ARM64; generic AArch64, dynamic MSVC CRT |
| `x86_64-unknown-linux-musl` | Native x86-64 Rust/Alpine container; baseline x86-64 |
| `aarch64-unknown-linux-musl` | Native AArch64 Rust/Alpine container; generic AArch64 |
| `riscv64gc-unknown-linux-gnu` | Rust/Debian cross toolchain; `qemu-riscv64` with target sysroot |
| `powerpc64le-unknown-linux-gnu` | Rust/Debian cross toolchain; `qemu-ppc64le` with target sysroot |
| `powerpc64-unknown-linux-gnu` | Rust/Debian cross toolchain; `qemu-ppc64` with target sysroot; big-endian host ABI |
| `s390x-unknown-linux-gnu` | Rust/Debian cross toolchain; `qemu-s390x` with target sysroot; big-endian host ABI |

Linux candidate containers are pinned by manifest digest in the workflow. GNU
cross builds retain Rust/GCC target defaults. QEMU execution establishes
emulated user-space coverage, not testing on physical target hardware. Each
archive records its experimental status, execution command/version, compiler
host, and Rust test counts in `build-info.json`. Promotion to the mandatory set
is an explicit change to `tools/capi/targets.py` and the workflow.

musl SDKs include both `.so` and `.a` libraries and use the dynamic musl CRT
(`-C target-feature=-crt-static`). They require a musl environment; they are
not glibc libraries, and the static archive does not promise a fully static
downstream executable. 32-bit hosts remain blocked by `vm-memory`.

These are **host** triples, independent of the guest ISA being emulated.
Older Linux/glibc versions are not runtime-certified; exact ELF symbol-version
requirements are recorded in each SDK. macOS 11.0 is a compilation deployment
target, while execution is checked on the listed runner. Windows GNU/MinGW is
supported by CMake packaging but is not in the automated release matrix.

Release builds explicitly override the repository's development x86-64-v3
setting with `-C target-cpu=x86-64`. ARM builds select `generic`. The development
configuration is unchanged. Releases use stable Rust, locked dependencies,
`panic=unwind`, and the default interpreter-only C API feature set. They do not
include JIT, KVM, HVF or trace. Feature-specific SDKs require separate validation.

Archives are named `rax-capi-<version>-<triple>.tar.gz` (Unix) or `.zip` (Windows)
and contain:

- `include/rax.h` and `include/rax.hpp`;
- shared/static libraries under `lib/`, plus Windows `bin/rax.dll` and its import library;
- `lib/cmake/rax/` and `lib/pkgconfig/rax.pc` metadata;
- `README.md`, `build-info.json`, and an internal `SHA256SUMS` manifest.

An adjacent `.sha256` file checks the archive itself. Build metadata records
the commit, package/ABI versions, target, toolchain, feature set, compiler flags,
OS, dependency information and Cargo.lock checksum.

Every successful release lane runs the complete Rust C API tests and builds/runs C and
C++ consumers with both linkage modes after moving the SDK to a path containing
spaces and hiding the original Cargo output directory. Unix lanes also exercise
pkg-config linking. Empty, ignored, or filtered Rust test runs cannot produce an
SDK. After all lanes finish, the publishing job requires every mandatory SDK
and checks every present candidate archive/checksum pair before uploading to a
draft and publishing the release. Partial or corrupt candidate pairs fail
publication; candidate absence is permitted.
Failed uploads leave a draft that can be retried; published assets are not
replaced. PR and manual-dispatch runs build/test artifacts without publishing.

To reproduce a native SDK build (Python 3.11+, CMake, Rust, C/C++ toolchain,
and pkg-config on Unix):

```sh
RUSTUP_TOOLCHAIN=stable python3 tools/capi/package.py \
  --target aarch64-apple-darwin \
  --work-dir /tmp/rax-sdk-build --output-dir /tmp/rax-sdk-dist
```

The work directory must not already exist. Native builds require the target to
match the Rust compiler host. The four registered GNU/Linux cross targets use
`--cross-linux`, which requires a Linux build host, the matching cross GCC/G++
toolchain and sysroot under `/usr/<toolchain-triple>`, and QEMU user emulation.
The same execution command is used by Cargo, CTest, and pkg-config consumers.
`tools/capi/cross-linux.sh` and `tools/capi/musl.sh` reproduce the container
setup used by CI; see the workflow for image digests and mounts.

## Optional Cargo features

The `rax-capi` crate forwards optional engine capabilities:

| feature | effect |
|---------|--------|
| `jit`   | enables the SMIR native hot‑block JIT (x86‑64 host) |
| `kvm`   | KVM backend (x86‑64 Linux; not exposed via the C backend selector yet) |
| `hvf`   | Hypervisor.framework backend (macOS) |
| `trace` | verbose instruction tracing |

```sh
cargo build -p rax-capi --release --features jit
```

## API overview

| Area | Functions |
|------|-----------|
| Library | `rax_version`, `rax_version_string`, `rax_strerror` |
| Lifecycle | `rax_engine_open`, `rax_engine_open_config`, `rax_engine_close`, `rax_engine_reset` |
| Queries | `rax_engine_arch`, `rax_engine_mode`, `rax_engine_supports_stepping`, `rax_engine_errmsg` |
| Memory map | `rax_mem_map`, `rax_mem_unmap`, `rax_mem_protect`, `rax_mem_regions` |
| Memory access | `rax_mem_read`/`write`, `rax_mem_read_virt`/`write_virt`, `rax_mem_translate` |
| Registers | `rax_reg_size`, `rax_reg_read`/`write`, `rax_reg_read_u64`/`write_u64` |
| Execution | `rax_emu_start`, `rax_emu_step`, `rax_emu_stop`, `rax_emu_last_exit`, `rax_emu_icount` |
| Interrupts | `rax_interrupt`, `rax_nmi`, `rax_can_interrupt` |
| Hooks | `rax_hook_add_code`/`block`/`intr`/`io_in`/`io_out`/`mmio_read`/`mmio_write`/`invalid`/`mem`, `rax_hook_del` |
| Context | `rax_context_save`, `rax_context_restore` |
| Stateless analysis | `rax_decode`, `rax_analyze` |

### Stateless instruction analysis

`rax_analyze` lifts one instruction without opening an engine or mapping guest
memory. It returns the same decoded control-flow/target summary as `rax_decode`,
plus normalized architectural-register reads/writes, memory access and effective
address characteristics, condition-code effects, and direct constant/register
results when SMIR proves them. Rich effects currently cover x86-64, AArch64,
RV64 and Hexagon; the summary explicitly distinguishes complete, partial and
unsupported results.

The effect list is caller-owned and uses normal two-call negotiation: pass a
NULL array and zero capacity to obtain the required count, then pass that many
`rax_analysis_effect` records. Every returned structure carries its fixed ABI
size/version and reserved zero fields; no Rust pointer or allocation crosses the
C boundary. An undersized non-NULL array receives a deterministic prefix and
returns `RAX_ERR_BOUNDS` with `RAX_ANALYSIS_TRUNCATED` set.

### Memory model

Memory is a set of non‑overlapping, page‑aligned regions backed by demand‑paged
anonymous mappings; you may map regions at **any 64‑bit address**. The opener
pre‑maps one default region so the simplest programs "just work"; you can unmap
or remap it (at least one region must always remain mapped). Host accesses
(`rax_mem_read`/`write`) succeed for any mapped range regardless of permissions;
virtual accesses translate through the guest's current paging state.

### Registers

Each architecture has its own register‑id space. The header exposes both
**family macros** (e.g. `RAX_X86_GPR64(i)`, `RAX_ARM64_X(i)`, `RAX_X86_ZMM(i)`)
that give complete coverage, and **named aliases** (`RAX_X86_REG_RAX`, …) that
evaluate to the same numbers. Values are little‑endian, sized to the register's
natural width (`rax_reg_size`); vector registers are raw byte arrays. x86
sub‑register writes follow architectural semantics (writing `EAX` zero‑extends
into `RAX`; `AX`/`AL`/`AH` preserve the rest).

### Execution & stop reasons

`rax_emu_start(begin, until, timeout_us, count)` runs until the first stop
condition; `rax_emu_last_exit` reports why (`rax_exit.reason` is one of the
`RAX_STOP_*` values: count/until/timeout/stopped/hlt/io/mmio/exception/…). The
call returns `RAX_OK` for any clean stop and an error status only for an
unrecoverable fault.

### Hooks

Code and block hooks fire per instruction / per basic‑block entry and require a
stepping‑capable backend. Interrupt, port‑I/O, MMIO, and invalid‑instruction
hooks service the corresponding exits and let execution continue (e.g. an
`io_in` hook supplies the value the guest reads). **Per‑access memory hooks**
(`rax_hook_add_mem`, filtered by `RAX_HOOK_MEM_READ`/`WRITE`/`FETCH` and an
address range) fire once for every data load, store, and instruction fetch the
guest makes, reporting the address, size, and value — ideal for watchpoints and
memory tracing. All callbacks receive the engine handle and may freely re‑enter
the API, including `rax_emu_stop`: memory accesses are recorded during execution
and dispatched at instruction boundaries, so no callback ever runs while the
engine is internally borrowed. Memory hooks require a recording‑capable backend
(x86‑64 and AArch64 today; query via the `RAX_ERR_UNSUPPORTED` result of
`rax_hook_add_mem`).

## Architecture capability matrix

| Architecture | `RAX_ARCH_*` | registers / memory / run | single‑step + code/block hooks |
|--------------|--------------|--------------------------|--------------------------------|
| x86 / x86‑64 | `X86`        | ✅                       | ✅                              |
| AArch64      | `ARM64`      | ✅                       | ✅                              |
| RISC‑V (RV64)| `RISCV64`    | ✅                       | ✅                              |
| AArch32 / ARMv7 | `ARM`     | ✅                       | run‑to‑exit                    |
| Cortex‑M     | `CORTEXM`    | ✅                       | run‑to‑exit                    |
| Hexagon      | `HEXAGON`    | ✅                       | run‑to‑exit                    |

All architectures support the full register, memory, run, reset, and context
API. Instruction‑granular control (`count`/`until`, code/block hooks, and
`rax_emu_step`) is available on every backend that advertises
`rax_engine_supports_stepping` — x86‑64, AArch64, and RISC‑V today; the
remaining architectures run to the next exit. Query at runtime rather than
assuming.

## Threading & safety

An `rax_engine` handle is **not** thread‑safe: drive a single handle from one
thread at a time. Distinct handles are independent and may run concurrently on
different threads. The library never takes ownership of caller buffers; all data
is copied. Every entry point validates its arguments, and a panic in engine code
is contained and reported as `RAX_ERR_INTERNAL` rather than crossing the FFI
boundary.

## Examples

See `examples/`:

- `x86_64_basic.c` — minimal open/load/run/read.
- `x86_64_hooks.c` — code + block hooks and stopping from a hook.
- `x86_64_step.c` — single‑stepping instruction by instruction.
- `x86_64_io.c` — servicing guest port I/O with hooks.
- `x86_64_memhook.c` — per-access memory read/write watchpoints.
- `mem_and_context.c` — sparse mapping, region enumeration, snapshots.
- `cpp_engine.cpp` — the C++ wrapper with a lambda hook and a context round‑trip.
- `cpp_registers.cpp` — scalar/byte-buffer register agreement across host byte orders.

## License

MIT (matching the RAX engine).
