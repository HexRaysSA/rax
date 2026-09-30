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

This is the CPU-engine ABI. Linux process emulation, ELF/sysroot loading,
syscall servicing, guest processes/signals/IPC, and guest `ptrace` belong to
the separate Rust `rax::user::linux` subsystem and `rax-user` binary; they
are not exported by `librax`. See [Linux programs](../docs/getting-started/linux-programs.md)
for that interface and its partial i386 compatibility. `librax` provides only
the CPU half of process emulation: `RAX_MODE_USER` (ABI 1.5) runs unprivileged
code and returns its system calls and exceptions to the embedder; see
[User-mode execution](#user-mode-execution-abi-15).

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
C ABI version (currently 1.8.0).

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

### Debug symbols

The shipped libraries stay stripped, so every lane also publishes
`rax-capi-<version>-<triple>-debug.tar.gz` (or `.zip`) built from the same
compilation, carrying the debug information split out of that SDK:

| SDK triple | Debug archive contents |
|---|---|
| Linux (glibc and musl) | `lib/librax.so.debug` and the unstripped `lib/librax.a` |
| macOS | `lib/librax.dylib.dSYM/` and the unstripped `lib/librax.a` |
| Windows MSVC | `bin/rax.pdb` (the static `rax.lib` keeps its own CodeView records) |

Both halves carry the same `build-info.json`, whose `debug_info` field lists
the sidecars and `debug` records the level, plus its own `SHA256SUMS`. The
debug archive is not needed to use the SDK and can be downloaded later:
symbols are matched to the shipped library by the GNU debug link, the Mach-O
UUID, or the PDB signature, so the exact release archive stays usable
unchanged.

Releases are built with Cargo's `limited` debug level: function names, source
files and line numbers, which is what symbolicated backtraces, profilers and
crash reports need. Local variable and full type descriptions are not
included. Producing them would require fusing the engine crate under fat LTO
with complete DWARF, which needs far more memory than a release runner has;
build the crate yourself with `debug = 2` if you need to inspect values.

- **GDB/LLDB on Linux**: unpack the debug archive so `librax.so.debug` sits
  beside the installed `librax.so`, or point the debugger at it with
  `set debug-file-directory` / `target symbols add`.
- **LLDB on macOS**: keep `librax.dylib.dSYM` next to the `dylib`, or register
  it with `target symbols add librax.dylib.dSYM`. Spotlight also resolves it by
  UUID from anywhere it has indexed.
- **Windows**: add the archive's `bin/` to `_NT_SYMBOL_PATH`, or load
  `rax.pdb` from the debugger.
- **Static linking**: replace the SDK's stripped `lib/librax.a` with the
  unstripped copy from the debug archive; the two are otherwise identical.

Every successful release lane runs the complete Rust C API tests and builds/runs C and
C++ consumers with both linkage modes after moving the SDK to a path containing
spaces and hiding the original Cargo output directory. Unix lanes also exercise
pkg-config linking. Empty, ignored, or filtered Rust test runs cannot produce an
SDK. Consumers are built and executed against the stripped libraries the SDK
archive actually ships, after the debug information has been split out. After
all lanes finish, the publishing job requires every mandatory SDK and its debug
archive, and checks every present candidate's archive/checksum pairs before
uploading to a draft and publishing the release. A lane that delivers a partial
or corrupt set fails publication; candidate absence is permitted.
Failed uploads leave a draft that can be retried; published assets are not
replaced. PR and manual-dispatch runs build/test artifacts without publishing.

To reproduce a native SDK build (Python 3.11+, CMake, Rust, C/C++ toolchain,
and pkg-config on Unix):

```sh
RUSTUP_TOOLCHAIN=stable python3 tools/capi/package.py \
  --target aarch64-apple-darwin \
  --work-dir /tmp/rax-sdk-build --output-dir /tmp/rax-sdk-dist
```

This writes both the SDK and its `-debug` archive. The work directory must not
already exist. Native builds require the target to match the Rust compiler host. The four registered GNU/Linux cross targets use
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
| Execution | `rax_emu_start`, `rax_emu_step`, `rax_emu_stop`, `rax_emu_last_exit`, `rax_emu_last_fault`, `rax_emu_last_exception`, `rax_emu_icount` |
| Interrupts | `rax_interrupt`, `rax_nmi`, `rax_can_interrupt` |
| Hooks | `rax_hook_add_code`/`block`/`intr`/`io_in`/`io_out`/`mmio_read`/`mmio_write`/`invalid`/`mem`/`syscall`, `rax_hook_del` |
| Context | `rax_context_save`, `rax_context_restore` |
| User mode (ABI 1.5) | `RAX_MODE_USER`, `rax_hook_add_syscall`, `RAX_STOP_SYSCALL`, `rax_emu_last_exception` |
| Stateless analysis | `rax_decode`, `rax_instruction_info`, `rax_analyze` (C++: `rax::decode`, `rax::instructionInfo`, `rax::analyze`) |

### Stateless instruction analysis

`rax_analyze` lifts one instruction without opening an engine or mapping guest
memory. It returns the same decoded control-flow/target summary as `rax_decode`,
plus normalized architectural-register reads/writes, memory access and effective
address characteristics, condition-code effects, and direct constant/register
results when SMIR proves them. Rich effects currently cover x86-64, AArch64,
RV64 and Hexagon; the summary explicitly distinguishes complete, partial and
unsupported results. x86 decodes in the code size the mode selects:
`RAX_MODE_64` (the default), `RAX_MODE_32`, or `RAX_MODE_16` (since ABI 1.5;
earlier versions decoded all x86 as 64-bit code, so `40 90` was one 2-byte
instruction rather than `inc eax`). 16- and 32-bit code decodes for length and
control flow only: `pc` is the offset in the code segment, relative targets
wrap to the operand size, far jumps and calls have no static target, and
`rax_analyze` reports the effects as unsupported.

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
into `RAX`; `AX`/`AL`/`AH` preserve the rest). Writing `RFLAGS`/`EFLAGS`/`FLAGS`
replaces flags the core would otherwise still derive from the last ALU result.

ABI 1.5 adds register ids for state the engine models but earlier versions did
not expose:

| Architecture | Ids | Notes |
|---|---|---|
| x86 | `RAX_X86_ST(i)`, `RAX_X86_REG_FPCW`/`FPSW`/`FPTAG`/`FOP`/`FIP`/`FDP`, `RAX_X86_REG_MXCSR` | ST(i) is stack‑relative in the exact 80‑bit format (10 bytes); writing it tags the register by its encoding; `FPSW` carries TOP; MXCSR writes with reserved bits return `RAX_ERR_ARG` |
| x86 | `RAX_X86_REG_KERNEL_GS_BASE`, `TSC_AUX`, `PKRU` | read by `SWAPGS`, `RDTSCP`/`RDPID`, `RDPKRU` |
| x86 | `RAX_X86_SEG_ATTR(i)`, `RAX_X86_REG_TR_ATTR`, `RAX_X86_REG_LDTR_ATTR` | VMX access‑rights layout (Intel SDM Vol. 3C, Table 26‑2); writing CS can select 64‑bit, compatibility, or legacy mode |
| AArch64 | `RAX_ARM64_REG_TPIDR_EL0` … `RAX_ARM64_REG_CNTV_CVAL_EL0` | thread pointers, banked `SP_EL0`/`SP_EL1`, EL1 exception/translation registers, generic timers |
| AArch32 | `RAX_ARM_D(i)` (D0–D31), `RAX_ARM_Q(i)` (Q0–Q15) | D0–D15 overlay S0–S31 |
| RISC‑V | `RAX_RISCV_V(i)`, `RAX_RISCV_CSR(n)`, `RAX_RISCV_REG_PRIV` | V0–V31 (16 bytes, VLEN 128); CSR *n* as the hart implements it, written with its WARL rules (`vl`/`vtype` are writable here; use `mstatus`/`mie`/`mip` rather than the `sstatus`/`sie`/`sip` views; an unimplemented CSR reports `RAX_ERR_REG`); privilege 0, 1, or 3 (a user‑mode engine stays at 0); all saved in contexts |
| Cortex‑M | `RAX_CM_REG_SP`, `RAX_CM_REG_VTOR`, `CCR`, `SHCSR`, `CFSR`, `HFSR`, `BFAR`, `AIRCR`, `SHPR1`–`SHPR3` | SP is the active stack pointer; the System Control Block registers the core models (the System Control Space is not memory‑mapped) |

### Execution & stop reasons

`rax_emu_start(begin, until, timeout_us, count)` runs until the first stop
condition; `rax_emu_last_exit` reports why (`rax_exit.reason` is one of the
`RAX_STOP_*` values: count/until/timeout/stopped/hlt/io/mmio/exception/syscall/…).
The call returns `RAX_OK` for any clean stop and an error status only for an
unrecoverable fault. An unbounded run stops only at a guest event or an
explicit condition; a backend's periodic yield is not reported as a halt. A
vCPU that stopped in `HLT`, `WFI`, or `WFE` reports `RAX_STOP_HLT`;
`rax_emu_start` resumes it at `begin` (since ABI 1.5; earlier versions kept
it halted until a reset or restore). A system‑mode RV64 engine stops at
`ECALL` with `RAX_STOP_SHUTDOWN` (with `a7` = 93 and a nonzero `a0`, the
riscv-tests failure convention, `RAX_STOP_ERROR`) and at `EBREAK` with
`RAX_STOP_DEBUG`.

The engine an `arch`/`mode` pair selects owns no devices: every mapped byte is
ordinary memory (the RV64 core no longer claims `0x1000_0000` as a UART), and
the choice does not depend on the process environment (`RAX_MACHINE`, which
selects board vCPUs for full‑machine runs, is ignored).

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
`rax_hook_add_mem`). **System‑call hooks** (`rax_hook_add_syscall`) service
the system calls of a user‑mode engine; see below.

## Architecture capability matrix

| Architecture | `RAX_ARCH_*` | registers / memory / run | single‑step + code/block hooks | user mode (`RAX_MODE_USER`) |
|--------------|--------------|--------------------------|--------------------------------|-----------------------------|
| x86 / x86‑64 | `X86`        | ✅                       | ✅                              | ✅ 64‑bit and 32‑bit compatibility mode |
| AArch64      | `ARM64`      | ✅                       | ✅                              | ✅ EL0                       |
| RISC‑V (RV64)| `RISCV64`    | ✅                       | ✅                              | ✅ U‑mode                    |
| AArch32 / ARMv7 | `ARM`     | ✅                       | ✅                              | ✅ ARM/Thumb EL0 (ABI 1.7)   |
| Hexagon      | `HEXAGON`    | ✅                       | ✅ (per packet)                 | —                           |
| Cortex‑M     | `CORTEXM`    | ✅ Cortex‑M4, no FPU     | ✅                              | —                           |

Every architecture supports the full register, memory, run, reset, and
context API, and instruction‑granular control (`count`/`until`, code/block
hooks, `rax_emu_step`; `rax_engine_supports_stepping` reports it). Hexagon
steps whole packets.

The ARM engines take exceptions architecturally through the guest's vector
table — AArch32 `SVC` and `BKPT` through SCTLR.V's vectors, Cortex‑M `SVC`,
`BKPT` (escalated to HardFault), and the UsageFaults (`UNALIGNED`,
`DIVBYZERO`, `INVSTATE`, and `INVPC` on a bad `EXC_RETURN`, escalated to
HardFault while SHCSR leaves them disabled) through `VTOR` — while a memory
fault or an UNDEFINED instruction is returned at the faulting instruction,
which does not retire (`RAX_ERR_FAULT` with `rax_emu_last_fault`, or the
invalid‑instruction hook). `WFI`/`WFE` stop with `RAX_STOP_HLT`, and a
Cortex‑M lockup is an error.

`RAX_ARCH_CORTEXM` (since ABI 1.5) is a Cortex‑M4: the Armv7E‑M Thumb
instruction set with the DSP extension and the Armv7‑M exception model
(8‑byte frame alignment per CCR.STKALIGN, priority escalation, `EXC_RETURN`
through `BX`, `POP`, `LDM`, or `LDR`). It has no Floating‑point Extension —
FP instructions are invalid instructions and `RAX_CM_S(i)`/`RAX_CM_REG_FPSCR`
report `RAX_ERR_REG` — and its System Control Space (NVIC, SCB, SysTick) is
reached through the `RAX_CM_REG_*` registers, not memory: addresses in
`0xE000_E000` are ordinary memory. It is little‑endian and Thumb‑only;
`RAX_MODE_ARM` and `RAX_MODE_BIG_ENDIAN` are rejected. Its instruction
semantics are checked against QEMU's Cortex‑M4 (`tools/cortex-m-diff`).

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
- `x86_64_user.c` — user mode: servicing `write`/`exit` system calls, enforced page permissions.
- `mem_and_context.c` — sparse mapping, region enumeration, snapshots.
- `cpp_engine.cpp` — the C++ wrapper with a lambda hook, a context round‑trip, and a failed hook registration that releases its callback.
- `cpp_registers.cpp` — scalar/byte-buffer register agreement across host byte orders.
- `cpp_fault_recovery.cpp` — typed sparse fetch recovery with retirement checks.
- `cpp_user_arm64.cpp` — AArch64 EL0 with `hookSyscall`, `TPIDR_EL0`, `BRK` via `lastException()`, and `rax::decode`/`rax::analyze`.

## License

The C API wrapper is [MIT-licensed](LICENSE). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the engine's third-party
components. Include both files when redistributing RAX binaries.

SDK and debug archives include these files. CMake installs them under
`share/licenses/rax`.


### Sparse guest execution and fault diagnostics (ABI 1.4)

`rax_emu_last_fault` / C++ `Engine::lastFault()` returns a versioned
`rax_fault_info`. Initialize `struct_size` and `version` before the C call.
Only `RAX_FAULT_UNMAPPED` with `RAX_FAULT_ADDRESS_VALID` identifies missing
physical backing eligible for an external map-and-retry operation. Its address
is the first inaccessible byte, which can be on the next instruction page.
Permission, invalid-instruction, and other faults must not be "recovered" by
mapping a guessed page. A width of zero means the backend cannot supply it.

The query does not clear error text. Host register/memory operations preserve
the record; run/step, reset, and context restoration clear it. Unknown query
versions and short output buffers fail without writing output; extension tails
remain untouched. Existing ABI structures and callback signatures are unchanged.
Code/block hooks remain **pre-execution** notifications, not proof of retirement.
`retired_instructions` counts completed steps in the last run/step, including
I/O stops where `rax_exit.value` has another meaning. Failed fetches/accesses
retire nothing; architecturally completed REP elements remain committed for
retry. Mapping changes preserve the cumulative `rax_emu_icount`; reset/context
restoration starts its count again at zero.

### User-mode execution (ABI 1.5)

`RAX_MODE_USER` runs guest code the way an operating system runs a process —
x86 CPL 3 in 64‑bit (`RAX_MODE_64`) or 32‑bit compatibility (`RAX_MODE_32`)
mode, AArch64 EL0, RV64 U‑mode, or AArch32 EL0 (ABI 1.7) — and makes the embedder that operating
system. It is the engine‑level counterpart of `rax-user`: librax traps system
calls and exceptions through that engine API. Full-process execution uses the
separate `rax_process_*` API described below.

```c
rax_engine_config cfg = {sizeof cfg, RAX_ARCH_ARM64, RAX_MODE_USER};
cfg.mem_base = 0x400000; cfg.mem_size = 0x10000;
cfg.mem_perms = RAX_PROT_READ | RAX_PROT_EXEC;      /* enforced in user mode */
rax_engine_open_config(&cfg, &e);
rax_hook_add_syscall(e, on_svc, &os, NULL);          /* X8 = number, X0.. = args */
rax_emu_start(e, 0x400000, RAX_NO_ADDR, 0, 0);
```

- **Address space.** Every guest load, store, and fetch is checked against the
  region's `RAX_PROT_*` bits. A violation or unmapped access fails the run
  with `RAX_ERR_FAULT` and a `rax_fault_info` of kind `PERMISSION` or
  `UNMAPPED` carrying the exact first inaccessible byte; the instruction does
  not retire, so `rax_mem_protect`/`rax_mem_map` and a retry resume it.
  Virtual accessors and `rax_mem_translate` apply the same checks; physical
  host access does not.
- **System calls.** `SYSCALL`/`SYSENTER`, `SVC`, and `ECALL` complete (and
  count as one executed instruction) with the PC at the resume address. The
  first syscall hook — `(engine, pc, insn, imm, user)`, `insn` a
  `RAX_SYSCALL_INSN_*` class, `imm` the `SVC` immediate — services the call
  through the register API; without one the run stops with `RAX_STOP_SYSCALL`
  (`address` = the instruction, `size` = its length, `port` = the class,
  `intno` = the immediate). x86 `SYSCALL` sets RCX and R11 architecturally.
- **Exceptions.** x86 IDT events (`#UD`, `#GP`, `INT n`, `INT3`, …), AArch64
  `BRK` and UNDEFINED instructions, and RV64 `EBREAK`, illegal instructions,
  and misaligned fetches or AMOs are not delivered through guest vector tables. The
  PC moves to the architectural return address and the interrupt hook
  receives the vector (x86 IDT vector, AArch64 `ESR_EL1.EC`, RISC‑V `mcause`)
  and may change the PC; without a hook the run stops with
  `RAX_STOP_EXCEPTION`. `rax_emu_last_exception` returns a versioned
  `rax_exception_info` with the raising PC, return PC, and syndrome (x86 error
  code, AArch64 ISS, RISC‑V `mtval`); initialize `struct_size` and `version`
  as for `rax_emu_last_fault`. An undefined instruction that stops the run is
  also reported as `RAX_FAULT_INVALID_INSTRUCTION`.
- **Environment.** Open and reset install the unprivileged state (x86: the
  Linux `execve` segments — CS `0x33`, or `0x23` in compatibility mode —
  `EFER.SCE`, SSE/AVX/AVX‑512 enabled). There are no asynchronous interrupts:
  `rax_interrupt`/`rax_nmi` return `RAX_ERR_UNSUPPORTED`. x86 `HLT` and other
  privileged instructions raise `#GP`; AArch64 EL1 system registers, RV64
  higher‑privilege CSRs, and the RV64 counters are UNDEFINED/illegal. Register
  writes are not privilege‑checked. Contexts record the mode, so a restored
  user‑mode context yields a user‑mode engine with its permissions.

Context format: ABI 1.5 writes context format 2, whose x86 state keeps the x87
registers in their exact 80‑bit encoding. Contexts written by ABI 1.4 and
earlier (format 1, binary64 x87 registers) still restore, each register
widened exactly; ABI 1.4 libraries cannot read format 2.

AArch32 user engines reuse `rax::user::cpu::arm::A32UserCpu` with the C API's
mapped-memory adapter. ARM and Thumb interworking, IT state, SVC immediates,
FP/SIMD, and TLS follow that executor's implemented instruction set. This does
not imply complete Thumb-2 or NEON coverage. Big-endian user mode is rejected.
`RAX_ARM_REG_TPIDRURW` and `RAX_ARM_REG_TPIDRURO` are 4-byte host-accessible
registers; guest writes to TPIDRURO remain privileged. CPSR writes retain user
flags and ARM/Thumb state but cannot select a privileged mode or big-endian data.
BKPT reports exception class `0x38` and its immediate as the syndrome, matching
the AArch32 exception definition used by the Linux personality.

ABI 1.7 writes context format 3 only for AArch32 user engines. It adds a
length-prefixed, 20-byte image of both TLS registers and the local exclusive
monitor after the generic emulator image. Memory-map reconstruction and context
restore preserve that state. Instruction-observation boundaries retain the
monitor; a syscall or exception clears it. Other engines continue to write
format 2, and existing format 1/2 readers remain supported. An older library
cannot restore an AArch32 user context.

| Assumption | Basis | Dependent behavior | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A32-1: C API and process execution use the same instruction semantics. | Both use `A32UserCpu`; only memory storage differs. | ARM/Thumb execution and traps. | C API interworking/IT, privilege, SVC/BKPT tests plus existing executor tests. | Tested in the native C API suite. |
| A32-2: A host observation boundary is not a guest context switch. | Instruction stepping must permit LDREX followed by STREX. | Exclusive-monitor persistence. | LDREX, map an unrelated page, save/restore, then STREX must succeed; a trap must clear it. | Tested in the native C API suite. |
| A32-3: Existing context consumers retain their format. | Only the new AArch32 user mode emits format 3. | Context compatibility. | Existing format 1/2 tests plus malformed format-3 and system-to-user restore tests. | Tested in the native C API suite. |

### Native x86 instruction metadata (ABI 1.5)

`rax_instruction_info` and `rax::instructionInfo` expose a stateless projection
of RAX's native x86 decoder. There is no external decoder dependency. Mode is
explicit (`RAX_MODE_16`, `RAX_MODE_32`, `RAX_MODE_64`); zero selects 64-bit mode,
and a user-mode engine's `RAX_MODE_USER` mode is accepted as its code size.
`rax_decode` uses the same projection for x86. `ret` denotes near C2/C3 returns;
far returns and interrupt returns have distinct mnemonics. Return stack adjustment
includes the unsigned immediate cleanup. Instruction bytes are read anew per call.

Initialize `struct_size` and `abi_version`. The 576-byte v1 record contains the
unchanged 40-byte `rax_decoded`, inline strings and up to five 96-byte operands.
Larger caller tails remain untouched; smaller or unknown versions are rejected.
`BASIC_COMPLETE` means mnemonic/length/flow are represented; `OPERANDS_COMPLETE`
means explicit operands are represented, not implicit effects or full execution
semantics. Unsupported native metadata is not evidence of unsupported execution.
For unprojected encodings, `rax_decode`'s decoder for the same code size (the SMIR
projection in 64-bit mode, the legacy length decoder in 16- and 32-bit mode) can
supply length/flow with both completeness flags clear and `UNREPRESENTED` set.
Legacy modes never pass through the long-mode lifter. Unrepresented, invalid and truncated encodings never acquire
invented mnemonics. Consumers must inspect completeness flags.

The C API tests exercise prefixes, modes, truncation, memory/register branch
operands and size/version negotiation. The installed SDK consumer builds the C
layout guard and executes the C++ example with both static and shared libraries
on the existing platform matrix.

### Syscall observation (ABI 1.6)

`rax_emu_last_syscall` (`Engine::lastSyscall()` in C++) returns a versioned
`rax_syscall_info` record. Initialize `struct_size` and `version` to
`sizeof(rax_syscall_info)` and `RAX_SYSCALL_INFO_VERSION`. Check
`RAX_SYSCALL_VALID` before using the fields. The record captures the instruction
class, immediate, instruction address and length in bytes, and the architectural
resume PC before a syscall hook modifies registers. It describes the most recent
syscall in the current or last run/step, even when a hook serviced the call and
execution later stopped for another reason. A new run/step, reset, or successful
context restore clears it. It is transient observation state, not context data.
No guest ABI argument decoding or host OS syscall forwarding is implied.

The query copies a fixed 40-byte record in O(1) time and space. Existing
`rax_exit` layout and syscall-hook signatures are unchanged.

### Full PE processes (ABI 1.8)

`rax_process_open_image` and `rax::Process` execute a Windows process using the
existing PE loader, thread scheduler, exception handling, and built-in DLL/CRT
services. PE32 x86 and PE32+ x64/ARM64 run on Windows, macOS, and Linux hosts.
This API does not yet export the Linux ELF or Darwin Mach-O personalities.

```cpp
rax::Process process(executable_bytes,
    R"({"guest_path":"C:\\sample.exe","memory_bytes":134217728,
         "slice_instructions":4096,"console_capacity":1048576})");
process.feedStdin(input.data(), input.size());
auto result = process.run(10000, 1000000); // turns and microseconds
std::string snapshot = process.infoJson();
auto output = process.readOutput(RAX_PROCESS_STDOUT, 1048576);
```

See `examples/cpp_process.cpp` for a complete executable example. Supplied DLLs
use `rax_process_image` records (or `rax::Process::Image`), containing guest paths
and copied bytes. The profile denies guest disk operations and host dependency
searches. stdin/stdout/stderr are bounded captured streams. Input exhaustion is
EOF. The guest can receive input again after the caller appends it; pending
asynchronous console reads are not implemented by this finite-input profile.

`run` reports budget exhaustion, blocked threads, persistent cancellation,
timeout, process exit, or an emulator/personality failure. The last two are
terminal and cached. A nonzero guest exit code is distinct from an API error.
Turn and time limits are checked at scheduler boundaries: a turn is not an
instruction, and the deadline is cooperative rather than hard preemption.
`setCancelled(true)` may overlap execution; clear it explicitly to resume.

Inspection schema 1 contains threads, base Windows CONTEXT availability, modules,
half-open memory mappings, guest committed-memory use, console counts, and
capabilities. Addresses are hexadecimal strings. Memory writes preserve guest
permissions, commit no bytes on an access fault, and invalidate native code
caches. Context writes use the existing architecture-specific validated Windows
CONTEXT restoration; extended XSAVE components are not exposed by that format.
No whole-process checkpoint or fork is advertised.

Every handle owns a dedicated runtime thread, which constructs and destroys all
thread-affine personality state. Calls may originate on different caller threads
but must be serialized except cancellation. Concurrent ordinary calls fail with
`RAX_ERR_STATE`; close requires all calls to have returned. No native caller
callback or caller buffer is retained. API failures have thread-local diagnostic
text available through `rax_process_last_error`; guest failures have a diagnostic
in inspection JSON. Query/fill lengths include a trailing NUL for text/JSON and
exclude it for binary context data. Failed short fills preserve the destination.

Limits and defaults are specified beside the C declarations in `include/rax.h`.
The guest memory bound excludes parser buffers, supplied image storage, runtime
bookkeeping, and the owner thread's host stack. Loading is bounded by input sizes,
not by the later run deadline. The full-process ABI assumes finite console input
and immutable supplied dependencies (P1/P2 in `docs/embedding.md`); mutation of a
virtual disk and persistent asynchronous console reads require additional APIs.
