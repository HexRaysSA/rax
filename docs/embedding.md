[← Documentation home](../README.md)

# Embedding `rax` through C and C++

The `capi` workspace member builds `librax`, the embeddable interface to the software emulation engine. This page explains how the embedding surface relates to the root VM application. The normative ABI reference remains [`capi/README.md`](../capi/README.md) and the hand-authored header `capi/include/rax.h`.

## Scope

The command-line `rax` application builds complete machines: guest memory, boot loaders, devices, serial console, snapshots, and selected hardware backends. `librax` instead exposes engine-level control for embedding:

- open an architecture/mode engine;
- map arbitrary guest memory;
- load code and data;
- read and write architecture registers;
- run, bound, stop, or step execution where supported;
- inspect stop reasons;
- service I/O and MMIO exits;
- install code, block, interrupt, invalid-instruction, and memory hooks;
- save and restore engine contexts;
- decode or analyze an instruction without opening an engine.

It is not automatically the same interface as the root PC/AArch64 virtual machines. Device construction, Linux boot protocols, and all root CLI backend combinations are not implied by the C ABI.

The separate Rust `rax::user::linux` subsystem and `rax-user` binary supply
Linux ELF loading, syscall servicing, processes, signals, sockets, IPC, and
guest ptrace. `librax` does not export that Linux personality or its process
scheduler. An engine accepting 32-bit x86 code is a different contract from
`rax-user`'s partial i386 syscall compatibility.

## Build

```sh
cargo build -p rax-capi --release
```

Artifacts are written to the normal Cargo target directory and include:

```text
librax.a
librax.so       # Linux
librax.dylib    # macOS
```

The dynamic library is the simplest direct link because it carries its Rust/system dependency linkage:

```sh
cc -I capi/include app.c \
   -L target/release -lrax \
   -o app

c++ -std=c++17 -I capi/include app.cpp \
    -L target/release -lrax \
    -o app
```

Static linking requires platform system libraries. Use the supplied CMake or pkg-config integration rather than copying a stale list into a downstream build.

## CMake

Build and install:

```sh
cmake -S capi -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build
cmake --install build
```

Consume it:

```cmake
find_package(rax REQUIRED)
target_link_libraries(myapp PRIVATE rax::rax)
```

For the static target:

```cmake
target_link_libraries(myapp PRIVATE rax::rax_static)
```

The imported static target carries the platform libraries expected by the supplied package definition.

## pkg-config and Make

```sh
make -C capi install PREFIX=/usr/local
cc app.c $(pkg-config --cflags --libs rax) -o app
```

The C API’s own test entrypoint builds the library and compiles/runs its examples:

```sh
make -C capi test
```

Treat an example build as an integration result for that compiler/linker/runtime combination, not as ABI compatibility evidence for every downstream toolchain.

## Minimal C flow

The normal lifecycle is:

1. open an engine;
2. map or use mapped memory;
3. write code/data;
4. initialize registers;
5. execute;
6. inspect exit state/registers;
7. close the engine.

Representative code:

```c
#include <rax.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    rax_engine *engine = NULL;
    rax_status st = rax_engine_open(RAX_ARCH_X86, RAX_MODE_64, &engine);
    if (st != RAX_OK) {
        fprintf(stderr, "open: %s\n", rax_strerror(st));
        return 1;
    }

    const unsigned char code[] = {
        0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, /* mov rax,0x1337 */
        0x48, 0xFF, 0xC0,                         /* inc rax */
        0xF4                                      /* hlt */
    };

    st = rax_mem_write(engine, 0x1000, code, sizeof(code));
    if (st == RAX_OK)
        st = rax_reg_write_u64(engine, RAX_X86_REG_RSP, 0x8000);
    if (st == RAX_OK)
        st = rax_emu_start(engine, 0x1000, RAX_NO_ADDR, 0, 0);

    uint64_t value = 0;
    if (st == RAX_OK)
        st = rax_reg_read_u64(engine, RAX_X86_REG_RAX, &value);

    if (st != RAX_OK)
        fprintf(stderr, "engine: %s\n", rax_engine_errmsg(engine));
    else
        printf("RAX = 0x%llx\n", (unsigned long long)value);

    rax_engine_close(engine);
    return st == RAX_OK ? 0 : 1;
}
```

Production code should check every status. A clean execution stop is reported through the exit record; only unrecoverable engine/API failures are returned as error statuses.

## C++17 wrapper

`capi/include/rax.hpp` provides a header-only RAII wrapper with typed access, exceptions, and lambda hooks:

```cpp
#include <rax.hpp>

rax::Engine engine(rax::Arch::X86, RAX_MODE_64);
engine.memWrite(0x1000, code);
engine.hookCode([](rax::Engine&, std::uint64_t pc, std::uint32_t size) {
    // Observe one instruction on a stepping-capable engine.
});
engine.setReg(RAX_X86_REG_RSP, std::uint64_t{0x8000});
engine.start(0x1000);
auto result = engine.regU64(RAX_X86_REG_RAX);
```

The wrapper improves lifetime and error handling; it does not make one engine safe for concurrent use.

## Optional C API features

The C API forwards selected engine features under names that differ from the root package:

| Feature | Current documented effect |
|---|---|
| `jit` | enables the native SMIR hot-block JIT for the supported embedding path |
| `kvm` | builds KVM capability, but the C backend selector does not yet expose KVM |
| `hvf` | builds Hypervisor.framework capability |
| `trace` | enables verbose instruction tracing |

Example:

```sh
cargo build -p rax-capi --release --features jit
```

Do not translate root `smir-jit` commands mechanically into `rax-capi`; inspect `capi/Cargo.toml` and the C API README for the current forwarded names.

## ABI contract

The C interface is defined by `capi/include/rax.h` rather than generated from Rust layout. The current contract includes:

- frozen status and enum values;
- sized/versioned or reserved structures for extension;
- no Rust allocation or pointer escaping through returned analysis records;
- caller-owned input/output buffers;
- explicit two-call sizing for variable-length outputs;
- error strings and engine-specific diagnostic messages;
- panic containment at every FFI entrypoint.

The root release profile keeps `panic = "unwind"` so panics can be caught and converted to `RAX_ERR_INTERNAL`. Building an aborting variant would invalidate that guarantee.

ABI stability does not imply semantic stability for every newly implemented instruction. Version the library and document behavior changes separately from numeric ABI compatibility.

## Memory model

The embedding API manages non-overlapping, page-aligned guest regions. The engine opens with a default mapped region for simple examples; callers can enumerate, unmap, protect, and create regions subject to the API invariants.

Important distinctions:

- host API reads/writes operate on mapped guest storage according to the host-access contract;
- guest virtual reads/writes and translation depend on guest paging state;
- permissions apply to guest execution/access semantics and are not identical to the host helper API;
- regions can be placed at arbitrary 64-bit guest addresses, but mappings may not overlap;
- at least one region must remain mapped under the current opener contract.

Validate all address-plus-length operations for overflow in downstream code before calling the API.

## Registers

Each architecture owns a register-ID namespace. The header exposes:

- family macros for indexed register sets;
- named aliases for common registers;
- natural-width query through `rax_reg_size`;
- byte-array access for vector registers;
- convenience `u64` accessors for scalar values.

Values are represented little-endian at the byte-buffer boundary. Architecture-specific subregister rules still apply—for example, x86 `EAX` writes zero-extend into `RAX`, while narrower writes preserve unaffected bits.

Do not hard-code register widths from one architecture into architecture-neutral embedding code. Query them.

## Execution and exit reasons

`rax_emu_start(begin, until, timeout_us, count)` runs until the first configured or architectural stop condition. `rax_emu_last_exit` distinguishes reasons such as:

- instruction count reached;
- `until` address reached;
- timeout;
- explicit stop;
- halt;
- port I/O;
- MMIO;
- exception;
- invalid/unsupported execution path.

A return of `RAX_OK` means the API call completed with a clean engine stop. It does not mean the guest program produced its intended result. Always inspect the exit record and application-specific state.

Single-step, bounded execution, code hooks, and block hooks require a stepping-capable backend. Query:

```c
rax_engine_supports_stepping(engine)
```

rather than assuming support from the architecture name.

## Hooks and re-entry

The API provides hooks for:

- instruction/code entry;
- basic-block entry;
- interrupts;
- port input/output;
- MMIO reads/writes;
- invalid instruction;
- memory read/write/fetch.

I/O hooks can supply values or service an exit so execution continues. Memory hooks report address, size, access kind, and value for recording-capable engines.

Callbacks receive the engine handle and may re-enter the API, including requesting a stop. The implementation records memory accesses during execution and dispatches them at instruction boundaries so callbacks do not run while the engine is internally borrowed.

Re-entry support does not make arbitrary recursive execution sensible. Avoid starting a second run on the same engine from within an execution callback unless the API explicitly documents that pattern.

## Contexts and checkpoints

The C API’s context save/restore captures engine state for the embedding contract. It is distinct from the root VM’s `.rxc` whole-machine checkpoint, which also covers machine configuration, guest RAM, devices, and timing anchors.

Use:

- C API contexts for engine-level state round trips inside an embedding application;
- root VM checkpoints for complete command-line machine restore.

Do not interchange their files or compatibility expectations.

## Stateless decode and analysis

`rax_decode` and `rax_analyze` can inspect one instruction without opening an engine or mapping guest memory. The analysis result can include:

- decoded control-flow and target summary;
- normalized architectural register reads/writes;
- memory-access/effective-address characteristics;
- condition-code effects;
- direct constant or register results when the SMIR analysis proves them.

The current API distinguishes complete, partial, and unsupported effect summaries. Downstream analysis must preserve that status. Absence of an effect in a partial summary is not evidence that the instruction cannot produce it.

Variable-length effect output uses two-call sizing: first query the required count, then supply a sufficiently large array. An undersized array receives a deterministic prefix and an explicit bounds/truncation result.

## Architecture capability boundary

The C API README currently describes full memory/register/run/reset/context surfaces for:

- x86/x86-64;
- AArch64;
- RV64;
- AArch32/ARMv7;
- Cortex-M;
- Hexagon.

Instruction-granular stepping and code/block hooks are currently advertised for engines that return true from `rax_engine_supports_stepping`, identified there as x86-64, AArch64, and RISC-V. The remaining architectures run to the next engine exit under the current contract.

Query at runtime. Do not compile an architecture table into downstream logic without version negotiation.

## Threading and lifetime

One `rax_engine` handle is not thread-safe. Drive it from one thread at a time. Distinct handles have independent state and may run concurrently on different threads.

The library:

- owns the engine object until `rax_engine_close`;
- copies caller data rather than retaining caller buffers under the documented APIs;
- does not launch hidden worker threads;
- does not use process-global emulator state for normal engines;
- validates arguments at the FFI boundary.

Downstream callbacks, logging, allocators, and user data can still introduce their own synchronization requirements.

## Security considerations

Embedding an emulator increases the host application’s input surface. Treat guest code, executable formats, analysis buffers, callback data, and context files as untrusted unless provenance is controlled.

At minimum:

- impose instruction/time limits;
- bound mapped memory and allocation counts;
- validate all lengths and addresses;
- isolate debugger/listener ports;
- handle every stop reason;
- avoid loading untrusted native plugins in the same process;
- fuzz the exact architectures and hooks your product exposes;
- run sanitizers and platform hardening in the downstream integration;
- do not present the engine as a security sandbox without an independent threat model and review.

Rust memory safety and FFI validation reduce classes of defect; they do not prove the absence of parser, semantic, resource-exhaustion, logic, or unsafe-code vulnerabilities.

## Integration validation

A downstream release should test:

```text
[ ] dynamic and/or static link on every supported platform
[ ] header compatibility with supported C and C++ compilers
[ ] version/status string behavior
[ ] open/close/reset loops
[ ] sparse/high-address memory maps
[ ] permission changes and overlap rejection
[ ] every register family used by the product
[ ] each execution stop reason handled by the product
[ ] hook add/remove and callback re-entry
[ ] context round trip
[ ] stateless decode/analysis complete/partial/unsupported paths
[ ] panic containment test
[ ] distinct-engine concurrency
[ ] same-engine misuse rejected or serialized by the application
[ ] ABI size/version checks
[ ] loader/runtime search path in packaged products
```

## Related pages

- [`capi/README.md`](../capi/README.md) — normative API and build reference
- [Cargo features](reference/build-features.md)
- [Architecture overview](architecture/overview.md)
- [SMIR and native execution](architecture/smir.md)
- [Status and limitations](reference/status-and-limitations.md)
