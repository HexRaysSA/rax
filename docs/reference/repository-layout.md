[← Documentation home](../../README.md)

# Repository layout and ownership

The repository is organized by responsibility, but it also contains generated inputs, independent build systems, reference material, guest images, and compatibility paths. This page explains where truth lives and where a change should go.

## Root map

| Path | Responsibility |
|---|---|
| `Cargo.toml` | root package, workspace membership, features, explicit integration-test targets, dependencies, release profile |
| `.cargo/` | checked-in Cargo/compiler configuration, including host CPU baseline flags |
| `.github/workflows/` | actual CI build/test/tool matrix |
| `src/` | production Rust implementation for CLI, VM runtime, machines, backends, ISAs, devices, SMIR, debugging, and observability |
| `tests/` | integration suites, fixtures, generated test data, and shared support |
| `capi/` | workspace member exporting the C ABI and C++17 wrapper |
| `docs/` | architecture, development, hardware, research, specifications, and this breakout documentation |
| `examples/` | runnable examples and benchmarks; not automatically conformance tests |
| `microkernel/` | independent freestanding multi-architecture workload and build system |
| `scripts/` | maintenance, generation, validation, or packaging scripts |
| `tools/` | independent developer tools such as the ASL parser work |
| `linux-aarch64/` | checked-in AArch64 Linux image and initramfs used by the clean-checkout path |
| `linux*/`, `initrd_root/`, root initrd artifacts | Linux build/output and initramfs material used by helper paths |
| `_ref/` | excluded reference or specialist material; not part of the root workspace build |
| `assets/` | README and documentation media |
| `Makefile`, `run.sh` | common build/test/benchmark/Linux helper entrypoints |
| `AGENTS.md` | engineering contract, truth hierarchy, validation discipline, and repository workflow guidance |

Not every directory is part of the root Cargo workspace. `capi` is a member; `microkernel`, `tools/asl-parser/asl-parser-rs`, and `_ref` are explicitly excluded and own independent builds.

## Production source ownership

The canonical source responsibility map is maintained in [`src/README.md`](../../src/README.md):

| Directory | Owns |
|---|---|
| `src/isa/` | guest instruction decoding and architectural semantics |
| `src/machine/` | platform selection, loaders, boot state, address maps, and device wiring |
| `src/backend/` | execution mechanisms and their `VCpu` adapters |
| `src/devices/` | device models and I/O buses |
| `src/vm/` | architecture-neutral runtime, memory, snapshots, timing, and vCPU contracts |
| `src/smir/` | cross-ISA IR, lifting, interpretation, optimization, native lowering, and JIT runtime |
| `src/oracle/` | static ISA decode/lift oracle output |
| `src/user/` | process-level (user-mode) emulation: ELF images, guest address spaces, CPU adapters, the Linux personality |
| `src/debug/` | interactive debugger protocols |
| `src/observability/` | trace and profiling implementation |
| `src/host/` | terminal, console, signals, and host-facing interaction |
| `src/config/` | public architecture/backend/profile types, file schema, defaults, detection, validation, and precedence |
| `src/cli/` | command-line parsing and CLI-to-runtime wiring |
| `src/bin/` | additional binaries: the ISA oracle and `rax-user` |

The collaboration graph is approximately:

```text
cli -> config -> vm/runtime -> machine -> devices
                         \-> backend -> isa
                                    \-> smir
oracle ----------------------------> isa + smir
host/debug/observability ----------> runtime execution surfaces
```

The graph is not a strict DAG. Machine initialization and backend adapters share bounded platform contracts. That does not move instruction semantics into machine code or device ownership into the backend.

## Compatibility and canonical paths

Compatibility re-exports in `lib.rs` and thin files under older backend paths may preserve previous public names. They do not own new implementation.

When moving code:

1. Put the implementation in the canonical owner directory.
2. Keep a thin compatibility export only where an API transition requires it.
3. Update direct callers to use the canonical path.
4. Update generated inventories and test imports.
5. Remove compatibility code only under an explicit compatibility decision.

Do not create a second implementation under a compatibility path.

## ISA change routing

A new or corrected instruction usually affects more than one file:

```text
encoding/decode
architectural state representation
semantic execution
exceptions/flags/memory behavior
SMIR lift
native lowerer or admission gate
formatter/disassembler/oracle output
unit tests
differential tests
generated inventory
architecture documentation
```

Not every instruction requires every layer, but the change author should explicitly mark each layer as changed, unaffected, unsupported, or deferred. Silent omission is how interpreter/JIT/oracle drift enters the tree.

Architecture homes:

- `src/isa/x86_64/`
- Arm-family directories under `src/isa/`
- Hexagon directories under `src/isa/`
- RISC-V directories under `src/isa/`

Use the owning architecture’s existing category structure rather than creating a cross-ISA “miscellaneous instructions” directory.

## Machine change routing

Machine work belongs under `src/machine/` when it defines:

- image loading;
- reset/entry state;
- guest physical address map;
- kernel boot protocol;
- DTB construction;
- device attachment;
- interrupt topology;
- machine-specific configuration interpretation.

Current machine files/directories include PC, Arm virtual/SoC work, Cortex-M/S3C64xx/S5L8900-oriented paths, Hexagon bare-metal, and RISC-V bare-metal.

If a change modifies a generic device’s internal behavior, implement it under `src/devices/` and wire it from the machine. If it modifies generic guest memory or snapshot semantics, use `src/vm/`.

## Backend change routing

Backend code owns how guest execution is driven:

- software vCPU adapters;
- KVM setup/exits/state transfer;
- HVF setup/exits/state transfer;
- conversion between backend-specific registers and architecture-neutral contracts;
- run-loop mechanisms that are not architecture semantics.

A KVM quirk is not evidence that software ISA semantics belong in the KVM backend. A software decoder fix is not automatically a machine fix.

## SMIR change routing

A SMIR change can alter:

- IR data model and serialization/debug form;
- architecture lifters;
- SMIR interpreter;
- optimizer transforms;
- native lowerers;
- helper ABI;
- executable-memory runtime;
- cache identity/invalidation;
- hot-region admission;
- interpreter/JIT equivalence tests;
- architecture specifications under `docs/specifications/smir/`.

The implementation is authoritative when a derived specification lags. Update both in the same change when the contract itself changes.

## Device change routing

`src/devices/` owns reusable models and bus behavior. A device status claim should identify separately:

- model exists;
- bus exposes it;
- machine attaches it;
- default or opt-in state;
- guest enumerates it;
- guest driver operates it;
- interrupts/DMA work;
- checkpoint state is complete;
- tests cover reset and error paths.

A source file alone is not a platform-support claim.

## Test tree

The test tree is organized by evidence domain, as documented in [`tests/README.md`](../../tests/README.md):

```text
tests/
├── fixtures/         buildable or executable guest inputs
├── generated/        checked-in generated Rust/data; never Cargo targets
├── support/          shared harness code
└── suites/
    ├── api/          public API contracts
    ├── backend/      backend integration
    ├── coverage/     source/specification inventory assertions
    ├── differential/ state comparison with external references
    ├── isa/          direct instruction semantics
    ├── machine/      boot and platform integration
    ├── smir/         lift, interpreter, round-trip, and native/JIT tests
    └── tooling/      CI, scripts, PGO, generation, and repository invariants
```

Because `autotests = false`, the runnable target name comes from `Cargo.toml`, not from the filename alone. Keep three objects in sync:

1. source under `tests/suites/`;
2. explicit `[[test]]` registration;
3. target mapping in `tests/README.md` and [the breakout test map](../development/testing/README.md).

Generated files belong under `tests/generated/` and are included by registered targets. Do not turn each generated shard into an accidental Cargo binary.

## Documentation tree

This overlay deliberately has no `docs/README.md`. The root [`README.md`](../../README.md) is the only complete index.

Breakout ownership:

```text
docs/getting-started/    build and run procedures
docs/architecture/       execution, machines, devices, ISAs, SMIR
docs/development/        verification, target map, generators, microkernel
docs/operations/         observability, checkpoints, performance
docs/reference/          exact CLI/config/features/env/status/layout
docs/embedding.md        C/C++ integration map
docs/documentation-policy.md
```

Existing specialist material remains under:

```text
docs/hardware/
docs/research/
docs/specifications/
docs/development/... specialist reports
docs/architecture/... architecture-specific references
```

A specialist report should not become the current status page merely because it is detailed. Date it, identify its source revision, and link it from the owning current page.

## Source-of-truth order

For repository claims, use:

1. architecture/vendor specification for architectural behavior;
2. public parser/config/build definitions for accepted repository interfaces;
3. current source for implementation;
4. executable tests for exercised behavior;
5. CI workflows for automated host/tool coverage;
6. maintained documentation for explanation;
7. historical reports, comments, issue text, and old README prose for context.

When two levels conflict, record the conflict. Do not silently choose the more impressive claim.

Examples:

- `src/config/kinds.rs` limits the public Hexagon selector to `v69`; an old `V73` prose claim is not the public interface.
- A green external-oracle test that printed a skip message is not evidence that comparison cases executed.
- A file under `src/devices/` is not proof that the default machine attaches or validates the device.
- An architecture selector for Armv9.4 is not an exhaustive implementation certificate.

## Change checklist

Before merging a repository change:

```text
[ ] canonical source owner selected
[ ] public API/CLI/config impact reviewed
[ ] machine/backend/device boundary reviewed
[ ] interpreter semantics tested
[ ] SMIR lift/interpreter/lowerer impact reviewed
[ ] external oracle prerequisites and case count recorded
[ ] generated material regenerated and clean
[ ] explicit Cargo target registration updated if needed
[ ] tests/README.md mapping updated if needed
[ ] root README changed only if project-level navigation/status changed
[ ] owning breakout documentation updated
[ ] volatile inventory kept out of the root README
[ ] benchmark claims include environment and workload
[ ] known limitation recorded rather than hidden
```

## Related pages

- [Documentation policy](../documentation-policy.md)
- [Architecture overview](../architecture/overview.md)
- [Testing target map](../development/testing/README.md)
- [Generated suites](../development/generated-suites.md)
- [Status and limitations](status-and-limitations.md)
