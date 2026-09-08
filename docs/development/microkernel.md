[← Documentation home](../../README.md)

# Microkernel test harness

`microkernel/` is a freestanding integration workload used to exercise CPU, loader, memory, UART, and runtime behavior without depending on a full Linux guest. It is built for multiple architectures from one codebase and emits machine-readable pass/checksum markers.

## What it contains

The workload includes:

- freestanding startup and linker configuration;
- a small allocator;
- deterministic N-body computation;
- instruction and runtime coverage selected for each architecture;
- serial output;
- a final `RAX-MK: RESULT PASS` marker;
- a deterministic N-body checksum compared across architectures.

The checksum catches broad arithmetic/state divergence across complete executions. It does not isolate which instruction caused a mismatch and it cannot cover instructions the workload never executes.

## Build targets

The Makefile builds bare-metal images for:

- x86-64;
- AArch64;
- ARMv6.

It also builds a hosted x86-64 Linux form for optional Intel SDE comparison.

```sh
cd microkernel
make
```

The freestanding Rust build requires a nightly toolchain with `rust-src` because it builds core/runtime components for custom targets. An appropriate `objcopy` is needed to produce the final image forms.

The x86-64 image retains `x86_64-unknown-none`'s soft-float code-generation
baseline. Its SSE/AVX/AVX2/AVX-512 instruction probes use explicit inline
assembly with memory operands and declared vector scratch registers. Do not
enable SSE-implying `#[target_feature]` attributes on these functions: current
nightly rejects that combination with `x86_softfloat_sse`. The explicit probes
still execute unconditionally, so their test guest must provide the named ISA
features and corresponding vector state. The scalar comparison code continues
to use the target's software arithmetic. See the [archived Rust compiler and
inline-assembly references](microkernel-references/README.md) for provenance and
the captured compilation regression.

## Run all architectures

```sh
cd microkernel
make run
```

The run target launches the architecture images through the configured `rax` binary, checks for the final pass marker, extracts the N-body checksum, and requires the expected cross-architecture agreement.

A successful run establishes that the specific binaries completed through their selected machine paths. It does not establish external-oracle agreement.

## Intel SDE comparison

```sh
cd microkernel
make test-sde
```

This executes the hosted x86-64 workload under Intel SDE when `SDE_PATH` is configured. The hosted build and bare-metal image do not have identical startup/device environments, so compare the deterministic computational result and intended instruction surface rather than raw full traces unless the harness defines them as equivalent.

## Environment variables

| Variable | Purpose |
|---|---|
| `RAX_BIN` | Path to the `rax` executable used by run targets |
| `FORCE_BUILD` | Force rebuilding `rax` or workload artifacts according to the Makefile path |
| `MEM` | Guest memory passed to relevant launches |
| `OBJCOPY` | Override the object-copy tool |
| `SDE_PATH` | Path to Intel SDE for the optional hosted comparison |

Consult the current Makefile before relying on defaults; these are build-script controls, not the main runtime API.

## Relationship to Cargo integration tests

The root Cargo target `microkernel_multiarch` wraps the multi-architecture machine validation in the test suite. Running the Makefile directly is useful for iterative diagnosis and leaves the console/artifacts visible. Running the Cargo target integrates it with the repository’s explicit test map.

## Failure triage

### Build failure

Check:

- nightly toolchain availability;
- `rust-src` component;
- custom target JSON/linker inputs;
- `objcopy` selection;
- stale target artifacts;
- whether the configured `rax` binary is current.

### No pass marker

Capture the full serial log and determine the last named phase. The cause may be instruction semantics, machine loading, UART, exception handling, allocator state, or a hang.

### Checksum mismatch

Record all architecture checksums, exact binaries, compiler versions, and optimization level. Re-run the architecture individually with tracing or a reduced deterministic iteration count. A checksum mismatch is high-value evidence but not yet a minimized instruction case.

### One architecture skips

A run that omits one image is not a multi-architecture pass. The harness should fail or print an explicit non-success state rather than silently comparing the remaining outputs.

## Extending the workload

When adding coverage:

- keep the computation deterministic;
- avoid depending on unsupported allocation or runtime services;
- emit a phase marker before difficult blocks;
- preserve a simple final pass marker;
- ensure every architecture executes semantically equivalent work;
- separate architecture-specific probes from the cross-architecture checksum;
- add external differential or unit tests for any newly exposed instruction bug.

The microkernel is a system integration layer. It complements, rather than replaces, instruction-level differential testing.
