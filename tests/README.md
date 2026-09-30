# Test tree

The test tree is organized by what is being verified, rather than by how a
test happened to be created.

```text
tests/
├── fixtures/       # Buildable or executable guest inputs
├── generated/      # Checked-in generated Rust/data; never Cargo targets
├── support/        # Shared test support modules
└── suites/
    ├── api/        # Public API contracts
    ├── backend/    # Execution-backend integration
    ├── coverage/   # Source/specification inventory assertions
    ├── differential/ # RAX state compared with an external oracle
    ├── isa/        # Direct instruction-semantics tests
    ├── machine/    # Boot and platform integration
    ├── smir/       # Lift, lower, JIT, and round-trip validation
    ├── user/       # Linux and Windows program, ABI, memory, and process checks
    └── tooling/    # Repository and build-tool invariants
```

Cargo automatic integration-test discovery must remain disabled. Each file
listed below is declared explicitly with a `[[test]]` entry in the root
`Cargo.toml`. Keeping the historical target names preserves existing
`cargo test --test <name>` and CI interfaces.

| Cargo target | Source |
|---|---|
| `aarch64_smir_native` | `suites/smir/lower/aarch64_native.rs` |
| `arm` | `suites/isa/arm/main.rs` |
| `arm_diff` | `suites/differential/arm/aarch64.rs` |
| `arm_diff32` | `suites/differential/arm/aarch32.rs` |
| `arm_vfp_a32` | `suites/isa/arm/aarch32/vfp.rs` |
| `asm_instructions` | `suites/isa/x86_64/assembly.rs` |
| `ci_actions_pinned` | `suites/tooling/ci_actions_pinned.rs` |
| `diff_fuzz` | `suites/differential/x86_64/fuzz.rs` |
| `differential` | `suites/differential/x86_64/kvm.rs` |
| `hexagon_bare_metal` | `suites/machine/hexagon_baremetal/boot.rs` |
| `hexagon_cf_diff` | `suites/differential/hexagon/control_flow.rs` |
| `hexagon_diff` | `suites/differential/hexagon/scalar.rs` |
| `hexagon_float_diff` | `suites/differential/hexagon/float.rs` |
| `hexagon_hvx_diff` | `suites/differential/hexagon/hvx.rs` |
| `hexagon_hvx_mem_diff` | `suites/differential/hexagon/hvx_memory.rs` |
| `hexagon_mem_diff` | `suites/differential/hexagon/memory.rs` |
| `hexagon_smir_lift` | `suites/smir/lift/hexagon.rs` |
| `isa_oracle` | `suites/api/isa_oracle.rs` |
| `kvm_minimal` | `suites/backend/kvm/minimal.rs` |
| `microkernel_multiarch` | `suites/machine/microkernel/multiarch.rs` |
| `pgo_build_script` | `suites/tooling/pgo/build.rs` |
| `pgo_script_safe` | `suites/tooling/pgo/safety.rs` |
| `realmode_boot` | `suites/machine/pc/real_mode_boot.rs` |
| `riscv_boot` | `suites/machine/riscv_virt/boot.rs` |
| `riscv_diff` | `suites/differential/riscv/scalar.rs` |
| `riscv_smir_lift` | `suites/smir/lift/riscv.rs` |
| `riscv_smir_aarch64_jit` | `suites/smir/jit/riscv_aarch64.rs` |
| `riscv_smir_x86_jit` | `suites/smir/jit/riscv_x86_64.rs` |
| `riscv_vector` | `suites/differential/riscv/vector.rs` |
| `smir_avx10_roundtrip` | `suites/smir/roundtrip/avx10.rs` |
| `smir_jit_evex_masking` | `suites/smir/jit/x86_64_evex_masking.rs` |
| `smir_jit_vcpu` | `suites/smir/jit/x86_64.rs` |
| `smir_jit_x86_aarch64` | `suites/smir/jit/x86_64_aarch64.rs` |
| `smir_jit_aarch32_aarch64` | `suites/smir/jit/aarch32_aarch64.rs` |
| `smir_jit_thumb_aarch64` | `suites/smir/jit/thumb_aarch64.rs` |
| `user_darwin` | `suites/user/darwin/main.rs` |
| `user_linux` | `suites/user/linux/main.rs` |
| `user_windows` | `suites/user/windows/main.rs` |
| `user_windows_memory` | `suites/user/windows_memory.rs` |
| `x86_64` | `suites/isa/x86_64/main.rs` |
| `x86_64_apx_map4_qemu_diff` | `suites/differential/x86_64/qemu_apx.rs` |
| `x86_64_avx512_inventory` | `suites/coverage/x86_64/avx512_inventory.rs` |
| `x86_64_avx512_kvm_diff` | `suites/differential/x86_64/kvm_avx512.rs` |
| `x86_64_evex_qemu_diff` | `suites/differential/x86_64/qemu_evex.rs` |
| `x86_64_unimplemented_manifests` | `suites/coverage/x86_64/unimplemented_manifests.rs` |
| `x86_64_unimplemented_qemu_diff` | `suites/differential/x86_64/qemu_unimplemented.rs` |
| `x86_64_unimplemented_source_inventory` | `suites/coverage/x86_64/unimplemented_source_inventory.rs` |

## Reachability rules

- Files below `generated/` are included by suite runners and are not
  standalone integration-test targets.
- `suites/isa/arm/main.rs` preserves the previous ARM reachability: one
  handwritten AArch64 leaf and the generated AArch64 suite are active.
- The handwritten ARM module graph and
  `suites/isa/arm/legacy_aarch32_dormant/` remain dormant. Moving them did not
  activate or delete any tests.
- `suites/isa/x86_64/main.rs` is the canonical x86-64 aggregate. It registers
  each semantic leaf directly; redundant nested `mod.rs` graphs are absent.
- External-oracle suites self-gate according to their existing host/tool
  checks; directory placement does not imply that an oracle is installed.

## Adding tests

`user_linux` reaches its ABI-table, CLI, host-signal, syscall-fixture, and
whole-program modules through `suites/user/linux/main.rs`. Its execution
matrices cover x86-64, AArch64, and RV64, and the syscall fixtures also an
i386 subset recorded on an x86-64 Linux kernel under `qemu-system-x86_64`
(`fixtures/user/linux/oracle/`); i386 numbering is checked there, and the
compatibility conversions have library tests under
`src/user/linux/tests/i386/`. The ignored live Docker comparison requires
`RAX_USER_DOCKER_ORACLE=1`; checked-in recordings need no live oracle.

`user_darwin` compares `rax-user` runs of the C fixtures in
`fixtures/user/darwin/src` and of system programs with their native runs on
a macOS host (x86_64 through Rosetta), checks the generated Darwin tables
with their generators' `--check` mode, and checks the signal-frame layouts
against a probe compiled with the SDK. Without a macOS host the comparisons
report themselves skipped.

Add behavioral cases beneath the matching suite domain. Add generated material
under `generated/` and record its provenance in `generated/manifest.toml`.
If a new executable runner is needed, add one explicit Cargo target and update
the table above.

`user_windows` reaches freestanding PE32 x86 and PE32+ x64/ARM64 programs
through `suites/user/windows/main.rs`. It validates process startup, TEB/PEB
state, calling conventions, heap behavior, virtual memory transitions, fixture
hashes and imports, CLI personality selection, supplied-byte process loading,
and rejection of malformed or unsupported process images and startup sizes.
Its fixtures are rebuilt with `bash tests/fixtures/user/windows/build.sh` and
require no Windows SDK or CRT. Expectations derive from Microsoft
specifications; no native Windows oracle recording is available. Run with
`cargo +stable test --locked --no-default-features --test user_windows -- --test-threads=1`.

The same target reaches `suites/user/windows/lifecycle.rs`, whose separate
`fixtures/user/windows/lifecycle/build.sh` graph tests dynamic/static DLL
notifications, TLS installation/isolation, forwarding and missing-export
rollback, failed-attach retry, reference ownership, unload and EXE data mapping
on all three guest ABIs. Controlled CLI runs use scheduling slices of 1 and
4,096 instructions and an external 30 s watchdog. Public-contract checks and
labeled personality policies are not recorded native differential results.

The same target reaches `suites/user/windows/fibers.rs`. Its independent
`fixtures/user/windows/fibers/build.sh` produces eight CRT/SDK-free PE programs
for each of x86, x64 and ARM64, checking conversion, FLS/TLS isolation,
synchronized migration, call-preserved/FP state, normal/forced exits and demand
stack growth. Every program runs at slices of 1 and 4,096 instructions with a
30 s external watchdog. Source/artifact hashes and explicitly retained profiles
are in that fixture directory; no native Windows oracle is claimed.

The same target reaches `suites/user/windows/crt.rs`. Its separate
`fixtures/user/windows/crt/build.sh` graph checks named MSVCRT, UCRTBASE and
UCRT heap/string/runtime API-set and VCRUNTIME140 imports for x86, x64 and ARM64.
Custom-entry programs exercise CRT allocations, checked byte/UTF-16 memory/string routines,
thread-local error state and real invalid-parameter callbacks. They run at
slices of 1 and 4,096 instructions under a 30 s external watchdog. These
programs do not replace or establish ordinary compiler CRT startup or stdio;
native Windows differential execution remains unknown.

The same target reaches `suites/user/windows/crt_init.rs`. The separate
`fixtures/user/windows/crt_init/build.sh` graph exercises compiler-produced
constructor tables, NULL holes, lazy future-entry mutation, nested guest calls,
first-error termination and nonreturning callbacks on x86, x64 and ARM64.
Custom-entry PE probes preserve the distinction from ordinary compiler startup.
Both scheduling slices and the preserved pre-change CLI use identical hashed
inputs; native Windows execution remains unknown.

The same target reaches `suites/user/windows/crt_startup.rs`. Its independently
compiled `fixtures/user/windows/crt_startup/` probes exercise genuine per-ABI
legacy data/functions and UCRT startup leaves, including the unmodified static
MinGW UCRT getter wrappers, CP1252-before-parse conversion, narrow/wide argument
transitions, environment snapshots, new-mode state and actual wildcard
enumeration. All 45 images execute on the matching x86/x64/ARM64 guest at both
slice sizes; environment images also run with an empty environment. These are
custom-entry probes, not ordinary linked CRT startup or a native Windows oracle.

The same target reaches `suites/user/windows/crt_onexit.rs`. Its separate
`fixtures/user/windows/crt_onexit/` graph exercises genuine UCRTBASE/runtime
API-set explicit table imports on x86, x64 and ARM64, including reverse callback
order, nested generations, lazy slot mutation, actual pending-slot VEH repair,
OOM-preserving registration and nonreturning callbacks. Companion DLLs execute
tables during actual DLL_PROCESS_DETACH. The terminal witness deliberately
overrides requested status 88 with forced status 0 only after a successful
detach-time drain; missing notification remains observable. Both slice sizes,
hashed prechange inputs and explicitly retained private profiles are distinct
from a native Windows oracle or complete CRT termination/stdio.

The same target reaches `suites/user/windows/crt_stdio.rs`. Its independently
compiled `fixtures/user/windows/crt_stdio/` programs exercise real CRT FILE
storage, descriptor/HANDLE ownership, actual caller/automatic buffers, bounded
binary/ANSI-text byte I/O, flush/close, sticky status and captured VEH repair
across x86, x64 and ARM64. MSVCRT, UCRTBASE and the stdio API-set retain their
genuine producer binding differences. Sixty semantic PEs run at both scheduling
slices; six unmodified ordinary main/wmain PEs preserve the remaining startup
import graph as separate observations, not ordinary-startup success evidence.
Native Windows differential behavior and complete CRT termination/Unicode
stdio remain unproven. Primary provenance and exact private profiles are
recorded in `docs/architecture/user-mode/windows-crt-stdio.md`.

The same target reaches `suites/user/windows/crt_termination.rs`. Its separate
`fixtures/user/windows/crt_termination/` graph tests the genuine UCRT/runtime
API-set `_crt_atexit` and `_crt_at_quick_exit` registrars for x86, x64 and ARM64,
including NULL/duplicate callbacks, growth beyond 1024 pointers, registration
inside explicit callbacks, and another thread waiting on the shared exit lock.
Raw `ExitProcess` must not execute the executable's global CRT callbacks.
The 30 custom-entry programs run at slices of 1 and 4096 guest instructions;
they do not establish ordinary CRT startup or admit CRT termination/TLS APIs.
Source, IAT, binary, and retained baseline receipts are checked by the same
test binary. Native Windows differential execution remains unknown. See
`docs/architecture/user-mode/windows-crt-global-registration.md`.

The same target reaches `suites/user/windows/crt_exit.rs`. Its independently
compiled `fixtures/user/windows/crt_exit/` corpus has 12 physical PEs and 126
individual cases (three ABIs, two bindings, 21 modes), each run at slices 1
and 4096. It checks dynamic UCRT full/quick/minimal and returning cleanup,
executable TLS callbacks, terminate/abort and software SIGABRT/SIGTERM,
guest search/unwind ordering across synthetic HLE filters, and normal DLL
detach flushing versus forced termination. Exact stdout, full 32-bit terminal
status, pending file bytes, source/IAT/PE hashes and 252 preserved-CLI
observations are checked. Forced-exit baseline passes remain negative controls;
normal raw ExitProcess exposes the pre-feature flush defect. These custom-entry
probes do not establish ordinary compiler startup, complete C++ exception
personality or native Windows equivalence. See
`docs/architecture/user-mode/windows-crt-exit.md`.

The same target reaches `suites/user/windows/dynamic_unwind_x64.rs` and
`suites/user/windows/arm64_dynamic_unwind.rs`. Their independent freestanding
PE32+ fixtures import the public fixed-table APIs, allocate guest-owned
executable code and a separate function table, raise a continuable exception
inside a nonleaf frame, check that a language handler ran, resume, and remove
the registration by its original pointer. They import `RtlLookupFunctionEntry`
and check a NULL result before registration and after deletion, plus exact
guest record-pointer and image-base outputs while the table is active. The
NULL-history-table and unchanged-base-on-miss conditions are the documented
RAX profile, not native Windows differential evidence. The ARM64 fixture also
separates `.xdata` into its own mapping. Each executes at scheduling slices of
1 and 4,096 instructions; source, binary, PE imports and unwind metadata have
provenance checks. Native Windows differential results and undocumented
overlap or mutation behavior remain unknown.

`user_windows_memory` tests native Windows external-mapping ownership through
`GuestMemoryMmap`: retained snapshots, cross-thread destruction, multiple views,
and rejected ranges. Its three tests run in the Windows C API CI lane. Other
hosts compile an empty target; that result is not Windows runtime coverage.
