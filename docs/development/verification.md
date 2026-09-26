[← Documentation home](../../README.md)

# Verification model

Verification is central to `rax`, but the project uses several different kinds of evidence. They must not be collapsed into the single claim “verified.” A precise report names the implementation path, reference, input corpus, state projection, prerequisites, test count, and result.

## The differential contract

A differential case constructs an initial state `s`, executes guest bytes `b` through `rax` and a reference, and compares an explicit projection `P` of the resulting state:

```text
P(E_rax(b, s)) == P(E_ref(b, s))
```

A passing corpus establishes that equality for the cases that executed, under the host features and reference version used. It does not establish:

```text
for every byte sequence, every architectural state, every exception path,
every memory-system interaction, and every reference implementation:
    E_rax == E_architecture
```

The difference is not rhetorical. It determines what a test can rule out.

## Evidence classes

| Evidence | What it can establish | What it cannot establish alone |
|---|---|---|
| Direct semantic unit test | A named operation produces expected values for named cases | Agreement with real hardware across the architecture |
| Generated semantic corpus | Broad finite coverage of a machine-readable encoding/input set | Correctness outside the generator’s model or projection |
| Differential test | Agreement with the named reference for executed states and compared outputs | Correctness of both implementations or unobserved state |
| Inventory test | Source/generated manifest contains or excludes expected entries | Behavioral correctness of those entries |
| Boot/integration test | A named image reaches a named milestone | Complete ISA/device correctness or general OS compatibility |
| SMIR lift comparison | Lifted/IR-interpreted behavior agrees with the architecture interpreter | External correctness if both share a bug |
| Native lowerer comparison | Native output agrees with interpreter for named states | Formal equivalence for all states or safe live integration |
| Runtime live verification | A compiled region agrees with an interpreter replay under that mode | Coverage of regions never promoted or unsupported host paths |
| Benchmark | Performance of a named build/workload/host | Portable project performance or correctness |

## Reference hierarchy

### x86-64: KVM and host hardware

Selected x86 tests place machine code and architectural state into a KVM vCPU and compare the post-execution state with the software interpreter. This gives a hardware-backed reference for instructions supported and exposed by the host CPU/KVM interface.

Qualifications:

- `/dev/kvm` must be usable;
- the host CPU must implement the tested feature;
- virtualization may mask or virtualize architectural details;
- the harness exports a selected register/memory projection;
- undefined or implementation-specific behavior cannot be treated as a portable expected value;
- KVM cannot reference an extension absent from shipping host hardware.

### x86-64: QEMU user mode

Generated EVEX and rejection suites can use `qemu-x86_64`. QEMU supplies a second implementation and can expose state not conveniently available from a specific host. It remains software and may share specification misunderstandings.

### AArch64: native EL0 and QEMU

On AArch64 hosts, the user-mode harness can install a controlled signal frame, execute an instruction directly at EL0, and recover the resulting state. On other hosts the same style of cases can use `qemu-aarch64`.

Neither path validates EL1 machine behavior merely because the instruction decoder is shared. Privileged registers, exception delivery, MMU behavior, GIC, timers, and devices require separate system tests.

### AArch32: QEMU user mode

Generated A32/Thumb cases use `qemu-arm` for the user-visible projection. Machine/profile state outside that user-mode contract needs direct tests or board-level integration evidence.

### Hexagon and RISC-V: QEMU user mode

Small reference harnesses under `tools/` serialize initial state, execute the instruction/sequence under the matching QEMU user-mode target, and serialize the result. These are appropriate for user-level instruction semantics. They do not validate an operating-system machine that the current bare-metal targets do not implement.

### Intel APX: assembler and documented semantics

APX is exceptional because the current setup has neither a shipping-hardware oracle nor a generally executing QEMU reference for the staged corpus. LLVM can establish exact assembled bytes for supported syntax. The architectural effect must then be checked against documented semantics and direct tests.

This yields two separate claims:

1. LLVM produced the expected encoding.
2. `rax` produced the expected documented state transition.

It is not honest to call LLVM an execution oracle, and a QEMU target that self-skips is not present evidence.

### Generated Arm ASL and Intel corpus material

Machine-readable specifications and checked-in instruction corpora can define a finite set of encodings or cases. They are valuable for coverage, but the generator and parser are part of the trusted computing base. A parser bug can systematically produce the wrong expected set.

## Linux process and whole-program comparisons

The `user_linux` target compares guest stdout text and exit status with
checked-in Linux recordings. It has two inputs: syscall fixtures under
`tests/fixtures/user/linux/` and the morok corpus under its `programs/`
subdirectory. The runners enumerate x86-64, AArch64, and RV64; ELF32 i386
compatibility currently has library tests, not the same recorded matrix.

Each corpus's `expected/ORACLE` identifies the actual recording kernel,
container engine, native architecture, translator, and overrides. The
personality models vendored Linux 6.19 sources; the checked-in recordings
identify a Linux 7.0.14 OrbStack kernel on AArch64. They are distinct evidence
sources. An expectation borrowed from another ABI or derived from kernel
source is labeled in `oracle-overrides.txt`; it is not execution of that
syscall on native silicon for the borrowed ABI.

Both runners decode stdout with `String::from_utf8_lossy`; these textual
corpora therefore do not establish equality of arbitrary invalid UTF-8 bytes.
The whole-program runner also applies the declared `noise.txt` filters to both
outputs. Filters may normalize addresses/numbers, mask or drop lines, or
ignore stdout while retaining exit-status comparison. Its
`known-divergences.txt` must match observed failures exactly; a listed failure
is an expected divergence, not successful equivalence. Fixture/program mode
labels also do not prove native admission: the x86 JIT is host-specific and
the RV64 `--riscv-jit` path can fall back.

The ordinary target verifies binaries and recordings without Docker:

```sh
cargo test --release --locked --no-default-features --features smir-jit --test user_linux
```

The ignored live Docker test additionally requires `RAX_USER_DOCKER_ORACLE=1`
and a daemon able to run the three architectures. It still uses the declared
oracle substitutions. Record ignored/self-skip output separately. Unit tests
under `src/user/` exercise faults, layouts, scheduling, signals, ABI conversion,
and cache invalidation that stdout/status alone does not expose.

## State projection

A differential result is only as broad as the compared state. Common projections include:

- general-purpose registers;
- instruction pointer/program counter;
- selected flags or condition state;
- XMM/YMM/ZMM and opmask state;
- Arm vector and predicate registers;
- RISC-V scalar, floating, vector, FCSR/VCSR, `vl`, and `vtype`;
- Hexagon scalar, predicate, user/status, vector, and vector-predicate state;
- scratch memory;
- stack memory;
- explicit fault/exit classification.

Potentially omitted dimensions include:

- timing and performance counters;
- microarchitectural state;
- interruptibility between operations;
- memory ordering with other CPUs;
- unexported control registers;
- exception delivery details;
- device side effects;
- NaN payload choices or undefined flags not normalized by the harness.

The harness should mask architecturally undefined bits rather than treating arbitrary reference output as a specification.

## Input generation

A strong instruction corpus combines:

- systematic enumeration of encoding fields;
- boundary immediates and displacements;
- register aliasing cases;
- zero, all-ones, sign-boundary, and carry-chain values;
- floating-point zeros, infinities, NaNs, subnormals, and halfway cases;
- mask/predicate extremes;
- aligned, unaligned, page-edge, and faulting memory addresses;
- randomized states with a recorded seed;
- short relational sequences for flags, forwarding, packet commit, or atomic behavior.

One-instruction tests are insufficient for properties whose semantics emerge only across a sequence, such as lazy flags, Hexagon `.new` forwarding, lock/atomic visibility, call/return state, or self-modifying code.

## Self-skips and false-green results

Many external-reference tests intentionally self-skip when prerequisites are absent. A command can return status 0 while providing no comparison evidence.

Before citing a run, record:

- host OS and architecture;
- CPU features;
- Cargo feature set;
- `running N tests` count;
- ignored/filtered counts;
- explicit skip messages;
- presence and versions of QEMU, LLVM, cross-compilers, SDE, or `/dev/kvm`;
- whether the target compiled but the internal cases skipped;
- whether a generated aggregate selected zero cases.

Bad report:

> `cargo test` passed, therefore all four CPUs are verified.

Good report:

> On Linux/x86-64 with KVM available, `cargo test --release --test differential` ran 137 tests and passed. The compared projection included GPRs, RIP, masked RFLAGS, XMM state, and scratch memory. AVX-512 cases were not run because the host lacked the required feature.

## Correlated implementations

Internal comparison chains are useful but can share code:

```text
architecture interpreter ↔ SMIR interpreter ↔ native lowerer
```

If both sides call the same helper for a difficult operation, agreement does not independently validate that helper. External references and known-answer vectors reduce correlated risk. Tests should identify shared helpers when claiming independence.

## JIT evidence chain

A native-region claim contains several obligations:

1. the architecture interpreter implements the guest operation;
2. the lifter preserves the interpreter’s behavior;
3. optimizer passes preserve SMIR behavior;
4. the lowerer preserves optimized SMIR behavior;
5. the state adapter transfers registers/flags/vector state correctly;
6. memory helpers preserve faults and commit boundaries;
7. region construction stops at unsafe frontiers;
8. cache identity and SMC invalidation prevent stale code;
9. the run loop synchronizes exits and fallbacks correctly.

A direct native-vs-interpreter test covers several obligations at once for its cases, but no finite test corpus turns the chain into a formal proof.

## Boot evidence

Boot tests should state the milestone, image provenance, kernel configuration, backend, host, and console output marker. Useful milestones include:

- first instruction executed;
- early serial console;
- decompressor completed;
- initrd mounted;
- BusyBox shell prompt;
- guest driver enumerated a device;
- named firmware stage reached;
- named checksum/output marker emitted.

A boot may succeed despite latent instruction errors because the image never executes them. Conversely, a boot failure can be a device, address-map, image, configuration, or backend problem rather than an ISA bug.

## Required language for public claims

Prefer:

- “compared with KVM over the generated corpus”;
- “the named suite reported no divergence in the exported state”;
- “boots the repository’s controlled kernel to a BusyBox shell”;
- “the public selector accepts V4 through V69”;
- “unsupported regions fall back to the interpreter.”

Avoid unless literally proven:

- “every instruction is correct”;
- “the silicon proves the emulator”;
- “bit-identical” without naming the state and cases;
- “complete ISA support” without a finite executable inventory and exclusions;
- “the suite is green on any host” as though green means an oracle ran;
- “JIT does not change behavior” without the tested scope.

## Reproducible result record

Use this template for serious verification reports:

```text
rax commit:
host OS / kernel:
host architecture / CPU:
Cargo profile and features:
command:
target source:
reference binary/version:
cross-compiler/assembler version:
prerequisite check:
number run / skipped / ignored / filtered:
input seed or generated manifest revision:
state projection:
first divergence, if any:
artifacts (trace, bytes, initial/final state):
```

See [Development and testing](testing/README.md) for the complete target map and [Generated suites](generated-suites.md) for provenance rules.
