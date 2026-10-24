# QARMA reference comparison

Run from the repository root:

```sh
python3 tools/pauth-reference/verify.py
```

The script verifies the pinned QEMU source hash, builds its unmodified pure
QARMA routines with `cc`, and builds the RAX primitive with stable `rustc`.
It compares 4,096 independently seeded input/modifier/key tuples per algorithm
(8,192 total), including both 64-bit key halves. `--seed` and `--cases` select
reproducible campaigns; `--cases` is the count per algorithm. Build products
live in a temporary directory and are removed on completion.

The reference is LGPL-2.1-or-later, with its original notice preserved under
`docs/specifications/arm/pauth/`. It is compiled only for this comparison;
it is not linked into the RAX engine. The RAX implementation follows Arm's
shared pseudocode; the provenance file identifies both sources.

This comparison covers the cryptographic primitive. It does not establish
architectural feature gating, key/control-state integration, exception delivery,
Darwin behavior, or native lowering. The direct engine now uses these primitives
with configured guest keys and controls. Backend state, VM checkpoints, and C API
contexts persist the selected configuration and keys. Feature-configured SMIR
and opt-in native helper execution now use the shared architectural planner;
the AArch64 CPU JIT admits exact one-instruction PAuth regions. Those execution-plane results
are covered by separate tests, not established by this primitive comparison.

`verify_architecture.py` also compiles the pinned QEMU `pauth_addpac`,
`pauth_original_ptr`, `pauth_auth`, and `pauth_strip` functions without changing
their bodies. Fixture shims supply resolved address widths/TBI and feature
selection. The QARMA primitive remains QEMU's implementation. Its non-returning
fault hook records the complete authentication ISS and returns to the driver
through `setjmp`/`longjmp`. No RAX algorithm is used to produce expected values.

```sh
python3 tools/pauth-reference/verify_architecture.py --seed 0xa6420261024
```

The structured campaign covers both algorithms, all four accepted profiles,
every address width from 16 through 48 bits, both TBI settings, instruction/data
keys A/B, standalone/combined authentication, signing, stripping, arbitrary
inputs, signed inputs, and corrupted signatures. Default additional randomized
cases produce 25,216 total comparisons. It compares every result bit or the
exact fault ISS, requires a nonzero case count and actual faults, and has no
skip path. `--cases` selects additional random cases; structured cases always
run. This verifies the resolved PAC layout/failure model, not translation-regime
selection, privilege traps, CPU exception entry, SMIR, or native execution.

Print independently computed vectors for five distinct key slots:

```sh
python3 tools/pauth-reference/verify.py --cases 1024 --seed 0x5c0fed --known-key-vectors
```

This adds ten fixed input cases to the 2,048 random primitive cases: data=0,
modifier=1, key pairs (Lo,Hi)=(1,2), (3,4), (5,6), (7,8), (9,10), under
QARMA5 and QARMA3. The output labels algorithm 0 as QARMA5 and 1 as QARMA3.
The execution regressions in `src/smir/interpret/tests/pauth/keys.rs` retain
these QEMU MACs as constants, apply the specified 48-bit PAC field or PACGA
selection, and check distinct IA/IB/DA/DB/GA routing in direct, SMIR and native
execution. The oracle is not called back into RAX to generate expected values.

Darwin kernel-produced pointer fixtures have an independent generator:

```sh
python3 tools/pauth-reference/darwin_vectors.py --check
```

It compiles the unchanged QEMU signing functions, checks the six XNU string
discriminators using Clang's arm64e builtins, and checks all 20 retained vectors
for IA/DA thread-state pointers, ucontext pointers, signal pointer nonces,
function pointers and address-diverse shared-cache v5 rebases. Algorithm 0 is
QARMA5 and 1 is QARMA3; the fixtures use FPACCOMBINE and the Darwin 48-bit
instruction/data layouts. Omitting `--check` regenerates the JSON under the
reference documentation. The Rust Darwin tests consume those expected values;
the generator does not use RAX to produce them. This establishes signing values,
not task inheritance or signal behavior, which have separate process tests.

The mixed-width handoff encodings can be reproduced independently with Clang:

```sh
clang -target armv8a-none-eabi -c tools/pauth-reference/aarch32-handoff.s -o /tmp/rax-aarch32-handoff.o
llvm-objdump -d /tmp/rax-aarch32-handoff.o
```

The fixture contains 12 A32 instructions: a double-precision FP alias case,
all four exclusive widths, CLREX, MOV and WFE. The handoff tests additionally
use Thumb MOV `0x4608` and ADD SP `0xb001`. In particular, CLREX is
`0xf57ff01f`; it overlaps the old shared decoder's overly broad preload-hint
mask. Its explicit dispatch now precedes that mask. The instruction encodings
come from LLVM; execution-state and bank/PSR expectations follow Arm's retained
`LookUpRIndex`, `GetPSRFromPSTATE`, `RestoredITBits`, `AArch64_ExceptionReturn`,
and AArch32 exception/abort pseudocode. This is encoding evidence, not AArch32
hardware execution evidence.
