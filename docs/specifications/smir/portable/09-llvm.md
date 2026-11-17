# LLVM compiler contract

Status: **CC-L compiler contracts and independent witnesses; no SMIR frontend or emitter**.
Combined qualification is recorded by the integrator outside candidate inputs.

[CC-L closure](llvm/closure.md) supersedes the initial diagnostic-only boundary. Required constructs now have exact lowering recipes and candidate bindings; optional native/language extensions alone diagnose. Contract choices are separate from later implementations.
Required constant-initializer materialization and coroutine partial-object adoption
use the exact coordinated interfaces in [constants](llvm/constants.md),
[coroutines](llvm/coroutines.md) and [retained lifetime notes](llvm/lifetime-markers.md).
Current combined admission and qualification remain integrator-owned checks.
This package specifies the compiler boundary and classifies the pinned LLVM
universe. Classification is not implemented lowering. Every generated matrix
row records `implemented=false`; diagnostics identify optional nonbaseline extensions or invalid internal input. The existing envelope remains non-executable.

LLVM-001: Source baseline is LLVM commit
`36763294ef639d8a6a4379d81da653dda1c20686` (source version **24.0.0git**).
Installed or build-directory executable identities are separate evidence:
Clang and TableGen in the reference build report 24.0.0git, Clang names this
commit, but `build/bin/opt` reports **23.0.0git**. The latter is an independent
bootstrap oracle for the documented generic-IR subset, never a pinned LLVM24
execution claim. Sources, identity, license and SHA-256 are recorded in
[llvm/sources.json](llvm/sources.json); the integrator owns primary-source archival.

LLVM-002: The proposed target is `smir64-unknown-rax`, LP64, little endian,
64-bit pointers and pointer indices. Personality and container are independent
options; no host or selected personality changes language layout. Candidate
DataLayout and remaining prerequisites are in [llvm/target.json](llvm/target.json).
Accepted logical data space0 and program space1 append
`-pe1:64:64:64:64-P1`: stable external state, 64-bit size/index/ABI/preferred
alignment and zero null bits. Function-pointer storage addresses remain data
space0. This allocation supplies no runtime origin or call permission. LLVM
BlockAddress also has program space1 and retains its computed-label rejection;
the actual admitted source/type/descriptor context selects the semantic domain.
Compiler-private parameterless `smir.code_binding` and `smir.source_scope` are
unsized SSA-only carriers, with no source ABI/storage/freeze/foreign escape.
TargetInfo/ABI settings and storage exceptions are specified in
[llvm/frontend.md](llvm/frontend.md). Both direct and indirect parameters/results
are logical values or explicit guest storage; never physical registers. Host
headers, va_list, native TLS, long double or Microsoft LLP64 defaults cannot be
substituted. No existing target compiled with an edited triple is portable IR.

LLVM-003: Implement a registered TargetMachine with a shared IR-to-portable-SMIR
lowering engine after compiler freeze. Legacy `addPassesToEmitFile` and new-PM
`buildCodeGenPipeline` must invoke the same validation/lowering/serialization.
Keep values virtual; RAX allocates host registers in its later JIT. Pinned SPIR-V
provides a concrete virtual-register reference: its pass config returns null
from `createTargetRegisterAllocator` and disables physical-register assumptions.
This does not make the SPIR-V instruction set, ABI or module rules reusable as
SMIR semantics. Exact existing hooks and planned additions are mapped in
[llvm/integration.md](llvm/integration.md).

LLVM-004: Coverage is exhaustive for the pinned finite source inventories:

| Inventory | Rows | Evidence |
|---|---:|---|
| Instruction.def opcodes, including internal UserOp1/2 | 69 | [instruction matrix](llvm/instruction-matrix.json) |
| TableGen-expanded intrinsics, all targets | 16601 | [intrinsic matrix](llvm/intrinsic-matrix.tsv) |
| Intrinsics with empty TargetPrefix | 474 | Same matrix; target-independent does not imply supported |
| TableGen Attr definitions | 115 | [attribute matrix](llvm/attribute-matrix.json) |
| LLVM TypeID definitions | 22 | [type matrix](llvm/type-matrix.json) |
| Constant ValueIDs / retained ConstantExpr opcodes | 23 / 13 | [constant matrix](llvm/constant-matrix.json) |

Each row is an exact required operation/expansion/helper recipe or an optional-extension diagnostic. [lowering-contracts.json](llvm/lowering-contracts.json) and [candidate-bindings.json](llvm/candidate-bindings.json) record the current core/import mapping. No emitter implementation is inferred.
Unknown opcodes/type IDs fail inventory regeneration. Unknown intrinsic names,
arbitrary string attributes, metadata with semantic effects, operand bundles,
address spaces and module flags require diagnostics, never permissive defaults.
TableGen expansion includes multiclasses and defm; regex enumeration of intrinsic
source declarations is insufficient. Completeness is not semantic implementation.

Poison, undef, freeze, signed division/remainder, vector masking and raw byte
semantics are defined or explicitly excluded in
[llvm/refinement.md](llvm/refinement.md). LLVM24 `PtrToAddr`, split branch opcodes,
and `ByteTyID` are included. A discarded poison-producing instruction cannot
become an eager trap. Raw poison/provenance, FP/fenv, atomics, calls, varargs, TLS, EH and ordinary C++ coroutine legalization use the CC-L recipes and coherent candidate records. Cross-role option/catalog/ABI bindings require current combined verification, rather than generic missing-contract diagnostics. A similarly named architectural OpKind is
not evidence of portability.

LLVM-005: The eventual `.smo` pipeline must verify LLVM IR, validate the exact
triple/layout/ABI/profile, perform proven expansions, reject every unsupported
construct, construct symbolic portable records, run semantic/link verification,
and only then serialize. Failed compilation publishes no accepted output.
Symbols, relocations, TLS, exception records, capability requirements and debug
source maps use accepted module schemas; no raw host addresses or native assembly
round trip. LTO, separate compilation and all driver/pass-manager paths share
this engine. Object magic/readers/archive indexing and dedicated sysroot/driver
integration are required; their exact source hooks are in integration.md.

LLVM-006: No compiler backend work starts before accepted cross-role contracts,
public ID allocation, payload grammars, independent fixtures and current combined
validation establish compiler freeze. [request.schema.json](llvm/request.schema.json)
and the local request checker validate draft metadata only; the checker always
rejects emission with `E-COMPILER-NOT-FROZEN`. It is not an LLVM IR verifier,
semantic verifier, executable format or proof of source provenance.

## Reproduce the LLVM package checks

From the RAX root, Python 3.11+ and the reference LLVM tools are required:

```sh
SMIR_LLVM_ROOT=/Users/int/dev/llvm-project \
  python3 -B -m unittest discover -s tools/smir-llvm-contract -p 'test_*.py' -v
python3 -B tools/smir-llvm-contract/inventory.py \
  --llvm /Users/int/dev/llvm-project
```

Set `SMIR_LLVM_BIN` to an explicit tool directory if necessary. Missing tools,
revision mismatch and unobserved witnesses fail; no tests silently skip. The
inventory command checks current generated bytes; `--write` regenerates only
LLVM-owned generated matrices. Use an isolated `TMPDIR` for parallel work.

The independent witnesses cover mathematical scalar integer refinements,
LLVM DataLayout allocation/alignment/field offsets, optimizer constant folds,
and freestanding C23/C++23 language/layout subsets plus nontrivial EH/RTTI/coroutine/TLS/atomic/varargs/strict-FP IR on an explicitly named existing target. They also observe rejection of the absent SMIR frontend.
They do not execute portable SMIR, qualify hosts, test hosted libraries, perform
foreign unwinding, or establish all choices of nondeterministic LLVM semantics.

[upstream-gaps.json](llvm/upstream-gaps.json) preserves the pinned Clang C23/C++23
and libc++ C++23 status rows that are incomplete/partial/unknown, with paper
links and source identity. Upstream status documents are not executable standards
certificates. LLVM libc's documented partial macOS/Windows support is distinct
from the wholly unimplemented SMIR library port. No unconditional hosted
C23/C++23 conformance claim follows from `-std=c23` or `-std=c++23` acceptance.
