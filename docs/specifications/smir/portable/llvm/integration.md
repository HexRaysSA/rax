# Pinned integration map and emission protocol

All paths below are in LLVM source commit
36763294ef639d8a6a4379d81da653dda1c20686. Existing hook means inspected source,
not a SMIR implementation. Planned paths do not exist in that checkout and are
not created by the first wave. Source hashes are in sources.json.

| Surface | Existing integration point | Required later change |
|---|---|---|
| Triple identity/layout | llvm/include/llvm/TargetParser/Triple.h; llvm/lib/TargetParser/Triple.cpp | Add smir64 architecture and rax OS identity/parser/printing/layout; personality remains separate |
| LLVM target registration | llvm/lib/Target/SPIRV/TargetInfo/SPIRVTargetInfo.cpp; TargetMachine registration in SPIRVTargetMachine.cpp | New llvm/lib/Target/SMIR/ and target info/TargetMachine registration |
| Pipeline API | llvm/include/llvm/Target/TargetMachine.h | Override legacy addPassesToEmitFile and new-PM buildCodeGenPipeline through shared engine |
| Virtual-value pipeline reference | SPIRVTargetMachine.cpp; SPIRVCodeGenPassBuilder.cpp | Disable physical register allocation/stack/frame assumptions; never import SPIR-V ABI semantics |
| Target-independent optimizer | llvm/lib/Passes/PassBuilderPipelines.cpp | TargetTransformInfo/cost model and legal portable expansions; verify post-optimization IR |
| Mandatory pre-optimization legalization | clang/lib/CodeGen/BackendUtil.cpp; llvm/include/llvm/Passes/PassBuilder.h | Run full-width powi expansion before first simplification at every frontend/IR/LTO entry; see exact phase hooks below |
| Clang target allocation | clang/lib/Basic/Targets.cpp | Allocate new SMIRTargetInfo; no host-dependent SPIR HostTarget fallback |
| Program pointer space | clang/lib/CodeGen/CodeGenTypes.cpp getTargetAddressSpace; CodeGenModule.cpp | Use exact DataLayout program AS1 for unqualified function types, data AS0 for storage addresses; actual source/type/descriptor facts choose semantic domain, never AS number alone |
| Target properties | clang/include/clang/Basic/TargetInfo.h; clang/lib/Basic/Targets/{SPIR,WebAssembly}.h | New clang/lib/Basic/Targets/SMIR.h/.cpp with ABI-owned data model/macros/va_list/atomics |
| Clang ABI dispatch | clang/lib/CodeGen/CodeGenModule.cpp | Select dedicated SMIRTargetCodeGenInfo |
| Logical argument ABI | clang/lib/CodeGen/Targets/SPIR.cpp reference | New clang/lib/CodeGen/Targets/SMIR.cpp; custom ABIInfo, EmitVAArg and aggregate copies/sret |
| BitInt/record storage | clang/lib/CodeGen/CodeGenTypes.cpp; CGRecordLayoutBuilder.cpp; clang/lib/AST/RecordLayoutBuilder.cpp | Preserve AST source size/alignment/field offsets separately from LLVM iN SSA precision |
| Portable C++ | clang/lib/CodeGen/ItaniumCXXABI.cpp; CGCXXABI.h | Pinned GenericItanium configuration, even code tokens, logical EH and typed descriptors |
| Clang driver | clang/lib/Driver/Driver.cpp; ToolChains/Clang.cpp | Target/sysroot/tool selection and direct .smo output; no host linker/header fallback |
| Binary recognition | llvm/lib/BinaryFormat/Magic.cpp | Recognize exact accepted SMIR envelope/object identity; recognition grants no execution |
| Object readers | llvm/lib/Object/{Binary,ObjectFile}.cpp | Symbol/section/relocation reader for accepted format; unsupported revision diagnostic |
| Archives | llvm/lib/Object/ArchiveWriter.cpp | Object symbol indexing for .smo and deterministic archive behavior |
| Runtime libraries | compiler-rt/lib/builtins/CMakeLists.txt; libc/docs/porting.md | Build portable helpers/libc with exact guest ABI and imports |
| C++ libraries/unwind | libcxxabi/src/CMakeLists.txt; libunwind/src/CMakeLists.txt; libcxx ABI docs | Required dedicated logical-SMIR/private-EH source ports under the selected ABI site; see exact component set below |

The required pinned portable source components are exactly `libc`, `compiler-rt`
builtins, `libcxxabi`, `libcxx` and `libunwind` (R049REV2). The last component is a
DEDICATED RAX-adapted logical-SMIR/private-EH source port, selected by the existing
ABI site options and `rax_logical_libunwind` identity. It integrates the existing
typed logical SEARCH/CLEANUP/E/journal/personality protocols; component selection
introduces no additional exposed library API, opcode or signature. Actual library
and runtime implementation remains later-gated.

Pinned libunwind is also a native/foreign CFI/personality reference. Actual foreign
frames still require independently admitted code/build/personality/CFI/lease facts.
This reference role does not replace its required portable source-port role.
Unmodified native/host libunwind or ordinary native `_Unwind_Context`/
`_Unwind_Exception` header ABI cannot substitute for SSA-only private E. There is
no automatic host unwinder fallback. Selected CMake options describe the dedicated
port to implement, not a claim that unmodified upstream builds or unwinds SMIR.

Source-path existence and hash checks are executable. The exact eventual LLVM
class/file names are proposals; no backend source or build configuration was
modified. In particular, physical register allocation is postponed to the RAX
x86-64/AArch64 JIT, not implemented by this package.

## Single lowering engine

```
Clang / hand-authored IR / LTO
              |
     verify LLVM IR + origin/profile
              |
  target/layout/ABI/construct validation
              |
  mandatory pre-optimization legalizations
              |
    permitted LLVM optimizer pipeline
              |
  post-optimization verify + legalize
              |
    symbolic portable module
              |
 semantic + reference/link verification
              |
     buffered canonical serialization
              |
  atomic output publication (.smo)
```

Fail before publishing output on unsupported constructs, helper requirements,
missing metadata, resource exhaustion or semantic/link verification failure.
Never execute a framed payload to discover whether it is valid. A later backend
must use an unpublished buffer/temporary in the output directory, verify fully,
then atomically publish on success. Truncating a requested final output before
verification would violate this contract.

Pass the same target identity, ABI revision, profile, capability requirements,
accepted schema hash and library configuration to legacy/new-PM and LTO paths.
No path may skip validation because its input came from Clang or a prior object.
An LLVM verifier success does not establish portable type/CFG/memory/ABI semantics.

### Pinned wide-power hazard and exact pipeline coverage

At this pin ConstantFolding.cpp converts the powi exponent with
`static_cast<int>(getSExtValue())`; an actual Clang24 -O1 witness folds
powi.f64.i64(2,4294967296) to1. A final backend-only pass cannot recover the lost
exponent. Required full-width square-and-multiply legalization therefore precedes
ANY optimizer simplification, including O0, imported IR and pre/post-link LTO.
Freeze the exponent once before control use; unsigned modular absolute value
handles signed MIN without nsw overflow. Width1 consumes its only bit then uses
zero instead of an overshift. Fixed-vector base expands lane-wise with a shared
frozen scalar exponent. Ordinary FP uses nearest-even multiplication/division
without guest fenv updates; this selects a permitted multiplication sequence,
not a correctly-rounded real-power claim. Fast-math promises remain separately
validated; unused poison never becomes a branch-UB through expansion.

| Pipeline entry | Exact pin hook / ordering |
|---|---|
| Clang frontend and standalone default IR pipeline, O0 and optimized | PipelineStartEPCallback before simplification, additionally explicit driver-owned pre-pass for custom pipeline entry |
| Full/ThinLTO pre-link | Same pipeline-start hook; include FatLTO and both emitted partitions |
| FullLTO post-link, including O0 | FullLinkTimeOptimizationEarlyEPCallback |
| ThinLTO post-link | ThinLinkTimeOptimizationEarlyEPCallback |
| Post-optimization linked builtin bitcode / external module imports | Legalize immediately after link and before any new simplifier, then validate final module |
| Custom pass pipelines | Driver-owned pre-pass required before first pass; unreviewed plugin/pipeline has no supported source-equivalence claim |

PassBuilder.h explicitly states PipelineStart does NOT cover backend LTO;
registering it alone is insufficient. The owned driver assembles these phases
through one legalization engine. Current pin SimplifyLibCalls creates new powi
with TargetLibraryInfo int width32; InstCombine recombines existing powi exponent
types. Initial elimination of wide forms plus this audited creation set prevents
wide recurrence in the permitted standard pipelines. The creation audit is
invalidated by a source-pin/pass-pipeline change. Post-pass validation is useful
but cannot repair an already folded wrong constant. External IR is interpreted
as the supplied IR; an origin string is never evidence that an earlier arbitrary
optimizer preserved another source program. These are exact future integration
requirements; the witness generator implements no backend or LLVM modification.

The request schema is a strict *local metadata* grammar, not LLVM serialization:
revision, source LLVM revision, target triple, exact DataLayout, declared origin,
personality, carrier, address spaces, inline-assembly presence, operand bundles
and module flags. Request declaration is not attested frontend provenance.
`gate.py` rejects all emission attempts regardless of valid metadata. No current
RAX runtime invokes this tool or admits its results.

## Coverage and rejection rules

1. Verify exact source pin and source-hash manifest; exhaustive matrix generation
   expands Intrinsics.td and Attributes.td with TableGen dependency files.
2. Verify the full LLVM module, including unreachable functions/blocks and global
   initializers. Unsupported constructs in dead code remain diagnostics until a
   proven legalization removes them; do not emit a partial executable.
3. Type rules include widths, data AS0 and allocated stable external-state program
   AS1, aggregate fields, vector counts and exact signatures. Preserve the exact
   `-pe1:64:64:64:64-P1` contract. Raw byte types preserve bit-level shadow through
   candidate raw records. The six exact parameterless compiler carrier names have
   their closed source/context/SSA restrictions; other TargetExt names/parameters
   and scalable types diagnose. B/S are unsized SSA only, never public source ABI,
   ordinary memory, freeze or foreign escape. BlockAddress keeps its computed-label
   diagnostic even in AS1; actual source facts select CodeAddress versus typed code,
   native or label domains. Existing typed internal AS0 helper representations keep
   their explicit descriptor context and are not silently relabelled by this source
   function-address allocation.
4. Integer flags have transfer rules, not host-ISA flag assumptions. Semantic
   metadata, constrained FP, operand bundles and arbitrary string attributes must
   be recognized explicitly; unknown semantics diagnose. Pure debug records may
   map to optional source maps. Omission must not drop mandatory capability data.
5. Globals need exact mutability/alignment/initial bytes, TLS model, linkage,
   visibility, COMDAT and initialization order. Native block addresses, host
   pointer initializers, inline assembly and target-specific linkage conventions
   diagnose. Symbolic relocations cannot be replaced by host process addresses.
6. Calls require a canonical normalized signature, ABI attribute validation,
   ordered arguments/results, checked code token and continuation. Variadics,
   musttail, exceptions, setjmp/longjmp, callback reentry and dynamic module leases
   use exact CC-L recipes and accepted candidate call/ABI/EH/helper bindings; no generic missing-contract fallback.
   Source C/C++ language linkage uses ABI030's explicit boundary projection,
   not general source-language erasure. Function type entity is canonical function;
   actual C/mangled symbol belongs to linkage/export. Complete value layout and
   source plan remain checked independently of equal execution pointer shapes.
7. Ordinary C++ Switch coroutines use the exact [phase-specific pipeline](coroutines.md),
   typed portable header, aligned-allocation policy, pre-Split opaque liveness check
   and current-child lifetime ownership contract. ThinLTO prelink may retain
   coroutine intrinsics; FINAL serialization rejects residuals. Split precedes
   logical journal instrumentation; passing CoroSplit alone proves no runtime support.
8. Atomics must use accepted parallel helpers with legal success/failure orders,
   scopes, width/alignment, backing-object alias and lifetime rules. Strengthening
   to SC is allowed only within the accepted runtime contract; a lock-based
   implementation never reports a lock-free result.

The current table specifies all required integer/aggregate/raw/FP/memory/call/EH/atomic/helper lowerings; optional native/ISA/language extensions diagnose. It implements zero emitter lowerings. Newly generated rows cannot inherit an implementation
claim. Updating a whitelist requires exact semantics, fixtures and affected-role
acknowledgement before changing the compiler-freeze evidence.

## Required compiler/runtime helper boundary

CC-L exact helper/import candidate ABI is published in schema/runtime/helpers-v1.json and candidate.json, with R-010 options and normalized signature/type bindings. Central review and combined semantic admission still govern freeze. The OS import catalog is distinct from
compiler-internal checked memory, stack lifetime, atomics, TLS, fenv/binary128,
varargs, EH and nonlocal-control helpers. Each future helper needs:

| Field | Contract |
|---|---|
| identity | accepted symbolic name, signature and version/capability binding |
| arguments/results | ordered guest types, sizes, alignments, pointer/code distinction |
| lifetime | thread/module/object/activation leases and alias identity |
| progress | exact logical next operation and side-effect commit point |
| failure | trap/status/exception identity and output state |
| concurrency | scope/order, locks, blocking, cancellation and reentry |
| admission | required metadata, resource bounds and fail-closed conditions |

Foreign compiler-generated bridges receive the ABI-P4 guest BridgeFrame through
a native ABI entry. Their implementation belongs to a later explicitly assigned
wave; generated metadata does not implement DWARF/SEH two-phase unwinding. A
binary-only C++ object without required metadata/adapters is an explicit error.

## Freeze and qualification evidence

The LLVM local suite checks source completeness/hashes, arithmetic/refinements,
DataLayout geometry, existing-target frontend subsets and negative request gates.
It observes no executable SMIR. Combined compiler freeze additionally needs
accepted execution/ABI/runtime payloads, complete reachable helper semantics,
resolved exceptions/raw-byte poison/FP, shared IDs, source archive and all named
consumer acknowledgements. Full six-host interpreter/JIT/library/foreign-domain qualification is a later independent gate. Missing production implementations are tracked separately from missing contract decisions.

Foreign WindowsGNU Itanium is distinct from portable logical EH and from physical
calling convention. Pinned C++ witnesses for x86_64/aarch64-w64-windows-gnu emit
landingpad with __gxx_personality_seh0; libcxxabi source provides its four-pointer
SEH entry. The normalized guest_itanium_seh profile binds independent Win64 or
AAPCS64Windows CC/Windows unwind evidence. Itanium object layout does not imply
SysV CC. No native Windows libraries or unwinding execute in this package.
