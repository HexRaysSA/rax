# Pinned AST record-input witness

This isolated tool extracts source declaration facts and existing-target layout
observations from actual Clang AST libraries. It does not emit SMIR, implement a
SMIR TargetInfo, bind runtime symbols, compute nominal definitions, or authorize
execution. The input contract is INT030REV2 / immutable ABI024REV1, ABI payload2.
Its inspection report `clang-record-input-draft-v2` is not an executable schema
or an accepted nominal_type record. All nominal/source-symbol IDs remain local
inspection handles with an explicit caller-supplied logical owner.

Run from the RAX checkout, with build products outside both checkouts:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s tools/smir-llvm-contract/record_layout -p 'test_*.py' -v
```

`LLVM_REFERENCE_CHECKOUT` selects the read-only LLVM checkout. The source HEAD
and actual compiler version must identify pin
`36763294ef639d8a6a4379d81da653dda1c20686`. Existing static Clang libraries are
linked; absence is an error, never a skipped test. An observed stale shared Clang
library is excluded. Each run retains build argv, input/library/compiler/binary
hashes, diagnostics and actual source observations under
`/tmp/rax-portable-smir-01/LLVM/record-layout-runs/` by default. Override the parent
with `SMIR_RECORD_WITNESS_DIR` inside an authorized output directory. Build-input
hashes must remain equal during compilation; they attest the local artifacts,
not a reproducible LLVM build from source. No LLVM checkout build or edit occurs.

The CLI is `record-input-witness SOURCE LOGICAL_UNIT [c23|cpp23]`. Its fixed
header-free profile is `x86_64-unknown-linux-gnu`, C23/C++23, with pedantic errors.
Source input is limited to 1 MiB; 256 complete main-file record roots, 4096 type
nodes and 100000 producer graph-work units are bounded separately. The tests run
the tool with a 30 s timeout. These limits do not bound all Clang parsing work;
the tool is a local trusted-fixture witness, not an adversarial compiler service.
Headers, templates, modules and arbitrary frontend options are not qualified.

The producer preserves actual canonical QualType references, original logical
owner, source record declarations, top-level const/volatile, declaration-order
fields and bases, exact source traits and numeric explicit alignment. A reserved
placeholder precedes graph traversal, permitting recursive pointer edges. It
reads the full evaluated bit-field APInt and rejects values above UINT_MAX with
`E-SMIR-UPSTREAM-BITFIELD-WIDTH` before requesting that record's layout. This
avoids the pinned unsigned getBitWidthValue truncation; the portable u64 format
is not narrowed. Packed/MS layout attributes and dependent records are errors.
Accepted LLVM-PROD009REV2 normalizes actual implicit ordinary unnamed lambda
fields to Some($captureN), with N the zero-based index among all fields. Source
identifiers beginning $capture diagnose E-SMIR-RESERVED-METADATA-NAME. Other
implicit ordinary unnamed fields reject; they are never labelled anonymous.
Generic ABI structural validation checks index/name/nonanonymous/nonbitfield
consistency; it does not prove a lambda AST origin. Actual value/reference/array/
init/*this/empty capture witnesses preserve types, owners and selected names.

The native report includes size/alignment/data size/nonvirtual geometry, ordered
physical fields/bases, and all six vptr fields: offset, offset_top, rtti, slots,
vcall_offsets, vbase_offsets. RTTI and slots use explicitly unbound source
declaration namespaces, not runtime symbol references. Raw vtable component
indices and byte positions are retained. No callable code or RTTI object exists
by virtue of this report. Method types are inspection graphs and omit full ABI
function qualifiers/attributes; they cannot establish source signature identity.

Accepted INT033REV1 adds component_order, retaining all six original vptr fields.
For lengthL and indexi its exact negative slot is -8*(2+L-i) B. Raw thunk reports
retain separate this/return fixed and virtual displacements, source method
overrides and pointer-null/reference policy, all explicitly unbound. Typed
receiver/virtual-base slot queries preserve original source types. Construction
reports use actual VTTBuilder definition mode and actual construction layouts;
VTT indices resolve to exact group/address points and phase-specific RTTI source.
They do not bind source paths, runtime groups, callable recipes or RTTI objects.
No public dispatch schema is defined by these private inspection additions.

The separately released Stage W source function-address witnesses run with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s tools/smir-llvm-contract/record_layout -p test_fnaddr.py -v
```

These nine tests require the actual pinned compiler and preserve five header-free
fixtures. They check incomplete/complete source pointer forms, stable pointer-to-
array/prototype syntax, exact noexcept conversion direction and source rejections.
The char-copy fixture records i8 loads/stores at O0 and direct pointer forwarding
at O1; it proves neither portable origin preservation nor an ISO source-legality
guarantee. AST/IR/compiler hashes and diagnostics remain under the LLVM role's
external fnaddr-runs directory. No fixture program is executed. The accepted
S016 semantic contract does not implement these portable lowering operations.

Call observations record actual argument types after Sema; throw observations
record normalized payloads. The C23 BitInt witness distinguishes declared N from
bit-field widthM/native ABI coercion. Default C++23 extension and incomplete-
pointee rejection are parser/Sema observations, not an implemented SMIR frontend.

Three separate native IR fixtures expose open C++ compiler-contract boundaries.
An incomplete by-value function prototype permits pointer size, null/address
initializers and pointer copies without an actual call; Clang's address-only
`void()` declaration is not the eventual call ABI. Early pointer RTTI can retain
an incomplete class descriptor even after the class definition and a direct
typeid query. Complete/base constructor and destructor variants have distinct
hidden-VTT execution shapes despite sharing source declarations. The
test_native_boundaries suite verifies these actual pinned outputs and retains
compiler/source/IR hashes. It never executes the source program. Cohesive ABI038
logical/issued-plan and portable RTTI normalization choices remain unreleased;
opaque function-pointer representation and exact source-data/phase joins are
still contract gates. These observations do not create public records or IDs.

Native comparable geometry is restricted to the tested LP64 char/integer/pointer
and selected record subset. Native x86 long double, oversized bit-field container
selection (64 bits versus SMIR's 128 bits), calling convention, vector/_BitInt
layout and hosted library types are not portable oracles. AST trait extraction
preserves the pinned POD03 behavior, including its documented wide-bit-field
upstream limitation; it does not invent corrected traits.

| Assumption | Falsification probe | Dependent result |
|---|---|---|
| Existing static libraries match the pinned AST APIs | Compile/link and check library version; retain hashes | Local source extraction |
| Tested native subset agrees with selected portable geometry | Independent ABI model comparison after owner publication | Portable geometry comparison, currently absent |
| Canonical RecordDecl identifies top-CV variants of one source class | QualifiedEmpty const/nonconst test | Empty-subobject identity evidence |
| Every traversed field has representable source facts | Reject unknown types, layout attributes and implicit ordinary names | Draft record_input extraction |
| Declaration traversal terminates inside limits | Recursive graph and explicit resource guards | Finite fixture tool completion |

High impact: raw AST spelling cannot replace typed source metadata; typed VB
target and full final dispatch/VTT/RTTI/thunk relations remain the cohesive ABI038
contract gate beyond accepted INT033 component ordering. Medium impact: existing
native target geometry and local library provenance cannot certify portable
TargetInfo behavior. Low impact: report spellings are inspection text only;
tests select declarations using qualified record_name.

Primary APIs are from the pinned clang AST DeclCXX/Decl/ASTContext/RecordLayout/
VTableBuilder headers and AST RecordLayoutBuilder/VTableBuilder implementations,
archived by the integrator with identity, license and checksums. No external
service access is needed. See the integrator's accepted INT030REV2 decision and
primary-source index; this tool does not create a competing shared registry.
