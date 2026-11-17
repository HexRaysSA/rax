# LLVM24 constant forms and required legalization

LLVM-CC finite audit, pin36763294ef639d8a6a4379d81da653dda1c20686. The generated
[constant matrix](constant-matrix.json) exhaustively enumerates all23 Constant
ValueIDs and13 retained ConstantExpr opcodes. inventory.py checks actual
Constants.cpp isSupportedBinOp/isSupportedCastOp and Value.def before generation.
All entries have implemented=false. Required staged expression materialization
is a named joint runtime interface gate; the current single-target relocations
alone do not close it. No envelope is executed by these witnesses.

## Exact retained expression universe

| ConstantExpr opcode | Required semantics and lowering |
|---|---|
| Add/Sub/Xor | Same-width scalar/fixed-vector integer bitvector operation, lane-wise poison/undef and source flags retained; ordered operands, not host integer overflow |
| Trunc | Low destination bits; source poison/undef transfer and supported no-wrap promises preserved |
| PtrToInt | Truncate/zero-extend64; actual source/domain context selects the cast. Data AS0 uses the selected exposure contract. Generic AS1 CodeAddress cast observes bits only; source CODE exposure requires its explicit preoptimization/staged source operation |
| PtrToAddr | Same address bits cast but captures address ONLY, no DATA/CODE provenance exposure; never substitute a ptrtoint relocation with implicit exposure |
| IntToPtr | Low64/zero-extend; data AS0 uses selected recovery. Generic AS1 CodeAddress conversion creates authority-free bits; observing source CODE recovery is separate. Bits alone mint no object or code authority |
| BitCast | Equal-size exact bit/shadow/origin transfer in portable little-endian lane/aggregate order, no host FP conversion or new authority |
| AddrSpaceCast | Identity only within the same validated semantic kind in AS0 or AS1. Cross-AS conversion needs its separately admitted exact contract; unknown/native spaces diagnose. No cast converts a block label into source CodeAddress |
| GetElementPtr | Portable DL constant index conversion/scaling/ordered offset addition, actual-base flags and final result-relative inrange exactly retained |
| ExtractElement/InsertElement | Exact fixed lane/index semantics; out-of-range index produces poison, other lanes/bit shadow retained |
| ShuffleVector | Exact constant ordered mask; poison mask lanes and input poison/undef handled by aggregate recipe; no guessed identity shuffle |

LLVM24 removes retained binary UDiv/SDiv/URem/SRem/FAdd/FSub/FMul/FDiv/FRem/And/Or/
LShr/AShr/Shl/Mul and casts ZExt/SExt/FPTrunc/FPExt/UIToFP/SIToFP/FPToUI/FPToSI.
A folded concrete constant can reflect any of those computations, but there is
no retained CE node with those opcodes at this pin. Legacy bitcode upgrades must
run the pinned reader and then use the resulting current IR; no invented opcode
is accepted. Select/ICmp/FCmp/Freeze/InsertValue/ExtractValue are also absent from
the retained CE grammar; their concrete aggregate results use ordinary constants.

A DAG is not assumed affine. Distinct-symbol subtraction, sum and XOR are valid
retained expressions. Algebraic rewrites require exact width/no-wrap/poison/
exposure equivalence. In particular moving GEP-before-cast to add-after-cast for
N>64 requires proof of no64-bit pointer wrap; widening changes those expressions.
Trunc(ptrtoint P) may fold to ptrtointN, but preserved source flags cannot be lost.

## All constant kinds

| ValueIDs | Exact policy |
|---|---|
| ConstantInt/ConstantByte/ConstantFP | Exact APInt/raw/APFloat payload bits and declared type; NaN payload/sign retained, no host numerical conversion |
| UndefValue/PoisonValue | Chosen zero refinement for ordinary undef; poison remains per-bit shadow. No branded E/journal/fenv/stack cookie is forged from either |
| ConstantAggregateZero | Recursively typed zero for ordinary present values; no valid opaque E/authority manufactured. Empty aggregates contain no present elements |
| ConstantArray/Struct/Vector | Ordered recursive fields/lanes, explicit physical layout/padding/storage shadow; fixed count resource bounds separate from ABI |
| ConstantDataArray/Vector | Exact packed data sequence using same ordered element rules, including strings with embedded NUL |
| ConstantPointerNull | Zero address/code token and no object/call authority; a function null cannot be invoked |
| Function/GlobalVariable | Actual selected portable function/data/TLS binding; no native PC/address, no guessed dependency-private ID |
| GlobalAlias | Checked kind/type/ABI/source-compatible selected definition; cycles reject before value construction |
| DSOLocalEquivalent | Select the actual resolved function/alias equivalent and issue its checked portable function token; choosing the original resolved function is the declared equivalent. IFunc operand follows optional IFunc rejection |
| NoCFIValue | Actual selected function token without a native CFI jump-table representation; portable signature/type/capability admission still applies, never disable portable call validation |
| ConstantTokenNone | Transient coroutine token only; required Split/Cleanup eliminates it, otherwise E-CONSTANT-RESIDUAL-TOKEN |
| ConstantTargetNone | Private E default is invalid; other target-extension defaults need the exact optional type profile, otherwise E-CONSTANT-TARGET-NONE |
| BlockAddress | Optional computed-label profile unavailable: E-CONSTANT-BLOCK-ADDRESS, including dormant address-taken blocks |
| GlobalIFunc | Optional GNU resolver/ISA multiversion extension: E-CONSTANT-IFUNC; ordinary required C23/C++23 functions never silently become native resolvers |
| ConstantPtrAuth | Optional native pointer-authentication profile: E-CONSTANT-PTRAUTH; never strip key/discriminator/address discriminator to claim equivalent authentication |

The accepted AS1 program allocation does not change this BlockAddress row.
LLVM gives a block address its containing function's program address space, so
both a source function address and a block label can have `ptr addrspace(1)`.
Only the actual original source/type/descriptor context selects the SMIR domain;
an AS1 check cannot turn a label into CodeAddress or callable authority. The
library-only witness records actual BlockAddress AS1 while preserving this
portable compiler diagnostic.

An optional type (scalable vectors, native address spaces, unrecognized target
extension) fails its explicit type/profile gate even inside an otherwise required
constant form. Required ordinary scalar/fixed-vector/aggregate symbolic expressions
cannot be relabeled optional simply because no single relocation represents them.

## Current relocation and required staging boundary

R039REV6 directly represents pointer data addresses, issued function/import tokens,
TLS provider-module offsets and single-target integer casts with ordered GEP
steps/inrange. normalize_indices independently discharges ORIGINAL constant-index
width conversion, multiply and accumulated-offset promises before flattening.
Known failure initializes poison without relocation/origin/exposure. Remaining
actual-base no-wrap/inbounds promises stay on each ordered i64 pointer step; final
inrange attaches ONLY to that source GEP result. Multiple source GEP nodes retain
their intermediate restrictions. Malformed lower>upper is an admission error.
ConstantExpr::getAsInstruction in the pin copies GEP no-wrap flags but omits the
constant inrange field: a future emitter must preserve it separately, not infer
that this convenience API is semantics-complete.

For instruction operands, expand a supported CE DAG into ordinary core operations
at the dominating use/phi predecessor with the original semantic edge and shadow;
no evaluation on an unexecuted path is permitted to add eager UB/effects. For a
static initializer, fold truly placement-independent leaves; direct relocations
are an optimization only when exactly equivalent. Other REQUIRED placement-dependent
DAGs need a staged pre-publication evaluator/initializer, after actual SCC binding
and storage/code placement and before any source-visible initializer or concurrent
access. Byte/shadow/origins/exposures commit together or not at all, including
readonly storage. TLS-dependent expressions require per-logical-thread template
instantiation, never one arbitrary host thread's pointer.

The exact candidate composition is INT018REV2/R041/S074. Section5 root fields are
`payload_revision,relocations,constant_initializers`; each initializer has ordered
`id:u32,source_kind:token,source:u32,offset:u64,layout:entity_ref,function:entity_ref,
association:opt:entity_ref`. Function/layout are SELF, result type equals the actual
physical layout.type, access_bytes positive, and whole source allocation/segment alignment and whole-segment selection ownership
are independently checked. Private Raw8 patches use access alignment1, including
packed scalar byte offset1; layout.alignment is allocation geometry, not an
automatic patch-offset constraint. Shared-byte bitfields require one joint
aggregate result so separate typed stores cannot zero neighboring bits. The existing SEM
execution grammar is reused: no new expression VM or public opcode IDs.

The restricted initializer has portable fixed Fn()->[T], ABI None, param_noundef[],
result_noundef[false], no_return=false, escape=propagate, exactly one block/no phis/
EH and one return. Its23 allowed existing operations are constant/copy/freeze,
i_add/i_sub/i_xor/i_mul/icmp/select, extract/insert/extract_element/insert_element/
shuffle, trunc/zext/sext/bitcast, ptrtoint/ptrtoaddr/inttoptr/ptr_offset/address_of.
These are a lowering closure; the LLVM retained CE grammar remains13 opcodes.

Original GEP indices may themselves be placement-dependent CE, e.g a valid
`getelementptr inbounds(i64,ptr@a,i128 ptrtoint(ptr@b to i128))`; the actual pin
preserves this case. For symbolic indices, use integer casts/roundtrip comparison
and select-poison for original width promises, flagged i_mul/i_add for stride and
accumulated offsets. `ptr_offset.check_base` AFTERinbounds (S075) distinguishes
nonzero ORIGINAL index from computed byte delta0, including zero-sized strides.
Select the original base only when ALL original indices are zero; unselected
strict-pointer poison creates no eager fault. Then apply the source GEP NEW inrange
with an unflagged offset0/check_base=false step to the selected result, intersecting
its prior range. Even all-zero indices cannot erase the newly declared restriction. Typed lanes are handled independently.
Known indices still use normalize_indices before flattening. Historical ptr_offset
check_base=false retains its old zero-byte exemption; true requires inbounds.
Tombstone object/generation/extents remain valid for GEP, actual dereference checks
liveness separately. No +1/-1 validation workaround at zero extent/one-past.

S074 evaluate_initializer consumes an actual verified RootContext, private actual
Memory reservations, selected qualified symbols/code entries and explicit budgets.
It returns typed Value, Raw8 tuple and COMPLETE private DATA/CODE exposure sets;
input objects/maps/exposures are unchanged. R041 owns selected source/generation/
lease/TLS authority, all-patch atomic commit/readonly sealing, previous staged
exposure visibility and original source constructor ordering. Budget checks cover
cumulative object/SSA/output bytes and value/fact nodes before materialization.

Published R041/R044/S074/S075 and R043 interfaces cover staged materialization,
selected association, strict source-GEP obligations and authenticated weak absence.
The independent reference consumes actual verified RootContexts and owner-issued
reservations. Missing weak symbols issue no data/code authority; provider AND
consumer snapshots are checked before use. Combined runtime selection, transaction
and whole-module admission receipts are external integrator-owned qualification.
No production static linker or LLVM emission follows from these reference checks.

## Independent source evidence and limitations

`global_initializers.py` generates10 header-free cases in C23/C++23, two LP64
existing targets, O0/O2/full-LTO-prelink/ThinLTO-prelink:160 compilations. Both
architectures observe the same classification in this finite sample:

| Source case | C23 | C++23 |
|---|---|---|
| pointer to unsigned long; via64 to _BitInt33; pointer+integer bias | static ptrtoint/GEP | static ptrtoint/GEP |
| direct pointer to unsigned int/char | frontend rejection | frontend rejection |
| via64 to _BitInt65/uint128; mask; distinct-object difference | nonconstant initializer rejection | zero initializer plus source dynamic constructor |
| same-object difference | nonconstant initializer rejection | O0 dynamic constructor; optimized initializer4 |

This is source behavior at the pin, not a source-language extension guarantee or
exhaustive reachability proof. The first _BitInt33 physical global is64 bits;
logical33-bit meaningful bits/padding follow the source binding. `relocation-forms.cpp`
adds ordinary absolute Itanium vtable inrange(-16,8), not an optional relative-vtable
extension. `constant-expressions.ll` independently parses retained multi-symbol
Add/Sub/Xor, casts and DSOLocalEquivalent/NoCFI wrappers in pinned Clang. The parser
folds trunc(ptrtoint64 P) to ptrtoint7 P. `gep-prefix.ll` shows equal netzero with
different original promises; LLVM O2 may legally refine those poison cases to base.
No universal compiler equivalence, portable guest execution, native relocation
execution or LLVM24 postlink LTO execution is established by these probes.

Primary source identities/licenses/checksums are in sources.json and the
integrator-owned archive: Constants.cpp/.h, Value.def, LangRef.md and the existing
frontend/backend/ABI sources. Exact ISO clause attribution not archived here is
unknown; project compiler contract choices are stated as such.
