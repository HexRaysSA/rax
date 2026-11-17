# Runtime contract witness map

All paths below are relative to tools/smir-runtime-contract unless marked SEM.
These are finite reference/compile witnesses; no row qualifies production runtime,
portable JIT, hosted library, launcher or all six native host configurations.

| Requirements | Positive/boundary evidence | Rejection evidence |
|---|---|---|
| MEM-001/002/003 | candidate/atomic.py arbitrary byte/shadow aliases; test_candidate_contract; legacy guarded memory | stale generation, revoke/drain, permission/range, mixed alias/fault atomicity |
| MEM-004 | atomic_probe.cpp 336 integer RMW comparisons,300000 flag hot ops,1000mixed-SC | illegal masks/orders/precision, failed CAS and source unknown comparison |
| MEM-005/006 | legacy independent.cpp2workers/20000alias updates/200ticket races; private handoff/frontier | duplicated worker epoch, forged ticket, bulk committed prefix/resource limits |
| MEM-007 | process_witness.py fresh process private/shared file behavior; nonlocal checkpoint | no inherited opaque host scheduler/locks, same-thread/source cleanup restrictions |
| LINK-001 | exact six-root joins; actual ABI full call plan/source-unit/deployment | wrong body/import/storage/source-plan/table/export/minor/site/grant |
| LINK-002 | all six COMDAT policies, ordinary redirects, actual symbol+function selection | unequal exactmatch, unionABI, missing loser member, independent physical aliases |
| LINK-003 | test_candidate_initialization actual SEM+R+Plan, static byte patches,old provider/TLS | overlap, unused inrange/strictbase, forged/stale/changedplan, sourcequota beforeclone, revoked held lease |
| RT-001 | 59 services, pinned four-personality error maps, actual memory.map wrapper | registered requirements, argument/buffer/handle/status/terminal errors |
| RT-002 | pinned hosted baseline/configuration contract; powi/fenv independent oracles | language/library gaps explicit; no native hosted-library build inferred |
| RT-003 | personality/ISA admission races; qualified TLS/private source-child cohort | incompatible ISA/personality, unreserved TLS, recursion, unauthorized TID, child/escape drain |
| JIT-001/002/003 | typed actual SSA/EH live frontier, nested journals, fresh dtor,process partial Builder | extra/missing values, wrong continuation/owner/gen/seed, branded opaque memory, code/CFI mismatch |
| JIT-004 | cache key/canonical state contract; native profile/TOP/MMX models | stale code/stack/TLS/CFI owner, reserved CPU state, unrecognized extensions |
| JIT-005 | six-host qualification matrix and explicit stage contract | skipped/cross-compiled/fallback cases cannot report native pass |
| PACK-001/002/003 | ELF/Mach-O/PE bounded discovery; explicit/installed/embedded launch descriptors | duplicate/corrupt locator, unsupported entry/personality/catalog/runtime selection |
| PACK-004 | include header21functions; pinned cross-targetC23/C++23 layout declarations12probes | version/size/reserved/handle/reentry/custom callback owner lifetime |

Runtime JSON corpus: legacy87 inputs remain unchanged; candidate86 inputs cover
ordered records, local root joins, services, fenv, startup, COMDAT, GEP steps and
new constant/seed record fields. check_candidate.py reports accept/reject totals.
Actual executable initializer, partial/capture/claim/lease and native-state
protocol cases are Python tests rather than schema-only JSON authority assertions.

Independent owner integrations are separate observations: SEM actual ten-root
constant/weak/TLS/capture witnesses; ABI actual nominal/call-plan/layout graph;
LLVM actual function comparison/math/IR/lifetime notes; integrator whole-module
admission. Their receipts must bind current input hashes; historical pass counts
are not added to this package's own unittest total.
