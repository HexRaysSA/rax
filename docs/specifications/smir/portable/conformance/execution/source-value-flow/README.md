# UNBOUND SourceValueFlow assertion reference

This package implements a closed executable JSON assertion schema, a static
checker over actual original RootContext ABI/body/type/SSA records, and actual
generic interpreter phi/select/freeze witnesses. It follows the draft ABI byte
09 plus mandatory10 flow shapes and07/08 source-init distinctions. It does not
implement their private source-body producer, sidecars, value events or source
entry protocol. Every result has source/category/body-proof/admission/runtime/
private-event flags false. Public observations remain constructible descriptions.
Fixtures retain the existing legacy source ABI epoch1 with explicitly declared
Raw8 nominals and generic core functions. New epoch2's genuine category-evidence
gate is not bypassed, downgraded or positively qualified by this tool; a real
ABI rejection propagates before any static success.

The local format is `source-value-flow-assertion`, revision1, with exact required
fields `format,revision,function,flows,nominals,seeds`. References in this initial
static profile are actual SELF references. The executable schema is
`schema/execution/source-value-flow-assertion.json`; unknown fields, floating
numbers, booleans as integer IDs, sentinel U32, duplicate JSON keys, NaN, excessive
depth/extent and unsupported tags reject. The checker executes the checked-in
closed JSON Schema subset directly, without an external schema service.

`flows` contains exactly the closed noop/phi/select/freeze variants from09/10,
tagged locally by `kind`. Rows are sorted/unique by actual result SSA ID. `nominals`
maps every actual scalar Raw8 definition to one declared original scalar/enum
8-bit value nominal with an actual Raw8 execution projection. `seeds` classifies
the remaining parameter/literal/numeric_to_byte/load/bitcast/call_result core
definitions, sorted/unique by value ID. These extra coverage rows are public
assertions, not the07 source-representation evidence payload or a new persisted
SourceContract table. Root alone assigns a future combined catalog/wire revision.

The API is `check(owner, assertion_bytes, *, budget)`. It requires the actual
RootContext class and canonical SourceQueryBudget, rechecks original snapshots,
executes actual ABI and whole-body verification, validates the closed assertion,
then checks its exact body coordinates and complete Raw8 definition coverage.
No unclassified unused definition or duplicate producer receives a default state.
NoOp accepts only actual scalar Raw8 copy/representation bitcast, with exact
operands and declared nominals; a numeric Int8-to-Raw8 conversion cannot masquerade
as NoOp. Freeze has its own exact operation/input/output record. Phi requires the
complete ORIGINAL ORDERED incoming predecessor/value vector. Select requires the
actual scalar Int1 condition, true/false operands and result. Raw8 FullFn
parameters/results require noundef=false.

Actual original source category, source numeric legality, initialized state and
AST-to-body equivalence are UNKNOWN to this public checker. In particular, equal
core Raw8 copy instructions cannot establish whether an absent original AST
conversion was a NoOp or an IntegralCast. A declaration saying unsigned char, a
nominal fingerprint, defined core bits, a static seed row or a generic core
parameter cannot issue initialized source state. A genuine source qualifier needs
09/10's actual registered source backend and private facts/events. Those APIs are
not called or fabricated here. Source representation seeds with load/call/bitcast
identify core definitions only; they are not proof of07/08 binding/source-law
eligibility, incoming tickets or a successful numeric source observation.

The five complete encoded modules contain: a loop with simultaneous Raw8 phi swap,
NoOp/select/freeze and an UNUSED byte definition; literal/numeric conversion seeds;
a literal-only body; maximum nonsentinel U32 SSA IDs; and 4,096 actual Raw8
definitions. There are39 authored assertion cases:6 positive and33 rejection
cases. Encoded octet lengths and SHA-256 hashes are explicit. Positive definition/
flow/seed counts are respectively8/5/3,4/2/2,1/0/1,2/1/1,4096/4095/1, and0/0/0
for the byte-free original identity function. The generator writes only this new
corpus; `--check` compares exact authored bytes without writing.

Actual core witnesses allocate two real guest objects and select Raw8 fragments
with equal bits and different actual allocation origins. They run the genuine
verified generic Machine, with no source-registry attachment. Observations check
parallel phi snapshots across1/2/3 loop iterations and both selection arms, one
actual select step, undef condition's existing zero refinement, poison selection
with no chosen operand, and actual freeze from poison to defined Raw. Diagnostic
ordinals are ordinary witness counters, NOT private dynamic value-birth facts.
The false private-event flag refers specifically to09 ActualCoreValueEventRef;
the existing Machine's ordinary internal frame/value observations stay intact.
No source-init mask is invented to claim source-runtime success from these tests.

This finite profile caps assertion input at4 MiB, JSON/schema depth64, each vector
at4096 and selected-body scalar Raw8 definitions at4096. Local checker/capture work
uses the SAME canonical B. Tests cover zero/no verifier entry, exact and one-less
work/edges/copied-octets, unchanged identity of the actual resource exception,
and actual copied-owner mutation after a real resource failure. Changed-owner
diagnostic is primary with that SAME unchanged resource object as explicit cause.
Both guards run after capture on successful and failed checks.
Original sections are checked for exact primitive container/value types BEFORE
profile lookups or verifier entry. A nonplain section's lookup callback is never
called. Both schema reads use explicit unbuffered FileIO and request at most the original
octet size plus one. This bounds returned bytes and the actual file-descriptor
position advance, not physical device/cache read-ahead or allocator/RSS costs.
Default BufferedReader prefetch is not used; a real
schema enlargement after body verification is a checked mutation, not an
unbounded read. Original capture is capped at1,000,000 nodes and16*2^20 Unicode
code points across keys/values. A fixed conservative LOCAL guard reservation is
charged to the same B before work:64*(node_cap+text_cap+1) work units,
4*node_cap edges,128*node_cap+32*text_cap copied octets. This funds the bounded
primitive afterguard even after resource failure; it is not a second ledger or
complete delegated-factory cost proof. Fourteen test methods cover these cases.

Full canonical-B cost of the delegated legacy ABI/body factories is NOT qualified
here; the result explicitly reports delegated_factory_cost_qualified=false.
Those real factories are bounded by their existing reference profiles, not a new
CPU/RSS or private-source quota proof. Static indexing/joins are O(N+F log(F+1)+E)
time and O(N+F+E) space for actual declarations/operations N, assertion rows F and
phi edges E, plus original factory/JSON capture costs and conservative local
reservation charges. No source array-extent enumeration or allocation by SSA ID
occurs. Maximum-ID and4,096-definition controls test these bounds structurally.

Source ellipsis is actual ABI metadata with a fixed execution Fn. The checker
refuses selected variadic source plans and wider direct Raw carriers in this
initial profile. The tests observe an invalid variadic CORE Fn rejected by the
real type checker; this is NOT a positive source-varargs admission witness.
No complete variadic-source-plan positive fixture is claimed. Coroutine source
identity and C23 indeterminate legality require genuine original source evidence;
this public body description cannot determine or qualify them. ABI09's varargs,
coroutine, wider-Raw and C23-indeterminate REQUIRED gaps remain open.

From the repository root, use a fresh absent cache prefix per command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/flow-generator-normal python3.15 -B tools/smir-format/execution/source_value_flow/generate.py --check
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/flow-tests-normal python3.15 -B tools/smir-format/execution/test_candidate_source_value_flow.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/flow-tests-optimized python3.15 -B -O tools/smir-format/execution/test_candidate_source_value_flow.py
```

Assumption register:

- VF1: the owner is the actual immutable original RootContext. Probe wrong type/
  subclass, changed owner, undefined body return and exact snapshot guards.
- VF2: public assertions provide no source truth. Probe all flags false, numeric
  cast mislabeled NoOp, missing unused definition, fake initialized undef/poison
  literal and no private source-event construction.
- VF3: real core phi/select behavior is distinct from future source-sidecar
  issuance. Probe simultaneous loop swaps, same-bit different-origin arms, actual
  selected operand and poison-with-no-selection; diagnostic counters are unbound.
- VF4: local canonical ledger/capture checks do not prove complete source-factory
  cost. Probe zero/exact/one-less and actual exception identity/mutation, retain
  explicit cost-qualified=false and separate required source/runtime work.

High impact: treating public flow coordinates/defined bits as source authority
would bypass actual source legality/initialization. Medium: private body producer,
dynamic SSA/ticket shadow, full source operation laws and exact factory costs
remain implementation work. Low: no existing wire/opcode/kernel/Rust/default or
lifted-ISA change. Passing this package cannot pass compiler/runtime freeze.
