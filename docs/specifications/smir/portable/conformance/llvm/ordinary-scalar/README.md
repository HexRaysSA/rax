# Independent ordinary source scalar cases

These complete executable-format objects are independently source-authored in
`tools/smir-llvm-contract/ordinary_scalar_cases.py`. Each carries source nominal
types, source layouts, original call plans, actual execution FullFn types,
function SSA bodies and source-linked symbols. The shared seed supplies only
the existing site/container records. Scalars and plans are rebuilt explicitly;
no host C type, default function inference or other role's case generator is
an oracle. Canonical nominal fingerprints use the actual ABI implementation.

| Coverage | Cases | Required Rust result |
| --- | ---: | --- |
| Ten exact builtin identities in both C23 and C++23 | 20 | verified-object |
| Zero/mixed arguments, void, no source default, execution alias, multiple plans | 8 | verified-object |
| Invalid signedness, precision/layout, lowering, source/physical joins and returns | 12 | exact semantic rejection |
| Some(void), plain char | 2 | P2_ABI_VERIFIER_INCOMPLETE |
| Hidden source symbol | 1 | P2_METADATA_PROFILE_UNAUDITED |

Python independently verifies the full ABI, execution and runtime metadata
semantics. It accepts the three semantically valid excluded coverage controls;
Rust must keep those exact explicit coverage refusals. ABI rejection uses the
actual ABIError class; execution and metadata rejection uses Reject. A framing,
resource or unavailable-evidence error cannot satisfy a semantic negative.

The source-only function has `execution=None, representation=none`, while its
original explicit CallSignature still supplies the actual FullFn. Canonical
source void uses an actual void nominal at the end of the source prototype,
`CallSignature.result=None`, no lowered results and no FullFn results. Some(void)
is a distinct semantic-valid excluded form. Long and long long, and signed and
unsigned source identities, remain distinct even with equal physical widths.

The multiple-plan case includes independent Int64 and Int8 source prototypes,
original plans, executable bodies and source-linked symbols. The structural
alias case uses different actual Int32 IDs in an equal FullFn. The wrong source
identity case uses long versus long long with equal physical Int64 and a valid
source-only alternate prototype, requiring an actual nominal join refusal.

Run from the repository root:

```
python3 -B tools/smir-llvm-contract/ordinary_scalar_cases.py generate
cd tools/smir-llvm-contract
SMIR_SCALAR_RUST_CLI=/absolute/path/to/current/smir-inspect \
  python3 -B -m unittest test_ordinary_scalar_calls -v
```

The tests regenerate exact wire bytes, check all 76 prior metadata/generic
fixture hashes, invoke genuine Python factories in separate normal/optimized
processes and invoke the actual Rust whole-object verifier. Source, schema,
fixture and binary hashes are guarded across each run. Generation never updates
an expected-result contract from observed verifier outcomes.

Assumptions and falsification probes:

| Assumption | Probe | Dependent claim |
| --- | --- | --- |
| Explicit source names, signedness and LP64 geometry determine the finite profile | Every builtin plus source identity, signedness, width and layout negatives | Finite static scalar coverage |
| Source and execution reference namespaces remain distinct | Wrong lowered type, explicit FullFn, source-plan and structural alias cases | Actual ABI/metadata joins |
| None and Some(void) retain their original meanings | Canonical void and excluded Some(void) control | No normalization/inferred plan |
| Original private factories decide proof issuance | Real old/new Rust and independent RootContext; no fake facts | Static verification only |
| Shared sources can change | Before/after input hashes; immutable qualification copy | Exact recorded source cut |

Generation uses O(total serialized case bytes) time/space, apart from the genuine
validators' bounded graph/fingerprint costs. Multiple source scalar/layout and
function/plan rows prevent a one-I32-cardinality shortcut. Widths are bits;
layout size/alignment and serialized integer lengths are octets.

Primary contracts: portable `03-abi.md`, execution/ABI/runtime `candidate.json`
schemas, and the actual compiler-contract source snapshot. Named cross-role
decisions and exact before/after receipts are held by the integrator and LLVM
coordination handoff. This corpus does not issue runtime authority or execute
guest/source functions. Bound source calls require the separately released CLI
revision and actual machine/registry witnesses. No native, JIT, hosted-library,
parallel-execution, foreign-C++ or compiler-freeze completion follows from it.
