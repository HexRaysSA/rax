# ABI contract reference tools

These dependency-free Python3.11+ tools validate candidate ABI section10 and
preserved legacy models, with pinned Clang24 existing-target layout witnesses.
Independent C++ wire/native-language witnesses require a host C++23 compiler.
They neither grant executable admission nor execute SMIR or a foreign CPU adapter. Existing lifted-ISA paths are untouched.

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/smir-abi/check.py \
  --output /tmp/rax-portable-smir-01/ABI/check
```

A passing run prints nonzero test count, zero failures/skips, and PASS. Output
contains `receipt.json` with exact arguments, source/schema/fixture hashes, actual
HEAD, compiler binary/version/hash, Python/host identity and evidence limits;
`tests.log`; `compiler-witness.json`; and the emitted comparison LLVM IR in
`compiler/`. Output inside the checkout is rejected. Missing/mismatched compiler
or a zero-test run fails, rather than silently skipping the independent oracle.
No package installation is needed. Set `SMIR_ABI_CLANG` to a binary reporting the
exact LLVM36763294ef639d8a6a4379d81da653dda1c20686 pin; by default the supplied
`/Users/int/dev/llvm-project/build/bin/clang` is used. The compiler checkout is
read-only; all emitted files go to the chosen evidence directory.

Individual checks:

```sh
python3 tools/smir-abi/layout.py docs/specifications/smir/portable/conformance/abi/layouts.json
python3 tools/smir-abi/descriptors.py \
  docs/specifications/smir/portable/conformance/abi/descriptor.json \
  --evidence docs/specifications/smir/portable/conformance/abi/descriptor-evidence.json
python3 tools/smir-abi/witness.py --output /tmp/rax-portable-smir-01/ABI/witness
```

`layout.py` accepts `abi-layout-draft-v1` and returns size/alignment in bytes and
member offsets/widths in bits. Its arbitrary-precision equations do not call
Clang or use host ctypes. Closed schemas are under `portable/schema/abi/`.
`descriptors.py` requires a separate evidence
input and returns `admitted_for_execution:false`, even on success. Evidence
fixtures are synthetic trusted inputs to test validation, not real loaded-object
attestations. The production evidence producer remains unimplemented.

`protocols.py` supplies logical call classification, canonical little-endian
varargs packing/cursor validation, per-thread LIFO transitions and a two-phase
exception state model. These are sequential protocol witnesses. They do not
provide concurrency, foreign DWARF/SEH walking or destructor execution.

`contract_json.py` checks the exact closed JSON Schema subset used by this
package, rejects unsupported schema keywords, and offers canonical local JSON
encoding. It is not a general JSON Schema service or the SMIR envelope format.
No third-party schema library is installed. Payloads above16 MiB reject. Schemas
also bound record counts, widths, alignments and array lengths; cross-record
semantic constraints remain the models' responsibility.

`witness.py` compiles C23/C++23 without headers/sysroots for six existing triples.
Only x86_64 Linux with explicit binary128 long double is the complete comparison
profile for the small C layout corpus. Other target outputs are explicit native-
ABI differences, not portable results. C++ generic Itanium expectations include
hand-derived empty/base/tail-padding/member-pointer cases; full profile snapshots
are compiler regression fixtures, not an independent C++ implementation. Base
and virtual-base dump offsets are bytes; size/alignment/member offsets are bits.
No generated test is accepted merely because the compiler exits successfully:
record counts, values and expected layouts are compared.

The seeded differential uses0x41424901 and64 records of eight mixed-base
bit-fields plus a byte tail, preserving the source in test code and reproducible
seed. Negative descriptor cases are declarative mutations with expected symbolic
errors. Test logs distinguish expected compiler rejection (Microsoft wide C++
bit-field) from harness failure. The installed default Clang23 is intentionally
not the pinned witness; its location or a directory name is insufficient provenance.

See `portable/03-abi.md` and `portable/07-foreign-domains.md` for equations,
layout/call/varargs/ownership/callback/EH contracts and explicit freeze blockers.
No JSON grammar, generated profile snapshot or passing local receipt freezes the
compiler ABI. Current candidate source/execution/storage bindings, selected site manifest
and cross-role interfaces are reference contracts. Production source frontend,
hosted libraries, runtime/bridges and native mixed unwinding remain later gates.

To intentionally refresh only the ABI-owned existing-target profile snapshot:

```sh
python3 tools/smir-abi/witness.py --output /tmp/rax-portable-smir-01/ABI/profile-refresh \
  --snapshot-output docs/specifications/smir/portable/conformance/abi/compiler-profiles.json
```

Review changed outputs against pinned source and hand-derived expectations. This
snapshot command does not regenerate independent layout expectations or any
other role's artifacts. Portable va_list layout and array-parameter adjustment
are compiler-witnessed explicitly, separate from native __builtin_va_list.


The candidate package additionally provides:

| Tool | Purpose |
|---|---|
| candidate_schema.py/candidate_codec.py | exact ordered section10 grammar and independent bounded Python codec |
| candidate_probe.cpp/candidate_records.inc | independently implemented C++ ordered decoder |
| candidate.py/nominal.py/graph_identity.py | source type/layout/call verification and canonical source graph identities |
| execution_shapes.py | independent S028 execution bisimulation/identity oracle |
| storage_binding.py | exact source view, physical storage and effect-bit validation |
| namespaces.py | closed namespace/dependency declaration lookup |
| native_contract.py | typed action CFG/captures, CFI/personality/catch/bridge verification |
| construction.py/object_lifetimes.py | partial arrays, completed-object certificates and fresh destruction claims |
| candidate_varargs.py | registered caller tables/backing, callee cookies and typed decode before cursor commit |
| fenv_contract.py/site_config.py | exact source fenv state and pinned hosted-library configuration |
| c_boundary.py/c_interop_fixtures.py | explicit C-linkage function/data compatibility and complete C/C++ fixtures |

[CONTEXT.md](CONTEXT.md) specifies every admission callback and evidence boundary.
Do not replace actual-root resolvers by a predicate returning success. Foreign
build/type/layout/symbol/unwind certificates come from an independent registered
producer; synthetic fixtures are not such a producer. Source wrappers and internal
multiresult services have separate ABIs. Source scalar/sret rules are never relaxed
to make an internal service signature appear compatible.

`check.py` records both pinned Clang and native host C++ compiler path/version/hash,
checks owned hashes and consumed archive/independent-codec hashes before/after,
and rejects changes to relevant pinned LLVM headers. It executes the host C++
wire oracle and three native-language modes: normal cleanup/catch/exception_ptr/
flag, expected catch-copy termination, and object cross-thread destruction/
transparent placement/member lifetime. These finite host observations do not
qualify the six-host SMIR platform. The standalone existing-target layout witness
still compiles twelve translation units and executes none of that output.

The object registry model exercises flat completed objects; nested current-child
certificate validation belongs to the independent runtime protocol reference.
Construction journals express nested array instances separately. Varargs reference
operates on admitted concrete byte/origin images after frontend promotions; its
required typed decode callback validates actual value/provenance before advancing
the cursor. It never turns unregistered numeric pointer bytes into authority.
C++ nullptr through ellipsis converts to void* at the pin, whereas C23 nullptr
retains its source type; C++ nontrivial ellipsis arguments receive diagnostics.

The active incompatible cut is ABI root10 revision3; roots1/2/3/5 revision2;
roots4/6/7/8/9 revision1; envelope0.2/profile2. Every call_signature authors its
mandatory LAST execution:qref. Old ABI2 bytes remain unmodified under legacy/abi2;
new semantic fixtures are produced from current source, without an upgrade reader.
Source function pointers use CodeAddress (8B/A8), independently of a nominal
prototype's optional issued execution default. V3 source identity uses transitive
DEF/EXPR graphs; it excludes execution/default choices.

Run the genuine source-call groups in a fresh interpreter, separately from old
flat ABI tests: the historical ABI candidate.py and execution candidate package
share a module name, so mixing them in one discovery process is unsupported.

```sh
(cd tools/smir-abi && PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest \
  function_address.test_execution_compare function_address.test_model -v)
(cd tools/smir-abi && PYTHONDONTWRITEBYTECODE=1 python3 -B -O -m unittest \
  function_address.test_execution_compare function_address.test_model -v)
(cd tools/smir-abi && PYTHONDONTWRITEBYTECODE=1 python3 -B -m function_address.check)
```

function_address.model implements actual-first API6 ordinary compatibility using
two privately issued canonical SourceCallContext views and one cumulative source
budget. It compares complete source/lowering/recipe/varargs and execution graphs,
keeps original dependency expectations, and rechecks snapshots before either
boolean. Internal/local declarations additionally use each actual module family.
The execution comparator independently walks full descriptors; no identity/hash
shortcut supplies compatibility. These booleans issue no runtime or entry rights.

The Rust ABI verifier consumes the same mandatory plans and exposes branded
SignatureFact.execution_signature(). Its admitted source-only extension permits
reachable opaque declarations and their real pointer storage, while retaining
unavailable errors for unsupported callable families and unrelated opaque types.
The all-phase tests include semantic rejections for nonobject storage, incomplete
by-value calls and invented Function defaults. No portable JIT, native bridge,
parallel runtime or complete foreign C++ admission follows from these tests.
