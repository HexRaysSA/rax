# Portable SMIR runtime contracts and witnesses

This package specifies and independently checks portable compiler/runtime
contracts. It does not implement production portable execution, JIT, hosted
libraries, native C++ unwinding, launchers or exported embedding functions.
An envelope decoder is framing only; executable profile 0.2 requires all ten
sections and cross-owner semantic admission.

Run from the repository root, without altering production build state:

```sh
python3 -B tools/smir-runtime-contract/check.py
python3 -B tools/smir-runtime-contract/check_candidate.py
SMIR_RUNTIME_TMPDIR=/tmp/rax-portable-smir-01/RUNTIME python3 -B -m unittest discover -s tools/smir-runtime-contract -p 'test_*.py' -v
python3 -B tools/smir-runtime-contract/candidate/capi_probe.py
```

Python >=3.11 and a C++20 host compiler/thread library are required. CXX selects
the independent native witness compiler (default /usr/bin/clang++). The C ABI
probe requires Clang and records its actual identity; it does not assume the
compiler found on PATH is the pinned LLVM baseline. Missing tools/source archives
fail, never self-skip. SMIR_RUNTIME_TMPDIR must exist and be caller-owned. No LLVM
build, package installation, network lookup, production execution or Cargo build
is invoked. Temporary C++ outputs are isolated and removed by the test harness.

| Artifact | Exact scope |
|---|---|
| candidate/schema_build.py + schema/runtime/candidate.json | ordered section2/4/5/6/7/9 and private deployment/live-state records |
| candidate/wire.py | strict ordered codec using integrator primitives; no semantic admission |
| candidate/helpers.py + helpers-v1.json | exact actual-type helper signature/options/ABI-namespace instantiation |
| candidate/services.py + services-v1.json + errno-v1.json | 59 portable services, guarded preflight, structures and primary-header error maps |
| candidate/linking.py | actual symbol/body/import/storage/export joins, explicit deployment, version/SCC binding |
| candidate/comdat.py + selection.py | independent alpha comparison and whole-group/ordinary selection, symbol AND function redirects |
| candidate/relocations.py + initialization.py | typed leaf patches and restricted pure static initialization, whole-SCC atomic byte/shadow/origin and separate DATA/CODE exposure commit |
| candidate/reservations.py | fixed-link weak absence factories, actual context/selection/binding snapshots, no fabricated code entry 0 |
| candidate/atomic.py + atomic_probe.cpp | arbitrary-byte+shadow/precision oracle; independent 14 integer RMW byte algorithm and flag/SC protocol |
| candidate/identity.py | stable project source-unit identity, independent of artifact hash |
| candidate/fenv.py + powi.py | exact source environment layout/flags/mode and full-width selected-step powi protocol |
| candidate/flow.py + live.py | actual verified SSA/EH liveness, typed snapshots, private exactly-once worker handoff |
| candidate/journals.py + lifetimes.py | global-clock nested cleanup replay and current-object/fresh-thread destruction seeds |
| candidate/partials.py | process partial objects, fixed capture environments, prepublication detach, fresh resumer/cleanup J and current child ownership |
| candidate/native.py | exact x86-64/AArch64 CPU/TLS/stack/code/CFI checkpoint validation; no native restore |
| candidate/nonlocal_exit.py | registry-bound 32 B cookies, same-thread live activation, no memory rollback, cleanup rejection |
| candidate/tls.py | actual qualified provider TLS binding, private source-child cohort, once guards and failed-init child/escape drain |
| candidate/exceptions.py | private E/process owner proxy, fresh facades, refcounts, destructor tickets and source termination policy |
| candidate/host.py + embedding.py | registered scalar-only custom callbacks, private typed results, fresh threads and cleanup-before-EXIT lifecycle |
| candidate/startup.py | actual CRT signature checks, staged strict UTF-8 argv/env and exit-code conversion |
| include/rax_portable_contract_v1.h + candidate/capi_probe.py | 21 host C ABI declarations, fixed layouts, C23/C++23 compile-only probes for six host targets |
| check_candidate.py + candidate fixtures | record/semantic positive, boundary and rejection corpus |
| legacy top-level *.py/*.cpp + legacy *.schema.json | preserved runtime-draft-v1 JSON protocol and its 87 fixtures; not profile-0.2 executable roots |

Legacy semantics intentionally differ: the old 64 B nonlocal cookie, restricted
atomic widths and exact-content-only selection remain historical witness inputs.
They do not override current candidate contracts. `check.py` excludes the candidate
subdirectory and verifies its original corpus plus archived primary hashes.
Candidate fixture JSON represents inputs to an ordered codec or named reference
protocol, not JSON executable payload encoding. The ordered binary grammar is
specified in [schema/runtime](../../docs/specifications/smir/portable/schema/runtime/README.md).

Regeneration is explicit and limited to owned files:

```sh
python3 -B tools/smir-runtime-contract/candidate/schema_build.py
python3 -B tools/smir-runtime-contract/candidate/catalog_build.py
python3 -B tools/smir-runtime-contract/candidate/services_build.py
python3 -B tools/smir-runtime-contract/candidate/fixture_build.py
```

Do not regenerate another role's schema/fixtures. schema_build mirrors only named
shared execution/ABI state records and tests exact equality. Consumer migration
requires accepted proposals, current fixtures and combined integration evidence.
Requirements, grants, native producer certificates, host callbacks, source object
facts and lifetime claims always originate from independent runtime/admission
registries. A convenient callback returning a supplied producer assertion is not
a valid actual-root witness. COMDAT body projections use the LLVM owner's actual
function/EH graph and actual source/execution identities; no file body digest is
accepted as proof.

## Assumption register

| ID | Premise and dependent results | Stress/falsification probe | Status |
|---|---|---|---|
| RA1 | candidate profile2/commonwire/ref namespaces are the accepted shared contracts | actual codec/all-root joins; named proposal rejection | draft until integrator compiler gate |
| RA2 | registry callbacks derive actual admitted roots and independently registered facts | wrong source/function/import/table/generation, forged owner/result/facade tests | explicit precondition; actual cross-owner witnesses required |
| RA3 | native112 B x87 is project state, not FXSAVE | primary SDM components; TOP/MMX/80-bit, reserved/extension/stale-generation tests | exact local serialization, no native restore claim |
| RA4 | generic SC locks refine valid atomics; flag has separate lock-free hot path | independent byte RMW, paused generic owner, mixed SC litmus; six-host qualification | model evidence only, production absent |
| RA5 | internal multi-result services differ from source C ABI | actual wrapper/source-plan and memory.map pointer results | old mandatory-service-ABI assumption falsified/corrected |
| RA6 | source one-past must fit u64; raw MMU may end2^64 | top-address/startup/source-layout boundaries | exact separate ranges |
| RA7 | object current lifetime differs from constructor history | independent ABI replay, ended member, nested child, fresh-thread dtor claim/placement | current process certificate model, no universal raw-pointer UB detection |
| RA8 | ByteTy-to-integer would expose address | pinned LangRef explicit byte conversion | falsified: strips provenance WITHOUT exposure |
| RA9 | explicitterminate/bare rethrow always use current global handler | pinned cxa_handlers/cxa_exception and handler-swap witness | falsified: active-catch snapshot/bare inheritance; dependent rethrow refreshes |
| RA10 | an outer runtime catch recovers native callback unwinding | C++ noexcept/Rust extern-C boundary | falsified: provider must contain inside shim; abort not recoverable |
| RA11 | checking input facade.thread suffices | forged same ID/new thread, independent SEM projection | falsified: actual registry fact.thread also checked |

High-impact implementation boundaries: current MMU reclamation/fork/TLS assumptions
are single-host-thread premises; a shared broker and complete code/object/EH leases
are required before actual parallel execution. Full source call-plan and selection
joins are compiler-freeze conditions; isolated local models do not establish them.
Medium-impact opportunity: private process owner proxies permit cross-thread
exception_ptr without storing opaque E; explicit object certificates permit fresh
source destructor activations. Low-impact limit: finite schedules/host compiler
witnesses prove only their recorded cases, not all executions or six-host runtime.

Complexities: ordered codec O(record bytes), liveness reference O(V*E*L), SCC
O(modules+edges), COMDAT selection O(definitions^2+projected bytes), journal replay
O(events log events+live subobjects), current-child certificate validation
O(descendant facts), nonlocal restore O(frames+allocations), atomic byte oracle
O(width) per operation. Resource quotas are explicit implementation policy and do
not silently change source ABI size limits.

Constant transactions preflight cumulative staging bytes, actual reserved memory,
SSA widths, present component/fact nodes and outputs before any staging clone.
The default 1 MiB/65536-operation/100000-node reference quotas are configurable,
not ABI limits. An actual selected plan removes every losing physical segment
before leaf relocation or pure evaluation, including alias chains and prior
published winners outside the new SCC. Read-only retained provider facts qualify
external generations; old images/phases are never transaction outputs.

Partial-object snapshots separate historical completion from current lifetime.
Builder ranks survive TID migration independently of per-thread event clocks.
Detach precedes await_suspend/handle publication; claim/resume issues fresh J.
An owned constructor failure consumes its actual old J/failed ticket only after
current-E/unwind-frontier validation. Source-pointer explicit destruction and
completed placement replacement update the current owner graph. No snapshot can
mint a lifetime, replay a constructor, or extend a captured pointee lifetime.

Current exact commands/results/source hashes/changed-path ownership are recorded
under `/tmp/rax-portable-smir-01/RUNTIME/`. Earlier receipts are historical after
any source/schema/catalog change. No file here authorizes a later-wave production
rewrite, launch, commit or publication.

## Function addresses: current static implementation

Current executable source producers author section1/2/3/5 payload revision2 and
section10 ABI revision3. Envelope0.2/profile2 remain unchanged. Each call signature
contains its own mandatory execution Fn reference; optional Function.execution
is never a call-plan default. Generic calls explicitly carry source_plan=None;
source calls retain the actual caller plan and its original SELF/DEP namespace.
The source nominal graph uses SMIR-NOMINAL-SHAPE-V3 with its trailing NUL byte.

CodeAddress is an unbound 64-bit address category; it grants no callable permit.
function_address symbols carry a source Function nominal, CodeAddress execution,
no ABI call plan, size, alias/TLS/common definition, COMDAT or fallback. Native
address descriptors require independent domain/image evidence and grant no bridge
or portable callable Fn. code_address relocation leaves are exactly8bytes,
integer_bits0, addend0 and no derivation, flags, check_base or inrange. Bounds,
source namespace, target category and whole relocation/initializer overlap remain
mandatory static checks.

The Rust metadata coverage implementation admits only a strong default CPP
undefined function_address with the same actual SELF nominal as the independently
audited ordinary function, and a full8-byte SELF patch at offset0 into an existing
audited DATA8-byte owner targeting an actual defined ordinary function. Four
current objects reach the real all-phase factory; weak, DEP, TLS and import
address cases remain unavailable. SymbolBinding/LeafRelocation obligations remain
attached to the original context. These static facts allocate no runtime target,
address token, binding permit or executable entry.

The reference PatchRegistry explicitly raises code_address_unavailable before
calling its old dictionary resolver or publishing bytes. Actual source address,
legacy registration, process-pool reservation, bind/entry and composite completion
require the separately released actual registry/Machine implementation.
The shared pointer and origin wire records append binding_permit:opt:u64 last;
a numeric ID alone is never a permit. Live-state outer revision2 retains the
separate thread record revision1.

Actual regression commands:

```sh
python3 -B crates/smir-portable/tests/metadata/function_address_fixtures.py --check
python3 -B -m unittest discover -s tools/smir-runtime-contract -p test_candidate_function_addresses.py -v
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/RUNTIME/cargo-target cargo test --manifest-path crates/smir-portable/Cargo.toml --lib metadata_tests::function_addresses::
```

Assumption RA-FADDR: preceding actual semantic predicates check all newly admitted
fields and preserve deferred selection obligations. Falsify with wrong source
nominal/plan/namespace, address execution replaced by Fn, nonzero or overlapping
patch, a missing requirement, cross-context facts or exhausted cumulative budget.
High-impact limit: static admission is not address publication or guest execution.
Medium-impact limit: same-module finite coverage excludes native/DEP/weak/TLS/import
address factories. Low-impact opportunity: retained exact legacy corpora permit
byte-for-byte compatibility audits independently of current semantic admission.
