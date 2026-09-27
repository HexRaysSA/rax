# Windows CRT foundation

This semantic group implements the allocation, error-state and non-locale
byte/UTF-16 memory/string foundation of built-in `msvcrt.dll` and `ucrtbase.dll`,
plus the stateless byte-memory/string-search subset of `vcruntime140.dll`,
for PE32 x86 and PE32+ x64/ARM64 guests. It is one implementation group within
the continuing Windows userland objective, not a complete C/C++ runtime.

The authoritative export lists are in `src/user/windows/dll/crt/`. Unsupported
functions retain the loader's explicit missing-export execution diagnostic.
Normal compiler CRT startup,
onexit tables, standard I/O, formatted I/O, locale, math, C++ exceptions, debug
CRT and over-aligned allocation remain required subsequent groups. No success
stub substitutes for them. In particular, a custom-entry PE testing CRT imports
is not evidence that a normal MSVC or MinGW startup graph runs.

Constructor-table traversal is implemented separately in
[windows-crt-initializers.md](windows-crt-initializers.md). The foundation-only
named counts below exclude that subsequent group; the combined current source
adds `_initterm` to MSVCRT and both initializer functions to UCRT.
MSVCRT also admits `_initterm_e` on ARM64 only, following the retained primary
ARM-specific binding declaration rather than x86/x64 compatibility shims.

Argument/environment startup and genuine per-ABI data/accessor bindings are
implemented in [windows-crt-startup.md](windows-crt-startup.md), including
CP1252 conversion, configuration, wildcard enumeration and new-mode state.
That successor supersedes C6's default-mode-only boundary: handler registration
is still unsupported, and the documented default is no new handler. The
foundation-only export counts below do not include either successor group.

## Acceptance criteria and ownership

1. Both real import names and the exercised UCRT heap/string/runtime API-set
   contracts reach separately constructed built-in PE images through the existing
   checked HLE frontier. They retain distinct runtime-owned state.
2. Allocation APIs preserve Microsoft NULL/zero distinctions, pointer-sized
   counts, checked multiplication, alignment and failed-reallocation ownership.
   CRT error reporting does not substitute Win32 `LastError`.
3. `errno` and `_doserrno` are guest-authoritative 32-bit storage, independently
   owned by runtime and guest thread. A fiber switch does not silently turn a
   documented thread-local value into fiber-local state. Terminated threads
   release their private storage through checked host ownership.
4. UCRT global and thread-local invalid-parameter handlers execute actual guest
   callbacks through the existing continuation ABI. Recovery executes the API's
   documented failure continuation; the default fatal path does not become a
   successful error return or a resumable guest SEH exception.
5. Byte and 16-bit-unit algorithms implement all admitted functions without a
   length cap masquerading as NUL termination, an unbounded host-sized buffer,
   raw guest pointers, or reading beyond a terminating unit. Overlapping
   `memmove` preserves the original bytes in both directions.
6. Compiled PE fixtures and host-side adversarial tests exercise all three ABIs,
   actual import bindings, boundary faults, error-state isolation and callback
   transitions. Independent expectations come from retained Microsoft contracts.
   Native Windows execution equivalence remains **unknown**.

Baseline HEAD: `78e3abc5d932ab5bd5027e957828e88e6e401eea`. The tracked tree and
index were clean before edits. The pre-change CLI was copied without rebuilding
to an isolated temporary directory; its SHA-256 is
`15d49476e26d17535b6bbca45c0ff535d04ba58c866381fa35f8a5acc7f1c32f`.
This artifact is a regression baseline, not a native Windows oracle.

Owned changes: CRT facade and semantic siblings, DLL registry, API-set profile
documentation/tests, checked thread-resource teardown, the existing registered
Windows test runner and a new CRT fixture/runner graph, this feature record,
Windows/test/reference indexes, and retained primary sources. Unrelated
pre-existing untracked files are outside ownership.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| C1 | Guest mappings cannot change concurrently during one checked HLE operation | Serialized scheduler and existing AddressSpace contract | Guest-memory probing/copy and allocator publication | Last-page protection/guard or commitment failure | Concurrent mapping mutation through a retained AddressSpace clone | Retained execution prerequisite |
| C2 | Runtime identity is the live built-in module containing the entered trap slot | Ctx.entry_pc and module registry, not caller-selected guest metadata | Separate CRT heap/error/handler namespaces | Dynamic loading and nested calls to both runtimes | Cross-runtime fixture observes shared errno address or handler | Confirmed by source, units and three-ABI compiled runtime-isolation probes |
| C3 | Public thread-local error/handler contracts select guest thread identity | Microsoft CRT documentation | Error state across threads and fibers | Fiber migration and thread termination/reuse | Native probe showing specified storage follows a fiber rather than the calling thread | Retained public-contract profile; private native storage unknown |
| C4 | Checked guest access is the fault authority; exact native CRT partial-write/fault order is not established | Existing checked memory APIs; native oracle unavailable | Memory/string fault behavior | NUL at a page end, read-only destination and skipped guard | Native trace of identical faulting CRT invocation | Retained; native ordering unknown |
| C5 | Synthetic CRT images implement only named admitted exports, not a particular binary build's complete ordinal/layout ABI | Synthetic PE builder, named import fixtures and documentation-only `_invalid_parameter` admission | Registry and API-set host selection | Missing export and unknown contract version | Native DLL export/ordinal comparison for a pinned Windows build | Confirmed admitted surface; retained version/ordinal profile, native `_invalid_parameter` availability unknown |
| C6 | CRT routines run with their default new-handler mode unless genuine mode APIs are implemented | Microsoft allocation documentation and explicit missing-export diagnostics | OOM returns and callback scope | Attempt to call unsupported new-mode export | A mode-changing API succeeds without actual handler/retry behavior | Retained default-mode scope |
| C7 | Normal CRT startup and I/O cannot be inferred from custom-entry fixture success | Actual startup dependency audit and fixture source entry points | Full-objective completion boundary | Link a normal MSVC/MinGW main program | Inspect final imports and execute its unmodified startup graph | Confirmed boundary; full startup remains incomplete |
| C8 | Zero-count memory/bounded-copy operations perform no access, while string append still finds/writes its terminator | Explicit personality policy; Microsoft strncpy page contains inconsistent return/error statements | Hostile zero-count pointer tests | NULL and unmapped pointers, count 0, unbounded scan | Pinned native invocation and callback/errno/fault trace | Retained policy; native zero/NULL ordering unknown |
| C9 | Installed import-library IAT evidence selects an admitted legacy subset, not the complete native Windows 11 export inventory | MinGW legacy native imports versus static compatibility members; Microsoft get-errno YAML lists msvcrt.dll among locations | Separate common/UCRT tables | Dynamic lookup of excluded legacy helpers and direct UCRT imports | Export-table capture from a pinned native msvcrt.dll build | Retained conservative admission; full native inventory unknown |
| C10 | Numeric allocation ceiling and private allocation geometry use the retained SDK/shared-heap profile | MinGW `_HEAP_MAXREQ` excerpt and existing checked heap implementation | SIZE_MAX rejection, requested-size `_msize`, non-LFH `_expand` and zero-allocation geometry | Maximum-width request, failed in-place growth and zero-size shrink | Probe the identical calls against a pinned native CRT DLL and heap configuration | Retained profile; exact native geometry unknown |
| C11 | Lazy per-thread context allocation failure raises STATUS_NO_MEMORY before an errno cell exists | Guest-authoritative cells cannot report ENOMEM before establishment; explicit admission policy | First accessor/allocator context failure | Exhaust guest commitment before the first CRT access | Native first-access failure trace distinguishes exception/termination/error behavior | Retained admission policy; native first-context failure unknown |

## Admitted named surface and primary evidence

| Host | Named exports | State ownership |
|---|---:|---|
| MSVCRT | 36 = 9 allocation + 2 error pointers + 5 byte memory + 20 byte/wide strings | Separate private heap and per-thread cells |
| UCRTBASE | 50 = common 36 + 12 error/handler functions + 2 bounded lengths | Separate private heap, per-thread cells and global/thread handlers |
| VCRUNTIME140 | 11 = 5 byte memory + 6 byte/wide character/substring searches | Stateless; no CRT allocation namespace |

The common allocation names are `malloc`, `calloc`, `realloc`, `free`, `_msize`,
`_expand`, `_strdup`, `_wcsdup` and `_get_heap_handle`. Error pointers are
`_errno` and `__doserrno`. String pairs are length, comparison, bounded
comparison, copy, bounded copy, append, bounded append, first/last character
search and substring search. UCRT adds `strnlen`/`wcsnlen`, four validated
error setters/getters, four global/thread handler setters/getters and the four
invalid-parameter/Watson entry points. Authoritative names and signatures remain
the checked source export tables, not this arithmetic summary.

The exercised API-set contract names are
`api-ms-win-crt-{heap,string,runtime}-l1-1-0.dll`. They select the same live UCRT
host and namespace. This is host redirection, not an assertion that every UCRT
export belongs to each API-set contract. Fixture `.def` inputs independently
select real contract names; `_strdup`/`_wcsdup` belong to the exercised string
contract, not its heap contract. Existing family-prefix fallback is retained
and explicitly does not establish other versions' native schemas.

[Allocation/error manifest](../../specifications/windows/crt-foundation/manifest-alloc.json)
retains 21 Microsoft contract documents and four auxiliary inputs.
[Memory/string manifest](../../specifications/windows/crt-foundation/manifest-memory.json)
retains 17 Microsoft documents and two owning licenses. All new Microsoft
documents are pinned to cpp-docs commit
`f2355df9f7136d8a2097193fc507882a7caeb5f5`; prose and code-sample licenses are
kept separately. These are public contracts, not the version of a native DLL.
[Binding evidence](../../specifications/windows/crt-foundation/bindings/manifest-abi.json)
retains installed MinGW/Zig source excerpts, symbol observations, original input
hashes, tool identity and license notices. The fixture's
[ABI manifest](../../../tests/fixtures/user/windows/crt/manifest-abi.json)
selects five already-retained Microsoft ABI/license inputs by exact content
hash; their original upstream commit is unknown.

The installed legacy archive implements several UCRT-style error helpers as
static compatibility members, not native IAT symbols. The public Microsoft
`_get_errno` page's combined DLL list conflicts with interpreting that evidence
as universal absence. Consequently their legacy named admission is excluded
conservatively, not declared absent from every Windows build [C9].
`_invalid_parameter` has explicit Microsoft API documentation, but its named
availability is not established by the retained UCRT IAT inventory. Its
admission is documentation-based; pinned native export availability is unknown
[C5]. The compiled guest probes use dynamic lookup for that profile, not a
manufactured import-library proof.

Nonsecure `wmem*` functions are not synthesized DLL exports. The retained public
header shows inline algorithms; checked 16-bit buffer helpers are tested through
private test descriptors only. Actual compiled imports contain no such names.
Secure, locale, multibyte and C++/stdio aliases are not supplied as success stubs.

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode | Unchanged: fixture instructions use existing guest ISA decoders |
| Direct execute | Unchanged semantics; exercised by actual PE execution |
| CPU state | Existing scalar Cdecl/Win64/ARM64 argument and continuation state reused; no architectural state layout change |
| Memory/MMU | Affected at the personality layer: checked CRT spans, heap ownership, per-thread storage and teardown |
| SMIR lift | Unaffected: Windows guests step direct interpreters |
| SMIR IR | Unaffected: no operation added |
| SMIR interpreter | Unaffected: no new IR behavior |
| Optimizer | Unaffected: no optimization/admission changes |
| Native lowering | Unaffected: no native CRT/JIT code generation |
| JIT runtime | Unaffected: no native Windows admission |
| Backend | Unaffected: no KVM/HVF/software adapter state interface changes |
| Machine/device | Unaffected: process personality, not guest kernel or board |
| Oracle/analysis | Unaffected: static instruction analysis interfaces unchanged |
| C ABI | Unaffected: capi does not expose these internal service implementations |
| Public Rust | Existing CrtState path, Default and compatibility fields retained; added private service state prevents prior external struct-literal construction. No tracked literal consumer exists; external consumers are unknown |
| Tests/docs | Affected: CRT units, registered user_windows module, independently compiled PE inputs and primary provenance |

## Arithmetic and algorithm contract

`size_t` and pointers are 32 bits for x86 and 64 bits for x64/ARM64. CRT integers
and Windows `unsigned long` are 32 bits on every admitted guest. Windows
`wchar_t` is a 16-bit unit: a wide unit index is scaled by 2 bytes with checked
multiplication/addition before that access; duplicate allocations scale their
complete NUL-inclusive length. This does not imply whole-span preflight for
streaming wide strings. Unpaired UTF-16 surrogates remain ordinary units;
these routines do not decode Unicode scalar values or apply locale folding.
Integer widths and page/granularity ceilings have exact arithmetic, not
floating-point error intervals. Overflow must not wrap into a small allocation
or permit a span to cross the 32-bit guest-address boundary.

The retained Microsoft `strncpy` page states that the return value is the
destination with no reserved error value, but also describes invalid parameters
including count zero returning -1 through an invalid-parameter handler. The
retained `strnlen` page describes NULL causing an access violation without
separately specifying a zero bound. These source inconsistencies are not
resolved by pretending the RAX tests are a native oracle. RAX's explicitly
tested zero-count no-access profile and checked NULL faults for actual accesses
remain subject to a pinned native probe; positive-count valid-input behavior
and storage widths have separate contract evidence.

Allocation uses the existing checked heap primitives and a CRT ownership
namespace. Streaming scans/copies use bounded temporary storage. The final
source/test audit records exact algorithm complexity and operation-specific
fault/invalid-input profiles; no native timing or host-throughput claim is made.

The pointer-width ceiling is computed exactly: x86 `SIZE_MAX = 2^32 - 1`,
so `_HEAP_MAXREQ = 2^32 - 32 = 0xFFFF_FFE0` bytes; x64/ARM64 use
`2^64 - 32 = 0xFFFF_FFFF_FFFF_FFE0` bytes [C10]. Multiplication for `calloc`
is checked before any truncation. A duplicate of L raw units requests
`(L + 1) * unit_bytes`, with both addition and multiplication checked. Public
integer counts are truncated only according to their declared guest ABI, not
host `usize`. Alignment is 8 bytes for x86 and 16 bytes for x64/ARM64.

Ownership-ledger lookups are expected O(1), with O(b + t) retained entries for
b live CRT blocks and t thread contexts. Shared heap best-fit indexing retains
O(log f) cost for f free blocks and O(s) segment checks for s heap segments.
Initialization/copy, length, comparison and character search take O(N) time
for N accessed bytes/units, with O(1) auxiliary working storage. Byte transfers
use at most 256 bytes and do not cross an unchecked guest page in a chunk.
Substring search takes O(H * M) worst-case time and O(1) auxiliary storage
for haystack/needle lengths H/M. Guest-page residency remains a separate host
memory cost, not a constant-space total process-memory claim.

With sufficient allocation resources, `malloc(0)` returns an owned non-NULL
allocation; `free(NULL)` is a no-op;
`realloc(NULL, n)` follows malloc, while `realloc(nonNULL, 0)` frees and returns
NULL. Failed realloc and `_expand` preserve the original block and bytes.
Zero-operand calloc selects one requested byte, without asserting defined
caller access to that block. `_msize` reports the requested size rather than
private native capacity; `_expand` uses the shared non-LFH in-place geometry
[C10]. Normal allocation OOM reports ENOMEM (12); EINVAL is 22. Win32 LastError
and `_doserrno` are not overwritten to emulate errno.

Each runtime's thread cell occupies 8 bytes: a 32-bit errno followed by a
32-bit Windows unsigned-long `_doserrno`, independently of pointer width.
Existing read-only cells remain readable by accessors; allocator mutation
preflights the errno write before resizing/publication [C4]. Lazy establishment
failure uses C11. Malformed, freed, private-cell and foreign-runtime block
ownership selects forced STATUS_HEAP_CORRUPTION (`0xC0000374`), an explicit
checked personality profile rather than a native invalid-pointer oracle.

Invalid-parameter recovery executes the selected actual guest handler, preferring
the current thread's non-NULL handler over the global handler. Required failure
errno is written after recovery, including guest handler re-entry. The default
and explicit nonreturn paths terminate with `0xC0000409`, bypassing SEH, DLL and
FLS callbacks. FAST_FAIL_INVALID_ARG (5) is not exposed as a debugger exception
parameter by this personality. Five-argument callback transport uses 32-bit
Cdecl stack slots on x86; Win64's fifth integer argument is at entry RSP +
40 bytes (8-byte return address + 32-byte shadow space); ARM64 uses X0..X4.
The group changes no aggregate, FP, vectorcall or native debugger ABI.

## Acceptance evidence map

| Criterion | Implementation | Direct evidence |
|---|---|---|
| 1: named hosts and bindings | DLL registry, runtime trap ownership and named API-set profile | Export uniqueness/Cdecl and live-host units; per-ABI foundation/module PEs; parsed final IAT inventories |
| 2: allocation/failure/widths | allocation.rs and existing checked private heap primitives | Zero/alignment/zeroing, multiplication overflow, commitment exhaustion, failed realloc/in-place preservation, private/foreign/double-free and duplicate-unit tests; compiled foundation PEs |
| 3: error identity and teardown | state.rs, RuntimeState namespaces and actual thread::destroy hook | Guest-authoritative 4-byte writes/read-only cells, release/re-establishment and runtime/thread tests; synchronized parent-worker-parent fiber migration and runtime-isolation PEs |
| 4: guest callback/termination | invalid.rs and existing HLE continuation/forced-exit paths | Handler selection/recovery/re-entry units; five nonzero argument probes and global/thread precedence in compiled invalid PEs; full-status fatal PEs with forbidden VEH/FLS callbacks |
| 5: complete checked algorithms | memory.rs/strings.rs, bounded buffer and checked unit arithmetic | Both overlap directions, unsigned byte/raw-surrogate ordering, page-end terminators, guards/read-only/late faults, SIZE_MAX/32-bit boundary, exact padding, unterminated scans and lengths beyond 64 KiB; compiled return/sign/truncation-tail probes |
| 6: executable and independent provenance | Registered user_windows CRT module and owned custom-entry build graph | 39 PEs across three guest ABIs and admitted bindings, two scheduling slices per PE; 14 source/39 artifact and 61 reference/auxiliary hash checks; final 78-case old-RAX baseline receipt |

The 30 new CRT unit functions consist of 13 allocation/error/handler functions
and 17 buffer/string functions; each iterates all three guest ABIs. Registry and
API-set tests add two more library functions. Import/provenance tests do not
substitute for executing the actual guests. Assembly probes establish normal
stack/nonvolatile-GPR behavior only, not FP/vector preservation, exceptional
unwinding, poisoned shadow-space behavior or ordinary compiler CRT startup.

## Bounded findings

High — Complete Windows userland remains unimplemented, including raw numeric
NT service tables, full CRT startup/I/O/C++ and GUI/network/registry services.
This blocks declaring the full objective achieved, not this semantic group's
validation. Native Windows oracle execution and private modern layout fidelity
remain unknown.

High — Native CRT generation identity, complete export ordinals, private heap
geometry and fault-time partial completion require pinned native observations;
named synthetic export admission cannot establish them.

High — Adding private runtime ownership to public `CrtState` preserves its path,
Default constructor and compatibility fields but prevents the old two-field
external struct literal. No tracked literal consumer exists (`rg` across src,
tests, capi and examples); external consumers are unknown. The change does not
alter the C ABI. Source compatibility for unknown Rust embedders is not claimed.

Medium — Ordinary threads still eagerly commit stacks independently of PE
initial commitment; reserve-promotion boundary arithmetic and stack guarantees
need a separate stack state-machine group. Existing fiber growth does not prove
ordinary-thread stack fidelity. These issues do not block named CRT foundation
tests but remain relevant to full Windows compatibility.

Medium — A long host-side CRT scan/copy occupies one serialized HLE call; guest
instruction-slice fairness does not preempt it. This group must not introduce a
silent string-length ceiling to hide that scheduling limitation.

Medium — Workspace all-target builds emit the existing `librax.rlib` output
filename collision between the root library and `rax-capi` (its baseline
Cargo.toml already names its library `rax`). Combined build success does not
establish which package owns that convenience output path. Package/runtime
artifact identity must be selected explicitly; renaming the C ABI package is
outside this group.

Low — Family-prefix API-set routing remains a labeled personality fallback,
not a schema/version oracle. An unknown family's redirection cannot establish
support for its exports.

The existing KnownDLL profile now selects the newly available MSVCRT/UCRT
built-ins before application DLLs; VCRUNTIME140 retains native-application search
before its built-in fallback. This host-selection policy is not a verified
per-build native KnownDLL schema, and no missing-export native fallback was added.

## Verification record — 2026-09-27

Host: `aarch64-apple-darwin`, macOS ARM64; Rust stable 1.98.1, rustc commit
`48a229ceaefd4985c50990b14116b6d856af0985`. The combined tree consists of this
group's owned changes; no unrelated tracked change was present. Engine and
fixture execution inputs remained hash-identical through the final gates.

| Check | Observed result |
|---|---|
| Portable complete library + CI contract target | 6,549 library passed, 2 ignored, 0 filtered; all 10 CI tests passed |
| Feature-enabled complete library, serial | 8,721 passed, 2 ignored, 0 filtered; 1,058.50 s test runtime |
| Final portable Windows + CI targets, serial | 108 Windows and 10 CI passed; 0 ignored, 0 filtered |
| Final feature-enabled Windows + CI targets, serial | 108 Windows and 10 CI passed; 0 ignored, 0 filtered |
| Workspace all-target builds, both selections | Passed; existing root/C-API convenience-output collision warning retained |
| Workspace all-target Clippy, default features + x86_64-suite | Passed without new warnings |
| rustfmt all-workspace check | Passed; only exact owned Rust paths were formatted |
| Feature-enabled doctests | 0 executed, 5 ignored; not behavioral proof |
| Source/artifact and primary/binding/ABI integrity | 14 source inputs, 39 PEs and 61 reference/auxiliary hashes verified |

The selected library graph contains 277 Windows unit functions (245 baseline
plus 32 new). The CRT integration subtree has 41 functions: 39 actual guest
cases and two integrity functions; the main runner adds one CRT primary-hash
function. Every final integration selection executes all 39 CRT PEs at both
scheduling slices, hence 78 CRT guest executions per selection, 156 across the
two final selections. Fatal cases assert the full `0xC0000409` diagnostic and
low-byte shell exit 9; timeouts, signals, premature exits and fixture mutations
fail the test. No CRT matrix cell is self-skipped or filtered.

Two final deterministic fixture builds produced identical bytes for all 39
PEs and their manifest. The artifacts total 168,960 bytes; final manifest SHA-256
is `6d9d159801760def6d5de1d2d173f3bad246fceb6b9cbcda35b0de058931670a`.
The retained [baseline receipt](../../../tests/fixtures/user/windows/crt/baseline.json)
contains 78 unique exact-input observations against the preserved pre-change
CLI: all failed with `0xC0000135`, shell exit 53, with zero timeouts. This is
old-RAX regression evidence, not native Windows execution. The integrity test
checks receipt identity, configuration, complete two-slice matrix and input
hashes against the final manifest, not merely the existence of a receipt file.

Commands, from repository root:

```sh
cargo +stable test --locked --no-default-features --lib --test ci_actions_pinned -- --test-threads=4 --quiet
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib -- --test-threads=1 --quiet
cargo +stable test --locked --no-default-features --test user_windows --test ci_actions_pinned -- --test-threads=1
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --test user_windows --test ci_actions_pinned -- --test-threads=1
cargo +stable build --locked --workspace --all-targets --no-default-features
cargo +stable build --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit
cargo +stable clippy --locked --workspace --all-targets --features x86_64-suite
cargo +stable fmt --all --check
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --doc -- --test-threads=1
```

The two library ignores are existing optional microkernel lift/roundtrip tests;
neither is claimed as executed. The five ignored doctests are existing ISA/SMIR
documentation examples. Other unrelated integration targets were built, not
executed. Native Windows oracle execution was not available; Linux KVM and
other host-native lanes were not run on this macOS host. C/C++ ABI consumer
runtime tests were not required because that surface is unchanged; workspace
compilation is not a substitute for their execution. Counts from a selected
host graph do not establish that every cfg-elided or self-gated native oracle
ran. Explicit `_invalid_parameter_noinfo_noreturn` recovery and `_invoke_watson`
have direct HLE/continuation unit coverage, not separate compiled guest cases.

No dependency, lock, toolchain pin, feature default or host CPU baseline changed.
Owned source has no whitespace errors. Seven byte-identical retained owning
license/disclaimer files contain upstream trailing whitespace; those exact
bytes are preserved and their content hashes verified, not reformatted to hide
the provenance exception. The byte-exact installed wchar.h excerpt also retains
its extracted terminal blank line; this is a source-retention exception, not
authored formatting debt. Unrelated pre-existing untracked IDE/reference,
hardware-image, iboot, Linux-image, rax/tmp/triage and yolo.sh paths were left
untouched. Staging/commit ownership is the exact 136-path feature graph, never
the worktree or an unrelated untracked directory.

## Reconciled quality gates

All personal QG1–QG7 pass for this declared foundation group: no ethical or
opinion judgment is required; C1–C11 provide stress/falsification probes; all six
acceptance criteria have direct evidence; integer arithmetic/units and commands
are reproducible; source conflicts and invalid-input edges use explicit bounded
profiles; primary provenance is verified; adjacent findings are impact-labeled.
Retained assumptions are not reclassified as native confirmations by RAX tests.

Repository QG1–QG9 also pass within that scope: the register is reconciled,
requirements and reproducibility are audited, no relevant contradiction is
hidden, provenance and scope boundaries are explicit, ownership excludes user
content, every affected execution plane is mapped/tested, and source/test
registration/features/documentation agree. Self-red-team specifically checked
shadowing, guest-triggered panics, late publication/ownership loss, read-only
errno, fault prefixes, real callback transport, forced-versus-normal exit,
test skip/filter/status collisions, generated input identity and cross-plane
omissions. Native unknowns, public Rust construction compatibility and ordinary
CRT startup remain bounded limitations, not claims that the full Windows
userland objective is complete.
