# CRT onexit table evidence and termination boundary

This archive supports the explicit UCRT table group at baseline
`3efe07a63ab935815d84ea4a48958282672a9059`. The root agent verified the tracked
tree and index were clean before this archive was created. Only this new
directory is owned by the evidence task; prior archives, runtime source and
fixtures are unchanged by it. Native Windows private behavior and a native
Windows execution oracle are **unknown**.

## Reproduction and inventory

Run from the repository root:

```sh
ruby -c docs/specifications/windows/crt-onexit/acquire.rb
ruby docs/specifications/windows/crt-onexit/acquire.rb
```

[sources.json](sources.json) records 26 inputs, 182,599 bytes referenced in
total: 2 new byte-exact inputs (2,324 bytes) and 24 reused inputs. Reused entries
retain their original producer, input hash, extraction recipe, retrieval date,
symbol command and license metadata. They are verified before use; acquisition
does not rewrite their bytes. Five entries are owning licenses/disclaimers: the
two MicrosoftDocs licenses, upstream MinGW `COPYING` and `DISCLAIMER.PD`, and
the installed Zig-bundled MinGW `COPYING`. There are five physical files in this
new directory: this README, the script, the manifest and the two snapshots.

Observed archive validation: Ruby syntax passed; all 26 hash/size checks,
9 available installed producer hashes, 2 exact header-extraction replays and
4 archive-symbol command replays passed. Two repeated acquisition runs produced
byte-identical snapshots and manifests. All 27 README relative links resolved;
the physical inventory matched the five declared files. Final manifest SHA-256:
`cd97c6f3556795b19602d02cf4405f3a03a4d56eaff2e88afe5e59d79ac1cd8c`.

New snapshots are pinned to MicrosoftDocs/cpp-docs commit
`f2355df9f7136d8a2097193fc507882a7caeb5f5` and MinGW-w64 v14.0.0 commit
`9b3dd0125792fe94d16cacdc596dbd42fca1b369` (annotated tag object
`e25dbe3428ce40d7321606a5642623a5a6e3da73`). Download normalization is none.
The exact upstream source and canonical publisher URLs are in the manifest.

The reused installed input observations come from Homebrew MinGW-w64
14.0.0_3 and Zig 0.16.0_1. Their exact bundled/upstream producer commits are
unknown; they are not relabeled as the pinned MinGW release. Symbol evidence
was produced by `/Users/int/local/bin/llvm-nm`, LLVM 23.0.0git, binary SHA-256
`20e1aa425fda511df6d594ba6ff5298871644a6a74dea8d6da38ea0b3ad2c94f`.
The four retained symbol observations record complete archive input hashes and
commands. They distinguish an `I __imp_` import member from a local function
with a `T` definition and `D __imp_` compatibility pointer. A DEF alias, not
the local C symbol spelling alone, establishes the selected PE import name.
None of this is a measured native DLL export inventory.

Microsoft prose uses the retained
[CC-BY-4.0 license](../crt-initializers/microsoft/LICENSE), with code samples
under the retained [MIT license](../crt-initializers/microsoft/LICENSE-CODE).
Marked MinGW headers and implementation inputs retain their Public Domain
notice and [DISCLAIMER.PD](../crt-initializers/mingw14/DISCLAIMER.PD);
[upstream COPYING](../crt-initializers/mingw14/COPYING) and
[installed bundled COPYING](../crt-initializers/zig/COPYING) retain the owning
ZPL-2.1 fallback for unmarked inputs. No imported text was reformatted.

## Authoritative public contract

The retained Microsoft
[explicit-table page](../crt-initializers/microsoft/execute-onexit-table-initialize-onexit-table-register-onexit-function.md)
requires initialization before registration or execution. Registration appends
a callback; execution calls all callbacks, clears the table and returns.
After execution the table is invalid and requires explicit reinitialization.
Success is zero; failure is a negative C `int`. The page does not define a
specific negative value, errno effect or exception/invalid-parameter policy.
It explicitly makes the table fields opaque and subject to change.

The public page does not specify explicit-table callback ordering, NULL table
or callback treatment, concurrent mutation, re-registration during execution,
recursive execution, reinitialization during execution, initialization of a
populated table, copied table ownership, endpoint aliasing, allocation growth,
callback fault recovery or guest-memory mutation during a drain. Those cases
must not be presented as measured native UCRT behavior.

[Microsoft `__dllonexit`](microsoft/dllonexit.md) describes a registration
worker receiving a callback and addresses of caller-owned begin/end pointer
variables. It returns the callback pointer on success or NULL on failure.
The DLL maintains its own callback list; the worker does not itself execute
callbacks. Allocation representation, sentinel values, null/alias validation
and memory-fault atomicity are not specified there.

The ordinary callback contracts are distinct. Microsoft
[`atexit`](../crt-initializers/microsoft/atexit.md) and
[`_onexit`](../crt-initializers/microsoft/onexit-onexit-m.md) document no-argument,
last-in-first-out callbacks at normal termination. `atexit` returns zero on
success and nonzero on error; `_onexit` returns the callback pointer or NULL
when storage is unavailable. DLL-local callbacks run after the DLL's
`DllMain(DLL_PROCESS_DETACH)`. These obligations do not turn an explicit-table
implementation into a complete global registration/termination implementation.

## Exact selected binding evidence

The matrix below concerns genuine names in the retained import definitions and
installed import archives, not absence across every native Windows version.
The MSVCRT common DEF and UCRT common/API-runtime DEF entries are unqualified
for these names; the retained `func.def.in` defines architecture filtering.
The ARM64 columns therefore have primary DEF evidence, not an installed ARM64
import-archive measurement.

| Name | MSVCRT x86/x64 | MSVCRT ARM64 | UCRTBASE / runtime API set, all three ABIs |
|---|---|---|---|
| `_initialize_onexit_table` | Local MinGW `T` + `D __imp_` shim; not a genuine IAT name in the selected evidence | Absent from selected common DEF; no admission inferred | Unqualified DEF entry; genuine x86/x64 `I __imp_` member |
| `_register_onexit_function` | Local MinGW `T` + `D __imp_` shim | Absent from selected common DEF; no admission inferred | Unqualified DEF entry; genuine x86/x64 `I __imp_` member |
| `_execute_onexit_table` | Local MinGW `T` + `D __imp_` shim | Absent from selected common DEF; no admission inferred | Unqualified DEF entry; genuine x86/x64 `I __imp_` member |
| `__dllonexit` | Genuine `I __imp_` member and common DEF name | Unqualified common DEF name | Not in selected UCRT common/API-runtime DEFs; no admission inferred |
| `_crt_atexit` C symbol | Import-library alias to native PE name `atexit` | Same unqualified common DEF alias | Genuine PE `_crt_atexit` name |
| `atexit` | Native name imported through the `_crt_atexit` alias; MinGW startup also supplies a local C wrapper | Same DEF alias; local wrapper is separate evidence | Local startup wrapper calls `_crt_atexit`; no fabricated PE `atexit` name |
| `_onexit` / `onexit` | MinGW compatibility definitions; MSVCRT DEF expressly replaces `_onexit` | Selected DEF replacement comment; native version-specific availability unknown | Local MinGW compatibility definitions; no fabricated PE name |

Evidence paths:

- [MSVCRT common DEF](../crt-initializers/mingw14/msvcrt.def.in) and
  [architecture macros](../crt-initializers/mingw14/func.def.in).
- [UCRT common DEF](../crt-startup/zig/ucrtbase-common.def.in) and
  [runtime API-set DEF](../crt-initializers/zig/api-ms-win-crt-runtime.def.in).
- [MSVCRT x86 symbols](../crt-initializers/symbols/msvcrt-os-x86.txt),
  [MSVCRT x64 symbols](../crt-initializers/symbols/msvcrt-os-x64.txt),
  [UCRT x86 symbols](../crt-initializers/symbols/ucrtbase-x86.txt), and
  [UCRT x64 symbols](../crt-initializers/symbols/ucrtbase-x64.txt).

Only the genuine UCRTBASE/runtime API-set explicit triple is selected for this
implementation group. The table, both registering and executing entry points,
and callback functions use C `__cdecl` on x86; x64 and ARM64 use their Windows
platform calling conventions. `_onexit_t` returns a C `int`; the table drain
does not use that return value in the retained MinGW comparison.

## Header layout and compatibility comparison

The exact installed
[MinGW 14 declaration](../crt-initializers/mingw14/corecrt-startup-excerpt.h)
and [Zig-bundled declaration](../crt-initializers/zig/corecrt-startup-excerpt.h)
both define `_onexit_table_t` as three pointer fields in order `_first`, `_last`,
`_end`. With pointer width `P`, its selected layout is `3P`: 12 bytes on x86
(`P = 4 bytes`) and 24 bytes on x64/ARM64 (`P = 8 bytes`). Offsets are 0, `P`,
`2P`, with no extra field/padding under the installed declaration. This is
header/layout evidence, not proof of native endpoint encoding or ownership.
The declaration is in `corecrt_startup.h`; the publisher requirement lists
`process.h`, which includes the startup header in the toolchain.

The pinned MinGW
[onexit table implementation](../crt-initializers/mingw14/onexit_table.c)
initializes all fields to NULL, returns -1 for NULL initialize/register tables,
and allocates an initial 32-slot buffer on first registration. It doubles the
buffer when full. Execution snapshots endpoints and resets the visible table
before invoking non-NULL callbacks in reverse order, then frees the detached
buffer. It has no explicit NULL-table check in execute. Callback re-registration
uses a new visible buffer and is not part of the outer snapshot. Initializing
a populated table resets endpoints without freeing that buffer. These are
compatibility implementation facts, not selected native UCRT requirements.

The newly retained [MinGW `_onexit` wrapper](mingw14/onexit.c) converts the
callback to the no-return-value `atexit` callback signature and maps the
registration result to the callback pointer or NULL. The retained
[EXE startup wrapper](../crt-initializers/mingw14/crtexe.c) uses `_crt_atexit`;
the [DLL startup wrapper](../crt-initializers/mingw14/crtdll.c) owns an explicit
table and executes it on detach. The DLL source expressly avoids process-global
MSVCRT `atexit` / UCRT `_crt_atexit` for unloadable DLL-local registration.

## Selected personality design and edge partitions

The selected extension is a plain three-pointer table, NULL callback skipped,
reverse registration order, host-validated ownership, and explicit invalidation
after execution. Those representations/order/validation policies are not all
defined by the public table page. A successful initialize establishes a fresh
epoch; execute detaches the existing epoch and invalidates its visible table.
Callbacks may explicitly initialize and register an independent new epoch.
The old detached buffer is read lazily, so pending slot changes by callbacks
remain visible in this profile. Registration without reinitialization and
recursive execution of the invalidated table return a negative result.

Negative results for NULL, uninitialized or malformed ownership fields, a
specific value such as -1, finite capacity, busy cross-thread policy, and
abandoned-drain cleanup must be labeled personality behavior wherever admitted.
No native errno, invalid-parameter callback or exception status is inferred
from the opaque table page. Guest read/write faults require checked propagation;
they must not become fabricated callback addresses or successful registration.

An implementation coupling audit must track an executing epoch independently
of its guest table address. Callback code can initialize the same address,
switch fibers, block, raise/repair an exception, unwind, change full context,
exit a thread/process or unload code. Consume the pending callback before
calling it, preserve the exact next read/publication frontier on repair, and
drop/retire old epoch ownership when its continuation is abandoned. Do not
hold a host borrow or mutex across guest callbacks. The new visible epoch must
not be freed or invalidated by completion/abandonment of the old one.

Strategic probes are empty/one/many callbacks, independent tables/runtimes,
duplicates, NULL callback, callback integer returns, reverse ordering,
allocation growth/OOM rollback, pointer-width/overflow/alignment boundaries,
copied/corrupted ownership fields, page-crossing read/write protection, guard
repair after a completed callback, pending slot mutation, nested independent
tables, explicit reinitialize/register during drain, recursive execute,
same-address epoch replacement, thread/fiber migration, callback unwind/full
context abandonment, callback process termination and DLL lifetime. The evidence
task executes no guest or Cargo tests; the implementation/fixture owners own
those results.

For `K` registered callbacks, a geometric buffer can provide amortized `O(1)`
registration and `O(K)` buffer storage. Reverse drain is `O(K)` checked slots
plus callback work, with `O(1)` per active epoch cursor state. Host validation
and ownership indexes must have their own stated costs. Any fixed cap or
reentrant progress bound is explicit personality policy, not native capacity.

## Termination remains outside this admission

The retained Microsoft
[`exit` contract](../crt-initializers/microsoft/exit-exit-exit.md) includes
thread-local C++ object destruction, ordinary callback drain, buffer flushing
and process termination. [`_cexit`](../crt-initializers/microsoft/cexit-c-exit.md)
also drains callbacks and flushes/closes streams but returns to its caller;
`_c_exit` returns without the ordinary drain/flush. The separate
[`quick_exit` registry](../crt-initializers/microsoft/quick-exit1.md) must not be
merged into the ordinary registry. No fake successful stream flush, process
exit shortcut for a returning cleanup call, global callback implementation or
ordinary compiler-generated CRT startup proof is provided by this group.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| O1 | Pinned docs and retained inputs are the design evidence, not a native Windows oracle | Exact revisions, hashes and producer metadata | Contract/binding conclusions | Changed remote branch or installed toolchain | Reacquire pinned inputs and replay retained input hashes/recipes | confirmed for retained bytes |
| O2 | Plain three-pointer representation is the selected guest layout | Two installed header declarations; public document says opaque | Fixture layout and host ownership validation | Pointer-width variation, copied table, encoded endpoint | Native SDK/DLL probe showing different layout/encoding | retained profile; native encoding unknown |
| O3 | LIFO, skipped NULL and detached lazy-read drain define this personality | MinGW reverse/NULL comparison plus requested epoch design; no public mutation guarantee | Callback order/reentrant fixture expectations | Callback changes pending slot; reinitializes same table | Native UCRT trace of those exact cases | retained profile; native behavior unknown |
| O4 | Explicit initialize creates a new independent epoch and invalid tables fail negatively | Public mandatory reinitialization; selected failure/epoch policy | Reuse, recursion and abandonment semantics | Reinitialize while callback blocks or abandons | Independent native tracing or counterexample in owned lifetime tests | retained policy beyond documented successful lifecycle |
| O5 | Import definitions/archives justify the selected named binding surface only | DEF aliases, genuine imports versus local compatibility definitions | UCRT-only triple admission and legacy exclusions | Alternate Windows/SDK/runtime version | Inspect actual PE import names and native DLL export table for each ISA/version | confirmed selected source inventory; native version coverage unknown |

## Bounded findings and quality gates

| Impact | Finding | Blocker |
|---|---|---|
| High | Global registration requires per-runtime/module ownership and complete termination/stdio; ordinary EXE/DLL wrappers have different ownership | Blocks global admission, not explicit table infrastructure |
| High | A persistent drain ledger without abandonment cleanup can retain busy ownership or free a replacement epoch after context escape | Blocks an implementation with that defect; evidence identifies required probes, does not claim tests ran |
| Medium | Native reentrancy, private fields, mutation, null/error handling and callback-fault atomicity remain unknown | No native-equivalence claim; bounded profile and falsification probes required |
| Low | The reused exact table source supports static legacy wrapper fixture work later | Not an additional named legacy export claim |

Evidence-only scope changes the tests/docs plane. Decode, execute, CPU, memory,
SMIR, optimizer, native lowering/JIT, backend, machine/device, analysis and public
C ABI are unchanged by this archive. Required archive checks are Ruby syntax,
all manifest hash/size checks, repeated acquisition byte equality, owning
license/provenance review, relative-link resolution and physical inventory.
Runtime/Cargo gates are deliberately not run by this task.
