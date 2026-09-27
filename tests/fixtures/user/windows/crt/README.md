# Custom-entry CRT foundation fixtures

This independent group contains 39 PE programs for x86, x64, and ARM64, requiring
no Windows SDK headers, CRT startup objects, or CRT implementation blobs. It
tests actual named imports rather than ordinary CRT startup. The three bindings
are MSVCRT, UCRTBASE, and CRT `heap`/`string`/`runtime` API sets with the evidenced
VCRUNTIME140 byte-memory/search subset. The generator uses Clang, LLVM dlltool,
and LLD link from the installed LLVM 23.0.0git toolchain. Exact identities and
executable SHA-256 values are generated into [manifest.toml](manifest.toml).

| Family | MSVCRT | UCRTBASE | API sets + VCRUNTIME140 | Evidence |
|---|---|---|---|---|
| `foundation.exe` | 3 ABIs | 3 ABIs | 3 ABIs | Allocation, preservation/failure, bytes, UTF-16 strings |
| `errno.exe` | 3 ABIs | 3 ABIs | 3 ABIs | Error cells, thread isolation, synchronized fiber migration |
| `module.exe` | 3 ABIs | 3 ABIs | 3 ABIs | Dynamic lookup, runtime separation, assembly call ABI |
| `invalid.exe` | Not compiled | 3 ABIs | 3 ABIs | Returning/reentrant global and thread-local handlers |
| `fatal.exe` | Not compiled | 3 ABIs | 3 ABIs | Default invalid-parameter termination |

The excluded legacy cells are a compile-time matrix choice, not test self-skips.
The installed MinGW legacy archive contains compatibility implementations rather
than genuine IAT imports for the modern getter/setter and handler APIs; the
legacy fixture uses `_errno` and `__doserrno` pointers. Legacy bounded string
length calls are likewise excluded. The actual import inventories, raw API-set
definitions, `wchar.h` inline evidence, and licenses are retained in
[the binding archive](../../../../../docs/specifications/windows/crt-foundation/bindings/README.md).
The [ABI manifest](manifest-abi.json) references already-retained Microsoft
calling-convention documents and their license. The independent semantic
references are in [CRT foundation](../../../../../docs/specifications/windows/crt-foundation/).

`foundation.c` covers `malloc(0)` (non-null), pointer alignment (8 bytes on x86,
16 bytes on the 64-bit ABIs), `calloc` zeroing and checked multiplication
overflow, `realloc(NULL,n)`, growth/shrink prefix retention, size-zero free, and
failure with the original block preserved. `_msize` is checked as at least the
requested size, not a guessed native capacity. `_expand` shrink preserves its
pointer/data; oversized failure preserves the remaining block. String duplicate
results are released by the matching runtime. Memory probes cover unsigned-byte
ordering, return pointers, count-zero cases using valid pointers, and both
overlap directions of `memmove`; `memcpy` overlap is not tested. String probes
cover comparison sign rather than magnitude, bound truncation with a nonzero
byte/code-unit sentinel proving no appended terminator at the bound, NUL padding,
concatenation, first/last match, empty/absent substring, and UTF-16 raw code units
including an unpaired surrogate. No named nonsecure `wmem*` export is fabricated.

`errno.c` tests 32-bit `errno` and `_doserrno` cells independently of Win32
`LastError`, per-thread initialization and separation, same-thread fiber sharing,
and a fiber migrated parent-to-worker-to-parent behind event barriers. Cached
error pointers are not interpreted as fiber state. The shared-thread-error
policy is explicitly identified below; no native migrated-fiber CRT oracle is
claimed. `invalid.c` executes real five-argument cdecl guest callbacks. It checks
returning `_get_errno(NULL)`, `_get_doserrno(NULL)`, and `_msize(NULL)` errors,
handler reentry into allocation/free, thread-local precedence, previous-handler
return values, and explicit `_invalid_parameter_noinfo` null/zero arguments.
The documented `_invalid_parameter` personality entry is additionally resolved
with `GetProcAddress` and called with three distinct UTF-16 pointers, unsigned
line sentinel `0x89abcdef`, and a pointer-width reserved sentinel. All five
callback arguments and recovery are checked. Its named native export availability
is unknown; it is not fabricated as a genuine installed IAT import.
`fatal.c` must not reach its post-call exit; the configured fatal profile is
`0xc0000409`, whose low eight bits are shell exit 9. The runner additionally
checks the complete status in CLI diagnostics.
Registered VEH and non-null FLS callbacks terminate with distinct diagnostic
codes if incorrectly invoked, so the fatal test also checks the configured
SEH/FLS-bypass policy.

`module.c` loads both runtime facades and all three API-set contracts, checks
independent error cells and failure reporting, actual imported versus dynamically
resolved function pointers, and missing legacy facade exports. API-set host
handle equality is loader-profile evidence, not a native export/handle oracle.
The hand assembly calls `memcpy` 64 times for 17 bytes each (1,088 bytes total).
It checks the returned pointer, caller stack balance and call-preserved GPRs.
On x86, 16 saved bytes place the four arguments at offsets 20, 24, 28, and 32
bytes from the probe frame; the three CRT arguments occupy 12 bytes and the
caller removes them. On x64, entry RSP modulo 16 is 8; 64 saved bytes plus a
72-byte local frame make call RSP modulo 16 zero and reserve 32-byte shadow
space, with locals above it. ARM64's 128-byte frame remains 16-byte aligned,
preserves x19–x30, and does not modify x18. Shadow contents are not poisoned;
floating-point/vector state and exceptional unwinding through the assembly are
not tested by this group.

## Reproduction and validation

```sh
bash tests/fixtures/user/windows/crt/build.sh
```

The exact target triples, compilation flags, import-stub commands, link flags,
zero PE timestamps, and source/artifact SHA-256 values are retained in the build
script and manifest. ARM64 C uses `-mgeneral-regs-only -ffixed-x18`; no FP or
vector intrinsic is required. The script writes only its owned `bin` directory
and generated manifest, and removes its exact temporary intermediate paths.
It does not install tools or invoke Cargo.

Two final builds produced byte-identical manifests and all 39 PE artifacts,
without source edits between builds. The artifacts total 168,960 bytes; their
manifest SHA-256 is
`6d9d159801760def6d5de1d2d173f3bad246fceb6b9cbcda35b0de058931670a`.
All 53 source/artifact hash checks pass. The complete preserved-CLI receipt is
[baseline.json](baseline.json). The
registered [runner](../../../../suites/user/windows/crt.rs) contains 39 actual
guest cases and two integrity tests, with no self-skips. Each guest case runs
at scheduling slices of 1 and 4,096 instructions, seed 1, 64 MiB arena,
`RAX_NO_JIT=1`, and a 30 s external watchdog: 78 CLI executions in total.
Source/artifact integrity (14 source inputs, 39 artifacts), retained ABI/license
hashes, and all 12 binding-archive hashes are checked separately. The root agent
owns main-module registration, Cargo execution, and final gate reporting.

Observed initial baseline: preserved `rax-user` from source revision
`78e3abc5d932ab5bd5027e957828e88e6e401eea`, executable SHA-256
`15d49476e26d17535b6bbca45c0ff535d04ba58c866381fa35f8a5acc7f1c32f`,
failed all 39 final programs at both scheduling slices: 78 observed loader
failures, all `STATUS_DLL_NOT_FOUND` (`0xc0000135`, shell exit 53), none timed
out. The first missing modules were MSVCRT, UCRTBASE, or CRT heap/runtime API-set
contracts according to the program's actual imports. The receipt retains every
input hash, argument, scheduling slice, and stderr. This is an observed old-RAX
loader failure, not native Windows behavior. Final root-coordinated portable
and feature-enabled `user_windows` runs each passed all 108 tests, including
these 39 CRT cases at both slices: 78 executions per selection, 156 total.
Both selections passed all ten CI-contract tests, with no skips or filters.
The integrity runner also verifies all 78 baseline observations against this
final manifest. Complete library/build/lint results and native limitations are
recorded in [the feature report](../../../../../docs/architecture/user-mode/windows-crt.md).

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| C1 | These probes use Windows LLP64 widths: pointers/size_t 32 or 64 bits, DWORD/int 32 bits, UTF-16 units 16 bits. | Retained Microsoft ABI/data-type references and emitted PE machine kinds. | Declarations, length arithmetic, callback tails, and error widths. | High-bit DWORD values, surrogate code unit, architecture-specific pointer alignment. | Compile a public SDK sizeof/prototype probe or observe a contrary ABI layout on an admitted target. | confirmed for the configured fixture ABIs |
| C2 | CRT error state is keyed by the executing ordinary thread, not the current fiber. | Public separate CRT/thread-local-state description; this personality makes the identity choice explicit. Native migrated-fiber CRT equivalence is unknown. | `errno.exe` sharing and migration expectations. | Fiber moves between two live threads with distinct cells and returns to its original thread. | Run this same PE on a specified native Windows/CRT build and record `_errno` pointers/values across switches. | retained personality policy |
| C3 | The three CRT API-set contracts resolve to the same UCRT facade, including handle identity. | Current loader's declared API-set host profile; genuine contract-name inputs are retained. | Module handle/pointer alias checks and state sharing. | Load all three contracts and direct UCRTBASE, then compare callable addresses and error cells. | A loader/native version returns different contract handles or resolves these contracts to different state owners. | retained loader profile |
| C4 | Unhandled invalid parameters terminate with configured status `0xc0000409`. | Microsoft specifies default termination and fast-fail behavior; fallback/native status and processor availability differ. | `fatal.exe` expected full status and shell code. | NULL error output without any registered callback. | A specified native processor/CRT returns instead or terminates with another full status; that would revise native equivalence, not this selected profile. | retained fatal profile; native exact status unknown |
| C5 | The admitted named-export subset follows the installed import evidence conservatively, not every Microsoft generic `api_location` entry. | Archive `I` imports, compatibility `T`/`D` objects, raw definitions, and header-inline evidence conflict with a universal-export interpretation. | Compile-time legacy exclusions and missing-facade lookup checks. | Modern UCRT getter/callback bindings versus legacy pointer cells; API-set/VCRUNTIME separation. | Dump actual exports from an identified native DLL set and resolve every name; ARM64 native export availability is unknown. | retained inventory-limited admission |

Bounded limitations: ordinary MinGW/UCRT startup, `FILE`/stdio, locale,
multibyte conversions, secure string families, CRT signal/exit infrastructure,
C++ EH, FP/data exports, and native Windows differential execution are not
claimed (high impact for general application compatibility; non-blocking for
this custom-entry foundation). Memory fault/rollback semantics have separate
core unit coverage, not independent native fault recordings. The tests/docs
plane is changed here; CPU decode/execute/state and memory paths are exercised
without edits. SMIR, optimizer, native lowering/JIT admission, backends/devices,
oracle APIs, and the public C ABI are unchanged by this fixture group.

The workload is bounded: strings/arrays contain at most 32 bytes or 24 UTF-16
units; module-copy work is 64 × 17 bytes. Guest fixture time/space is O(1) in
repository inputs; individual length/copy/search calls have their documented
input-linear or substring-search costs. Migration uses a fixed number of event
barriers and two threads; no host sleep or unbounded retry loop is added.
