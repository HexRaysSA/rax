# CRT argv/environment custom-entry probes

These 45 compiler-produced PE images use explicit `entry` functions and
`kernel32!ExitProcess`. They do not use, replace, or prove ordinary MinGW/MSVC
`main`/`wmain` startup, stdio, CRT exit tables, or a native Windows oracle.

The matrix is x86, x64 and ARM64 times MSVCRT, UCRTBASE and genuine CRT API-set
bindings for `arguments`, `environment`, `wildcards` and `newmode` (36 images),
plus UCRTBASE/API-set `modes` (6) and mixed-runtime `isolation` (3). Each image is
executed with scheduling slices of 1 and 4096 instructions. Environment images
also execute with an independently supplied empty environment.

`arguments` compares independent literal expectations against an explicit raw
UTF-16 command line. It checks argv0's special quoting, empty arguments, escaped
quotes, literal backslashes, embedded quoting, CP1252 `é`, and U+FF02 fullwidth
quotes. Windows BestFit converts the full narrow line before parsing: fullwidth
quotes delimit a narrow argument but remain ordinary units for the wide parser.
The program path is the loaded image's full path, not raw argv0. Uninterrupted
same-mode, same-active-width calls preserve selected vector pointers. Alternating
narrow/wide calls re-establish consistent shared `__argc` and selected vectors
with independent counts of 7 and 8; pointer identity across width transitions
is unknown and is not asserted.

The UCRT getter calls compile the **unmodified** retained installed Zig 0.16.0
MinGW `ucrt__getmainargs.c` and `ucrt__wgetmainargs.c` bodies. Their static calls
import genuine initialization/configuration/accessor/new-mode leaves, not named
UCRT `__getmainargs` or `__wgetmainargs`. The local wrapper headers are only an
ABI declaration bridge. MSVCRT imports modern Windows XP-or-later five-argument
getters directly. The installed i686 compatibility shim does not prove native
getter absence: its `__msvcrt_getmainargs` import aliases actual `__getmainargs`.

MSVCRT data `__argc`, `__argv`, `__wargv`, `_acmdln`, `_wcmdln`, `_pgmptr`, and
`_wpgmptr` are tested across the three architectures. Environment/initial data
are x86/x64 only; true `__p___*` accessors are x86 only. ARM64 legacy environment
tests call genuine `_get_environ`/`_get_wenviron` void-output functions and mutate
returned shared vectors rather than importing excluded cells.
UCRT uses genuine accessor APIs and `_get_initial_*_environment` leaves. It
never imports shim-only UCRT initial-environment data/accessors.

Legacy `arguments` also makes its five-argument getter output record read-only.
A real guest vectored exception handler restores write access and nulls all
five saved formal arguments (registers or stack). The retried getter must use
captured original inputs and publish the original seven golden narrow arguments
exactly once. UCRT/API-set `modes` similarly protects the public `__argc` page;
its handler replaces the saved mode with 3, but captured mode 1 must complete
without invoking the invalid-parameter handler. The CONTEXT offsets are the
public MinGW header fields verified by the existing layout probes. Native CRT
fault order/retry details are unknown; these are explicit HLE frontier probes.

`environment` checks case-insensitive overwrite through CLI process parameters,
CP1252/wide values, NULL terminators, repeated initialization, redirection of
current environment cells without replacement of initial vectors, and an empty
environment. `wildcards` uses isolated controlled files/directories, not the
repository tree; it tests unexpanded and expanded modes, quoted/nonmatching
patterns, `?`, final-component matching, and extensionless `*.*`. `modes` checks
enum values 0/1/2, same-mode idempotence, guest cell edits, and actual guest
invalid-parameter callbacks plus `EINVAL`. `newmode` checks 0/1 transitions and
the actual getter/wrapper's application of `startup_info.newmode`; decorated
legacy query is intentionally omitted on ARM64. `isolation` checks distinct
runtime cells, strings and new-mode state in one process.

## Reproduction

Use the installed pinned Clang/LLD/llvm-dlltool tools recorded in `manifest.toml`
and Zig 0.16.0 for source/toolchain provenance. `bash build.sh` compiles all owned
images; two consecutive builds must have identical manifest and artifact bytes.
`bash baseline.sh /absolute/path/to/preserved/rax-user` records actual old-RAX
failures using the pinned baseline executable. It is not native differential
evidence. The integration runner verifies source/artifact/baseline hashes,
architecture, timestamp, exact named IAT sets, all matrix entries and retained
primary-source inputs. No case self-skips or treats timeout as success.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | CP1252 with Windows BestFit is the selected narrow runtime code page. | Retained Microsoft conversion contracts and Unicode vendor mapping. | Narrow `é` and fullwidth-quote golden arguments. | U+00E9 and U+FF02 in the same raw line. | Repeat on pinned native CRT with ACP 1252 and inspect raw bytes/argv. | Retained profile; native oracle unknown. |
| S2 | Same configure mode and active width preserve guest cell edits; width transitions re-establish argc/vector consistency; initial vectors survive current-cell redirection. | Explicit personality contract; public cells/accessors are guest-writable. | `modes`, alternating `arguments`, and environment pointer checks. | Replace vectors/counts before a repeated call; alternate widths with counts 7/8. | Repeat against a pinned native UCRT build. | Revised profile; private native identity unknown. |
| S3 | A leading quote disables globbing; only the final path component expands; `*.*` matches extensionless entries; results use ordinal UTF-16 sort. | Explicit bounded enumeration profile, primary expansion contract does not define exact order. | `wildcards` literal ordering and quoted wildcard checks. | Files plus a directory, `?`, absent match, extensionless file. | Record native set/order on the same controlled directory. | Retained profile; native enumeration order unknown. |
| S4 | Modern MSVCRT getter return ABI is used; legacy pre-XP void-return adaptation is outside scope. | Retained MinGW14 DEF and wrapper comments. | Direct five-argument MSVCRT IAT probes. | 32 repeated narrow/wide calls per architecture. | Run against pre-XP MSVCRT or inspect an incompatible return ABI. | Confirmed admitted modern profile. |
| S5 | A repaired HLE fault retries captured startup inputs rather than rereading guest-clobbered formals. | Explicit personality retry contract; public CONTEXT/VEH layouts. | Protected getter/configure output probes. | Handler writes NULL to five getter formals or mode3 to the configure formal. | Disable captured retry and observe invalid-input failure instead of valid original outputs. | Retained HLE profile; native CRT fault ordering unknown. |

Bounded limits: ordinary compiler startup remains unproved (high, non-blocking
for these custom-entry probes); native wildcard ordering/pointer identity is
unknown (medium, explicit profiles); FP/vector preservation and exception
unwinding through CRT startup are not probed (medium, outside this group).
