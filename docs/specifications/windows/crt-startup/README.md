# CRT argument, environment and startup binding evidence

This task owns evidence only, not runtime implementation or fixtures. Baseline
HEAD is `0753ca1c0b769da93d24390d1f24c4aad070b9d2`; the tracked tree/index were
clean. Only this directory is owned. Existing unrelated untracked material is
preserved. No native Windows oracle, SDK/CRT binary download, compiler startup
execution or Cargo command is attributed to this archive task.

## Provenance and reproduction

[sources.json](sources.json) enumerates 60 inputs: 46 local snapshots/observations
and 14 explicitly reused inputs in the frozen constructor archive. Local inputs
total 297,076 bytes; counting reused inputs once gives 432,833 bytes. Reused
records retain their original producer revision, date, hash and owning manifest.
A `../crt-initializers/` path denotes a retained reference, not an unrecorded
network dependency. Raw files remain byte-exact, including CRLF, non-UTF-8
mapping comments and the best-fit file's final 0x1A byte.

```sh
ruby docs/specifications/windows/crt-startup/acquire.rb
```

The script retrieves MicrosoftDocs/cpp-docs at
`f2355df9f7136d8a2097193fc507882a7caeb5f5`, MicrosoftDocs/sdk-api at
`a4fd3f7efe2e3378a96c6fe5a6a9455eba9fa021`, and MinGW-w64 v14.0.0 at
`9b3dd0125792fe94d16cacdc596dbd42fca1b369`. The MinGW release and installed
Homebrew 14.0.0_3 producer are distinct; the latter's build-source commit is
unknown. Installed Zig 0.16.0_1 bundles another MinGW copy; its producer commit
is unknown. Original-input hashes, extraction recipes and LLVM-nm executable
identity are recorded. No native export inventory is inferred from a header.

Unicode-hosted mapping/license URLs are mutable, with no verified producer
commit; their exact contents are pinned by SHA-256. CP1252.TXT identifies table
2.01, Unicode 2.0, 1998-04-15. WindowsBestFit's producer revision/date is unknown.
Unicode License V3 is retained with these data files. Microsoft prose/code
licenses and MinGW COPYING/Public Domain notices are retained locally or by
explicit reference. Excerpts are identified, not described as full compilable
sources. Publisher Markdown keeps upstream-relative links; those do not imply
every linked document is also retained here.

## Named binding evidence

The four actual installed x86/x64 archive observations distinguish `I __imp_*`
imports from `T` plus `D __imp_*` compatibility implementations. A `T` import
stub accompanied by `I` is not the same as a `T/D` shim. Actual imported names
follow DEF aliases, not archive C-symbol spelling. ARM64 entries below are
DEF/header evidence, not installed import-archive/native-DLL measurements.

The nine selected data names are `__argc`, `__argv`, `__wargv`, `_acmdln`,
`_wcmdln`, `_environ`, `_wenviron`, `_pgmptr`, `_wpgmptr`. Their corresponding
accessors are `__p___argc`, `__p___argv`, `__p___wargv`, `__p__acmdln`,
`__p__wcmdln`, `__p__environ`, `__p__wenviron`, `__p__pgmptr`, `__p__wpgmptr`.

| Surface | MSVCRT x86 | MSVCRT x64 | MSVCRT ARM64 | UCRT all three guests |
|---|---|---|---|---|
| Selected data names | Nine genuine imports | Nine genuine imports | Seven common DEF data entries; no `_environ`/`_wenviron` | No selected named DATA entries evidenced; macros use accessors |
| Selected accessors | Nine genuine imports | Nine local shims | i386-only DEF entries | Genuine x86/x64 imports; common ARM64 DEF entries |
| `__getmainargs` / `__wgetmainargs` | Local wrappers; genuine imports aliased as `__msvcrt_getmainargs` / `__msvcrt_wgetmainargs` retain native names `__getmainargs` / `__wgetmainargs` | Genuine imports | Non-i386 DEF entries | Local wrappers, not named-import evidence |
| `_configure_*_argv`, `_initialize_*_environment`, `_get_initial_*_environment`, `_get_*_winmain_command_line` | No corresponding imports evidenced | Same | No corresponding DEF entries | Genuine x86/x64 imports; common ARM64 DEF entries |
| `_get_pgmptr` / `_get_wpgmptr` | Local shims | Local shims | DEF comments mark compatibility implementation | Genuine x86/x64 imports; common ARM64 DEF entries |
| `_get_environ` / `_get_wenviron` | Genuine names; selected header does not establish x86 return contract | Same limitation | DEF entries; header declares void output-pointer functions | No corresponding selected import evidenced |
| New-mode functions | Decorated setter/query genuine imports | Same | Decorated setter in DEF; query absent from DEF | Plain `_set_new_mode` / `_query_new_mode` imports/common DEF |
| `__initenv` / `__winitenv` DATA | Genuine imports | Genuine imports | `F_X86_ANY` excluded; compatibility data | Local compatibility data, not genuine named DATA |
| `__p___initenv` / `__p___winitenv` | Genuine imports | Local shims | i386-only DEF excluded | Local shims; use genuine initial-environment getters instead |

The [legacy DEF](../crt-initializers/mingw14/msvcrt.def.in),
[architecture macros](../crt-initializers/mingw14/func.def.in), and
[x86](symbols/msvcrt-os-x86.txt)/[x64](symbols/msvcrt-os-x64.txt) observations
preserve these distinctions. The decorated mode names are
`?_set_new_mode@@YAHH@Z` and `?_query_new_mode@@YAHXZ`. The retained
[x86 mainargs wrapper](mingw14/msvcrt__getmainargs.c) describes a pre-XP void
return versus XP-or-later int return, detecting failure through temporary
outputs before publishing caller outputs. This is independent compatibility
source, not an observed native version/ABI oracle.

The [runtime API-set DEF](zig/api-ms-win-crt-runtime-l1-1-0.def.in) owns
argc/argv/command-line/program-path accessors, argv configure, environment
initialize/initial-environment getters and WinMain-tail getters. The
[environment DEF](zig/api-ms-win-crt-environment-l1-1-0.def) owns `__p__environ`
and `__p__wenviron`, not the runtime contract. The
[heap DEF](zig/api-ms-win-crt-heap-l1-1-0.def) owns new-mode/query-new-handler
names; the runtime contract owns `_set_new_handler`. API-set routing does not
make every CRT contract name an interchangeable genuine import.

The [startup header](mingw14/corecrt_startup.h) defines argv modes
0=no_arguments, 1=unexpanded_arguments, 2=expanded_arguments. Configure returns
`errno_t`; environment initialization returns `int`; initial-environment and
WinMain-tail getters return pointers. It also defines app types 0/1/2 and their
signatures. These declarations do not prove named binding or runtime policy.
The [stdlib excerpt](mingw14/stdlib-startup-excerpt.h) preserves the actual ARM
environment conditional. The [internal excerpt](zig/internal-startup-excerpt.h)
defines `_startupinfo` containing one 32-bit `int newmode` and mainargs prototypes.

## Public exception-layout evidence for repair probes

The [installed MinGW14](mingw14/winnt-exception-context-excerpt.h) and
[installed Zig-bundled](zig/winnt-exception-context-excerpt.h) `winnt.h` excerpts
retain the full public x86, x64 and ARM64 `CONTEXT` declarations, their relevant
architecture conditionals and floating-save dependencies, plus generic
`EXCEPTION_RECORD` and `EXCEPTION_POINTERS`. These are exact line subsequences
extracted on 2026-09-27, not whole or standalone-compilable headers. Input hashes
and complete extraction commands identify the two different full-header inputs;
their selected declaration bytes coincide. Neither is a native Microsoft SDK
or private CRT-layout oracle. The file notices have no Public Domain assignment:
ZPL 2.1 applies through the retained owning COPYING. Both installed owning
COPYING inputs match the corresponding retained licenses byte-for-byte; their
paths/hashes are recorded without adding duplicate license snapshots.

The independent [compile-only layout probe](../../../../tests/fixtures/user/windows/layout/public.c)
and its [toolchain receipt](../../../../tests/fixtures/user/windows/layout/README.md)
establish the following selected byte offsets for the fixture's saved-formal
mutation. For x86, `Esp + 4 + 4*i` selects stack formal `i`; for x64, formal 4
is at `Rsp + 8 + 32 = Rsp + 0x28` bytes after the return address and shadow area.
ARM64 formal `i` uses `X[i]` at `8 + 8*i` bytes. This is a captured-input HLE
retry probe, not a native CRT fault-ordering contract.

| Guest | Public fields | Offsets in bytes |
|---|---|---|
| x86 | `CONTEXT.Esp` | `0xC4` |
| x64 | `Rcx`, `Rdx`, `R8`, `R9`, `Rsp` | `0x80`, `0x88`, `0xB8`, `0xC0`, `0x98` |
| ARM64 | `X[0]` through `X[4]` | `0x08`, `0x10`, `0x18`, `0x20`, `0x28` |

The SDK-free exception records use Windows 32-bit `DWORD` and 4/8-byte guest
pointers. Thus `ExceptionInformation` begins at `0x14` bytes on x86 and `0x20`
bytes on x64/ARM64; the 15-word record sizes are `0x14 + 15*4 = 0x50` bytes and
`0x20 + 15*8 = 0x98` bytes. The pointer pair has size 8/16 bytes respectively.
The retained declarations, not emulator-private TEB fields, are their basis.

## Contracts and explicit unknowns

[Mainargs](../crt-initializers/microsoft/getmainargs-wgetmainargs.md) specifies
argc >= 1, NULL-terminated argv/environment arrays, `doWildCard` 0/1, zero
success and negative failure. Parameter order is `int*`, `char***/wchar_t***`,
`char***/wchar_t***`, `int`, `_startupinfo*`. Windows `int` is 32 bits; output
pointer cells are 4 bytes on x86, 8 bytes on x64/ARM64. Invalid/overlapping output
pointers, NULL startInfo, non-0/1 wildcard values, failure atomicity and exact
errno are unknown from that public page.

[Argument globals](microsoft/argc-argv-wargv.md) describe heap strings and
startup initialization. The [CRT parser](../crt-initializers/microsoft/parsing-c-command-line-arguments.md)
distinguishes argv[0] quoting from later space/tab, quote, backslash and doubled-
quote rules. CommandLineToArgvW is not used as CRT parsing authority. Raw empty
command lines, leading space/tab before argv[0], guest replacement of command-
line cells and malformed UTF-16 require an explicit profile or measurement.

A publisher conflict is retained: the globals page says wildcards are expanded,
while [the wildcard contract](microsoft/expanding-wildcard-arguments.md) says
default expansion is off and requires setargv/wsetargv. Mainargs' explicit
mode and [MinGW's wildcard default](zig/wildcard.c) distinguish these cases.
The public wildcard page does not specify ordering, case/dot/8.3 matching,
unmatched patterns, directories, quoting or allocation failures. A POSIX host
glob is not established native CRT evidence.

The pinned [.NET FileSystemName implementation](dotnet/FileSystemName.cs),
revision `33baf8ee337b20dd0f184b69a6f09be92850bf9e`, translates Win32 patterns
and explicitly describes DOS_STAR, DOS_QM and DOS_DOT rules. Its
[MIT license](dotnet/LICENSE.TXT) is retained. `*.*` translates to `*`; `?`
translates to DOS_QM; final `*.` translates to DOS_STAR; a period followed by
`*` or `?` translates to DOS_DOT. It is an independent source-derived matching
profile, not native CRT enumeration, ordering, case tables or 8.3 alias proof.
Skipping expansion when the argument began with a quote is an explicit profile;
the retained Microsoft wildcard prose does not resolve that policy.

[Environment globals](../crt-initializers/microsoft/environ-wenviron.md)
describe lazy opposite-encoding creation, movable/resizable arrays on mutation
and non-bijective conversion. The page's DLL-linkage caveat says the CRT DLL
cannot infer entry-point type and creates a multibyte copy. Initial-environment
getter identity, reinitialization, mutation aliasing, environment order,
duplicate/case handling and hidden drive variables remain unknown here.

[Program-path globals](microsoft/pgmptr-wpgmptr.md) distinguish Cmd.exe full paths
from invocation-dependent relative/name/full-path alternatives. Program path
and argv[0] are therefore not interchangeable. Functional
[_get_pgmptr](microsoft/get-pgmptr.md)/[_get_wpgmptr](microsoft/get-wpgmptr.md)
specify zero success and NULL-output invalid-parameter handling, followed by
EINVAL return/errno if continued, and matching narrow/wide entry-point use.
The retained MinGW shims set EINVAL directly instead; they cannot redefine the
native public validation contract.

[Command-line globals](microsoft/acmdln-tcmdln-wcmdln.md) hold complete strings.
The [internal interface index](../crt-initializers/microsoft/internal-crt-globals-and-functions.md)
treats internal interfaces as version-variable. No standalone publisher contract
for configure/init/initial-environment/WinMain-tail APIs was found. Repeated mode
changes, no-arguments results, writable cell synchronization and storage lifetime
are unknown. The retained [narrow](../crt-initializers/zig/ucrt__getmainargs.c)
and [wide](../crt-initializers/zig/ucrt__wgetmainargs.c) wrappers initialize env,
configure argv, read accessor cells and set new-mode, then return zero without
checking initialization results. Their source cannot authorize fabricated
success after faults or fake named UCRT mainargs exports.
Installed [WinMain glue](zig/crtexewin.c) and
[wide inclusion wrapper](zig/ucrtexewin.c) are separately retained. Their
command-line-tail scan is compiler glue, not an independently verified native
UCRT WinMain-tail implementation.

## New-mode and encoding dependencies

[_set_new_mode](microsoft/set-new-mode.md) accepts 0/1, returns the previous
mode, and handles invalid values through invalid-parameter callbacks then
-1/EINVAL if continued. [_query_new_mode](microsoft/query-new-mode.md) returns
current 0/1 mode. [_set_new_handler](microsoft/set-new-handler.md) states there
is no default handler. A registered `int (__cdecl *)(size_t)` handler receives
requested bytes; nonzero requests retry, zero requests failure. Mode 1 affects
allocation if a handler is registered. A no-registration profile is not a full
handler implementation. [Global-state evidence](microsoft/global-state.md)
separates application and OS-mode CRT instances.

[CP1252.TXT](unicode/CP1252.TXT) has 251 defined byte mappings and marks
81/8D/8F/90/9D undefined. [WindowsBestFit](unicode/bestfit1252.txt) instead has
256 MBTABLE entries, including same-valued U+0081/U+008D/U+008F/U+0090/U+009D.
CPINFO declares SBCS, byte default 0x3F and Unicode default U+003F. WCTABLE has
698 distinct records: 256 round-trip and 442 non-round-trip best-fit mappings.
These are distinct behaviors, not a silently normalized common map.

The [format description](unicode/windows-bestfit-readme.txt) specifies comment,
field, count and code-page encoding rules. The raw table is machine-readable;
no handwritten duplicate map is needed. Its SHA-256 is
`72ea23c939c5b26fae7aded0207b327e2f3902d7d3c168d7087f5cfc38ee76a9`.
[GetCommandLineA](sdk-api/getcommandlinea.md) explicitly documents process-code-
page conversion and CP1252 best fits U+0100 -> 0x41, U+FF02 -> 0x22, U+2010 ->
0x2D. Narrow parsing after conversion can differ from parsing wide arguments
then converting, because conversion can introduce syntax characters. UTF8
process manifests are acknowledged. [GetACP](sdk-api/getacp.md) does not make
1252 universal; fixed 1252 is a named emulator profile.

[WideCharToMultiByte](sdk-api/widechartomultibyte.md) distinguishes best-fit
from WC_NO_BEST_FIT_CHARS direct/default behavior. WC_ERR_INVALID_CHARS applies
only to UTF8/54936, not 1252. [MultiByteToWideChar](sdk-api/multibytetowidechar.md)
documents version-dependent invalid inputs; [GetCPInfo](sdk-api/getcpinfo.md)
describes installed-code-page queries. The BMP WCTABLE has no supplementary or
surrogate records. Exact 1252 replacement cardinality for a valid surrogate
pair or isolated surrogate is unknown. Per-16-bit-unit replacement is an
explicit profile, not established by this table or UTF8-only rules.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Installed archive/DEF evidence defines only this binding subset | Import I versus shim T/D and architecture macros | Runtime/ABI matrix | x86 aliases, ARM environment data absence, x64 shims | Inspect exact imports/exports on a pinned native target | confirmed inputs; native inventory unknown |
| S2 | Internal initialization needs an explicit profile beyond signatures | Internal-interface disclaimer; incomplete public contracts | No native identity/reconfigure/error claim | Reinitialize after writable-cell replacement | Native/publisher-source trace resolves a policy | retained unknown |
| S3 | Fixed CP1252 best-fit conversion is a bounded profile | Existing ACP choice; primary map and command-line examples | Narrow representation and parse order | Fullwidth quote, five control bytes, unmappable text | Pinned process-code-page trace differs | retained profile, not universal default |
| S4 | Mapping data does not resolve surrogate replacement cardinality | BMP records; UTF8-specific error flag | No native supplementary/malformed claim | Valid pair versus isolated half | Pinned WideCharToMultiByte(1252) probe | retained unknown |
| S5 | Dedicated wildcard instructions qualify the globals summary | Mode-specific contract and source default | Separately selected expansion mode | Quotes, no matches, *.*, case/dots | Pinned CRT trace differs | confirmed conflict; precise matching unknown |
| S6 | Startup primitives do not prove ordinary compiler startup | Retained crtexe/wrapper dependency graph | Completion boundary | Unmodified startup reaches main and exits | Independently verify genuine startup output/cleanup | confirmed boundary |
| S7 | Pinned .NET DOS-wildcard translation/matching can define an explicit profile | Author implementation with documented DOS tokens | *.* extensionless matching and DOS period/question rules | Multi-period, trailing-dot, short name and quoted wildcard cases | Pinned native CRT/Win32 match enumeration contradicts it | retained independent-source profile; native equivalence unknown |

## Bounded findings and validation scope

| Impact | Finding | Archive blocker? |
|---|---|---|
| High | Header-only import admission loses aliases/shims/architecture distinctions | Resolved by retained DEF and installed observations |
| High | ASCII-only or UTF8 narrow conversion changes documented CP1252 behavior and parser syntax | Evidence supplied; implementation root-owned |
| High | Startup publication requires checked loader initialization/rollback, not success after failed writes | Runtime requirement; no implementation owned |
| Medium | Internal init, wildcard and surrogate details lack native oracle | Explicit profiles required, not native equivalence |
| Medium | Bootstrap snapshots do not implement later environment mutation or alternate CRT/OS-state ownership | Subsequent semantics, not claimed complete |
| Low | Raw mapping/import observations support independent full-table/generated-IAT audits | Evidence available, no execution oracle claim |

Only docs/provenance changes. Decode/execute, CPU state, memory/MMU, SMIR
lift/IR/interpreter, optimizer, native lowering/JIT, backend, machine/device,
oracle, Rust/C ABI and executable tests are unchanged. Generic conversion and
parsing cost O(L) time and O(L + A*P) output storage for L input units, A argument
pointers, P=4/8 bytes; fixed-map lookup depends on its consumer. This is analysis,
not a runtime measurement. Validation covers syntax, recorded hashes/sizes,
installed extraction/nm replay, complete local inventory and local links.
Native/Cargo/runtime gates are unrun because this task owns reference inputs.

Observed on 2026-09-27: 60/60 retained SHA-256 and byte-size checks, 21/21
installed-input hashes and exact extraction/nm replays, all local README links,
and the complete 49-file physical inventory passed. Nine license/disclaimer
inputs are included in the manifest. A second final acquisition preserved the
manifest and all 60 input hashes byte-for-byte; `ruby -c acquire.rb` passed.
