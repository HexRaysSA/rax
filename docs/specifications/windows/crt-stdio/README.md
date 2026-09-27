# CRT standard-stream and byte-I/O evidence

This archive supports the selected standard-stream acquisition, binary/ANSI-text
file-descriptor engine, and buffered byte-I/O group. It is not evidence of full
stdio, Unicode stream I/O, global CRT termination, or native Windows equivalence.
No runtime, fixture, Cargo, or Git operation is performed by its acquisition
script. The parent recorded a clean tracked tree/index at baseline
`9b73397628567e675f129ecf38896ee50f601576`; this agent owns only this new directory.

## Inventory and reproduction

[sources.json](sources.json) identifies every retained input by SHA-256 and byte
size. It contains 78 references: 61 new local snapshots/observations and 17
hash-verified references to unchanged earlier archives. Five references are
owning licenses/disclaimers: MicrosoftDocs prose `LICENSE` (CC BY 4.0),
`LICENSE-CODE` (MIT), MinGW-w64 `COPYING` and `DISCLAIMER.PD`, and the installed
Zig-bundled MinGW `COPYING`. Input-specific notices remain verbatim.

The MicrosoftDocs sources are raw bytes pinned to cpp-docs revision
`f2355df9f7136d8a2097193fc507882a7caeb5f5`. Their own `ms.date` values are retained;
they are not relabeled as the dates of mutable Learn pages. The upstream
MinGW-w64 definitions are pinned to v14.0.0 commit
`9b3dd0125792fe94d16cacdc596dbd42fca1b369`. Installed Homebrew MinGW-w64
14.0.0_3 and Zig 0.16.0_1 inputs have full input hashes; their exact build/bundled
MinGW commits are unknown. Release-tag and installed bytes are not equated.

```sh
ruby -c docs/specifications/windows/crt-stdio/acquire.rb
ruby docs/specifications/windows/crt-stdio/acquire.rb
ruby docs/specifications/windows/crt-stdio/acquire.rb --verify
```

Acquisition downloads pinned raw publisher files, copies or extracts installed
inputs without byte normalization, and records deterministic tool observations.
It never rewrites reused archives or copies toolchain binary blobs. LLVM 23.0.0git
`llvm-nm`, `llvm-ar`, `llvm-readobj`, `llvm-objdump`, and GCC 16.2.0 executable
hashes/complete version strings are recorded. The verifier checks all retained
hashes/sizes, available producer hashes, extraction recipes, derived commands,
tool hashes, and the acquisition-script hash. Missing installed inputs are
reported explicitly, not counted as successful replays. Network access and the
listed installed toolchain/cache paths are prerequisites for complete acquisition;
the retained-hash check remains possible without them.

Header excerpts are exact disjoint line subsequences, not compilable headers.
Their manifest recipes provide original 1-based inclusive ranges. Juxtaposition
does not create a new preprocessor control flow: interpret conditionals in each
original span and the recorded input, not across an excerpt boundary. The original
notices, `_UCRT` distinctions, architecture-independent layout declarations, and
selected function/flag declarations remain unchanged.

Raw publisher Markdown keeps its upstream relative links; the full publisher
site is not mirrored here. Resolve unretained cross-references against the
recorded upstream source/canonical URL. Archive-authored local links below are
checked separately. The reused
[parameter-validation contract](../crt-foundation/allocation/parameter-validation.md)
is hash-checked through its owning allocation manifest rather than duplicated.

## Genuine binding matrix

These are selected producer/import-definition facts, not a measured inventory of
every native Windows DLL version. The original conditional macros in
[func.def.in](../crt-initializers/mingw14/func.def.in),
[msvcrt.def.in](../crt-initializers/mingw14/msvcrt.def.in), and
[crt-aliases.def.in](mingw14/crt-aliases.def.in) are authoritative for these rows.
The installed x86/x64 observations are in [symbols](symbols/).

| C-facing name | Legacy MSVCRT selected PE binding | UCRTBASE | stdio API-set |
|---|---|---|---|
| `_fmode`, `_commode`, `_iob` | Unqualified `DATA`, all three target architectures; x86/x64 observed import members | Not selected named data exports | Not selected named data exports |
| `__p__fmode`, `__p__commode` | Genuine x86 imports; x64/ARM compatibility bodies, not admitted named imports on that basis | Genuine functions | Genuine functions |
| `__p__iob` | x86 imports `__p__iob`; x64/ARM alias imports `__iob_func` | Not selected | Not selected |
| `__iob_func` | x86 alias imports `__p__iob`; x64/ARM imports `__iob_func` | Not selected | Not selected |
| `__acrt_iob_func` | Installed x86/x64 local compatibility body, not a genuine selected legacy name | Genuine function | Genuine function |
| `_get_fmode`, `_set_fmode` | Genuine ARM-family names; x86/x64 compatibility bodies | Genuine functions | Genuine functions |
| `_fdopen` | Genuine function | Genuine function | Absent from the installed selected DEF |
| `_wfdopen` | Genuine function | Genuine function | Genuine function |

The selected UCRT and stdio API-set definitions contain `setvbuf`, `fflush`,
`fread`, `fwrite`, `fclose`, `feof`, `ferror`, `clearerr`, `_fileno`,
`_open_osfhandle`, `_get_osfhandle`, `_close`, `_setmode`, `_read`, and `_write`.
Low-I/O names are in
[api-ms-win-crt-stdio-l1-1-0](zig/api-ms-win-crt-stdio.def), not an installed
`api-ms-win-crt-lowio` definition. `fopen`/`_wfopen` are retained graph-boundary
inputs, not admission of path-based open or all mode-string features.

An `I __imp_*` symbol is an import member, but does not alone prove the PE name.
The exact [x86 alias member](symbols/msvcrt-iob-alias-x86.txt) has C
`__iob_func` and `.idata$6` string `__p__iob`; the
[x64 alias member](symbols/msvcrt-iob-alias-x64.txt) has C `__p__iob` and PE
`__iob_func`. A `T` body plus `D __imp_*` can instead be a local compatibility
implementation. The retained `__acrt_iob_func` disassemblies demonstrate that
case and legacy indexing strides of 32 bytes (x86) and 48 bytes (x64).
Microsoft metadata `api_name`/`api_location` arrays do not establish every
function/DLL cross product or remove architecture restrictions.

## FILE layout and state boundaries

[MinGW-w64 14 headers](mingw14/stdio-x64-excerpt.h) define the legacy `_iobuf`
and distinguish it from UCRT's opaque `void *_Placeholder`. With packing 8,
32-bit `int`, and pointer width `P`, the legacy header-profile offsets are:

| Field | x86, `P = 4 bytes` | x64/ARM64, `P = 8 bytes` |
|---|---:|---:|
| `_ptr` | 0 | 0 |
| `_cnt` | 4 | 8 |
| `_base` | 8 | 16 |
| `_flag` | 12 | 24 |
| `_file` | 16 | 28 |
| `_charbuf` | 20 | 32 |
| `_bufsiz` | 24 | 36 |
| `_tmpfname` | 28 | 40 |
| `sizeof(FILE)` | 32 bytes | 48 bytes |

These calculations follow the retained declaration and packing; ARM64 is the
same header-profile calculation, not an actual native-DLL layout measurement.
`_IOB_ENTRIES = 20`, so a selected legacy array occupies
`20 × 32 = 640 bytes` on x86 or `20 × 48 = 960 bytes` on Win64.
The `_iob` export is that array, not a pointer-cell export. UCRT's public
placeholder size is `P`; it provides no native FILE stride, field layout,
allocation geometry, index-range, or recycling guarantee. Standard-stream
identity must be obtained through the selected runtime's accessor/array,
not inferred by arithmetic on opaque UCRT FILE values.

Retained buffering values are `_IOFBF = 0`, `_IOLBF = 0x40`, `_IONBF = 4`.
Legacy flags are `_IOREAD = 1`, `_IOWRT = 2`, `_IOMYBUF = 8`, `_IOEOF = 0x10`,
`_IOERR = 0x20`, `_IOSTRG = 0x40`, `_IORW = 0x80`; they do not establish UCRT
internal flags. Translation flags are `_O_TEXT = 0x4000`, `_O_BINARY = 0x8000`,
`_O_WTEXT = 0x10000`, `_O_U16TEXT = 0x20000`, `_O_U8TEXT = 0x40000`.
The older installed Zig header also exposes legacy `_cnt`/`_ptr` nolock macros;
MinGW-w64 14 uses function declarations there. Header producer differences matter.

## Public contracts and unresolved source conflicts

| Subject | Retained publisher contract | Implementation boundary / unknown |
|---|---|---|
| Mode cells | [Default `_fmode`](microsoft/fmode.md) is `_O_TEXT`; [accessors](microsoft/p-fmode.md) return the global cell. `_commode` controls commit behavior; default is no-commit `n`. | Installed `xtxtmode.c` initializes `_fmode` to numeric zero and retained `crtexe.c` publishes it. Zero's direct-cell interpretation is a producer profile, not the `_set_fmode` contract. `xncommod.c` supplies numeric zero; public docs do not specify numeric commit encoding. |
| `_set_fmode` | [Parameters](microsoft/set-fmode.md) list TEXT/BINARY; Return value also permits WTEXT. Invalid mode invokes the handler then returns/sets EINVAL if continued. | WTEXT discrepancy is retained, not silently resolved as EINVAL. A byte-only engine must deliberately reject unsupported Unicode before effects, rather than claim general mode support. |
| `setvbuf` | [Contract](microsoft/setvbuf.md) gives size 2..INT_MAX, rounded down to an even byte count; caller buffer remains caller-owned. `_IOLBF` equals full buffering on Win32. `_IONBF` ignores size/buffer; its example uses size 0. | Generic invalid-size rule versus IONBF exception requires an explicit priority profile; native validation order and post-I/O calls are unknown. Do not free the caller's buffer on close. |
| Ownership chain | [open-osfhandle](microsoft/open-osfhandle.md) transfers HANDLE ownership to FD; successful [fdopen](microsoft/fdopen-wfdopen.md) transfers FD ownership to FILE. [fclose](microsoft/fclose-fcloseall.md) flushes, closes FD/OS handle, and frees owned buffers. [get-osfhandle](microsoft/get-osfhandle.md) returns a borrowed handle. | Caller close/reuse of a transferred HANDLE, same-object alias/ABA behavior, duplicate adoption, and native misuse diagnostics are unknown. They are not authority to modify global object semantics. |
| Byte counts/status | [fread](microsoft/fread.md) returns complete elements; partial-item contents are indeterminate. Zero element-size/count returns 0 without buffer change. [feof](microsoft/feof.md) becomes true only after a read beyond EOF. [ferror](microsoft/ferror.md) is sticky; [clearerr](microsoft/clearerr.md) clears both flags. | Null-versus-zero validation order, fault partial completion, incomplete element tails, and caller mutation of private FILE fields are not specified native oracles. |
| Flush | [fflush](microsoft/fflush.md) flushes all relevant outputs for NULL; input/no-buffer cases do not discard the read buffer. | Commit-to-disk is distinct from an OS write; no-commit does not promise durable persistence. Ungetc/last-direction/update-stream boundaries require their own admitted implementation. |
| Text engine | [read](microsoft/read.md) translates CRLF to LF and CTRL+Z to input EOF; [write](microsoft/write.md) translates LF to CRLF and describes CTRL+Z handling for files/devices. | Binary/ANSI text is not Unicode byte/stream support. Wide-oriented Unicode modes and device-specific behavior require separate evidence/implementation or unsupported-before-effects. |
| Attachment/mode | [fdopen](microsoft/fdopen-wfdopen.md) attaches an existing FD; omitted t/b selects `_fmode`. | Its mode table also describes w destruction/a creation, despite attachment to an existing FD. Native truncate/create behavior is unknown; copied open-table prose is not sufficient proof. fdopen's blanket direction-switch wording conflicts with the more precise input/output/EOF rules in [fopen](microsoft/fopen-wfopen.md) and [Stream I/O](microsoft/stream-i-o.md). |
| Fileno/access | [fileno](microsoft/fileno.md) on a closed/non-open stream is undefined; NULL invokes validation then returns -1/EINVAL if continued. Detached standard streams can yield -2; older versions used -1. | No general invalid/private-pointer native validation or universal detached-console version equivalence is established. |

The original publisher pages are preserved, including these conflicts. Their
unresolved private/validation details are not a barrier to an explicitly named,
tested emulator profile, but do block claims that the profile measures native
behavior. Existing initializer, startup, allocation, and onexit infrastructure
does not by itself implement CRT `exit`, global atexit draining, stream flushing
at every termination path, or complete ordinary producer startup.

## Ordinary producer evidence

[producer](producer/) contains four installed GCC startup-object undefined-symbol
lists, four GCC main/wmain driver dry runs, two ARM64 cached startup
object/archive observations, and six actual linked ordinary main/wmain PE import
graphs. GCC dry runs use `-### -save-temps=obj` and an empty
C input; they print the selected `crt2.o`/`crt2u.o`, libraries and link actions
without running them. Stable printed temporary names do not denote generated
artifacts. Undefined symbols include local runtime/archive dependencies, not just
named DLL imports. The ARM64 cache producer command and source revision are
unknown; hashes identify the observed object/archive, not source equivalence.

The six actual IAT graphs are recorded by `llvm-readobj --coff-imports -` with
exact PE bytes as stdin, whose input hashes/sizes are retained. Their output
does not require native execution. GCC graphs include setvbuf/fflush and
`__stdio_common_vfprintf` plus additional startup dependencies; ARM64's graph
differs but also includes `__stdio_common_vfprintf` and private-API-set
`__C_specific_handler`.
This is a producer/version distinction, not authority to fabricate that name
in another DLL/API set. The underlying compilation recipes, source/artifact
manifest and actual entry/startup acceptance belong to the independently owned
CRT stdio fixture group. Neither empty driver input, undefined-object
closure, nor successful custom-entry byte-I/O tests proves complete ordinary
startup, global termination, locale, mathematical-error, or C exception support.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Selected definitions plus exact installed alias members identify the producer's genuine named-import subset. | Pinned DEF conditionals and x86/x64 `.idata$6` observations. | Binding matrix; no fabricated compatibility names. | x86/x64/ARM naming and DATA/function splits. | Inspect every final PE import and compare against selected architecture DEF; a contrary native DLL measurement changes native claims, not retained bytes. | confirmed for retained producer; native version inventory unknown |
| S2 | Legacy plain FILE layout/strides may be used only as a labeled header profile. | Public MinGW declarations, packing 8, pointer/int widths; x86/x64 compatibility disassembly. | 32/48-byte layout and 640/960-byte array calculations. | Cross-ABI array index and direct-field macros. | Compile sizeof/offsetof under each exact producer; inspect a native DLL/version if native equivalence is claimed. | retained; ARM64 native oracle unknown |
| S3 | Publisher contradictions need explicit profile selection rather than an invented native resolution. | WTEXT, IONBF size, attachment and update-direction conflicts above. | Error/unsupported boundaries for this semantic group. | Unicode requests; size0 IONBF; descriptor attach after existing data; EOF direction switch. | Run native all-ABI/API-version probes measuring return, errno, callback, FD/FILE state and OS data. | retained; native resolution unknown |
| S4 | Installed-cache observations are reproducible only while exact hashed inputs/tools remain available. | Input/tool hashes and replay recipes. | Local replay receipt; ordinary graph audit. | Changed cache producer, removed inputs, alternate GCC specs. | `ruby acquire.rb --verify` reports hash/replay failure or unavailable input. | confirmed for this acquisition environment |
| S5 | Transferred handle/FD ownership excludes subsequent caller destruction/reuse from the supported ownership profile. | Publisher HANDLE→FD→FILE ownership contract. | Close ownership and no global object/ABA expansion. | CloseHandle after adoption, duplicate adoption, same-object aliased handles. | Native misuse probe or a newly admitted contract that specifies these outcomes. | retained; misuse native behavior unknown |

## Bounded scope and quality gates

High-impact boundaries: Unicode modes, private FILE corruption, ownership misuse,
global termination/flush, and complete ordinary-startup closure are not silently
accepted through byte-I/O evidence. They block broader compatibility claims, not
this evidence archive. Medium-impact boundary: installed/cached inputs have
hash-identified but unknown exact source-build commits. No archive licenses,
old snapshots, or adjacent runtime files are altered.

Only the documentation/reference plane changes. Direct decode/execute, CPU
state, MMU, SMIR, optimizers/lowerers/JIT, backends/devices, oracle and public
Rust/C ABI are unaffected: the acquisition script never executes guest code or
changes admission. Hashing/copying and line extraction cost O(B) time/space in
the observed input size B; command replay cost is that of the recorded producer
tool. No host sleeps or unbounded guest execution is used.

The final receipt requires all 78 hash/size checks, exact producer/extraction
replay, two identical acquisitions, reachable local links and exact physical
inventory. These checks establish retained provenance/reproducibility, not
native behavioral correctness. QG1 has no normative content; QG2 is the register
above; QG3 covers requested inputs/bindings; QG4 records byte widths/arithmetic;
QG5 isolates unresolved contracts without resolving them as facts; QG6 verifies
publisher/producer provenance; QG7 bounds expansion as above.

Observed acquisition receipt (2026-09-27): Ruby syntax passed. Two complete
acquisitions compared byte-identically across all 64 physical archive files;
this documentation-only receipt was added afterward without changing snapshots,
script, or manifest. There are 78 retained hash/size checks, 33 available unique
installed/fixture input hashes, 15 exact copy/extraction replays, 24 derived
command replays, six tool hashes, and no unavailable inputs/tools. The 61 new
inputs total 269,231 bytes; all 78 references total 458,236 bytes. All 30
archive-authored local links resolve. No Cargo, runtime, fixture generation,
Git, or native-oracle run was performed by this archive agent.

Final `sources.json` SHA-256:
`f790ef92e0a908038a66f0dc6aff59f6f7565b2ab22a802917aa43dd95bd9ed1`.
Acquisition-script SHA-256:
`33cbc93581798c740cb3a60ef1e2594de1e57a39adce6d3c461035b3e6666ec3`.
