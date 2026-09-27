# CRT standard-stream and byte-I/O probes

The custom-entry matrix is six programs × three guest architectures × three
genuine bindings, plus six modern-only returning-handler error probes: 60 PEs,
each executed with instruction slices 1 and 4096 (120 semantic runs).
The six ordinary main/wmain PEs are distinct compiler-selected startup
observations, not successful ordinary-CRT acceptance probes. Native Windows
execution is unknown.

Custom programs use x86 ILP32 and x64/ARM64 LLP64 C ABIs, freestanding Clang
23.0.0git revision b51054818b78dc395cd4d33f17cfb6e98a36a76d and LLD with zero
timestamps. The installed Zig 0.16.0 and MinGW-w64 14.0.0/GCC 16.2.0 versions
are recorded. `bash build.sh` performs deterministic production; two complete
builds must reproduce every PE and observation hash. `bash baseline.sh
/absolute/preserved/rax-user` captures the pre-feature failures without Cargo.

The ordinary recipes select the compiler's own entry/startup objects without
an /entry, -nostartfiles or CRT replacement. Accepted Zig linking uses
-s; GNU --no-insert-timestamp is not accepted by its driver. Its default
timestamp field is recorded as producer bytes without treating it as a date;
the ordinary PE and full readobj observations reproduced byte-identically.
Baseline ordinary observations retain export failures or explicit 30 s
watchdog expiry with unknown cause, never a fabricated successful status.

Bindings are MSVCRT, UCRTBASE and api-ms-win-crt-stdio-l1-1-0. Legacy x86
genuinely imports `__p__iob`, whereas x64/ARM64 import `__iob_func`; the
retained MinGW legacy FILE declaration has strides 32 and 48 bytes respectively.
UCRT uses `__acrt_iob_func`. Legacy mode cells are DATA `_fmode`/`_commode`;
UCRT uses genuine `__p__fmode`/`__p__commode`. API-set imports use `_wfdopen`,
because the retained APIstdio DEF lacks `_fdopen`; MSVCRT/UCRTBASE also test
the genuine narrow name. No fake legacy `__acrt_iob_func` or getter aliases
are manufactured. The authoritative producer/primary archive is
[crt-stdio](../../../../../docs/specifications/windows/crt-stdio/README.md).

| Program | Independent witness |
|---|---|
| streams | Stable standard identities/FDs, real mode cells, exact stdout/stderr bytes |
| bytes | Binary embedded NUL/0xff, complete fread elements, EOF versus error, caller buffer, flush/close ownership |
| descriptors | OS-handle transfer, narrow/wide fdopen, direct read/write/setmode, actual final handle closure |
| translation | CRLF split across calls, three-physical-byte read contraction, CTRL+Z text EOF, untranslated binary bytes, fdopen default `_fmode` |
| buffering | Win32 IOLBF full buffering, odd-size rounding, automatic/user buffers, fflush(NULL), fclose flush |
| repair | Page-crossing read/write after 256-byte progress, actual VEH repair and clobbered arguments, consumed-prefix mutation detects replay |
| errors (modern only) | Genuine five-argument invalid handler, documented resumed EBADF/EINVAL results and unchanged byte on rejected read |

Runner-created `text.dat` is independently fixed to `a\r\nb\rx\r\nYZ\x1aQ`.
`edge.dat` is 255 `a` bytes + CRLF + 512 `b` bytes + `Z` (770 bytes).
A 768-physical-byte text read must return 767 translated bytes and leave `bZ`,
detecting unbudgeted lookahead across the internal 256-byte chunk boundary.
`read.dat` contains 768 bytes with byte[i]=(7×i+3) mod 256. Expected host
outputs are literal byte arrays, not generated using the CRT under test.
Every run gets an isolated temporary directory containing only its executable
and required inputs. Copied inputs are verified byte-identical; output inventory
and bytes are checked. Cleanup names exact owned files. Console input, pipes,
Unicode stream modes, fopen/wfopen, ordinary exit and formatted I/O are not
claimed by this group.

The partial-fault profile retains completed ≤256-byte/page-bounded chunks,
selected stream/FD and original arguments across resumed HLE faults. The guest
handler modifies consumed memory and saved formal arguments, making whole-call
replay observable. Native CRT fault ordering and partial-item contents remain
unknown; tests compare complete items only. Success LastError preservation is
an explicit RAX profile, not a universal native CRT guarantee. FILE internals
are not inspected beyond genuine legacy array stride.

The text-output CTRL+Z probe excludes the marker and remaining suffix from the
current call's bytes and returned count, then accepts a fresh subsequent write.
This exact marker/count frontier is an explicit RAX profile; native marker
inclusion and count behavior are unknown.

Assumption Register:

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Retained installed producer inventories define the admitted named subset, not the full native inventory | Primary DEF/header/IAT observations | Binding matrix | All architectures and data/function asymmetries | Actual PE IAT differs from independently listed names | retained |
| S2 | Legacy public MinGW FILE declaration supplies array stride for iob access | Retained header and 32/48-byte layouts | Standard identities | All three indices/ABIs | Installed producer declaration/layout differs | retained |
| S3 | Partial faults retain committed progress and captured inputs | Explicit checked-retry profile; native order unknown | Repair probe | Consumed-prefix and volatile-formal mutation | Duplicate bytes, restarted cursor or wrong target | retained |
| S4 | Default CRT text mode translates CRLF/CTRL+Z and LF output; binary is untranslated | Microsoft low-I/O/stdio contracts | Literal output oracle | Split pairs, bare CR, CTRL+Z, embedded NUL/0xff | Wrong literal bytes or counts | retained |
| S5 | Ordinary startup remains an observation, not replaced entry/startup code | Unmodified compiler-selected crt2/crt2u | Completeness boundary | main and wmain on each ABI | Custom entry or fake imports substituted | retained |
| S6 | openOS accepts documented-header access mask 0/1/2 and enforces it in addition to real Windows handle grants | Explicit RAX access-mask profile; native accepted bitset unknown | Converted FD permissions | Readonly/writeonly/readwrite plus actual grant denial | Native accepted-flags observation or incorrect RAX access | retained |

Bounded findings: high—ordinary startup still requires genuine termination,
locale/FP and x64/ARM64 C personality dependencies; not a success claim here.
Medium—native buffering geometry, fault ordering and full export inventory
remain unknown. Parsing/hashing is linear in source/artifact bytes; guest I/O
probes have fixed-size buffers and bounded loops.
