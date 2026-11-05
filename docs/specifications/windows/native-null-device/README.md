# Native null-device opens

Status: independent native contract, failing pre-fix dispatcher regression and
corrected installed ARM64 command comparison confirmed. The NUL regression passes
on all four host views. Owning-module runs retain two translated x64 failures at
the pre-existing installed ARM64X loader boundary.

The installed ARM64 CMD calls `NtCreateFile` with the counted name `\??\NUL`,
access `0x80100080`, share 3, disposition 1 and options `0x20060` for
`cmd.exe /d /c type NUL`. The previous resolver requires a DOS drive after the
prefix and returns `STATUS_INVALID_PARAMETER`. The captured corrected-MUI
baseline exits 1 and writes `The parameter is incorrect.`, while native CMD exits
0 with empty output. The new dispatcher regression independently reproduces the
invalid-parameter return before the null-device correction.

The selected null device owns no host pathname or host file. Its opens do not
require the filesystem capability, do not create files, and do not participate
in filesystem sharing or deletion lifetimes. Each open still owns a typed file
object, exact granted access, synchronous mode and a separately closable handle.
Open completion publishes zero `Information`, unlike an ordinary existing file's
`FILE_OPENED` value. Directory/non-directory restrictions are applied after device
resolution because they belong to filesystems. Regular file opens retain those
restrictions.

## Native evidence

The adjacent std-only producer calls actual NT APIs without RAX code. Windows
10.0.29698 ARM64 and translated x64 produce identical output: 46 cases, 39
successful opens, all successful handles closed. The cases include NT open and
create entry points, upper/lower-case names, DOS and device prefixes, child names,
all six create dispositions, sharing-zero simultaneous opens, reduced grants,
asynchronous opens and directory-option boundaries.

| Observation | Measured result |
| --- | --- |
| `\??\NUL`, `\DosDevices\NUL`, `\Device\Null` and measured case variants | Open and create succeed |
| Remaining counted `\child` | Accepted by the null driver |
| Counted `NUL.` component | `STATUS_OBJECT_NAME_NOT_FOUND`; NT names do not receive Win32 dot cleanup |
| Create dispositions 0 through 5 | Success, `Information = 0` |
| Two simultaneous read/write opens with sharing 0 | Both succeed |
| Directory and non-directory option bits together | Accepted by the null driver |
| File type / volume class 4 | Character device / device `0x15`, characteristics `0x100` |
| Standard information | 24 bytes, zero allocation/EOF, one link, not a directory |
| Synchronous reads of 0, 1 or 4 bytes | `STATUS_END_OF_FILE`, zero bytes, unchanged output buffer |

The full logs retain additional query statuses, IOSB publication and byte values.
The 46 open rows are transcribed into `open-observations-v1.json` and replayed
through the real native-service dispatcher for each of the three guest ABIs.
Native WoW64 producer execution is not included in this capture. Guest ABI parity
and measured host/caller profiles are separate claims.

The Microsoft [NtCreateFile reference](references/ntcreatefile.md) and
[NtOpenFile reference](references/ntopenfile.md) describe the native device/open
interfaces. Source URLs, retrieval times and document hashes are retained in
`references/provenance.json`; source/image/receipt identities are in
`provenance-v1.json`.

## Corrected execution

The unchanged service-return observer, relinked against the corrected production
library, runs the actual installed ARM64 CMD and DLLs. Native and emulated
`cmd.exe /d /c type NUL` both exit 0 with empty stdout and stderr. The formerly
failing NUL `NtCreateFile` returns success; the guest reaches
`Complete(Exited(0))` without an active exception. Native redirected pipes and
the guest captured-console adapter remain different I/O preconditions. No
separate sysroot or synthesized command result is used.

| Host execution | Complete selected owning modules | Failed / ignored |
| --- | --- | --- |
| macOS ARM64 | 41 passed | 0 / 0 |
| Linux AMD64 under host translation | 41 passed | 0 / 0 |
| Windows ARM64 | 43 passed | 0 / 0 |
| Windows x64 under Windows ARM64 translation | 41 passed | 2 / 0 |

The selected modules cover file open, create, read, write, information and volume
queries. All four configurations compile with debug assertions and overflow
checks enabled. Normal `clippy --lib --tests` succeeds on all four targets;
Windows retains the existing `vendor/vm-memory` calling-convention warning.
Formatting passes. Full-library completion is not established by these module
runs; the existing broad validation jobs and their original failures remain
separate.

The two x64 failures are
`file_information_installed_native_and_wow64_leaves_preserve_five_argument_return_abi`
and `nt_read_file_installed_native_and_wow64_nine_argument_leaves`. Both stop at
`WindowsProcess::spawn_image`, before their file-service calls, because the
installed NTDLL architecture does not match the selected guest. The unchanged
native-runtime selector compares the on-disk ARM64X machine with x64 before
alternate-view transformation. The new NUL regression and all other 41 selected
x64 tests pass. These original failures are retained; no tests are skipped or
weakened to qualify this correction. They remain requirements of the full
process-emulation objective.

## Assumptions and bounds

| ID | Assumption and dependent result | Basis | Stress test and falsification probe | Status |
| --- | --- | --- | --- | --- |
| N1 | The NUL mismatch survives the MUI length correction; a separate open correction is needed. | Actual installed-command baseline with the retained-length fix. | Native/guest exit and output equality would falsify the remaining mismatch. | Confirmed: native 0, guest 1; traced invalid-parameter NUL open. |
| N2 | The selected default null-device profile can be modeled without a host file. | Identical native ARM64/x64 controls and the corrected actual installed-command comparison. | Exact open-row replay, no filesystem authority, simultaneous sharing-zero opens and handle-count restoration. | Confirmed for the measured profile and completed module runs; remaining caller/kernel profiles are separate. |

High impact, outside this changeset: ARM64X alternate-view/ABI execution and other
missing native services still block the full process-emulation objective.
Medium impact: process-defined DOS aliases, relative object-directory null opens,
maximum-allowed/system-security grants and asynchronous null I/O need additional
contracts; the current correction does not establish those behaviors. Existing
unsupported paths remain explicit. Other Windows kernel builds and physical AMD64
hardware remain unmeasured. Broader full-library validation is separate from
selected owning-module tests.
