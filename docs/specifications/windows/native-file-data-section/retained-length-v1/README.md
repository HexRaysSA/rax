# Retained data-section file length

Status: native contract, retained-handle correction and four host-view regression
runs confirmed. The actual installed ARM64 `cmd.exe /d /c ver` comparison also
matches native exit status and output. Other installed programs remain separate
validation targets.

The pre-fix constructor calls `File::metadata().len()` before creating a data
section. On the measured Windows profile, a real `FILE_READ_DATA` handle permits
both a read-only section and `FileStandardInfo`, but Rust metadata requires
`FILE_READ_ATTRIBUTES`. The extra metadata precondition incorrectly returns
`STATUS_ACCESS_DENIED` while mapping installed MUI resources.

The correction queries only the retained handle's length through the
Windows filesystem adapter. Unix keeps the existing metadata query. It adds no
access rights, reopens no pathname and retains the existing zero-size,
read-only-growth and 64 MiB section bounds.

The documented synchronous
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
selector `FileStandardInfo = 1` returns
[FILE_STANDARD_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info).
The 24-byte native record stores signed 64-bit `EndOfFile` at byte offset 8.
A host-local aligned record remains live for the call. A negative end-of-file
result is invalid, rather than an unsigned size. There is one host API call and
constant-size caller storage; provider latency is not bounded by this count.

## Independent native evidence

The exact producer and source/image/output provenance are adjacent. Both ARM64
and translated x64 producers exit 0 on Windows 10.0.29698 ARM64. Each opens five
handles to the installed `C:\Windows\System32\en-US\cmd.exe.mui`, queries its
length and creates/closes a read-only unnamed section. The 132,608-byte target
has the same SHA-256 before and after each control. Each producer closes all
five file and five section handles.

| Requested access | NT open options | Rust metadata | Win32 standard query | Read-only section |
| --- | --- | --- | --- | --- |
| `0x00100001` | `0x60`, synchronous non-directory | error 5 | 132608 bytes | success |
| `0x00000001` | `0x40`, asynchronous non-directory | error 5 | 132608 bytes | success |
| `0x00100081` | `0x60` | success | 132608 bytes | success |
| `0x00000081` | `0x40` | success | 132608 bytes | success |
| `0x00120089` | `0x60` | success | 132608 bytes | success |

Direct NT `FileStandardInformation` queries on the three synchronous handles
also return success and exactly 24 bytes with the same end-of-file value.
The asynchronous handles use the synchronous Win32 wrapper; the producer does
not leave a raw pending NT query with stack-owned output storage.

## Regression and installed-command validation

The new dispatcher regression opens real files with data-only grants, then
renames the opened file and replaces its former pathname. It creates read-only
and copy-on-write sections, closes the original file handle, maps the section,
compares the original bytes, unmaps and closes the section. All three guest ABIs
and both synchronous/asynchronous opens are selected. On Windows, it also
requires the original host handle's Rust metadata call to remain denied.
The captured pre-fix installed-command trace returns `STATUS_ACCESS_DENIED` from
`NtCreateSection` while opening the MUI resource. The independent native control
above distinguishes the denied metadata query from successful section creation.
The new dispatcher regression was not run against a pre-fix library; its baseline
is this captured installed-command failure and independently measured handle
contract.

| Host execution | Complete data-section module | Failed / ignored |
| --- | --- | --- |
| macOS ARM64 | 17 passed | 0 / 0 |
| Linux AMD64 under host translation | 17 passed | 0 / 0 |
| Windows ARM64 | 17 passed | 0 / 0 |
| Windows x64 under Windows ARM64 translation | 17 passed | 0 / 0 |

All four builds enable debug assertions and overflow checks. Each run includes
the new regression and the existing section geometry, protection, growth,
coherence, lifetime and fault-priority tests. These are complete module runs
selected from the library test binaries, not completed full-library runs.
Normal `clippy --lib --tests` succeeds for all four targets; Windows retains an
existing `vendor/vm-memory` calling-convention warning. Formatting passes.

The unchanged service-return observer, relinked against the corrected production
library, runs the actual installed ARM64 CMD and DLLs without a separate sysroot.
Native and emulated `cmd.exe /d /c ver` both exit 0, write identical 47-byte stdout
and leave stderr empty. The exact stdout is
`\r\nMicrosoft Windows [Version 10.0.29698.1000]\r\n`. The emulated process reaches
`Complete(Exited(0))` without an active exception. Native redirected pipes and
the guest captured-console adapter remain different I/O preconditions. This
comparison establishes this command on the measured Windows profile, not
arbitrary program completion or execution on physical AMD64 hardware.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Basis | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| L1 | The synchronous standard-info query can supply length without extra handle rights. The Windows adapter depends on it. | Independent five-grant native controls and the documented API. | Data-only asynchronous/synchronous handles; any query or section failure, negative EOF or NT disagreement falsifies the profile. | Confirmed on the two measured caller views; other kernel builds unknown. |
| L2 | Only the Windows length mechanism changes. Shared section policy and Unix behavior remain intact. | Common caller and filesystem adapter boundaries; unchanged source hashes during all four module runs. | Existing scalar, protection, growth, COW, lifetime and bounds tests on Windows/macOS/Linux; any changed outcome falsifies parity. | Confirmed for the four measured host views and selected module; full-library results remain separate. |

High impact: the separate ARM64X alternate-view/ABI execution gap still blocks
translated x64 installed-runtime admission. This correction does not resolve it.
Medium impact: other kernel builds and physical AMD64 execution remain unmeasured.
Neither limits the recorded result on Windows 10.0.29698 ARM64.
