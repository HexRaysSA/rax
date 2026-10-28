# Volume-device queries from installed Windows libraries

This increment implements `NtQueryVolumeInformationFile` class 4,
`FileFsDeviceInformation`, for admitted file objects and standard devices.
Other information classes remain explicit unsupported operations. The service
shares the existing NT export factory and native/WoW64 dispatch; it adds no
public C ABI layout, package option, dependency or permission expansion.

| Object | DeviceType | Characteristics |
|---|---|---|
| Console input/output/error | `0x50` | `0x20000` |
| NUL, including a NUL FileObj | `0x15` | `0x100` |
| Named/anonymous pipe object | `0x11` | `0x20000` |
| Real Windows file/directory | queried from retained host file | owning volume's actual flags |
| Unix-hosted Windows DriveMap file/directory | virtual mounted disk `0x07` | captured Windows profile `0x20020` |

The Unix adapter implements the Windows virtual drive model; it does not expose
Unix hardware/device flags as Windows values. Metadata-only pathname objects
revalidate identity before reporting this virtual profile. Windows uses the
retained File where present. Its legacy metadata-only fallback obtains a private
metadata handle and verifies the original file identity. A replaced pathname
fails closed. Normal retained files are not reopened by pathname.

Real Windows volumes can differ: the controls report `0x20020` for the local
C volume and `0x10` for captured shared output. The Windows adapter obtains the
actual eight-byte result through fixed class/length NT arguments, an owned file,
and aligned private buffers. Guest pointers, handles, names and lengths never
enter that host call. Stable private IOSB/OVERLAPPED-prefix and output boxes
remain alive until completion. `GetOverlappedResult(FALSE)` observes a pending
completion without requesting SYNCHRONIZE rights or waiting on an unrelated
operation. V7 validates the prefix/API pairing with zero/SYNCHRONIZE grants on
regular, directory, async-opened and shared-output files. All observed calls
complete immediately; an actually pending kernel request is not claimed as an
exercised native oracle path.

The class-4 length check precedes handle/pointer probes. A native 64-bit caller
then probes the four-byte IOSB Status, checks output alignment (four bytes),
and probes the complete caller output span before resolving the file object.
WoW64 passes a null IOSB through but uses private native scratch for a nonnull
IOSB; it probes output before a successful late status copy. Data is written
before status and Information. Native readonly guard probes and WoW64 direct
status-copy faults retain their measured different guard behavior. Unknown
handles and wrong object types remain distinct. Reduced grants, including zero,
do not prevent this metadata query, as established independently by V5.

Native64 IOSB's unused upper Status-union word is zeroed deterministically.
Some providers leave those reserved bytes unchanged; they are not the defined
NTSTATUS field. The defined fields are the low four-byte Status and the
pointer-sized Information count. No byte-identical claim is made for all
providers' reserved padding. The replay preserves every captured status, guard, nonpayload byte, alias and
partial-publication assertion. Unix virtual-drive data remains the captured
profile. On Windows, the real fixture file's eight-byte device payload is bound
to an independent native class4 query before emulation; IOSB stores that overwrite
aliased payload bytes retain their captured values. Actual volume flags may
differ from the historical local-disk profile. Query work is O(P) for P probed output pages plus host
metadata work, with O(1) private scratch; it does not allocate caller-length
buffers. Pointer-width publication is checked and preserves caller LastError.

The native interface/layout references are Microsoft's
[query API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryvolumeinformationfile),
[device information structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_fs_device_information),
and [IOSB](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block).
User-mode capture order, guard effects and device constants are direct native
observations on ARM64 Windows 10.0.29683, including AMD64 and WoW64 execution
views. These views are not an independent physical AMD64 kernel oracle.

## Native controls and validation

| Producer | Per view | Scope |
|---|---|---|
| V2 | 78 calls | 13 object roles, six lengths |
| V3 | 240 calls | six roles, 20 pointer/guard/alias cases, two lengths |
| V4 | 264 calls | V3 plus readonly guard distinctions |
| V5 | 198 calls; 33 duplicates | zero/SYNCHRONIZE/READ_ATTRIBUTES grants |
| V7 | eight calls; eight duplicates | retained-handle completion prefix and async-opened file |

All five accepted versions complete four views, with stable source/executable/
module identities and balanced owned resources. They record 3,152 calls across
versions, including repeated inputs. A separate V2 ARM64 launch records another
78 calls. V1 is a rejected compile failure (initializer-list header dependency).
V6's reopen experiment is rejected: directory reopens fail and shared-file
identity queries are unavailable. Neither rejected version supplies completed
final identity proof. Original records remain immutable.

Six focused tests pass on all three hosts. The compiled V4 replay compares
1,056 complete native observations: return status, memory windows, consumed and
unconsumed guards, aliases, wrong handle kinds, handle-table stability and the
retained file cursor. The red baseline against `3661ff6b` has zero passes and
three failures. The original test prefix remained unchanged at that qualification frame.
The later live-volume binding below corrects its host-dependent disk fixture. The frozen source graph contains 26,895 inputs, SHA-256
`336e8771aaa128fabb49c5e87cd2629285344f0b04f2de7eee78d851ceab44de`.
Later publication records are outside the compilation graph.

| Host | Full library | C API | Integration |
|---|---|---|---|
| macOS ARM64, no default features | 8,146 pass; two existing ignores | 183 pass | 544 pass |
| Linux AMD64 container, no default features | 8,140 pass; two existing ignores | 183 pass | 544 pass |
| Windows ARM64, no default features | 7,609 pass; five existing lowerer failures; two existing ignores | 183 pass | four pass |

The Linux container uses the ARM64 host's virtualization/translation environment.
Native Windows and actual owning consumer evidence are distinct gates. Retained
Assist ABI184 consumers pass on all three hosts; this is not a claim about whole
current Assist ABI274 GUI/package execution. The first macOS gate launch lacked
its configured temporary directory and failed before completing its replay;
the original failed record and the successful complete retry remain separate.
The first ARM64 cross-check hit cargo-xwin's shared clang-cl symlink setup race;
its serial retry retains the original failed setup transcript.

Both actual owning ordinary routes still run smoke to exit status zero. Both
advance whoami past the volume query to `NtOpenKey` outside the selected runtime
snapshot, for `\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Sorting\\Versions`.
Rust terminal index 2,558 corresponds to 2,559 C API turns started. C API reason
5 with exit-code field zero is an emulator failure, not guest exit. The next
NLS snapshot boundary, independent image-view unwind registration and previous
image/runtime policy boundaries keep the full same-host userland objective
active. No changelog or release work is included.


## Live Windows replay fixture (2026-10-28)

A later complete Windows29695 library run retained24 disk-payload mismatches
while every corresponding NTSTATUS matched. A separate direct native query
reports DeviceType0x07/Characteristics0x00220020 on the current volume; V4's
historical local volume reports0x07/0x00020020. The production Windows adapter
already returns live volume data as documented. Pinning it to the historical
flags would change that contract.

The fixture now queries its independently opened retained file through a raw
native class4 call with separate private buffers. The file cursor remains7.
If completion is pending, a private nonalertable file wait keeps those buffers
alive. The oracle does not call the production host adapter. Only bytes whose
captured source is the eight-byte device payload receive this live binding.
Successful IOSB status/Information stores win over overlapping payload; fault
rows require captured evidence that the complete payload store occurred. All
1056 original rows, statuses, guards, aliases, other bytes, handle sets and
cursor checks remain enabled. Original producer and capture bytes are unchanged.
A pure regression checks changed type/flags against both x86 IOSB overlap
directions, a late fault and a rejected output probe.

Assumption VD1: a retained real Windows file exposes its owning volume's live
class4 data. Basis: the native query and the existing adapter contract. The
payload binding depends on it. Stress tests cover differing flags/type and
captured alias/fault publication. A status, guard, cursor or nonpayload change
falsifies the fixture projection; such changes remain hard replay failures.
The filesystem flag bit names beyond the measured numeric masks are not inferred.

The seven focused volume-device tests pass on Windows ARM64 build29695,
macOS ARM64 and Linux x86-64 container execution. Each run includes all1056
retained observations and the independent payload-binding regression. This
fixture-only change does not alter the production host adapter.
