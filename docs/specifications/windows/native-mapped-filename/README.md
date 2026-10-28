# Mapped backing-file names

`NtQueryVirtualMemory` class 2 reads the backing-file identity of a guest image
or file mapping. It does not return the object-manager section name, a loader
basename, or a guessed DOS-to-device translation. Pagefile mappings return
`STATUS_FILE_INVALID`; private, free and ordinary reserved addresses return
`STATUS_INVALID_ADDRESS`. Query rights and caller-buffer validation retain the
native and WoW64 ordering captured below.

The loader retains the file it actually read through image admission. In native
mode, a separate read-only `SEC_IMAGE_NO_EXECUTE` view retains that file object
for filename queries. Selected kernel sections retain their existing section
handle instead. The native adapter queries only independently owned host views
with aligned, initialized, bounded host buffers. Guest handles, addresses and
output pointers remain in the common emulator. A rename changes the observed
name; closing the file handle or replacing its former pathname does not change
the mapped file identity. Allocation release retires the metadata before address
reuse. Explicit supplied bytes without a selected file/section name remain an
explicit unavailable input, rather than receiving an invented device path.

The CLI uses the file-backed process constructor after its format preflight.
The new executable-name fixture compares its actual image filename with native
execution, including Unicode paths and spaces. The explicit `spawn_image` API
continues to represent supplied bytes and does not reopen its descriptive path.

## ABI and copy behavior

The record is `UNICODE_STRING` followed by UTF-16 units and a terminating NUL.
The header is 8 bytes for x86 and 16 bytes for x64/ARM64. The required size is
`header_bytes + 2 * (name_units + 1)` bytes. Native64 preserves its four padding
bytes. Short native buffers can contain a truncated name; the device-prefix
boundary also has a measured `STATUS_OBJECT_PATH_INVALID`/zero-length result.
WoW64 converts only a successful native record and publishes `ReturnLength`
after caller copy. Its initial optional-slot read consumes a reached guard;
a readable, read-only slot can fail at the final store instead. An incomplete
copy can retain a temporary pointer in the header. The emulator gives that
pointer guest-owned temporary storage and retires it on every copy outcome.
The captured ARM64-host WoW64 converter preserves completed 16-byte copy blocks
before a straddling block faults.

Common query work is O(L + log A), excluding native filesystem metadata cost,
for L filename units and A allocations; retained metadata is O(A). Native name
buffers are bounded by the 16-bit NT string ceiling. WoW64 conversion backing
uses the guest memory manager and cannot allocate beyond its commitment budget.
The exact native allocation-failure profile for extreme caller lengths remains
unqualified; conversion-storage failures remain explicit emulator diagnostics.

## Frozen native evidence

Every executed versioned C probe and runner is immutable after execution.
They record Windows 10.0.29695 ARM64, x64 compatibility, and x86 compatibility
observations. The x86 control's loaded system-image family can differ from the
emulator's explicitly selected pure-x86 file family; file identity comparisons
therefore use the selected physical file rather than that control's basename.

| Version | Cases per ABI | Purpose |
| --- | ---: | --- |
| 1 | 48 | Images, data/pagefile mappings, rights, lengths, guards, aliases, rename, close and deletion |
| 2 | 18 | Zero-length probes, read-only optional slots and short headers |
| 3 | 11 | Small native string buffers |
| 4 | 19 | Partial names and the device-prefix boundary |
| 5 | 28 | Every byte length across that boundary |
| 6 | 9 | Partial caller copies, crossing optional slots and string aliases |
| 7 | 48 | First-group queries with deletion result/error captured before the query |
| 8 | 64 | Every 1-32-byte writable prefix before no-access and guard boundaries |

The 399 retained observations include source and executable SHA-256 identities.
`project-v1.py` removes duplicated JSON stdout while preserving every parsed
observation, and binds the original receipt's canonical JSON by SHA-256. Raw
receipts and build logs are retained separately in task evidence. Reproduce a
version with `run-vN.py --compiler-env <saved-environment> --output <in-tree-dir>`.
`run-amd64-v2.py` runs the six case groups on native AMD64 and WoW64 and writes
394 observations: the original 266 plus 128 byte-boundary controls. It uses `probe-v7.c` for the first group, preserving versions
1-6 unchanged. Version 7 records both the result and error of the mapped-file
deletion attempt and then always executes the filename query. The original
version 1 stopped before that query when deletion failed on Windows 2022
(build 20348, x64, case 44, exit 94). Failed deletion does not imply that the
filename query is unavailable; its returned name is compared with the same
strict service replay. `run-v7.py` captures this corrected setup on all three
ABIs of the ARM64 host. `probe-v8.c`/`run-v8.py` cover 1-32 caller bytes before
a no-access or guard boundary. Each receipt binds its actual probe source hash. The existing Windows 2022/2025 jobs replay those fresh native
results through service dispatch using `RAX_NATIVE_MAPPED_FILENAME_OBSERVATIONS`.
The ordinary three-platform matrix replays the retained corpus. No jobs are added.

Additional Windows tests compare the filename adapter with
`K32GetMappedFileNameW` after close, rename and replacement, and execute installed
NTDLL query leaves for the host ISA and the selected pure-x86 catalog. x64
startup through ARM64X projections on an ARM64 host remains a separate process
runtime frontier; this change does not silently substitute another file family.

## Assumption register and scope

| ID | Assumption and dependent result | Basis | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| A1 | Mapping names belong to backing-file identity; allocation-owned metadata is required | Native image/data/pagefile, rename and close controls | Reopen a replaced pathname and compare both live mappings | Confirmed on the captured host; native regression also exercises replacement |
| A2 | Native local-device short-buffer geometry generalizes across selected installed images | Every byte length around the device prefix and separate KERNEL32 controls | Replay fresh native AMD64/x86 matrices on both existing Windows CI kernels | Retained pending those native lanes |
| A3 | The selected WoW64 copy profile preserves whole 16-byte blocks before a crossing fault | Six no-access/guard partial-copy controls | Fresh AMD64/x86 captures and complete buffer-prefix comparison | Confirmed for the captured ARM64 kernel; other kernels require their native lane |

Caller permissions are captured before conversion-storage allocation. A dedicated
regression rejects an initially invalid destination even when its address would
be reused for the next temporary allocation.

The feature concerns the Windows personality and its native input acquisition.
Linux/Linux and macOS/macOS process paths, public C ABI, dependency pins, feature
defaults and package contents are unchanged. General file-data section creation,
unimplemented NT information classes, and complete CMD startup remain separate
frontiers. These are high-impact outstanding parts of the full process goal,
not completion claims from this bounded query implementation.

Primary ABI provenance (accessed 2026-10-28):

- [Microsoft NtQueryVirtualMemory signature](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory);
  its public description covers class 0, not this private class's copy behavior.
- [PHNT memory information classes](https://github.com/winsiderss/phnt/blob/master/ntmmapi.h),
  `MemoryMappedFilenameInformation = 2`, returning `UNICODE_STRING`.
- [Microsoft CreateFileMappingW](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw),
  `SEC_IMAGE_NO_EXECUTE` with `PAGE_READONLY` for a non-executed image view.

The status, padding, copy, guard and lifecycle claims above come from the retained
native observations and executable comparisons, rather than the class-0 prose.

## Validation and actual process frontier

Rust 1.95.0 with default features disabled, on the feature source:

| Host | Query tests | Wider virtual-memory tests | CLI | C API | Existing Windows integration |
| --- | ---: | ---: | ---: | ---: | ---: |
| macOS ARM64 | 3 | 51 | 8 | 191 | 544 |
| Linux x86-64 container | 3 | 51 | 8 | 191 | 544 |
| Windows ARM64 10.0.29695 | 5 | 57 | 10 | 191 | Not run on this host |

All rows above passed with zero failures or skips in the named selections.
The Linux container runs through host translation and is not independent
physical AMD64 evidence. Native AMD64/WoW64 qualification is owned by the two
existing Windows profile lanes. All-target checks passed on macOS and Linux;
the production library also passed Clippy with warnings denied on macOS.
An exploratory all-target Clippy command with all warnings denied failed on
pre-existing unused imports/dead code in unrelated integration targets; the
ordinary all-target Clippy command passed. No unrelated warning suppression
was added.

The actual installed ARM64 `cmd.exe /d /c echo RAX_MAPPED_FILENAME_CMD`, launched
without a separate sysroot, now passes class 2 and reaches unsupported
`NtOpenThread` (service `0x139`). Native execution exits 0 and writes the marker;
the emulator still exits 125 before writing it. The executable SHA-256 is
`d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`;
the tested CLI SHA-256 is
`a3ea6b02e03a8fe2811cc6f14fb04f61801e64dc4ed2f1b0a6311964ebe8085e`.
Both stayed unchanged across the comparison. The complete three-platform
process objective remains active and incomplete.

The first fresh AMD64 qualification also falsified the assumption that native
string padding and WoW64 copy blocks generalize from the ARM64 kernel. Build
26100 zeros the four padding bytes on successful native64 queries, preserves
them on short results, and reaches further into partial WoW64 destinations.
The original exact replay correctly failed; these are open model corrections
until the new byte-boundary controls are replayed. No padding mask, skipped
case, or assertion reduction is used to qualify that profile.

The added retained inputs are 144 ARM64-host version-7 rows, 192 ARM64-host
version-8 rows, and all 266 first-run AMD64 build-26100 rows in
`amd64-26100-projected-v1.json`. The first AMD64 run and ZIP digest are recorded
in that corpus. The query implementation still needs the measured profile
correction; capturing an observation does not establish a passing replay.

Version 9 repeats the byte-boundary campaign with the installed KERNEL32 image
as the subject and every 1-128-byte writable prefix. It distinguishes filename
length from kernel architecture when selecting a WoW64 copy profile. The v3
AMD64 runner retains all preceding controls and adds 512 short-name rows
(906 native observations per kernel). This acquisition precedes qualification
of the length-dependent copy model.
