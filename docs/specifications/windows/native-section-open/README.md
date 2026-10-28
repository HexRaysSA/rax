# Native installed image-section opening

`NtOpenSection` now opens guest-owned typed `ImageSection` resources from the
bounded installed KnownDll namespace. The implementation acquires host metadata
through fixed absolute native opens, closes every acquired host handle, and
retains immutable path, access, case-policy, attributes and extent metadata.
Guest handles share an `Arc` identity; they do not contain native HANDLE values.
No image mapping, file backing, `NtQuerySection` implementation or successful
ordinary guest process exit is claimed by this semantic group.

The preceding unchanged production observer stopped at `NtOpenSection` service
`0x37`, instruction PC `0x1800013b0`, stopped PC `0x1800013b4`, desired access
`0xD`, after 145453 scheduler calls. The observer source is 11177 bytes with SHA-256
`d41c953666769f60c0a4a53b098bd85f8b778133d6839be4c8ea6ca221c1734e`.
The final owning rebuild and ordinary rerun are recorded separately.

## Native evidence and bounded applicability

Actual captures use Windows `10.0.29683.1000`, native machine `IMAGE_FILE_MACHINE_ARM64`
(`0xAA64`), and subject `S-1-5-18`. ARM64, x64 compatibility, x86 and x86 LAA are
four executable profiles on that one ARM64 kernel. They are not physical x64
kernel evidence. Other builds, subjects, physical x64 kernels and previously
unselected namespaces remain unknown.

| Producer family | Executable profiles | Measured cases per profile | Mature replay rows |
| --- | --- | --- | --- |
| `fresh-v3` | ARM64 | 1 excluded warmup + 2 first calls | Separate debugger evidence |
| `probe-v3` | ARM64, x64, x86, x86 LAA | 5646 | 22584 |
| `duplicate-v2` | ARM64, x64, x86, x86 LAA | 17760 | 71040 |

The mature replay total is `4 * (5646 + 17760) = 93624` rows. Producer identities
bind the actual native source, executable, PE machine/LAA flags, stdout, kernel,
principal, inspector and installed NTDLL files. No executable or archive is stored
in this corpus. Source hashes are frozen after clang-format and before compilation;
MSVC `/we4473` rejects missing variadic arguments. Excluded helpers are recorded
in [excluded-helper-register.json](excluded-helper-register.json).

| Open family | Cartesian partition | Rows per profile |
| --- | --- | --- |
| Access/name/case | 37 masks * 9 names * 2 flags | 666 |
| Root/name/reparse | 15 roots * 27 names * 4 flags | 1620 |
| Attribute flags | 42 flags * 4 names * 4 access masks | 672 |
| Attributes/output/name descriptor | 10 * 12 * 6 * 2 lengths | 1440 |
| Output/name descriptor/name buffer | 12 * 8 * 8 | 768 |
| Counted strings | 4 names * 8 lengths * 5 maxima * 3 buffers | 480 |
| Total | Sum of six partitions | 5646 |

Duplication covers `3 parents * 4 source grants * 37 desired masks * 10 options
* 4 source flag combinations = 17760` rows per profile. Every row restores the
exact typed section-handle set and owned input handles. Global handle counts
remain diagnostic because unrelated kernel activity can change them.

The fresh helper patches only its owned debugger child. It records the original
NTDLL `SVC #0x37; RET` bytes `E10600D4C0035FD6`, original three arguments, 48-byte
OBJECT_ATTRIBUTES, requested `KERNEL32.DLL`, root Directory grant `0x3`, true LR,
the original successful service return, Section grant `0xD`, image attributes
`0x01800000` and extent `0x171000 = 1511424` bytes. The return debugger PC is true
LR plus 4 bytes. Child exit 77 is a capture stop before mapping, not an ordinary
guest exit. The two non-warmup parent handle sets restore exactly.

## Implemented semantics

| Contract | Measured implementation |
| --- | --- |
| Selection | Root plus `\KnownDlls`, optional `\KnownDlls32` and `\KnownDllsChpe32`; at most 8192 entries, 32766 UTF-16 code units per bounded string, 16 MiB aggregate captured-string input |
| Resource | Typed `Object::ImageSection`, canonical selected path, guest reference lifetime, captured authorization ceiling, image attributes and positive extent |
| Image profile | Attributes `0x01800000`, BaseAddress 0 at acquisition, extent 1 through `0x7FFFFFFF` bytes inclusive; out-of-profile acquisition fails explicitly |
| Case policy | Captured independently from directory/link policy; `OBJ_CASE_INSENSITIVE` (`0x40`) performs folded lookup; mixed selected section policies are rejected |
| Attribute mask | Sections accept `0x11FF2`, including ignored user-mode `OBJ_KERNEL_HANDLE` (`0x10000`); directory/link mask stays `0x1FF2` |
| Ordering | Lookup precedes type-specific rejection; section OPENLINK (`0x100`) rejection precedes authorization, EXCLUSIVE (`0x20`) rejection follows authorization |
| Empty link root | Selected DOS KnownDllPath target yields `STATUS_OBJECT_NAME_INVALID`; `OBJ_DONT_REPARSE` yields `STATUS_REPARSE_POINT_ENCOUNTERED`; unmeasured NT-target grammar is explicitly unsupported |
| Generic rights | READ `0x20005`, WRITE `0x20002`, EXECUTE `0x20008`, ALL `0xF001F`; opening zero grant is denied; MAXIMUM_ALLOWED adds the captured ceiling |
| Duplication | Drops unassigned low bits `0xFFE0`, retains invalid SYNCHRONIZE for denial, discards MAXIMUM_ALLOWED, permits zero grant, and preserves existing close-source/protect/inherit/output/slot-reuse policy |
| Publication | Atomic handle/output behavior, cleanup after faults, distinct Native64 and WoW64 caller copyback, measured partial-page/guard effects |

On the captured ARM64 host's CHPE-enabled x86 profile, WoW64 section opens with a direct Directory root
named `\KnownDlls32` select the captured `\KnownDllsChpe32` resource. Absolute
`\KnownDlls32\...` and root `\` plus relative `KnownDlls32\...` retain
`\KnownDlls32`. Reduced query/read-control grants and low-bit handle tags retain
the direct-root redirect. The selector requires the actual native host machine,
queried through dynamically resolved `IsWow64Process2`; GetNativeSystemInfo can
report an emulated x86/x64 machine on ARM64. Missing architecture detection with
a present/unknown CHPE namespace produces an explicit unsupported result.

This conversion also depends on the process's hybrid-execution selection.
The installed pure x86 runtime disables that direct-root redirect while
preserving the captured native machine and the explicitly named CHPE resources.
The original CHPE-enabled replay above remains unchanged. See the independent
build-29695 enabled/disabled controls and regression tests in
[native-x86-chpe-profile](../native-x86-chpe-profile/README.md).

For read-only guarded output, Native64 returns `STATUS_GUARD_PAGE_VIOLATION`
(`0x80000001`) and consumes the guard (`0x102 -> 0x2`). WoW64 section copyback
returns `STATUS_ACCESS_VIOLATION` (`0xC0000005`) and retains it (`0x102 -> 0x102`).
Writable guard consumption and crossed output atomicity are independently replayed.
Directory/link publication and descriptor-read guard handling retain their own
previously measured contracts.

Native `NtQuerySection` is used to acquire/query capture metadata only. A denied
ancillary query returns zero metadata with native returned length 0; WoW64 records
`0xFFFFFFF8 = 4294967288`, the observed 24-to-16-byte adjustment underflow. Replay
does not invent a guest query implementation or zero that native diagnostic.

The shared open algorithm captures the ABI descriptors, performs the measured
WoW64 conversion reads, resolves the selected path, computes authorization,
opens/reuses a typed resource, then publishes the handle. Publication faults
close only the newly opened handle and retain the primary measured fault/status.
For U decoded UTF-16 code units, E directory entries, object-table capacity C and
H live handles, path lookup is bounded by O(U log(E + 1)), resource scanning by
O(C), and ordered handle selection/insertion by O(H + log(H + 1)). Hash-map object
lookup/creation uses expected constant-time probes. Auxiliary path storage is
O(U); the namespace snapshot and retained table allocations are separate storage.
The resource helper's documented O(C + (H + 1) log(H + 1)) is a conservative
expected-time bound; neither count nor runtime is independent of table size.

## Validation and provenance

The portable Rust tests replay all 93624 mature rows through the actual service
and duplication paths, including exact output bytes, protection changes, statuses,
typed grants, canonical identity, cleanup and handle slot reuse. A separate pure
test covers invalid capture bounds, case-policy disagreement and unselected
resources. The Windows installed-leaf test executes actual NTDLL entries for the
native host and x86 guest, checks typed identity/grants/cleanup, and asserts x86
`RET 12` stack movement (16 bytes including the return address).

Run from this directory:

```text
python3 -B check-evidence.py
python3 -B check-negative-evidence.py
```

The independent evidence verifier validates producer partitions, identities,
fresh original-service/LR evidence, cleanup and specific case/CHPE/guard controls.
Controlled corruption recomputes claimed stdout hashes before checking semantic
rejection. Optimized Python verification is rejected explicitly.
Results are stored in [negative-evidence-report.json](negative-evidence-report.json).

[assumption-register.json](assumption-register.json) identifies dependent results,
stress tests and falsification probes. [change-surface-map.json](change-surface-map.json)
covers every RAX and Assist plane. Complete final platform gates, owning-source and
archive identities, ordinary continuation evidence and bounded findings are separate
records so controlled replay cannot be mistaken for installed or shipping proof.

Primary sources and their exact downloaded bytes/hashes are in
[references/sources.json](references/sources.json): PHNT `ntmmapi.h`, Microsoft
ZwOpenSection, GetNativeSystemInfo and IsWow64Process2 documentation and licenses.
Documentation defines APIs and structures; native captures own the measured
ordering, WoW64 conversion, authorization and fault behavior on this host/build.

## Final gate and continuation record

| Host | Full passed / failed / ignored | Focused passed | C API passed | All-targets |
| --- | --- | --- | --- | --- |
| macOS | 7749 / 0 / 2 | 4 | 168 | Pass |
| Linux | 7743 / 0 / 2 | 4 | 168 | Pass |
| Windows | 7163 / 5 / 2 | 5 | 168 | Pass |

The five Windows BZHI/FP16 failure identities and two ignored microkernel tests
exactly match the preceding group. No new failure or ignored test is introduced.
Unix integration runs544 Windows-personality tests; Windows runs4 native-memory
integration tests. Owning checks compile/run113 current Rust units,2 verified
helpers and9 matching current C++ consumers with empty core features. macOS runs
7 CLI/MCP/consumer CTests and2 protected-text scans; Linux/Windows build the
shipping archive and run5 C++ consumers. Every final archive passes an independent
member walk. These use frozen owning embeddings; whole current-root/plugin/GUI/
package proof is excluded. Exact source/archive/executable hashes, gate commands,
counts, failure names, ignored selection and limits live in
[validation-summary.json](validation-summary.json) and the owning identity records.

The unchanged observer advances145453->161784 scheduler calls:
`161784 - 145453 = 16331`. Three ordinary CRT programs now stop at native
`NtMapViewOfSection` service0x28, instruction PC0x1800012a0, stopped PC0x1800012a4.
Whoami retains NtTraceEvent0x5E. All four outcomes remain reason5/Internal with
exit_code0; zero ordinary guest exits are proved. Original debugger child exit77
continues to mean capture stop. Installed NTDLL and all9 native producer source,
executable and stdout identities are unchanged after the owning runs.

[bounded-findings.json](bounded-findings.json) records the outstanding full-process
mapping/exit requirement, physical x64/build/subject limits, frozen-root exclusions,
pre-existing warnings/failures and adjacent architecture-comment discrepancy.
The full same-host process-userland goal remains active and incomplete.
