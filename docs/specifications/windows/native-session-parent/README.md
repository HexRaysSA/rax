# Installed current-session directory selection

A Windows process can traverse its `\Sessions\<session>` directory without
permission to enumerate that directory. Installed namespace acquisition keeps
the native authorization ceiling and captures the already selected `Windows`
child, plus `BaseNamedObjects` for a nonzero session, through fixed typed opens.
Other membership remains explicitly uncaptured. Guest lookup uses the immutable
captured graph and never forwards a guest name or desired access to the host.

The acquisition adapter first tries `NtOpenSymbolicLinkObject`. Only
`STATUS_OBJECT_TYPE_MISMATCH` permits the directory alternative. Each successful
child open has a bounded canonical-name query, an independent absolute open,
`NtCompareObjects` identity comparison, and matching granted rights. All
temporary handles close before the metadata is returned. Two samples must
agree within three attempts. Existing link-target and alias validation still
governs the selected graph, and existing case-policy probes operate on these
independently observed child names.

The parent remains a partial directory. A name not captured beneath it is
`Unselected`, rather than a fabricated missing entry. Known children retain
their independently selected bodies, access profiles and identity after the
namespace catalog or a parent handle is dropped. The selected parent's native
maximum grant and system-security result continue to govern opens.

## Native observations

The two read-only C++ controls were executed under the same ordinary-user SID
and installed NTDLL hash. Their receipts include process birth and executable,
source and output hashes. They do not independently identify the kernel build
or establish other caller subjects, Windows versions or architectures.

| Control | Open requests | Other observations | Opened/closed handles |
| --- | ---: | --- | ---: |
| Ten selected directories, eight access masks | 80 | 94 enumeration attempts | 47/47 |
| Fixed session children, type/case/attribute matrix | 120 | 16 relative/absolute identity comparisons | 33/33 |

The captured current session is 1. `\Sessions\1` grants `0x00000002`
(`DIRECTORY_TRAVERSE`) through `MAXIMUM_ALLOWED`, while its enumeration attempts
return `STATUS_ACCESS_DENIED` (`0xC0000022`). The selected child directories open
independently: `BaseNamedObjects` grants `0x000F000F` and `Windows` grants
`0x00020003`. Their canonical names, native types and independent handle
identities match the fixed selection. Original and lowercase spellings both
resolve under the captured parent, including without `OBJ_CASE_INSENSITIVE`.

Zero-right opens of existing directories return `0xC0000022` in these controls,
consistent with the earlier directory corpus. `NtOpenDirectoryObject` rejects
`OBJ_OPENLINK` with `STATUS_INVALID_PARAMETER` (`0xC000000D`) when resolving
these existing children; that attribute is absent from the adapter. The
symbolic-link typed opens return `STATUS_OBJECT_TYPE_MISMATCH` (`0xC0000024`)
for the observed directory children. The fixed missing child returns
`STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`); this observation does not classify
arbitrary uncaptured names as absent.

Microsoft documents `DIRECTORY_QUERY` (`0x00000001`) and `DIRECTORY_TRAVERSE`
(`0x00000002`) separately in
[NtOpenDirectoryObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopendirectoryobject),
and the native directory output and enumeration context in
[NtQueryDirectoryObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerydirectoryobject).
The concrete authorization, type, case and status results above come from the
retained native controls. `NtCompareObjects` is the same runtime export used
by installed directory-alias verification; its presence and successful paired
comparisons were checked in these controls.

```sh
python3 -B docs/specifications/windows/native-session-parent/verify-evidence.py
cargo +1.95.0 test --locked --offline --no-default-features --lib traverse_only_tests::
cargo +1.95.0 test --locked --offline --no-default-features --lib partial_session::
# On Windows, exercise the actual fixed-subject acquisition adapter:
cargo +1.95.0 test --locked --offline --no-default-features --lib object_namespace::installed::session_parent::tests
```

The adapter adds at most two fixed child records and two temporary native
handles at a time. Its 4096-byte canonical-name buffer and three paired sample
attempts give O(1) extra time and space relative to the existing directory
selection. Returned UTF-16 lengths and pointers must lie inside the reported
native output extent; the complete canonical name must match the fixed path.

This change concerns host-side installed namespace acquisition. It does not
add a guest `NtQueryDirectoryObject` service or establish complete installed
Windows process startup. The actual native Rust executable passed three
capture-adapter tests, two partial-model tests and one entered-service test
covering every `WinArch`. The retained source/artifact manifest joins the
host build to that native executable; it does not assert a native rebuild.
Portable macOS checks passed the three new model/service cases, all 17 owning
directory replay cases, 244 C API cases and strict library Clippy. The three
new model/service cases also passed in an x86-64 Linux container translated
on an AArch64 Docker host; this is not physical x86-64 qualification.
Workspace/all-target compilation passed for macOS, Windows ARM64 and Windows
x86-64. The rebuilt ordinary-user
CMD attempt passes process construction, loads installed `ntdll.dll`,
`kernel32.dll`, `KernelBase.dll` and `ucrtbase.dll`, and enters guest execution.
It then stops at `NtSecureConnectPort`: the selected guest server and owned
shared views are not matched. Its terminal sample reports an instruction
budget bound of 2144320; this is an upper bound, not an independently counted
retired-instruction total. The diagnostic wrapper exits 0 after recording the
internal guest error. That wrapper result is not a successful CMD exit.
The retained `startup-control.rs` is the exact diagnostic source, joined by
its SHA-256 digest to the startup build manifest and native receipt.
