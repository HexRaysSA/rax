# Installed CurrentVersion headers and registry views

The Windows installed-library selector captures the complete values, ordered
child metadata, access ceiling, canonical name and eight immutable `NtQueryKey`
records for two fixed HKLM subjects in both native and WoW64 views:

```text
Software\Microsoft\Windows NT
    `-- CurrentVersion
        |-- Image File Execution Options  (previously selected shared tree)
        `-- GRE_Initialize                (previously selected shared tree)
```

This is a pair of complete key headers, not a recursive acquisition of every
CurrentVersion descendant. A child absent from complete ordered metadata is
missing. A present child whose body was not selected remains explicitly
unavailable. Existing IFEO and GRE_Initialize routes retain their selected
immutable trees. Retained parent handles retain those routes without an Arc
cycle, including after the original registry catalog is dropped.

A selected direct child's presence must agree with the parent's complete
enumeration. An absent parent cannot retain a present selected child. Acquisition
rejects these contradictory snapshots instead of publishing a route that
disagrees with enumeration.

Acquisition uses fixed `RegOpenKeyExW` paths and fixed view flags. A native
64-bit `NtOpenKey` call does not itself perform Win32 WoW64 redirection. No
guest-supplied name, handle, access mask or pointer reaches a host acquisition
call. Every native HKEY closes before guest execution. Values and query records
must remain stable across bounded repeated observations; unstable acquisition
fails instead of publishing a mixed header.

## Independent native controls

`controls-v1.json` contains 1,248 observations from independent C programs that
do not link RAX. The programs dynamically resolve NTDLL functions and import
only Kernel32. They read key names, metadata, grants and handle tags, without
walking descendants or emitting installed registry value contents.

| Family | Cases per process ABI | ARM64 + x64 + x86 |
| --- | ---: | ---: |
| Absolute logical CurrentVersion | 136 | 408 |
| Relative opens from MACHINE | 48 | 144 |
| Retained logical and physical CurrentVersion parents | 96 | 288 |
| Absolute physical WOW6432Node CurrentVersion | 136 | 408 |
| Total | 416 | 1,248 |

All three process ABIs ran on one Windows ARM64 kernel, build 29698. x64 and
x86 results cover the Windows compatibility processes on that kernel; they do
not establish behavior on a physical AMD64 kernel. Each retained control record
has equal process handle counts before and after its observations.

The native view has 32 values and 96 children; the WoW64 default view has 23
values and 59 children on this installation. Explicit 64-bit selection chooses
the native view. Relative IFEO and GRE_Initialize opens resolve to shared native
keys, including from retained physical WoW64 parents. The corpus records exact
canonical names, access results and handle tags rather than assuming tag
inheritance. `ACCESS_SYSTEM_SECURITY` requests return `STATUS_ACCESS_DENIED`
(`0xC0000022`) in these controls; acquisition captures the actual native result.

The nine `validation/*-source-v1.json` files preserve the exact source text,
original CMake/toolchain inputs and image hashes associated with each captured
stdout stream. The current CMake project builds all three control programs;
the historical source bundles retain their original smaller target lists.
This provenance does not assert that a later toolchain produces an identical
executable. The verifier checks retained source and stdout bindings to recorded
image hashes; it does not rebuild or execute the archived images. Python
optimization is rejected so that the validation assertions remain active.

From the repository root, verify all retained identities and case counts:

```sh
python3 docs/specifications/windows/native-current-version/verify.py
```

Expected output:

```text
Verified 1248 independent CurrentVersion cases and 9 source/image/stdout bindings
```

In a Windows Visual Studio developer environment, build the controls inside
this worktree. Select the desired native or cross architecture in that
environment before configuring:

```text
cmake -S docs/specifications/windows/native-current-version -B target/native-current-version -G Ninja
cmake --build target/native-current-version
target\native-current-version\current_version_profile.exe
target\native-current-version\current_version_parent.exe
target\native-current-version\current_version_physical.exe
```

Each program writes JSON lines. Fresh output describes the current installed
system; a changed installation need not match the archived build-29698 corpus.
Build-only temporary directories and compiler caches must also remain inside
the worktree, as required by `AGENTS.md`.

## Owning implementation checks

The scheduler test replays all 1,248 independent open/view/parent cases through
the real NT service dispatcher for ARM64, x64 and x86 guest ABIs. Its value
bytes are explicit synthetic fixtures, not a claim to reproduce private
installed value contents. The native Windows acquisition test separately
compares every installed value, ordered entry, access grant and all eight
query records for both subjects and views against fresh native captures. This
checks the stored immutable representation using the same acquisition helpers;
the separate C programs provide the independent open/view controls.

```sh
cargo +1.95.0 test --locked --no-default-features -p rax --lib --features x86_64-suite current_version_ -- --test-threads=1
```

Installed acquisition tests run on Windows. Shared immutable-header and NT
dispatcher replay tests run on Windows, macOS and Linux. Filtering by
`current_version_` can also select unrelated existing tests; inspect the test
names and counts before attributing the result to this feature.

## Assumption register and boundaries

| ID | Assumption and dependent result | Falsification probe | Status |
| --- | --- | --- | --- |
| C1 | Installed CMD's failing relative open is rooted at MACHINE; fixed HKLM header acquisition addresses that lookup. | Inspect the retained root handle and relative UTF-16 name in the baseline startup diagnostic. | Confirmed on the captured run. |
| C2 | Native and WoW64 CurrentVersion share one header. | Compare native/default-32 canonical names, counts and records. | Falsified; independent paired headers are required. |
| C3 | IFEO and GRE_Initialize retain shared native routes beneath both views. | Replay relative opens from logical and physical parents with every captured view flag and compare exact names/tags. | Confirmed for the 1,248-case corpus. |
| C4 | Security-access failure can use a fixed privilege-error status. | Request `ACCESS_SYSTEM_SECURITY` from each process ABI and path spelling. | Falsified; actual `0xC0000022` is retained. |
| C5 | Complete ordered child metadata distinguishes absence from an uncaptured body. | Query an absent sibling, then an enumerated but unselected descendant, and retain parents after catalog drop. | Confirmed by immutable-header tests and native parent controls. |
| C6 | Selected direct routes agree with complete parent metadata. | Construct present/missing child contradictions, an absent parent retaining a child, and a valid absent child beneath a present parent. | Enforced by constructor rejection and the dedicated regression test. |

High-impact boundary: this feature does not make an uncaptured present
descendant available and does not complete arbitrary Windows process emulation.
The installed CMD diagnostic advances past the previous `NtOpenKeyEx`
CurrentVersion failure and stops explicitly at an unimplemented
`NtQueryInformationFile` service. A successful diagnostic wrapper exit is not
an emulated program exit.
