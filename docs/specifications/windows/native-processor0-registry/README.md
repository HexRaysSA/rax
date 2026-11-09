# Fixed processor-0 registry metadata

The published `a15bb3ce` runtime stops while opening
`\Registry\MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0`.
The independent AMD64 thread program exits zero natively. A read-only emulator
postmortem captures desired access `KEY_QUERY_VALUE` (`0x1`), root handle zero,
`OBJ_CASE_INSENSITIVE` (`0x40`), a 48-byte OBJECT_ATTRIBUTES record and a
128-byte counted UTF-16 name. The caller executes the ARM64EC NTDLL entry on
Windows 10.0.29698.0. Diagnostic wrapper exit zero does not mean guest success.

The runtime now selects this compile-time hardware subject before guest
execution. The existing bounded shared-subtree mechanism retains canonical
names, raw value types/bytes, ordered child metadata and each key's access
ceiling and system-security result. Both logical views represent one physical
subject. Capture rejects inconsistent existence, identity, contents or grants;
native handles close during acquisition. Guest handles and retained MACHINE
handles own immutable records through catalog replacement and duplication.
Unselected processors and neighboring prefixes remain unknown. Captured
absence preserves the native name-not-found versus path-not-found distinction.

The captured data describes Windows' native hardware subject, including when
an AMD64 caller executes under ARM64 translation. Values are not fabricated
from the emulated instruction set or a guessed processor frequency.
Microsoft's [shared-key rules](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)
classify HKLM as shared except for named overrides; HARDWARE inherits that
shared behavior. Native controls below establish actual grants and key-body
tags, which are not inferred from the documentation.

## Independent native controls

The four C producers perform read/query/open/close operations against the fixed
subject. Absolute, absent-child and MACHINE-relative producers reuse unchanged
CMD helper sources. The tree producer derives from the OLE producer, retaining
its SHA-256 provenance in the source, selecting the hardware subject and
retaining each node's eight raw FILETIME bytes. Each
architecture's 136 absolute, 136 absent-child and 12 relative controls are
supplemented by 448/448/384 tree/reopen cases for ARM64/AMD64/x86 respectively:

`3 × (136 + 136 + 12) + 448 + 448 + 384 = 2,132` recorded opens.

The native host exposes 29 raw values in processor 0, identically through both
views. All twelve producer processes exit zero with no stderr and retain their
original executable and installed-library identities. AMD64 and x86 callers
run translated on the ARM64 host; physical AMD64 kernels and other Windows
versions require their own controls. `controls-v1.json` is generated observation
data: it retains complete reports, producer identities, source hashes and raw
stdout hashes. It contains no executable images or build archives.

The service replay compares every recorded status, published handle, grant,
canonical name and key-body flag through the actual guest NT dispatcher. It
also checks raw values and complete descendant lifetime through duplicated
handles and catalog replacement. Pure tests cover shared-view races, exact
absence classes, fixed-name boundaries and retained MACHINE routes. Native
Windows tests compare installed capture and verify full-startup selection.

## Reproduction and qualification

From the repository root, portable source/corpus verification is:

```text
python tools/ci/windows_ole_registry.py --subject processor0 --verify-corpus
```

On Windows with CMake and Visual Studio, capture fresh native controls and
replay them through the current guest implementation:

```text
python tools/ci/windows_ole_registry.py --subject processor0 --output target/native-processor0-registry-v1
```

The default subject remains OLE, preserving the existing invocation. The
processor-0 campaign uses its own contained output directory, artifacts and
corpus environment variable. CI verifies both retained subjects on every host
and runs both native campaigns on Windows. Shared model/replay execution on
Windows, macOS and Linux and the installed-program successor remain separate
qualification gates; source verification alone does not establish those runs.

## Controlled native capture fixtures

The broader Windows registry selection exposed ten pre-existing controlled
present-capture tests that used the real IFEO subtree as their input. Protected
IFEO descendants deny read access on this host. These tests now use a unique
volatile HKCU leaf containing four keys and four values, including Unicode,
raw binary, DWORD and multi-string data. Real fixed-root read-only integration
checks remain separate. The test-only helper mutates and deletes a leaf only
after REG_CREATED_NEW_KEY establishes ownership; pre-existing name collisions
are retained. A native test verifies that the owned leaf is absent after its
readers and owner drop. Runtime registry capture and access policy are unchanged.

## Assumptions and bounded scope

The fixed path and query access are observed in the published-runtime failure.
The shared-subject assumption is confirmed on this kernel by identical native
views and remains falsifiable by rerunning the unchanged producers. Existing
snapshot limits bound keys, values, byte counts, paths and recursion before
publication; allocation/capture errors reject selection. Acquisition and
projection use the existing O(V log V + K log K) bounded-tree algorithms for
V values and K keys, with O(V + K + B) storage for retained metadata and B raw
bytes; lookup follows the existing folded-path maps and retained key routes.

High impact: ordinary Windows startup and subsequent process-supervision
requests remain unproven until independently compared with native execution.
Medium impact: the host registry is mutable; acquisition deliberately rejects
inconsistent snapshots rather than claiming an atomic hive transaction.
Public C ABI, service export identities, permission scopes and persisted
layouts are unchanged. Guest-supplied names, handles and pointers remain within
the existing guest registry implementation.
