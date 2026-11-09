# Fixed WOW64 amd64 startup subject

The installed x64 library startup observed on Windows 10.0.29698.0 opens
`\Registry\Machine\Software\Microsoft\Wow64\amd64\` with `KEY_READ`.
The independent native oracle in this directory records
`STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`) for both view flags, with and
without the trailing separator. No native key handle is published on those calls.
This is profile evidence, not a constant absence assumption.

The runtime acquires this fixed subject through the existing native snapshot
pipeline before guest execution. It captures both views through explicit native
view flags. Present subjects retain bounded raw values/types, complete descendants,
ordered child names and FILETIME metadata, per-node access ceilings and native
canonical names. The two views may name different physical trees; if they name
one physical tree, conflicting contents are rejected. Canonical root validation
admits the fixed logical spelling and, for the x86 view, the reserved redirected
physical spelling returned by the native API. Captured canonical aliases use the
existing handle-owned routing machinery.

Acquisition uses counted UTF-16 names and `NtOpenKeyEx` with options0 and fixed
maximum-access/view flags. Native name-not-found and path-not-found statuses remain
distinct. Other native acquisition errors fail closed under the existing snapshot
contract. All host key handles close before guest handles are exposed; neither a
host HKEY nor a guest-to-host lookup callback is retained.

The subject shares the existing aggregate startup limits: 1,024 keys, 4,096 values,
16 MiB of value/name storage and the existing path/enumeration budgets. No default,
permission policy, public C ABI or dependency pin changes. Capture and construction
use at most O((K + V + B) log(K + V + 2)) Rust-side time and O(K + V + B)
owned storage for K keys, V values and B bytes of names/data, subject to those
bounds. Native API latency is outside this algorithmic bound.

Verification includes pure present/absent view fixtures, exact native absence
records, malformed-tree and same-physical-key consistency checks, retained machine
routes, aggregate-budget exhaustion, native Windows acquisition and the unchanged
actual-CLI thread witness. Passing unit fixtures alone does not prove installed
x64 program execution or full guest child-process supervision.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The logical machine subject and its measured x86 canonical spelling identify this fixed selection. | Native fixed-path observations and existing canonical subject checks. | Present-tree admission and retained guest routing. | Foreign roots, suffix collisions, missing descendants, inconsistent physical trees. | A supported native profile returns a different canonical subject. | Retained canonical profile; pure fixtures and native acquisition are separate gates. |
| A2 | An ARM64 capture process uses the x86 view for `KEY_WOW64_32KEY`. | Microsoft alternate-view documentation and explicit native view probes. | Windows x86 guest registry projection. | Both flags, separate physical trees and exact absence classes. | The supported native capture process selects a non-x86 view. | Confirmed for the identified ARM64 process. |

The native corpus records ARM64-process acquisition on kernel `10.0.29698.0`.
It does not establish physical x64 host execution. Absence on that machine is
an observation; a present host subtree is captured rather than replaced with
that recorded absence. The acquisition source hash is retained with its native
receipt. Recognizing the reserved canonical name does not cause acquisition by
that physical path: native opens use the fixed logical name and explicit flags.

## Remaining scope

* **High:** Complete ordinary-process execution, native x64-host validation and
  guest child-process supervision remain separate acceptance gates.
* **Medium:** Existing native registry integration tests have a separate pending
  private-fixture update; those unrelated test edits are outside this changeset.

Primary references:

- [Microsoft alternate registry views](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)
- [Microsoft registry redirector](https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector)
- `native-oracle-v3.cs`: fixed read-only native and Win32 open probes.
- `observations-v3.json`: exact native kernel/image identity and returned statuses.
