# Creator application compatibility Layers key

The installed Windows shell opens `AppCompatFlags\Layers` relative to the
creator's `HKCU\Software\Microsoft\Windows NT\CurrentVersion` key. The
installed-runtime snapshot retains that fixed leaf alongside the parent
header. Absolute lookup and a relative open through the parent handle give
the same immutable key and captured grant. Querying a value observes the
retained bytes for that value. The guest registry path does not invoke a
live host registry operation.

Native Windows 10.0.29708.1003 ARM64 measurements opened the leaf and its
immediate ancestor using absolute and relative names in three view
configurations. All 12 ordinary opens succeeded. The leaf held one value
for a different application and had no subkeys or value for installed
`System32\cmd.exe`. The capture retained no private value contents. The
private native projection has SHA-256
`ce0345ad070f5edcf7106023e22d4e5fe0f37b62b330695f632213497246d914`.
The [native key-open API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkey)
and [Windows registry access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
document the query and access contracts.

The loader reads the fixed leaf under the already validated creator key,
closes its native handles after acquisition, and checks that two views agree
on canonical identity, grants, and retained contents. Missing-name and
missing-path statuses remain distinct. The leaf consumes the existing
aggregate key, path, value and ordered metadata budgets. Only the fixed
`Layers` route is attached. New storage and acquisition work are proportional
to the captured direct metadata and value bytes.

| ID | Assumption and dependent result | Basis | Falsification probe | Status |
|---|---|---|---|---|
| L1 | The two configured views select the same creator leaf | The 12 absolute and relative native controls | Compare both views' identity, grant and complete retained contents | Confirmed on the measured host |
| L2 | Capturing the fixed leaf leaves other descendants unselected | Explicit two-component route under a validated creator key | Open a sibling and a prefix lookalike | Covered by shared snapshot tests |
| L3 | Native absence can distinguish a missing leaf from a missing path | Native key-open status captured before guest execution | Replay both statuses and inconsistent paired views | Covered by shared snapshot tests |

The measured shell advances from the relative key open to the application
compatibility-cache request. Native fixture coverage comes from ARM64. The
portable assertions also exercise the paired guest views on macOS and Linux.
