# Child image registry lookups on Windows ARM64

The installed shell on Windows ARM64 build 29708 opened these keys after the
file-backed image metadata query and before creating the child process.

| Request | Native result |
| --- | --- |
| `\Registry\Machine\System\CurrentControlSet\Control\Session Manager\Memory Management` | `STATUS_SUCCESS` |
| `cmd.exe` or `where.exe` relative to the Memory Management key | `STATUS_OBJECT_NAME_NOT_FOUND` |
| `\Registry\Machine\Software\Microsoft\Wow64\x86\xtajit` | `STATUS_OBJECT_NAME_NOT_FOUND` |

The normal shell launch identified the keys and the relative probe for
`cmd.exe`. Direct read-only opens also checked `where.exe` and reproduced
all four results with both view selectors. The [native control](arm64-29708.json)
records status codes and root counts.

The snapshot selects the bounded Memory Management subtree and uses it for
both views of the shared SYSTEM hive. It captures the XtaJit subject
independently in both SOFTWARE views, including the native missing-name or
missing-path status. These selections use fixed host paths and immutable guest records.
Child names outside a selected subtree remain outside the runtime snapshot.

[Microsoft's registry view rules](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)
describe the different handling of shared SYSTEM and redirected SOFTWARE keys.
